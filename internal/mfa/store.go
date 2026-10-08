package mfa

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	db *pgxpool.Pool
}

func NewPostgresStore(db *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{db: db}
}

func (s *PostgresStore) Get(ctx context.Context, userID string) (Record, error) {
	var r Record
	err := s.db.QueryRow(ctx,
		`SELECT secret_ciphertext, enabled_at IS NOT NULL FROM user_mfa WHERE user_id = $1::uuid`, userID,
	).Scan(&r.Ciphertext, &r.Enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return Record{}, ErrNotEnabled
	}
	if err != nil {
		return Record{}, fmt.Errorf("buscando mfa: %w", err)
	}
	return r, nil
}

func (s *PostgresStore) SavePending(ctx context.Context, userID string, ciphertext []byte) error {
	tag, err := s.db.Exec(ctx,
		`INSERT INTO user_mfa (user_id, secret_ciphertext) VALUES ($1::uuid, $2)
		 ON CONFLICT (user_id) DO UPDATE
		 SET secret_ciphertext = EXCLUDED.secret_ciphertext, last_used_step = 0, created_at = now()
		 WHERE user_mfa.enabled_at IS NULL`,
		userID, ciphertext)
	if err != nil {
		return fmt.Errorf("salvando mfa pendente: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrAlreadyEnabled
	}
	return nil
}

func (s *PostgresStore) Enable(ctx context.Context, userID string, codeHashes [][32]byte) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("abrindo transação: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx,
		`UPDATE user_mfa SET enabled_at = now() WHERE user_id = $1::uuid AND enabled_at IS NULL`, userID)
	if err != nil {
		return fmt.Errorf("ativando mfa: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrAlreadyEnabled
	}
	if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id = $1::uuid`, userID); err != nil {
		return fmt.Errorf("limpando códigos antigos: %w", err)
	}
	for _, h := range codeHashes {
		if _, err := tx.Exec(ctx,
			`INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES ($1::uuid, $2)`, userID, h[:]); err != nil {
			return fmt.Errorf("gravando código de recuperação: %w", err)
		}
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) Disable(ctx context.Context, userID string) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("abrindo transação: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id = $1::uuid`, userID); err != nil {
		return fmt.Errorf("apagando códigos: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM user_mfa WHERE user_id = $1::uuid`, userID); err != nil {
		return fmt.Errorf("desativando mfa: %w", err)
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) UseStep(ctx context.Context, userID string, step int64) (bool, error) {
	tag, err := s.db.Exec(ctx,
		`UPDATE user_mfa SET last_used_step = $2 WHERE user_id = $1::uuid AND last_used_step < $2`, userID, step)
	if err != nil {
		return false, fmt.Errorf("registrando uso do código: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func (s *PostgresStore) UseRecoveryCode(ctx context.Context, userID string, hash [32]byte) (bool, error) {
	tag, err := s.db.Exec(ctx,
		`UPDATE mfa_recovery_codes SET used_at = now()
		 WHERE user_id = $1::uuid AND code_hash = $2 AND used_at IS NULL`, userID, hash[:])
	if err != nil {
		return false, fmt.Errorf("usando código de recuperação: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
