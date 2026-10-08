package user

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound   = errors.New("usuário não encontrado")
	ErrEmailTaken = errors.New("e-mail já cadastrado")
)

const uniqueViolation = "23505"

type User struct {
	ID           string
	Email        string
	PasswordHash string
	CreatedAt    time.Time
}

type Store struct {
	db *pgxpool.Pool
}

func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

func (s *Store) Create(ctx context.Context, email, passwordHash string) (User, error) {
	u := User{Email: email, PasswordHash: passwordHash}
	err := s.db.QueryRow(ctx,
		`INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id::text, created_at`,
		email, passwordHash,
	).Scan(&u.ID, &u.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return User{}, ErrEmailTaken
		}
		return User{}, fmt.Errorf("inserindo usuário: %w", err)
	}
	return u, nil
}

func (s *Store) ByEmail(ctx context.Context, email string) (User, error) {
	return s.one(ctx,
		`SELECT id::text, email::text, password_hash, created_at FROM users WHERE email = $1`, email)
}

func (s *Store) ByID(ctx context.Context, id string) (User, error) {
	return s.one(ctx,
		`SELECT id::text, email::text, password_hash, created_at FROM users WHERE id = $1::uuid`, id)
}

func (s *Store) UpdatePasswordHash(ctx context.Context, id, passwordHash string) error {
	_, err := s.db.Exec(ctx,
		`UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1::uuid`, id, passwordHash)
	if err != nil {
		return fmt.Errorf("atualizando hash: %w", err)
	}
	return nil
}

func (s *Store) one(ctx context.Context, query string, arg string) (User, error) {
	var u User
	err := s.db.QueryRow(ctx, query, arg).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("buscando usuário: %w", err)
	}
	return u, nil
}
