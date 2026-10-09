package client

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const ScopeSessionExchange = "session:exchange"

var (
	ErrNotFound        = errors.New("cliente não encontrado")
	ErrInvalidName     = errors.New("nome do cliente precisa ter entre 1 e 100 caracteres")
	ErrInvalidScope    = errors.New("escopo inválido")
	ErrInvalidAudience = errors.New("audiência inválida")
)

var scopePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9:._-]{0,63}$`)

type Client struct {
	ClientID  string
	Name      string
	Scopes    []string
	Audiences []string
	CreatedAt time.Time
	RevokedAt *time.Time
}

type Store struct {
	db *pgxpool.Pool
}

func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

func (s *Store) Create(ctx context.Context, name string, scopes, audiences []string) (Client, string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > 100 {
		return Client{}, "", ErrInvalidName
	}
	scopes, err := NormalizeScopes(scopes)
	if err != nil {
		return Client{}, "", err
	}
	audiences, err = NormalizeAudiences(audiences)
	if err != nil {
		return Client{}, "", err
	}

	c := Client{ClientID: "cli_" + strings.ToLower(rand.Text()), Name: name, Scopes: scopes, Audiences: audiences}
	secret := rand.Text() + rand.Text()
	hash := HashSecret(secret)
	err = s.db.QueryRow(ctx,
		`INSERT INTO clients (client_id, name, secret_hash, scopes, audiences) VALUES ($1, $2, $3, $4, $5) RETURNING created_at`,
		c.ClientID, c.Name, hash[:], c.Scopes, c.Audiences,
	).Scan(&c.CreatedAt)
	if err != nil {
		return Client{}, "", fmt.Errorf("inserindo cliente: %w", err)
	}
	return c, secret, nil
}

func (s *Store) Active(ctx context.Context, clientID string) (Client, [32]byte, error) {
	var c Client
	var raw []byte
	err := s.db.QueryRow(ctx,
		`SELECT client_id, name, scopes, audiences, created_at, secret_hash FROM clients
		 WHERE client_id = $1 AND revoked_at IS NULL`, clientID,
	).Scan(&c.ClientID, &c.Name, &c.Scopes, &c.Audiences, &c.CreatedAt, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return Client{}, [32]byte{}, ErrNotFound
	}
	if err != nil {
		return Client{}, [32]byte{}, fmt.Errorf("buscando cliente: %w", err)
	}
	var hash [32]byte
	if len(raw) != len(hash) {
		return Client{}, [32]byte{}, fmt.Errorf("cliente %s com hash corrompido", clientID)
	}
	copy(hash[:], raw)
	return c, hash, nil
}

func (s *Store) SetAudiences(ctx context.Context, clientID string, audiences []string) ([]string, error) {
	audiences, err := NormalizeAudiences(audiences)
	if err != nil {
		return nil, err
	}
	tag, err := s.db.Exec(ctx,
		`UPDATE clients SET audiences = $2 WHERE client_id = $1 AND revoked_at IS NULL`, clientID, audiences)
	if err != nil {
		return nil, fmt.Errorf("atualizando audiências: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return audiences, nil
}

func (s *Store) Revoke(ctx context.Context, clientID string) error {
	tag, err := s.db.Exec(ctx,
		`UPDATE clients SET revoked_at = now() WHERE client_id = $1 AND revoked_at IS NULL`, clientID)
	if err != nil {
		return fmt.Errorf("revogando cliente: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) List(ctx context.Context) ([]Client, error) {
	rows, err := s.db.Query(ctx,
		`SELECT client_id, name, scopes, audiences, created_at, revoked_at FROM clients ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("listando clientes: %w", err)
	}
	defer rows.Close()

	var out []Client
	for rows.Next() {
		var c Client
		if err := rows.Scan(&c.ClientID, &c.Name, &c.Scopes, &c.Audiences, &c.CreatedAt, &c.RevokedAt); err != nil {
			return nil, fmt.Errorf("lendo cliente: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func HashSecret(secret string) [32]byte {
	return sha256.Sum256([]byte(secret))
}

func NormalizeScopes(scopes []string) ([]string, error) {
	return normalizeNames(scopes, ErrInvalidScope)
}

func NormalizeAudiences(audiences []string) ([]string, error) {
	return normalizeNames(audiences, ErrInvalidAudience)
}

func normalizeNames(names []string, invalid error) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range names {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		if !scopePattern.MatchString(s) {
			return nil, fmt.Errorf("%w: %q", invalid, s)
		}
		seen[s] = true
		out = append(out, s)
	}
	return out, nil
}
