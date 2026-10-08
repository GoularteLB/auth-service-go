package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var ErrNotFound = errors.New("sessão não encontrada")

const keyPrefix = "session:"

type Session struct {
	UserID    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
}

type Store struct {
	rdb *redis.Client
	ttl time.Duration
}

func NewStore(rdb *redis.Client, ttl time.Duration) *Store {
	return &Store{rdb: rdb, ttl: ttl}
}

func (s *Store) TTL() time.Duration {
	return s.ttl
}

func (s *Store) Create(ctx context.Context, userID string) (string, error) {
	token := rand.Text()
	data, err := json.Marshal(Session{UserID: userID, CreatedAt: time.Now().UTC()})
	if err != nil {
		return "", fmt.Errorf("serializando sessão: %w", err)
	}
	if err := s.rdb.Set(ctx, key(token), data, s.ttl).Err(); err != nil {
		return "", fmt.Errorf("gravando sessão: %w", err)
	}
	return token, nil
}

func (s *Store) Get(ctx context.Context, token string) (Session, error) {
	if token == "" {
		return Session{}, ErrNotFound
	}
	data, err := s.rdb.Get(ctx, key(token)).Bytes()
	if errors.Is(err, redis.Nil) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, fmt.Errorf("lendo sessão: %w", err)
	}
	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return Session{}, fmt.Errorf("sessão corrompida: %w", err)
	}
	return sess, nil
}

func (s *Store) Delete(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	if err := s.rdb.Del(ctx, key(token)).Err(); err != nil {
		return fmt.Errorf("apagando sessão: %w", err)
	}
	return nil
}

func key(token string) string {
	sum := sha256.Sum256([]byte(token))
	return keyPrefix + base64.RawURLEncoding.EncodeToString(sum[:])
}
