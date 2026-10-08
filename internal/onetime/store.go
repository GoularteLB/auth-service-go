package onetime

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type Purpose string

const (
	VerifyEmail   Purpose = "verify_email"
	ResetPassword Purpose = "reset_password"
	MFAChallenge  Purpose = "mfa_challenge"
)

const maxTokenLength = 128

var ErrInvalid = errors.New("link inválido ou expirado")

type Store struct {
	rdb *redis.Client
}

func NewStore(rdb *redis.Client) *Store {
	return &Store{rdb: rdb}
}

func (s *Store) Issue(ctx context.Context, p Purpose, userID string, ttl time.Duration) (string, error) {
	token := rand.Text() + rand.Text()
	k := tokenKey(p, token)
	ptr := pointerKey(p, userID)

	old, err := s.rdb.Get(ctx, ptr).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return "", fmt.Errorf("lendo token anterior: %w", err)
	}

	pipe := s.rdb.TxPipeline()
	if old != "" {
		pipe.Del(ctx, old)
	}
	pipe.Set(ctx, k, userID, ttl)
	pipe.Set(ctx, ptr, k, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return "", fmt.Errorf("gravando token: %w", err)
	}
	return token, nil
}

func (s *Store) Consume(ctx context.Context, p Purpose, token string) (string, error) {
	if token == "" || len(token) > maxTokenLength {
		return "", ErrInvalid
	}
	userID, err := s.rdb.GetDel(ctx, tokenKey(p, token)).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrInvalid
	}
	if err != nil {
		return "", fmt.Errorf("consumindo token: %w", err)
	}
	if err := s.rdb.Del(ctx, pointerKey(p, userID)).Err(); err != nil {
		return "", fmt.Errorf("limpando token: %w", err)
	}
	return userID, nil
}

func (s *Store) Peek(ctx context.Context, p Purpose, token string) (string, error) {
	if token == "" || len(token) > maxTokenLength {
		return "", ErrInvalid
	}
	userID, err := s.rdb.Get(ctx, tokenKey(p, token)).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrInvalid
	}
	if err != nil {
		return "", fmt.Errorf("lendo token: %w", err)
	}
	return userID, nil
}

func tokenKey(p Purpose, token string) string {
	sum := sha256.Sum256([]byte(token))
	return "onetime:" + string(p) + ":" + base64.RawURLEncoding.EncodeToString(sum[:])
}

func pointerKey(p Purpose, userID string) string {
	return "onetime:" + string(p) + ":user:" + userID
}
