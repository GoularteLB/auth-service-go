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

const (
	keyPrefix     = "session:"
	userKeyPrefix = "user_sessions:"
)

type Session struct {
	UserID    string    `json:"user_id"`
	AMR       []string  `json:"amr,omitempty"`
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

func (s *Store) Create(ctx context.Context, userID string, amr []string) (string, error) {
	token := rand.Text()
	data, err := json.Marshal(Session{UserID: userID, AMR: amr, CreatedAt: time.Now().UTC()})
	if err != nil {
		return "", fmt.Errorf("serializando sessão: %w", err)
	}
	k := key(token)
	pipe := s.rdb.TxPipeline()
	pipe.Set(ctx, k, data, s.ttl)
	pipe.SAdd(ctx, userKey(userID), k)
	pipe.Expire(ctx, userKey(userID), s.ttl)
	if _, err := pipe.Exec(ctx); err != nil {
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
	k := key(token)
	data, err := s.rdb.GetDel(ctx, k).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("apagando sessão: %w", err)
	}
	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil || sess.UserID == "" {
		return nil
	}
	if err := s.rdb.SRem(ctx, userKey(sess.UserID), k).Err(); err != nil {
		return fmt.Errorf("atualizando índice de sessões: %w", err)
	}
	return nil
}

func (s *Store) DeleteAll(ctx context.Context, userID string) error {
	uk := userKey(userID)
	keys, err := s.rdb.SMembers(ctx, uk).Result()
	if err != nil {
		return fmt.Errorf("listando sessões: %w", err)
	}
	if err := s.rdb.Del(ctx, append(keys, uk)...).Err(); err != nil {
		return fmt.Errorf("apagando sessões: %w", err)
	}
	return nil
}

func userKey(userID string) string {
	return userKeyPrefix + userID
}

func key(token string) string {
	sum := sha256.Sum256([]byte(token))
	return keyPrefix + base64.RawURLEncoding.EncodeToString(sum[:])
}
