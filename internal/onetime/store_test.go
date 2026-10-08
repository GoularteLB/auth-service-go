package onetime

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestStore(t *testing.T) (*Store, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return NewStore(rdb), mr
}

func TestIssueAndConsumeOnce(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()

	token, err := s.Issue(ctx, VerifyEmail, "user-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(token) < 40 {
		t.Fatalf("token curto demais: %q", token)
	}
	for _, k := range mr.Keys() {
		if strings.Contains(k, token) {
			t.Fatalf("token em texto puro no redis: %s", k)
		}
	}

	userID, err := s.Consume(ctx, VerifyEmail, token)
	if err != nil || userID != "user-1" {
		t.Fatalf("Consume = %q, %v", userID, err)
	}
	if _, err := s.Consume(ctx, VerifyEmail, token); !errors.Is(err, ErrInvalid) {
		t.Fatal("token usado duas vezes")
	}
	if len(mr.Keys()) != 0 {
		t.Errorf("sobrou lixo no redis: %v", mr.Keys())
	}
}

func TestPurposesAreSeparate(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	token, _ := s.Issue(ctx, VerifyEmail, "user-1", time.Hour)

	if _, err := s.Consume(ctx, ResetPassword, token); !errors.Is(err, ErrInvalid) {
		t.Fatal("token de verificação serviu para redefinir senha")
	}
}

func TestNewTokenInvalidatesPrevious(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	first, _ := s.Issue(ctx, ResetPassword, "user-1", time.Hour)
	second, _ := s.Issue(ctx, ResetPassword, "user-1", time.Hour)
	other, _ := s.Issue(ctx, ResetPassword, "user-2", time.Hour)

	if _, err := s.Consume(ctx, ResetPassword, first); !errors.Is(err, ErrInvalid) {
		t.Fatal("link antigo continuou valendo")
	}
	if _, err := s.Consume(ctx, ResetPassword, second); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Consume(ctx, ResetPassword, other); err != nil {
		t.Fatalf("token de outro usuário foi afetado: %v", err)
	}
}

func TestTokenExpires(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()
	token, _ := s.Issue(ctx, ResetPassword, "user-1", 30*time.Minute)
	mr.FastForward(31 * time.Minute)
	if _, err := s.Consume(ctx, ResetPassword, token); !errors.Is(err, ErrInvalid) {
		t.Fatal("token expirado ainda vale")
	}
}

func TestConsumeRejectsGarbage(t *testing.T) {
	s, _ := newTestStore(t)
	for _, tok := range []string{"", "nao-existe", strings.Repeat("a", 129)} {
		if _, err := s.Consume(context.Background(), VerifyEmail, tok); !errors.Is(err, ErrInvalid) {
			t.Errorf("Consume(%q) = %v", tok, err)
		}
	}
}

func TestPeekDoesNotConsume(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	token, _ := s.Issue(ctx, MFAChallenge, "user-1", time.Minute)

	for range 2 {
		userID, err := s.Peek(ctx, MFAChallenge, token)
		if err != nil || userID != "user-1" {
			t.Fatalf("Peek = %q, %v", userID, err)
		}
	}
	if _, err := s.Consume(ctx, MFAChallenge, token); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Peek(ctx, MFAChallenge, token); !errors.Is(err, ErrInvalid) {
		t.Fatal("Peek achou token já consumido")
	}
}
