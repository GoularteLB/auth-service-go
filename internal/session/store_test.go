package session

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestStore(t *testing.T, ttl time.Duration) (*Store, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return NewStore(rdb, ttl), mr
}

func TestCreateAndGet(t *testing.T) {
	store, _ := newTestStore(t, time.Hour)
	ctx := context.Background()

	token, err := store.Create(ctx, "user-1", []string{"pwd", "otp", "mfa"})
	if err != nil {
		t.Fatal(err)
	}
	if len(token) < 26 {
		t.Fatalf("token curto demais: %q", token)
	}

	sess, err := store.Get(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if sess.UserID != "user-1" {
		t.Errorf("UserID = %q, esperado user-1", sess.UserID)
	}
	if !slices.Equal(sess.AMR, []string{"pwd", "otp", "mfa"}) {
		t.Errorf("AMR = %v", sess.AMR)
	}
}

func TestTokenIsNotStoredInPlainText(t *testing.T) {
	store, mr := newTestStore(t, time.Hour)
	token, _ := store.Create(context.Background(), "user-1", nil)

	for _, k := range mr.Keys() {
		if strings.Contains(k, token) {
			t.Fatalf("token aparece na chave do redis: %s", k)
		}
	}
}

func TestSessionExpires(t *testing.T) {
	store, mr := newTestStore(t, time.Minute)
	ctx := context.Background()
	token, _ := store.Create(ctx, "user-1", nil)

	mr.FastForward(time.Minute + time.Second)
	if _, err := store.Get(ctx, token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("sessão expirada ainda válida: %v", err)
	}
}

func TestDelete(t *testing.T) {
	store, _ := newTestStore(t, time.Hour)
	ctx := context.Background()
	token, _ := store.Create(ctx, "user-1", nil)

	if err := store.Delete(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("sessão continuou após Delete: %v", err)
	}
}

func TestGetUnknownToken(t *testing.T) {
	store, _ := newTestStore(t, time.Hour)
	for _, token := range []string{"", "nao-existe"} {
		if _, err := store.Get(context.Background(), token); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get(%q) = %v, esperado ErrNotFound", token, err)
		}
	}
}

func TestDeleteAll(t *testing.T) {
	store, mr := newTestStore(t, time.Hour)
	ctx := context.Background()
	a, _ := store.Create(ctx, "user-1", nil)
	b, _ := store.Create(ctx, "user-1", nil)
	other, _ := store.Create(ctx, "user-2", nil)

	if err := store.DeleteAll(ctx, "user-1"); err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{a, b} {
		if _, err := store.Get(ctx, tok); !errors.Is(err, ErrNotFound) {
			t.Errorf("sessão %q sobreviveu ao DeleteAll", tok)
		}
	}
	if _, err := store.Get(ctx, other); err != nil {
		t.Fatalf("DeleteAll apagou sessão de outro usuário: %v", err)
	}
	if mr.Exists(userKeyPrefix + "user-1") {
		t.Error("índice do usuário não foi apagado")
	}
	if err := store.DeleteAll(ctx, "ninguem"); err != nil {
		t.Fatalf("DeleteAll sem sessões deveria ser nulo: %v", err)
	}
}

func TestDeleteRemovesFromIndex(t *testing.T) {
	store, mr := newTestStore(t, time.Hour)
	ctx := context.Background()
	a, _ := store.Create(ctx, "user-1", nil)
	_, _ = store.Create(ctx, "user-1", nil)

	if err := store.Delete(ctx, a); err != nil {
		t.Fatal(err)
	}
	members, err := mr.Members(userKeyPrefix + "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 {
		t.Fatalf("índice com %d sessões, esperado 1", len(members))
	}
	if err := store.Delete(ctx, a); err != nil {
		t.Fatalf("apagar duas vezes deveria ser nulo: %v", err)
	}
}
