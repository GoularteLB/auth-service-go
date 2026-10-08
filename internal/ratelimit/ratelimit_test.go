package ratelimit

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newRedis(t *testing.T) (*redis.Client, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb, mr
}

func TestLimiterBlocksAfterLimit(t *testing.T) {
	rdb, mr := newRedis(t)
	l := NewLimiter(rdb)
	ctx := context.Background()

	for i := range 3 {
		retry, err := l.Allow(ctx, "login:10.0.0.1", 3, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if retry != 0 {
			t.Fatalf("requisição %d bloqueada cedo demais", i+1)
		}
	}

	retry, err := l.Allow(ctx, "login:10.0.0.1", 3, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if retry <= 0 || retry > time.Minute {
		t.Fatalf("retry = %v, esperado entre 0 e 1m", retry)
	}

	if retry, _ := l.Allow(ctx, "login:10.0.0.2", 3, time.Minute); retry != 0 {
		t.Fatal("limite vazou para outro IP")
	}

	mr.FastForward(time.Minute)
	if retry, _ := l.Allow(ctx, "login:10.0.0.1", 3, time.Minute); retry != 0 {
		t.Fatal("janela não reiniciou")
	}
}

func TestKeysDoNotStoreRawValues(t *testing.T) {
	rdb, mr := newRedis(t)
	ctx := context.Background()
	_, _ = NewLimiter(rdb).Allow(ctx, "login:10.0.0.1", 1, time.Minute)
	_, _ = NewLockout(rdb, DefaultLockoutPolicy).Fail(ctx, "ana@example.com")

	for _, k := range mr.Keys() {
		if strings.Contains(k, "10.0.0.1") || strings.Contains(k, "ana@") {
			t.Fatalf("chave expõe dado bruto: %s", k)
		}
	}
}

func TestLockoutGrowsAndCaps(t *testing.T) {
	rdb, mr := newRedis(t)
	policy := LockoutPolicy{Threshold: 3, BaseDelay: time.Minute, MaxDelay: 5 * time.Minute, Memory: time.Hour}
	l := NewLockout(rdb, policy)
	ctx := context.Background()

	want := []time.Duration{0, 0, time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	for i, w := range want {
		got, err := l.Fail(ctx, "ana@example.com")
		if err != nil {
			t.Fatal(err)
		}
		if got != w {
			t.Fatalf("falha %d: bloqueio = %v, esperado %v", i+1, got, w)
		}
	}

	retry, err := l.Check(ctx, "ana@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if retry <= 0 {
		t.Fatal("conta deveria estar bloqueada")
	}

	mr.FastForward(5 * time.Minute)
	if retry, _ := l.Check(ctx, "ana@example.com"); retry != 0 {
		t.Fatalf("bloqueio não expirou: %v", retry)
	}
}

func TestLockoutReset(t *testing.T) {
	rdb, _ := newRedis(t)
	l := NewLockout(rdb, LockoutPolicy{Threshold: 1, BaseDelay: time.Minute, MaxDelay: time.Hour, Memory: time.Hour})
	ctx := context.Background()

	if d, _ := l.Fail(ctx, "ana@example.com"); d != time.Minute {
		t.Fatalf("bloqueio = %v, esperado 1m", d)
	}
	if err := l.Reset(ctx, "ana@example.com"); err != nil {
		t.Fatal(err)
	}
	if retry, _ := l.Check(ctx, "ana@example.com"); retry != 0 {
		t.Fatal("reset não liberou a conta")
	}
	if d, _ := l.Fail(ctx, "ana@example.com"); d != time.Minute {
		t.Fatalf("contador não zerou após reset: %v", d)
	}
}

func TestLockoutForgetsOldFailures(t *testing.T) {
	rdb, mr := newRedis(t)
	l := NewLockout(rdb, LockoutPolicy{Threshold: 2, BaseDelay: time.Minute, MaxDelay: time.Hour, Memory: 10 * time.Minute})
	ctx := context.Background()

	_, _ = l.Fail(ctx, "ana@example.com")
	mr.FastForward(11 * time.Minute)
	if d, _ := l.Fail(ctx, "ana@example.com"); d != 0 {
		t.Fatalf("falha antiga ainda contou: bloqueio = %v", d)
	}
}
