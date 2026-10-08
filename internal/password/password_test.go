package password

import (
	"context"
	"errors"
	"strings"
	"testing"
)

var fastParams = Params{Memory: 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}

func newTestHasher(t *testing.T) *Hasher {
	t.Helper()
	h, err := NewHasher(fastParams, 2)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestHashAndVerify(t *testing.T) {
	h := newTestHasher(t)
	ctx := context.Background()

	encoded, err := h.Hash(ctx, "cavalo-bateria-grampo")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$m=1024,t=1,p=1$") {
		t.Fatalf("formato inesperado: %s", encoded)
	}

	ok, err := h.Verify(ctx, "cavalo-bateria-grampo", encoded)
	if err != nil || !ok {
		t.Fatalf("senha correta rejeitada: ok=%v err=%v", ok, err)
	}

	ok, err = h.Verify(ctx, "cavalo-bateria-grampa", encoded)
	if err != nil || ok {
		t.Fatalf("senha errada aceita: ok=%v err=%v", ok, err)
	}
}

func TestSamePasswordGetsDifferentHashes(t *testing.T) {
	h := newTestHasher(t)
	a, _ := h.Hash(context.Background(), "mesma-senha-longa")
	b, _ := h.Hash(context.Background(), "mesma-senha-longa")
	if a == b {
		t.Fatal("salt não está sendo aplicado")
	}
}

func TestVerifyRejectsMalformedHash(t *testing.T) {
	h := newTestHasher(t)
	for _, encoded := range []string{
		"",
		"texto-qualquer",
		"$argon2i$v=19$m=1024,t=1,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=18$m=1024,t=1,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=0,t=1,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=1024,t=1,p=1$$aGFzaA",
		"$argon2id$v=19$m=1024,t=1,p=1$c2FsdA$!!!",
	} {
		if _, err := h.Verify(context.Background(), "x", encoded); !errors.Is(err, ErrInvalidHash) {
			t.Errorf("%q: esperava ErrInvalidHash, recebeu %v", encoded, err)
		}
	}
}

func TestVerifyDummy(t *testing.T) {
	if err := newTestHasher(t).VerifyDummy(context.Background(), "qualquer"); err != nil {
		t.Fatal(err)
	}
}

func TestNeedsRehash(t *testing.T) {
	h := newTestHasher(t)
	encoded, _ := h.Hash(context.Background(), "senha-bem-comprida")
	if h.NeedsRehash(encoded) {
		t.Error("hash com parâmetros atuais não deveria precisar de rehash")
	}

	stronger, err := NewHasher(Params{Memory: 2048, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !stronger.NeedsRehash(encoded) {
		t.Error("hash com memória menor deveria precisar de rehash")
	}
}

func TestHashRespectsCanceledContext(t *testing.T) {
	h, err := NewHasher(fastParams, 1)
	if err != nil {
		t.Fatal(err)
	}
	h.slots <- struct{}{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.Hash(ctx, "senha-bem-comprida"); !errors.Is(err, context.Canceled) {
		t.Fatalf("esperava context.Canceled, recebeu %v", err)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		plain string
		want  error
	}{
		{"curta", ErrTooShort},
		{strings.Repeat("a", MinLength), nil},
		{strings.Repeat("ç", MinLength), nil},
		{strings.Repeat("a", MaxLength+1), ErrTooLong},
	}
	for _, tt := range tests {
		if err := Validate(tt.plain); !errors.Is(err, tt.want) {
			t.Errorf("Validate(%d runas) = %v, esperado %v", len([]rune(tt.plain)), err, tt.want)
		}
	}
}
