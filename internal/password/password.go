package password

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	MinLength = 12
	MaxLength = 128

	maxEncodedBytes = 256
)

var (
	ErrTooShort    = fmt.Errorf("a senha precisa ter pelo menos %d caracteres", MinLength)
	ErrTooLong     = fmt.Errorf("a senha pode ter no máximo %d caracteres", MaxLength)
	ErrInvalidHash = errors.New("hash de senha em formato inválido")
)

type Params struct {
	Memory  uint32
	Time    uint32
	Threads uint8
	SaltLen uint32
	KeyLen  uint32
}

var DefaultParams = Params{
	Memory:  19 * 1024,
	Time:    2,
	Threads: 1,
	SaltLen: 16,
	KeyLen:  32,
}

func Validate(plain string) error {
	n := utf8.RuneCountInString(plain)
	switch {
	case n < MinLength:
		return ErrTooShort
	case n > MaxLength:
		return ErrTooLong
	}
	return nil
}

type Hasher struct {
	params Params
	slots  chan struct{}
	dummy  string
}

func NewHasher(params Params, maxConcurrent int) (*Hasher, error) {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	h := &Hasher{params: params, slots: make(chan struct{}, maxConcurrent)}
	dummy, err := h.encode(rand.Text())
	if err != nil {
		return nil, err
	}
	h.dummy = dummy
	return h, nil
}

func (h *Hasher) Hash(ctx context.Context, plain string) (string, error) {
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()
	return h.encode(plain)
}

func (h *Hasher) Verify(ctx context.Context, plain, encoded string) (bool, error) {
	p, salt, key, err := decode(encoded)
	if err != nil {
		return false, err
	}
	if err := h.acquire(ctx); err != nil {
		return false, err
	}
	defer h.release()
	got := argon2.IDKey([]byte(plain), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	return subtle.ConstantTimeCompare(got, key) == 1, nil
}

func (h *Hasher) VerifyDummy(ctx context.Context, plain string) error {
	_, err := h.Verify(ctx, plain, h.dummy)
	return err
}

func (h *Hasher) NeedsRehash(encoded string) bool {
	p, _, _, err := decode(encoded)
	if err != nil {
		return true
	}
	return p.Memory != h.params.Memory ||
		p.Time != h.params.Time ||
		p.Threads != h.params.Threads ||
		p.SaltLen != h.params.SaltLen ||
		p.KeyLen != h.params.KeyLen
}

func (h *Hasher) acquire(ctx context.Context) error {
	select {
	case h.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *Hasher) release() {
	<-h.slots
}

func (h *Hasher) encode(plain string) (string, error) {
	salt := make([]byte, h.params.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("gerando salt: %w", err)
	}
	p := h.params
	key := argon2.IDKey([]byte(plain), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Threads,
		b64.EncodeToString(salt), b64.EncodeToString(key),
	), nil
}

func decode(encoded string) (Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return Params{}, nil, nil, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return Params{}, nil, nil, ErrInvalidHash
	}

	var p Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Threads); err != nil {
		return Params{}, nil, nil, ErrInvalidHash
	}
	if p.Memory == 0 || p.Time == 0 || p.Threads == 0 {
		return Params{}, nil, nil, ErrInvalidHash
	}

	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return Params{}, nil, nil, ErrInvalidHash
	}
	key, err := b64.DecodeString(parts[5])
	if err != nil {
		return Params{}, nil, nil, ErrInvalidHash
	}
	if p.SaltLen, err = length(salt); err != nil {
		return Params{}, nil, nil, err
	}
	if p.KeyLen, err = length(key); err != nil {
		return Params{}, nil, nil, err
	}
	return p, salt, key, nil
}

func length(b []byte) (uint32, error) {
	n := len(b)
	if n <= 0 || n > maxEncodedBytes {
		return 0, ErrInvalidHash
	}
	return uint32(n), nil
}
