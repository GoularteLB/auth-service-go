package mfa

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"
	"time"
)

const recoveryCodeCount = 10

var (
	ErrNotEnabled     = errors.New("mfa não está ativo")
	ErrAlreadyEnabled = errors.New("mfa já está ativo")
	ErrNoPendingSetup = errors.New("comece a configuração do mfa antes de confirmar")
	ErrInvalidCode    = errors.New("código inválido")
)

type Record struct {
	Ciphertext []byte
	Enabled    bool
}

type Store interface {
	Get(ctx context.Context, userID string) (Record, error)
	SavePending(ctx context.Context, userID string, ciphertext []byte) error
	Enable(ctx context.Context, userID string, codeHashes [][32]byte) error
	Disable(ctx context.Context, userID string) error
	UseStep(ctx context.Context, userID string, step int64) (bool, error)
	UseRecoveryCode(ctx context.Context, userID string, hash [32]byte) (bool, error)
}

type Setup struct {
	Secret string
	URI    string
}

type Service struct {
	store  Store
	cipher *Cipher
	issuer string
	now    func() time.Time
}

func NewService(store Store, cipher *Cipher, issuer string) *Service {
	return &Service{store: store, cipher: cipher, issuer: issuer, now: time.Now}
}

func (s *Service) Enabled(ctx context.Context, userID string) (bool, error) {
	r, err := s.store.Get(ctx, userID)
	if errors.Is(err, ErrNotEnabled) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return r.Enabled, nil
}

func (s *Service) Setup(ctx context.Context, userID, account string) (Setup, error) {
	secret := newSecret()
	if err := s.store.SavePending(ctx, userID, s.cipher.seal(secret, userID)); err != nil {
		return Setup{}, err
	}
	return Setup{Secret: b32.EncodeToString(secret), URI: otpauthURI(s.issuer, account, secret)}, nil
}

func (s *Service) Enable(ctx context.Context, userID, code string) ([]string, error) {
	r, err := s.store.Get(ctx, userID)
	if errors.Is(err, ErrNotEnabled) {
		return nil, ErrNoPendingSetup
	}
	if err != nil {
		return nil, err
	}
	if r.Enabled {
		return nil, ErrAlreadyEnabled
	}
	if err := s.checkTOTP(ctx, userID, r, code); err != nil {
		return nil, err
	}

	codes := make([]string, recoveryCodeCount)
	hashes := make([][32]byte, recoveryCodeCount)
	for i := range codes {
		raw := strings.ToLower(rand.Text())[:10]
		codes[i] = raw[:5] + "-" + raw[5:]
		hashes[i] = hashRecovery(raw)
	}
	if err := s.store.Enable(ctx, userID, hashes); err != nil {
		return nil, err
	}
	return codes, nil
}

func (s *Service) Verify(ctx context.Context, userID, code string) (bool, error) {
	r, err := s.store.Get(ctx, userID)
	if err != nil {
		return false, err
	}
	if !r.Enabled {
		return false, ErrNotEnabled
	}

	code = strings.TrimSpace(code)
	if isNumeric(code) {
		return false, s.checkTOTP(ctx, userID, r, code)
	}

	normalized := normalizeRecovery(code)
	if len(normalized) != 10 {
		return false, ErrInvalidCode
	}
	ok, err := s.store.UseRecoveryCode(ctx, userID, hashRecovery(normalized))
	if err != nil {
		return false, err
	}
	if !ok {
		return false, ErrInvalidCode
	}
	return true, nil
}

func (s *Service) Disable(ctx context.Context, userID string) error {
	return s.store.Disable(ctx, userID)
}

func (s *Service) checkTOTP(ctx context.Context, userID string, r Record, code string) error {
	secret, err := s.cipher.open(r.Ciphertext, userID)
	if err != nil {
		return err
	}
	st, ok := validate(secret, strings.TrimSpace(code), s.now())
	if !ok {
		return ErrInvalidCode
	}
	fresh, err := s.store.UseStep(ctx, userID, st)
	if err != nil {
		return err
	}
	if !fresh {
		return ErrInvalidCode
	}
	return nil
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func normalizeRecovery(code string) string {
	code = strings.ToLower(code)
	return strings.NewReplacer("-", "", " ", "").Replace(code)
}

func hashRecovery(normalized string) [32]byte {
	return sha256.Sum256([]byte(normalized))
}
