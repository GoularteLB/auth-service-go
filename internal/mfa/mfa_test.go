package mfa

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHOTPRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	vectors := map[int64]string{
		59:          "94287082",
		1111111109:  "07081804",
		1111111111:  "14050471",
		1234567890:  "89005924",
		2000000000:  "69279037",
		20000000000: "65353130",
	}
	for unix, want := range vectors {
		if got := hotp(secret, uint64(step(time.Unix(unix, 0))), 8); got != want {
			t.Errorf("T=%d: %s, esperado %s", unix, got, want)
		}
	}
}

func TestValidateWindow(t *testing.T) {
	secret := newSecret()
	now := time.Unix(1_700_000_000, 0)
	code := hotp(secret, uint64(step(now)), digits)

	for _, delta := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		if _, ok := validate(secret, code, now.Add(delta)); !ok {
			t.Errorf("código recusado com desvio de %v", delta)
		}
	}
	for _, delta := range []time.Duration{-90 * time.Second, 90 * time.Second} {
		if _, ok := validate(secret, code, now.Add(delta)); ok {
			t.Errorf("código aceito com desvio de %v", delta)
		}
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if _, ok := validate(secret, bad, now); ok {
			t.Errorf("aceitou %q", bad)
		}
	}
}

func TestOTPAuthURI(t *testing.T) {
	uri := otpauthURI("Minha App", "ana@example.com", []byte("12345678901234567890"))
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" {
		t.Fatalf("uri = %s", uri)
	}
	q := u.Query()
	if q.Get("secret") != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" || q.Get("issuer") != "Minha App" || q.Get("digits") != "6" {
		t.Errorf("parâmetros errados: %v", q)
	}
	if !strings.HasPrefix(u.Path, "/Minha App:ana@example.com") {
		t.Errorf("label = %q", u.Path)
	}
}

func TestCipherBindsToUser(t *testing.T) {
	c, err := NewCipher(GenerateKey())
	if err != nil {
		t.Fatal(err)
	}
	sealed := c.seal([]byte("segredo"), "user-1")
	if strings.Contains(string(sealed), "segredo") {
		t.Fatal("segredo em claro no texto cifrado")
	}
	plain, err := c.open(sealed, "user-1")
	if err != nil || string(plain) != "segredo" {
		t.Fatalf("open = %q, %v", plain, err)
	}
	if _, err := c.open(sealed, "user-2"); !errors.Is(err, ErrDecrypt) {
		t.Fatal("segredo de um usuário abriu para outro")
	}
	other, _ := NewCipher(GenerateKey())
	if _, err := other.open(sealed, "user-1"); !errors.Is(err, ErrDecrypt) {
		t.Fatal("abriu com outra chave")
	}
	if _, err := c.open([]byte("curto"), "user-1"); !errors.Is(err, ErrDecrypt) {
		t.Fatal("aceitou texto cifrado truncado")
	}
}

func TestParseKey(t *testing.T) {
	if _, err := ParseKey("nao-e-base64!"); err == nil {
		t.Error("aceitou chave fora de base64")
	}
	if _, err := ParseKey("c2hvcnQ="); err == nil {
		t.Error("aceitou chave curta")
	}
	if _, err := ParseKey(base64.StdEncoding.EncodeToString(make([]byte, KeySize))); err != nil {
		t.Fatal(err)
	}
}

type memStore struct {
	mu    sync.Mutex
	recs  map[string]*memRecord
	codes map[string]map[[32]byte]bool
}

type memRecord struct {
	ciphertext []byte
	enabled    bool
	lastStep   int64
}

func newMemStore() *memStore {
	return &memStore{recs: map[string]*memRecord{}, codes: map[string]map[[32]byte]bool{}}
}

func (m *memStore) Get(_ context.Context, userID string) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.recs[userID]
	if !ok {
		return Record{}, ErrNotEnabled
	}
	return Record{Ciphertext: r.ciphertext, Enabled: r.enabled}, nil
}

func (m *memStore) SavePending(_ context.Context, userID string, ct []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.recs[userID]; ok && r.enabled {
		return ErrAlreadyEnabled
	}
	m.recs[userID] = &memRecord{ciphertext: ct}
	return nil
}

func (m *memStore) Enable(_ context.Context, userID string, hashes [][32]byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.recs[userID]
	if r.enabled {
		return ErrAlreadyEnabled
	}
	r.enabled = true
	m.codes[userID] = map[[32]byte]bool{}
	for _, h := range hashes {
		m.codes[userID][h] = false
	}
	return nil
}

func (m *memStore) Disable(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.recs, userID)
	delete(m.codes, userID)
	return nil
}

func (m *memStore) UseStep(_ context.Context, userID string, step int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.recs[userID]
	if step <= r.lastStep {
		return false, nil
	}
	r.lastStep = step
	return true, nil
}

func (m *memStore) UseRecoveryCode(_ context.Context, userID string, h [32]byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	used, ok := m.codes[userID][h]
	if !ok || used {
		return false, nil
	}
	m.codes[userID][h] = true
	return true, nil
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTestService(t *testing.T) (*Service, *clock) {
	t.Helper()
	c, err := NewCipher(GenerateKey())
	if err != nil {
		t.Fatal(err)
	}
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	svc := NewService(newMemStore(), c, "auth-service")
	svc.now = clk.now
	return svc, clk
}

func currentCode(t *testing.T, setup Setup, now time.Time) string {
	t.Helper()
	secret, err := b32.DecodeString(setup.Secret)
	if err != nil {
		t.Fatal(err)
	}
	return hotp(secret, uint64(step(now)), digits)
}

func TestEnrollVerifyDisable(t *testing.T) {
	svc, clk := newTestService(t)
	ctx := context.Background()

	if on, _ := svc.Enabled(ctx, "user-1"); on {
		t.Fatal("mfa ativo sem configurar")
	}
	if _, err := svc.Enable(ctx, "user-1", "123456"); !errors.Is(err, ErrNoPendingSetup) {
		t.Fatalf("ativar sem setup: %v", err)
	}

	setup, err := svc.Setup(ctx, "user-1", "ana@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(setup.URI, "secret="+setup.Secret) {
		t.Errorf("uri não traz o segredo: %s", setup.URI)
	}
	if on, _ := svc.Enabled(ctx, "user-1"); on {
		t.Fatal("setup pendente já conta como ativo")
	}
	if _, err := svc.Enable(ctx, "user-1", "000000"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("código errado ativou: %v", err)
	}

	codes, err := svc.Enable(ctx, "user-1", currentCode(t, setup, clk.t))
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != recoveryCodeCount || len(codes[0]) != 11 || codes[0][5] != '-' {
		t.Fatalf("códigos de recuperação inesperados: %v", codes)
	}
	if on, _ := svc.Enabled(ctx, "user-1"); !on {
		t.Fatal("mfa não ficou ativo")
	}
	if _, err := svc.Setup(ctx, "user-1", "ana@example.com"); !errors.Is(err, ErrAlreadyEnabled) {
		t.Fatalf("setup por cima de mfa ativo: %v", err)
	}

	if _, err := svc.Verify(ctx, "user-1", currentCode(t, setup, clk.t)); !errors.Is(err, ErrInvalidCode) {
		t.Fatal("o mesmo código foi aceito duas vezes")
	}
	clk.t = clk.t.Add(30 * time.Second)
	recovery, err := svc.Verify(ctx, "user-1", currentCode(t, setup, clk.t))
	if err != nil || recovery {
		t.Fatalf("código novo recusado: %v", err)
	}

	recovery, err = svc.Verify(ctx, "user-1", " "+strings.ToUpper(codes[3])+" ")
	if err != nil || !recovery {
		t.Fatalf("código de recuperação recusado: %v", err)
	}
	if _, err := svc.Verify(ctx, "user-1", codes[3]); !errors.Is(err, ErrInvalidCode) {
		t.Fatal("código de recuperação usado duas vezes")
	}
	if _, err := svc.Verify(ctx, "user-1", "abcde-fghij"); !errors.Is(err, ErrInvalidCode) {
		t.Fatal("código de recuperação inventado foi aceito")
	}

	if err := svc.Disable(ctx, "user-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Verify(ctx, "user-1", codes[4]); !errors.Is(err, ErrNotEnabled) {
		t.Fatalf("verificação depois de desativar: %v", err)
	}
}

func TestSetupReplacesPendingSecret(t *testing.T) {
	svc, clk := newTestService(t)
	ctx := context.Background()
	first, _ := svc.Setup(ctx, "user-1", "ana@example.com")
	second, _ := svc.Setup(ctx, "user-1", "ana@example.com")
	if first.Secret == second.Secret {
		t.Fatal("setup repetido reaproveitou o segredo")
	}
	if _, err := svc.Enable(ctx, "user-1", currentCode(t, first, clk.t)); !errors.Is(err, ErrInvalidCode) {
		t.Fatal("segredo do setup anterior ainda ativa")
	}
}
