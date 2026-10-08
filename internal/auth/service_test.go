package auth

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GoularteLB/auth-service/internal/audit"
	"github.com/GoularteLB/auth-service/internal/password"
	"github.com/GoularteLB/auth-service/internal/session"
	"github.com/GoularteLB/auth-service/internal/user"
)

type fakeUsers struct {
	mu      sync.Mutex
	byEmail map[string]user.User
	seq     int
}

func newFakeUsers() *fakeUsers {
	return &fakeUsers{byEmail: map[string]user.User{}}
}

func (f *fakeUsers) Create(_ context.Context, email, hash string) (user.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.byEmail[email]; ok {
		return user.User{}, user.ErrEmailTaken
	}
	f.seq++
	u := user.User{ID: strconv.Itoa(f.seq), Email: email, PasswordHash: hash, CreatedAt: time.Now()}
	f.byEmail[email] = u
	return u, nil
}

func (f *fakeUsers) ByEmail(_ context.Context, email string) (user.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byEmail[email]
	if !ok {
		return user.User{}, user.ErrNotFound
	}
	return u, nil
}

func (f *fakeUsers) ByID(_ context.Context, id string) (user.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.byEmail {
		if u.ID == id {
			return u, nil
		}
	}
	return user.User{}, user.ErrNotFound
}

func (f *fakeUsers) UpdatePasswordHash(_ context.Context, id, hash string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for email, u := range f.byEmail {
		if u.ID == id {
			u.PasswordHash = hash
			f.byEmail[email] = u
			return nil
		}
	}
	return user.ErrNotFound
}

type fakeSessions struct {
	mu   sync.Mutex
	data map[string]session.Session
}

func newFakeSessions() *fakeSessions {
	return &fakeSessions{data: map[string]session.Session{}}
}

func (f *fakeSessions) Create(_ context.Context, userID string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	token := "tok-" + strconv.Itoa(len(f.data)+1)
	f.data[token] = session.Session{UserID: userID, CreatedAt: time.Now()}
	return token, nil
}

func (f *fakeSessions) Get(_ context.Context, token string) (session.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.data[token]
	if !ok {
		return session.Session{}, session.ErrNotFound
	}
	return s, nil
}

func (f *fakeSessions) Delete(_ context.Context, token string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.data, token)
	return nil
}

type fakeLockout struct {
	mu        sync.Mutex
	threshold int
	fails     map[string]int
	resets    int
}

func newFakeLockout(threshold int) *fakeLockout {
	return &fakeLockout{threshold: threshold, fails: map[string]int{}}
}

func (f *fakeLockout) Check(_ context.Context, key string) (time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fails[key] >= f.threshold {
		return time.Minute, nil
	}
	return 0, nil
}

func (f *fakeLockout) Fail(_ context.Context, key string) (time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fails[key]++
	return 0, nil
}

func (f *fakeLockout) Reset(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.fails, key)
	f.resets++
	return nil
}

type fakeAudit struct {
	mu     sync.Mutex
	events []audit.Event
	err    error
}

func (f *fakeAudit) Record(_ context.Context, e audit.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
	return f.err
}

func (f *fakeAudit) types() []audit.Type {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]audit.Type, len(f.events))
	for i, e := range f.events {
		out[i] = e.Type
	}
	return out
}

var testParams = password.Params{Memory: 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}

type testEnv struct {
	svc      *Service
	users    *fakeUsers
	sessions *fakeSessions
	lockout  *fakeLockout
	audit    *fakeAudit
}

func newTestEnv(t *testing.T, params password.Params) testEnv {
	t.Helper()
	hasher, err := password.NewHasher(params, 2)
	if err != nil {
		t.Fatal(err)
	}
	env := testEnv{
		users:    newFakeUsers(),
		sessions: newFakeSessions(),
		lockout:  newFakeLockout(1000),
		audit:    &fakeAudit{},
	}
	env.svc = NewService(Deps{
		Users:    env.users,
		Sessions: env.sessions,
		Hasher:   hasher,
		Lockout:  env.lockout,
		Audit:    env.audit,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return env
}

func newTestService(t *testing.T, params password.Params) (*Service, *fakeUsers, *fakeSessions) {
	t.Helper()
	env := newTestEnv(t, params)
	return env.svc, env.users, env.sessions
}

const goodPassword = "uma-senha-bem-longa"

func TestSignupAndLogin(t *testing.T) {
	svc, users, _ := newTestService(t, testParams)
	ctx := context.Background()

	if err := svc.Signup(ctx, "  Ana@Example.com ", goodPassword); err != nil {
		t.Fatal(err)
	}
	u, err := users.ByEmail(ctx, "ana@example.com")
	if err != nil {
		t.Fatalf("usuário não foi salvo com e-mail normalizado: %v", err)
	}
	if strings.Contains(u.PasswordHash, goodPassword) {
		t.Fatal("senha salva em texto puro")
	}

	token, err := svc.Login(ctx, "ANA@example.com", goodPassword)
	if err != nil {
		t.Fatal(err)
	}

	current, err := svc.Current(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if current.ID != u.ID {
		t.Errorf("Current devolveu %q, esperado %q", current.ID, u.ID)
	}
}

func TestSignupDuplicateLooksLikeSuccess(t *testing.T) {
	svc, _, _ := newTestService(t, testParams)
	ctx := context.Background()

	if err := svc.Signup(ctx, "ana@example.com", goodPassword); err != nil {
		t.Fatal(err)
	}
	if err := svc.Signup(ctx, "ana@example.com", "outra-senha-qualquer"); err != nil {
		t.Fatalf("cadastro duplicado deveria parecer sucesso, recebeu %v", err)
	}
	if _, err := svc.Login(ctx, "ana@example.com", "outra-senha-qualquer"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("cadastro duplicado sobrescreveu a senha original")
	}
}

func TestSignupValidation(t *testing.T) {
	svc, _, _ := newTestService(t, testParams)
	tests := []struct {
		name, email, password string
		want                  error
	}{
		{"e-mail vazio", "", goodPassword, ErrInvalidEmail},
		{"sem arroba", "ana.example.com", goodPassword, ErrInvalidEmail},
		{"sem domínio com ponto", "ana@localhost", goodPassword, ErrInvalidEmail},
		{"com nome", "Ana <ana@example.com>", goodPassword, ErrInvalidEmail},
		{"e-mail longo", strings.Repeat("a", 250) + "@x.com", goodPassword, ErrInvalidEmail},
		{"senha curta", "ana@example.com", "curta", password.ErrTooShort},
		{"senha longa", "ana@example.com", strings.Repeat("a", password.MaxLength+1), password.ErrTooLong},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := svc.Signup(context.Background(), tt.email, tt.password); !errors.Is(err, tt.want) {
				t.Errorf("erro = %v, esperado %v", err, tt.want)
			}
		})
	}
}

func TestLoginFailuresAreIndistinguishable(t *testing.T) {
	svc, _, sessions := newTestService(t, testParams)
	ctx := context.Background()
	if err := svc.Signup(ctx, "ana@example.com", goodPassword); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ email, password string }{
		{"ana@example.com", "senha-errada-aqui"},
		{"ninguem@example.com", goodPassword},
		{"isso-nao-e-email", goodPassword},
		{"ana@example.com", strings.Repeat("a", 10_000)},
	} {
		if _, err := svc.Login(ctx, tc.email, tc.password); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("Login(%q) = %v, esperado ErrInvalidCredentials", tc.email, err)
		}
	}
	if len(sessions.data) != 0 {
		t.Errorf("login inválido criou %d sessão(ões)", len(sessions.data))
	}
}

func TestLoginRehashesOutdatedHash(t *testing.T) {
	weak, users, sessions := newTestService(t, testParams)
	ctx := context.Background()
	if err := weak.Signup(ctx, "ana@example.com", goodPassword); err != nil {
		t.Fatal(err)
	}
	before, _ := users.ByEmail(ctx, "ana@example.com")

	hasher, err := password.NewHasher(password.Params{Memory: 2048, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}, 1)
	if err != nil {
		t.Fatal(err)
	}
	strong := NewService(Deps{
		Users:    users,
		Sessions: sessions,
		Hasher:   hasher,
		Lockout:  newFakeLockout(1000),
		Audit:    &fakeAudit{},
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if _, err := strong.Login(ctx, "ana@example.com", goodPassword); err != nil {
		t.Fatal(err)
	}

	after, _ := users.ByEmail(ctx, "ana@example.com")
	if after.PasswordHash == before.PasswordHash || !strings.Contains(after.PasswordHash, "m=2048") {
		t.Fatalf("hash não foi atualizado: %s", after.PasswordHash)
	}
}

func TestLogoutInvalidatesSession(t *testing.T) {
	svc, _, _ := newTestService(t, testParams)
	ctx := context.Background()
	_ = svc.Signup(ctx, "ana@example.com", goodPassword)
	token, err := svc.Login(ctx, "ana@example.com", goodPassword)
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.Logout(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Current(ctx, token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("sessão continuou válida após logout: %v", err)
	}
}

func TestCurrentDropsOrphanSession(t *testing.T) {
	svc, _, sessions := newTestService(t, testParams)
	ctx := context.Background()
	token, _ := sessions.Create(ctx, "id-que-nao-existe")

	if _, err := svc.Current(ctx, token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("esperava ErrUnauthenticated, recebeu %v", err)
	}
	if _, ok := sessions.data[token]; ok {
		t.Fatal("sessão órfã não foi apagada")
	}
}

func TestLoginLockedAccount(t *testing.T) {
	env := newTestEnv(t, testParams)
	env.lockout.threshold = 3
	ctx := context.Background()
	_ = env.svc.Signup(ctx, "ana@example.com", goodPassword)

	for range 3 {
		if _, err := env.svc.Login(ctx, "ana@example.com", "senha-errada-aqui"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("esperava ErrInvalidCredentials, recebeu %v", err)
		}
	}

	_, err := env.svc.Login(ctx, "ana@example.com", goodPassword)
	var locked *LockedError
	if !errors.As(err, &locked) || !errors.Is(err, ErrLocked) {
		t.Fatalf("esperava LockedError, recebeu %v", err)
	}
	if locked.RetryAfter <= 0 {
		t.Error("RetryAfter deveria ser positivo")
	}
	if len(env.sessions.data) != 0 {
		t.Fatal("conta bloqueada recebeu sessão")
	}
}

func TestLockoutAppliesToUnknownEmails(t *testing.T) {
	env := newTestEnv(t, testParams)
	env.lockout.threshold = 2
	ctx := context.Background()

	for range 2 {
		_, _ = env.svc.Login(ctx, "Ninguem@Example.com", goodPassword)
	}
	if _, err := env.svc.Login(ctx, "ninguem@example.com", goodPassword); !errors.Is(err, ErrLocked) {
		t.Fatalf("e-mail inexistente deveria bloquear igual a um existente, recebeu %v", err)
	}
}

func TestSuccessfulLoginResetsLockout(t *testing.T) {
	env := newTestEnv(t, testParams)
	env.lockout.threshold = 3
	ctx := context.Background()
	_ = env.svc.Signup(ctx, "ana@example.com", goodPassword)

	_, _ = env.svc.Login(ctx, "ana@example.com", "senha-errada-aqui")
	_, _ = env.svc.Login(ctx, "ana@example.com", "senha-errada-aqui")
	if _, err := env.svc.Login(ctx, "ana@example.com", goodPassword); err != nil {
		t.Fatal(err)
	}
	if env.lockout.fails["ana@example.com"] != 0 {
		t.Fatal("login bem-sucedido não zerou as falhas")
	}
}

func TestAuditTrail(t *testing.T) {
	env := newTestEnv(t, testParams)
	env.lockout.threshold = 1
	ctx := context.Background()

	_ = env.svc.Signup(ctx, "ana@example.com", goodPassword)
	_ = env.svc.Signup(ctx, "ana@example.com", goodPassword)
	token, err := env.svc.Login(ctx, "ana@example.com", goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	_ = env.svc.Logout(ctx, token)
	_ = env.svc.Logout(ctx, token)
	_, _ = env.svc.Login(ctx, "ana@example.com", "senha-errada-aqui")
	_, _ = env.svc.Login(ctx, "ana@example.com", goodPassword)

	want := []audit.Type{
		audit.SignupCreated,
		audit.SignupDuplicate,
		audit.LoginSucceeded,
		audit.LoggedOut,
		audit.LoginFailed,
		audit.LoginLocked,
	}
	got := env.audit.types()
	if len(got) != len(want) {
		t.Fatalf("eventos = %v, esperado %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("eventos = %v, esperado %v", got, want)
		}
	}

	for _, e := range env.audit.events {
		if e.Type != audit.SignupDuplicate && e.Type != audit.LoginLocked && e.UserID == "" {
			t.Errorf("evento %s sem user_id", e.Type)
		}
	}
}

func TestAuditFailureDoesNotBreakLogin(t *testing.T) {
	env := newTestEnv(t, testParams)
	env.audit.err = errors.New("banco fora")
	ctx := context.Background()

	if err := env.svc.Signup(ctx, "ana@example.com", goodPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := env.svc.Login(ctx, "ana@example.com", goodPassword); err != nil {
		t.Fatalf("falha de auditoria derrubou o login: %v", err)
	}
}
