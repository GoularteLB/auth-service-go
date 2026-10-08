package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GoularteLB/auth-service/internal/auth"
	"github.com/GoularteLB/auth-service/internal/password"
	"github.com/GoularteLB/auth-service/internal/user"
)

type fakeAuth struct {
	mu         sync.Mutex
	users      map[string]string
	sessions   map[string]string
	fail       error
	locked     time.Duration
	currentErr error
	seq        int
}

func newFakeAuth() *fakeAuth {
	return &fakeAuth{users: map[string]string{}, sessions: map[string]string{}}
}

func (f *fakeAuth) Signup(_ context.Context, email, plain string) error {
	if f.fail != nil {
		return f.fail
	}
	if err := password.Validate(plain); err != nil {
		return err
	}
	if !strings.Contains(email, "@") {
		return auth.ErrInvalidEmail
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.users[email]; !ok {
		f.users[email] = plain
	}
	return nil
}

func (f *fakeAuth) Login(_ context.Context, email, plain string) (string, error) {
	if f.fail != nil {
		return "", f.fail
	}
	if f.locked > 0 {
		return "", &auth.LockedError{RetryAfter: f.locked}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if p, ok := f.users[email]; !ok || p != plain {
		return "", auth.ErrInvalidCredentials
	}
	f.seq++
	token := "tok-" + email + "-" + strconv.Itoa(f.seq)
	f.sessions[token] = email
	return token, nil
}

func (f *fakeAuth) Logout(_ context.Context, token string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.sessions, token)
	return nil
}

func (f *fakeAuth) Current(_ context.Context, token string) (user.User, error) {
	if f.currentErr != nil {
		return user.User{}, f.currentErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	email, ok := f.sessions[token]
	if !ok {
		return user.User{}, auth.ErrUnauthenticated
	}
	return user.User{ID: "id-" + email, Email: email, PasswordHash: "nunca-expor"}, nil
}

type fakeLimiter struct {
	mu     sync.Mutex
	counts map[string]int
	err    error
}

func newFakeLimiter() *fakeLimiter {
	return &fakeLimiter{counts: map[string]int{}}
}

func (f *fakeLimiter) Allow(_ context.Context, key string, limit int, window time.Duration) (time.Duration, error) {
	if f.err != nil {
		return 0, f.err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counts[key]++
	if f.counts[key] > limit {
		return window, nil
	}
	return 0, nil
}

func newAuthTestHandler(t *testing.T, a *fakeAuth, production bool) http.Handler {
	t.Helper()
	return NewHandler(Deps{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Checks:     map[string]Pinger{},
		Auth:       a,
		Limiter:    newFakeLimiter(),
		SessionTTL: time.Hour,
		Production: production,
	})
}

func jsonRequest(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func sessionCookie(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

const credsJSON = `{"email":"ana@example.com","password":"uma-senha-bem-longa"}`

func TestSignupLoginMeLogout(t *testing.T) {
	h := newAuthTestHandler(t, newFakeAuth(), false)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, jsonRequest(http.MethodPost, "/v1/auth/signup", credsJSON))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("signup status = %d, esperado 202: %s", rec.Code, rec.Body)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, jsonRequest(http.MethodPost, "/v1/auth/login", credsJSON))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("login status = %d, esperado 204: %s", rec.Code, rec.Body)
	}
	cookie := sessionCookie(t, rec, "session")
	if cookie == nil || cookie.Value == "" {
		t.Fatal("login não devolveu cookie de sessão")
	}
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" {
		t.Errorf("atributos do cookie inseguros: %+v", cookie)
	}
	if strings.Contains(rec.Body.String(), cookie.Value) {
		t.Error("token apareceu no corpo da resposta")
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("me status = %d, esperado 200", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["email"] != "ana@example.com" {
		t.Errorf("email = %v", body["email"])
	}
	if strings.Contains(rec.Body.String(), "nunca-expor") {
		t.Fatal("hash de senha vazou no /me")
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d, esperado 204", rec.Code)
	}
	if c := sessionCookie(t, rec, "session"); c == nil || c.MaxAge >= 0 {
		t.Error("logout não limpou o cookie")
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("me após logout = %d, esperado 401", rec.Code)
	}
}

func TestProductionCookie(t *testing.T) {
	a := newFakeAuth()
	_ = a.Signup(context.Background(), "ana@example.com", "uma-senha-bem-longa")
	rec := httptest.NewRecorder()
	newAuthTestHandler(t, a, true).ServeHTTP(rec, jsonRequest(http.MethodPost, "/v1/auth/login", credsJSON))

	c := sessionCookie(t, rec, "__Host-session")
	if c == nil {
		t.Fatal("cookie __Host-session ausente em produção")
	}
	if !c.Secure || c.Domain != "" || c.Path != "/" {
		t.Errorf("cookie não cumpre o prefixo __Host-: %+v", c)
	}
}

func TestLoginReplacesPreviousSession(t *testing.T) {
	a := newFakeAuth()
	_ = a.Signup(context.Background(), "ana@example.com", "uma-senha-bem-longa")
	old, _ := a.Login(context.Background(), "ana@example.com", "uma-senha-bem-longa")

	req := jsonRequest(http.MethodPost, "/v1/auth/login", credsJSON)
	req.AddCookie(&http.Cookie{Name: "session", Value: old})
	rec := httptest.NewRecorder()
	newAuthTestHandler(t, a, false).ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rec.Code)
	}
	if _, ok := a.sessions[old]; ok {
		t.Fatal("sessão anterior continuou válida após novo login")
	}
	if c := sessionCookie(t, rec, "session"); c == nil || c.Value == old {
		t.Fatal("login reaproveitou o token antigo")
	}
}

func TestLoginWrongPassword(t *testing.T) {
	a := newFakeAuth()
	_ = a.Signup(context.Background(), "ana@example.com", "uma-senha-bem-longa")

	rec := httptest.NewRecorder()
	newAuthTestHandler(t, a, false).ServeHTTP(rec,
		jsonRequest(http.MethodPost, "/v1/auth/login", `{"email":"ana@example.com","password":"errada-errada-errada"}`))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, esperado 401", rec.Code)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("login falho devolveu cookie")
	}
}

func TestSignupValidationError(t *testing.T) {
	rec := httptest.NewRecorder()
	newAuthTestHandler(t, newFakeAuth(), false).ServeHTTP(rec,
		jsonRequest(http.MethodPost, "/v1/auth/signup", `{"email":"ana@example.com","password":"curta"}`))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, esperado 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "pelo menos") {
		t.Errorf("mensagem não explica a regra: %s", rec.Body)
	}
}

func TestInternalErrorDoesNotLeak(t *testing.T) {
	a := newFakeAuth()
	a.fail = errors.New("pq: senha do banco xyz123 errada")
	rec := httptest.NewRecorder()
	newAuthTestHandler(t, a, false).ServeHTTP(rec, jsonRequest(http.MethodPost, "/v1/auth/signup", credsJSON))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, esperado 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "xyz123") {
		t.Fatal("detalhe interno vazou na resposta")
	}
}

func TestDecodeRejectsBadBodies(t *testing.T) {
	h := newAuthTestHandler(t, newFakeAuth(), false)
	tests := []struct {
		name        string
		contentType string
		body        string
		want        int
	}{
		{"sem content-type", "", credsJSON, http.StatusUnsupportedMediaType},
		{"form", "application/x-www-form-urlencoded", "email=a&password=b", http.StatusUnsupportedMediaType},
		{"json quebrado", "application/json", `{"email":`, http.StatusBadRequest},
		{"campo desconhecido", "application/json", `{"email":"a@b.com","password":"x","admin":true}`, http.StatusBadRequest},
		{"dois objetos", "application/json", credsJSON + credsJSON, http.StatusBadRequest},
		{"grande demais", "application/json", `{"email":"` + strings.Repeat("a", maxCredentialsBytes) + `"}`, http.StatusRequestEntityTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(tt.body))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Errorf("status = %d, esperado %d", rec.Code, tt.want)
			}
		})
	}
}

func TestMeWithoutCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	newAuthTestHandler(t, newFakeAuth(), false).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, esperado 401", rec.Code)
	}
}

func TestCrossSiteLoginIsRejected(t *testing.T) {
	req := jsonRequest(http.MethodPost, "/v1/auth/login", credsJSON)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	newAuthTestHandler(t, newFakeAuth(), false).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, esperado 403", rec.Code)
	}
}

func TestLoginRateLimitedByIP(t *testing.T) {
	h := newAuthTestHandler(t, newFakeAuth(), false)
	body := `{"email":"ana@example.com","password":"errada-errada-errada"}`

	for range loginRate.Limit {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, jsonRequest(http.MethodPost, "/v1/auth/login", body))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, esperado 401", rec.Code)
		}
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, jsonRequest(http.MethodPost, "/v1/auth/login", body))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, esperado 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "60" {
		t.Errorf("Retry-After = %q, esperado 60", rec.Header().Get("Retry-After"))
	}

	req := jsonRequest(http.MethodPost, "/v1/auth/login", body)
	req.RemoteAddr = "198.51.100.7:4321"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("limite vazou para outro IP: status = %d", rec.Code)
	}
}

func TestRateLimiterFailureIsUnavailable(t *testing.T) {
	limiter := newFakeLimiter()
	limiter.err = errors.New("redis fora")
	h := NewHandler(Deps{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Checks:     map[string]Pinger{},
		Auth:       newFakeAuth(),
		Limiter:    limiter,
		SessionTTL: time.Hour,
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, jsonRequest(http.MethodPost, "/v1/auth/login", credsJSON))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, esperado 503", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "redis") {
		t.Fatal("detalhe interno vazou na resposta")
	}
}

func TestLockedLogin(t *testing.T) {
	a := newFakeAuth()
	a.locked = 90*time.Second + time.Millisecond
	rec := httptest.NewRecorder()
	newAuthTestHandler(t, a, false).ServeHTTP(rec, jsonRequest(http.MethodPost, "/v1/auth/login", credsJSON))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, esperado 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "91" {
		t.Errorf("Retry-After = %q, esperado 91", rec.Header().Get("Retry-After"))
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("login bloqueado devolveu cookie")
	}
}
