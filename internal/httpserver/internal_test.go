package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/GoularteLB/auth-service/internal/token"
	"github.com/GoularteLB/auth-service/pkg/authn"
)

func newInternalTestHandler(t *testing.T, a *fakeAuth) (http.Handler, *token.Issuer) {
	t.Helper()
	key, err := token.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	iss := token.NewIssuer(key, nil, token.Options{Issuer: "auth-service", Audience: "internal", TTL: 5 * time.Minute})
	return NewInternalHandler(InternalDeps{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Auth:   a,
		Tokens: iss,
	}), iss
}

func TestJWKSEndpoint(t *testing.T) {
	h, iss := newInternalTestHandler(t, newFakeAuth())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Cache-Control"), "max-age") {
		t.Errorf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}
	var set authn.JWKS
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 1 || set.Keys[0].Kid != iss.KeyID() {
		t.Fatalf("jwks inesperado: %+v", set)
	}
	if strings.Contains(rec.Body.String(), `"d"`) {
		t.Fatal("jwks expôs a parte privada da chave")
	}
}

func TestExchangeSessionForToken(t *testing.T) {
	a := newFakeAuth()
	_ = a.Signup(context.Background(), "ana@example.com", "uma-senha-bem-longa")
	session, _ := a.Login(context.Background(), "ana@example.com", "uma-senha-bem-longa")
	h, iss := newInternalTestHandler(t, a)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, jsonRequest(http.MethodPost, "/internal/v1/token", `{"session_token":"`+session+`"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("resposta com token precisa de no-store")
	}

	var resp tokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.TokenType != "Bearer" || resp.ExpiresIn != 300 {
		t.Errorf("resposta inesperada: %+v", resp)
	}

	pub, _ := iss.JWKS().Keys[0].PublicKey()
	v := &authn.Verifier{Keys: authn.StaticKeys{iss.KeyID(): pub}, Issuer: "auth-service", Audience: "internal"}
	c, err := v.Verify(context.Background(), resp.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "id-ana@example.com" {
		t.Errorf("sub = %q", c.Subject)
	}
}

func TestExchangeRejects(t *testing.T) {
	h, _ := newInternalTestHandler(t, newFakeAuth())
	tests := []struct {
		name, body string
		want       int
	}{
		{"sessão inexistente", `{"session_token":"nao-existe"}`, http.StatusUnauthorized},
		{"sessão vazia", `{"session_token":""}`, http.StatusUnauthorized},
		{"campo extra", `{"session_token":"x","sub":"admin"}`, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, jsonRequest(http.MethodPost, "/internal/v1/token", tt.body))
			if rec.Code != tt.want {
				t.Errorf("status = %d, esperado %d", rec.Code, tt.want)
			}
		})
	}
}

func TestExchangeInternalError(t *testing.T) {
	a := newFakeAuth()
	a.currentErr = errors.New("redis: senha xyz123")
	h, _ := newInternalTestHandler(t, a)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, jsonRequest(http.MethodPost, "/internal/v1/token", `{"session_token":"x"}`))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "xyz123") {
		t.Fatal("detalhe interno vazou")
	}
}

func TestPublicHandlerDoesNotExposeTokenRoutes(t *testing.T) {
	h := newAuthTestHandler(t, newFakeAuth(), false)
	for _, path := range []string{"/internal/v1/token", "/.well-known/jwks.json"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, jsonRequest(http.MethodPost, path, `{}`))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s no listener público: status = %d, esperado 404", path, rec.Code)
		}
	}
}

func TestMicroserviceAcceptsExchangedToken(t *testing.T) {
	a := newFakeAuth()
	_ = a.Signup(context.Background(), "ana@example.com", "uma-senha-bem-longa")
	session, _ := a.Login(context.Background(), "ana@example.com", "uma-senha-bem-longa")
	h, _ := newInternalTestHandler(t, a)
	authSrv := httptest.NewServer(h)
	t.Cleanup(authSrv.Close)

	resp, err := http.Post(authSrv.URL+"/internal/v1/token", "application/json",
		strings.NewReader(`{"session_token":"`+session+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	var tok tokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tok)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}

	keys, err := authn.NewRemoteKeys(authSrv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	verifier := &authn.Verifier{Keys: keys, Issuer: "auth-service", Audience: "internal", Leeway: 30 * time.Second}
	service := verifier.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := authn.ClaimsFrom(r.Context())
		_, _ = w.Write([]byte(c.Subject))
	}))

	req := httptest.NewRequest(http.MethodGet, "/pedidos", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	rec := httptest.NewRecorder()
	service.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "id-ana@example.com" {
		t.Fatalf("microsserviço recusou o token: %d %s", rec.Code, rec.Body)
	}

	req = httptest.NewRequest(http.MethodGet, "/pedidos", nil)
	req.Header.Set("Authorization", "Bearer "+session)
	rec = httptest.NewRecorder()
	service.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("microsserviço aceitou o token de sessão cru: %d", rec.Code)
	}
}
