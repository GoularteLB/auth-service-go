package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/GoularteLB/auth-service/internal/audit"
	"github.com/GoularteLB/auth-service/internal/client"
	"github.com/GoularteLB/auth-service/internal/token"
	"github.com/GoularteLB/auth-service/pkg/authn"
)

type memClients map[string]struct {
	secret    string
	scopes    []string
	audiences []string
}

func (m memClients) Active(_ context.Context, id string) (client.Client, [32]byte, error) {
	c, ok := m[id]
	if !ok {
		return client.Client{}, [32]byte{}, client.ErrNotFound
	}
	return client.Client{ClientID: id, Scopes: c.scopes, Audiences: c.audiences}, client.HashSecret(c.secret), nil
}

type discardAudit struct{}

func (discardAudit) Record(context.Context, audit.Event) error { return nil }

type internalEnv struct {
	handler http.Handler
	issuer  *token.Issuer
	limiter *fakeLimiter
}

func newInternalEnv(t *testing.T, a *fakeAuth) internalEnv {
	t.Helper()
	key, err := token.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	iss := token.NewIssuer(key, nil, token.Options{Issuer: "auth-service", Audience: "internal", TTL: 5 * time.Minute})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo := memClients{
		"cli_bff":     {secret: "segredo-bff", scopes: []string{client.ScopeSessionExchange}},
		"cli_bff_aud": {secret: "segredo-bff", scopes: []string{client.ScopeSessionExchange}, audiences: []string{"pedidos"}},
		"cli_pedidos": {secret: "segredo-pedidos", scopes: []string{"estoque:ler", "estoque:escrever"}},
	}
	limiter := newFakeLimiter()
	return internalEnv{
		handler: NewInternalHandler(InternalDeps{
			Logger:  logger,
			Auth:    a,
			Clients: client.NewService(repo, iss, discardAudit{}, logger),
			Tokens:  iss,
			Limiter: limiter,
		}),
		issuer:  iss,
		limiter: limiter,
	}
}

func (e internalEnv) verifier() *authn.Verifier {
	pub, _ := e.issuer.JWKS().Keys[0].PublicKey()
	return &authn.Verifier{Keys: authn.StaticKeys{e.issuer.KeyID(): pub}, Issuer: "auth-service", Audience: "internal"}
}

func exchangeRequestFor(session, id, secret string) *http.Request {
	req := jsonRequest(http.MethodPost, "/internal/v1/token", `{"session_token":"`+session+`"}`)
	if id != "" {
		req.SetBasicAuth(id, secret)
	}
	return req
}

func clientTokenRequest(form url.Values, id, secret string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if id != "" {
		req.SetBasicAuth(id, secret)
	}
	return req
}

func loggedInSession(t *testing.T, a *fakeAuth) string {
	t.Helper()
	_ = a.Signup(context.Background(), "ana@example.com", "uma-senha-bem-longa")
	session, err := a.Login(context.Background(), "ana@example.com", "uma-senha-bem-longa")
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func TestJWKSEndpoint(t *testing.T) {
	env := newInternalEnv(t, newFakeAuth())
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))

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
	if len(set.Keys) != 1 || set.Keys[0].Kid != env.issuer.KeyID() {
		t.Fatalf("jwks inesperado: %+v", set)
	}
	if strings.Contains(rec.Body.String(), `"d"`) {
		t.Fatal("jwks expôs a parte privada da chave")
	}
}

func TestExchangeSessionForToken(t *testing.T) {
	a := newFakeAuth()
	session := loggedInSession(t, a)
	env := newInternalEnv(t, a)

	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, exchangeRequestFor(session, "cli_bff", "segredo-bff"))
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

	c, err := env.verifier().Verify(context.Background(), resp.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "id-ana@example.com" || c.ClientID != "cli_bff" || c.IsService() {
		t.Errorf("claims inesperadas: %+v", c)
	}
	if !c.HasAMR(authn.AMRPassword) || c.HasAMR(authn.AMRMFA) {
		t.Errorf("amr = %v", c.AMR)
	}
}

func TestExchangeWithAudience(t *testing.T) {
	a := newFakeAuth()
	session := loggedInSession(t, a)
	env := newInternalEnv(t, a)
	pub, _ := env.issuer.JWKS().Keys[0].PublicKey()
	keys := authn.StaticKeys{env.issuer.KeyID(): pub}

	req := jsonRequest(http.MethodPost, "/internal/v1/token", `{"session_token":"`+session+`","audience":"pedidos"}`)
	req.SetBasicAuth("cli_bff_aud", "segredo-bff")
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	var resp tokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	pedidos := &authn.Verifier{Keys: keys, Issuer: "auth-service", Audience: "pedidos"}
	if _, err := pedidos.Verify(context.Background(), resp.AccessToken); err != nil {
		t.Fatalf("pedidos recusou o token dele: %v", err)
	}
	if _, err := env.verifier().Verify(context.Background(), resp.AccessToken); !errors.Is(err, authn.ErrWrongAudience) {
		t.Fatalf("token de pedidos valeu na audiência genérica: %v", err)
	}

	for _, body := range []string{
		`{"session_token":"` + session + `","audience":"pagamentos"}`,
		`{"session_token":"` + session + `"}`,
	} {
		req = jsonRequest(http.MethodPost, "/internal/v1/token", body)
		req.SetBasicAuth("cli_bff_aud", "segredo-bff")
		rec = httptest.NewRecorder()
		env.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_target") {
			t.Fatalf("%s: %d %s", body, rec.Code, rec.Body)
		}
	}
}

func TestExchangeAuthenticatesBeforeReadingBody(t *testing.T) {
	env := newInternalEnv(t, newFakeAuth())
	req := jsonRequest(http.MethodPost, "/internal/v1/token", `{isso não é json`)
	req.SetBasicAuth("cli_bff", "errado")
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "invalid_client") {
		t.Fatalf("corpo foi lido antes de autenticar: %d %s", rec.Code, rec.Body)
	}
}

func TestExchangeCarriesMFA(t *testing.T) {
	a := newFakeAuth()
	session, err := a.LoginMFA(context.Background(), "desafio-ok", "123456")
	if err != nil {
		t.Fatal(err)
	}
	env := newInternalEnv(t, a)

	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, exchangeRequestFor(session, "cli_bff", "segredo-bff"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	var resp tokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	c, err := env.verifier().Verify(context.Background(), resp.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if !c.HasAMR(authn.AMRMFA) || !c.HasAMR(authn.AMROTP) {
		t.Errorf("amr = %v", c.AMR)
	}
}

func TestExchangeRequiresAuthorizedClient(t *testing.T) {
	a := newFakeAuth()
	session := loggedInSession(t, a)
	env := newInternalEnv(t, a)

	tests := []struct {
		name, id, secret string
		want             int
	}{
		{"sem cliente", "", "", http.StatusUnauthorized},
		{"segredo errado", "cli_bff", "errado", http.StatusUnauthorized},
		{"cliente desconhecido", "cli_x", "segredo-bff", http.StatusUnauthorized},
		{"cliente sem escopo de troca", "cli_pedidos", "segredo-pedidos", http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			env.handler.ServeHTTP(rec, exchangeRequestFor(session, tt.id, tt.secret))
			if rec.Code != tt.want {
				t.Errorf("status = %d, esperado %d", rec.Code, tt.want)
			}
			if strings.Contains(rec.Body.String(), "access_token") {
				t.Fatal("token emitido para cliente não autorizado")
			}
		})
	}
}

func TestExchangeRejects(t *testing.T) {
	env := newInternalEnv(t, newFakeAuth())
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
			req := jsonRequest(http.MethodPost, "/internal/v1/token", tt.body)
			req.SetBasicAuth("cli_bff", "segredo-bff")
			rec := httptest.NewRecorder()
			env.handler.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Errorf("status = %d, esperado %d", rec.Code, tt.want)
			}
		})
	}
}

func TestExchangeInternalError(t *testing.T) {
	a := newFakeAuth()
	a.currentErr = errors.New("redis: senha xyz123")
	env := newInternalEnv(t, a)

	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, exchangeRequestFor("x", "cli_bff", "segredo-bff"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "xyz123") {
		t.Fatal("detalhe interno vazou")
	}
}

func TestClientCredentials(t *testing.T) {
	env := newInternalEnv(t, newFakeAuth())

	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, clientTokenRequest(url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"estoque:ler"},
	}, "cli_pedidos", "segredo-pedidos"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}

	var resp tokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Scope != "estoque:ler" || resp.TokenType != "Bearer" {
		t.Errorf("resposta inesperada: %+v", resp)
	}
	c, err := env.verifier().Verify(context.Background(), resp.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsService() || c.Subject != "cli_pedidos" || !c.HasScope("estoque:ler") || c.HasScope("estoque:escrever") {
		t.Errorf("claims inesperadas: %+v", c)
	}
}

func TestClientCredentialsErrors(t *testing.T) {
	env := newInternalEnv(t, newFakeAuth())
	good := url.Values{"grant_type": {"client_credentials"}}

	tests := []struct {
		name       string
		req        *http.Request
		wantStatus int
		wantError  string
	}{
		{"sem basic", clientTokenRequest(good, "", ""), http.StatusUnauthorized, "invalid_client"},
		{"segredo errado", clientTokenRequest(good, "cli_pedidos", "errado"), http.StatusUnauthorized, "invalid_client"},
		{"grant errado", clientTokenRequest(url.Values{"grant_type": {"password"}}, "cli_pedidos", "segredo-pedidos"), http.StatusBadRequest, "unsupported_grant_type"},
		{"escopo que não tem", clientTokenRequest(url.Values{"grant_type": {"client_credentials"}, "scope": {"admin"}}, "cli_pedidos", "segredo-pedidos"), http.StatusBadRequest, "invalid_scope"},
		{"audiência que não tem", clientTokenRequest(url.Values{"grant_type": {"client_credentials"}, "audience": {"pagamentos"}}, "cli_pedidos", "segredo-pedidos"), http.StatusBadRequest, "invalid_target"},
		{"segredo no corpo", clientTokenRequest(url.Values{"grant_type": {"client_credentials"}, "client_id": {"cli_pedidos"}, "client_secret": {"segredo-pedidos"}}, "", ""), http.StatusBadRequest, "invalid_request"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			env.handler.ServeHTTP(rec, tt.req)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, esperado %d: %s", rec.Code, tt.wantStatus, rec.Body)
			}
			var body map[string]string
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			if body["error"] != tt.wantError {
				t.Errorf("error = %q, esperado %q", body["error"], tt.wantError)
			}
			if tt.wantStatus == http.StatusUnauthorized && rec.Header().Get("WWW-Authenticate") == "" {
				t.Error("401 sem WWW-Authenticate")
			}
		})
	}

	req := httptest.NewRequest(http.MethodPost, "/internal/v1/oauth/token", strings.NewReader(`{"grant_type":"client_credentials"}`))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("cli_pedidos", "segredo-pedidos")
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("json no endpoint oauth: status = %d, esperado 415", rec.Code)
	}
}

func TestClientCredentialsRateLimited(t *testing.T) {
	env := newInternalEnv(t, newFakeAuth())
	form := url.Values{"grant_type": {"client_credentials"}}
	for range clientTokenRate.Limit {
		env.handler.ServeHTTP(httptest.NewRecorder(), clientTokenRequest(form, "cli_pedidos", "errado"))
	}
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, clientTokenRequest(form, "cli_pedidos", "segredo-pedidos"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, esperado 429", rec.Code)
	}
}

func TestPublicHandlerDoesNotExposeTokenRoutes(t *testing.T) {
	h := newAuthTestHandler(t, newFakeAuth(), false)
	for _, path := range []string{"/internal/v1/token", "/internal/v1/oauth/token", "/.well-known/jwks.json"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, jsonRequest(http.MethodPost, path, `{}`))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s no listener público: status = %d, esperado 404", path, rec.Code)
		}
	}
}

func TestMicroserviceAcceptsExchangedToken(t *testing.T) {
	a := newFakeAuth()
	session := loggedInSession(t, a)
	env := newInternalEnv(t, a)
	authSrv := httptest.NewServer(env.handler)
	t.Cleanup(authSrv.Close)

	req, _ := http.NewRequest(http.MethodPost, authSrv.URL+"/internal/v1/token", strings.NewReader(`{"session_token":"`+session+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("cli_bff", "segredo-bff")
	resp, err := http.DefaultClient.Do(req)
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

	call := httptest.NewRequest(http.MethodGet, "/pedidos", nil)
	call.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	rec := httptest.NewRecorder()
	service.ServeHTTP(rec, call)
	if rec.Code != http.StatusOK || rec.Body.String() != "id-ana@example.com" {
		t.Fatalf("microsserviço recusou o token: %d %s", rec.Code, rec.Body)
	}

	call = httptest.NewRequest(http.MethodGet, "/pedidos", nil)
	call.Header.Set("Authorization", "Bearer "+session)
	rec = httptest.NewRecorder()
	service.ServeHTTP(rec, call)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("microsserviço aceitou o token de sessão cru: %d", rec.Code)
	}
}
