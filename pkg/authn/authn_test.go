package authn

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

var epoch = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func validClaims() Claims {
	return Claims{
		Issuer:    "auth-service",
		Subject:   "user-1",
		Audience:  Audience{"internal"},
		IssuedAt:  epoch.Unix(),
		NotBefore: epoch.Unix(),
		ExpiresAt: epoch.Add(5 * time.Minute).Unix(),
		ID:        "jti-1",
	}
}

func newVerifier(keys KeySource, now time.Time) *Verifier {
	return &Verifier{
		Keys:     keys,
		Issuer:   "auth-service",
		Audience: "internal",
		Leeway:   30 * time.Second,
		Now:      func() time.Time { return now },
	}
}

func TestSignAndVerify(t *testing.T) {
	pub, priv := newKey(t)
	kid := Thumbprint(pub)
	token, err := Sign(priv, kid, validClaims())
	if err != nil {
		t.Fatal(err)
	}

	c, err := newVerifier(StaticKeys{kid: pub}, epoch.Add(time.Minute)).Verify(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "user-1" || c.ID != "jti-1" {
		t.Errorf("claims inesperadas: %+v", c)
	}
}

func TestVerifyRejects(t *testing.T) {
	pub, priv := newKey(t)
	otherPub, otherPriv := newKey(t)
	kid := Thumbprint(pub)
	keys := StaticKeys{kid: pub, Thumbprint(otherPub): otherPub}

	sign := func(c Claims) string {
		tok, err := Sign(priv, kid, c)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	with := func(f func(*Claims)) string {
		c := validClaims()
		f(&c)
		return sign(c)
	}
	good := sign(validClaims())
	parts := strings.Split(good, ".")

	header := func(h string) string {
		return b64.EncodeToString([]byte(h)) + "." + parts[1] + "." + parts[2]
	}
	forgedWithOtherKey, _ := Sign(otherPriv, kid, validClaims())
	tamperedPayload := parts[0] + "." + b64.EncodeToString([]byte(`{"iss":"auth-service","sub":"admin","aud":"internal","exp":9999999999}`)) + "." + parts[2]

	tests := []struct {
		name  string
		token string
		now   time.Time
		want  error
	}{
		{"vazio", "", epoch, ErrMalformed},
		{"dois segmentos", parts[0] + "." + parts[1], epoch, ErrMalformed},
		{"alg none", header(`{"alg":"none","typ":"JWT","kid":"` + kid + `"}`), epoch, ErrMalformed},
		{"alg hs256", header(`{"alg":"HS256","typ":"JWT","kid":"` + kid + `"}`), epoch, ErrMalformed},
		{"sem kid", header(`{"alg":"EdDSA","typ":"JWT"}`), epoch, ErrMalformed},
		{"kid desconhecido", header(`{"alg":"EdDSA","typ":"JWT","kid":"x"}`), epoch, ErrUnknownKey},
		{"payload adulterado", tamperedPayload, epoch, ErrSignature},
		{"assinado com outra chave", forgedWithOtherKey, epoch, ErrSignature},
		{"expirado", good, epoch.Add(6 * time.Minute), ErrExpired},
		{"antes do nbf", good, epoch.Add(-time.Minute), ErrNotYetValid},
		{"emissor errado", with(func(c *Claims) { c.Issuer = "outro" }), epoch, ErrWrongIssuer},
		{"audiência errada", with(func(c *Claims) { c.Audience = Audience{"billing"} }), epoch, ErrWrongAudience},
		{"sem sub", with(func(c *Claims) { c.Subject = "" }), epoch, ErrMalformed},
		{"sem exp", with(func(c *Claims) { c.ExpiresAt = 0 }), epoch, ErrMalformed},
		{"grande demais", strings.Repeat("a", maxTokenSize+1), epoch, ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newVerifier(keys, tt.now).Verify(context.Background(), tt.token)
			if !errors.Is(err, tt.want) {
				t.Errorf("erro = %v, esperado %v", err, tt.want)
			}
		})
	}
}

func TestLeeway(t *testing.T) {
	pub, priv := newKey(t)
	kid := Thumbprint(pub)
	token, _ := Sign(priv, kid, validClaims())
	v := newVerifier(StaticKeys{kid: pub}, epoch.Add(5*time.Minute+20*time.Second))
	if _, err := v.Verify(context.Background(), token); err != nil {
		t.Fatalf("leeway não foi aplicado: %v", err)
	}
}

func TestAudienceAcceptsArray(t *testing.T) {
	var a Audience
	if err := json.Unmarshal([]byte(`["billing","internal"]`), &a); err != nil {
		t.Fatal(err)
	}
	if !a.Contains("internal") {
		t.Fatal("audiência em array não foi lida")
	}
	out, _ := json.Marshal(Audience{"internal"})
	if string(out) != `"internal"` {
		t.Errorf("audiência única deveria virar string, virou %s", out)
	}
}

func TestThumbprintRFC7638(t *testing.T) {
	raw, _ := b64.DecodeString("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
	if got := Thumbprint(ed25519.PublicKey(raw)); got != "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" {
		t.Errorf("thumbprint = %s", got)
	}
}

func TestJWKRoundTrip(t *testing.T) {
	pub, _ := newKey(t)
	jwk := NewJWK(pub)
	got, err := jwk.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(got) {
		t.Fatal("chave mudou na ida e volta")
	}

	bad := jwk
	bad.Crv = "X25519"
	if _, err := bad.PublicKey(); err == nil {
		t.Fatal("aceitou curva errada")
	}
}

func jwksServer(t *testing.T, keys *atomic.Value, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_ = json.NewEncoder(w).Encode(keys.Load())
	}))
	t.Cleanup(srv.Close)
	return srv
}

func mustRemote(t *testing.T, url string) *RemoteKeys {
	t.Helper()
	r, err := NewRemoteKeys(url)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestNewRemoteKeysValidatesURL(t *testing.T) {
	for _, bad := range []string{"", "file:///etc/passwd", "ftp://auth/jwks", "https://", "https://user:pw@auth/jwks", "://"} {
		if _, err := NewRemoteKeys(bad); err == nil {
			t.Errorf("aceitou %q", bad)
		}
	}
	for _, good := range []string{
		"https://auth-service:8081/.well-known/jwks.json",
		"http://localhost:8081/.well-known/jwks.json",
		"http://LocalHost:8081/.well-known/jwks.json",
		"http://127.0.0.1:8081/.well-known/jwks.json",
		"http://[::1]:8081/.well-known/jwks.json",
	} {
		if _, err := NewRemoteKeys(good); err != nil {
			t.Errorf("recusou %q: %v", good, err)
		}
	}
}

func TestNewRemoteKeysRejectsPlainHTTPOutsideLoopback(t *testing.T) {
	const internal = "http://auth-service:8081/.well-known/jwks.json"
	if _, err := NewRemoteKeys(internal); err == nil {
		t.Fatal("aceitou http:// fora de localhost")
	}
	if _, err := NewRemoteKeys(internal, AllowInsecureHTTP()); err != nil {
		t.Fatalf("AllowInsecureHTTP não liberou http://: %v", err)
	}
}

func TestRemoteKeysWithRootCAs(t *testing.T) {
	pub, _ := newKey(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(JWKS{Keys: []JWK{NewJWK(pub)}})
	}))
	t.Cleanup(srv.Close)
	ctx := context.Background()

	untrusted := mustRemote(t, srv.URL)
	if _, err := untrusted.Key(ctx, Thumbprint(pub)); err == nil {
		t.Fatal("confiou num certificado fora da cadeia")
	}

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	trusted, err := NewRemoteKeys(srv.URL, WithRootCAs(pool))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trusted.Key(ctx, Thumbprint(pub)); err != nil {
		t.Fatalf("não confiou na CA informada: %v", err)
	}
}

func TestRemoteKeysFetchesAndCaches(t *testing.T) {
	pub, _ := newKey(t)
	var keys atomic.Value
	keys.Store(JWKS{Keys: []JWK{NewJWK(pub)}})
	var hits atomic.Int32
	srv := jwksServer(t, &keys, &hits)

	r := mustRemote(t, srv.URL)
	ctx := context.Background()
	for range 3 {
		got, err := r.Key(ctx, Thumbprint(pub))
		if err != nil {
			t.Fatal(err)
		}
		if !pub.Equal(got) {
			t.Fatal("chave errada")
		}
	}
	if hits.Load() != 1 {
		t.Errorf("jwks buscado %d vezes, esperado 1", hits.Load())
	}
}

func TestRemoteKeysPicksUpRotation(t *testing.T) {
	oldPub, _ := newKey(t)
	newPub, _ := newKey(t)
	var keys atomic.Value
	keys.Store(JWKS{Keys: []JWK{NewJWK(oldPub)}})
	var hits atomic.Int32
	srv := jwksServer(t, &keys, &hits)

	r := mustRemote(t, srv.URL)
	r.MinInterval = 0
	ctx := context.Background()
	if _, err := r.Key(ctx, Thumbprint(oldPub)); err != nil {
		t.Fatal(err)
	}

	keys.Store(JWKS{Keys: []JWK{NewJWK(newPub), NewJWK(oldPub)}})
	if _, err := r.Key(ctx, Thumbprint(newPub)); err != nil {
		t.Fatalf("chave nova não foi buscada: %v", err)
	}
}

func TestRemoteKeysThrottlesUnknownKids(t *testing.T) {
	pub, _ := newKey(t)
	var keys atomic.Value
	keys.Store(JWKS{Keys: []JWK{NewJWK(pub)}})
	var hits atomic.Int32
	srv := jwksServer(t, &keys, &hits)

	r := mustRemote(t, srv.URL)
	for i := range 20 {
		if _, err := r.Key(context.Background(), "kid-inventado-"+string(rune('a'+i))); !errors.Is(err, ErrUnknownKey) {
			t.Fatalf("erro = %v, esperado ErrUnknownKey", err)
		}
	}
	if hits.Load() != 1 {
		t.Errorf("kids inventados causaram %d buscas, esperado 1", hits.Load())
	}
}

func TestRemoteKeysServesStaleWhenDown(t *testing.T) {
	pub, _ := newKey(t)
	var keys atomic.Value
	keys.Store(JWKS{Keys: []JWK{NewJWK(pub)}})
	var hits atomic.Int32
	srv := jwksServer(t, &keys, &hits)

	r := mustRemote(t, srv.URL)
	r.MaxAge, r.MinInterval = 0, 0
	if _, err := r.Key(context.Background(), Thumbprint(pub)); err != nil {
		t.Fatal(err)
	}
	srv.Close()
	if _, err := r.Key(context.Background(), Thumbprint(pub)); err != nil {
		t.Fatalf("deveria usar a chave em cache com o jwks fora: %v", err)
	}
}

func TestMiddleware(t *testing.T) {
	pub, priv := newKey(t)
	kid := Thumbprint(pub)
	token, _ := Sign(priv, kid, validClaims())
	v := newVerifier(StaticKeys{kid: pub}, epoch)

	h := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := ClaimsFrom(r.Context())
		if !ok {
			t.Error("claims ausentes no contexto")
		}
		_, _ = w.Write([]byte(c.Subject))
	}))

	tests := []struct {
		name, auth string
		want       int
		challenge  string
	}{
		{"sem header", "", http.StatusUnauthorized, "Bearer"},
		{"basic", "Basic abc", http.StatusUnauthorized, "Bearer"},
		{"token inválido", "Bearer abc.def.ghi", http.StatusUnauthorized, `Bearer error="invalid_token"`},
		{"válido", "Bearer " + token, http.StatusOK, ""},
		{"esquema minúsculo", "bearer " + token, http.StatusOK, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.auth != "" {
				req.Header.Set("Authorization", tt.auth)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, esperado %d", rec.Code, tt.want)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != tt.challenge {
				t.Errorf("WWW-Authenticate = %q, esperado %q", got, tt.challenge)
			}
			if tt.want == http.StatusOK && rec.Body.String() != "user-1" {
				t.Errorf("corpo = %q", rec.Body)
			}
		})
	}
}

func TestScopes(t *testing.T) {
	c := Claims{Subject: "cli_x", ClientID: "cli_x", Scope: "pedidos:ler  pedidos:escrever"}
	if !c.HasScope("pedidos:ler") || !c.HasScope("pedidos:escrever") || c.HasScope("pedidos") {
		t.Errorf("HasScope errado para %q", c.Scope)
	}
	if !c.IsService() {
		t.Error("token de cliente deveria ser serviço")
	}
	if (Claims{Subject: "user-1", ClientID: "cli_bff"}).IsService() {
		t.Error("token de usuário marcado como serviço")
	}
}

func TestRequireScope(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	h := RequireScope("pedidos:ler", ok)

	tests := []struct {
		name   string
		claims *Claims
		want   int
	}{
		{"sem claims", nil, http.StatusUnauthorized},
		{"sem escopo", &Claims{Scope: "outro"}, http.StatusForbidden},
		{"com escopo", &Claims{Scope: "outro pedidos:ler"}, http.StatusNoContent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.claims != nil {
				req = req.WithContext(WithClaims(req.Context(), *tt.claims))
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Errorf("status = %d, esperado %d", rec.Code, tt.want)
			}
		})
	}
}

func TestRequireMFA(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	h := RequireMFA(ok)

	tests := []struct {
		name      string
		claims    *Claims
		want      int
		challenge string
	}{
		{"sem claims", nil, http.StatusUnauthorized, "Bearer"},
		{"só senha", &Claims{Subject: "user-1", AMR: []string{AMRPassword}}, http.StatusUnauthorized, `Bearer error="insufficient_user_authentication"`},
		{"serviço", &Claims{Subject: "cli_x", ClientID: "cli_x"}, http.StatusUnauthorized, `Bearer error="insufficient_user_authentication"`},
		{"com mfa", &Claims{Subject: "user-1", AMR: []string{AMRPassword, AMROTP, AMRMFA}}, http.StatusNoContent, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.claims != nil {
				req = req.WithContext(WithClaims(req.Context(), *tt.claims))
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, esperado %d", rec.Code, tt.want)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != tt.challenge {
				t.Errorf("WWW-Authenticate = %q, esperado %q", got, tt.challenge)
			}
		})
	}
}

func TestAMRRoundTrip(t *testing.T) {
	pub, priv := newKey(t)
	kid := Thumbprint(pub)
	c := validClaims()
	c.AMR = []string{AMRPassword, AMRMFA}
	token, err := Sign(priv, kid, c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := newVerifier(StaticKeys{kid: pub}, epoch).Verify(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if !got.HasAMR(AMRMFA) || got.HasAMR(AMROTP) {
		t.Errorf("amr = %v", got.AMR)
	}
}
