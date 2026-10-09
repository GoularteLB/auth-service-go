package httpserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeDB struct{ err error }

func (f fakeDB) Ping(context.Context) error { return f.err }

func newTestHandler(t *testing.T, db Pinger, production bool) http.Handler {
	t.Helper()
	return NewHandler(Deps{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Checks:     map[string]Pinger{"postgres": db},
		Auth:       newFakeAuth(),
		Limiter:    newFakeLimiter(),
		SessionTTL: time.Hour,
		Production: production,
	})
}

func TestHealthz(t *testing.T) {
	h := newTestHandler(t, fakeDB{}, false)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, esperado 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"ok"`) {
		t.Errorf("corpo inesperado: %s", rec.Body)
	}
}

func TestReadyz(t *testing.T) {
	tests := []struct {
		name string
		db   Pinger
		want int
	}{
		{"banco ok", fakeDB{}, http.StatusOK},
		{"banco fora", fakeDB{err: errors.New("connection refused")}, http.StatusServiceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			newTestHandler(t, tt.db, false).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			if rec.Code != tt.want {
				t.Errorf("status = %d, esperado %d", rec.Code, tt.want)
			}
		})
	}
}

func TestSecureHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestHandler(t, fakeDB{}, true).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	want := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Cache-Control":             "no-store",
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, esperado %q", k, got, v)
		}
	}
	if rec.Header().Get("X-Request-ID") == "" {
		t.Error("X-Request-ID ausente")
	}
}

func TestNoHSTSInDevelopment(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestHandler(t, fakeDB{}, false).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS não deveria ser enviado em desenvolvimento")
	}
}

func TestCrossOriginRequestIsRejected(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	newTestHandler(t, fakeDB{}, false).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, esperado 403", rec.Code)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	newTestHandler(t, fakeDB{}, false).ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, esperado 405", rec.Code)
	}
}

func TestRecoverPanic(t *testing.T) {
	h := recoverPanic(slog.New(slog.NewTextHandler(io.Discard, nil)), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, esperado 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "boom") {
		t.Error("detalhe do panic vazou na resposta")
	}
}

func TestServeShutsDownGracefully(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(ln.Addr().String(), newTestHandler(t, fakeDB{}, false), logger)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, srv, ln, time.Second) }()

	resp, err := http.Get("http://" + ln.Addr().String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve retornou erro: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("servidor não encerrou a tempo")
	}
}

func writeTestCert(t *testing.T) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "auth-service"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "internal.crt"), filepath.Join(dir, "internal.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return certFile, keyFile, pool
}

func TestServeWithTLS(t *testing.T) {
	certFile, keyFile, pool := writeTestCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(ln.Addr().String(), newTestHandler(t, fakeDB{}, false), logger)
	if err := UseTLS(srv, certFile, keyFile); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, srv, ln, time.Second) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	if resp, err := http.Get("http://" + ln.Addr().String() + "/healthz"); err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatal("servidor com tls respondeu em texto puro")
		}
	}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}}
	resp, err := client.Get("https://" + ln.Addr().String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.TLS == nil || resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("status = %d, tls = %+v", resp.StatusCode, resp.TLS)
	}
}

func TestUseTLSWithMissingFiles(t *testing.T) {
	srv := New("127.0.0.1:0", http.NotFoundHandler(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := UseTLS(srv, "/nao/existe.crt", "/nao/existe.key"); err == nil {
		t.Fatal("aceitou certificado inexistente")
	}
}
