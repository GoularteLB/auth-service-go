package httpserver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
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
