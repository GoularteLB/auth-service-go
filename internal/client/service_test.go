package client

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GoularteLB/auth-service/internal/audit"
)

type fakeRepo struct {
	clients map[string]Client
	secrets map[string]string
	err     error
}

func (f *fakeRepo) Active(_ context.Context, id string) (Client, [32]byte, error) {
	if f.err != nil {
		return Client{}, [32]byte{}, f.err
	}
	c, ok := f.clients[id]
	if !ok {
		return Client{}, [32]byte{}, ErrNotFound
	}
	return c, HashSecret(f.secrets[id]), nil
}

type fakeIssuer struct {
	subject, clientID string
	scopes            []string
}

func (f *fakeIssuer) Issue(subject, clientID string, scopes, _ []string) (string, time.Duration, error) {
	f.subject, f.clientID, f.scopes = subject, clientID, scopes
	return "jwt", 5 * time.Minute, nil
}

type fakeAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (f *fakeAudit) Record(_ context.Context, e audit.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
	return nil
}

func (f *fakeAudit) last() audit.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.events) == 0 {
		return audit.Event{}
	}
	return f.events[len(f.events)-1]
}

func newTestService() (*Service, *fakeIssuer, *fakeAudit) {
	repo := &fakeRepo{
		clients: map[string]Client{
			"cli_bff":     {ClientID: "cli_bff", Scopes: []string{ScopeSessionExchange}},
			"cli_pedidos": {ClientID: "cli_pedidos", Scopes: []string{"estoque:ler", "estoque:escrever"}},
		},
		secrets: map[string]string{"cli_bff": "segredo-bff", "cli_pedidos": "segredo-pedidos"},
	}
	iss, aud := &fakeIssuer{}, &fakeAudit{}
	return NewService(repo, iss, aud, slog.New(slog.NewTextHandler(io.Discard, nil))), iss, aud
}

func TestAuthenticate(t *testing.T) {
	svc, _, aud := newTestService()
	ctx := context.Background()

	if _, err := svc.Authenticate(ctx, "cli_bff", "segredo-bff"); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ id, secret string }{
		{"cli_bff", "errado"},
		{"cli_bff", ""},
		{"cli_nao_existe", "segredo-bff"},
		{"", "segredo-bff"},
		{"cli_bff' OR 1=1", "x"},
		{"cli_\xff", "x"},
		{strings.Repeat("a", 65), "x"},
		{"cli_bff", strings.Repeat("a", 257)},
	} {
		if _, err := svc.Authenticate(ctx, tc.id, tc.secret); !errors.Is(err, ErrInvalidClient) {
			t.Errorf("Authenticate(%q) = %v, esperado ErrInvalidClient", tc.id, err)
		}
		if aud.last().Type != audit.ClientAuthFailed {
			t.Errorf("falha de %q não foi auditada", tc.id)
		}
	}
}

func TestAuthenticateRepositoryError(t *testing.T) {
	svc, _, _ := newTestService()
	svc.repo.(*fakeRepo).err = errors.New("banco fora")
	if _, err := svc.Authenticate(context.Background(), "cli_bff", "segredo-bff"); err == nil || errors.Is(err, ErrInvalidClient) {
		t.Fatalf("erro de banco deveria subir como erro interno, recebeu %v", err)
	}
}

func TestAuthorize(t *testing.T) {
	svc, _, aud := newTestService()
	ctx := context.Background()

	if _, err := svc.Authorize(ctx, "cli_bff", "segredo-bff", ScopeSessionExchange); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authorize(ctx, "cli_pedidos", "segredo-pedidos", ScopeSessionExchange); !errors.Is(err, ErrForbidden) {
		t.Fatalf("esperava ErrForbidden, recebeu %v", err)
	}
	if aud.last().Type != audit.ClientForbidden {
		t.Error("recusa de escopo não foi auditada")
	}
}

func TestToken(t *testing.T) {
	svc, iss, aud := newTestService()
	ctx := context.Background()

	tok, err := svc.Token(ctx, "cli_pedidos", "segredo-pedidos", "")
	if err != nil {
		t.Fatal(err)
	}
	if iss.subject != "cli_pedidos" || iss.clientID != "cli_pedidos" {
		t.Errorf("token emitido para %q/%q", iss.subject, iss.clientID)
	}
	if strings.Join(tok.Scopes, " ") != "estoque:ler estoque:escrever" {
		t.Errorf("sem scope pedido deveria receber todos: %v", tok.Scopes)
	}
	if aud.last().Type != audit.ClientTokenIssued || aud.last().ClientID != "cli_pedidos" {
		t.Errorf("emissão não auditada: %+v", aud.last())
	}

	tok, err = svc.Token(ctx, "cli_pedidos", "segredo-pedidos", "estoque:ler estoque:ler")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(tok.Scopes, " ") != "estoque:ler" {
		t.Errorf("escopo reduzido errado: %v", tok.Scopes)
	}

	if _, err := svc.Token(ctx, "cli_pedidos", "segredo-pedidos", "estoque:ler admin"); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("pediu escopo que não tem e recebeu %v", err)
	}
}

func TestNormalizeScopes(t *testing.T) {
	got, err := NormalizeScopes([]string{" a:b ", "a:b", "", "c.d-e_f"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, " ") != "a:b c.d-e_f" {
		t.Errorf("got %v", got)
	}
	for _, bad := range []string{"Maiúscula", "com espaço", ":começa", strings.Repeat("a", 65), `aspas"`} {
		if _, err := NormalizeScopes([]string{bad}); !errors.Is(err, ErrInvalidScope) {
			t.Errorf("aceitou %q", bad)
		}
	}
}
