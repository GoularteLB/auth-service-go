package integration

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/GoularteLB/auth-service/internal/audit"
	"github.com/GoularteLB/auth-service/internal/client"
	"github.com/GoularteLB/auth-service/internal/database"
	"github.com/GoularteLB/auth-service/internal/mfa"
	"github.com/GoularteLB/auth-service/internal/user"
)

func openDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("AUTH_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AUTH_TEST_DATABASE_URL não definida")
	}

	m, err := database.NewMigrator(url)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Up(); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	pool, err := database.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `TRUNCATE users, clients, audit_events CASCADE`); err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestUserStore(t *testing.T) {
	pool := openDB(t)
	ctx := context.Background()
	users := user.NewStore(pool)

	u, err := users.Create(ctx, "ana@example.com", "hash-1")
	if err != nil {
		t.Fatal(err)
	}
	if u.ID == "" || u.CreatedAt.IsZero() {
		t.Fatalf("usuário criado sem id ou data: %+v", u)
	}

	if _, err := users.Create(ctx, "ANA@example.com", "hash-2"); !errors.Is(err, user.ErrEmailTaken) {
		t.Fatalf("citext deveria barrar e-mail repetido com outra caixa: %v", err)
	}

	got, err := users.ByEmail(ctx, "Ana@Example.com")
	if err != nil || got.ID != u.ID {
		t.Fatalf("ByEmail = %+v, %v", got, err)
	}
	if got.EmailVerified() {
		t.Fatal("usuário novo já nasce verificado")
	}

	if err := users.UpdatePasswordHash(ctx, u.ID, "hash-novo"); err != nil {
		t.Fatal(err)
	}
	if err := users.MarkEmailVerified(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	got, err = users.ByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.PasswordHash != "hash-novo" || !got.EmailVerified() {
		t.Fatalf("atualização não persistiu: %+v", got)
	}

	if _, err := users.ByID(ctx, "00000000-0000-0000-0000-000000000000"); !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("ByID inexistente: %v", err)
	}
	if _, err := users.ByEmail(ctx, "ninguem@example.com"); !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("ByEmail inexistente: %v", err)
	}
}

func TestClientStore(t *testing.T) {
	pool := openDB(t)
	ctx := context.Background()
	clients := client.NewStore(pool)

	c, secret, err := clients.Create(ctx, "bff", []string{client.ScopeSessionExchange, "x:y", client.ScopeSessionExchange}, []string{"pedidos", "pedidos"})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Scopes) != 2 || len(c.Audiences) != 1 {
		t.Fatalf("escopos ou audiências não foram normalizados: %v %v", c.Scopes, c.Audiences)
	}

	active, hash, err := clients.Active(ctx, c.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	if hash != client.HashSecret(secret) || active.Name != "bff" || len(active.Scopes) != 2 || len(active.Audiences) != 1 {
		t.Fatalf("cliente lido diferente do criado: %+v", active)
	}

	updated, err := clients.SetAudiences(ctx, c.ClientID, []string{"pedidos", "estoque"})
	if err != nil {
		t.Fatal(err)
	}
	active, _, _ = clients.Active(ctx, c.ClientID)
	if len(updated) != 2 || strings.Join(active.Audiences, " ") != "pedidos estoque" {
		t.Fatalf("audiências não foram atualizadas: %v", active.Audiences)
	}
	if _, err := clients.SetAudiences(ctx, c.ClientID, []string{"Inválida"}); !errors.Is(err, client.ErrInvalidAudience) {
		t.Fatalf("audiência inválida: %v", err)
	}
	if _, err := clients.SetAudiences(ctx, "cli_nao_existe", nil); !errors.Is(err, client.ErrNotFound) {
		t.Fatalf("cliente inexistente: %v", err)
	}

	if err := clients.Revoke(ctx, c.ClientID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := clients.Active(ctx, c.ClientID); !errors.Is(err, client.ErrNotFound) {
		t.Fatalf("cliente revogado ainda ativo: %v", err)
	}
	if err := clients.Revoke(ctx, c.ClientID); !errors.Is(err, client.ErrNotFound) {
		t.Fatalf("revogar duas vezes: %v", err)
	}

	list, err := clients.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].RevokedAt == nil {
		t.Fatalf("lista inesperada: %+v", list)
	}

	if _, _, err := clients.Create(ctx, "", nil, nil); !errors.Is(err, client.ErrInvalidName) {
		t.Fatalf("nome vazio: %v", err)
	}
}

func TestMFAStore(t *testing.T) {
	pool := openDB(t)
	ctx := context.Background()
	u, err := user.NewStore(pool).Create(ctx, "ana@example.com", "hash")
	if err != nil {
		t.Fatal(err)
	}
	store := mfa.NewPostgresStore(pool)

	if _, err := store.Get(ctx, u.ID); !errors.Is(err, mfa.ErrNotEnabled) {
		t.Fatalf("Get sem registro: %v", err)
	}
	if err := store.SavePending(ctx, u.ID, []byte("cifrado-1")); err != nil {
		t.Fatal(err)
	}
	if err := store.SavePending(ctx, u.ID, []byte("cifrado-2")); err != nil {
		t.Fatalf("refazer setup pendente: %v", err)
	}

	codes := [][32]byte{sha256.Sum256([]byte("a")), sha256.Sum256([]byte("b"))}
	if err := store.Enable(ctx, u.ID, codes); err != nil {
		t.Fatal(err)
	}
	r, err := store.Get(ctx, u.ID)
	if err != nil || !r.Enabled || string(r.Ciphertext) != "cifrado-2" {
		t.Fatalf("registro = %+v, %v", r, err)
	}
	if err := store.SavePending(ctx, u.ID, []byte("cifrado-3")); !errors.Is(err, mfa.ErrAlreadyEnabled) {
		t.Fatalf("setup por cima de mfa ativo: %v", err)
	}
	if err := store.Enable(ctx, u.ID, codes); !errors.Is(err, mfa.ErrAlreadyEnabled) {
		t.Fatalf("ativar duas vezes: %v", err)
	}

	for _, tc := range []struct {
		step int64
		want bool
	}{{100, true}, {100, false}, {99, false}, {101, true}} {
		ok, err := store.UseStep(ctx, u.ID, tc.step)
		if err != nil || ok != tc.want {
			t.Fatalf("UseStep(%d) = %v, %v; esperado %v", tc.step, ok, err, tc.want)
		}
	}

	if ok, _ := store.UseRecoveryCode(ctx, u.ID, codes[0]); !ok {
		t.Fatal("código de recuperação válido recusado")
	}
	if ok, _ := store.UseRecoveryCode(ctx, u.ID, codes[0]); ok {
		t.Fatal("código de recuperação usado duas vezes")
	}
	if ok, _ := store.UseRecoveryCode(ctx, u.ID, sha256.Sum256([]byte("z"))); ok {
		t.Fatal("código inexistente aceito")
	}

	if err := store.Disable(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, u.ID); !errors.Is(err, mfa.ErrNotEnabled) {
		t.Fatalf("mfa continuou depois de desativar: %v", err)
	}
	if ok, _ := store.UseRecoveryCode(ctx, u.ID, codes[1]); ok {
		t.Fatal("código de recuperação sobreviveu à desativação")
	}
}

func TestAuditStore(t *testing.T) {
	pool := openDB(t)
	ctx := context.Background()
	u, err := user.NewStore(pool).Create(ctx, "ana@example.com", "hash")
	if err != nil {
		t.Fatal(err)
	}
	store := audit.NewStore(pool)

	ctx = audit.WithClient(ctx, audit.Client{IP: "203.0.113.9", UserAgent: "teste/1.0", RequestID: "req-1"})
	if err := store.Record(ctx, audit.Event{Type: audit.LoginSucceeded, UserID: u.ID, Email: "ana@example.com"}); err != nil {
		t.Fatal(err)
	}
	bad := audit.WithClient(context.Background(), audit.Client{IP: "não é ip"})
	if err := store.Record(bad, audit.Event{Type: audit.ClientAuthFailed, ClientID: "cli_x"}); err != nil {
		t.Fatalf("ip inválido deveria virar null, não erro: %v", err)
	}

	var typ, email, ua, req string
	var ip netip.Addr
	err = pool.QueryRow(ctx,
		`SELECT event_type, email::text, ip, user_agent, request_id FROM audit_events WHERE user_id = $1::uuid`, u.ID,
	).Scan(&typ, &email, &ip, &ua, &req)
	if err != nil {
		t.Fatal(err)
	}
	if typ != string(audit.LoginSucceeded) || email != "ana@example.com" || ip.String() != "203.0.113.9" || ua != "teste/1.0" || req != "req-1" {
		t.Fatalf("evento gravado errado: %s %s %s %s %s", typ, email, ip, ua, req)
	}

	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE client_id = 'cli_x' AND ip IS NULL`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("evento de cliente: n=%d, %v", n, err)
	}
}
