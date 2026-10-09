package auth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/GoularteLB/auth-service/internal/audit"
	"github.com/GoularteLB/auth-service/internal/password"
)

func tokenFrom(t *testing.T, text, path string) string {
	t.Helper()
	prefix := "https://app.example.com" + path + "#token="
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	t.Fatalf("link %s não encontrado no e-mail:\n%s", path, text)
	return ""
}

func TestSignupSendsVerificationAndVerifyWorksOnce(t *testing.T) {
	env := newTestEnv(t, testParams)
	ctx := context.Background()

	if err := env.svc.Signup(ctx, "ana@example.com", goodPassword); err != nil {
		t.Fatal(err)
	}
	m := env.mailer.last(t)
	if m.To != "ana@example.com" || m.Subject != "Confirme seu e-mail" {
		t.Fatalf("e-mail inesperado: %+v", m)
	}
	token := tokenFrom(t, m.Text, "/verificar-email")

	if err := env.svc.VerifyEmail(ctx, token); err != nil {
		t.Fatal(err)
	}
	u, _ := env.users.ByEmail(ctx, "ana@example.com")
	if !u.EmailVerified() {
		t.Fatal("e-mail não foi marcado como verificado")
	}
	if err := env.svc.VerifyEmail(ctx, token); !errors.Is(err, ErrInvalidLink) {
		t.Fatalf("link usado duas vezes: %v", err)
	}
	if err := env.svc.VerifyEmail(ctx, "inventado"); !errors.Is(err, ErrInvalidLink) {
		t.Fatalf("token inventado: %v", err)
	}
}

func TestDuplicateSignupWarnsOwner(t *testing.T) {
	env := newTestEnv(t, testParams)
	ctx := context.Background()
	_ = env.svc.Signup(ctx, "ana@example.com", goodPassword)
	_ = env.svc.Signup(ctx, "ana@example.com", "outra-senha-qualquer")

	m := env.mailer.last(t)
	if m.Subject != "Você já tem uma conta" || strings.Contains(m.Text, "#token=") {
		t.Fatalf("aviso de conta existente errado: %+v", m)
	}
}

func TestResendVerification(t *testing.T) {
	env := newTestEnv(t, testParams)
	ctx := context.Background()
	_ = env.svc.Signup(ctx, "ana@example.com", goodPassword)
	first := tokenFrom(t, env.mailer.last(t).Text, "/verificar-email")
	session, _ := env.svc.Login(ctx, "ana@example.com", goodPassword)

	if err := env.svc.ResendVerification(ctx, session); err != nil {
		t.Fatal(err)
	}
	second := tokenFrom(t, env.mailer.last(t).Text, "/verificar-email")
	if err := env.svc.VerifyEmail(ctx, first); !errors.Is(err, ErrInvalidLink) {
		t.Fatal("link antigo continuou valendo após reenvio")
	}
	if err := env.svc.VerifyEmail(ctx, second); err != nil {
		t.Fatal(err)
	}

	before := env.mailer.count()
	if err := env.svc.ResendVerification(ctx, session); err != nil {
		t.Fatal(err)
	}
	if env.mailer.count() != before {
		t.Error("reenviou verificação para e-mail já verificado")
	}
	if err := env.svc.ResendVerification(ctx, "sessao-falsa"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("reenvio sem sessão: %v", err)
	}
}

func TestForgotPasswordUnknownEmailIsSilent(t *testing.T) {
	env := newTestEnv(t, testParams)
	if err := env.svc.ForgotPassword(context.Background(), "ninguem@example.com"); err != nil {
		t.Fatalf("e-mail inexistente deveria parecer sucesso: %v", err)
	}
	if env.mailer.count() != 0 {
		t.Fatal("mandou e-mail para conta que não existe")
	}
	if env.audit.types()[0] != audit.PasswordResetRequested {
		t.Error("pedido não foi auditado")
	}
	if err := env.svc.ForgotPassword(context.Background(), "nao-e-email"); !errors.Is(err, ErrInvalidEmail) {
		t.Fatalf("e-mail malformado: %v", err)
	}
}

func TestResetPasswordFlow(t *testing.T) {
	env := newTestEnv(t, testParams)
	env.lockout.threshold = 3
	ctx := context.Background()
	_ = env.svc.Signup(ctx, "ana@example.com", goodPassword)
	sessionA, _ := env.svc.Login(ctx, "ana@example.com", goodPassword)
	sessionB, _ := env.svc.Login(ctx, "ana@example.com", goodPassword)
	_, _ = env.svc.Login(ctx, "ana@example.com", "senha-errada-aqui")
	_, _ = env.svc.Login(ctx, "ana@example.com", "senha-errada-aqui")

	if err := env.svc.ForgotPassword(ctx, " ANA@example.com "); err != nil {
		t.Fatal(err)
	}
	m := env.mailer.last(t)
	if m.Subject != "Redefinição de senha" {
		t.Fatalf("assunto = %q", m.Subject)
	}
	token := tokenFrom(t, m.Text, "/redefinir-senha")

	if err := env.svc.ResetPassword(ctx, token, "curta"); !errors.Is(err, password.ErrTooShort) {
		t.Fatalf("senha curta: %v", err)
	}
	if err := env.svc.ResetPassword(ctx, token, "uma-senha-nova-e-longa"); err != nil {
		t.Fatalf("senha inválida não deveria ter queimado o link: %v", err)
	}
	if env.lockout.total() != 0 || env.account.total() != 0 {
		t.Error("redefinir a senha não liberou o bloqueio")
	}

	for _, s := range []string{sessionA, sessionB} {
		if _, err := env.svc.Current(ctx, s); !errors.Is(err, ErrUnauthenticated) {
			t.Error("sessão antiga sobreviveu à redefinição")
		}
	}
	if _, err := env.svc.Login(ctx, "ana@example.com", goodPassword); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("senha antiga ainda funciona")
	}
	if _, err := env.svc.Login(ctx, "ana@example.com", "uma-senha-nova-e-longa"); err != nil {
		t.Fatalf("senha nova não funciona: %v", err)
	}

	u, _ := env.users.ByEmail(ctx, "ana@example.com")
	if !u.EmailVerified() {
		t.Error("redefinir pelo e-mail deveria provar posse do e-mail")
	}
	if env.mailer.last(t).Subject != "Sua senha foi alterada" {
		t.Error("aviso de senha alterada não foi enviado")
	}
	if err := env.svc.ResetPassword(ctx, token, "mais-uma-senha-longa"); !errors.Is(err, ErrInvalidLink) {
		t.Fatalf("link de redefinição usado duas vezes: %v", err)
	}
}

func TestVerificationTokenCannotResetPassword(t *testing.T) {
	env := newTestEnv(t, testParams)
	ctx := context.Background()
	_ = env.svc.Signup(ctx, "ana@example.com", goodPassword)
	verify := tokenFrom(t, env.mailer.last(t).Text, "/verificar-email")

	if err := env.svc.ResetPassword(ctx, verify, "uma-senha-nova-e-longa"); !errors.Is(err, ErrInvalidLink) {
		t.Fatalf("token de verificação redefiniu senha: %v", err)
	}
}

func TestMailerFailureDoesNotBreakSignup(t *testing.T) {
	env := newTestEnv(t, testParams)
	env.mailer.err = errors.New("fila cheia")
	if err := env.svc.Signup(context.Background(), "ana@example.com", goodPassword); err != nil {
		t.Fatalf("falha no e-mail derrubou o cadastro: %v", err)
	}
	if err := env.svc.ForgotPassword(context.Background(), "ana@example.com"); err != nil {
		t.Fatalf("falha no e-mail mudou a resposta do esqueci a senha: %v", err)
	}
}
