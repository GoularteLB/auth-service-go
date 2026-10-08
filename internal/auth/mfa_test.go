package auth

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/GoularteLB/auth-service/internal/audit"
)

func enrolledEnv(t *testing.T) (testEnv, string) {
	t.Helper()
	env := newTestEnv(t, testParams)
	ctx := context.Background()
	_ = env.svc.Signup(ctx, "ana@example.com", goodPassword)
	session, err := env.svc.Login(ctx, "ana@example.com", goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.svc.SetupMFA(ctx, session, goodPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := env.svc.EnableMFA(ctx, session, "111111"); err != nil {
		t.Fatal(err)
	}
	return env, session
}

func mfaChallenge(t *testing.T, env testEnv) string {
	t.Helper()
	_, err := env.svc.Login(context.Background(), "ana@example.com", goodPassword)
	var required *MFARequiredError
	if !errors.As(err, &required) || required.Challenge == "" {
		t.Fatalf("esperava MFARequiredError, recebeu %v", err)
	}
	return required.Challenge
}

func TestSetupRequiresPassword(t *testing.T) {
	env := newTestEnv(t, testParams)
	ctx := context.Background()
	_ = env.svc.Signup(ctx, "ana@example.com", goodPassword)
	session, _ := env.svc.Login(ctx, "ana@example.com", goodPassword)

	if _, err := env.svc.SetupMFA(ctx, session, "senha-errada-aqui"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("setup com senha errada: %v", err)
	}
	if _, err := env.svc.SetupMFA(ctx, "sessao-falsa", goodPassword); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("setup sem sessão: %v", err)
	}
	if _, err := env.svc.EnableMFA(ctx, session, "111111"); !errors.Is(err, ErrMFANoPendingSetup) {
		t.Fatalf("ativar sem setup: %v", err)
	}
}

func TestLoginWithMFA(t *testing.T) {
	env, _ := enrolledEnv(t)
	ctx := context.Background()
	if env.mailer.last(t).Subject != "Verificação em duas etapas ativada" {
		t.Error("aviso de ativação não foi enviado")
	}

	before := len(env.sessions.data)
	challenge := mfaChallenge(t, env)
	if len(env.sessions.data) != before {
		t.Fatal("senha sozinha criou sessão com mfa ativo")
	}

	if _, err := env.svc.LoginMFA(ctx, challenge, "000000"); !errors.Is(err, ErrInvalidMFACode) {
		t.Fatalf("código errado: %v", err)
	}
	session, err := env.svc.LoginMFA(ctx, challenge, "222222")
	if err != nil {
		t.Fatalf("código certo depois de um errado: %v", err)
	}
	_, amr, err := env.svc.Identify(ctx, session)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(amr, []string{"pwd", "otp", "mfa"}) {
		t.Errorf("amr = %v", amr)
	}
	if _, err := env.svc.LoginMFA(ctx, challenge, "223333"); !errors.Is(err, ErrMFAChallenge) {
		t.Fatalf("desafio reaproveitado: %v", err)
	}
	if _, err := env.svc.LoginMFA(ctx, "inventado", "224444"); !errors.Is(err, ErrMFAChallenge) {
		t.Fatalf("desafio inventado: %v", err)
	}
}

func TestLoginMFALockout(t *testing.T) {
	env, _ := enrolledEnv(t)
	env.lockout.threshold = 3
	ctx := context.Background()
	challenge := mfaChallenge(t, env)

	for range 3 {
		_, _ = env.svc.LoginMFA(ctx, challenge, "000000")
	}
	if _, err := env.svc.LoginMFA(ctx, challenge, "222222"); !errors.Is(err, ErrLocked) {
		t.Fatalf("esperava bloqueio após códigos errados, recebeu %v", err)
	}
	if _, err := env.svc.Login(ctx, "ana@example.com", goodPassword); errors.Is(err, ErrLocked) {
		t.Fatal("bloqueio de mfa vazou para o bloqueio de senha")
	}
}

func TestLoginWithRecoveryCode(t *testing.T) {
	env, _ := enrolledEnv(t)
	ctx := context.Background()

	session, err := env.svc.LoginMFA(ctx, mfaChallenge(t, env), "aaaaa-bbbbb")
	if err != nil {
		t.Fatal(err)
	}
	if _, amr, _ := env.svc.Identify(ctx, session); !slices.Equal(amr, []string{"pwd", "mfa"}) {
		t.Errorf("amr = %v", amr)
	}
	found := false
	for _, e := range env.audit.events {
		found = found || e.Type == audit.MFARecoveryUsed
	}
	if !found {
		t.Error("uso de código de recuperação não foi auditado")
	}
	if _, err := env.svc.LoginMFA(ctx, mfaChallenge(t, env), "aaaaa-bbbbb"); !errors.Is(err, ErrInvalidMFACode) {
		t.Fatal("código de recuperação aceito duas vezes")
	}
}

func TestDisableMFA(t *testing.T) {
	env, session := enrolledEnv(t)
	ctx := context.Background()

	if err := env.svc.DisableMFA(ctx, session, "senha-errada-aqui", "222222"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("desativou com senha errada: %v", err)
	}
	if err := env.svc.DisableMFA(ctx, session, goodPassword, "000000"); !errors.Is(err, ErrInvalidMFACode) {
		t.Fatalf("desativou com código errado: %v", err)
	}
	if err := env.svc.DisableMFA(ctx, session, goodPassword, "222222"); err != nil {
		t.Fatal(err)
	}
	if on, _ := env.svc.MFAEnabled(ctx, env.sessions.data[session].UserID); on {
		t.Fatal("mfa continuou ativo")
	}
	if _, err := env.svc.Login(ctx, "ana@example.com", goodPassword); err != nil {
		t.Fatalf("login sem mfa depois de desativar: %v", err)
	}
	if env.mailer.last(t).Subject != "Verificação em duas etapas desativada" {
		t.Error("aviso de desativação não foi enviado")
	}
}

func TestPasswordResetKeepsMFA(t *testing.T) {
	env, _ := enrolledEnv(t)
	ctx := context.Background()

	_ = env.svc.ForgotPassword(ctx, "ana@example.com")
	token := tokenFrom(t, env.mailer.last(t).Text, "/redefinir-senha")
	if err := env.svc.ResetPassword(ctx, token, "uma-senha-nova-e-longa"); err != nil {
		t.Fatal(err)
	}
	_, err := env.svc.Login(ctx, "ana@example.com", "uma-senha-nova-e-longa")
	if !errors.Is(err, ErrMFARequired) {
		t.Fatalf("redefinir senha pelo e-mail pulou o mfa: %v", err)
	}
}
