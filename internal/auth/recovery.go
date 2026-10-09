package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/GoularteLB/auth-service/internal/audit"
	"github.com/GoularteLB/auth-service/internal/mail"
	"github.com/GoularteLB/auth-service/internal/onetime"
	"github.com/GoularteLB/auth-service/internal/password"
	"github.com/GoularteLB/auth-service/internal/user"
)

const (
	verifyTTL = 24 * time.Hour
	resetTTL  = 30 * time.Minute
)

var ErrInvalidLink = errors.New("link inválido ou expirado")

type OneTimeTokens interface {
	Issue(ctx context.Context, p onetime.Purpose, userID string, ttl time.Duration) (string, error)
	Consume(ctx context.Context, p onetime.Purpose, token string) (string, error)
	Peek(ctx context.Context, p onetime.Purpose, token string) (string, error)
}

type Mailer interface {
	Send(ctx context.Context, m mail.Message) error
}

func (s *Service) VerifyEmail(ctx context.Context, token string) error {
	userID, err := s.tokens.Consume(ctx, onetime.VerifyEmail, token)
	if errors.Is(err, onetime.ErrInvalid) {
		return ErrInvalidLink
	}
	if err != nil {
		return err
	}
	if err := s.users.MarkEmailVerified(ctx, userID); err != nil {
		return err
	}
	s.record(ctx, audit.Event{Type: audit.EmailVerified, UserID: userID})
	return nil
}

func (s *Service) ResendVerification(ctx context.Context, sessionToken string) error {
	u, err := s.Current(ctx, sessionToken)
	if err != nil {
		return err
	}
	if u.EmailVerified() {
		return nil
	}
	return s.sendVerification(ctx, u.ID, u.Email)
}

func (s *Service) ForgotPassword(ctx context.Context, email string) error {
	email, err := normalizeEmail(email)
	if err != nil {
		return err
	}

	u, err := s.users.ByEmail(ctx, email)
	if errors.Is(err, user.ErrNotFound) {
		s.record(ctx, audit.Event{Type: audit.PasswordResetRequested, Email: email})
		return nil
	}
	if err != nil {
		return err
	}

	token, err := s.tokens.Issue(ctx, onetime.ResetPassword, u.ID, resetTTL)
	if err != nil {
		return err
	}
	s.send(ctx, mail.Message{
		To:      u.Email,
		Subject: "Redefinição de senha",
		Text: lines(
			"Recebemos um pedido para redefinir a senha da sua conta.",
			"",
			"Para escolher uma senha nova, abra o link abaixo. Ele vale por 30 minutos e só funciona uma vez:",
			"",
			s.link("/redefinir-senha", token),
			"",
			"Se não foi você, pode ignorar este e-mail. Sua senha continua a mesma.",
		),
	})
	s.record(ctx, audit.Event{Type: audit.PasswordResetRequested, UserID: u.ID, Email: email})
	return nil
}

func (s *Service) ResetPassword(ctx context.Context, token, plain string) error {
	if err := password.Validate(plain); err != nil {
		return err
	}

	userID, err := s.tokens.Consume(ctx, onetime.ResetPassword, token)
	if errors.Is(err, onetime.ErrInvalid) {
		return ErrInvalidLink
	}
	if err != nil {
		return err
	}
	u, err := s.users.ByID(ctx, userID)
	if errors.Is(err, user.ErrNotFound) {
		return ErrInvalidLink
	}
	if err != nil {
		return err
	}

	hash, err := s.hasher.Hash(ctx, plain)
	if err != nil {
		return fmt.Errorf("gerando hash: %w", err)
	}
	if err := s.users.UpdatePasswordHash(ctx, u.ID, hash); err != nil {
		return err
	}
	if err := s.sessions.DeleteAll(ctx, u.ID); err != nil {
		return err
	}
	if err := s.users.MarkEmailVerified(ctx, u.ID); err != nil {
		s.logger.WarnContext(ctx, "falha ao marcar e-mail verificado", slog.Any("error", err))
	}
	s.clearAccountLock(ctx, u.Email)

	s.record(ctx, audit.Event{Type: audit.PasswordReset, UserID: u.ID, Email: u.Email})
	s.send(ctx, mail.Message{
		To:      u.Email,
		Subject: "Sua senha foi alterada",
		Text: lines(
			"A senha da sua conta acabou de ser alterada, e todas as sessões abertas foram encerradas.",
			"",
			"Se não foi você, peça uma nova redefinição agora mesmo:",
			"",
			s.publicURL+"/esqueci-a-senha",
		),
	})
	return nil
}

func (s *Service) sendVerification(ctx context.Context, userID, email string) error {
	token, err := s.tokens.Issue(ctx, onetime.VerifyEmail, userID, verifyTTL)
	if err != nil {
		return err
	}
	s.send(ctx, mail.Message{
		To:      email,
		Subject: "Confirme seu e-mail",
		Text: lines(
			"Falta pouco. Para confirmar seu e-mail, abra o link abaixo. Ele vale por 24 horas:",
			"",
			s.link("/verificar-email", token),
			"",
			"Se você não criou uma conta, pode ignorar este e-mail.",
		),
	})
	return nil
}

func (s *Service) sendAccountExists(ctx context.Context, email string) {
	s.send(ctx, mail.Message{
		To:      email,
		Subject: "Você já tem uma conta",
		Text: lines(
			"Alguém tentou criar uma conta com este e-mail, mas ele já está cadastrado.",
			"",
			"Se foi você e esqueceu a senha, é só pedir uma nova:",
			"",
			s.publicURL+"/esqueci-a-senha",
			"",
			"Se não foi você, pode ignorar este e-mail. Nada mudou na sua conta.",
		),
	})
}

func (s *Service) send(ctx context.Context, m mail.Message) {
	if err := s.mailer.Send(ctx, m); err != nil {
		s.logger.ErrorContext(ctx, "falha ao enfileirar e-mail",
			slog.String("subject", m.Subject),
			slog.Any("error", err),
		)
	}
}

func (s *Service) link(path, token string) string {
	return s.publicURL + path + "#token=" + token
}

func lines(l ...string) string {
	return strings.Join(l, "\n") + "\n"
}
