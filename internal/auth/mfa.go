package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/GoularteLB/auth-service/internal/audit"
	"github.com/GoularteLB/auth-service/internal/mail"
	"github.com/GoularteLB/auth-service/internal/mfa"
	"github.com/GoularteLB/auth-service/internal/onetime"
	"github.com/GoularteLB/auth-service/internal/user"
	"github.com/GoularteLB/auth-service/pkg/authn"
)

const MFAChallengeTTL = 5 * time.Minute

var (
	ErrMFARequired       = errors.New("informe o código do autenticador")
	ErrMFAChallenge      = errors.New("desafio de mfa inválido ou expirado, faça login de novo")
	ErrInvalidMFACode    = errors.New("código inválido")
	ErrMFANotEnabled     = mfa.ErrNotEnabled
	ErrMFAEnabled        = mfa.ErrAlreadyEnabled
	ErrMFANoPendingSetup = mfa.ErrNoPendingSetup
)

type MFA interface {
	Enabled(ctx context.Context, userID string) (bool, error)
	Setup(ctx context.Context, userID, account string) (mfa.Setup, error)
	Enable(ctx context.Context, userID, code string) ([]string, error)
	Verify(ctx context.Context, userID, code string) (bool, error)
	Disable(ctx context.Context, userID string) error
}

type MFARequiredError struct {
	Challenge string
}

func (e *MFARequiredError) Error() string { return ErrMFARequired.Error() }

func (e *MFARequiredError) Unwrap() error { return ErrMFARequired }

func (s *Service) MFAEnabled(ctx context.Context, userID string) (bool, error) {
	return s.mfa.Enabled(ctx, userID)
}

func (s *Service) LoginMFA(ctx context.Context, challenge, code string) (string, error) {
	userID, err := s.tokens.Peek(ctx, onetime.MFAChallenge, challenge)
	if errors.Is(err, onetime.ErrInvalid) {
		return "", ErrMFAChallenge
	}
	if err != nil {
		return "", err
	}

	key := mfaLockKey(userID)
	retry, err := s.lockout.Check(ctx, key)
	if err != nil {
		return "", err
	}
	if retry > 0 {
		s.record(ctx, audit.Event{Type: audit.LoginLocked, UserID: userID})
		return "", &LockedError{RetryAfter: retry}
	}

	recovery, err := s.mfa.Verify(ctx, userID, code)
	if errors.Is(err, mfa.ErrInvalidCode) {
		s.record(ctx, audit.Event{Type: audit.LoginMFAFailed, UserID: userID})
		if _, err := s.lockout.Fail(ctx, key); err != nil {
			return "", err
		}
		return "", ErrInvalidMFACode
	}
	if errors.Is(err, mfa.ErrNotEnabled) {
		return "", ErrMFAChallenge
	}
	if err != nil {
		return "", err
	}

	if _, err := s.tokens.Consume(ctx, onetime.MFAChallenge, challenge); err != nil {
		if errors.Is(err, onetime.ErrInvalid) {
			return "", ErrMFAChallenge
		}
		return "", err
	}
	if err := s.lockout.Reset(ctx, key); err != nil {
		s.logger.WarnContext(ctx, "falha ao limpar bloqueio de mfa", slog.Any("error", err))
	}

	amr := []string{authn.AMRPassword, authn.AMROTP, authn.AMRMFA}
	if recovery {
		amr = []string{authn.AMRPassword, authn.AMRMFA}
	}
	token, err := s.sessions.Create(ctx, userID, amr)
	if err != nil {
		return "", err
	}
	if recovery {
		s.record(ctx, audit.Event{Type: audit.MFARecoveryUsed, UserID: userID})
	}
	s.record(ctx, audit.Event{Type: audit.LoginSucceeded, UserID: userID})
	return token, nil
}

func (s *Service) SetupMFA(ctx context.Context, sessionToken, plain string) (mfa.Setup, error) {
	u, err := s.Current(ctx, sessionToken)
	if err != nil {
		return mfa.Setup{}, err
	}
	if err := s.confirmPassword(ctx, u, plain); err != nil {
		return mfa.Setup{}, err
	}
	return s.mfa.Setup(ctx, u.ID, u.Email)
}

func (s *Service) EnableMFA(ctx context.Context, sessionToken, code string) ([]string, error) {
	u, err := s.Current(ctx, sessionToken)
	if err != nil {
		return nil, err
	}
	codes, err := s.mfa.Enable(ctx, u.ID, code)
	if errors.Is(err, mfa.ErrInvalidCode) {
		return nil, ErrInvalidMFACode
	}
	if err != nil {
		return nil, err
	}
	s.record(ctx, audit.Event{Type: audit.MFAEnabled, UserID: u.ID})
	s.send(ctx, mail.Message{
		To:      u.Email,
		Subject: "Verificação em duas etapas ativada",
		Text: lines(
			"A verificação em duas etapas foi ativada na sua conta. A partir de agora o login também pede o código do autenticador.",
			"",
			"Se não foi você, redefina sua senha agora mesmo:",
			"",
			s.publicURL+"/esqueci-a-senha",
		),
	})
	return codes, nil
}

func (s *Service) DisableMFA(ctx context.Context, sessionToken, plain, code string) error {
	u, err := s.Current(ctx, sessionToken)
	if err != nil {
		return err
	}
	if err := s.confirmPassword(ctx, u, plain); err != nil {
		return err
	}
	if _, err := s.mfa.Verify(ctx, u.ID, code); err != nil {
		if errors.Is(err, mfa.ErrInvalidCode) {
			return ErrInvalidMFACode
		}
		return err
	}
	if err := s.mfa.Disable(ctx, u.ID); err != nil {
		return err
	}
	s.record(ctx, audit.Event{Type: audit.MFADisabled, UserID: u.ID})
	s.send(ctx, mail.Message{
		To:      u.Email,
		Subject: "Verificação em duas etapas desativada",
		Text: lines(
			"A verificação em duas etapas foi desativada na sua conta.",
			"",
			"Se não foi você, redefina sua senha agora mesmo e ative a verificação de novo:",
			"",
			s.publicURL+"/esqueci-a-senha",
		),
	})
	return nil
}

func (s *Service) confirmPassword(ctx context.Context, u user.User, plain string) error {
	retry, err := s.lockout.Check(ctx, u.Email)
	if err != nil {
		return err
	}
	if retry > 0 {
		return &LockedError{RetryAfter: retry}
	}
	ok, err := s.hasher.Verify(ctx, plain, u.PasswordHash)
	if err != nil {
		return fmt.Errorf("verificando senha: %w", err)
	}
	if !ok {
		return s.fail(ctx, audit.Event{Type: audit.LoginFailed, UserID: u.ID, Email: u.Email})
	}
	return nil
}

func (s *Service) challengeMFA(ctx context.Context, u user.User) error {
	challenge, err := s.tokens.Issue(ctx, onetime.MFAChallenge, u.ID, MFAChallengeTTL)
	if err != nil {
		return err
	}
	s.record(ctx, audit.Event{Type: audit.LoginMFARequired, UserID: u.ID, Email: u.Email})
	return &MFARequiredError{Challenge: challenge}
}

func mfaLockKey(userID string) string {
	return "mfa:" + userID
}
