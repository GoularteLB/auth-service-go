package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"strings"
	"time"

	"github.com/GoularteLB/auth-service/internal/audit"
	"github.com/GoularteLB/auth-service/internal/password"
	"github.com/GoularteLB/auth-service/internal/session"
	"github.com/GoularteLB/auth-service/internal/user"
	"github.com/GoularteLB/auth-service/pkg/authn"
)

const maxEmailLength = 254

var (
	ErrInvalidEmail       = errors.New("e-mail inválido")
	ErrInvalidCredentials = errors.New("credenciais inválidas")
	ErrUnauthenticated    = errors.New("não autenticado")
	ErrLocked             = errors.New("muitas tentativas, tente novamente mais tarde")
)

type LockedError struct {
	RetryAfter time.Duration
}

func (e *LockedError) Error() string { return ErrLocked.Error() }

func (e *LockedError) Unwrap() error { return ErrLocked }

type Users interface {
	Create(ctx context.Context, email, passwordHash string) (user.User, error)
	ByEmail(ctx context.Context, email string) (user.User, error)
	ByID(ctx context.Context, id string) (user.User, error)
	UpdatePasswordHash(ctx context.Context, id, passwordHash string) error
	MarkEmailVerified(ctx context.Context, id string) error
}

type Sessions interface {
	Create(ctx context.Context, userID string, amr []string) (string, error)
	Get(ctx context.Context, token string) (session.Session, error)
	Delete(ctx context.Context, token string) error
	DeleteAll(ctx context.Context, userID string) error
}

type Lockout interface {
	Check(ctx context.Context, key string) (time.Duration, error)
	Fail(ctx context.Context, key string) (time.Duration, error)
	Reset(ctx context.Context, key string) error
}

type Auditor interface {
	Record(ctx context.Context, e audit.Event) error
}

type Deps struct {
	Users          Users
	Sessions       Sessions
	Hasher         *password.Hasher
	Lockout        Lockout
	AccountLockout Lockout
	Audit          Auditor
	Tokens         OneTimeTokens
	Mailer         Mailer
	MFA            MFA
	PublicURL      string
	Logger         *slog.Logger
}

type Service struct {
	users          Users
	sessions       Sessions
	hasher         *password.Hasher
	lockout        Lockout
	accountLockout Lockout
	audit          Auditor
	tokens         OneTimeTokens
	mailer         Mailer
	mfa            MFA
	publicURL      string
	logger         *slog.Logger
}

func NewService(d Deps) *Service {
	return &Service{
		users:          d.Users,
		sessions:       d.Sessions,
		hasher:         d.Hasher,
		lockout:        d.Lockout,
		accountLockout: d.AccountLockout,
		audit:          d.Audit,
		tokens:         d.Tokens,
		mailer:         d.Mailer,
		mfa:            d.MFA,
		publicURL:      strings.TrimRight(d.PublicURL, "/"),
		logger:         d.Logger,
	}
}

func (s *Service) Signup(ctx context.Context, email, plain string) error {
	email, err := normalizeEmail(email)
	if err != nil {
		return err
	}
	if err := password.Validate(plain); err != nil {
		return err
	}

	hash, err := s.hasher.Hash(ctx, plain)
	if err != nil {
		return fmt.Errorf("gerando hash: %w", err)
	}

	u, err := s.users.Create(ctx, email, hash)
	switch {
	case errors.Is(err, user.ErrEmailTaken):
		s.record(ctx, audit.Event{Type: audit.SignupDuplicate, Email: email})
		s.sendAccountExists(ctx, email)
		return nil
	case err != nil:
		return err
	}
	s.record(ctx, audit.Event{Type: audit.SignupCreated, UserID: u.ID, Email: email})
	if err := s.sendVerification(ctx, u.ID, email); err != nil {
		s.logger.ErrorContext(ctx, "falha ao preparar verificação de e-mail", slog.Any("error", err))
	}
	return nil
}

func (s *Service) Login(ctx context.Context, email, plain string) (string, error) {
	email, emailErr := normalizeEmail(email)
	if emailErr != nil || len(plain) > password.MaxLength*4 {
		return "", s.reject(ctx, plain)
	}

	retry, err := s.checkPasswordLock(ctx, email)
	if err != nil {
		return "", err
	}
	if retry > 0 {
		s.record(ctx, audit.Event{Type: audit.LoginLocked, Email: email})
		return "", &LockedError{RetryAfter: retry}
	}

	u, err := s.users.ByEmail(ctx, email)
	if errors.Is(err, user.ErrNotFound) {
		if err := s.reject(ctx, plain); !errors.Is(err, ErrInvalidCredentials) {
			return "", err
		}
		return "", s.fail(ctx, audit.Event{Type: audit.LoginFailed, Email: email})
	}
	if err != nil {
		return "", err
	}

	ok, err := s.hasher.Verify(ctx, plain, u.PasswordHash)
	if err != nil {
		return "", fmt.Errorf("verificando senha: %w", err)
	}
	if !ok {
		return "", s.fail(ctx, audit.Event{Type: audit.LoginFailed, UserID: u.ID, Email: email})
	}

	if s.hasher.NeedsRehash(u.PasswordHash) {
		s.rehash(ctx, u.ID, plain)
	}
	s.clearPasswordLock(ctx, email)

	mfaOn, err := s.mfa.Enabled(ctx, u.ID)
	if err != nil {
		return "", err
	}
	if mfaOn {
		return "", s.challengeMFA(ctx, u)
	}

	token, err := s.sessions.Create(ctx, u.ID, []string{authn.AMRPassword})
	if err != nil {
		return "", err
	}
	s.record(ctx, audit.Event{Type: audit.LoginSucceeded, UserID: u.ID, Email: email})
	return token, nil
}

func (s *Service) Logout(ctx context.Context, token string) error {
	sess, err := s.sessions.Get(ctx, token)
	if errors.Is(err, session.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := s.sessions.Delete(ctx, token); err != nil {
		return err
	}
	s.record(ctx, audit.Event{Type: audit.LoggedOut, UserID: sess.UserID})
	return nil
}

func (s *Service) Current(ctx context.Context, token string) (user.User, error) {
	u, _, err := s.Identify(ctx, token)
	return u, err
}

func (s *Service) Identify(ctx context.Context, token string) (user.User, []string, error) {
	sess, err := s.sessions.Get(ctx, token)
	if errors.Is(err, session.ErrNotFound) {
		return user.User{}, nil, ErrUnauthenticated
	}
	if err != nil {
		return user.User{}, nil, err
	}

	u, err := s.users.ByID(ctx, sess.UserID)
	if errors.Is(err, user.ErrNotFound) {
		if err := s.sessions.Delete(ctx, token); err != nil {
			s.logger.WarnContext(ctx, "falha ao apagar sessão órfã", slog.Any("error", err))
		}
		return user.User{}, nil, ErrUnauthenticated
	}
	if err != nil {
		return user.User{}, nil, err
	}
	return u, sess.AMR, nil
}

func (s *Service) reject(ctx context.Context, plain string) error {
	if len(plain) > password.MaxLength*4 {
		plain = plain[:password.MaxLength*4]
	}
	if err := s.hasher.VerifyDummy(ctx, plain); err != nil {
		return fmt.Errorf("verificando senha: %w", err)
	}
	return ErrInvalidCredentials
}

func (s *Service) fail(ctx context.Context, e audit.Event) error {
	s.record(ctx, e)
	if err := s.failPassword(ctx, e.Email); err != nil {
		return err
	}
	return ErrInvalidCredentials
}

func (s *Service) record(ctx context.Context, e audit.Event) {
	if err := s.audit.Record(ctx, e); err != nil {
		s.logger.WarnContext(ctx, "falha ao gravar auditoria",
			slog.String("event", string(e.Type)),
			slog.Any("error", err),
		)
	}
}

func (s *Service) rehash(ctx context.Context, userID, plain string) {
	hash, err := s.hasher.Hash(ctx, plain)
	if err == nil {
		err = s.users.UpdatePasswordHash(ctx, userID, hash)
	}
	if err != nil {
		s.logger.WarnContext(ctx, "falha ao atualizar hash de senha", slog.Any("error", err))
	}
}

func normalizeEmail(raw string) (string, error) {
	email := strings.TrimSpace(raw)
	if email == "" || len(email) > maxEmailLength {
		return "", ErrInvalidEmail
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Name != "" || addr.Address != email {
		return "", ErrInvalidEmail
	}
	if !strings.Contains(email[strings.LastIndex(email, "@")+1:], ".") {
		return "", ErrInvalidEmail
	}
	return strings.ToLower(email), nil
}
