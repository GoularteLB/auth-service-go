package audit

import (
	"context"
	"fmt"
	"net/netip"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgxpool"
)

const maxUserAgentLength = 512

type Type string

const (
	SignupCreated   Type = "signup.created"
	SignupDuplicate Type = "signup.duplicate"
	LoginSucceeded  Type = "login.succeeded"
	LoginFailed     Type = "login.failed"
	LoginLocked     Type = "login.locked"
	LoggedOut       Type = "logout"

	LoginMFARequired Type = "login.mfa_required"
	LoginMFAFailed   Type = "login.mfa_failed"
	MFAEnabled       Type = "mfa.enabled"
	MFADisabled      Type = "mfa.disabled"
	MFARecoveryUsed  Type = "mfa.recovery_code_used"

	EmailVerified          Type = "email.verified"
	PasswordResetRequested Type = "password.reset_requested"
	PasswordReset          Type = "password.reset"

	ClientAuthFailed  Type = "client.auth_failed"
	ClientForbidden   Type = "client.forbidden"
	ClientTokenIssued Type = "client.token_issued"
)

type Event struct {
	Type     Type
	UserID   string
	Email    string
	ClientID string
}

type Client struct {
	IP        string
	UserAgent string
	RequestID string
}

type ctxKey struct{}

func WithClient(ctx context.Context, c Client) context.Context {
	return context.WithValue(ctx, ctxKey{}, c)
}

func ClientFrom(ctx context.Context) Client {
	c, _ := ctx.Value(ctxKey{}).(Client)
	return c
}

type Store struct {
	db *pgxpool.Pool
}

func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

func (s *Store) Record(ctx context.Context, e Event) error {
	c := ClientFrom(ctx)
	_, err := s.db.Exec(ctx,
		`INSERT INTO audit_events (event_type, user_id, email, client_id, ip, user_agent, request_id)
		 VALUES ($1, $2::uuid, $3, $4, $5::inet, $6, $7)`,
		string(e.Type), nullable(e.UserID), nullable(e.Email), nullable(e.ClientID), nullable(validIP(c.IP)),
		nullable(truncate(c.UserAgent, maxUserAgentLength)), nullable(c.RequestID),
	)
	if err != nil {
		return fmt.Errorf("gravando evento de auditoria: %w", err)
	}
	return nil
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func validIP(s string) string {
	if _, err := netip.ParseAddr(s); err != nil {
		return ""
	}
	return s
}

func truncate(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	r := []rune(s)
	return string(r[:max])
}
