package client

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/GoularteLB/auth-service/internal/audit"
)

var (
	ErrInvalidClient = errors.New("cliente inválido")
	ErrForbidden     = errors.New("cliente sem permissão para esta operação")
	ErrInvalidTarget = errors.New("audiência não permitida para este cliente")
)

type Repository interface {
	Active(ctx context.Context, clientID string) (Client, [32]byte, error)
}

type Issuer interface {
	Issue(subject, clientID, audience string, scopes, amr []string) (string, time.Duration, error)
}

type Auditor interface {
	Record(ctx context.Context, e audit.Event) error
}

type Token struct {
	Value  string
	TTL    time.Duration
	Scopes []string
}

type Service struct {
	repo   Repository
	tokens Issuer
	audit  Auditor
	logger *slog.Logger
	dummy  [32]byte
}

func NewService(repo Repository, tokens Issuer, auditor Auditor, logger *slog.Logger) *Service {
	return &Service{repo: repo, tokens: tokens, audit: auditor, logger: logger, dummy: HashSecret("dummy")}
}

func (s *Service) Authenticate(ctx context.Context, clientID, secret string) (Client, error) {
	if !validClientID(clientID) || secret == "" || len(secret) > 256 {
		s.record(ctx, audit.Event{Type: audit.ClientAuthFailed})
		return Client{}, ErrInvalidClient
	}

	c, stored, err := s.repo.Active(ctx, clientID)
	switch {
	case errors.Is(err, ErrNotFound):
		stored = s.dummy
	case err != nil:
		return Client{}, err
	}

	given := HashSecret(secret)
	if subtle.ConstantTimeCompare(given[:], stored[:]) != 1 || err != nil {
		s.record(ctx, audit.Event{Type: audit.ClientAuthFailed, ClientID: clientID})
		return Client{}, ErrInvalidClient
	}
	return c, nil
}

func (s *Service) Authorize(ctx context.Context, clientID, secret, scope string) (Client, error) {
	c, err := s.Authenticate(ctx, clientID, secret)
	if err != nil {
		return Client{}, err
	}
	if !slices.Contains(c.Scopes, scope) {
		s.record(ctx, audit.Event{Type: audit.ClientForbidden, ClientID: c.ClientID})
		return Client{}, ErrForbidden
	}
	return c, nil
}

func (s *Service) Token(ctx context.Context, clientID, secret, scope, audience string) (Token, error) {
	c, err := s.Authenticate(ctx, clientID, secret)
	if err != nil {
		return Token{}, err
	}
	audience, err = s.Audience(ctx, c, audience)
	if err != nil {
		return Token{}, err
	}

	granted := c.Scopes
	if requested := strings.Fields(scope); len(requested) > 0 {
		for _, r := range requested {
			if !slices.Contains(c.Scopes, r) {
				s.record(ctx, audit.Event{Type: audit.ClientForbidden, ClientID: c.ClientID})
				return Token{}, fmt.Errorf("%w: %q", ErrInvalidScope, r)
			}
		}
		granted, _ = NormalizeScopes(requested)
	}

	value, ttl, err := s.tokens.Issue(c.ClientID, c.ClientID, audience, granted, nil)
	if err != nil {
		return Token{}, err
	}
	s.record(ctx, audit.Event{Type: audit.ClientTokenIssued, ClientID: c.ClientID})
	return Token{Value: value, TTL: ttl, Scopes: granted}, nil
}

func (s *Service) Audience(ctx context.Context, c Client, requested string) (string, error) {
	if requested == "" && len(c.Audiences) == 0 {
		return "", nil
	}
	if requested != "" && slices.Contains(c.Audiences, requested) {
		return requested, nil
	}
	s.record(ctx, audit.Event{Type: audit.ClientForbidden, ClientID: c.ClientID})
	return "", fmt.Errorf("%w: %q", ErrInvalidTarget, requested)
}

func (s *Service) record(ctx context.Context, e audit.Event) {
	if err := s.audit.Record(ctx, e); err != nil {
		s.logger.WarnContext(ctx, "falha ao gravar auditoria",
			slog.String("event", string(e.Type)),
			slog.Any("error", err),
		)
	}
}

func validClientID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if r > unicode.MaxASCII || !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '-' {
			return false
		}
	}
	return true
}
