package auth

import (
	"context"
	"log/slog"
	"time"

	"github.com/GoularteLB/auth-service/internal/audit"
)

func passwordLockKey(ctx context.Context, email string) string {
	return "pwd:" + email + "|" + audit.ClientFrom(ctx).Bucket()
}

func accountLockKey(email string) string {
	return "account:" + email
}

func (s *Service) checkPasswordLock(ctx context.Context, email string) (time.Duration, error) {
	local, err := s.lockout.Check(ctx, passwordLockKey(ctx, email))
	if err != nil {
		return 0, err
	}
	global, err := s.accountLockout.Check(ctx, accountLockKey(email))
	if err != nil {
		return 0, err
	}
	return max(local, global), nil
}

func (s *Service) failPassword(ctx context.Context, email string) error {
	if _, err := s.lockout.Fail(ctx, passwordLockKey(ctx, email)); err != nil {
		return err
	}
	_, err := s.accountLockout.Fail(ctx, accountLockKey(email))
	return err
}

func (s *Service) clearPasswordLock(ctx context.Context, email string) {
	if err := s.lockout.Reset(ctx, passwordLockKey(ctx, email)); err != nil {
		s.logger.WarnContext(ctx, "falha ao limpar bloqueio", slog.Any("error", err))
	}
}

func (s *Service) clearAccountLock(ctx context.Context, email string) {
	s.clearPasswordLock(ctx, email)
	if err := s.accountLockout.Reset(ctx, accountLockKey(email)); err != nil {
		s.logger.WarnContext(ctx, "falha ao limpar bloqueio da conta", slog.Any("error", err))
	}
}
