package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"golang.org/x/sync/errgroup"

	"github.com/GoularteLB/auth-service/internal/audit"
	"github.com/GoularteLB/auth-service/internal/auth"
	"github.com/GoularteLB/auth-service/internal/config"
	"github.com/GoularteLB/auth-service/internal/database"
	"github.com/GoularteLB/auth-service/internal/httpserver"
	"github.com/GoularteLB/auth-service/internal/password"
	"github.com/GoularteLB/auth-service/internal/ratelimit"
	"github.com/GoularteLB/auth-service/internal/session"
	"github.com/GoularteLB/auth-service/internal/token"
	"github.com/GoularteLB/auth-service/internal/user"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx)
	stop()
	if err != nil {
		slog.Error("auth-service encerrado com erro", slog.Any("error", err))
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuração inválida: %w", err)
	}

	logger := newLogger(cfg)
	slog.SetDefault(logger)

	pool, err := database.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	rdb, err := database.OpenRedis(ctx, cfg.RedisURL)
	if err != nil {
		return err
	}
	defer func() {
		if err := rdb.Close(); err != nil {
			logger.Warn("erro ao fechar redis", slog.Any("error", err))
		}
	}()

	hasher, err := password.NewHasher(password.DefaultParams, runtime.NumCPU())
	if err != nil {
		return err
	}

	authService := auth.NewService(auth.Deps{
		Users:    user.NewStore(pool),
		Sessions: session.NewStore(rdb, cfg.SessionTTL),
		Hasher:   hasher,
		Lockout:  ratelimit.NewLockout(rdb, ratelimit.DefaultLockoutPolicy),
		Audit:    audit.NewStore(pool),
		Logger:   logger,
	})

	issuer, err := newIssuer(cfg, logger)
	if err != nil {
		return err
	}

	public := httpserver.NewHandler(httpserver.Deps{
		Logger: logger,
		Checks: map[string]httpserver.Pinger{
			"postgres": pool,
			"redis":    database.RedisPinger{Client: rdb},
		},
		Auth:           authService,
		Limiter:        ratelimit.NewLimiter(rdb),
		TrustedProxies: cfg.TrustedProxies,
		SessionTTL:     cfg.SessionTTL,
		Production:     cfg.IsProduction(),
	})
	internal := httpserver.NewInternalHandler(httpserver.InternalDeps{
		Logger:         logger,
		Auth:           authService,
		Tokens:         issuer,
		TrustedProxies: cfg.TrustedProxies,
	})

	logger.Info("auth-service iniciando", slog.Any("config", cfg), slog.String("jwt_kid", issuer.KeyID()))
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return httpserver.Run(gctx, httpserver.New(cfg.HTTPAddr, public, logger), cfg.ShutdownTimeout)
	})
	g.Go(func() error {
		return httpserver.Run(gctx, httpserver.New(cfg.InternalAddr, internal, logger), cfg.ShutdownTimeout)
	})
	if err := g.Wait(); err != nil {
		return err
	}
	logger.Info("auth-service encerrado")
	return nil
}

func newIssuer(cfg config.Config, logger *slog.Logger) (*token.Issuer, error) {
	var key ed25519.PrivateKey
	var err error
	if cfg.JWT.KeyFile == "" {
		logger.Warn("AUTH_JWT_KEY_FILE vazio, usando chave efêmera de desenvolvimento")
		key, err = token.GenerateKey()
	} else {
		key, err = token.LoadPrivateKey(cfg.JWT.KeyFile)
	}
	if err != nil {
		return nil, err
	}

	previous := make([]ed25519.PublicKey, 0, len(cfg.JWT.PreviousKeyFiles))
	for _, path := range cfg.JWT.PreviousKeyFiles {
		pub, err := token.LoadPublicKey(path)
		if err != nil {
			return nil, err
		}
		previous = append(previous, pub)
	}

	return token.NewIssuer(key, previous, token.Options{
		Issuer:   cfg.JWT.Issuer,
		Audience: cfg.JWT.Audience,
		TTL:      cfg.JWT.TTL,
	}), nil
}

func newLogger(cfg config.Config) *slog.Logger {
	opts := &slog.HandlerOptions{Level: cfg.LogLevel}
	if cfg.IsProduction() {
		return slog.New(slog.NewJSONHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stdout, opts))
}
