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

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sync/errgroup"

	"github.com/GoularteLB/auth-service/internal/audit"
	"github.com/GoularteLB/auth-service/internal/auth"
	"github.com/GoularteLB/auth-service/internal/client"
	"github.com/GoularteLB/auth-service/internal/config"
	"github.com/GoularteLB/auth-service/internal/database"
	"github.com/GoularteLB/auth-service/internal/httpserver"
	"github.com/GoularteLB/auth-service/internal/mail"
	"github.com/GoularteLB/auth-service/internal/mfa"
	"github.com/GoularteLB/auth-service/internal/onetime"
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

	auditStore := audit.NewStore(pool)
	limiter := ratelimit.NewLimiter(rdb)

	sender, err := newSender(cfg, logger)
	if err != nil {
		return err
	}
	mailQueue := mail.NewQueue(sender, logger, 1000)

	mfaService, err := newMFA(cfg, pool, logger)
	if err != nil {
		return err
	}

	authService := auth.NewService(auth.Deps{
		Users:     user.NewStore(pool),
		Sessions:  session.NewStore(rdb, cfg.SessionTTL),
		Hasher:    hasher,
		Lockout:   ratelimit.NewLockout(rdb, ratelimit.DefaultLockoutPolicy),
		Audit:     auditStore,
		Tokens:    onetime.NewStore(rdb),
		Mailer:    mailQueue,
		MFA:       mfaService,
		PublicURL: cfg.PublicURL,
		Logger:    logger,
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
		Limiter:        limiter,
		TrustedProxies: cfg.TrustedProxies,
		SessionTTL:     cfg.SessionTTL,
		Production:     cfg.IsProduction(),
	})
	internal := httpserver.NewInternalHandler(httpserver.InternalDeps{
		Logger:         logger,
		Auth:           authService,
		Clients:        client.NewService(client.NewStore(pool), issuer, auditStore, logger),
		Tokens:         issuer,
		Limiter:        limiter,
		TrustedProxies: cfg.TrustedProxies,
	})

	logger.Info("auth-service iniciando", slog.Any("config", cfg), slog.String("jwt_kid", issuer.KeyID()))
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		mailQueue.Run(gctx, 4)
		return nil
	})
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

func newMFA(cfg config.Config, pool *pgxpool.Pool, logger *slog.Logger) (*mfa.Service, error) {
	key := cfg.MFAKey
	if len(key) == 0 {
		logger.Warn("AUTH_MFA_KEY vazio, usando chave temporária: quem ativar mfa perde o acesso ao reiniciar")
		key = mfa.GenerateKey()
	}
	cipher, err := mfa.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return mfa.NewService(mfa.NewPostgresStore(pool), cipher, cfg.MFAIssuer), nil
}

func newSender(cfg config.Config, logger *slog.Logger) (mail.Sender, error) {
	if cfg.SMTPURL == "" {
		logger.Warn("AUTH_SMTP_URL vazio, e-mails vão só para o log")
		return mail.LogSender{Logger: logger}, nil
	}
	from, err := mail.ParseFrom(cfg.MailFrom)
	if err != nil {
		return nil, err
	}
	return mail.NewSMTPSender(cfg.SMTPURL, from, cfg.IsProduction())
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
