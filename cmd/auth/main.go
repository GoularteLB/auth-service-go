package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/GoularteLB/auth-service/internal/config"
	"github.com/GoularteLB/auth-service/internal/database"
	"github.com/GoularteLB/auth-service/internal/httpserver"
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

	handler := httpserver.NewHandler(httpserver.Deps{
		Logger:     logger,
		DB:         pool,
		Production: cfg.IsProduction(),
	})
	srv := httpserver.New(cfg.HTTPAddr, handler, logger)

	logger.Info("auth-service iniciando", slog.Any("config", cfg))
	if err := httpserver.Run(ctx, srv, cfg.ShutdownTimeout); err != nil {
		return err
	}
	logger.Info("auth-service encerrado")
	return nil
}

func newLogger(cfg config.Config) *slog.Logger {
	opts := &slog.HandlerOptions{Level: cfg.LogLevel}
	if cfg.IsProduction() {
		return slog.New(slog.NewJSONHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stdout, opts))
}
