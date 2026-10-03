package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
)

type Environment string

const (
	Development Environment = "development"
	Production  Environment = "production"
)

type Config struct {
	Env             Environment
	HTTPAddr        string
	DatabaseURL     string
	LogLevel        slog.Level
	ShutdownTimeout time.Duration
}

func (c Config) IsProduction() bool {
	return c.Env == Production
}

func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("env", string(c.Env)),
		slog.String("http_addr", c.HTTPAddr),
		slog.String("database_url", redactURL(c.DatabaseURL)),
		slog.String("log_level", c.LogLevel.String()),
		slog.Duration("shutdown_timeout", c.ShutdownTimeout),
	)
}

func Load() (Config, error) {
	return load(os.LookupEnv)
}

func load(lookup func(string) (string, bool)) (Config, error) {
	get := func(key, fallback string) string {
		if v, ok := lookup(key); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
		return fallback
	}

	var errs []error
	cfg := Config{
		Env:         Environment(get("AUTH_ENV", string(Development))),
		HTTPAddr:    get("AUTH_HTTP_ADDR", ":8080"),
		DatabaseURL: get("AUTH_DATABASE_URL", ""),
	}

	if cfg.Env != Development && cfg.Env != Production {
		errs = append(errs, fmt.Errorf("AUTH_ENV deve ser %q ou %q, recebido %q", Development, Production, cfg.Env))
	}

	if _, _, err := net.SplitHostPort(cfg.HTTPAddr); err != nil {
		errs = append(errs, fmt.Errorf("AUTH_HTTP_ADDR inválido: %w", err))
	}

	if err := cfg.LogLevel.UnmarshalText([]byte(get("AUTH_LOG_LEVEL", "info"))); err != nil {
		errs = append(errs, fmt.Errorf("AUTH_LOG_LEVEL inválido: %w", err))
	}

	timeout, err := time.ParseDuration(get("AUTH_SHUTDOWN_TIMEOUT", "15s"))
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("AUTH_SHUTDOWN_TIMEOUT inválido: %w", err))
	case timeout <= 0 || timeout > time.Minute:
		errs = append(errs, errors.New("AUTH_SHUTDOWN_TIMEOUT deve estar entre 0 e 1m"))
	default:
		cfg.ShutdownTimeout = timeout
	}

	if err := validateDatabaseURL(cfg.DatabaseURL, cfg.Env); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return Config{}, errors.Join(errs...)
	}
	return cfg, nil
}

func validateDatabaseURL(raw string, env Environment) error {
	if raw == "" {
		return errors.New("AUTH_DATABASE_URL é obrigatório")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("AUTH_DATABASE_URL não é uma URL válida")
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return fmt.Errorf("AUTH_DATABASE_URL deve usar o esquema postgres://, recebido %q", u.Scheme)
	}
	if u.Host == "" || strings.Trim(u.Path, "/") == "" {
		return errors.New("AUTH_DATABASE_URL precisa de host e nome do banco")
	}
	if env == Production {
		secure := []string{"require", "verify-ca", "verify-full"}
		if !slices.Contains(secure, u.Query().Get("sslmode")) {
			return errors.New("em produção AUTH_DATABASE_URL precisa de sslmode=require, verify-ca ou verify-full")
		}
	}
	return nil
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[inválida]"
	}
	return u.Redacted()
}
