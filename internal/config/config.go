package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/mail"
	"net/netip"
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
	InternalAddr    string
	DatabaseURL     string
	RedisURL        string
	LogLevel        slog.Level
	ShutdownTimeout time.Duration
	SessionTTL      time.Duration
	TrustedProxies  []netip.Prefix
	JWT             JWT
	PublicURL       string
	SMTPURL         string
	MailFrom        string
	MFAKey          []byte
	MFAIssuer       string
}

type JWT struct {
	KeyFile          string
	PreviousKeyFiles []string
	Issuer           string
	Audience         string
	TTL              time.Duration
}

func (c Config) IsProduction() bool {
	return c.Env == Production
}

func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("env", string(c.Env)),
		slog.String("http_addr", c.HTTPAddr),
		slog.String("internal_addr", c.InternalAddr),
		slog.String("database_url", redactURL(c.DatabaseURL)),
		slog.String("redis_url", redactURL(c.RedisURL)),
		slog.String("log_level", c.LogLevel.String()),
		slog.Duration("shutdown_timeout", c.ShutdownTimeout),
		slog.Duration("session_ttl", c.SessionTTL),
		slog.Any("trusted_proxies", c.TrustedProxies),
		slog.String("public_url", c.PublicURL),
		slog.String("smtp_url", redactURL(c.SMTPURL)),
		slog.String("mail_from", c.MailFrom),
		slog.Bool("mfa_key_set", len(c.MFAKey) > 0),
		slog.String("mfa_issuer", c.MFAIssuer),
		slog.Group("jwt",
			slog.String("key_file", c.JWT.KeyFile),
			slog.Int("previous_keys", len(c.JWT.PreviousKeyFiles)),
			slog.String("issuer", c.JWT.Issuer),
			slog.String("audience", c.JWT.Audience),
			slog.Duration("ttl", c.JWT.TTL),
		),
	)
}

func Load() (Config, error) {
	return load(os.LookupEnv)
}

func LoadDatabaseURL() (string, error) {
	return loadDatabaseURL(os.LookupEnv)
}

func loadDatabaseURL(lookup func(string) (string, bool)) (string, error) {
	get := getter(lookup)
	raw := get("AUTH_DATABASE_URL", "")
	if err := validateDatabaseURL(raw, Environment(get("AUTH_ENV", string(Development)))); err != nil {
		return "", err
	}
	return raw, nil
}

func getter(lookup func(string) (string, bool)) func(key, fallback string) string {
	return func(key, fallback string) string {
		if v, ok := lookup(key); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
		return fallback
	}
}

func load(lookup func(string) (string, bool)) (Config, error) {
	get := getter(lookup)

	var errs []error
	cfg := Config{
		Env:          Environment(get("AUTH_ENV", string(Development))),
		HTTPAddr:     get("AUTH_HTTP_ADDR", ":8080"),
		InternalAddr: get("AUTH_INTERNAL_ADDR", ":8081"),
		DatabaseURL:  get("AUTH_DATABASE_URL", ""),
		RedisURL:     get("AUTH_REDIS_URL", ""),
		SMTPURL:      get("AUTH_SMTP_URL", ""),
		JWT: JWT{
			KeyFile:          get("AUTH_JWT_KEY_FILE", ""),
			PreviousKeyFiles: splitList(get("AUTH_JWT_PREVIOUS_KEY_FILES", "")),
			Issuer:           get("AUTH_JWT_ISSUER", "auth-service"),
			Audience:         get("AUTH_JWT_AUDIENCE", "internal"),
		},
	}

	if cfg.Env != Development && cfg.Env != Production {
		errs = append(errs, fmt.Errorf("AUTH_ENV deve ser %q ou %q, recebido %q", Development, Production, cfg.Env))
	}

	if _, _, err := net.SplitHostPort(cfg.HTTPAddr); err != nil {
		errs = append(errs, fmt.Errorf("AUTH_HTTP_ADDR inválido: %w", err))
	}

	if _, _, err := net.SplitHostPort(cfg.InternalAddr); err != nil {
		errs = append(errs, fmt.Errorf("AUTH_INTERNAL_ADDR inválido: %w", err))
	} else if cfg.InternalAddr == cfg.HTTPAddr {
		errs = append(errs, errors.New("AUTH_INTERNAL_ADDR precisa ser diferente de AUTH_HTTP_ADDR"))
	}

	jwtTTL, err := time.ParseDuration(get("AUTH_JWT_TTL", "5m"))
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("AUTH_JWT_TTL inválido: %w", err))
	case jwtTTL < time.Minute || jwtTTL > 15*time.Minute:
		errs = append(errs, errors.New("AUTH_JWT_TTL deve estar entre 1m e 15m"))
	default:
		cfg.JWT.TTL = jwtTTL
	}

	if cfg.Env == Production && cfg.JWT.KeyFile == "" {
		errs = append(errs, errors.New("em produção AUTH_JWT_KEY_FILE é obrigatório"))
	}

	devURL, devFrom := "http://localhost:5173", "auth-service <no-reply@localhost>"
	if cfg.Env == Production {
		devURL, devFrom = "", ""
	}
	cfg.PublicURL = strings.TrimRight(get("AUTH_PUBLIC_URL", devURL), "/")
	if err := validatePublicURL(cfg.PublicURL, cfg.Env); err != nil {
		errs = append(errs, err)
	}

	cfg.MailFrom = get("AUTH_MAIL_FROM", devFrom)
	if addr, err := mail.ParseAddress(cfg.MailFrom); err != nil || !strings.Contains(addr.Address, "@") {
		errs = append(errs, errors.New("AUTH_MAIL_FROM precisa ser um endereço como \"Nome <no-reply@dominio>\""))
	}

	if err := validateSMTPURL(cfg.SMTPURL, cfg.Env); err != nil {
		errs = append(errs, err)
	}

	cfg.MFAIssuer = get("AUTH_MFA_ISSUER", "auth-service")
	switch raw := get("AUTH_MFA_KEY", ""); {
	case raw == "" && cfg.Env == Production:
		errs = append(errs, errors.New("em produção AUTH_MFA_KEY é obrigatório"))
	case raw != "":
		key, err := base64.StdEncoding.DecodeString(raw)
		if err != nil || len(key) != 32 {
			errs = append(errs, errors.New("AUTH_MFA_KEY precisa ser 32 bytes em base64 (openssl rand -base64 32)"))
		} else {
			cfg.MFAKey = key
		}
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

	ttl, err := time.ParseDuration(get("AUTH_SESSION_TTL", "12h"))
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("AUTH_SESSION_TTL inválido: %w", err))
	case ttl < 5*time.Minute || ttl > 30*24*time.Hour:
		errs = append(errs, errors.New("AUTH_SESSION_TTL deve estar entre 5m e 720h"))
	default:
		cfg.SessionTTL = ttl
	}

	proxies, err := parsePrefixes(get("AUTH_TRUSTED_PROXIES", ""))
	if err != nil {
		errs = append(errs, fmt.Errorf("AUTH_TRUSTED_PROXIES inválido: %w", err))
	}
	cfg.TrustedProxies = proxies

	if err := validateDatabaseURL(cfg.DatabaseURL, cfg.Env); err != nil {
		errs = append(errs, err)
	}

	if err := validateRedisURL(cfg.RedisURL, cfg.Env); err != nil {
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

func validateRedisURL(raw string, env Environment) error {
	if raw == "" {
		return errors.New("AUTH_REDIS_URL é obrigatório")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("AUTH_REDIS_URL não é uma URL válida")
	}
	if u.Scheme != "redis" && u.Scheme != "rediss" {
		return fmt.Errorf("AUTH_REDIS_URL deve usar o esquema redis:// ou rediss://, recebido %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("AUTH_REDIS_URL precisa de host")
	}
	if env == Production && u.Scheme != "rediss" {
		return errors.New("em produção AUTH_REDIS_URL precisa usar rediss://")
	}
	return nil
}

func validatePublicURL(raw string, env Environment) error {
	if raw == "" {
		return errors.New("AUTH_PUBLIC_URL é obrigatório em produção")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return errors.New("AUTH_PUBLIC_URL precisa ser algo como https://app.exemplo.com")
	}
	if env == Production && u.Scheme != "https" {
		return errors.New("em produção AUTH_PUBLIC_URL precisa usar https://")
	}
	return nil
}

func validateSMTPURL(raw string, env Environment) error {
	if raw == "" {
		if env == Production {
			return errors.New("em produção AUTH_SMTP_URL é obrigatório")
		}
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("AUTH_SMTP_URL não é uma URL válida")
	}
	if u.Scheme != "smtp" && u.Scheme != "smtps" {
		return fmt.Errorf("AUTH_SMTP_URL deve usar smtp:// ou smtps://, recebido %q", u.Scheme)
	}
	if u.Hostname() == "" {
		return errors.New("AUTH_SMTP_URL precisa de host")
	}
	return nil
}

func splitList(raw string) []string {
	var out []string
	for item := range strings.SplitSeq(raw, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func parsePrefixes(raw string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range splitList(raw) {
		if !strings.Contains(item, "/") {
			addr, err := netip.ParseAddr(item)
			if err != nil {
				return nil, err
			}
			out = append(out, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(item)
		if err != nil {
			return nil, err
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[inválida]"
	}
	return u.Redacted()
}
