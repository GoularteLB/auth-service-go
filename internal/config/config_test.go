package config

import (
	"encoding/base64"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func lookupFrom(env map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := load(lookupFrom(map[string]string{
		"AUTH_DATABASE_URL": "postgres://auth:secret@localhost:5432/auth?sslmode=disable",
		"AUTH_REDIS_URL":    "redis://localhost:6379/0",
	}))
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if cfg.Env != Development {
		t.Errorf("Env = %q, esperado %q", cfg.Env, Development)
	}
	if cfg.HTTPAddr != ":8080" {
		t.Errorf("HTTPAddr = %q, esperado :8080", cfg.HTTPAddr)
	}
	if cfg.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel = %v, esperado INFO", cfg.LogLevel)
	}
	if cfg.ShutdownTimeout != 15*time.Second {
		t.Errorf("ShutdownTimeout = %v, esperado 15s", cfg.ShutdownTimeout)
	}
	if cfg.SessionTTL != 12*time.Hour {
		t.Errorf("SessionTTL = %v, esperado 12h", cfg.SessionTTL)
	}
	if cfg.InternalAddr != ":8081" {
		t.Errorf("InternalAddr = %q, esperado :8081", cfg.InternalAddr)
	}
	if cfg.JWT.TTL != 5*time.Minute || cfg.JWT.Issuer != "auth-service" || cfg.JWT.Audience != "internal" {
		t.Errorf("JWT = %+v", cfg.JWT)
	}
	if cfg.PublicURL != "http://localhost:5173" || cfg.SMTPURL != "" || !strings.Contains(cfg.MailFrom, "@localhost") {
		t.Errorf("e-mail em desenvolvimento: %q %q %q", cfg.PublicURL, cfg.SMTPURL, cfg.MailFrom)
	}
}

func TestLoadErrors(t *testing.T) {
	validURL := "postgres://auth:secret@localhost:5432/auth?sslmode=disable"
	redisURL := "redis://localhost:6379/0"
	base := func(extra map[string]string) map[string]string {
		env := map[string]string{"AUTH_DATABASE_URL": validURL, "AUTH_REDIS_URL": redisURL}
		for k, v := range extra {
			env[k] = v
		}
		return env
	}

	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"sem banco", map[string]string{"AUTH_REDIS_URL": redisURL}, "AUTH_DATABASE_URL é obrigatório"},
		{"esquema errado", base(map[string]string{"AUTH_DATABASE_URL": "mysql://localhost/auth"}), "esquema postgres"},
		{"sem nome do banco", base(map[string]string{"AUTH_DATABASE_URL": "postgres://localhost:5432"}), "nome do banco"},
		{"ambiente inválido", base(map[string]string{"AUTH_ENV": "staging"}), "AUTH_ENV"},
		{"endereço inválido", base(map[string]string{"AUTH_HTTP_ADDR": "8080"}), "AUTH_HTTP_ADDR"},
		{"nível de log inválido", base(map[string]string{"AUTH_LOG_LEVEL": "verbose"}), "AUTH_LOG_LEVEL"},
		{"timeout inválido", base(map[string]string{"AUTH_SHUTDOWN_TIMEOUT": "abc"}), "AUTH_SHUTDOWN_TIMEOUT"},
		{"timeout longo demais", base(map[string]string{"AUTH_SHUTDOWN_TIMEOUT": "5m"}), "AUTH_SHUTDOWN_TIMEOUT"},
		{"produção sem tls", base(map[string]string{"AUTH_ENV": "production"}), "sslmode"},
		{"sem redis", map[string]string{"AUTH_DATABASE_URL": validURL}, "AUTH_REDIS_URL é obrigatório"},
		{"esquema do redis errado", base(map[string]string{"AUTH_REDIS_URL": "http://localhost:6379"}), "redis://"},
		{"redis sem tls em produção", base(map[string]string{
			"AUTH_ENV":          "production",
			"AUTH_DATABASE_URL": "postgres://auth:secret@db:5432/auth?sslmode=verify-full",
		}), "rediss://"},
		{"ttl inválido", base(map[string]string{"AUTH_SESSION_TTL": "1 dia"}), "AUTH_SESSION_TTL"},
		{"ttl curto demais", base(map[string]string{"AUTH_SESSION_TTL": "1m"}), "AUTH_SESSION_TTL"},
		{"jwt ttl longo demais", base(map[string]string{"AUTH_JWT_TTL": "1h"}), "AUTH_JWT_TTL"},
		{"jwt ttl curto demais", base(map[string]string{"AUTH_JWT_TTL": "10s"}), "AUTH_JWT_TTL"},
		{"listeners iguais", base(map[string]string{"AUTH_INTERNAL_ADDR": ":8080"}), "AUTH_INTERNAL_ADDR"},
		{"listener interno inválido", base(map[string]string{"AUTH_INTERNAL_ADDR": "8081"}), "AUTH_INTERNAL_ADDR"},
		{"public url sem esquema", base(map[string]string{"AUTH_PUBLIC_URL": "app.example.com"}), "AUTH_PUBLIC_URL"},
		{"public url com fragmento", base(map[string]string{"AUTH_PUBLIC_URL": "https://app.example.com/#x"}), "AUTH_PUBLIC_URL"},
		{"produção sem public url", base(map[string]string{"AUTH_ENV": "production"}), "AUTH_PUBLIC_URL"},
		{"produção public url http", base(map[string]string{"AUTH_ENV": "production", "AUTH_PUBLIC_URL": "http://app.example.com"}), "https://"},
		{"produção sem smtp", base(map[string]string{"AUTH_ENV": "production"}), "AUTH_SMTP_URL"},
		{"produção sem remetente", base(map[string]string{"AUTH_ENV": "production"}), "AUTH_MAIL_FROM"},
		{"smtp esquema errado", base(map[string]string{"AUTH_SMTP_URL": "http://mail:25"}), "AUTH_SMTP_URL"},
		{"remetente inválido", base(map[string]string{"AUTH_MAIL_FROM": "sem arroba"}), "AUTH_MAIL_FROM"},
		{"produção sem chave mfa", base(map[string]string{"AUTH_ENV": "production"}), "AUTH_MFA_KEY"},
		{"chave mfa curta", base(map[string]string{"AUTH_MFA_KEY": "c2hvcnQ="}), "AUTH_MFA_KEY"},
		{"chave mfa fora de base64", base(map[string]string{"AUTH_MFA_KEY": "isso não é base64"}), "AUTH_MFA_KEY"},
		{"produção sem chave jwt", base(map[string]string{"AUTH_ENV": "production"}), "AUTH_JWT_KEY_FILE"},
		{"proxy inválido", base(map[string]string{"AUTH_TRUSTED_PROXIES": "10.0.0.0/8, nao-e-ip"}), "AUTH_TRUSTED_PROXIES"},
		{"ttl longo demais", base(map[string]string{"AUTH_SESSION_TTL": "1000h"}), "AUTH_SESSION_TTL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(lookupFrom(tt.env))
			if err == nil {
				t.Fatal("esperava erro, recebeu nil")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("erro %q não contém %q", err, tt.want)
			}
		})
	}
}

func TestLoadAccumulatesErrors(t *testing.T) {
	_, err := load(lookupFrom(map[string]string{"AUTH_ENV": "x", "AUTH_LOG_LEVEL": "y"}))
	if err == nil {
		t.Fatal("esperava erro")
	}
	for _, want := range []string{"AUTH_ENV", "AUTH_LOG_LEVEL", "AUTH_DATABASE_URL", "AUTH_REDIS_URL"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("erro não menciona %s: %v", want, err)
		}
	}
}

func TestProductionWithTLS(t *testing.T) {
	_, err := load(lookupFrom(map[string]string{
		"AUTH_ENV":          "production",
		"AUTH_DATABASE_URL": "postgres://auth:secret@db:5432/auth?sslmode=verify-full",
		"AUTH_REDIS_URL":    "rediss://:secret@cache:6380/0",
		"AUTH_JWT_KEY_FILE": "/run/secrets/jwt.pem",
		"AUTH_PUBLIC_URL":   "https://app.example.com/",
		"AUTH_SMTP_URL":     "smtp://user:pw@smtp.example.com:587",
		"AUTH_MAIL_FROM":    "Exemplo <no-reply@example.com>",
		"AUTH_MFA_KEY":      base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}))
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
}

func TestLogValueRedactsPassword(t *testing.T) {
	cfg := Config{
		DatabaseURL: "postgres://auth:supersecret@localhost:5432/auth",
		RedisURL:    "redis://:outrosegredo@localhost:6379/0",
	}
	logged := cfg.LogValue().String()
	for _, secret := range []string{"supersecret", "outrosegredo"} {
		if strings.Contains(logged, secret) {
			t.Fatalf("senha %q apareceu no log", secret)
		}
	}
}

func TestLoadTrustedProxies(t *testing.T) {
	cfg, err := load(lookupFrom(map[string]string{
		"AUTH_DATABASE_URL":    "postgres://auth:secret@localhost:5432/auth?sslmode=disable",
		"AUTH_REDIS_URL":       "redis://localhost:6379/0",
		"AUTH_TRUSTED_PROXIES": " 10.1.2.3/8 , 172.18.0.5,,::1 ",
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0/8", "172.18.0.5/32", "::1/128"}
	if len(cfg.TrustedProxies) != len(want) {
		t.Fatalf("TrustedProxies = %v, esperado %v", cfg.TrustedProxies, want)
	}
	for i, p := range cfg.TrustedProxies {
		if p.String() != want[i] {
			t.Errorf("TrustedProxies[%d] = %s, esperado %s", i, p, want[i])
		}
	}
}

func TestLoadPreviousKeyFiles(t *testing.T) {
	cfg, err := load(lookupFrom(map[string]string{
		"AUTH_DATABASE_URL":           "postgres://auth:secret@localhost:5432/auth?sslmode=disable",
		"AUTH_REDIS_URL":              "redis://localhost:6379/0",
		"AUTH_JWT_PREVIOUS_KEY_FILES": "/keys/a.pem, ,/keys/b.pem",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.JWT.PreviousKeyFiles) != 2 || cfg.JWT.PreviousKeyFiles[1] != "/keys/b.pem" {
		t.Errorf("PreviousKeyFiles = %v", cfg.JWT.PreviousKeyFiles)
	}
}

func TestLoadDatabaseURLIgnoresOtherSettings(t *testing.T) {
	url, err := loadDatabaseURL(lookupFrom(map[string]string{
		"AUTH_DATABASE_URL": "postgres://auth:secret@localhost:5432/auth?sslmode=disable",
	}))
	if err != nil {
		t.Fatalf("migrate não deveria exigir redis nem chave jwt: %v", err)
	}
	if !strings.HasPrefix(url, "postgres://") {
		t.Errorf("url = %q", url)
	}

	if _, err := loadDatabaseURL(lookupFrom(map[string]string{
		"AUTH_ENV":          "production",
		"AUTH_DATABASE_URL": "postgres://auth:secret@db:5432/auth?sslmode=disable",
	})); err == nil {
		t.Fatal("migrate em produção aceitou banco sem tls")
	}
}

func TestLogValueHidesMFAKey(t *testing.T) {
	cfg := Config{MFAKey: []byte("0123456789abcdef0123456789abcdef")}
	out := cfg.LogValue().String()
	if strings.Contains(out, "0123456789abcdef") {
		t.Fatalf("chave de mfa vazou no log: %s", out)
	}
}
