package config

import (
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
}

func TestLoadErrors(t *testing.T) {
	validURL := "postgres://auth:secret@localhost:5432/auth?sslmode=disable"

	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"sem banco", map[string]string{}, "AUTH_DATABASE_URL é obrigatório"},
		{"esquema errado", map[string]string{"AUTH_DATABASE_URL": "mysql://localhost/auth"}, "esquema postgres"},
		{"sem nome do banco", map[string]string{"AUTH_DATABASE_URL": "postgres://localhost:5432"}, "nome do banco"},
		{"ambiente inválido", map[string]string{"AUTH_DATABASE_URL": validURL, "AUTH_ENV": "staging"}, "AUTH_ENV"},
		{"endereço inválido", map[string]string{"AUTH_DATABASE_URL": validURL, "AUTH_HTTP_ADDR": "8080"}, "AUTH_HTTP_ADDR"},
		{"nível de log inválido", map[string]string{"AUTH_DATABASE_URL": validURL, "AUTH_LOG_LEVEL": "verbose"}, "AUTH_LOG_LEVEL"},
		{"timeout inválido", map[string]string{"AUTH_DATABASE_URL": validURL, "AUTH_SHUTDOWN_TIMEOUT": "abc"}, "AUTH_SHUTDOWN_TIMEOUT"},
		{"timeout longo demais", map[string]string{"AUTH_DATABASE_URL": validURL, "AUTH_SHUTDOWN_TIMEOUT": "5m"}, "AUTH_SHUTDOWN_TIMEOUT"},
		{"produção sem tls", map[string]string{"AUTH_DATABASE_URL": validURL, "AUTH_ENV": "production"}, "sslmode"},
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
	for _, want := range []string{"AUTH_ENV", "AUTH_LOG_LEVEL", "AUTH_DATABASE_URL"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("erro não menciona %s: %v", want, err)
		}
	}
}

func TestProductionWithTLS(t *testing.T) {
	_, err := load(lookupFrom(map[string]string{
		"AUTH_ENV":          "production",
		"AUTH_DATABASE_URL": "postgres://auth:secret@db:5432/auth?sslmode=verify-full",
	}))
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
}

func TestLogValueRedactsPassword(t *testing.T) {
	cfg := Config{DatabaseURL: "postgres://auth:supersecret@localhost:5432/auth"}
	if strings.Contains(cfg.LogValue().String(), "supersecret") {
		t.Fatal("senha do banco apareceu no log")
	}
}
