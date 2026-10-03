package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/GoularteLB/auth-service/internal/config"
	"github.com/GoularteLB/auth-service/internal/database"
)

const usage = "uso: migrate <up|down|version>"

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("migrate falhou", slog.Any("error", err))
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 1 {
		return errors.New(usage)
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuração inválida: %w", err)
	}

	m, err := database.NewMigrator(cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer func() {
		if err := m.Close(); err != nil {
			slog.Warn("erro ao fechar migrator", slog.Any("error", err))
		}
	}()

	switch args[0] {
	case "up":
		if err := m.Up(); err != nil {
			return fmt.Errorf("aplicando migrations: %w", err)
		}
	case "down":
		if err := m.Down(); err != nil {
			return fmt.Errorf("revertendo migration: %w", err)
		}
	case "version":
	default:
		return errors.New(usage)
	}

	version, dirty, err := m.Version()
	if err != nil {
		return fmt.Errorf("lendo versão: %w", err)
	}
	slog.Info("migrations", slog.String("comando", args[0]), slog.Uint64("versao", uint64(version)), slog.Bool("dirty", dirty))
	return nil
}
