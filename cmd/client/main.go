package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/GoularteLB/auth-service/internal/client"
	"github.com/GoularteLB/auth-service/internal/config"
	"github.com/GoularteLB/auth-service/internal/database"
)

const usage = `uso:
  client create <nome> [escopo...] [--audience aud1,aud2]
  client audiences <client_id> [aud...]
  client list
  client revoke <client_id>`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stdout)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "client:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	text, err := execute(ctx, args)
	if err != nil {
		return err
	}
	_, err = io.WriteString(out, text)
	return err
}

func execute(ctx context.Context, args []string) (string, error) {
	if len(args) == 0 {
		return "", errors.New(usage)
	}

	databaseURL, err := config.LoadDatabaseURL()
	if err != nil {
		return "", fmt.Errorf("configuração inválida: %w", err)
	}
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		return "", err
	}
	defer pool.Close()
	store := client.NewStore(pool)

	switch {
	case args[0] == "create" && len(args) >= 2:
		scopes, audiences, err := splitCreateArgs(args[2:])
		if err != nil {
			return "", err
		}
		c, secret, err := store.Create(ctx, args[1], scopes, audiences)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("client_id:     %s\nclient_secret: %s\nescopos:       %s\naudiências:    %s\n\nGuarde o segredo agora. Ele não fica salvo e não dá para ver de novo.\n",
			c.ClientID, secret, strings.Join(c.Scopes, " "), strings.Join(c.Audiences, " ")), nil

	case args[0] == "audiences" && len(args) >= 2:
		audiences, err := store.SetAudiences(ctx, args[1], args[2:])
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s agora pode pedir tokens para: %s\n", args[1], strings.Join(audiences, " ")), nil

	case args[0] == "list" && len(args) == 1:
		clients, err := store.List(ctx)
		if err != nil {
			return "", err
		}
		return table(clients)

	case args[0] == "revoke" && len(args) == 2:
		if err := store.Revoke(ctx, args[1]); err != nil {
			return "", err
		}
		return args[1] + " revogado. Tokens já emitidos valem até expirar.\n", nil
	}
	return "", errors.New(usage)
}

func splitCreateArgs(args []string) ([]string, []string, error) {
	var scopes, audiences []string
	wantAudience := false
	for _, arg := range args {
		switch {
		case wantAudience:
			audiences = append(audiences, strings.Split(arg, ",")...)
			wantAudience = false
		case arg == "--audience":
			wantAudience = true
		default:
			scopes = append(scopes, arg)
		}
	}
	if wantAudience {
		return nil, nil, errors.New("--audience precisa de um valor, ex.: --audience pedidos,estoque")
	}
	return scopes, audiences, nil
}

func table(clients []client.Client) (string, error) {
	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	rows := []string{"CLIENT_ID\tNOME\tESCOPOS\tAUDIÊNCIAS\tCRIADO\tSITUAÇÃO"}
	for _, c := range clients {
		status := "ativo"
		if c.RevokedAt != nil {
			status = "revogado em " + c.RevokedAt.Format(time.DateOnly)
		}
		rows = append(rows, strings.Join([]string{
			c.ClientID, c.Name, strings.Join(c.Scopes, " "), strings.Join(c.Audiences, " "), c.CreatedAt.Format(time.DateOnly), status,
		}, "\t"))
	}
	if _, err := io.WriteString(tw, strings.Join(rows, "\n")+"\n"); err != nil {
		return "", err
	}
	if err := tw.Flush(); err != nil {
		return "", err
	}
	return b.String(), nil
}
