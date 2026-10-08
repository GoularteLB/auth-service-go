package mail

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"mime/quotedprintable"
	netmail "net/mail"
	"strings"
	"time"
)

var ErrInvalidMessage = errors.New("mensagem de e-mail inválida")

type Message struct {
	To      string
	Subject string
	Text    string
}

type Sender interface {
	Send(ctx context.Context, m Message) error
}

func (m Message) validate() error {
	if strings.ContainsAny(m.To+m.Subject, "\r\n") {
		return ErrInvalidMessage
	}
	if _, err := netmail.ParseAddress(m.To); err != nil {
		return ErrInvalidMessage
	}
	if m.Subject == "" || m.Text == "" {
		return ErrInvalidMessage
	}
	return nil
}

func (m Message) render(from *netmail.Address, now time.Time) ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	domain := from.Address[strings.LastIndex(from.Address, "@")+1:]

	var b bytes.Buffer
	header := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	header("From", from.String())
	header("To", m.To)
	header("Subject", mime.QEncoding.Encode("utf-8", m.Subject))
	header("Date", now.Format(time.RFC1123Z))
	header("Message-ID", "<"+strings.ToLower(rand.Text())+"@"+domain+">")
	header("MIME-Version", "1.0")
	header("Content-Type", "text/plain; charset=UTF-8")
	header("Content-Transfer-Encoding", "quoted-printable")
	header("Auto-Submitted", "auto-generated")
	b.WriteString("\r\n")

	qp := quotedprintable.NewWriter(&b)
	if _, err := qp.Write([]byte(strings.ReplaceAll(m.Text, "\n", "\r\n"))); err != nil {
		return nil, err
	}
	if err := qp.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

type LogSender struct {
	Logger *slog.Logger
}

func (l LogSender) Send(ctx context.Context, m Message) error {
	if err := m.validate(); err != nil {
		return err
	}
	l.Logger.InfoContext(ctx, "e-mail de desenvolvimento",
		slog.String("to", m.To),
		slog.String("subject", m.Subject),
		slog.String("text", m.Text),
	)
	return nil
}

func ParseFrom(raw string) (*netmail.Address, error) {
	addr, err := netmail.ParseAddress(raw)
	if err != nil {
		return nil, fmt.Errorf("remetente inválido: %w", err)
	}
	if !strings.Contains(addr.Address, "@") {
		return nil, errors.New("remetente sem domínio")
	}
	return addr, nil
}
