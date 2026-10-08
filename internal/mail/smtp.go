package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	netmail "net/mail"
	"net/smtp"
	"net/url"
	"time"
)

type SMTPSender struct {
	host       string
	addr       string
	implicit   bool
	requireTLS bool
	username   string
	password   string
	from       *netmail.Address
	now        func() time.Time
}

func NewSMTPSender(rawURL string, from *netmail.Address, requireTLS bool) (*SMTPSender, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, errors.New("url do smtp inválida")
	}
	if u.Scheme != "smtp" && u.Scheme != "smtps" {
		return nil, fmt.Errorf("esquema do smtp deve ser smtp:// ou smtps://, recebido %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return nil, errors.New("url do smtp precisa de host")
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"smtp": "587", "smtps": "465"}[u.Scheme]
	}

	s := &SMTPSender{
		host:       host,
		addr:       net.JoinHostPort(host, port),
		implicit:   u.Scheme == "smtps",
		requireTLS: requireTLS,
		from:       from,
		now:        time.Now,
	}
	if u.User != nil {
		s.username = u.User.Username()
		s.password, _ = u.User.Password()
	}
	return s, nil
}

func (s *SMTPSender) Send(ctx context.Context, m Message) error {
	body, err := m.render(s.from, s.now())
	if err != nil {
		return err
	}

	conn, err := s.dial(ctx)
	if err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return err
	}

	c, err := smtp.NewClient(conn, s.host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp: %w", err)
	}
	defer func() { _ = c.Close() }()

	if !s.implicit {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(s.tlsConfig()); err != nil {
				return fmt.Errorf("smtp starttls: %w", err)
			}
		} else if s.requireTLS {
			return errors.New("smtp: servidor não oferece STARTTLS")
		}
	}

	if s.username != "" {
		if err := c.Auth(smtp.PlainAuth("", s.username, s.password, s.host)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(s.from.Address); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	if err := c.Rcpt(m.To); err != nil {
		return fmt.Errorf("smtp rcpt to: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		_ = w.Close()
		return fmt.Errorf("smtp escrevendo corpo: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp fechando corpo: %w", err)
	}
	return c.Quit()
}

func (s *SMTPSender) dial(ctx context.Context) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	if s.implicit {
		td := &tls.Dialer{NetDialer: d, Config: s.tlsConfig()}
		conn, err := td.DialContext(ctx, "tcp", s.addr)
		if err != nil {
			return nil, fmt.Errorf("smtp conectando: %w", err)
		}
		return conn, nil
	}
	conn, err := d.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("smtp conectando: %w", err)
	}
	return conn, nil
}

func (s *SMTPSender) tlsConfig() *tls.Config {
	return &tls.Config{ServerName: s.host, MinVersion: tls.VersionTLS12}
}
