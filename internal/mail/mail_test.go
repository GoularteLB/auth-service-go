package mail

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	netmail "net/mail"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var from = &netmail.Address{Name: "Auth", Address: "no-reply@example.com"}

func TestRender(t *testing.T) {
	m := Message{To: "ana@example.com", Subject: "Confirme seu e-mail", Text: "Olá!\nClique no link."}
	raw, err := m.render(from, time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := netmail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Header.Get("To") != "ana@example.com" {
		t.Errorf("To = %q", parsed.Header.Get("To"))
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(parsed.Header.Get("Subject"))
	if err != nil || subject != "Confirme seu e-mail" {
		t.Errorf("Subject = %q, %v", subject, err)
	}
	if !strings.HasSuffix(parsed.Header.Get("Message-ID"), "@example.com>") {
		t.Errorf("Message-ID = %q", parsed.Header.Get("Message-ID"))
	}
	if !strings.Contains(string(raw), "\r\n\r\nOl=C3=A1!\r\nClique no link.") {
		t.Errorf("corpo inesperado:\n%s", raw)
	}
}

func TestRejectsHeaderInjection(t *testing.T) {
	for _, m := range []Message{
		{To: "ana@example.com\r\nBcc: todo-mundo@example.com", Subject: "x", Text: "x"},
		{To: "ana@example.com", Subject: "oi\r\nBcc: todo-mundo@example.com", Text: "x"},
		{To: "nao-e-email", Subject: "x", Text: "x"},
		{To: "ana@example.com", Subject: "", Text: "x"},
	} {
		if _, err := m.render(from, time.Now()); !errors.Is(err, ErrInvalidMessage) {
			t.Errorf("aceitou %+v", m)
		}
	}
}

type fakeSMTP struct {
	ln       net.Listener
	mu       sync.Mutex
	data     string
	rcpt     string
	starttls bool
}

func newFakeSMTP(t *testing.T, starttls bool) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln, starttls: starttls}
	t.Cleanup(func() { _ = ln.Close() })
	go f.serve()
	return f
}

func (f *fakeSMTP) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

func (f *fakeSMTP) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	say := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
	say("220 fake")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			if f.starttls {
				say("250-fake")
				say("250 STARTTLS")
			} else {
				say("250 fake")
			}
		case strings.HasPrefix(cmd, "MAIL"):
			say("250 ok")
		case strings.HasPrefix(cmd, "RCPT"):
			f.mu.Lock()
			f.rcpt = strings.TrimSpace(line)
			f.mu.Unlock()
			say("250 ok")
		case cmd == "DATA":
			say("354 manda")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.data = b.String()
			f.mu.Unlock()
			say("250 ok")
		case cmd == "QUIT":
			say("221 tchau")
			return
		default:
			say("502 não")
		}
	}
}

func (f *fakeSMTP) received() (string, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rcpt, f.data
}

func TestSMTPSenderPlainInDevelopment(t *testing.T) {
	srv := newFakeSMTP(t, false)
	s, err := NewSMTPSender("smtp://"+srv.ln.Addr().String(), from, false)
	if err != nil {
		t.Fatal(err)
	}
	m := Message{To: "ana@example.com", Subject: "Teste", Text: "corpo do teste"}
	if err := s.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	rcpt, data := srv.received()
	if !strings.Contains(rcpt, "ana@example.com") || !strings.Contains(data, "corpo do teste") {
		t.Errorf("servidor recebeu rcpt=%q data=%q", rcpt, data)
	}
}

func TestSMTPSenderRequiresTLS(t *testing.T) {
	srv := newFakeSMTP(t, false)
	s, _ := NewSMTPSender("smtp://"+srv.ln.Addr().String(), from, true)
	err := s.Send(context.Background(), Message{To: "ana@example.com", Subject: "Teste", Text: "x"})
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("enviou sem TLS: %v", err)
	}
	if _, data := srv.received(); data != "" {
		t.Fatal("corpo chegou ao servidor sem TLS")
	}
}

func TestNewSMTPSenderValidates(t *testing.T) {
	for _, bad := range []string{"http://mail:25", "smtp://", "://x"} {
		if _, err := NewSMTPSender(bad, from, true); err == nil {
			t.Errorf("aceitou %q", bad)
		}
	}
	s, err := NewSMTPSender("smtps://user:senha@mail.example.com", from, true)
	if err != nil {
		t.Fatal(err)
	}
	if s.addr != "mail.example.com:465" || !s.implicit || s.username != "user" || s.password != "senha" {
		t.Errorf("config errada: %+v", s)
	}
}

type countingSender struct {
	fails atomic.Int32
	sent  atomic.Int32
}

func (c *countingSender) Send(context.Context, Message) error {
	if c.fails.Load() > 0 {
		c.fails.Add(-1)
		return errors.New("servidor fora")
	}
	c.sent.Add(1)
	return nil
}

func TestQueueRetriesAndDrains(t *testing.T) {
	sender := &countingSender{}
	sender.fails.Store(1)
	q := NewQueue(sender, slog.New(slog.NewTextHandler(io.Discard, nil)), 10)
	q.retries = []time.Duration{time.Millisecond}

	for range 3 {
		if err := q.Send(context.Background(), Message{To: "ana@example.com", Subject: "x", Text: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	q.Run(ctx, 2)

	if sender.sent.Load() != 3 {
		t.Fatalf("enviados = %d, esperado 3", sender.sent.Load())
	}
}

func TestQueueFull(t *testing.T) {
	q := NewQueue(&countingSender{}, slog.New(slog.NewTextHandler(io.Discard, nil)), 1)
	m := Message{To: "ana@example.com", Subject: "x", Text: "x"}
	if err := q.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if err := q.Send(context.Background(), m); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("esperava ErrQueueFull, recebeu %v", err)
	}
	if err := q.Send(context.Background(), Message{To: "x\r\nBcc: y", Subject: "x", Text: "x"}); !errors.Is(err, ErrInvalidMessage) {
		t.Fatal("fila aceitou mensagem inválida")
	}
}
