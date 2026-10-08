package mail

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

var ErrQueueFull = errors.New("fila de e-mail cheia")

type Queue struct {
	sender  Sender
	logger  *slog.Logger
	ch      chan Message
	retries []time.Duration
}

func NewQueue(sender Sender, logger *slog.Logger, size int) *Queue {
	return &Queue{
		sender:  sender,
		logger:  logger,
		ch:      make(chan Message, size),
		retries: []time.Duration{time.Second, 5 * time.Second},
	}
}

func (q *Queue) Send(_ context.Context, m Message) error {
	if err := m.validate(); err != nil {
		return err
	}
	select {
	case q.ch <- m:
		return nil
	default:
		return ErrQueueFull
	}
}

func (q *Queue) Run(ctx context.Context, workers int) {
	var wg sync.WaitGroup
	for range max(workers, 1) {
		wg.Go(func() {
			for {
				select {
				case <-ctx.Done():
					return
				case m := <-q.ch:
					q.deliver(ctx, m)
				}
			}
		})
	}
	wg.Wait()

	drain, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	for {
		select {
		case m := <-q.ch:
			q.deliver(drain, m)
		default:
			return
		}
	}
}

func (q *Queue) deliver(ctx context.Context, m Message) {
	base := context.WithoutCancel(ctx)
	for attempt := 0; ; attempt++ {
		sendCtx, cancel := context.WithTimeout(base, 30*time.Second)
		err := q.sender.Send(sendCtx, m)
		cancel()
		if err == nil {
			q.logger.InfoContext(ctx, "e-mail enviado", slog.String("subject", m.Subject))
			return
		}
		if attempt >= len(q.retries) || errors.Is(err, ErrInvalidMessage) {
			q.logger.ErrorContext(ctx, "falha ao enviar e-mail",
				slog.String("subject", m.Subject),
				slog.Int("tentativas", attempt+1),
				slog.Any("error", err),
			)
			return
		}
		select {
		case <-time.After(q.retries[attempt]):
		case <-ctx.Done():
		}
	}
}
