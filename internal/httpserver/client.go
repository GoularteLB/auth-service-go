package httpserver

import (
	"context"
	"log/slog"
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/GoularteLB/auth-service/internal/audit"
)

type RateLimiter interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (time.Duration, error)
}

type Rate struct {
	Limit  int
	Window time.Duration
}

func clientInfo(trusted []netip.Prefix, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := audit.Client{
			IP:        clientIP(r, trusted),
			UserAgent: r.UserAgent(),
			RequestID: RequestIDFrom(r.Context()),
		}
		next.ServeHTTP(w, r.WithContext(audit.WithClient(r.Context(), c)))
	})
}

func clientIP(r *http.Request, trusted []netip.Prefix) string {
	addr, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	ip := addr.Addr().Unmap()
	if !isTrusted(ip, trusted) {
		return ip.String()
	}

	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		ip = hop.Unmap()
		if !isTrusted(ip, trusted) {
			break
		}
	}
	return ip.String()
}

func isTrusted(ip netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func rateLimit(limiter RateLimiter, logger *slog.Logger, name string, rate Rate, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := audit.ClientFrom(r.Context()).IP
		retry, err := limiter.Allow(r.Context(), name+":"+ip, rate.Limit, rate.Window)
		if err != nil {
			logger.ErrorContext(r.Context(), "falha no rate limit",
				slog.String("request_id", RequestIDFrom(r.Context())),
				slog.Any("error", err),
			)
			writeError(w, http.StatusServiceUnavailable)
			return
		}
		if retry > 0 {
			logger.WarnContext(r.Context(), "rate limit excedido",
				slog.String("request_id", RequestIDFrom(r.Context())),
				slog.String("route", name),
				slog.String("ip", ip),
			)
			tooManyRequests(w, retry)
			return
		}
		next(w, r)
	}
}

func tooManyRequests(w http.ResponseWriter, retry time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(retry.Seconds()))))
	writeErrorMessage(w, http.StatusTooManyRequests, "muitas tentativas, tente novamente mais tarde")
}
