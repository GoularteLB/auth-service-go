package httpserver

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/netip"
	"time"
)

const maxBodyBytes = 1 << 20

type Pinger interface {
	Ping(ctx context.Context) error
}

var (
	signupRate = Rate{Limit: 10, Window: time.Hour}
	loginRate  = Rate{Limit: 10, Window: time.Minute}
	verifyRate = Rate{Limit: 20, Window: time.Hour}
	resendRate = Rate{Limit: 5, Window: time.Hour}
	forgotRate = Rate{Limit: 5, Window: time.Hour}
	resetRate  = Rate{Limit: 10, Window: time.Hour}
	mfaRate    = Rate{Limit: 10, Window: time.Minute}
	manageRate = Rate{Limit: 20, Window: time.Hour}
)

type Deps struct {
	Logger         *slog.Logger
	Checks         map[string]Pinger
	Auth           Authenticator
	Limiter        RateLimiter
	TrustedProxies []netip.Prefix
	SessionTTL     time.Duration
	Production     bool
}

func NewHandler(d Deps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealth)
	mux.HandleFunc("GET /readyz", handleReady(d.Logger, d.Checks))

	a := &authHandler{
		auth:       d.Auth,
		logger:     d.Logger,
		cookieName: sessionCookieName(d.Production),
		mfaCookie:  mfaCookieName(d.Production),
		ttl:        d.SessionTTL,
	}
	mux.HandleFunc("POST /v1/auth/signup", rateLimit(d.Limiter, d.Logger, "signup", signupRate, a.signup))
	mux.HandleFunc("POST /v1/auth/login", rateLimit(d.Limiter, d.Logger, "login", loginRate, a.login))
	mux.HandleFunc("POST /v1/auth/logout", a.logout)
	mux.HandleFunc("GET /v1/auth/me", a.me)
	mux.HandleFunc("POST /v1/auth/email/verify", rateLimit(d.Limiter, d.Logger, "verify", verifyRate, a.verifyEmail))
	mux.HandleFunc("POST /v1/auth/email/resend", rateLimit(d.Limiter, d.Logger, "resend", resendRate, a.resendVerification))
	mux.HandleFunc("POST /v1/auth/password/forgot", rateLimit(d.Limiter, d.Logger, "forgot", forgotRate, a.forgotPassword))
	mux.HandleFunc("POST /v1/auth/password/reset", rateLimit(d.Limiter, d.Logger, "reset", resetRate, a.resetPassword))
	mux.HandleFunc("POST /v1/auth/login/mfa", rateLimit(d.Limiter, d.Logger, "login_mfa", mfaRate, a.loginMFA))
	mux.HandleFunc("POST /v1/auth/mfa/setup", rateLimit(d.Limiter, d.Logger, "mfa_manage", manageRate, a.setupMFA))
	mux.HandleFunc("POST /v1/auth/mfa/enable", rateLimit(d.Limiter, d.Logger, "mfa_manage", manageRate, a.enableMFA))
	mux.HandleFunc("POST /v1/auth/mfa/disable", rateLimit(d.Limiter, d.Logger, "mfa_manage", manageRate, a.disableMFA))

	var h http.Handler = mux
	h = limitBody(maxBodyBytes, h)
	h = http.NewCrossOriginProtection().Handler(h)
	h = secureHeaders(d.Production, h)
	h = recoverPanic(d.Logger, h)
	h = logRequests(d.Logger, h)
	h = clientInfo(d.TrustedProxies, h)
	h = requestID(h)
	return h
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleReady(logger *slog.Logger, checks map[string]Pinger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		ready := true
		for name, check := range checks {
			if err := check.Ping(ctx); err != nil {
				ready = false
				logger.WarnContext(r.Context(), "dependência indisponível",
					slog.String("request_id", RequestIDFrom(r.Context())),
					slog.String("dependency", name),
					slog.Any("error", err),
				)
			}
		}
		if !ready {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int) {
	writeErrorMessage(w, status, http.StatusText(status))
}

func writeErrorMessage(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
