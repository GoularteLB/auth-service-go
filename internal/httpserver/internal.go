package httpserver

import (
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/GoularteLB/auth-service/internal/auth"
	"github.com/GoularteLB/auth-service/pkg/authn"
)

type TokenIssuer interface {
	Issue(subject string) (string, time.Duration, error)
	JWKS() authn.JWKS
}

type InternalDeps struct {
	Logger         *slog.Logger
	Auth           Authenticator
	Tokens         TokenIssuer
	TrustedProxies []netip.Prefix
}

type exchangeRequest struct {
	SessionToken string `json:"session_token"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func NewInternalHandler(d InternalDeps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealth)
	mux.HandleFunc("GET /.well-known/jwks.json", handleJWKS(d.Tokens))

	a := &authHandler{auth: d.Auth, logger: d.Logger}
	mux.HandleFunc("POST /internal/v1/token", handleExchange(a, d.Tokens))

	var h http.Handler = mux
	h = limitBody(maxCredentialsBytes, h)
	h = internalHeaders(h)
	h = recoverPanic(d.Logger, h)
	h = logRequests(d.Logger, h)
	h = clientInfo(d.TrustedProxies, h)
	h = requestID(h)
	return h
}

func handleJWKS(tokens TokenIssuer) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=300")
		writeJSON(w, http.StatusOK, tokens.JWKS())
	}
}

func handleExchange(a *authHandler, tokens TokenIssuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req exchangeRequest
		if !a.decode(w, r, &req) {
			return
		}
		if req.SessionToken == "" {
			writeErrorMessage(w, http.StatusUnauthorized, auth.ErrUnauthenticated.Error())
			return
		}

		u, err := a.auth.Current(r.Context(), req.SessionToken)
		switch {
		case errors.Is(err, auth.ErrUnauthenticated):
			writeErrorMessage(w, http.StatusUnauthorized, err.Error())
			return
		case err != nil:
			a.internalError(w, r, "falha ao validar sessão", err)
			return
		}

		token, ttl, err := tokens.Issue(u.ID)
		if err != nil {
			a.internalError(w, r, "falha ao emitir token", err)
			return
		}
		writeJSON(w, http.StatusOK, tokenResponse{
			AccessToken: token,
			TokenType:   "Bearer",
			ExpiresIn:   int(ttl.Seconds()),
		})
	}
}

func internalHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
