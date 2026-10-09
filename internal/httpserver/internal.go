package httpserver

import (
	"context"
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/GoularteLB/auth-service/internal/auth"
	"github.com/GoularteLB/auth-service/internal/client"
	"github.com/GoularteLB/auth-service/pkg/authn"
)

var (
	exchangeRate    = Rate{Limit: 3000, Window: time.Minute}
	clientTokenRate = Rate{Limit: 60, Window: time.Minute}
)

type TokenIssuer interface {
	Issue(subject, clientID, audience string, scopes, amr []string) (string, time.Duration, error)
	JWKS() authn.JWKS
}

type Clients interface {
	Authorize(ctx context.Context, clientID, secret, scope string) (client.Client, error)
	Audience(ctx context.Context, c client.Client, requested string) (string, error)
	Token(ctx context.Context, clientID, secret, scope, audience string) (client.Token, error)
}

type InternalDeps struct {
	Logger         *slog.Logger
	Auth           Authenticator
	Clients        Clients
	Tokens         TokenIssuer
	Limiter        RateLimiter
	TrustedProxies []netip.Prefix
}

type exchangeRequest struct {
	SessionToken string `json:"session_token"`
	Audience     string `json:"audience"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

type internalHandler struct {
	*authHandler
	clients Clients
	tokens  TokenIssuer
}

func NewInternalHandler(d InternalDeps) http.Handler {
	h := &internalHandler{
		authHandler: &authHandler{auth: d.Auth, logger: d.Logger},
		clients:     d.Clients,
		tokens:      d.Tokens,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealth)
	mux.HandleFunc("GET /.well-known/jwks.json", h.jwks)
	mux.HandleFunc("POST /internal/v1/token", rateLimit(d.Limiter, d.Logger, "exchange", exchangeRate, h.exchange))
	mux.HandleFunc("POST /internal/v1/oauth/token", rateLimit(d.Limiter, d.Logger, "client_token", clientTokenRate, h.clientToken))

	var handler http.Handler = mux
	handler = limitBody(maxCredentialsBytes, handler)
	handler = internalHeaders(handler)
	handler = recoverPanic(d.Logger, handler)
	handler = logRequests(d.Logger, handler)
	handler = clientInfo(d.TrustedProxies, handler)
	handler = requestID(handler)
	return handler
}

func (h *internalHandler) jwks(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, h.tokens.JWKS())
}

func (h *internalHandler) exchange(w http.ResponseWriter, r *http.Request) {
	id, secret, ok := basicAuth(r)
	if !ok {
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	c, err := h.clients.Authorize(r.Context(), id, secret, client.ScopeSessionExchange)
	switch {
	case errors.Is(err, client.ErrInvalidClient):
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	case errors.Is(err, client.ErrForbidden):
		oauthError(w, http.StatusForbidden, "unauthorized_client")
		return
	case err != nil:
		h.internalError(w, r, "falha ao autenticar cliente", err)
		return
	}

	var req exchangeRequest
	if !h.decode(w, r, &req) {
		return
	}
	audience, err := h.clients.Audience(r.Context(), c, req.Audience)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_target")
		return
	}

	if req.SessionToken == "" {
		writeErrorMessage(w, http.StatusUnauthorized, auth.ErrUnauthenticated.Error())
		return
	}

	u, amr, err := h.auth.Identify(r.Context(), req.SessionToken)
	switch {
	case errors.Is(err, auth.ErrUnauthenticated):
		writeErrorMessage(w, http.StatusUnauthorized, err.Error())
		return
	case err != nil:
		h.internalError(w, r, "falha ao validar sessão", err)
		return
	}

	token, ttl, err := h.tokens.Issue(u.ID, c.ClientID, audience, nil, amr)
	if err != nil {
		h.internalError(w, r, "falha ao emitir token", err)
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   int(ttl.Seconds()),
	})
}

func (h *internalHandler) clientToken(w http.ResponseWriter, r *http.Request) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		writeErrorMessage(w, http.StatusUnsupportedMediaType, "o corpo precisa ser application/x-www-form-urlencoded")
		return
	}
	if err := r.ParseForm(); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeErrorMessage(w, http.StatusRequestEntityTooLarge, "corpo grande demais")
			return
		}
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if r.PostForm.Has("client_secret") {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if r.PostForm.Get("grant_type") != "client_credentials" {
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}

	id, secret, ok := basicAuth(r)
	if !ok {
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}

	tok, err := h.clients.Token(r.Context(), id, secret, r.PostForm.Get("scope"), r.PostForm.Get("audience"))
	switch {
	case errors.Is(err, client.ErrInvalidClient):
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	case errors.Is(err, client.ErrInvalidScope):
		oauthError(w, http.StatusBadRequest, "invalid_scope")
		return
	case errors.Is(err, client.ErrInvalidTarget):
		oauthError(w, http.StatusBadRequest, "invalid_target")
		return
	case err != nil:
		h.internalError(w, r, "falha ao emitir token de cliente", err)
		return
	}

	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken: tok.Value,
		TokenType:   "Bearer",
		ExpiresIn:   int(tok.TTL.Seconds()),
		Scope:       strings.Join(tok.Scopes, " "),
	})
}

func basicAuth(r *http.Request) (string, string, bool) {
	rawID, rawSecret, ok := r.BasicAuth()
	if !ok {
		return "", "", false
	}
	id, err := url.QueryUnescape(rawID)
	if err != nil {
		return "", "", false
	}
	secret, err := url.QueryUnescape(rawSecret)
	if err != nil {
		return "", "", false
	}
	return id, secret, id != "" && secret != ""
}

func oauthError(w http.ResponseWriter, status int, code string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="auth-service"`)
	}
	writeJSON(w, status, map[string]string{"error": code})
}

func internalHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
