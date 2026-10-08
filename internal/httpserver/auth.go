package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"time"

	"github.com/GoularteLB/auth-service/internal/auth"
	"github.com/GoularteLB/auth-service/internal/password"
	"github.com/GoularteLB/auth-service/internal/user"
)

const maxCredentialsBytes = 4 << 10

type Authenticator interface {
	Signup(ctx context.Context, email, plain string) error
	Login(ctx context.Context, email, plain string) (string, error)
	Logout(ctx context.Context, token string) error
	Current(ctx context.Context, token string) (user.User, error)
}

type credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type authHandler struct {
	auth       Authenticator
	logger     *slog.Logger
	cookieName string
	ttl        time.Duration
}

func sessionCookieName(production bool) string {
	if production {
		return "__Host-session"
	}
	return "session"
}

func (h *authHandler) signup(w http.ResponseWriter, r *http.Request) {
	var c credentials
	if !h.decode(w, r, &c) {
		return
	}

	err := h.auth.Signup(r.Context(), c.Email, c.Password)
	switch {
	case err == nil:
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
	case errors.Is(err, auth.ErrInvalidEmail),
		errors.Is(err, password.ErrTooShort),
		errors.Is(err, password.ErrTooLong):
		writeErrorMessage(w, http.StatusBadRequest, err.Error())
	default:
		h.internalError(w, r, "falha no cadastro", err)
	}
}

func (h *authHandler) login(w http.ResponseWriter, r *http.Request) {
	var c credentials
	if !h.decode(w, r, &c) {
		return
	}

	token, err := h.auth.Login(r.Context(), c.Email, c.Password)
	var locked *auth.LockedError
	switch {
	case errors.As(err, &locked):
		tooManyRequests(w, locked.RetryAfter)
		return
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeErrorMessage(w, http.StatusUnauthorized, err.Error())
		return
	case err != nil:
		h.internalError(w, r, "falha no login", err)
		return
	}

	if old, ok := h.token(r); ok {
		if err := h.auth.Logout(r.Context(), old); err != nil {
			h.logger.WarnContext(r.Context(), "falha ao apagar sessão anterior",
				slog.String("request_id", RequestIDFrom(r.Context())),
				slog.Any("error", err),
			)
		}
	}

	h.setCookie(w, token, int(h.ttl.Seconds()))
	w.WriteHeader(http.StatusNoContent)
}

func (h *authHandler) logout(w http.ResponseWriter, r *http.Request) {
	if token, ok := h.token(r); ok {
		if err := h.auth.Logout(r.Context(), token); err != nil {
			h.internalError(w, r, "falha no logout", err)
			return
		}
	}
	h.setCookie(w, "", -1)
	w.WriteHeader(http.StatusNoContent)
}

func (h *authHandler) me(w http.ResponseWriter, r *http.Request) {
	token, ok := h.token(r)
	if !ok {
		writeErrorMessage(w, http.StatusUnauthorized, auth.ErrUnauthenticated.Error())
		return
	}

	u, err := h.auth.Current(r.Context(), token)
	switch {
	case errors.Is(err, auth.ErrUnauthenticated):
		h.setCookie(w, "", -1)
		writeErrorMessage(w, http.StatusUnauthorized, err.Error())
		return
	case err != nil:
		h.internalError(w, r, "falha ao carregar sessão", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":         u.ID,
		"email":      u.Email,
		"created_at": u.CreatedAt,
	})
}

func (h *authHandler) token(r *http.Request) (string, bool) {
	c, err := r.Cookie(h.cookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	return c.Value, true
}

func (h *authHandler) setCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     h.cookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

func (h *authHandler) decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeErrorMessage(w, http.StatusUnsupportedMediaType, "o corpo precisa ser application/json")
		return false
	}

	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCredentialsBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeErrorMessage(w, http.StatusRequestEntityTooLarge, "corpo grande demais")
			return false
		}
		writeErrorMessage(w, http.StatusBadRequest, "json inválido")
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeErrorMessage(w, http.StatusBadRequest, "json inválido")
		return false
	}
	return true
}

func (h *authHandler) internalError(w http.ResponseWriter, r *http.Request, msg string, err error) {
	h.logger.ErrorContext(r.Context(), msg,
		slog.String("request_id", RequestIDFrom(r.Context())),
		slog.Any("error", err),
	)
	writeError(w, http.StatusInternalServerError)
}
