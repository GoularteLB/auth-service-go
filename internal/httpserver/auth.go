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
	"github.com/GoularteLB/auth-service/internal/mfa"
	"github.com/GoularteLB/auth-service/internal/password"
	"github.com/GoularteLB/auth-service/internal/user"
)

const maxCredentialsBytes = 4 << 10

type Authenticator interface {
	Signup(ctx context.Context, email, plain string) error
	Login(ctx context.Context, email, plain string) (string, error)
	Logout(ctx context.Context, token string) error
	Current(ctx context.Context, token string) (user.User, error)
	Identify(ctx context.Context, token string) (user.User, []string, error)
	VerifyEmail(ctx context.Context, token string) error
	ResendVerification(ctx context.Context, sessionToken string) error
	ForgotPassword(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, token, plain string) error
	LoginMFA(ctx context.Context, challenge, code string) (string, error)
	MFAEnabled(ctx context.Context, userID string) (bool, error)
	SetupMFA(ctx context.Context, sessionToken, plain string) (mfa.Setup, error)
	EnableMFA(ctx context.Context, sessionToken, code string) ([]string, error)
	DisableMFA(ctx context.Context, sessionToken, plain, code string) error
}

type credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type tokenBody struct {
	Token string `json:"token"`
}

type emailBody struct {
	Email string `json:"email"`
}

type resetBody struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

type authHandler struct {
	auth       Authenticator
	logger     *slog.Logger
	cookieName string
	mfaCookie  string
	ttl        time.Duration
}

func sessionCookieName(production bool) string {
	if production {
		return "__Host-session"
	}
	return "session"
}

func mfaCookieName(production bool) string {
	if production {
		return "__Host-mfa"
	}
	return "mfa"
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
	var required *auth.MFARequiredError
	switch {
	case errors.As(err, &required):
		h.setNamedCookie(w, h.mfaCookie, required.Challenge, int(auth.MFAChallengeTTL.Seconds()))
		writeJSON(w, http.StatusAccepted, map[string]bool{"mfa_required": true})
		return
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

	h.startSession(w, r, token)
}

func (h *authHandler) startSession(w http.ResponseWriter, r *http.Request, token string) {
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

	mfaOn, err := h.auth.MFAEnabled(r.Context(), u.ID)
	if err != nil {
		h.internalError(w, r, "falha ao consultar mfa", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":             u.ID,
		"email":          u.Email,
		"email_verified": u.EmailVerified(),
		"mfa_enabled":    mfaOn,
		"created_at":     u.CreatedAt,
	})
}

func (h *authHandler) verifyEmail(w http.ResponseWriter, r *http.Request) {
	var b tokenBody
	if !h.decode(w, r, &b) {
		return
	}
	err := h.auth.VerifyEmail(r.Context(), b.Token)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, auth.ErrInvalidLink):
		writeErrorMessage(w, http.StatusBadRequest, err.Error())
	default:
		h.internalError(w, r, "falha ao verificar e-mail", err)
	}
}

func (h *authHandler) resendVerification(w http.ResponseWriter, r *http.Request) {
	token, ok := h.token(r)
	if !ok {
		writeErrorMessage(w, http.StatusUnauthorized, auth.ErrUnauthenticated.Error())
		return
	}
	err := h.auth.ResendVerification(r.Context(), token)
	switch {
	case err == nil:
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
	case errors.Is(err, auth.ErrUnauthenticated):
		writeErrorMessage(w, http.StatusUnauthorized, err.Error())
	default:
		h.internalError(w, r, "falha ao reenviar verificação", err)
	}
}

func (h *authHandler) forgotPassword(w http.ResponseWriter, r *http.Request) {
	var b emailBody
	if !h.decode(w, r, &b) {
		return
	}
	err := h.auth.ForgotPassword(r.Context(), b.Email)
	switch {
	case err == nil:
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
	case errors.Is(err, auth.ErrInvalidEmail):
		writeErrorMessage(w, http.StatusBadRequest, err.Error())
	default:
		h.internalError(w, r, "falha no esqueci a senha", err)
	}
}

func (h *authHandler) resetPassword(w http.ResponseWriter, r *http.Request) {
	var b resetBody
	if !h.decode(w, r, &b) {
		return
	}
	err := h.auth.ResetPassword(r.Context(), b.Token, b.Password)
	switch {
	case err == nil:
		h.setCookie(w, "", -1)
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, auth.ErrInvalidLink),
		errors.Is(err, password.ErrTooShort),
		errors.Is(err, password.ErrTooLong):
		writeErrorMessage(w, http.StatusBadRequest, err.Error())
	default:
		h.internalError(w, r, "falha ao redefinir senha", err)
	}
}

func (h *authHandler) token(r *http.Request) (string, bool) {
	c, err := r.Cookie(h.cookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	return c.Value, true
}

func (h *authHandler) setCookie(w http.ResponseWriter, value string, maxAge int) {
	h.setNamedCookie(w, h.cookieName, value, maxAge)
}

func (h *authHandler) setNamedCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
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
