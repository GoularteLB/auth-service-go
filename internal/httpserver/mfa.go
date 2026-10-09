package httpserver

import (
	"errors"
	"net/http"

	"github.com/GoularteLB/auth-service/internal/auth"
)

type codeBody struct {
	Code string `json:"code"`
}

type passwordBody struct {
	Password string `json:"password"`
}

type disableBody struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

func (h *authHandler) loginMFA(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(h.mfaCookie)
	if err != nil || c.Value == "" {
		writeErrorMessage(w, http.StatusUnauthorized, auth.ErrMFAChallenge.Error())
		return
	}
	var b codeBody
	if !h.decode(w, r, &b) {
		return
	}

	token, err := h.auth.LoginMFA(r.Context(), c.Value, b.Code)
	var locked *auth.LockedError
	switch {
	case errors.As(err, &locked):
		tooManyRequests(w, locked.RetryAfter)
		return
	case errors.Is(err, auth.ErrMFAChallenge):
		h.setNamedCookie(w, h.mfaCookie, "", -1)
		writeErrorMessage(w, http.StatusUnauthorized, err.Error())
		return
	case errors.Is(err, auth.ErrInvalidMFACode):
		writeErrorMessage(w, http.StatusUnauthorized, err.Error())
		return
	case err != nil:
		h.internalError(w, r, "falha no login com mfa", err)
		return
	}

	h.setNamedCookie(w, h.mfaCookie, "", -1)
	h.startSession(w, r, token)
}

func (h *authHandler) setupMFA(w http.ResponseWriter, r *http.Request) {
	session, ok := h.requireSession(w, r)
	if !ok {
		return
	}
	var b passwordBody
	if !h.decode(w, r, &b) {
		return
	}
	setup, err := h.auth.SetupMFA(r.Context(), session, b.Password)
	if h.mfaError(w, r, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"secret":      setup.Secret,
		"otpauth_url": setup.URI,
	})
}

func (h *authHandler) enableMFA(w http.ResponseWriter, r *http.Request) {
	session, ok := h.requireSession(w, r)
	if !ok {
		return
	}
	var b codeBody
	if !h.decode(w, r, &b) {
		return
	}
	codes, err := h.auth.EnableMFA(r.Context(), session, b.Code)
	if h.mfaError(w, r, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string][]string{"recovery_codes": codes})
}

func (h *authHandler) disableMFA(w http.ResponseWriter, r *http.Request) {
	session, ok := h.requireSession(w, r)
	if !ok {
		return
	}
	var b disableBody
	if !h.decode(w, r, &b) {
		return
	}
	if h.mfaError(w, r, h.auth.DisableMFA(r.Context(), session, b.Password, b.Code)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *authHandler) requireSession(w http.ResponseWriter, r *http.Request) (string, bool) {
	token, ok := h.token(r)
	if !ok {
		writeErrorMessage(w, http.StatusUnauthorized, auth.ErrUnauthenticated.Error())
	}
	return token, ok
}

func (h *authHandler) mfaError(w http.ResponseWriter, r *http.Request, err error) bool {
	var locked *auth.LockedError
	switch {
	case err == nil:
		return false
	case errors.As(err, &locked):
		tooManyRequests(w, locked.RetryAfter)
	case errors.Is(err, auth.ErrUnauthenticated):
		writeErrorMessage(w, http.StatusUnauthorized, err.Error())
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeErrorMessage(w, http.StatusForbidden, "senha incorreta")
	case errors.Is(err, auth.ErrEmailNotVerified):
		writeErrorMessage(w, http.StatusForbidden, err.Error())
	case errors.Is(err, auth.ErrInvalidMFACode):
		writeErrorMessage(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, auth.ErrMFAEnabled),
		errors.Is(err, auth.ErrMFANotEnabled),
		errors.Is(err, auth.ErrMFANoPendingSetup):
		writeErrorMessage(w, http.StatusConflict, err.Error())
	default:
		h.internalError(w, r, "falha na gestão do mfa", err)
	}
	return true
}
