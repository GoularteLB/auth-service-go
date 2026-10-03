package httpserver

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

const maxBodyBytes = 1 << 20

type Pinger interface {
	Ping(ctx context.Context) error
}

type Deps struct {
	Logger     *slog.Logger
	DB         Pinger
	Production bool
}

func NewHandler(d Deps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealth)
	mux.HandleFunc("GET /readyz", handleReady(d.Logger, d.DB))

	var h http.Handler = mux
	h = limitBody(maxBodyBytes, h)
	h = http.NewCrossOriginProtection().Handler(h)
	h = secureHeaders(d.Production, h)
	h = recoverPanic(d.Logger, h)
	h = logRequests(d.Logger, h)
	h = requestID(h)
	return h
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleReady(logger *slog.Logger, db Pinger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := db.Ping(ctx); err != nil {
			logger.WarnContext(r.Context(), "banco indisponível",
				slog.String("request_id", RequestIDFrom(r.Context())),
				slog.Any("error", err),
			)
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
	writeJSON(w, status, map[string]string{"error": http.StatusText(status)})
}
