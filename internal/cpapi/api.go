// Package cpapi implements the control-plane side of the agent API:
// bearer-authenticated desired-state and heartbeat endpoints riding the
// public ingress under /api/v1.
package cpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/Arsolitt/krot/internal/model"
	"github.com/Arsolitt/krot/internal/store"
)

// maxBodyBytes bounds request bodies; declarations are a few kilobytes.
const maxBodyBytes = 1 << 20

// Store is the persistence surface the agent API needs; *store.Store
// satisfies it.
type Store interface {
	DesiredState(ctx context.Context, spec model.Spec) (model.DesiredState, error)
	Heartbeat(ctx context.Context, hb model.Heartbeat) error
}

// API serves the agent endpoints.
type API struct {
	store  Store
	logger *slog.Logger
	token  string
}

// New builds the agent API. A wrong or missing bearer token answers 404 —
// the endpoint must be indistinguishable from absent for non-agents.
func New(agentToken string, st Store, logger *slog.Logger) *API {
	if logger == nil {
		logger = slog.Default()
	}
	return &API{token: agentToken, store: st, logger: logger}
}

// Register wires the agent routes onto mux.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/agents/desired-state", a.handleDesiredState)
	mux.HandleFunc("POST /api/v1/agents/heartbeat", a.handleHeartbeat)
}

// authorized checks the bearer token in constant time.
func (a *API) authorized(r *http.Request) bool {
	const scheme = "Bearer "
	auth := r.Header.Get("Authorization")
	if len(auth) <= len(scheme) || auth[:len(scheme)] != scheme {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(auth[len(scheme):]), []byte(a.token)) == 1
}

// handleDesiredState reconciles the posted declaration and answers the full
// desired state. An invalid declaration answers 400 with the reason so the
// agent can surface it as config_error.
func (a *API) handleDesiredState(w http.ResponseWriter, r *http.Request) {
	if !a.authorized(r) {
		http.NotFound(w, r)
		return
	}

	var spec model.Spec
	if err := decodeJSON(r, &spec); err != nil {
		a.badRequest(w, err.Error())
		return
	}

	state, err := a.store.DesiredState(r.Context(), spec)
	if err != nil {
		if errors.Is(err, store.ErrInvalidSpec) {
			a.badRequest(w, err.Error())
			return
		}
		a.logger.ErrorContext(r.Context(), "desired-state failed",
			"server", spec.Server, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	a.logger.InfoContext(r.Context(), "desired-state served",
		"server", spec.Server, "hash", state.Hash,
		"inbounds", len(state.Inbounds), "users", len(state.Users))

	writeJSON(w, http.StatusOK, state)
}

// handleHeartbeat upserts the agent status report.
func (a *API) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if !a.authorized(r) {
		http.NotFound(w, r)
		return
	}

	var hb model.Heartbeat
	if err := decodeJSON(r, &hb); err != nil {
		a.badRequest(w, err.Error())
		return
	}

	if err := a.store.Heartbeat(r.Context(), hb); err != nil {
		if errors.Is(err, store.ErrUnknownServer) {
			a.badRequest(w, err.Error())
			return
		}
		a.logger.ErrorContext(r.Context(), "heartbeat failed", "server", hb.Server, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// decodeJSON decodes a bounded JSON request body.
func decodeJSON(r *http.Request, out any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode body: %w", err)
	}
	return nil
}

// badRequest answers 400 with a JSON error object.
func (a *API) badRequest(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
}

// writeJSON writes a JSON response with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, "encode response", http.StatusInternalServerError)
	}
}
