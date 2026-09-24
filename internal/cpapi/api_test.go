package cpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Arsolitt/krot/internal/model"
	"github.com/Arsolitt/krot/internal/store"
)

// fakeStore backs the API without a database.
type fakeStore struct {
	state     model.DesiredState
	stateErr  error
	heartErr  error
	gotSpec   model.Spec
	gotBeat   model.Heartbeat
	beatCalls int
}

func (f *fakeStore) DesiredState(_ context.Context, spec model.Spec) (model.DesiredState, error) {
	f.gotSpec = spec
	return f.state, f.stateErr
}

func (f *fakeStore) Heartbeat(_ context.Context, hb model.Heartbeat) error {
	f.gotBeat = hb
	f.beatCalls++
	return f.heartErr
}

// newTestAPI wires the API on its own mux with a fixed token.
func newTestAPI(st Store) http.Handler {
	mux := http.NewServeMux()
	New("sekrit", st, nil).Register(mux)
	return mux
}

func TestDesiredStateRoundTrip(t *testing.T) {
	st := &fakeStore{state: model.DesiredState{Hash: "h1", Users: []model.User{{Name: "a"}}}}
	handler := newTestAPI(st)

	body := `{"server":"vpn-dev1","endpoint":"e.example.org","route_profile":"proxy-server","inbounds":[]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/desired-state", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer sekrit")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var state model.DesiredState
	if err := json.Unmarshal(rec.Body.Bytes(), &state); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if state.Hash != "h1" || len(state.Users) != 1 {
		t.Errorf("state = %+v", state)
	}
	if st.gotSpec.Server != "vpn-dev1" || st.gotSpec.RouteProfile != "proxy-server" {
		t.Errorf("spec not forwarded: %+v", st.gotSpec)
	}
}

func TestDesiredStateAuth(t *testing.T) {
	tests := []struct {
		name string
		auth string
		want int
	}{
		{name: "wrong token", auth: "Bearer wrong", want: http.StatusNotFound},
		{name: "no token", auth: "", want: http.StatusNotFound},
		{name: "not bearer", auth: "Basic sekrit", want: http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := newTestAPI(&fakeStore{})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/desired-state", strings.NewReader("{}"))
			if tt.auth != "" {
				req.Header.Set("Authorization", tt.auth)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestDesiredStateInvalidSpec(t *testing.T) {
	st := &fakeStore{stateErr: fmt.Errorf("%w: unknown route profile", store.ErrInvalidSpec)}
	handler := newTestAPI(st)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/desired-state", strings.NewReader(`{"server":"s"}`))
	req.Header.Set("Authorization", "Bearer sekrit")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var errResp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil || errResp["error"] == "" {
		t.Errorf("error body = %s", rec.Body.String())
	}
}

func TestDesiredStateMalformedBody(t *testing.T) {
	handler := newTestAPI(&fakeStore{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/desired-state", strings.NewReader("not-json"))
	req.Header.Set("Authorization", "Bearer sekrit")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestHeartbeat(t *testing.T) {
	st := &fakeStore{}
	handler := newTestAPI(st)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/heartbeat",
		strings.NewReader(`{"server":"vpn-dev1","agent_version":"dev","user_count":3}`))
	req.Header.Set("Authorization", "Bearer sekrit")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if st.gotBeat.Server != "vpn-dev1" || st.gotBeat.UserCount != 3 {
		t.Errorf("heartbeat = %+v", st.gotBeat)
	}

	st.heartErr = fmt.Errorf("%w: ghost", store.ErrUnknownServer)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("unknown server heartbeat status = %d, want 400", rec.Code)
	}
}
