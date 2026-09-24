package agentapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Arsolitt/krot/internal/model"
)

// specFixture is one declared spec used across request assertions.
func specFixture() model.Spec {
	return model.Spec{
		Server:       "vpn-dev1",
		Endpoint:     "vpn1.example.com",
		RouteProfile: "proxy-server",
		Inbounds: []model.InboundDecl{
			{Tag: "vless-in", Type: model.InboundVLESSReality, ListenPort: 443, SNI: "cdn.example.com"},
		},
	}
}

func TestClientDesiredStateRoundTrip(t *testing.T) {
	var (
		gotMethod string
		gotPath   string
		gotAuth   string
		gotBody   model.Spec
	)
	want := model.DesiredState{
		Hash:   "abc123",
		Server: model.Server{Name: "vpn-dev1", Enabled: true},
		Users:  []model.User{{Name: "arsolitt"}},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAuth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(want); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	defer srv.Close()

	client := New(srv.URL, "sekrit", nil)
	got, err := client.DesiredState(context.Background(), specFixture())
	if err != nil {
		t.Fatalf("DesiredState: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if wantPath := "/api/v1/agents/desired-state"; gotPath != wantPath {
		t.Errorf("path = %q, want %q", gotPath, wantPath)
	}
	if wantAuth := "Bearer sekrit"; gotAuth != wantAuth {
		t.Errorf("authorization = %q, want %q", gotAuth, wantAuth)
	}
	if gotBody.Server != "vpn-dev1" || len(gotBody.Inbounds) != 1 {
		t.Errorf("request spec not round-tripped: %+v", gotBody)
	}
	if got.Hash != want.Hash || got.Server.Name != want.Server.Name || len(got.Users) != 1 {
		t.Errorf("response not decoded: %+v", got)
	}
}

func TestClientDesiredStateErrors(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantMsg    string
		status     int
		wantConfig bool
	}{
		{
			name:       "400 with error message",
			status:     http.StatusBadRequest,
			body:       `{"error":"port collision"}`,
			wantConfig: true,
			wantMsg:    "port collision",
		},
		{
			name:       "400 with non-json body",
			status:     http.StatusBadRequest,
			body:       "plain failure",
			wantConfig: true,
			wantMsg:    "plain failure",
		},
		{
			name:    "404 hides the endpoint",
			status:  http.StatusNotFound,
			body:    "not found",
			wantMsg: "404",
		},
		{
			name:    "500 is transient",
			status:  http.StatusInternalServerError,
			body:    "boom",
			wantMsg: "500",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				if _, err := w.Write([]byte(tt.body)); err != nil {
					t.Errorf("write body: %v", err)
				}
			}))
			defer srv.Close()

			client := New(srv.URL+"/", "tok", nil)
			_, err := client.DesiredState(context.Background(), specFixture())
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			cfgErr, isCfg := errors.AsType[*ConfigError](err)
			if isCfg {
				if !tt.wantConfig {
					t.Errorf("unexpected ConfigError: %v", err)
				}
				if cfgErr.Message != tt.wantMsg {
					t.Errorf("message = %q, want %q", cfgErr.Message, tt.wantMsg)
				}
				return
			}
			if tt.wantConfig {
				t.Errorf("expected ConfigError, got %v", err)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error %q does not contain %q", err, tt.wantMsg)
			}
		})
	}
}

func TestClientDesiredStateLargeBody(t *testing.T) {
	// Regression: success bodies larger than the error-snippet cap must
	// still decode fully.
	big := model.DesiredState{
		Hash: "large",
		Server: model.Server{
			Name: "srv", Endpoint: "e", RouteProfile: "p", Enabled: true,
		},
		Inbounds: make([]model.Inbound, 64),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(big); err != nil {
			t.Errorf("encode: %v", err)
		}
	}))
	defer srv.Close()

	got, err := New(srv.URL, "tok", nil).DesiredState(context.Background(), specFixture())
	if err != nil {
		t.Fatalf("large body decode: %v", err)
	}
	if got.Hash != "large" || len(got.Inbounds) != 64 {
		t.Errorf("truncated response: hash=%s inbounds=%d", got.Hash, len(got.Inbounds))
	}
}

func TestClientHeartbeat(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		wantErr bool
	}{
		{name: "ok", status: http.StatusOK},
		{name: "no content", status: http.StatusNoContent},
		{name: "server error", status: http.StatusInternalServerError, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotHB model.Heartbeat
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/agents/heartbeat" {
					t.Errorf("path = %q", r.URL.Path)
				}
				if err := json.NewDecoder(r.Body).Decode(&gotHB); err != nil {
					t.Errorf("decode body: %v", err)
				}
				w.WriteHeader(tt.status)
			}))
			defer srv.Close()

			hb := model.Heartbeat{Server: "vpn-dev1", AgentVersion: "dev", UserCount: 3}
			err := New(srv.URL, "tok", nil).Heartbeat(context.Background(), hb)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotHB.Server != hb.Server || gotHB.UserCount != hb.UserCount {
				t.Errorf("heartbeat not round-tripped: %+v", gotHB)
			}
		})
	}
}
