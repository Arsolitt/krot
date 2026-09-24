package sub

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Arsolitt/krot/internal/model"
)

// tokenChars is the derived token length in base64url characters.
const tokenChars = 22

// tokenKey32 is a fixed 32-byte key for deterministic token derivation.
var tokenKey32 = []byte("0123456789abcdef0123456789abcdef")

// fakeSource serves a static active-user and server view.
type fakeSource struct {
	err     error
	users   []model.User
	targets []model.ServerInbounds
}

func (f *fakeSource) ActiveUsers(context.Context) ([]model.User, error) {
	return f.users, f.err
}

func (f *fakeSource) EnabledServersWithInbounds(context.Context) ([]model.ServerInbounds, error) {
	return f.targets, f.err
}

// fakeAuthz gates authorization deterministically.
type fakeAuthz struct {
	err     error
	allowed bool
}

func (f fakeAuthz) Allowed(_ context.Context, _ string) (bool, error) {
	return f.allowed, f.err
}

// testEnv assembles a server with one active user, one reality inbound, and
// the routing profile the control plane advertises.
func testEnv(authz Authorizer) (*Server, model.User) {
	return testEnvWithProfile(Profile{
		Title:               "Krot VPN",
		UpdateIntervalHours: 24,
		RoutingURI:          "happ://routing/onadd/cHJvZmlsZQ==",
	}, authz)
}

// testEnvWithProfile assembles the same fixture with a caller-supplied
// profile, for tests that vary the advertised headers.
func testEnvWithProfile(profile Profile, authz Authorizer) (*Server, model.User) {
	user := model.User{
		Subject: "uuid-1", Name: "arsolitt",
		VLESSUUID: "397fd10e-5e2c-4817-bd56-2d8e9a78d099", Hy2Password: "pw", Active: true,
	}
	inbound := model.Inbound{
		ServerName: "srv-1", Tag: "vless", Type: model.InboundVLESSReality,
		ListenPort: 443, SNI: "cdn.example.com",
		PublicEndpoint: "srv-1.example.com", PublicPort: 443,
		RealityPublicKey: "Gs3SCdZr9mwSoaG4BwBINH074ZGayszZraPKhtaNA2w",
		RealityShortID:   "8a07bf48dee3fecc",
	}
	src := &fakeSource{
		users: []model.User{user},
		targets: []model.ServerInbounds{{
			Server: model.Server{
				Name:         "srv-1",
				Endpoint:     "srv-1.example.com",
				RouteProfile: "proxy-server",
				Enabled:      true,
			},
			Inbounds: []model.Inbound{inbound},
		}},
	}
	return New(tokenKey32, profile, src, authz, nil), user
}

func TestHandleSubServesLinksWithHeaders(t *testing.T) {
	server, user := testEnv(fakeAuthz{allowed: true})
	token := Token(tokenKey32, user.Subject)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+token, nil)
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "vless://397fd10e-5e2c-4817-bd56-2d8e9a78d099@srv-1.example.com:443?") {
		t.Errorf("body missing vless link:\n%s", body)
	}
	if !strings.HasSuffix(body, "\n") || strings.Count(body, "\n") != 1 {
		t.Errorf("body must be one link with trailing newline:\n%q", body)
	}
	if got := rec.Header().Get("profile-title"); got != "Krot VPN" {
		t.Errorf("profile-title = %q", got)
	}
	if got := rec.Header().Get("profile-update-interval"); got != "24" {
		t.Errorf("profile-update-interval = %q", got)
	}
	if got := rec.Header().Get("routing"); got != "happ://routing/onadd/cHJvZmlsZQ==" {
		t.Errorf("routing = %q", got)
	}
}

// TestHandleSubOmitsRoutingHeaderWhenUnset pins that an empty RoutingURI
// sends no routing header at all: clients would otherwise read an empty
// value as Happ's built-in Default profile.
func TestHandleSubOmitsRoutingHeaderWhenUnset(t *testing.T) {
	server, user := testEnvWithProfile(Profile{Title: "Krot VPN"}, fakeAuthz{allowed: true})

	rec := httptest.NewRecorder()
	server.Handler().
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sub/"+Token(tokenKey32, user.Subject), nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if vals := rec.Header().Values("routing"); len(vals) != 0 {
		t.Errorf("routing header = %q, want absent", vals)
	}
}

func TestHandleSubDenials(t *testing.T) {
	server, user := testEnv(fakeAuthz{allowed: false})
	token := Token(tokenKey32, user.Subject)

	tests := []struct {
		name   string
		target string
		want   int
	}{
		{name: "unknown token", target: "/sub/doesnotexist", want: http.StatusNotFound},
		{name: "denied user", target: "/sub/" + token, want: http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.target, nil))
			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestHandleSubAuthzError(t *testing.T) {
	server, user := testEnv(fakeAuthz{err: errors.New("directory down")})
	rec := httptest.NewRecorder()
	server.Handler().
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sub/"+Token(tokenKey32, user.Subject), nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}

func TestHandleSubSourceError(t *testing.T) {
	src := &fakeSource{err: errors.New("db down")}
	server := New(tokenKey32, Profile{}, src, fakeAuthz{allowed: true}, nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sub/anything", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (indistinguishable from unknown token)", rec.Code)
	}
}

func TestTokenForUUID(t *testing.T) {
	server, user := testEnv(fakeAuthz{allowed: true})

	got, ok := server.TokenForUUID(context.Background(), user.Subject)
	if !ok || got != Token(tokenKey32, user.Subject) {
		t.Errorf("TokenForUUID = %q, %v", got, ok)
	}
	if _, ok := server.TokenForUUID(context.Background(), "unknown"); ok {
		t.Error("unknown uuid must not resolve")
	}
}

func TestTokenStableShape(t *testing.T) {
	got := Token(tokenKey32, "uuid-1")
	if len(got) != tokenChars {
		t.Errorf("token length = %d, want 22", len(got))
	}
	if Token(tokenKey32, "uuid-1") != got {
		t.Error("token derivation must be deterministic")
	}
	if Token([]byte("another-32-byte-key-aaaaaaaaaaaaa"), "uuid-1") == got {
		t.Error("token must depend on the key")
	}
}
