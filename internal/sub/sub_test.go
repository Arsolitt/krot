package sub

import (
	"context"
	"encoding/hex"
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
	return testEnvWithProfile(testProfile(), authz)
}

// testProfile is the routing profile the standard fixture advertises.
func testProfile() Profile {
	return Profile{
		Title:               "Krot VPN",
		UpdateIntervalHours: 24,
		RoutingURI:          "happ://routing/onadd/cHJvZmlsZQ==",
	}
}

// testEnvWithProfile assembles the same fixture with a caller-supplied
// profile, for tests that vary the advertised headers.
func testEnvWithProfile(profile Profile, authz Authorizer) (*Server, model.User) {
	return testEnvWithNamespace(DefaultTokenNamespace, profile, authz)
}

// testEnvWithNamespace assembles the same fixture with a caller-supplied
// token namespace, for tests that vary the HMAC input.
func testEnvWithNamespace(namespace string, profile Profile, authz Authorizer) (*Server, model.User) {
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
	return New(tokenKey32, namespace, profile, src, authz, nil), user
}

func TestHandleSubServesLinksWithHeaders(t *testing.T) {
	server, user := testEnv(fakeAuthz{allowed: true})
	token := Token(tokenKey32, DefaultTokenNamespace, user.Subject)

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
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sub/"+Token(tokenKey32, DefaultTokenNamespace, user.Subject), nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if vals := rec.Header().Values("routing"); len(vals) != 0 {
		t.Errorf("routing header = %q, want absent", vals)
	}
}

// TestHandleSubOmitsSupportURLHeaderWhenUnset pins the same rule for the
// support contact: an empty header advertises a support channel and gives the
// client nothing to open.
func TestHandleSubOmitsSupportURLHeaderWhenUnset(t *testing.T) {
	server, user := testEnvWithProfile(Profile{Title: "Krot VPN"}, fakeAuthz{allowed: true})

	rec := httptest.NewRecorder()
	server.Handler().
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sub/"+Token(tokenKey32, DefaultTokenNamespace, user.Subject), nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if vals := rec.Header().Values("support-url"); len(vals) != 0 {
		t.Errorf("support-url header = %q, want absent", vals)
	}
}

func TestHandleSubDenials(t *testing.T) {
	server, user := testEnv(fakeAuthz{allowed: false})
	token := Token(tokenKey32, DefaultTokenNamespace, user.Subject)

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
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sub/"+Token(tokenKey32, DefaultTokenNamespace, user.Subject), nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}

func TestHandleSubSourceError(t *testing.T) {
	src := &fakeSource{err: errors.New("db down")}
	server := New(tokenKey32, DefaultTokenNamespace, Profile{}, src, fakeAuthz{allowed: true}, nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sub/anything", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (indistinguishable from unknown token)", rec.Code)
	}
}

func TestTokenForUUID(t *testing.T) {
	server, user := testEnv(fakeAuthz{allowed: true})

	got, ok := server.TokenForUUID(context.Background(), user.Subject)
	if !ok || got != Token(tokenKey32, DefaultTokenNamespace, user.Subject) {
		t.Errorf("TokenForUUID = %q, %v", got, ok)
	}
	if _, ok := server.TokenForUUID(context.Background(), "unknown"); ok {
		t.Error("unknown uuid must not resolve")
	}
}

func TestTokenStableShape(t *testing.T) {
	got := Token(tokenKey32, DefaultTokenNamespace, "uuid-1")
	if len(got) != tokenChars {
		t.Errorf("token length = %d, want 22", len(got))
	}
	if Token(tokenKey32, DefaultTokenNamespace, "uuid-1") != got {
		t.Error("token derivation must be deterministic")
	}
	if Token([]byte("another-32-byte-key-aaaaaaaaaaaaa"), DefaultTokenNamespace, "uuid-1") == got {
		t.Error("token must depend on the key")
	}
}

// TestTokenNamespaceVectors pins the derivation against independently
// computed vectors, catching any change to the namespace handling or the
// HMAC message construction.
func TestTokenNamespaceVectors(t *testing.T) {
	key, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	tests := []struct {
		name      string
		namespace string
		want      string
	}{
		{name: "default namespace", namespace: DefaultTokenNamespace, want: "PmQ7Al_p3LQrogMgo36uUw"},
		{name: "custom namespace", namespace: "cheburnet-sub:", want: "jlyoSpx7tjUgMO5v--zW_w"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Token(key, tt.namespace, "uuid-s")
			t.Logf("Token(namespace %q) = %q", tt.namespace, got)
			if got != tt.want {
				t.Errorf("Token(namespace %q) = %q, want %q", tt.namespace, got, tt.want)
			}
		})
	}
}

// TestHandleSubNamespace pins that lookups use the server's configured
// namespace: a token derived under it resolves, a default-namespace token
// does not.
func TestHandleSubNamespace(t *testing.T) {
	server, user := testEnvWithNamespace("cheburnet-sub:", testProfile(), fakeAuthz{allowed: true})

	rec := httptest.NewRecorder()
	server.Handler().
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sub/"+Token(tokenKey32, "cheburnet-sub:", user.Subject), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(
		body,
		"vless://397fd10e-5e2c-4817-bd56-2d8e9a78d099@srv-1.example.com:443?",
	) {
		t.Errorf("body missing vless link:\n%s", body)
	}

	rec = httptest.NewRecorder()
	server.Handler().
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sub/"+Token(tokenKey32, DefaultTokenNamespace, user.Subject), nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("default-namespace token status = %d, want 404", rec.Code)
	}
}
