package oidc

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// testRP builds an RP without provider discovery for handler-level tests.
func testRP() *RP {
	return &RP{
		oauth: oauth2.Config{
			ClientID:     "client",
			ClientSecret: "secret",
			Endpoint:     oauth2.Endpoint{AuthURL: "https://auth.example/authorize"},
			RedirectURL:  "https://sub.example/callback",
			Scopes:       []string{"openid", "profile", "email"},
		},
		cookieKey:  []byte("test-cookie-key"),
		sessionTTL: time.Hour,
	}
}

func TestSessionRoundtrip(t *testing.T) {
	rp := testRP()
	value, err := rp.signSession(Session{Sub: "uuid-a", Username: "alice", Exp: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatalf("signSession: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: value})
	s, ok := rp.Session(req)
	if !ok {
		t.Fatal("Session: expected verified session")
	}
	if s.Sub != "uuid-a" || s.Username != "alice" {
		t.Fatalf("Session = %+v", s)
	}
}

func TestSessionTamperedPayload(t *testing.T) {
	rp := testRP()
	value, err := rp.signSession(Session{Sub: "uuid-a", Username: "alice", Exp: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatalf("signSession: %v", err)
	}
	payload, sig, _ := strings.Cut(value, ".")
	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	// Re-encode a different identity but keep the original signature.
	tamperedJSON := strings.Replace(string(data), "alice", "mallory", 1)
	tampered := base64.RawURLEncoding.EncodeToString([]byte(tamperedJSON)) + "." + sig

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: tampered})
	if _, ok := rp.Session(req); ok {
		t.Fatal("Session: tampered payload must not verify")
	}
}

func TestSessionExpired(t *testing.T) {
	rp := testRP()
	value, err := rp.signSession(Session{Sub: "uuid-a", Username: "alice", Exp: time.Now().Add(-time.Minute).Unix()})
	if err != nil {
		t.Fatalf("signSession: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: value})
	if _, ok := rp.Session(req); ok {
		t.Fatal("Session: expired session must not verify")
	}
}

func TestLoginHandler(t *testing.T) {
	rp := testRP()
	rec := httptest.NewRecorder()
	rp.LoginHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	for _, want := range []string{
		"https://auth.example/authorize",
		"code_challenge_method=S256",
		"code_challenge=",
		"nonce=",
		"state=",
	} {
		if !strings.Contains(loc, want) {
			t.Errorf("auth URL %q missing %q", loc, want)
		}
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != stateCookieName {
		t.Fatalf("cookies = %+v, want exactly %s", cookies, stateCookieName)
	}
	c := cookies[0]
	if c.Path != "/callback" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("state cookie attributes: %+v", c)
	}
	if parts := strings.Split(c.Value, "|"); len(parts) != 3 {
		t.Fatalf("state cookie value = %q, want state|verifier|nonce", c.Value)
	}
}

func TestCallbackStateMismatch(t *testing.T) {
	rp := testRP()
	req := httptest.NewRequest(http.MethodGet, "/callback?state=attacker&code=x", nil)
	req.AddCookie(&http.Cookie{Name: stateCookieName, Value: "legit|verifier|nonce"})
	rec := httptest.NewRecorder()

	rp.CallbackHandler(func(http.ResponseWriter, *http.Request) {
		t.Error("success handler must not run on state mismatch")
	}).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestCallbackMissingStateCookie(t *testing.T) {
	rp := testRP()
	req := httptest.NewRequest(http.MethodGet, "/callback?state=x&code=y", nil)
	rec := httptest.NewRecorder()

	rp.CallbackHandler(nil).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestLogoutHandler(t *testing.T) {
	rp := testRP()
	rec := httptest.NewRecorder()
	rp.LogoutHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/logout", nil))

	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Fatalf("logout = %d %q, want 302 /", rec.Code, rec.Header().Get("Location"))
	}
	expired := 0
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			expired++
		}
	}
	if expired != 2 {
		t.Fatalf("expected both cookies expired, got %d", expired)
	}
}
