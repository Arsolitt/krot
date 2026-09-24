// Package oidc implements the relying-party side of the portal login: an
// authorization-code flow with PKCE (S256) and nonce against an authentik
// OIDC provider, plus the stateless HMAC-signed session cookie that keeps the
// user logged in.
//
// This is the only package allowed to import go-oidc and x/oauth2; the rest
// of krot-cp stays stdlib-only.
package oidc

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	// stateCookieName carries state|verifier|nonce through the redirect.
	stateCookieName = "krot_oauth"
	// sessionCookieName carries the signed session payload.
	sessionCookieName = "krot_session"
	// stateCookieTTL bounds the round trip through the identity provider.
	stateCookieTTL = 10 * time.Minute
	// stateBytes/nonceBytes are the raw random lengths for the OAuth state
	// and the ID-token nonce.
	stateBytes = 16
	nonceBytes = 16
	// verifierBytes is the raw PKCE code verifier length (RFC 7636 allows
	// 32..; base64url of 32 bytes stays within the 128-char limit).
	verifierBytes = 32
	// stateParts is the number of "|"-separated fields in the state cookie.
	stateParts = 3
)

// Session is the logged-in identity carried by the session cookie.
type Session struct {
	Sub      string `json:"sub"`
	Username string `json:"username"`
	Exp      int64  `json:"exp"`
}

// RP is the OIDC relying party: login/callback/logout handlers plus session
// verification. The redirect URL comes from configuration only, never from
// request headers — ingress TLS termination is invisible to the app.
type RP struct {
	oauth      oauth2.Config
	verifier   *oidc.IDTokenVerifier
	cookieKey  []byte
	sessionTTL time.Duration
}

// New discovers the provider at issuer and builds the relying party.
func New(
	ctx context.Context,
	issuer, clientID, clientSecret, redirectURL string,
	cookieKey []byte,
	sessionTTL time.Duration,
) (*RP, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery at %s: %w", issuer, err)
	}
	return &RP{
		oauth: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  redirectURL,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		verifier:   provider.Verifier(&oidc.Config{ClientID: clientID}),
		cookieKey:  cookieKey,
		sessionTTL: sessionTTL,
	}, nil
}

// LoginHandler starts the authorization-code flow: fresh state, PKCE
// verifier, and nonce are stashed in a short-lived cookie bound to /callback
// and the browser is redirected to the provider.
func (rp *RP) LoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, err := randomToken(stateBytes)
		if err != nil {
			http.Error(w, "oauth state generation failed", http.StatusInternalServerError)
			return
		}
		verifier, err := randomToken(verifierBytes)
		if err != nil {
			http.Error(w, "oauth verifier generation failed", http.StatusInternalServerError)
			return
		}
		nonce, err := randomToken(nonceBytes)
		if err != nil {
			http.Error(w, "oauth nonce generation failed", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     stateCookieName,
			Value:    state + "|" + verifier + "|" + nonce,
			Path:     "/callback",
			MaxAge:   int(stateCookieTTL.Seconds()),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
		authURL := rp.oauth.AuthCodeURL(
			state,
			oauth2.SetAuthURLParam("code_challenge", s256(verifier)),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
			oidc.Nonce(nonce),
		)
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

// CallbackHandler finishes the flow: validates state (constant time),
// exchanges the code with the PKCE verifier, verifies the ID token and its
// nonce, then installs the signed session cookie and delegates to success.
func (rp *RP) CallbackHandler(success http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(stateCookieName)
		if err != nil {
			http.Error(w, "missing oauth state cookie", http.StatusBadRequest)
			return
		}
		parts := strings.SplitN(c.Value, "|", stateParts)
		if len(parts) != stateParts {
			http.Error(w, "malformed oauth state cookie", http.StatusBadRequest)
			return
		}
		state, verifier, nonce := parts[0], parts[1], parts[2]
		if subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("state")), []byte(state)) != 1 {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}

		token, err := rp.oauth.Exchange(
			r.Context(),
			r.URL.Query().Get("code"),
			oauth2.SetAuthURLParam("code_verifier", verifier),
		)
		if err != nil {
			slog.ErrorContext(r.Context(), "oauth code exchange failed", "error", err)
			http.Error(w, "code exchange failed", http.StatusBadGateway)
			return
		}
		rawIDToken, _ := token.Extra("id_token").(string)
		if rawIDToken == "" {
			http.Error(w, "no id_token in token response", http.StatusBadGateway)
			return
		}
		idToken, err := rp.verifier.Verify(r.Context(), rawIDToken)
		if err != nil {
			slog.ErrorContext(r.Context(), "id token verification failed", "error", err)
			http.Error(w, "id token verification failed", http.StatusBadGateway)
			return
		}
		if idToken.Nonce != nonce {
			http.Error(w, "nonce mismatch", http.StatusBadRequest)
			return
		}

		var claims struct {
			Sub               string `json:"sub"`
			PreferredUsername string `json:"preferred_username"`
		}
		if err := idToken.Claims(&claims); err != nil {
			http.Error(w, "id token claims decode failed", http.StatusBadGateway)
			return
		}

		exp := time.Now().Add(rp.sessionTTL)
		value, err := rp.signSession(Session{
			Sub:      claims.Sub,
			Username: claims.PreferredUsername,
			Exp:      exp.Unix(),
		})
		if err != nil {
			http.Error(w, "session signing failed", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    value,
			Path:     "/",
			MaxAge:   int(rp.sessionTTL.Seconds()),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
		clearCookie(w, stateCookieName, "/callback")

		success(w, r)
	}
}

// Session verifies the session cookie signature and expiry and returns the
// logged-in identity.
func (rp *RP) Session(r *http.Request) (Session, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return Session{}, false
	}
	payload, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		return Session{}, false
	}
	want := hex.EncodeToString(hmacSum(rp.cookieKey, payload))
	if subtle.ConstantTimeCompare([]byte(want), []byte(sig)) != 1 {
		return Session{}, false
	}

	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return Session{}, false
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return Session{}, false
	}
	if time.Now().Unix() >= s.Exp {
		return Session{}, false
	}
	if s.Sub == "" {
		return Session{}, false
	}
	return s, true
}

// LogoutHandler expires both cookies and returns to the front page.
func (rp *RP) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clearCookie(w, sessionCookieName, "/")
		clearCookie(w, stateCookieName, "/callback")
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// signSession encodes the session cookie value: base64url(json) + "." +
// hex(HMAC-SHA256(cookieKey, payload)).
func (rp *RP) signSession(s Session) (string, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("oidc: encode session: %w", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(data)
	return payload + "." + hex.EncodeToString(hmacSum(rp.cookieKey, payload)), nil
}

// randomToken returns n random bytes base64url-encoded.
func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("oidc: read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// s256 derives the S256 PKCE code challenge for a verifier.
func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// hmacSum computes HMAC-SHA256(key, msg).
func hmacSum(key []byte, msg string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	return mac.Sum(nil)
}

// clearCookie expires a cookie in the browser.
func clearCookie(w http.ResponseWriter, name, path string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}
