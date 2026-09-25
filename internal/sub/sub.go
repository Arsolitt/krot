// Package sub serves per-user Happ subscription links, derived live from the
// control plane database on every fetch.
//
// Users are identified by their directory subject and carry no stored token:
// the subscription token is derived — Token(tokenKey, subject) — so no
// credential lives in the ConfigMap. Each /sub/{token} fetch resolves the
// token against the active user set (constant-time comparison), re-checks live
// group membership through Authorizer (verdict cache plus fail-open grace in
// the directory client), and renders fresh links from the enabled servers and
// their inbounds. Alongside the links, the endpoint advertises the Happ
// routing profile as a `routing` header so clients split RU/private traffic
// from the tunnel. Denial is indistinguishable from an unknown token.
package sub

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/Arsolitt/krot/internal/model"
	"github.com/Arsolitt/krot/internal/render"
)

const (
	// tokenPrefix namespaces the HMAC message so the key cannot be reused
	// against other HMAC schemes sharing it.
	tokenPrefix = "krot-sub:" // #nosec G101 -- HMAC input namespace, not a credential.
	// tokenBytes is the derived-token length in bytes (128-bit space).
	tokenBytes = 16
)

// Profile describes the subscription profile advertised to Happ clients
// via response headers.
type Profile struct {
	BaseURL    string `json:"base_url"`
	Title      string `json:"title"`
	SupportURL string `json:"support_url"`
	// RoutingURI is the Happ routing-profile deeplink advertised with the
	// subscription in the `routing` response header, binding the profile to
	// this subscription; empty means no routing profile is offered.
	RoutingURI          string `json:"routing_uri"`
	UpdateIntervalHours int    `json:"update_interval_hours"`
}

// User is one subscription holder with its rendered links. UUID is the
// directory subject and the HMAC input for the derived token.
type User struct {
	Name  string   `json:"name"`
	UUID  string   `json:"uuid"`
	Links []string `json:"links"`
}

// UserSource is the database view the server reads per request. It is
// satisfied by *store.Store.
type UserSource interface {
	ActiveUsers(ctx context.Context) ([]model.User, error)
	EnabledServersWithInbounds(ctx context.Context) ([]model.ServerInbounds, error)
}

// Authorizer checks live group membership; *directory.Cached satisfies it.
type Authorizer interface {
	Allowed(ctx context.Context, subject string) (bool, error)
}

// Token derives the subscription token for a user subject: the first tokenBytes
// of HMAC-SHA256(key, "krot-sub:"+subject), base64url-encoded without
// padding — 22 characters of a 128-bit space. Derived, never stored: stable
// across pod restarts, unguessable without the key.
func Token(key []byte, userUUID string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(tokenPrefix + userUUID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:tokenBytes])
}

// Render produces the subscription body for one user: links joined with
// newlines and a trailing newline.
func Render(u User) string {
	return strings.Join(u.Links, "\n") + "\n"
}

// Server serves subscription links with Happ management headers, including
// the routing profile. Link sets are rendered live from the database on
// every authorized fetch.
type Server struct {
	users    UserSource
	authz    Authorizer
	logger   *slog.Logger
	profile  Profile
	tokenKey []byte
}

// New builds a Server over the database view and the live-membership
// authorizer.
func New(tokenKey []byte, profile Profile, users UserSource, authz Authorizer, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{tokenKey: tokenKey, profile: profile, users: users, authz: authz, logger: logger}
}

// Handler returns the routed HTTP handler:
//
//	GET/HEAD /sub/{token} — subscription links with Happ headers, incl. routing
//	GET      /healthz     — liveness probe
//
// Everything else answers 404.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /sub/{token}", s.handleSub)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	return mux
}

// TokenForUUID returns the derived subscription token of the user with the
// given directory subject, for display on the portal page. Only active users
// resolve.
func (s *Server) TokenForUUID(ctx context.Context, subject string) (string, bool) {
	users, err := s.users.ActiveUsers(ctx)
	if err != nil {
		s.logger.ErrorContext(ctx, "token lookup failed", "error", err)
		return "", false
	}
	for _, u := range users {
		if u.Subject == subject {
			return Token(s.tokenKey, u.Subject), true
		}
	}
	return "", false
}

// lookup resolves the token against the active user set. Every derived token
// is compared with constant-time comparison regardless of a match, so
// response timing does not reveal how deep in the list a candidate matched.
func (s *Server) lookup(ctx context.Context, token string) (model.User, bool) {
	users, err := s.users.ActiveUsers(ctx)
	if err != nil {
		s.logger.ErrorContext(ctx, "subscription user load failed", "error", err)
		return model.User{}, false
	}

	var (
		match model.User
		found int
	)
	for _, u := range users {
		if subtle.ConstantTimeCompare(
			[]byte(token), []byte(Token(s.tokenKey, u.Subject)),
		) == 1 {
			match = u
			found = 1
		}
	}
	return match, found == 1
}

// linksFor renders one URI per enabled (server, inbound) pair for the user.
func (s *Server) linksFor(ctx context.Context, u model.User) ([]string, error) {
	servers, err := s.users.EnabledServersWithInbounds(ctx)
	if err != nil {
		return nil, fmt.Errorf("load link targets: %w", err)
	}

	links := make([]string, 0, len(servers))
	for _, target := range servers {
		for _, in := range target.Inbounds {
			uri, err := render.Link(target.Server.Name, in, u)
			if err != nil {
				return nil, fmt.Errorf("link %s/%s: %w", target.Server.Name, in.Tag, err)
			}
			links = append(links, uri)
		}
	}
	return links, nil
}

func (s *Server) handleSub(w http.ResponseWriter, r *http.Request) {
	user, ok := s.lookup(r.Context(), r.PathValue("token"))
	if !ok {
		s.logger.InfoContext(r.Context(), "subscription lookup miss")
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	if s.authz != nil {
		allowed, err := s.authz.Allowed(r.Context(), user.Subject)
		if err != nil {
			s.logger.ErrorContext(r.Context(), "subscription authz unavailable",
				"user", user.Name, "error", err)
			http.Error(w, "subscription authz unavailable", http.StatusServiceUnavailable)
			return
		}
		if !allowed {
			s.logger.InfoContext(r.Context(), "subscription denied", "user", user.Name)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
	}

	links, err := s.linksFor(r.Context(), user)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "link render failed", "user", user.Name, "error", err)
		http.Error(w, "link render failed", http.StatusInternalServerError)
		return
	}

	s.logger.InfoContext(r.Context(), "subscription served", "user", user.Name, "links", len(links))

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("profile-title", s.profile.Title)
	w.Header().Set("profile-update-interval", strconv.Itoa(s.profile.UpdateIntervalHours))
	// Advertised only when configured: an empty support-url header tells the
	// client there is a support contact and gives it nothing to open.
	if s.profile.SupportURL != "" {
		w.Header().Set("support-url", s.profile.SupportURL)
	}
	// Advertised only when a profile exists: an empty routing header would
	// push clients onto Happ's built-in Default profile.
	if s.profile.RoutingURI != "" {
		w.Header().Set("routing", s.profile.RoutingURI)
	}
	_, _ = w.Write([]byte(Render(User{Name: user.Name, UUID: user.Subject, Links: links})))
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}
