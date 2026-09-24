// Package web serves the krot portal: a templ+htmx user page with the
// subscription URL and a read-only admin view of nodes, users and sync state.
//
//nolint:godoclint // templ writes a version comment above its package clause.
package web

import (
	"bytes"
	"context"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/a-h/templ"

	"github.com/Arsolitt/krot/internal/model"
	"github.com/Arsolitt/krot/internal/oidc"
)

// Static exposes the embedded assets under their static/ prefix.
func Static() fs.FS {
	return static
}

// SubTokens resolves the derived subscription token of a user (sub.Server).
type SubTokens interface {
	TokenForUUID(ctx context.Context, subject string) (string, bool)
}

// SessionProvider verifies session cookies (oidc.RP).
type SessionProvider interface {
	Session(r *http.Request) (oidc.Session, bool)
}

// GroupChecker reports live group membership (directory.Cached).
type GroupChecker interface {
	Allowed(ctx context.Context, subject string) (bool, error)
}

// AdminStore is the admin data view (*store.Store).
type AdminStore interface {
	ServersWithStatus(ctx context.Context) ([]model.ServerWithStatus, error)
	Users(ctx context.Context) ([]model.User, error)
	SyncState(ctx context.Context) (model.SyncState, error)
}

// Deps wires the portal handlers. RP holds the relying party once OIDC
// discovery has succeeded; handlers treat a nil RP as "login unavailable".
type Deps struct {
	Sub                SubTokens
	Checker            GroupChecker
	AdminChecker       GroupChecker
	Store              AdminStore
	RP                 *atomic.Pointer[oidc.RP]
	Trigger            func()
	Logger             *slog.Logger
	BaseURL            string
	RoutingURI         string
	ProfileTitle       string
	RoutingProfileJSON []byte
}

// session resolves the logged-in identity, if any.
func (d *Deps) session(r *http.Request) (oidc.Session, bool) {
	rp := d.RP.Load()
	if rp == nil {
		return oidc.Session{}, false
	}
	return rp.Session(r)
}

// Page answers GET / — the user page with the subscription URL.
func (d *Deps) Page(w http.ResponseWriter, r *http.Request) {
	sess, ok := d.session(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	data := IndexData{Username: sess.Username}
	allowed, err := d.Checker.Allowed(r.Context(), sess.Sub)
	if err != nil {
		d.logError(r, "portal membership check failed", err)
		http.Error(w, "membership check unavailable", http.StatusServiceUnavailable)
		return
	}
	if allowed {
		if token, found := d.Sub.TokenForUUID(r.Context(), sess.Sub); found {
			data.URL = d.BaseURL + "/sub/" + token
		}
	}
	render(w, r, index(data))
}

// AdminPage answers GET /admin — the admin page shell. Non-admins get a 404
// so the page's existence is not revealed.
func (d *Deps) AdminPage(w http.ResponseWriter, r *http.Request) {
	if !d.adminAllowed(w, r) {
		return
	}
	data, ok := d.adminData(w, r)
	if !ok {
		return
	}
	render(w, r, admin(data))
}

// AdminPanel answers GET /admin/panel — the htmx fragment.
func (d *Deps) AdminPanel(w http.ResponseWriter, r *http.Request) {
	if !d.adminAllowed(w, r) {
		return
	}
	data, ok := d.adminData(w, r)
	if !ok {
		return
	}
	render(w, r, adminPanel(data))
}

// Sync answers POST /admin/sync — triggers an immediate identity sync and
// re-renders the panel fragment.
func (d *Deps) Sync(w http.ResponseWriter, r *http.Request) {
	if !d.adminAllowed(w, r) {
		return
	}
	if d.Trigger != nil {
		d.Trigger()
	}
	data, ok := d.adminData(w, r)
	if !ok {
		return
	}
	render(w, r, adminPanel(data))
}

// RoutingPage answers GET /routing — the public Happ routing-profile landing
// page. Unauthenticated by design: the profile is identical for every client
// and holds no per-user data.
func (d *Deps) RoutingPage(w http.ResponseWriter, r *http.Request) {
	render(w, r, routing(RoutingData{Title: d.ProfileTitle, Deeplink: d.RoutingURI}))
}

// RoutingProfile answers GET /routing.json — the raw profile, for clients and
// scripts that fetch it directly.
func (d *Deps) RoutingProfile(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(d.RoutingProfileJSON)
}

// RoutingImport answers GET /routing/import — a shareable https URL that hands
// the deeplink straight to Happ.
func (d *Deps) RoutingImport(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, d.RoutingURI, http.StatusFound)
}

// adminAllowed checks the admin group membership, answering 404 otherwise.
func (d *Deps) adminAllowed(w http.ResponseWriter, r *http.Request) bool {
	sess, ok := d.session(r)
	if !ok {
		http.NotFound(w, r)
		return false
	}
	allowed, err := d.AdminChecker.Allowed(r.Context(), sess.Sub)
	if err != nil {
		d.logError(r, "admin membership check failed", err)
		http.NotFound(w, r)
		return false
	}
	if !allowed {
		d.logInfo(r, "admin page denied")
		http.NotFound(w, r)
		return false
	}
	return true
}

// adminData assembles the panel state from the store.
func (d *Deps) adminData(w http.ResponseWriter, r *http.Request) (AdminPanelData, bool) {
	servers, err := d.Store.ServersWithStatus(r.Context())
	if err != nil {
		d.logError(r, "admin servers load failed", err)
		http.Error(w, "admin data unavailable", http.StatusInternalServerError)
		return AdminPanelData{}, false
	}
	users, err := d.Store.Users(r.Context())
	if err != nil {
		d.logError(r, "admin users load failed", err)
		http.Error(w, "admin data unavailable", http.StatusInternalServerError)
		return AdminPanelData{}, false
	}
	sync, err := d.Store.SyncState(r.Context())
	if err != nil {
		d.logError(r, "admin sync state load failed", err)
		http.Error(w, "admin data unavailable", http.StatusInternalServerError)
		return AdminPanelData{}, false
	}

	var username string
	if s, sessOK := d.session(r); sessOK {
		username = s.Username
	}

	data := AdminPanelData{
		Username: username,
		Sync:     SyncView{LastSync: formatTimePtr(sync.LastSyncAt), Error: sync.LastError},
	}
	for _, s := range servers {
		data.Servers = append(data.Servers, ServerView{
			Name:      s.Server.Name,
			Endpoint:  s.Server.Endpoint,
			Profile:   s.Server.RouteProfile,
			Enabled:   s.Server.Enabled,
			Healthy:   s.Status.SingboxHealthy,
			Seen:      formatSeen(s.Status.LastSeen),
			Version:   s.Status.AgentVersion,
			Users:     s.Status.UserCount,
			ConfigErr: s.Status.ConfigError,
		})
	}
	for _, u := range users {
		data.Users = append(data.Users, UserView{Name: u.Name, Active: u.Active})
	}
	return data, true
}

// render buffers a fully rendered component before writing, so a render
// error never produces a half-written response.
func render(w http.ResponseWriter, r *http.Request, c templ.Component) {
	var buf bytes.Buffer
	if err := c.Render(r.Context(), &buf); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// formatTimePtr renders an optional timestamp.
func formatTimePtr(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.UTC().Format(time.DateTime)
}

// formatSeen renders the last heartbeat time; the table default of the
// epoch marks "never seen".
func formatSeen(t time.Time) string {
	if t.IsZero() || t.Year() < wellKnownEpochYear {
		return "never"
	}
	return t.UTC().Format(time.DateTime)
}

// wellKnownEpochYear separates real timestamps from the epoch default.
const wellKnownEpochYear = 2000

// fmtInt exists for templ templates, which cannot call strconv directly.
func fmtInt(i int) string { return strconv.Itoa(i) }

// logError logs with the configured logger.
func (d *Deps) logError(r *http.Request, msg string, err error) {
	if d.Logger != nil {
		d.Logger.ErrorContext(r.Context(), msg, "error", err)
	}
}

// logInfo logs with the configured logger.
func (d *Deps) logInfo(r *http.Request, msg string) {
	if d.Logger != nil {
		d.Logger.InfoContext(r.Context(), msg)
	}
}
