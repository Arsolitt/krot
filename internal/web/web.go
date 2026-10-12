// Package web serves the krot portal: a templ+htmx user page with the
// subscription URL and a read-only admin view of nodes, users and sync state.
//
//nolint:godoclint // templ writes a version comment above its package clause.
package web

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
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
// RebuildCreate is wired by the control plane; a nil func makes POST
// /rebuild answer "not configured".
type Deps struct {
	Sub           SubTokens
	Checker       GroupChecker
	AdminChecker  GroupChecker
	Store         AdminStore
	RP            *atomic.Pointer[oidc.RP]
	Trigger       func()
	RebuildCreate func(ctx context.Context, r *http.Request, upstreamURL, proxyTag, adsMode, secret string) (token string, err error)
	Logger        *slog.Logger
	BaseURL       string
	RoutingURI    string
	ProfileTitle  string

	// rebuildLimit throttles failed POST /rebuild attempts per client IP. It
	// is installed lazily by limiter; tests may pre-set it (with a fake
	// clock) before the first handler call.
	rebuildLimit       *rebuildLimiter
	RoutingProfileJSON []byte
	rebuildLimitOnce   sync.Once
	RebuildSecretSet   bool
}

// limiter returns the rebuild failure limiter, installing the default on
// first use so a Deps literal needs no explicit construction.
func (d *Deps) limiter() *rebuildLimiter {
	d.rebuildLimitOnce.Do(func() {
		if d.rebuildLimit == nil {
			d.rebuildLimit = newRebuildLimiter(time.Now)
		}
	})
	return d.rebuildLimit
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

	data := IndexData{Nav: d.nav(r), Username: sess.Username}
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
	d.render(w, r, index(data))
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
	d.render(w, r, admin(data))
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
	d.render(w, r, adminPanel(data))
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
	d.render(w, r, adminPanel(data))
}

// RoutingPage answers GET /routing — the public Happ routing-profile landing
// page. Unauthenticated by design: the profile is identical for every client
// and holds no per-user data.
func (d *Deps) RoutingPage(w http.ResponseWriter, r *http.Request) {
	d.render(w, r, routing(RoutingData{Nav: d.nav(r), Title: d.ProfileTitle, Deeplink: d.RoutingURI}))
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

// maxRebuildURLLen bounds the provider subscription URL accepted by the
// re-builder form, matching the input's maxlength attribute.
const maxRebuildURLLen = 2048

// Ads modes accepted by the re-builder: light blocks geosite:category-ads,
// full blocks geosite:category-ads-all.
const (
	adsModeLight = "light"
	adsModeFull  = "full"
)

// rebuildClientErrorMsg is the fallback message rendered when the builder
// reports an error that must not be echoed back to the client.
const rebuildClientErrorMsg = "could not build the subscription link"

// rebuildThrottledMsg is the short message a throttled POST /rebuild receives;
// like the other failure messages it names no detail.
const rebuildThrottledMsg = "too many rebuild attempts; try again later"

// Parameters of the per-IP failure limiter behind POST /rebuild: a client may
// accumulate rebuildLimitBurst failed attempts, refilled over
// rebuildLimitWindow, and successful attempts clear the budget. The bucket
// map is pruned once it grows past rebuildLimitPruneAt entries, retiring
// buckets idle for rebuildLimitPruneAfter.
const (
	rebuildLimitBurst      = 10
	rebuildLimitWindow     = time.Minute
	rebuildLimitPruneAfter = 10 * time.Minute
	rebuildLimitPruneAt    = 1024
)

// rebuildLimiter is the failure limiter behind POST /rebuild: one token
// bucket per client IP, refilled continuously and spent by failed attempts
// only. A successful attempt clears the bucket, so a working client is never
// throttled; a client guessing the access secret burns its burst and is
// answered 429 until the bucket refills. State sits behind one mutex, which
// is enough at this endpoint's rate.
type rebuildLimiter struct {
	now     func() time.Time
	buckets map[string]*rebuildBucket
	burst   float64
	refill  float64
	mu      sync.Mutex
}

// rebuildBucket is one client's remaining failed-attempt budget: the token
// count and the time it was last accounted for.
type rebuildBucket struct {
	last   time.Time
	tokens float64
}

// newRebuildLimiter returns a limiter with the given clock; nil means
// time.Now. Tests inject a fake clock to step through refills.
func newRebuildLimiter(now func() time.Time) *rebuildLimiter {
	if now == nil {
		now = time.Now
	}
	return &rebuildLimiter{
		now:     now,
		buckets: make(map[string]*rebuildBucket),
		burst:   rebuildLimitBurst,
		refill:  rebuildLimitBurst / rebuildLimitWindow.Seconds(),
	}
}

// allow reports whether the client behind key may attempt a rebuild now:
// false once its failed attempts have exhausted the burst.
func (l *rebuildLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	bucket, ok := l.buckets[key]
	if !ok {
		return true
	}
	return l.refilled(bucket, l.now()) > 0
}

// fail records one failed attempt of the client behind key, spending a token.
func (l *rebuildLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	bucket, ok := l.buckets[key]
	if !ok {
		l.pruneLocked(now)
		bucket = &rebuildBucket{last: now, tokens: l.burst}
		l.buckets[key] = bucket
	}
	if tokens := l.refilled(bucket, now); tokens > 0 {
		tokens--
		bucket.tokens = tokens
	}
}

// succeed clears the failure budget of the client behind key: a client that
// completed a rebuild is never throttled by its earlier failures.
func (l *rebuildLimiter) succeed(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.buckets, key)
}

// refilled returns the bucket's token count with the time since its last
// accounting added in, capped at the burst, and updates the bucket to that
// state. The caller holds the mutex.
func (l *rebuildLimiter) refilled(bucket *rebuildBucket, now time.Time) float64 {
	elapsed := now.Sub(bucket.last).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	bucket.tokens = min(bucket.tokens+elapsed*l.refill, l.burst)
	bucket.last = now
	return bucket.tokens
}

// pruneLocked bounds the bucket map when it grows past rebuildLimitPruneAt
// entries: idle and fully refilled buckets are dropped, and if a flood of
// fresh clients leaves nothing droppable, arbitrary entries are evicted until
// the map is back under the limit. Eviction forgives a throttled client,
// which is the safe direction for a memory bound.
func (l *rebuildLimiter) pruneLocked(now time.Time) {
	if len(l.buckets) < rebuildLimitPruneAt {
		return
	}
	for key, bucket := range l.buckets {
		if now.Sub(bucket.last) >= rebuildLimitPruneAfter {
			delete(l.buckets, key)
		}
	}
	for key := range l.buckets {
		if len(l.buckets) < rebuildLimitPruneAt {
			return
		}
		delete(l.buckets, key)
	}
}

// clientIP extracts the client address the throttle keys on: the host part of
// the connection's RemoteAddr only. Forwarding headers are deliberately
// ignored — behind the ingress they are client-controlled and would let one
// client rotate identities past the limiter.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// RebuildPage answers GET /rebuild — the public subscription re-builder form.
// Unauthenticated by design: the token it produces is a capability and the
// page itself holds no per-user data.
func (d *Deps) RebuildPage(w http.ResponseWriter, r *http.Request) {
	d.render(w, r, rebuildPage(RebuildData{Nav: d.nav(r), Title: d.ProfileTitle, SecretSet: d.RebuildSecretSet}))
}

// RebuildCreateHandler answers POST /rebuild — validates the provider
// subscription URL, asks the wired builder to seal it, and renders the
// resulting /rbr/ link. htmx requests receive the result fragment alone;
// plain form posts receive the full page with the result embedded. Failed
// attempts are throttled per client IP (never per forwarding header), so a
// client guessing the access secret is answered 429 before the builder is
// consulted; a successful attempt clears the budget.
func (d *Deps) RebuildCreateHandler(w http.ResponseWriter, r *http.Request) {
	client := clientIP(r)
	limiter := d.limiter()
	if !limiter.allow(client) {
		d.logInfo(r, "rebuild request throttled")
		d.rebuildRespond(w, r, RebuildResultData{Error: rebuildThrottledMsg}, http.StatusTooManyRequests)
		return
	}
	if err := r.ParseForm(); err != nil {
		limiter.fail(client)
		d.rebuildRespond(w, r, RebuildResultData{Error: "could not read the form"}, http.StatusBadRequest)
		return
	}
	upstreamURL := r.PostFormValue("upstream_url")
	proxyTag := r.PostFormValue("proxy_tag")
	adsMode := r.PostFormValue("ads_mode")
	secret := r.PostFormValue("secret")

	if err := validateRebuildRequest(upstreamURL, adsMode); err != nil {
		limiter.fail(client)
		d.rebuildRespond(w, r, RebuildResultData{Error: err.Error()}, http.StatusBadRequest)
		return
	}
	if d.RebuildCreate == nil {
		d.logInfo(r, "rebuild requested while not configured")
		d.rebuildRespond(w, r, RebuildResultData{Error: "re-builder is not configured"}, http.StatusServiceUnavailable)
		return
	}

	token, err := d.RebuildCreate(r.Context(), r, upstreamURL, proxyTag, adsMode, secret)
	if err != nil {
		limiter.fail(client)
		d.logError(r, "rebuild failed", err)
		d.rebuildRespond(
			w,
			r,
			RebuildResultData{Error: rebuildClientError(err, upstreamURL, secret)},
			http.StatusBadRequest,
		)
		return
	}
	limiter.succeed(client)
	d.rebuildRespond(w, r, RebuildResultData{Link: d.BaseURL + "/rbr/" + token}, http.StatusOK)
}

// validateRebuildRequest checks the submitted non-empty fields: a plain https
// URL without credentials within the length bound, and a known ads mode.
// Error messages never echo the URL.
func validateRebuildRequest(upstreamURL, adsMode string) error {
	switch adsMode {
	case "", adsModeLight, adsModeFull:
	default:
		return errors.New("ads mode must be light or full")
	}
	if upstreamURL == "" {
		return errors.New("provider subscription URL is required")
	}
	if len(upstreamURL) > maxRebuildURLLen {
		return errors.New("provider subscription URL is too long")
	}
	u, err := url.Parse(upstreamURL)
	if err != nil {
		return errors.New("provider subscription URL is not a valid URL")
	}
	if u.Scheme != "https" || u.Host == "" {
		return errors.New("provider subscription URL must be an https URL")
	}
	if u.User != nil {
		return errors.New("provider subscription URL must not carry credentials")
	}
	return nil
}

// rebuildClientError returns the message to show for a builder failure: the
// builder's own error only when it is short and echoes neither the submitted
// URL nor the secret, which may both hold credentials.
func rebuildClientError(err error, upstreamURL, secret string) string {
	msg := err.Error()
	if msg == "" || len(msg) > 200 ||
		(upstreamURL != "" && strings.Contains(msg, upstreamURL)) ||
		(secret != "" && strings.Contains(msg, secret)) {
		return rebuildClientErrorMsg
	}
	return msg
}

// rebuildRespond renders the rebuild result: as an htmx fragment when the
// request came from htmx, and as a full page with the result embedded
// otherwise, so a plain form post works without JavaScript.
func (d *Deps) rebuildRespond(w http.ResponseWriter, r *http.Request, result RebuildResultData, status int) {
	if isHTMX(r) {
		d.renderStatus(w, r, status, rebuildResult(result))
		return
	}
	d.renderStatus(w, r, status, rebuildPage(RebuildData{
		Nav:       d.nav(r),
		Title:     d.ProfileTitle,
		SecretSet: d.RebuildSecretSet,
		Result:    &result,
	}))
}

// isHTMX reports whether the request was issued by htmx and thus expects a
// fragment response.
func isHTMX(r *http.Request) bool {
	return r.Header.Get("Hx-Request") == "true"
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
		Nav:      d.nav(r),
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
// error never produces a half-written response. The layout's conditional
// navigation is computed once per full-page render: the admin entry appears
// only for members, and the auth link follows the session.
func (d *Deps) render(w http.ResponseWriter, r *http.Request, c templ.Component) {
	d.renderStatus(w, r, http.StatusOK, c)
}

// renderStatus is render with an explicit response status.
func (d *Deps) renderStatus(w http.ResponseWriter, r *http.Request, status int, c templ.Component) {
	var buf bytes.Buffer
	if err := c.Render(r.Context(), &buf); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// nav assembles the page navigation for the current request: the admin entry
// is offered only to members, sign-in only to anonymous visitors and sign-out
// only to sessions. A membership error hides the admin entry rather than
// failing the page.
func (d *Deps) nav(r *http.Request) Nav {
	if d.RP == nil {
		return Nav{SignIn: true}
	}
	sess, signedIn := d.session(r)
	nav := Nav{SignedIn: signedIn, SignIn: !signedIn, SignOut: signedIn}
	if !signedIn || d.AdminChecker == nil {
		return nav
	}
	allowed, err := d.AdminChecker.Allowed(r.Context(), sess.Sub)
	if err != nil {
		d.logError(r, "admin membership check failed for navigation", err)
		return nav
	}
	nav.Admin = allowed
	return nav
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
