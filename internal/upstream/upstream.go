// Package upstream fetches provider subscriptions for the rebuild endpoint.
//
// The target is vetted before anything is dialed, and every address the
// transport is about to connect to is vetted again, which is what turns the
// guard into a rebinding-proof check instead of a check-then-dial race: HTTPS
// only, the standard port only, and a host whose every resolved address
// belongs to the public internet.
//
// The identification headers of the requesting client are relayed to the
// provider, so provider-side device accounting sees the device the fetch is
// made for rather than krot. Nothing else travels: credentials, cookies and
// control-plane headers stay behind.
//
// Bodies are cached per URL and client session with a short TTL and
// revalidated with an ETag. Concurrent fetches of one key share a single
// upstream request, at most maxConcurrentFetches of them are in flight at
// once, and the cache holds no more than maxCacheBytes of body bytes across no
// more than maxCacheEntries entries: neither a burst of clients nor a provider
// dictating body sizes can grow krot's memory without bound. An upstream
// failure serves the cached copy rather than an error, so a provider outage
// ends neither a client's subscription nor krot's availability.
//
// Nothing here ever surfaces a target URL — provider URLs carry the
// subscription secret in their query string — so errors and log lines name
// status codes and generic reasons only.
package upstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	// defaultTimeout bounds one upstream request end to end: connect, TLS,
	// redirects and body. It also bounds a shared in-flight fetch whose
	// initiating caller has gone away.
	defaultTimeout = 15 * time.Second
	// dialTimeout bounds one address dial inside the guarded dialer.
	dialTimeout = 10 * time.Second
	// defaultCacheTTL is how long a fetched body is served without asking the
	// provider again. Provider links change rarely, so several clients opening
	// the same rebuild link cost one upstream request, not one each.
	defaultCacheTTL = 120 * time.Second
	// maxRedirects is how many redirect hops are followed. Every hop is
	// re-vetted, so a permitted URL cannot bounce into a blocked one.
	maxRedirects = 3
	// maxResponseBytes caps the accepted body: a subscription is a small text
	// document, and an unbounded read would let the provider dictate krot's
	// memory use. It is deliberately far below the container's own limit,
	// because a fetch in flight holds its body in memory.
	maxResponseBytes = 2 << 20
	// drainLimit is how much of a refused body is read so the connection can
	// be reused for the next fetch of the same provider.
	drainLimit = 4 << 10
	// maxCacheBytes bounds the cache by the body bytes it holds. Entries are
	// evicted oldest-first until the cache fits again, so distinct URLs cannot
	// grow the cache without bound; headers are not counted, as bodies are
	// what a provider can inflate.
	maxCacheBytes = 16 << 20
	// maxCacheEntries bounds the cache by entries as well, as a second line of
	// defence: a body of a few bytes costs nothing against the byte budget,
	// so bodies alone would not bound the map.
	maxCacheEntries = 1024
	// maxConcurrentFetches bounds how many upstream fetches are in flight at
	// once. A shared in-flight fetch counts once, however many callers wait on
	// it, so the bound is on provider connections and buffered bodies rather
	// than on clients.
	maxConcurrentFetches = 8
	// httpsPort is the only port a target may use: reaching a subscription
	// provider over any other port is a port scan with extra steps.
	httpsPort = "443"
	// defaultContentType is assumed for a provider that sent no Content-Type
	// at all: the link-list form.
	defaultContentType = "text/plain; charset=utf-8"
)

// ErrBlockedTarget reports a target URL the guard refuses: a scheme other than
// HTTPS, embedded credentials, a port other than 443, a redirect chain longer
// than maxRedirects, or a host that resolves to an address outside the public
// internet. The message never repeats any part of the URL.
var ErrBlockedTarget = errors.New("upstream: target not allowed")

// ErrUnguardedClient reports a caller-supplied client whose transport cannot
// carry the dial guard: one that is not an *http.Transport, or that dials TLS
// or a proxy on its own. The dial-time check is what makes a fetch
// rebinding-proof, so such a client is never used as it is: every fetch of
// the fetcher built around it fails with this error instead.
var ErrUnguardedClient = errors.New("upstream: client transport cannot carry the dial guard")

// The address space the guard refuses, beyond what netip classifies itself.
var (
	// cgnatPrefix is 100.64.0.0/10 (RFC 6598), the carrier-grade NAT range,
	// which also carries the Alibaba Cloud metadata address 100.100.100.200.
	cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")
	// thisNetworkPrefix is 0.0.0.0/8: "this network", which a dialer reads as
	// an address of the local machine.
	thisNetworkPrefix = netip.MustParsePrefix("0.0.0.0/8")
	// reservedPrefix is 240.0.0.0/4, reserved for future use; it contains the
	// limited broadcast address 255.255.255.255.
	reservedPrefix = netip.MustParsePrefix("240.0.0.0/4")
	// transitionPrefixes are the IPv6 transition ranges that embed an IPv4
	// address: 6to4 (RFC 3056) and Teredo (RFC 4380) carry one in their own
	// encoding, and the NAT64 prefixes (RFC 6052 well-known, RFC 8215
	// local-use) reach the IPv4 address they embed through the translator.
	// A host in one of them is therefore only public on paper.
	transitionPrefixes = []netip.Prefix{
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("2001::/32"),
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("64:ff9b:1::/48"),
	}
)

// relayHeaderNames are the client identification headers forwarded to the
// provider, in the canonical form net/http keys headers by and matched
// case-insensitively, as header names are. The set is closed on purpose:
// keeping a client's credentials or a control-plane header out of the provider
// request matters more than any header the provider might like.
var relayHeaderNames = []string{
	"User-Agent",
	"Hwid",
	"X-Hwid",
	"X-Ver-Os",
	"X-Ver",
	"X-Device-Model",
	"Device",
	"Device-Model",
}

// profileHeaderNames are the Happ management headers relayed from a provider
// response. The provider's own routing header is deliberately not among them:
// the rebuild endpoint decides which routing profile the client is given.
var profileHeaderNames = []string{
	"Subscription-Userinfo",
	"Profile-Title",
	"Profile-Update-Interval",
	"Support-Url",
}

// Spec is the operator's rebuild request: the provider URL to fetch and the
// knobs the rebuild applies to the result. A rebuild token carries it, so the
// JSON keys are part of that wire format.
type Spec struct {
	UpstreamURL string `json:"u"`
	ProxyTag    string `json:"p,omitempty"`
	AdsMode     string `json:"a,omitempty"`
	RouteMode   string `json:"r,omitempty"`
}

// Request is one fetch of a provider subscription: the target URL, the
// identity of the client the fetch is made for, and that client's headers. The
// field order follows the alignment rule the linter enforces, not the reading
// order.
type Request struct {
	Header http.Header
	// SessionID is the caller's stable per-token identity: the same value for
	// every fetch one rebuild link makes, distinct from one link to another.
	// It is never relayed to the provider itself — the identity that travels
	// is the one in Header — it only keeps the cache entry and the in-flight
	// sharing of one client apart from another's, so the first caller of a URL
	// cannot have its provider-side accounting attributed to every later one.
	// An empty SessionID shares with every other empty one.
	SessionID string
	URL       string
}

// Result is a provider subscription body with the metadata a caller needs to
// rewrite and serve it. Fields are ordered by alignment, the house rule for
// structs here, so the order is not the contract's reading order.
type Result struct {
	// ProfileHeaders carries the Happ management headers of the provider
	// response, as a fresh map per Result: a caller owns it and may add or
	// override headers (the routing deeplink, say) without touching the cache.
	ProfileHeaders http.Header
	// ContentType is the provider's content type, defaulted for the link-list
	// form when the provider sent none.
	ContentType string
	// Body is the subscription payload. It is the cache's own slice, shared
	// with every other caller of the same URL, so it must be treated as
	// read-only.
	Body []byte
	// Status is the status the body must be served with: 200. An upstream
	// failure is an error, never a Result, and a cached body is a 200 body.
	Status int
	// NotModified reports that Body came from the cache rather than from a
	// fresh provider response: a fresh cache hit, a 304 revalidation, or a
	// stale copy served while the provider was failing.
	NotModified bool
}

// Fetcher fetches provider subscriptions. Implementations are safe for
// concurrent use.
type Fetcher interface {
	// Fetch returns the subscription body for req, from the cache when it is
	// fresh and from the provider otherwise. An error means no body could be
	// produced at all; the error names codes and generic reasons, never the
	// target URL.
	Fetch(ctx context.Context, req Request) (Result, error)
}

// cacheEntry is one cached provider body with its validators. The body and the
// profile headers are owned by the entry; fetchedAt and etag are updated in
// place under the fetcher's mutex when a 304 refreshes the entry. Fields are
// ordered by alignment, as everywhere in this package.
type cacheEntry struct {
	fetchedAt   time.Time
	profile     http.Header
	contentType string
	etag        string
	body        []byte
}

// fetcher implements Fetcher over one cache and one HTTP client. The map's
// mutex is only ever held for map and entry bookkeeping, never across a
// request. slots is the fetch bound: a buffered channel whose capacity is how
// many upstream fetches may be in flight at once, and bytes is the body bytes
// the cache currently holds against budget. Fields are ordered by alignment,
// as everywhere in this package.
type fetcher struct {
	group     singleflight.Group
	cache     map[string]*cacheEntry
	hc        *http.Client
	logger    *slog.Logger
	now       func() time.Time
	lookup    lookupFunc
	slots     chan struct{}
	ttl       time.Duration
	mu        sync.Mutex
	budget    int
	bytes     int
	unguarded bool
}

// NewFetcher builds a Fetcher. A nil hc installs the hardened default client:
// it resolves and vets every address immediately before dialing it, ignores
// proxy environment variables (a proxy would answer for the target and move
// the dial outside the guard), follows at most maxRedirects hops with every
// hop re-vetted, and bounds one request with defaultTimeout.
//
// A caller-supplied client is used as a template rather than as-is: its
// transport is kept (a test double, say) with the guard installed over its
// dialer, and the redirect policy and the URL guard apply exactly as they do
// to the default client. A template whose transport cannot carry the guard —
// anything that is not an *http.Transport, one that dials TLS itself, or one
// that proxies — yields a fetcher whose every fetch fails with
// ErrUnguardedClient, because dropping the guard silently would be worse than
// failing. Such a client must bound its own requests; a shared in-flight fetch
// is bounded by defaultTimeout either way.
func NewFetcher(hc *http.Client, logger *slog.Logger) Fetcher {
	if logger == nil {
		logger = slog.Default()
	}
	f := &fetcher{
		cache:  make(map[string]*cacheEntry),
		logger: logger,
		now:    time.Now,
		lookup: lookupNetIP,
		slots:  make(chan struct{}, maxConcurrentFetches),
		ttl:    defaultCacheTTL,
		budget: maxCacheBytes,
	}
	if hc == nil {
		f.hc = newGuardedClient(f.resolve)
	} else {
		template := *hc
		f.hc = &template
		transport, err := guardedTransport(template.Transport, f.resolve)
		if err != nil {
			// Fail closed: an unguarded dial could reach an address the guard
			// refuses, so no fetch is made at all.
			f.logger.Error("upstream client cannot be guarded", "error", err)
			f.unguarded = true
		} else {
			f.hc.Transport = transport
		}
	}
	f.hc.CheckRedirect = f.checkRedirect
	return f
}

// resolve is the fetcher's resolution seam, read at call time: the pre-flight
// check and the guard under every dial both go through the field as it is
// now, so swapping the seam swaps both and no dial resolves on its own.
func (f *fetcher) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	return f.lookup(ctx, host)
}

// Fetch returns the subscription body for req, from the cache when it is fresh
// and from the provider otherwise. Concurrent fetches of the same key share
// one upstream request, at most maxConcurrentFetches of those requests are in
// flight across the fetcher, and a provider failure while a cached copy exists
// serves that copy rather than an error.
func (f *fetcher) Fetch(ctx context.Context, req Request) (Result, error) {
	if f.unguarded {
		return Result{}, ErrUnguardedClient
	}
	target, err := parseTarget(req.URL)
	if err != nil {
		return Result{}, err
	}
	key := cacheKey(target.String(), req.SessionID)
	if res, ok := f.fresh(key); ok {
		return res, nil
	}
	// The address check runs per fetch, not once per URL: the provider's DNS
	// can have been repointed at a private address since the last fetch.
	if err := checkAddresses(ctx, f.resolve, target.Hostname()); err != nil {
		return Result{}, err
	}

	out := f.group.DoChan(key, func() (any, error) {
		// The provider request outlives the caller that happened to lead the
		// flight: a client that disconnects mid-fetch must neither cancel the
		// shared request nor leave the cache cold for the callers waiting on
		// it. defaultTimeout is its only lifetime bound.
		callCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultTimeout)
		defer cancel()
		// The slot is taken here rather than in Fetch, and once per flight:
		// the waiting callers have joined this one upstream request, so
		// charging them slots of their own would let a crowd waiting on one
		// key occupy the fetcher and deadlock the flight they all need.
		if err := f.acquire(callCtx); err != nil {
			return nil, err
		}
		defer f.release()
		res, err := f.fetch(callCtx, target, key, req)
		return res, err
	})

	select {
	case <-ctx.Done():
		return Result{}, fmt.Errorf("upstream: fetch: %w", ctx.Err())
	case shared := <-out:
		if shared.Err != nil {
			return Result{}, shared.Err
		}
		res, ok := shared.Val.(Result)
		if !ok {
			// Unreachable: the flight above returns a Result.
			return Result{}, errors.New("upstream: fetch: unexpected result")
		}
		return res, nil
	}
}

// acquire takes one of the fetcher's fetch slots, waiting for a free one and
// reporting ctx being done instead. A caller whose deadline passes while it
// waits for a slot gives up rather than queueing behind the bound.
func (f *fetcher) acquire(ctx context.Context) error {
	select {
	case f.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("upstream: fetch slot: %w", ctx.Err())
	}
}

// release returns a slot taken by acquire. It is only ever called by a flight
// that took one.
func (f *fetcher) release() {
	<-f.slots
}

// fetch performs one upstream request and maintains the cache: a 200 replaces
// the cached copy of key, a 304 refreshes it, and anything else is treated as
// an upstream failure. The key is the cache identity of the request, which is
// the target URL for a caller without a session and the URL plus the session
// identity otherwise.
func (f *fetcher) fetch(ctx context.Context, target *url.URL, key string, req Request) (Result, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return Result{}, fmt.Errorf("upstream: request: %w", sanitizeErr(err))
	}
	relayHeaders(httpReq.Header, req.Header)
	if tag := f.etag(key); tag != "" {
		httpReq.Header.Set("If-None-Match", tag)
	}

	resp, err := f.hc.Do(httpReq)
	if err != nil {
		// The response Client.Do may return alongside an error is closed
		// already; the error is the outcome that matters.
		return f.fallback(ctx, key, fmt.Errorf("upstream: request failed: %w", sanitizeErr(err)))
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		body, err := readBody(resp.Body)
		if err != nil {
			return f.fallback(ctx, key, err)
		}
		entry := &cacheEntry{
			fetchedAt:   f.now(),
			body:        body,
			contentType: responseContentType(resp.Header),
			etag:        resp.Header.Get("ETag"),
			profile:     profileHeaders(resp.Header),
		}
		f.store(key, entry)
		return entry.result(false), nil
	case http.StatusNotModified:
		return f.revalidated(key, resp.Header.Get("ETag"))
	default:
		// Read a bounded amount of the refused body so the connection can be
		// reused, then treat the response as a failure.
		_, _ = io.CopyN(io.Discard, resp.Body, drainLimit)
		return f.fallback(ctx, key, fmt.Errorf("upstream: status %d", resp.StatusCode))
	}
}

// checkRedirect enforces the hop budget and re-vets every hop, so a permitted
// URL cannot reach a blocked address through a redirect, whether the hop stays
// on the provider's host or moves to another one.
func (f *fetcher) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > maxRedirects {
		return blockedTarget("too many redirects")
	}
	if err := checkShape(req.URL); err != nil {
		return err
	}
	return checkAddresses(req.Context(), f.lookup, req.URL.Hostname())
}

// fresh serves the cached copy of key while it is within the TTL, and reports
// that it did. A body still being fetched is not cached yet, so concurrent
// misses share the flight instead of reading a half-filled cache.
func (f *fetcher) fresh(key string) (Result, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	entry, ok := f.cache[key]
	if !ok || f.now().Sub(entry.fetchedAt) >= f.ttl {
		return Result{}, false
	}
	return entry.result(true), true
}

// etag returns the cached validator of key, empty when there is none: the
// conditional request asks the provider only for a body that changed.
func (f *fetcher) etag(key string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	entry, ok := f.cache[key]
	if !ok {
		return ""
	}
	return entry.etag
}

// store replaces the cached copy of key and drops the oldest entries until the
// cache is within its bounds again: the cache is a bounded working set, so
// eviction is by age rather than by access, and the bound that matters is on
// body bytes, because a provider dictates how large a body is. The entry count
// is bounded as well, for bodies too small for the byte budget to notice.
func (f *fetcher) store(key string, entry *cacheEntry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if previous, ok := f.cache[key]; ok {
		f.bytes -= len(previous.body)
	}
	f.cache[key] = entry
	f.bytes += len(entry.body)
	// The entry just stored is the newest, so eviction — oldest first — never
	// drops it while any other entry remains, and one body is always within
	// the byte budget: the read cap is far below it.
	for len(f.cache) > 1 && f.overLimitLocked() {
		f.evictOldestLocked()
	}
}

// overLimitLocked reports whether the cache holds more than it may: more body
// bytes than its budget, or more entries than its secondary bound. The caller
// holds the mutex.
func (f *fetcher) overLimitLocked() bool {
	return f.bytes > f.budget || len(f.cache) > maxCacheEntries
}

// evictOldestLocked drops the entry with the oldest fetch time and releases
// the body bytes it held. The caller holds the mutex and has established that
// the cache is not empty.
func (f *fetcher) evictOldestLocked() {
	var (
		oldestKey  string
		oldestTime time.Time
		first      = true
	)
	for key, entry := range f.cache {
		if first || entry.fetchedAt.Before(oldestTime) {
			oldestKey, oldestTime, first = key, entry.fetchedAt, false
		}
	}
	f.bytes -= len(f.cache[oldestKey].body)
	delete(f.cache, oldestKey)
}

// revalidated serves the cached copy after the provider answered 304: the copy
// is what the answer refers to, so it is refreshed, and its validator is
// replaced when the provider sent a new one. Without a cached copy there is
// nothing to serve: only a fetch that had a validator asks conditionally, so
// this is a provider answering 304 on its own.
func (f *fetcher) revalidated(key, etag string) (Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	entry, ok := f.cache[key]
	if !ok {
		return Result{}, errors.New("upstream: not modified without a cached copy")
	}
	entry.fetchedAt = f.now()
	if etag != "" {
		entry.etag = etag
	}
	return entry.result(true), nil
}

// fallback answers an upstream failure: the cached copy of key when one exists
// — however old, because a provider outage must not break a subscription that
// worked a minute ago — and the failure itself otherwise. Failures are never
// cached, so a recovered provider is picked up by the next fetch.
func (f *fetcher) fallback(ctx context.Context, key string, cause error) (Result, error) {
	f.mu.Lock()
	entry, ok := f.cache[key]
	var res Result
	if ok {
		res = entry.result(true)
	}
	f.mu.Unlock()
	if !ok {
		f.logger.ErrorContext(ctx, "upstream fetch failed", "error", cause)
		return Result{}, cause
	}
	f.logger.WarnContext(ctx, "upstream fetch failed, serving cached copy", "error", cause)
	return res, nil
}

// result renders the entry as the caller's Result. cached reports that the
// body came from the cache rather than from a fresh provider response.
func (e *cacheEntry) result(cached bool) Result {
	return Result{
		Body:           e.body,
		ContentType:    e.contentType,
		ProfileHeaders: e.headers(),
		Status:         http.StatusOK,
		NotModified:    cached,
	}
}

// headers returns the entry's profile headers as a caller-owned map: a Result
// carries headers a caller may write to, so the cached copy is never shared
// with it.
func (e *cacheEntry) headers() http.Header {
	out := make(http.Header, len(e.profile))
	for name, values := range e.profile {
		out[name] = slices.Clone(values)
	}
	return out
}

// dialContextFunc dials one address. It is the shape net.Dialer and
// *http.Transport both carry, and what the guard wraps: the guard dials
// through the dialer of the transport under it.
type dialContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// guardDialer resolves and vets every dial target immediately before it is
// connected to, and dials the vetted address rather than the name, so the
// address krot talks to is the one the guard approved: a check-then-dial on
// the name would leave a rebinding window between the two resolutions.
type guardDialer struct {
	dial   dialContextFunc
	lookup lookupFunc
}

// DialContext implements the dialing of the guarded transport: the name is
// resolved at dial time, every address is vetted, and only a vetted address
// reaches the wrapped dialer, so a caller-supplied transport carrying a dialer
// of its own cannot dial around the guard.
func (d *guardDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, errors.New("upstream: dial address is not host:port")
	}
	if port != httpsPort {
		return nil, blockedTarget("non-standard port")
	}
	addrs, err := d.lookup(ctx, host)
	if err != nil {
		return nil, blockedTarget("unresolvable host")
	}
	if err := checkAddrs(addrs); err != nil {
		return nil, err
	}
	var lastErr error
	for _, ip := range addrs {
		conn, err := d.dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	// checkAddrs rejects an empty result, so the loop ran and lastErr is set.
	return nil, lastErr
}

// guardedDial wraps a transport's dialer with the guard, so that whatever the
// transport dials goes through the guard first. A nil dialer means the
// transport carries none of its own, and the standard dialer is wrapped
// instead.
func guardedDial(dial dialContextFunc, lookup lookupFunc) dialContextFunc {
	guarded := &guardDialer{dial: dial, lookup: lookup}
	if guarded.dial == nil {
		guarded.dial = (&net.Dialer{Timeout: dialTimeout}).DialContext
	}
	return guarded.DialContext
}

// cacheKey is the identity of a cache entry and of a shared in-flight fetch:
// the target URL, and the caller's session identity when it has one, so that
// the entry one client warms is never served to another. The NUL separator
// cannot occur in a parsed URL, so a URL can never be mistaken for a pair.
func cacheKey(target, sessionID string) string {
	if sessionID == "" {
		return target
	}
	return target + "\x00" + sessionID
}

// parseTarget parses a target URL and applies the URL-level guard. The parse
// error of url.Parse quotes the URL, so it is replaced by the refusal.
func parseTarget(raw string) (*url.URL, error) {
	target, err := url.Parse(raw)
	if err != nil {
		return nil, blockedTarget("malformed URL")
	}
	if err := checkShape(target); err != nil {
		return nil, err
	}
	return target, nil
}

// checkShape applies the URL-level part of the guard: HTTPS only, no embedded
// credentials (they would be forwarded to whatever the URL points at), the
// standard port only, and a non-empty host.
func checkShape(target *url.URL) error {
	switch {
	case target.Scheme != "https":
		return blockedTarget("not https")
	case target.User != nil:
		return blockedTarget("credentials in URL")
	case target.Port() != "" && target.Port() != httpsPort:
		return blockedTarget("non-standard port")
	case target.Hostname() == "":
		return blockedTarget("empty host")
	}
	return nil
}

// checkAddresses resolves host and refuses the target when any resolved
// address lies outside the public internet. The guarded dialer repeats the
// check against the address it is about to connect to.
func checkAddresses(ctx context.Context, lookup lookupFunc, host string) error {
	addrs, err := lookup(ctx, host)
	if err != nil {
		// A resolution error names the host; it is dropped.
		return blockedTarget("unresolvable host")
	}
	return checkAddrs(addrs)
}

// checkAddrs refuses an empty resolution result and any result containing an
// address krot must never reach on a client's behalf.
func checkAddrs(addrs []netip.Addr) error {
	if len(addrs) == 0 {
		return blockedTarget("no addresses")
	}
	if slices.ContainsFunc(addrs, blockedAddr) {
		return blockedTarget("non-public address")
	}
	return nil
}

// blockedAddr reports whether addr belongs to a network krot must never reach
// on a client's behalf: loopback, RFC 1918 and RFC 4193 private ranges,
// link-local (which carries the cloud metadata addresses 169.254.169.254 and,
// through the ULA range, fd00:ec2::254), carrier-grade NAT, "this network",
// the reserved block that contains the limited broadcast address, multicast,
// the IPv6 transition ranges that embed an IPv4 address (6to4, Teredo, NAT64),
// and anything carrying a scope zone. Addresses are unmapped first, so
// ::ffff:127.0.0.1 is judged as the IPv4 loopback it is.
func blockedAddr(addr netip.Addr) bool {
	if addr.Zone() != "" {
		return true
	}
	ip := addr.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	return cgnatPrefix.Contains(ip) || thisNetworkPrefix.Contains(ip) || reservedPrefix.Contains(ip) ||
		slices.ContainsFunc(transitionPrefixes, func(prefix netip.Prefix) bool { return prefix.Contains(ip) })
}

// blockedTarget wraps a reason into the guard's refusal: the reason names what
// was wrong without naming the target.
func blockedTarget(reason string) error {
	return fmt.Errorf("%w: %s", ErrBlockedTarget, reason)
}

// lookupFunc resolves a hostname to the addresses a dial has to choose from.
// It is a seam for tests; production uses the process resolver.
type lookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

// lookupNetIP is the process resolver. IP literals resolve to themselves; a
// resolution failure returns a generic error, because the resolver's own error
// names the host.
func lookupNetIP(ctx context.Context, host string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr}, nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, errors.New("upstream: host does not resolve")
	}
	return addrs, nil
}

// relayHeaders copies the identification headers of the client request onto
// the provider request, so provider-side device accounting sees the device the
// fetch is made for.
func relayHeaders(dst, src http.Header) {
	for _, name := range relayHeaderNames {
		if value := src.Get(name); value != "" {
			dst.Set(name, value)
		}
	}
}

// readBody reads the response body up to maxResponseBytes, reporting a larger
// body as an error rather than truncating it: a truncated subscription would
// look like a valid one to the rewrite.
func readBody(body io.Reader) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("upstream: read body: %w", err)
	}
	if len(payload) > maxResponseBytes {
		return nil, errors.New("upstream: response too large")
	}
	return payload, nil
}

// responseContentType is the provider's content type, defaulted when the
// provider sent none: a subscription without one is the link-list form.
func responseContentType(header http.Header) string {
	if contentType := header.Get("Content-Type"); contentType != "" {
		return contentType
	}
	return defaultContentType
}

// profileHeaders extracts the Happ management headers of a provider response.
func profileHeaders(header http.Header) http.Header {
	out := make(http.Header, len(profileHeaderNames))
	for _, name := range profileHeaderNames {
		if values := header.Values(name); len(values) > 0 {
			out[name] = values
		}
	}
	return out
}

// newGuardedClient builds the fetcher's default client: the guarded standard
// transport and a request timeout.
func newGuardedClient(lookup lookupFunc) *http.Client {
	return &http.Client{Transport: newGuardedTransport(lookup), Timeout: defaultTimeout}
}

// newGuardedTransport clones the standard transport and installs the guard
// over its dialer, with proxying disabled: a proxy would answer for the target
// and move the dial outside the guard.
func newGuardedTransport(lookup lookupFunc) *http.Transport {
	transport := cloneDefaultTransport()
	transport.Proxy = nil
	transport.DialContext = guardedDial(nil, lookup)
	return transport
}

// guardedTransport returns the transport a fetcher built around a
// caller-supplied client dials through: a copy of the template's own transport
// — its settings and TLS configuration kept as they are — with the guard
// installed over its dialer, so a client cannot arrive carrying a dialer that
// skips the guard. A template the guard cannot be installed on is refused
// rather than dialed unguarded: a RoundTripper that is not an *http.Transport
// has no dialer to wrap, one that dials TLS itself would hand the guard a
// socket it never vetted, and one that proxies would have the guard vet the
// proxy rather than the target. A nil transport means the standard one, which
// the guarded clone matches; a template carrying only the deprecated Dial
// field is dialed through the guarded standard dialer, because net/http gives
// DialContext priority and the guard must be what dials.
func guardedTransport(transport http.RoundTripper, lookup lookupFunc) (*http.Transport, error) {
	template, ok := transport.(*http.Transport)
	if !ok {
		if transport == nil {
			return newGuardedTransport(lookup), nil
		}
		return nil, errors.New("transport is not an *http.Transport")
	}
	if template == nil {
		// A typed-nil transport would panic on use and means the same as none:
		// the standard transport, which the guarded clone matches.
		return newGuardedTransport(lookup), nil
	}
	//nolint:staticcheck // the deprecated DialTLS still bypasses DialContext, so the guard never dials
	if template.DialTLS != nil || template.DialTLSContext != nil {
		return nil, errors.New("transport carries a dialer the guard cannot wrap")
	}
	if template.Proxy != nil {
		return nil, errors.New("transport proxies the dial")
	}
	guarded := template.Clone()
	guarded.DialContext = guardedDial(template.DialContext, lookup)
	return guarded, nil
}

// cloneDefaultTransport copies the standard transport's settings so the
// guarded dialer can be installed without mutating the shared instance.
func cloneDefaultTransport() *http.Transport {
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		return base.Clone()
	}
	return &http.Transport{}
}

// sanitizeErr strips the request URL from a transport error. net/http wraps
// every failure in a *url.Error whose message quotes the whole URL — provider
// secrets in the query string included — while the wrapped cause carries what
// actually went wrong. A cause that quotes a URL anyway (a redirect Location
// net/http could not parse, say) is replaced wholesale, so no URL ever reaches
// an error message or a log line.
func sanitizeErr(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) && uerr.Err != nil {
		err = uerr.Err
	}
	if strings.Contains(err.Error(), "://") {
		return errors.New("malformed upstream response")
	}
	return err
}
