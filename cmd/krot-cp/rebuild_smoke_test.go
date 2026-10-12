package main

// End-to-end smoke of the subscription re-builder wiring: the /rebuild form
// posts through the control plane's own handler chain and returns a link
// whose /rbr endpoint serves the rewritten subscription.
//
// The transport half is deliberately stubbed at the upstream.Fetcher seam:
// the fetcher's SSRF guard rejects loopback by design, so a live upstream
// cannot be served from a test binary. Everything on the control-plane side
// of the seam is the real code — the web handlers, the sealed token, the
// rebuild handler, the rewriter — and the fetcher replacement only stands in
// for the network.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/Arsolitt/krot/internal/model"
	"github.com/Arsolitt/krot/internal/rebuild"
	"github.com/Arsolitt/krot/internal/render"
	"github.com/Arsolitt/krot/internal/sub"
	"github.com/Arsolitt/krot/internal/upstream"
	"github.com/Arsolitt/krot/internal/web"
)

// fakeUsers satisfies sub.UserSource without a database: the rebuild
// endpoints never consult it, but the sub.Server constructor requires one.
type fakeUsers struct{}

func (fakeUsers) ActiveUsers(context.Context) ([]model.User, error) { return nil, nil }

func (fakeUsers) EnabledServersWithInbounds(context.Context) ([]model.ServerInbounds, error) {
	return nil, nil
}

// fakeAuthz allows every subject; the rebuild endpoints do not check it.
type fakeAuthz struct{}

func (fakeAuthz) Allowed(context.Context, string) (bool, error) { return true, nil }

// recordingFetcher stands in for the network half of the fetcher and records
// the request it was handed, so the test can assert the relay of the client
// identification headers end to end. Fields are ordered by alignment, the
// house rule for structs here.
type recordingFetcher struct {
	req  upstream.Request
	body []byte
}

func (f *recordingFetcher) Fetch(_ context.Context, req upstream.Request) (upstream.Result, error) {
	f.req = req
	// The content type is deliberately text/html: the rebuild must classify
	// the served type from the payload, never relay a provider value that a
	// browser on the control-plane origin would act on.
	return upstream.Result{
		Status:      http.StatusOK,
		ContentType: "text/html; charset=utf-8",
		Body:        f.body,
	}, nil
}

// rebuildSmoke assembles the control-plane side of the feature exactly as
// main does: the real web handlers over Deps with the buildRebuild closure,
// the real sub.RebuildHandler, and the real routing profile.
func rebuildSmoke(t *testing.T, fetcher upstream.Fetcher) (http.Handler, string) {
	t.Helper()

	key := []byte("0123456789abcdef0123456789abcdef")
	profileJSON, err := render.HappRoutingProfileJSON("Rebuild Smoke")
	if err != nil {
		t.Fatalf("profile json: %v", err)
	}
	logger := slog.New(slog.DiscardHandler)

	const secret = "sesame"
	subs := sub.New(key, sub.DefaultTokenNamespace, sub.Profile{
		BaseURL:             "https://vpn.example.test",
		Title:               "Krot VPN",
		UpdateIntervalHours: 24,
	}, fakeUsers{}, fakeAuthz{}, logger)

	pages := &web.Deps{
		BaseURL:            "https://vpn.example.test",
		ProfileTitle:       "Krot VPN",
		RoutingProfileJSON: profileJSON,
		RebuildCreate:      buildRebuild(key, secret),
		RebuildSecretSet:   true,
		Logger:             logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /rebuild", pages.RebuildPage)
	mux.HandleFunc("POST /rebuild", pages.RebuildCreateHandler)
	mux.Handle("GET /rbr/{token}", subs.RebuildHandler(key, fetcher, profileJSON, logger))
	return mux, secret
}

// providerJSON is a two-outbound Xray config shaped like a provider
// subscription: a direct outbound and the proxy the rebuild must map to.
func providerJSON() []byte {
	return []byte(`{
		"log": {"loglevel": "warning"},
		"inbounds": [{"port": 10808, "protocol": "socks", "tag": "socks"}],
		"outbounds": [
			{"protocol": "freedom", "tag": "direct"},
			{"protocol": "vless", "tag": "proxy", "settings": {}}
		],
		"routing": {"domainStrategy": "AsIs", "rules": [{"type": "field", "domain": ["ext:geo:fake"], "outboundTag": "proxy"}]}
	}`)
}

// TestRebuildSmokeEndToEnd drives the whole feature over real HTTP: POST the
// provider URL to /rebuild, follow the returned link, and inspect the served
// subscription and the relayed identification headers.
func TestRebuildSmokeEndToEnd(t *testing.T) {
	fetcher := &recordingFetcher{body: providerJSON()}
	mux, secret := rebuildSmoke(t, fetcher)

	form := url.Values{
		"upstream_url": {"https://provider.example.test/sub?token=secret"},
		"proxy_tag":    {"proxy"},
		"ads_mode":     {"light"},
		"secret":       {secret},
	}
	post := httptest.NewRequest(http.MethodPost, "/rebuild", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postRec := httptest.NewRecorder()
	mux.ServeHTTP(postRec, post)
	if postRec.Code != http.StatusOK {
		t.Fatalf("POST /rebuild = %d, want 200; body: %s", postRec.Code, postRec.Body.String())
	}

	linkRe := regexp.MustCompile(`https://vpn\.example\.test/rbr/rbr_[A-Za-z0-9_-]+`)
	link := linkRe.FindString(postRec.Body.String())
	if link == "" {
		t.Fatalf("no /rbr link in the form response: %s", postRec.Body.String())
	}

	// The provider URL must not leak into the rendered page: the link is the
	// only capability.
	if strings.Contains(postRec.Body.String(), "token=secret") {
		t.Fatal("provider URL leaked into the rebuild page")
	}

	rbrPath := strings.TrimPrefix(link, "https://vpn.example.test")
	get := httptest.NewRequest(http.MethodGet, rbrPath, nil)
	get.Header.Set("User-Agent", "Happ/5.2.0")
	get.Header.Set("X-Hwid", "device-1")
	get.Header.Set("X-Ver-Os", "iOS")
	getRec := httptest.NewRecorder()
	mux.ServeHTTP(getRec, get)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200; body: %s", rbrPath, getRec.Code, getRec.Body.String())
	}

	// Identification headers must have reached the fetcher untouched.
	if got := fetcher.req.Header.Get("User-Agent"); got != "Happ/5.2.0" {
		t.Errorf("relayed User-Agent = %q, want Happ/5.2.0", got)
	}
	if got := fetcher.req.Header.Get("X-Hwid"); got != "device-1" {
		t.Errorf("relayed X-Hwid = %q, want device-1", got)
	}
	if got := fetcher.req.URL; got != "https://provider.example.test/sub?token=secret" {
		t.Errorf("fetcher URL = %q, want the sealed provider URL", got)
	}

	// The baked document must carry the krot routing rules and DNS, and must
	// keep the provider's outbounds and its proxy tag addressable.
	var baked struct {
		Outbounds []struct {
			Tag string `json:"tag"`
		} `json:"outbounds"`
		DNS     map[string]any `json:"dns"`
		Routing struct {
			Rules []struct {
				OutboundTag string   `json:"outboundTag"`
				Domain      []string `json:"domain"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &baked); err != nil {
		t.Fatalf("served body is not JSON: %v", err)
	}
	if len(baked.Outbounds) != 2 {
		t.Errorf("provider outbounds = %d, want 2 (kept verbatim)", len(baked.Outbounds))
	}
	if baked.DNS == nil {
		t.Error("baked document carries no dns block")
	}
	var proxyRule bool
	for _, rule := range baked.Routing.Rules {
		if rule.OutboundTag == "proxy" {
			proxyRule = true
		}
	}
	if !proxyRule {
		t.Errorf("no routing rule targets the provider proxy tag; rules: %+v", baked.Routing.Rules)
	}

	if ct := getRec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want the classified JSON type", ct)
	}
	if got := getRec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
}

// TestRebuildSmokeLinkList covers the other upstream shape: a base64 link
// list must come back with the routing deeplink prepended and advertised.
func TestRebuildSmokeLinkList(t *testing.T) {
	link := "vless://11111111-2222-3333-4444-555555555555@example.test:443?encryption=none#test"
	fetcher := &recordingFetcher{body: []byte(link + "\n")}
	mux, secret := rebuildSmoke(t, fetcher)

	form := url.Values{
		"upstream_url": {"https://provider.example.test/sub?token=secret"},
		"secret":       {secret},
	}
	post := httptest.NewRequest(http.MethodPost, "/rebuild", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postRec := httptest.NewRecorder()
	mux.ServeHTTP(postRec, post)
	if postRec.Code != http.StatusOK {
		t.Fatalf("POST /rebuild = %d, want 200", postRec.Code)
	}
	linkRe := regexp.MustCompile(`/rbr/rbr_[A-Za-z0-9_-]+`)
	rbrPath := linkRe.FindString(postRec.Body.String())
	if rbrPath == "" {
		t.Fatalf("no /rbr link in the form response: %s", postRec.Body.String())
	}

	get := httptest.NewRequest(http.MethodGet, rbrPath, nil)
	getRec := httptest.NewRecorder()
	mux.ServeHTTP(getRec, get)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200; body: %s", rbrPath, getRec.Code, getRec.Body.String())
	}
	body := getRec.Body.String()
	if !strings.Contains(body, "happ://routing/onadd/") {
		t.Errorf("link list response carries no routing deeplink: %s", body)
	}
	if !strings.Contains(body, link) {
		t.Errorf("link list response lost the provider link: %s", body)
	}
	// Header.Get canonicalizes the lookup, so the canonical spelling reads the
	// lowercase Happ header the handler set just the same.
	routingHeader := getRec.Header().Get("Routing")
	if !strings.HasPrefix(routingHeader, "happ://routing/onadd/") {
		t.Errorf("routing header = %q, want the onadd deeplink", routingHeader)
	}
	if ct := getRec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q, want the classified text type", ct)
	}
	if got := getRec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
}

// TestRebuildSmokeSecretGate covers the generator gate: a wrong secret must
// yield no token, and a tampered token must yield no fetch.
func TestRebuildSmokeSecretGate(t *testing.T) {
	fetcher := &recordingFetcher{body: providerJSON()}
	mux, _ := rebuildSmoke(t, fetcher)

	form := url.Values{
		"upstream_url": {"https://provider.example.test/sub?token=secret"},
		"secret":       {"wrong"},
	}
	post := httptest.NewRequest(http.MethodPost, "/rebuild", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postRec := httptest.NewRecorder()
	mux.ServeHTTP(postRec, post)
	if postRec.Code != http.StatusBadRequest {
		t.Fatalf("POST /rebuild with the wrong secret = %d, want 400", postRec.Code)
	}
	if strings.Contains(postRec.Body.String(), "/rbr/rbr_") {
		t.Fatal("wrong secret still produced a capability link")
	}

	get := httptest.NewRequest(http.MethodGet, "/rbr/rbr_deadbeef", nil)
	getRec := httptest.NewRecorder()
	mux.ServeHTTP(getRec, get)
	if getRec.Code != http.StatusNotFound {
		t.Fatalf("GET tampered token = %d, want 404", getRec.Code)
	}
}

// TestRebuildSmokeTokenRoundTrip guards the seal/open pair at the wiring
// level: the closure the control plane installs must produce a token the
// handler opens, whatever the key derivation does.
func TestRebuildSmokeTokenRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	build := buildRebuild(key, "")
	token, err := build(context.Background(), nil, "https://provider.example.test/sub", "proxy", "light", "")
	if err != nil {
		t.Fatalf("buildRebuild: %v", err)
	}
	spec, err := rebuild.Open(key, token)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if spec.UpstreamURL != "https://provider.example.test/sub" || spec.ProxyTag != "proxy" || spec.AdsMode != "light" {
		t.Fatalf("spec round trip = %+v", spec)
	}
	if sid := rebuild.SessionID(key, token); len(sid) != 22 {
		t.Fatalf("session id = %q, want 22 chars", sid)
	}
}

// TestRebuildSmokeKeyDerivation covers the configuration paths of the rebuild
// key: unset derives a stable key from the token key, set is decoded as
// unpadded base64, and a malformed value is an error.
func TestRebuildSmokeKeyDerivation(t *testing.T) {
	tokenKey := []byte("0123456789abcdef0123456789abcdef")

	t.Setenv("KROT_REBUILD_KEY", "")
	derived, err := decodeRebuildKey(tokenKey)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(derived) != keyLen {
		t.Fatalf("derived key = %d bytes, want %d", len(derived), keyLen)
	}
	again, err := decodeRebuildKey(tokenKey)
	if err != nil || string(again) != string(derived) {
		t.Fatalf("derivation is not stable: %v", err)
	}
	if string(derived) == string(tokenKey) {
		t.Fatal("derived key equals the token key")
	}

	explicit := base64.RawStdEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxyz012345"))
	t.Setenv("KROT_REBUILD_KEY", explicit)
	got, err := decodeRebuildKey(tokenKey)
	if err != nil {
		t.Fatalf("explicit key: %v", err)
	}
	if string(got) != "abcdefghijklmnopqrstuvwxyz012345" {
		t.Fatalf("explicit key round trip = %q", got)
	}

	t.Setenv("KROT_REBUILD_KEY", "not-base64!!")
	if _, err := decodeRebuildKey(tokenKey); err == nil {
		t.Fatal("malformed key accepted")
	}
}

// TestRebuildSmokeSecretGateLocked exercises the build closure directly with
// the gate on: the wrong secret and no secret both fail, the right one seals.
// The comparison is over SHA-256 digests, so submissions of any length —
// empty, shorter, longer — are rejected without the secret's length ever
// mattering.
func TestRebuildSmokeSecretGateLocked(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	build := buildRebuild(key, "sesame")

	for _, wrong := range []string{"wrong", "", "sesam", "sesame ", strings.Repeat("x", 4096)} {
		if _, err := build(context.Background(), nil, "https://p.example.test/s", "", "", wrong); err == nil {
			t.Fatalf("secret %q accepted", wrong)
		}
	}
	token, err := build(context.Background(), nil, "https://p.example.test/s", "", "", "sesame")
	if err != nil {
		t.Fatalf("right secret rejected: %v", err)
	}
	if _, err := rebuild.Open(key, token); err != nil {
		t.Fatalf("sealed token does not open: %v", err)
	}
}
