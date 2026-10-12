package rebuild

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"

	up "github.com/Arsolitt/krot/internal/upstream"
)

// rewriteTestKey is a fixed key for the rewrite credential plumbing; the
// rewriter itself never reads it.
var rewriteTestKey = []byte("0123456789abcdef0123456789abcdef")

const (
	// testSessionID is the session id the standard fixture relays upstream.
	testSessionID = "session-abcdefghijklmnopqrst"
	// testUpstreamURL carries a secret-shaped path segment so tests can prove
	// it never leaks into an error.
	testUpstreamURL = "https://provider.example/sub/secret-token"
	// testProviderRule is the provider routing rule that must survive a
	// prepend and vanish under replace.
	testProviderRule = "geosite:provider-custom"
)

// testProfileJSON is a trimmed copy of the krot routing profile
// internal/render emits, carrying the fields the rewriter reads.
const testProfileJSON = `{
	"Name": "Krot VPN",
	"GlobalProxy": "true",
	"DomainStrategy": "IPIfNonMatch",
	"RemoteDNSType": "DoH",
	"RemoteDNSDomain": "https://dns.google/dns-query",
	"RemoteDNSIP": "8.8.8.8",
	"DomesticDNSType": "DoU",
	"DomesticDNSIP": "77.88.8.8",
	"DnsHosts": {"dns.google": "8.8.8.8"},
	"DirectSites": ["geosite:private", "geosite:category-ru"],
	"DirectIp": ["geoip:private", "geoip:ru"],
	"ProxySites": ["geosite:youtube"],
	"ProxyIp": [],
	"BlockSites": ["geosite:category-ads-all"],
	"BlockIp": []
}`

// testXrayConfig is a provider Xray config: the direct/block/proxy outbound
// trio plus one provider routing rule.
const testXrayConfig = `{
	"remarks": "provider",
	"dns": {"servers": ["1.1.1.1"]},
	"outbounds": [
		{"tag": "direct", "protocol": "freedom"},
		{"tag": "proxy", "protocol": "vless"},
		{"tag": "block", "protocol": "blackhole"}
	],
	"routing": {
		"rules": [
			{"type": "field", "outboundTag": "proxy", "domain": ["geosite:provider-custom"]}
		]
	}
}`

// testLinks is the minimal provider link list the standard fixture serves.
const testLinks = "vless://11111111-1111-1111-1111-111111111111@edge.example.com:443\nvmess://payload\n"

// fakeFetcher serves a canned upstream result and records the request it saw.
type fakeFetcher struct {
	req    up.Request
	err    error
	result up.Result
}

func (f *fakeFetcher) Fetch(_ context.Context, req up.Request) (up.Result, error) {
	f.req = req
	return f.result, f.err
}

// okResult wraps a body in the upstream result shape the tests rewrite,
// management headers and an upstream routing header included. The upstream
// content type is deliberately text/html: the rebuild must classify the
// served type from the payload and never relay this value to a browser on the
// control-plane origin.
func okResult(body string) up.Result {
	return up.Result{
		Status:      http.StatusOK,
		ContentType: "text/html; charset=utf-8",
		Body:        []byte(body),
		ProfileHeaders: http.Header{
			"Subscription-Userinfo":   {"upload=1; download=2; total=3; expire=4"},
			"Profile-Title":           {"Provider Plan"},
			"Profile-Update-Interval": {"12"},
			"Support-Url":             {"https://support.example.com"},
			"Routing":                 {"happ://routing/onadd/cHJvdmlkZXI="},
		},
	}
}

// rewriteOnce runs the rewriter over the standard fixtures and a canned
// upstream body.
func rewriteOnce(t *testing.T, body, hint, adsMode, routeMode string) (up.Result, error) {
	t.Helper()
	f := &fakeFetcher{result: okResult(body)}
	return Rewrite(
		context.Background(),
		f,
		rewriteTestKey,
		testSessionID,
		up.Request{URL: testUpstreamURL, Header: http.Header{"User-Agent": {"Happ/1.0"}}},
		[]byte(testProfileJSON),
		hint, adsMode, routeMode,
		slog.New(slog.DiscardHandler),
	)
}

// runRewrite rewrites a body with the default modes and fails on error.
func runRewrite(t *testing.T, body string) up.Result {
	t.Helper()
	out, err := rewriteOnce(t, body, "", "", "")
	if err != nil {
		t.Fatalf("Rewrite: %v", err)
	}
	return out
}

// rewriteError runs the rewriter and fails the test when it succeeds.
func rewriteError(t *testing.T, body, hint, adsMode, routeMode string) error {
	t.Helper()
	out, err := rewriteOnce(t, body, hint, adsMode, routeMode)
	if err == nil {
		t.Fatalf("Rewrite succeeded, rebuilt body:\n%s", out.Body)
	}
	return err
}

// decodeObject unmarshals a rebuilt JSON object body.
func decodeObject(t *testing.T, body []byte) map[string]any {
	t.Helper()
	doc := map[string]any{}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("rebuilt body is not a JSON object (%v):\n%s", err, body)
	}
	return doc
}

// decodeArray unmarshals a rebuilt JSON array body.
func decodeArray(t *testing.T, body []byte) []any {
	t.Helper()
	var docs []any
	if err := json.Unmarshal(body, &docs); err != nil {
		t.Fatalf("rebuilt body is not a JSON array (%v):\n%s", err, body)
	}
	return docs
}

// routingRules extracts the routing rules of a rebuilt config document.
func routingRules(t *testing.T, doc map[string]any) []any {
	t.Helper()
	routing, ok := doc[jsonRouting].(map[string]any)
	if !ok {
		t.Fatalf("rebuilt config has no routing object: %v", doc)
	}
	rules, ok := routing[jsonRules].([]any)
	if !ok || len(rules) == 0 {
		t.Fatalf("rebuilt config has no routing rules: %v", routing)
	}
	return rules
}

// ruleSends reports whether some rule routes the given domain/ip value to the
// outbound tag.
func ruleSends(rules []any, field, value, tag string) bool {
	for _, rule := range rules {
		fields, ok := rule.(map[string]any)
		if !ok || fields[jsonOutboundTag] != tag {
			continue
		}
		values, _ := fields[field].([]any)
		if slices.Contains(values, any(value)) {
			return true
		}
	}
	return false
}

// ruleIndex is the position of the first rule mentioning the domain value, or
// -1.
func ruleIndex(rules []any, value string) int {
	for i, rule := range rules {
		fields, _ := rule.(map[string]any)
		domains, _ := fields[jsonDomain].([]any)
		if slices.Contains(domains, any(value)) {
			return i
		}
	}
	return -1
}

// catchAll reports whether a rule matches everything to the outbound tag.
func catchAll(rule any, tag string) bool {
	fields, ok := rule.(map[string]any)
	if !ok || fields[jsonOutboundTag] != tag {
		return false
	}
	return fields[jsonDomain] == nil && fields[jsonIP] == nil
}

// dnsAddresses lists the address entries of a rebuilt DNS block.
func dnsAddresses(t *testing.T, doc map[string]any) []string {
	t.Helper()
	dns, ok := doc[jsonDNS].(map[string]any)
	if !ok {
		t.Fatalf("rebuilt config has no DNS block: %v", doc)
	}
	servers, _ := dns[jsonServers].([]any)
	addresses := make([]string, 0, len(servers))
	for _, server := range servers {
		if entry, ok := server.(map[string]any); ok {
			if address, ok := entry[jsonAddress].(string); ok {
				addresses = append(addresses, address)
			}
			continue
		}
		if address, ok := server.(string); ok {
			addresses = append(addresses, address)
		}
	}
	return addresses
}

// routingProfile decodes the profile embedded in a routing deeplink.
func routingProfile(t *testing.T, deeplink string) map[string]any {
	t.Helper()
	encoded := strings.TrimPrefix(deeplink, happRoutingPrefix)
	payload, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("routing deeplink payload is not base64: %v", err)
	}
	doc := map[string]any{}
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatalf("routing deeplink payload is not a JSON object: %v", err)
	}
	return doc
}

// profileSites reads a string array field of an embedded routing profile.
func profileSites(t *testing.T, profile map[string]any, key string) []string {
	t.Helper()
	values, ok := profile[key].([]any)
	if !ok {
		t.Fatalf("embedded profile has no %s list: %v", key, profile)
	}
	sites := make([]string, 0, len(values))
	for _, value := range values {
		if site, ok := value.(string); ok {
			sites = append(sites, site)
		}
	}
	return sites
}

func TestRewriteBakesXrayConfig(t *testing.T) {
	out, err := rewriteOnce(t, testXrayConfig, "", "", routeModeReplace)
	if err != nil {
		t.Fatalf("Rewrite: %v", err)
	}
	if out.Status != http.StatusOK {
		t.Errorf("status = %d, want %d", out.Status, http.StatusOK)
	}
	if out.ContentType != contentTypeJSON {
		t.Errorf("content-type = %q, want the classified JSON type %q", out.ContentType, contentTypeJSON)
	}
	if vals := out.ProfileHeaders.Values(headerRouting); len(vals) != 0 {
		t.Errorf("routing header = %q, want none for a baked config", vals)
	}

	doc := decodeObject(t, out.Body)
	if doc["remarks"] != "provider" {
		t.Errorf("provider fields not preserved: %v", doc)
	}
	rules := routingRules(t, doc)

	// Every profile category family lands on the matching provider outbound.
	if !ruleSends(rules, jsonDomain, "geosite:youtube", "proxy") {
		t.Errorf("proxy sites not routed to proxy: %v", rules)
	}
	if !ruleSends(rules, jsonDomain, "geosite:private", "direct") ||
		!ruleSends(rules, jsonIP, "geoip:ru", "direct") {
		t.Errorf("direct sites/ips not routed to direct: %v", rules)
	}
	if !ruleSends(rules, jsonDomain, "geosite:category-ads", "block") {
		t.Errorf("light ads not blocked: %v", rules)
	}

	// Replace mode drops the provider rule and closes with a catch-all.
	if ruleIndex(rules, testProviderRule) >= 0 {
		t.Errorf("replace mode kept the provider rule: %v", rules)
	}
	if !catchAll(rules[len(rules)-1], "proxy") {
		t.Errorf("replace mode did not end with a proxy catch-all: %v", rules)
	}

	// The krot DNS block replaces the provider's.
	addresses := dnsAddresses(t, doc)
	for _, want := range []string{"https://dns.google/dns-query", "77.88.8.8", "8.8.8.8"} {
		if !slices.Contains(addresses, want) {
			t.Errorf("DNS addresses %v missing %q", addresses, want)
		}
	}
	if slices.Contains(addresses, "1.1.1.1") {
		t.Errorf("provider DNS survived: %v", addresses)
	}
	routing, _ := doc[jsonRouting].(map[string]any)
	if routing[jsonDomainStrategy] != "IPIfNonMatch" {
		t.Errorf("domain strategy = %v, want IPIfNonMatch", routing[jsonDomainStrategy])
	}
}

// TestRewriteClassifiesContentType pins the XSS fix at the rewriter: the
// served content type comes from the payload classification, never from the
// provider. The fixture upstream sends text/html, which must not surface on
// the control-plane origin.
func TestRewriteClassifiesContentType(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"json config", testXrayConfig, contentTypeJSON},
		{"link list", testLinks, contentTypePlain},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := runRewrite(t, tc.body)
			if out.ContentType != tc.want {
				t.Errorf("content-type = %q, want the classified %q", out.ContentType, tc.want)
			}
		})
	}
}

func TestRewritePrependsKrotRules(t *testing.T) {
	out := runRewrite(t, testXrayConfig)
	rules := routingRules(t, decodeObject(t, out.Body))

	if !ruleSends(rules, jsonDomain, testProviderRule, "proxy") {
		t.Fatalf("provider rule did not survive the prepend: %v", rules)
	}
	krot, provider := ruleIndex(rules, "geosite:youtube"), ruleIndex(rules, testProviderRule)
	if krot < 0 || krot > provider {
		t.Errorf("krot rules (%d) must precede the provider rule (%d): %v", krot, provider, rules)
	}
	// The provider rule still supplies the default route, so no catch-all.
	if catchAll(rules[len(rules)-1], "proxy") {
		t.Errorf("catch-all appended although provider rules exist: %v", rules)
	}
}

func TestRewriteBakesConfigArray(t *testing.T) {
	second := `{
		"outbounds": [
			{"tag": "edge", "protocol": "trojan"},
			{"tag": "direct", "protocol": "freedom"}
		]
	}`
	out := runRewrite(t, "["+testXrayConfig+","+second+"]")

	docs := decodeArray(t, out.Body)
	if len(docs) != 2 {
		t.Fatalf("rebuilt array has %d configs, want 2", len(docs))
	}
	first, ok := docs[0].(map[string]any)
	if !ok {
		t.Fatalf("first config is not an object: %T", docs[0])
	}
	if !ruleSends(routingRules(t, first), jsonDomain, "geosite:youtube", "proxy") {
		t.Errorf("first config not baked: %v", first)
	}
	secondDoc, ok := docs[1].(map[string]any)
	if !ok {
		t.Fatalf("second config is not an object: %T", docs[1])
	}
	// The second config resolves its own tag and closes with its own
	// catch-all, since it carries no provider rules to fall back on.
	secondRules := routingRules(t, secondDoc)
	if !ruleSends(secondRules, jsonDomain, "geosite:youtube", "edge") {
		t.Errorf("second config not mapped onto its own tag: %v", secondRules)
	}
	if !catchAll(secondRules[len(secondRules)-1], "edge") {
		t.Errorf("second config has no catch-all: %v", secondRules)
	}
}

func TestRewriteProxyTagSelection(t *testing.T) {
	selectorConfig := `{
		"outbounds": [
			{"tag": "auto", "protocol": "selector"},
			{"tag": "edge", "protocol": "vless"},
			{"tag": "direct", "protocol": "freedom"}
		]
	}`
	hintedConfig := `{
		"outbounds": [
			{"tag": "proxy-a", "protocol": "vless"},
			{"tag": "proxy-b", "protocol": "trojan"},
			{"tag": "direct", "protocol": "freedom"}
		]
	}`
	cases := []struct {
		name string
		body string
		hint string
		want string
	}{
		{"auto-detect skips direct and block", testXrayConfig, "", "proxy"},
		{"auto-detect skips selector aggregates", selectorConfig, "", "edge"},
		{"hint wins over auto-detection", hintedConfig, "proxy-b", "proxy-b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := rewriteOnce(t, tc.body, tc.hint, "", "")
			if err != nil {
				t.Fatalf("Rewrite: %v", err)
			}
			rules := routingRules(t, decodeObject(t, out.Body))
			if !ruleSends(rules, jsonDomain, "geosite:youtube", tc.want) {
				t.Errorf("proxy sites not routed to %q: %v", tc.want, rules)
			}
		})
	}
}

func TestRewriteUnresolvableProxyTag(t *testing.T) {
	cases := []struct {
		name string
		body string
		hint string
		want []string
	}{
		{
			name: "only plumbing outbounds",
			body: `{"outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}]}`,
			want: []string{"direct", "block"},
		},
		{
			name: "hint not in the config",
			body: testXrayConfig,
			hint: "ghost",
			want: []string{"ghost", "direct", "proxy", "block"},
		},
		{
			name: "no outbounds at all",
			body: `{"remarks":"nothing"}`,
			want: []string{"no outbound tags"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := rewriteError(t, tc.body, tc.hint, "", "")
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not name %q", err, want)
				}
			}
			if strings.Contains(err.Error(), "secret-token") {
				t.Errorf("error leaks the upstream URL: %v", err)
			}
		})
	}
}

func TestRewriteLinkList(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(testLinks))
	cases := []struct {
		name string
		body string
	}{
		{"plain link list", testLinks},
		{"base64 link list", encoded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := runRewrite(t, tc.body)
			lines := strings.Split(strings.TrimSuffix(string(out.Body), "\n"), "\n")
			provider := strings.Split(strings.TrimSuffix(testLinks, "\n"), "\n")
			if len(lines) != len(provider)+1 {
				t.Fatalf("rebuilt body has %d lines, want %d:\n%s", len(lines), len(provider)+1, out.Body)
			}
			if !strings.HasPrefix(lines[0], happRoutingPrefix) {
				t.Fatalf("first line = %q, want a routing deeplink", lines[0])
			}
			if got := out.ProfileHeaders.Get(headerRouting); got != lines[0] {
				t.Errorf("routing header = %q, want %q", got, lines[0])
			}
			for i, link := range provider {
				if lines[i+1] != link {
					t.Errorf("link %d = %q, want %q", i, lines[i+1], link)
				}
			}
		})
	}
}

func TestRewriteAdsModes(t *testing.T) {
	cases := []struct {
		name string
		mode string
		want string
	}{
		{"default is light", "", "geosite:category-ads"},
		{"light", "light", "geosite:category-ads"},
		{"full", "full", "geosite:category-ads-all"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := rewriteOnce(t, testLinks, "", tc.mode, "")
			if err != nil {
				t.Fatalf("Rewrite: %v", err)
			}
			deeplink := out.ProfileHeaders.Get(headerRouting)
			profile := routingProfile(t, deeplink)
			sites := profileSites(t, profile, jsonBlockSites)
			if len(sites) != 1 || sites[0] != tc.want {
				t.Errorf("BlockSites = %v, want [%s]", sites, tc.want)
			}
			if profile["Name"] != "Krot VPN" {
				t.Errorf("profile fields not preserved: %v", profile)
			}
		})
	}

	// The baked JSON path carries the same choice in its block rule.
	out, err := rewriteOnce(t, testXrayConfig, "", "full", routeModeReplace)
	if err != nil {
		t.Fatalf("Rewrite: %v", err)
	}
	rules := routingRules(t, decodeObject(t, out.Body))
	if !ruleSends(rules, jsonDomain, "geosite:category-ads-all", "block") {
		t.Errorf("full ads not blocked in a baked config: %v", rules)
	}
}

func TestRewriteRelaysManagementHeaders(t *testing.T) {
	out := runRewrite(t, testLinks)
	for name, want := range map[string]string{
		"Subscription-Userinfo":   "upload=1; download=2; total=3; expire=4",
		"Profile-Title":           "Provider Plan",
		"Profile-Update-Interval": "12",
		"Support-Url":             "https://support.example.com",
	} {
		if got := out.ProfileHeaders.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if got := out.ProfileHeaders.Get(headerRouting); got == "happ://routing/onadd/cHJvdmlkZXI=" {
		t.Errorf("provider routing header was relayed: %q", got)
	}
}

// sessionCacheID is the cache discriminator the rewriter must derive from a
// session id: the hex SHA-256, computed here independently of the helper under
// test.
func sessionCacheID(t *testing.T, sessionID string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(sessionID))
	return hex.EncodeToString(sum[:])
}

func TestRewriteSessionIdentity(t *testing.T) {
	t.Run("client identity is preserved", func(t *testing.T) {
		f := &fakeFetcher{result: okResult(testLinks)}
		_, err := Rewrite(
			context.Background(), f, rewriteTestKey, testSessionID,
			up.Request{URL: testUpstreamURL, Header: http.Header{"Hwid": {"client-device"}}},
			[]byte(testProfileJSON), "", "", "", slog.New(slog.DiscardHandler),
		)
		if err != nil {
			t.Fatalf("Rewrite: %v", err)
		}
		if got := f.req.Header.Get(headerHWID); got != "client-device" {
			t.Errorf("relayed hwid = %q, want the client value", got)
		}
		if got := f.req.Header.Get(headerXHWID); got != "" {
			t.Errorf("synthesized identity overwrote the client value: %q", got)
		}
		// The cache discriminator is set regardless of the device identity the
		// client supplied, so provider cache entries stay separated per token.
		if got, want := f.req.SessionID, sessionCacheID(t, testSessionID); got != want {
			t.Errorf("SessionID = %q, want sha256 hex %q", got, want)
		}
	})

	t.Run("identity is synthesized when the client sends none", func(t *testing.T) {
		client := http.Header{"User-Agent": {"Happ/1.0"}}
		f := &fakeFetcher{result: okResult(testLinks)}
		_, err := Rewrite(
			context.Background(), f, rewriteTestKey, testSessionID,
			up.Request{URL: testUpstreamURL, Header: client},
			[]byte(testProfileJSON), "", "", "", slog.New(slog.DiscardHandler),
		)
		if err != nil {
			t.Fatalf("Rewrite: %v", err)
		}
		if got := f.req.Header.Get(headerXHWID); got != testSessionID {
			t.Errorf("synthesized hwid = %q, want the session id", got)
		}
		if got := f.req.Header.Get("User-Agent"); got != "Happ/1.0" {
			t.Errorf("relayed user-agent = %q", got)
		}
		if got := client.Get(headerXHWID); got != "" {
			t.Errorf("caller header map was mutated: %q", got)
		}
		if got, want := f.req.SessionID, sessionCacheID(t, testSessionID); got != want {
			t.Errorf("SessionID = %q, want sha256 hex %q", got, want)
		}
		if want := 64; len(f.req.SessionID) != want {
			t.Errorf("SessionID length = %d, want %d", len(f.req.SessionID), want)
		}
	})

	t.Run("no session id stays identity-free", func(t *testing.T) {
		f := &fakeFetcher{result: okResult(testLinks)}
		_, err := Rewrite(
			context.Background(), f, rewriteTestKey, "",
			up.Request{URL: testUpstreamURL, Header: http.Header{}},
			[]byte(testProfileJSON), "", "", "", slog.New(slog.DiscardHandler),
		)
		if err != nil {
			t.Fatalf("Rewrite: %v", err)
		}
		if f.req.Header.Get(headerXHWID) != "" {
			t.Errorf("identity synthesized without a session id: %q", f.req.Header.Get(headerXHWID))
		}
		if f.req.SessionID != "" {
			t.Errorf("SessionID = %q, want empty without a session id", f.req.SessionID)
		}
	})
}

func TestRewriteFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"plain garbage", "this is definitely not a subscription\n"},
		{"base64 garbage", base64.StdEncoding.EncodeToString([]byte("hello world"))},
		{"truncated JSON", `{"outbounds": [{"tag": "proxy"`},
		{"JSON scalar", `"vless://edge.example.com:443"`},
		{"empty config array", `[]`},
		{"config without outbounds", `{"remarks": "nothing"}`},
		{"mixed link list", "vless://edge.example.com:443\nnot a link\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := rewriteError(t, tc.body, "", "", "")
			if strings.Contains(err.Error(), "secret-token") {
				t.Errorf("error leaks the upstream URL: %v", err)
			}
		})
	}
}

func TestRewriteRejectsInvalidModes(t *testing.T) {
	cases := []struct {
		name      string
		adsMode   string
		routeMode string
	}{
		{"unknown ads mode", "max", ""},
		{"unknown route mode", "", "append"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeFetcher{result: okResult(testLinks)}
			_, err := Rewrite(
				context.Background(), f, rewriteTestKey, testSessionID,
				up.Request{URL: testUpstreamURL, Header: http.Header{}},
				[]byte(testProfileJSON), "", tc.adsMode, tc.routeMode, slog.New(slog.DiscardHandler),
			)
			if err == nil {
				t.Fatalf("Rewrite accepted ads mode %q, route mode %q", tc.adsMode, tc.routeMode)
			}
			if f.req.URL != "" {
				t.Errorf("upstream fetched despite invalid mode: %q", f.req.URL)
			}
		})
	}
}

func TestRewriteNotModified(t *testing.T) {
	t.Run("cached body is rewritten", func(t *testing.T) {
		f := &fakeFetcher{result: up.Result{
			Status:      http.StatusNotModified,
			NotModified: true,
			Body:        []byte(testLinks),
		}}
		out, err := Rewrite(
			context.Background(), f, rewriteTestKey, testSessionID,
			up.Request{URL: testUpstreamURL, Header: http.Header{}},
			[]byte(testProfileJSON), "", "", "", slog.New(slog.DiscardHandler),
		)
		if err != nil {
			t.Fatalf("Rewrite: %v", err)
		}
		if !out.NotModified {
			t.Errorf("NotModified flag lost")
		}
		if !strings.HasPrefix(string(out.Body), happRoutingPrefix) {
			t.Errorf("cached body not rewritten:\n%s", out.Body)
		}
	})

	t.Run("revalidation without a body fails closed", func(t *testing.T) {
		f := &fakeFetcher{result: up.Result{Status: http.StatusNotModified, NotModified: true}}
		_, err := Rewrite(
			context.Background(), f, rewriteTestKey, testSessionID,
			up.Request{URL: testUpstreamURL, Header: http.Header{}},
			[]byte(testProfileJSON), "", "", "", slog.New(slog.DiscardHandler),
		)
		if err == nil {
			t.Fatal("Rewrite served an empty revalidation")
		}
	})
}
