package rebuild

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"unicode"

	up "github.com/Arsolitt/krot/internal/upstream"
)

const (
	// happRoutingPrefix is the Happ deeplink scheme for routing profiles. The
	// base64-encoded profile is appended verbatim after it; internal/render
	// spells the same prefix for the /sub routing header, so the two must
	// stay in sync.
	happRoutingPrefix = "happ://routing/onadd/" // #nosec G101 -- deeplink scheme, not a credential.

	// adsModeLight and adsModeFull are the accepted ads modes; an empty mode
	// means light.
	adsModeLight = "light"
	adsModeFull  = "full"

	// adsSitesLight blocks the ad rule sets proper, adsSitesFull the wider
	// ads-and-tracking categories.
	adsSitesLight = "geosite:category-ads"
	adsSitesFull  = "geosite:category-ads-all"

	// routeModeReplace replaces the provider's routing rules with the krot
	// ones; the empty mode prepends them instead, keeping the provider's own
	// rules (and the balancers they feed) alive for unmatched traffic.
	routeModeReplace = "replace"

	// defaultDomainStrategy is the routing strategy used when the krot
	// profile itself carries none: domain rules match first, names that do
	// not resolve are re-matched by IP.
	defaultDomainStrategy = "IPIfNonMatch"

	// headerHWID and headerXHWID are the client identification headers
	// providers count devices by. Their spellings differ, so both are
	// watched before a synthesized identity is attached.
	headerHWID  = "Hwid"
	headerXHWID = "X-Hwid"

	// headerRouting is the Happ management header carrying the routing
	// profile deeplink, binding the profile to the subscription it arrived
	// with.
	headerRouting = "Routing"

	// headerSubscriptionUserinfo, headerProfileTitle,
	// headerProfileUpdateInterval and headerSupportURL are the upstream Happ
	// management headers the rebuild relays unchanged.
	headerSubscriptionUserinfo  = "Subscription-Userinfo"
	headerProfileTitle          = "Profile-Title"
	headerProfileUpdateInterval = "Profile-Update-Interval"
	headerSupportURL            = "Support-Url"

	// contentTypeJSON and contentTypePlain are the classified content types a
	// rebuilt body is served with: the payload format decides, never the
	// provider's own Content-Type, which the rebuild deliberately does not
	// relay — the control-plane origin serves /admin too, so a provider could
	// otherwise push text/html into a browser there.
	contentTypeJSON  = "application/json; charset=utf-8"
	contentTypePlain = "text/plain; charset=utf-8"

	// jsonRuleType is the only routing rule type Xray documents.
	jsonRuleType = "field"

	// privateSiteTag is the geosite category matching non-routable names,
	// used as the domestic DNS split of a profile without a direct list.
	privateSiteTag = "geosite:private"
)

// Xray document fields the rewriter reads or writes.
const (
	jsonOutbounds      = "outbounds"
	jsonTag            = "tag"
	jsonProtocol       = "protocol"
	jsonType           = "type"
	jsonOutboundTag    = "outboundTag"
	jsonDomain         = "domain"
	jsonIP             = "ip"
	jsonDNS            = "dns"
	jsonRouting        = "routing"
	jsonRules          = "rules"
	jsonDomainStrategy = "domainStrategy"
	jsonHosts          = "hosts"
	jsonServers        = "servers"
	jsonAddress        = "address"
	jsonDomains        = "domains"
)

// krot routing profile fields the rewriter reads or replaces.
const (
	jsonBlockSites        = "BlockSites"
	jsonBlockIP           = "BlockIp"
	jsonDirectSites       = "DirectSites"
	jsonDirectIP          = "DirectIp"
	jsonProxySites        = "ProxySites"
	jsonProxyIP           = "ProxyIp"
	jsonGlobalProxy       = "GlobalProxy"
	jsonDNSHosts          = "DnsHosts"
	jsonRemoteDNSDomain   = "RemoteDNSDomain"
	jsonRemoteDNSIP       = "RemoteDNSIP"
	jsonDomesticDNSDomain = "DomesticDNSDomain"
	jsonDomesticDNSIP     = "DomesticDNSIP"
	jsonProfileStrategy   = "DomainStrategy"
)

// linkEncodings are the base64 flavours a provider link list may arrive in,
// tried in order; standard padded encoding is what Happ-era providers emit.
var linkEncodings = []*base64.Encoding{
	base64.StdEncoding,
	base64.RawStdEncoding,
	base64.URLEncoding,
	base64.RawURLEncoding,
}

// passthroughProfileHeaders are the upstream Happ management headers the
// rebuild relays unchanged, so billing and support metadata stays visible on
// the rebuilt subscription.
var passthroughProfileHeaders = []string{
	headerSubscriptionUserinfo,
	headerProfileTitle,
	headerProfileUpdateInterval,
	headerSupportURL,
}

// Rewrite fetches the provider subscription behind req and returns it with
// krot's routing profile enforced:
//
//   - an Xray JSON config — a single object or an array of configs — keeps
//     the provider's outbounds, gets the krot DNS block, and gets krot routing
//     rules mapped onto the provider's own outbound tags;
//   - a plain or base64 link list is re-emitted with the
//     happ://routing/onadd deeplink carrying the profile prepended, and the
//     same deeplink is reported in the routing header;
//   - anything else fails closed, so an unrecognized payload is never served
//     to a client as a subscription.
//
// Upstream Happ management headers are relayed unchanged. sessionID is
// attached to the upstream fetch as the device identity when the client sent
// none, so device counting stays stable per rebuilt subscription, and the
// fetch also carries a hashed SessionID cache discriminator derived from it,
// so the fetcher's cache separates subscriptions without ever holding the
// raw id. The served content type is classified from the payload — JSON or
// plain text — and never relayed from the provider. key completes the
// rebuild credential set (Seal, Open, SessionID) and is otherwise unused by
// the rewrite. Errors and logs name modes, tags and formats only: the
// upstream URL and the token stay out of both.
func Rewrite(
	ctx context.Context,
	f up.Fetcher,
	key []byte, //nolint:revive // completes the rebuild credential set; the rewrite itself needs only sessionID.
	sessionID string,
	req up.Request,
	profileJSON []byte,
	proxyTagHint, adsMode, routeMode string,
	logger *slog.Logger,
) (up.Result, error) {
	// The exported entry point tolerates a nil logger, as the sibling
	// packages' constructors do (upstream.NewFetcher, sub.New,
	// cpapi.New): a caller without one still gets a working rewrite
	// instead of a nil dereference on the first log line.
	if logger == nil {
		logger = slog.Default()
	}
	profile, err := newHappProfile(profileJSON, adsMode)
	if err != nil {
		return up.Result{}, err
	}
	replace, err := parseRouteMode(routeMode)
	if err != nil {
		return up.Result{}, err
	}

	req = withSessionIdentity(req, sessionID)
	req.SessionID = sessionCacheIdentity(sessionID)
	res, err := f.Fetch(ctx, req)
	if err != nil {
		return up.Result{}, fmt.Errorf("upstream fetch: %w", err)
	}

	out := up.Result{
		Status:      res.Status,
		Body:        res.Body,
		NotModified: res.NotModified,
	}
	// A revalidation answer without the cached body has nothing to rewrite;
	// fail closed rather than serve an empty subscription the client would
	// treat as valid.
	if res.NotModified && len(res.Body) == 0 {
		return up.Result{}, errors.New("upstream revalidated without a cached body")
	}

	format := "links"
	var routingURI string
	// proxyTag and outboundTags carry the JSON mapping the log reports: the
	// tag every krot rule targets and the tags the provider config carried.
	var (
		proxyTag     string
		outboundTags []string
	)
	if docs, ok, err := jsonDocuments(res.Body); err != nil {
		return up.Result{}, err
	} else if ok {
		format = "json"
		out.ContentType = contentTypeJSON
		var errBake error
		out.Body, proxyTag, outboundTags, errBake = bakeDocuments(docs, profile, proxyTagHint, replace, logger)
		if errBake != nil {
			return up.Result{}, errBake
		}
	} else {
		out.ContentType = contentTypePlain
		out.Body, routingURI, err = bakeLinkList(res.Body, profile.payload)
		if err != nil {
			return up.Result{}, err
		}
	}
	out.ProfileHeaders = passthroughHeaders(res.ProfileHeaders, routingURI)

	// The JSON path reports the mapping it applied: the tag every krot rule
	// targets, the tags the provider config carried, and the hint when the
	// form named one, so an operator can confirm the resolution without
	// decoding the served body.
	attrs := []any{
		"session", sessionID, "format", format, "bytes", len(out.Body),
		"proxy_tag", proxyTag, "outbound_tags", outboundTags,
	}
	if proxyTagHint != "" {
		attrs = append(attrs, "proxy_tag_hint", proxyTagHint)
	}
	logger.InfoContext(ctx, "subscription rebuilt", attrs...)
	return out, nil
}

// withSessionIdentity returns req carrying the token-derived session id as the
// device identity when the client reported none: providers count devices by
// the HWID/x-hwid headers, and a rebuilt subscription fetched without one is
// either rejected or re-counted on every fetch. A client-supplied identity is
// never overwritten.
func withSessionIdentity(req up.Request, sessionID string) up.Request {
	if sessionID == "" || req.Header.Get(headerHWID) != "" || req.Header.Get(headerXHWID) != "" {
		return req
	}
	header := req.Header.Clone()
	if header == nil {
		header = http.Header{}
	}
	header.Set(headerXHWID, sessionID)
	req.Header = header
	return req
}

// sessionCacheIdentity derives the identity-keyed cache discriminator a
// rebuilt fetch carries: the hex SHA-256 of the token-derived session id, so
// the upstream cache separates rebuilt subscriptions of different tokens
// without ever seeing — or storing — the raw id. An empty session id stays
// empty, which leaves the fetch cache keyed by URL alone.
func sessionCacheIdentity(sessionID string) string {
	if sessionID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(sessionID))
	return hex.EncodeToString(sum[:])
}

// sniffResult is the JSON classification of a subscription body: the Xray
// config documents it parsed as, plus the shape they arrived in, which the
// rebuilt body preserves.
type sniffResult struct {
	docs    []map[string]any
	asArray bool
}

// jsonDocuments classifies body as a bare Xray config object or as an array of
// config objects. ok is false when the body does not even open like JSON; a
// body that opens like JSON but does not parse is an error, so a malformed
// subscription never falls through to the link-list path.
func jsonDocuments(body []byte) (sniffResult, bool, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return sniffResult{}, false, nil
	}
	switch trimmed[0] {
	case '{':
		doc := map[string]any{}
		if err := json.Unmarshal(trimmed, &doc); err != nil {
			return sniffResult{}, false, fmt.Errorf("subscription JSON: %w", err)
		}
		return sniffResult{docs: []map[string]any{doc}}, true, nil
	case '[':
		var docs []map[string]any
		if err := json.Unmarshal(trimmed, &docs); err != nil {
			return sniffResult{}, false, fmt.Errorf("subscription JSON: %w", err)
		}
		if len(docs) == 0 {
			return sniffResult{}, false, errors.New("subscription JSON: empty config array")
		}
		return sniffResult{docs: docs, asArray: true}, true, nil
	default:
		return sniffResult{}, false, nil
	}
}

// bakeDocuments bakes the krot profile into every config document and
// re-marshals them in the shape they arrived in. It returns the proxy tag the
// rules target and the outbound tags the config carried, so the caller can
// report the mapping it applied.
func bakeDocuments(
	docs sniffResult,
	profile *happProfile,
	proxyTagHint string,
	replace bool,
	logger *slog.Logger,
) ([]byte, string, []string, error) {
	resolved, tags := "", []string(nil)
	for i, doc := range docs.docs {
		tag, err := bakeDocument(doc, profile, proxyTagHint, replace, logger)
		if err != nil {
			return nil, "", nil, fmt.Errorf("config %d: %w", i+1, err)
		}
		if resolved == "" {
			resolved = tag
			if outbounds, ok := doc[jsonOutbounds].([]any); ok {
				tags = outboundTags(outbounds)
			}
		}
	}
	if docs.asArray {
		body, err := json.Marshal(docs.docs)
		return body, resolved, tags, err
	}
	body, err := json.Marshal(docs.docs[0])
	return body, resolved, tags, err
}

// bakeDocument rewrites one Xray config in place: the krot DNS block replaces
// the provider's, the krot rules are mapped onto the config's own outbound
// tags, and the routing strategy is fixed to the profile's, so domain rules
// keep matching when a name does not resolve. It returns the tag the proxy
// rules target.
func bakeDocument(
	doc map[string]any,
	profile *happProfile,
	proxyTagHint string,
	replace bool,
	logger *slog.Logger,
) (string, error) {
	outbounds, _ := doc[jsonOutbounds].([]any)
	proxyTag, err := resolveProxyTag(outbounds, proxyTagHint)
	if err != nil {
		return "", err
	}
	directTag := outboundTagMatching(outbounds, directOutbound)
	blockTag := outboundTagMatching(outbounds, blockOutbound)
	if directTag == "" && (len(profile.directSites) > 0 || len(profile.directIP) > 0) {
		logger.Warn("rebuild: provider config has no direct outbound, direct rules omitted")
	}
	if blockTag == "" && len(profile.blockSites) > 0 {
		logger.Warn("rebuild: provider config has no block outbound, ads rules omitted")
	}

	if dns := profile.dnsObject(); dns != nil {
		doc[jsonDNS] = dns
	}
	routing, _ := doc[jsonRouting].(map[string]any)
	if routing == nil {
		routing = map[string]any{}
	}
	existing, _ := routing[jsonRules].([]any)
	rules := profile.routingRules(proxyTag, directTag, blockTag)
	if !replace {
		rules = append(rules, existing...)
	}
	// The provider's own rules supplied the default route in prepend mode;
	// once they are gone (or were never there), GlobalProxy needs an explicit
	// catch-all so unmatched traffic still tunnels.
	if profile.globalProxy && (replace || len(existing) == 0) {
		rules = append(rules, fieldRule(proxyTag, nil, nil))
	}
	routing[jsonRules] = rules
	routing[jsonDomainStrategy] = profile.strategy()
	doc[jsonRouting] = routing
	return proxyTag, nil
}

// resolveProxyTag picks the outbound the krot rules route through: the hint
// when the operator supplied one, otherwise the first concrete tunnel
// outbound — skipping the direct/block/dns plumbing and selector-style
// aggregates — and failing that the first tagged outbound that is not
// plumbing. The error names the tags the config does carry and never the
// upstream URL.
func resolveProxyTag(outbounds []any, hint string) (string, error) {
	tags := outboundTags(outbounds)
	if hint != "" {
		if slices.Contains(tags, hint) {
			return hint, nil
		}
		return "", fmt.Errorf("proxy outbound tag %q is not in the config (%s)", hint, availableTags(tags))
	}
	for _, outbound := range outbounds {
		tag, protocol := outboundTag(outbound), outboundProtocol(outbound)
		if tag == "" || directishTag(tag) || aggregateProtocol(protocol) || tunnelLessProtocol(protocol) {
			continue
		}
		return tag, nil
	}
	for _, outbound := range outbounds {
		tag := outboundTag(outbound)
		if tag == "" || directishTag(tag) || tunnelLessProtocol(outboundProtocol(outbound)) {
			continue
		}
		return tag, nil
	}
	return "", errors.New("no usable proxy outbound: " + availableTags(tags))
}

// directishTag reports whether a tag names direct/block/dns plumbing, which
// the krot rules never target as the proxy.
func directishTag(tag string) bool {
	tag = strings.ToLower(tag)
	return strings.Contains(tag, "direct") || strings.Contains(tag, "block") || strings.Contains(tag, "dns")
}

// aggregateProtocol reports whether an outbound is a selector-style group that
// only forwards to other outbounds, not a concrete tunnel.
func aggregateProtocol(protocol string) bool {
	switch strings.ToLower(protocol) {
	case "selector", "urltest", "balancer":
		return true
	default:
		return false
	}
}

// tunnelLessProtocol reports whether an outbound never carries tunneled
// traffic: freedom passes through, blackhole drops, dns resolves.
func tunnelLessProtocol(protocol string) bool {
	switch strings.ToLower(protocol) {
	case "freedom", "blackhole", "dns":
		return true
	default:
		return false
	}
}

// outboundTags lists the tags the config's outbounds carry, in order.
func outboundTags(outbounds []any) []string {
	tags := make([]string, 0, len(outbounds))
	for _, outbound := range outbounds {
		if tag := outboundTag(outbound); tag != "" {
			tags = append(tags, tag)
		}
	}
	return tags
}

// outboundTag reads one outbound's tag; anything that is not an object with a
// string tag reads as untagged.
func outboundTag(outbound any) string {
	fields, ok := outbound.(map[string]any)
	if !ok {
		return ""
	}
	tag, _ := fields[jsonTag].(string)
	return tag
}

// outboundProtocol reads one outbound's protocol; anything that is not an
// object with a string protocol reads as empty.
func outboundProtocol(outbound any) string {
	fields, ok := outbound.(map[string]any)
	if !ok {
		return ""
	}
	protocol, _ := fields[jsonProtocol].(string)
	return protocol
}

// outboundTagMatching returns the tag of the first outbound the predicate
// matches, or "" when none does.
func outboundTagMatching(outbounds []any, match func(tag, protocol string) bool) string {
	for _, outbound := range outbounds {
		tag, protocol := outboundTag(outbound), outboundProtocol(outbound)
		if tag != "" && match(tag, protocol) {
			return tag
		}
	}
	return ""
}

// directOutbound reports whether an outbound is the direct plumbing: the rule
// target for traffic that must leave untunneled.
func directOutbound(tag, protocol string) bool {
	return strings.Contains(strings.ToLower(tag), "direct") || strings.EqualFold(protocol, "freedom")
}

// blockOutbound reports whether an outbound is the block plumbing: the rule
// target for traffic that must be dropped.
func blockOutbound(tag, protocol string) bool {
	return strings.Contains(strings.ToLower(tag), "block") || strings.EqualFold(protocol, "blackhole")
}

// availableTags renders an outbound tag listing for error messages.
func availableTags(tags []string) string {
	if len(tags) == 0 {
		return "no outbound tags"
	}
	return "available outbound tags: " + strings.Join(tags, ", ")
}

// happProfile is the decoded krot routing profile plus the payload the rebuilt
// subscription carries: the profile with its ad-blocking site list replaced by
// the requested ads mode. Fields the profile omits stay zero, and everything
// the rewriter does not read stays untouched in the payload.
type happProfile struct {
	dnsHosts          map[string]string
	remoteDNSDomain   string
	domainStrategy    string
	domesticDNSIP     string
	remoteDNSIP       string
	domesticDNSDomain string
	proxySites        []string
	blockIP           []string
	blockSites        []string
	proxyIP           []string
	payload           []byte
	directIP          []string
	directSites       []string
	globalProxy       bool
}

// newHappProfile decodes profileJSON — krot's own routing profile — and
// replaces its ad-blocking site list with the one the ads mode selects. The
// mutated profile is what the rebuilt subscription carries, link line and all,
// so a client importing it sees the operator's ads choice.
func newHappProfile(profileJSON []byte, adsMode string) (*happProfile, error) {
	blockSites, err := adsBlockSites(adsMode)
	if err != nil {
		return nil, err
	}
	doc := map[string]any{}
	if err := json.Unmarshal(profileJSON, &doc); err != nil {
		return nil, fmt.Errorf("routing profile: %w", err)
	}
	if doc == nil {
		return nil, errors.New("routing profile: not a JSON object")
	}
	doc[jsonBlockSites] = stringList(blockSites)
	payload, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("routing profile: %w", err)
	}
	return &happProfile{
		payload:           payload,
		directSites:       stringSlice(doc, jsonDirectSites),
		directIP:          stringSlice(doc, jsonDirectIP),
		proxySites:        stringSlice(doc, jsonProxySites),
		proxyIP:           stringSlice(doc, jsonProxyIP),
		blockSites:        blockSites,
		blockIP:           stringSlice(doc, jsonBlockIP),
		remoteDNSDomain:   stringValue(doc, jsonRemoteDNSDomain),
		domesticDNSDomain: stringValue(doc, jsonDomesticDNSDomain),
		remoteDNSIP:       stringValue(doc, jsonRemoteDNSIP),
		domesticDNSIP:     stringValue(doc, jsonDomesticDNSIP),
		domainStrategy:    stringValue(doc, jsonProfileStrategy),
		dnsHosts:          stringMap(doc, jsonDNSHosts),
		globalProxy:       globalProxyEnabled(doc),
	}, nil
}

// adsBlockSites maps an ads mode to the profile's ad-blocking site list. An
// empty mode is light; anything else is rejected so a stale form value cannot
// silently weaken the profile.
func adsBlockSites(mode string) ([]string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", adsModeLight:
		return []string{adsSitesLight}, nil
	case adsModeFull:
		return []string{adsSitesFull}, nil
	default:
		return nil, fmt.Errorf("ads mode %q: want %q, %q or empty", mode, adsModeLight, adsModeFull)
	}
}

// parseRouteMode maps a route mode to the replace flag. An empty mode prepends
// the krot rules; anything else is rejected.
func parseRouteMode(mode string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "":
		return false, nil
	case routeModeReplace:
		return true, nil
	default:
		return false, fmt.Errorf("route mode %q: want %q or empty", mode, routeModeReplace)
	}
}

// strategy is the routing domain strategy the rebuilt config carries.
func (p *happProfile) strategy() string {
	if p.domainStrategy != "" {
		return p.domainStrategy
	}
	return defaultDomainStrategy
}

// dnsObject builds the krot DNS block: the profile's remote (DoH) and domestic
// (DoU) resolvers, split by the profile's own direct site list so the names
// krot routes direct resolve domestically, and the plain remote IP as the
// final fallback. It returns nil when the profile carries no resolver at all,
// leaving the provider's DNS in place rather than replacing it with nothing.
func (p *happProfile) dnsObject() map[string]any {
	remote, domestic := p.remoteDNSAddress(), p.domesticDNSAddress()
	if remote == "" && domestic == "" {
		return nil
	}
	servers := make([]any, 0)
	if domestic != "" {
		servers = append(servers, dnsServer(domestic, p.domesticDomains()))
	}
	if remote != "" {
		servers = append(servers, dnsServer(remote, []string{"geosite:geolocation-!cn"}))
	}
	if p.remoteDNSIP != "" {
		servers = append(servers, p.remoteDNSIP)
	}
	block := map[string]any{jsonServers: servers}
	if hosts := stringMapToAny(p.dnsHosts); len(hosts) > 0 {
		block[jsonHosts] = hosts
	}
	return block
}

// remoteDNSAddress is the remote resolver address: the encrypted address from
// the profile when it carries one, its IP otherwise.
func (p *happProfile) remoteDNSAddress() string {
	if p.remoteDNSDomain != "" {
		return p.remoteDNSDomain
	}
	return p.remoteDNSIP
}

// domesticDNSAddress is the domestic resolver address: the encrypted address
// from the profile when it carries one, its IP otherwise.
func (p *happProfile) domesticDNSAddress() string {
	if p.domesticDNSDomain != "" {
		return p.domesticDNSDomain
	}
	return p.domesticDNSIP
}

// domesticDomains is the domain split of the domestic resolver: the profile's
// direct site list, so every name krot routes direct resolves domestically. A
// profile without a direct list falls back to the private category, keeping
// the resolver from becoming an implicit catch-all.
func (p *happProfile) domesticDomains() []string {
	if len(p.directSites) > 0 {
		return p.directSites
	}
	return []string{privateSiteTag}
}

// dnsServer is one Xray DNS server entry with its domain split.
func dnsServer(address string, domains []string) map[string]any {
	entry := map[string]any{jsonAddress: address}
	if len(domains) > 0 {
		entry[jsonDomains] = stringList(domains)
	}
	return entry
}

// routingRules maps the profile onto the config's own outbound tags: ads are
// blocked, the RU/private categories go direct, the international categories
// go proxy. A target tag the config does not carry drops its rules (the caller
// logs that), and an empty category list emits no rule at all.
func (p *happProfile) routingRules(proxyTag, directTag, blockTag string) []any {
	targets := []routingTarget{
		{tag: blockTag, domains: p.blockSites, ips: p.blockIP},
		{tag: directTag, domains: p.directSites, ips: p.directIP},
		{tag: proxyTag, domains: p.proxySites, ips: p.proxyIP},
	}
	rules := make([]any, 0, len(targets))
	for _, target := range targets {
		if target.tag == "" || (len(target.domains) == 0 && len(target.ips) == 0) {
			continue
		}
		rules = append(rules, fieldRule(target.tag, target.domains, target.ips))
	}
	return rules
}

// routingTarget is one outbound tag with the profile categories routing to it.
type routingTarget struct {
	tag     string
	domains []string
	ips     []string
}

// fieldRule is one Xray field routing rule: the given destinations go to tag,
// with empty destination lists omitted.
func fieldRule(tag string, domains, ips []string) map[string]any {
	rule := map[string]any{jsonType: jsonRuleType, jsonOutboundTag: tag}
	if len(domains) > 0 {
		rule[jsonDomain] = stringList(domains)
	}
	if len(ips) > 0 {
		rule[jsonIP] = stringList(ips)
	}
	return rule
}

// stringList wraps strings as a JSON list, never nil so lists marshal as []
// rather than null.
func stringList(values []string) []any {
	list := make([]any, len(values))
	for i, value := range values {
		list[i] = value
	}
	return list
}

// stringMapToAny wraps a string map as a JSON object, never nil.
func stringMapToAny(values map[string]string) map[string]any {
	out := make(map[string]any, len(values))
	for name, value := range values {
		out[name] = value
	}
	return out
}

// stringSlice reads a JSON string array field of the profile; a missing or
// wrongly typed field reads as empty.
func stringSlice(doc map[string]any, key string) []string {
	values, _ := doc[key].([]any)
	slice := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			slice = append(slice, text)
		}
	}
	return slice
}

// stringValue reads a JSON string field of the profile; a missing or wrongly
// typed field reads as empty.
func stringValue(doc map[string]any, key string) string {
	text, _ := doc[key].(string)
	return text
}

// stringMap reads a JSON object field of the profile with string values; a
// missing or wrongly typed field reads as empty.
func stringMap(doc map[string]any, key string) map[string]string {
	values, _ := doc[key].(map[string]any)
	out := make(map[string]string, len(values))
	for name, value := range values {
		if text, ok := value.(string); ok {
			out[name] = text
		}
	}
	return out
}

// globalProxyEnabled reports the profile's GlobalProxy flag. A profile that
// omits the field means the krot default: everything unmatched goes proxy.
func globalProxyEnabled(doc map[string]any) bool {
	switch value := doc[jsonGlobalProxy].(type) {
	case string:
		return strings.EqualFold(value, "true")
	case bool:
		return value
	default:
		return true
	}
}

// bakeLinkList re-emits a link list with the krot routing profile prepended as
// a happ://routing/onadd deeplink. It returns the rebuilt body and the same
// deeplink, which the caller advertises in the routing header.
func bakeLinkList(body, profilePayload []byte) ([]byte, string, error) {
	links, err := decodeLinks(body)
	if err != nil {
		return nil, "", err
	}
	routingURI := happRoutingPrefix + base64.StdEncoding.EncodeToString(profilePayload)
	rebuilt := routingURI + "\n" + links + "\n"
	return []byte(rebuilt), routingURI, nil
}

// decodeLinks extracts the provider links from a plain or base64 link list.
// Both paths require every non-empty line to look like a link, so a payload
// that merely happens to be base64-decodable is still rejected rather than
// served as a subscription.
func decodeLinks(body []byte) (string, error) {
	text := string(body)
	if lines := linkLines(text); len(lines) > 0 {
		return strings.Join(lines, "\n"), nil
	}
	compact := strings.Join(strings.Fields(text), "")
	if compact != "" {
		for _, encoding := range linkEncodings {
			decoded, err := encoding.DecodeString(compact)
			if err != nil {
				continue
			}
			if lines := linkLines(string(decoded)); len(lines) > 0 {
				return strings.Join(lines, "\n"), nil
			}
		}
	}
	return "", errors.New("unrecognized subscription payload: not a JSON config, a link list, or base64-encoded links")
}

// linkLines splits subscription text into its link lines. It returns nil —
// meaning "not a link list" — when the text is empty or any non-empty line
// does not look like a link.
func linkLines(text string) []string {
	rawLines := strings.Split(text, "\n")
	lines := make([]string, 0, len(rawLines))
	for _, line := range rawLines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !looksLikeLink(line) {
			return nil
		}
		lines = append(lines, line)
	}
	return lines
}

// looksLikeLink reports whether a line starts with a URI scheme, which every
// subscription link (vless://, vmess://, hysteria2://, happ://) does.
func looksLikeLink(line string) bool {
	scheme, _, found := strings.Cut(line, "://")
	if !found || scheme == "" {
		return false
	}
	for _, r := range scheme {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '+' && r != '-' && r != '.' {
			return false
		}
	}
	return true
}

// passthroughHeaders builds the rebuilt subscription's profile headers: the
// upstream management headers, plus the routing deeplink for link-list bodies.
// A provider routing header is deliberately not relayed: the rebuilt
// subscription carries krot's own profile, and a stale provider profile would
// fight it.
func passthroughHeaders(upstream http.Header, routingURI string) http.Header {
	out := http.Header{}
	for _, name := range passthroughProfileHeaders {
		if value := upstream.Get(name); value != "" {
			out.Set(name, value)
		}
	}
	if routingURI != "" {
		out.Set(headerRouting, routingURI)
	}
	return out
}
