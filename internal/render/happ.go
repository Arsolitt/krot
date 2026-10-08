package render

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// happRoutingPrefix is the Happ deeplink scheme for routing profiles; the
// encoded profile is appended verbatim after it.
const happRoutingPrefix = "happ://routing/onadd/"

// Geofile sources of the profile. These are Happ's own defaults (the
// Loyalsoldier v2ray-rules-dat release assets), so a client that keeps its
// bundled geosite.dat/geoip.dat in sync resolves every tag below; the control
// plane never ships its own geofiles.
const (
	happGeositeURL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
	happGeoipURL   = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
)

// happDirectSites are the RU geosite categories that bypass the tunnel. Order
// is part of the artifact: it reproduces the client-side rule-set order
// (rulesets.ruGeosite), so a profile diff against the sing-box client rules is
// line-for-line comparable.
//
// All tags were verified present in the latest Loyalsoldier release on
// 2026-09-24 (1547 geosite categories).
var happDirectSites = []string{
	"geosite:category-bank-ru",
	"geosite:category-ecommerce-ru",
	"geosite:category-entertainment-ru",
	"geosite:category-gov-ru",
	"geosite:category-media-ru",
	"geosite:category-ru",
	"geosite:category-travel-ru",
	"geosite:dzen",
	"geosite:ozon",
	"geosite:mailru",
	"geosite:mailru-group",
}

// happDirectIPs are the direct destinations that are address-based: Russian
// geoip plus the non-routable ranges a client must never tunnel. Order is part
// of the artifact, as for happDirectSites.
//
// geoip:ru was verified present in the same release (260 geoip categories).
var happDirectIPs = []string{
	"geoip:ru",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"224.0.0.0/4",
	"255.255.255.255",
}

// happProxySites are the international rule sets the client-side routing
// proxies explicitly, mirroring the travel-router profile (rulesets tags /
// intlProxy): the Google and AI/dev suites, the messengers and the
// cloud/CDN/hosting sets. With GlobalProxy they are belt and braces - the
// fallback already tunnels whatever they match - but they keep a proxied
// service proxied when it also matches a direct rule (the geoip:ru range, a
// direct CIDR), which is exactly their role in the client rules where the
// proxy tier is a real outbound choice.
//
// Every tag was verified present in the Loyalsoldier release of 2026-10-08
// (1549 geosite categories) by enumerating the published geosite.dat. The
// intlProxy entries no published dataset carries are omitted, as on the
// direct side: the itdog lists (russia-inside, geoblock, news, cloudfront,
// hetzner-full, ovh, google-meet, linode, haproxy) and the custom
// cloudflare-full/community-v1/proxy-v1 sets.
//
// Order is part of the artifact: it reproduces the intlProxy order with the
// omitted entries skipped, so a profile diff against the client rules is
// line-for-line comparable. A tag appears once - itdog's youtube and
// sagernet's geosite-youtube both map to geosite:youtube here.
var happProxySites = []string{
	"geosite:telegram",
	"geosite:discord",
	"geosite:meta",
	"geosite:twitter",
	"geosite:youtube",
	"geosite:tiktok",
	"geosite:cloudflare",
	"geosite:hetzner",
	"geosite:digitalocean",
	"geosite:roblox",
	"geosite:fastly",
	"geosite:cdn77",
	"geosite:amazon",
	"geosite:microsoft",
	"geosite:github",
	"geosite:openai",
	"geosite:google",
	"geosite:akamai",
	"geosite:oracle",
	"geosite:category-dev",
	"geosite:anthropic",
	"geosite:deepseek",
	"geosite:groq",
	"geosite:shopify",
}

// happRoutingProfile is the Happ routing profile payload, mirroring the
// client-side sing-box routing used on user devices: RU geosite categories,
// geoip:ru and the private ranges go direct, ads are blocked, and
// GlobalProxy turns the proxy into the default outbound so everything
// unmatched (including the international rule sets the client resolves) is
// tunneled.
//
// Happ reads the object by key, so the field order below — sorted by
// alignment, the house rule for structs here — carries no meaning; the JSON
// keys keep Happ's own spelling verbatim, mixed capitalisation included:
// RemoteDNSIP/DomesticDNSIP take a capital "IP" suffix, while the address
// lists are DirectIp/ProxyIp/BlockIp. The deprecated RemoteDns/DomesticDns
// aliases some old profiles carry are deliberately not emitted.
//
// Known gaps versus the sing-box client rules: no published geodataset
// carries the itdog lists (russia-outside on the direct side; russia-inside,
// geoblock and the rest of the proxy side listed on happProxySites), the
// custom direct-v1/proxy-v1 entries or the ip-check set - verified 2026-10-08
// against Loyalsoldier (1549 geosite categories) and runetfreedom's
// russia-v2ray-rules-dat (1543). A profile has exactly one Geositeurl, so
// those cannot be mixed in without hosting a custom xray-format geosite.dat;
// traffic they matched keeps being routed by the surrounding rules.
type happRoutingProfile struct {
	DNSHosts          map[string]string `json:"DnsHosts"`
	DomainStrategy    string            `json:"DomainStrategy"`
	DomesticDNSType   string            `json:"DomesticDNSType"`
	Geoipurl          string            `json:"Geoipurl"`
	RemoteDNSIP       string            `json:"RemoteDNSIP"`
	Geositeurl        string            `json:"Geositeurl"`
	Name              string            `json:"Name"`
	GlobalProxy       string            `json:"GlobalProxy"`
	RemoteDNSType     string            `json:"RemoteDNSType"`
	FakeDNS           string            `json:"FakeDNS"`
	RemoteDNSDomain   string            `json:"RemoteDNSDomain"`
	LastUpdated       string            `json:"LastUpdated"`
	DomesticDNSDomain string            `json:"DomesticDNSDomain"`
	DomesticDNSIP     string            `json:"DomesticDNSIP"`
	BlockSites        []string          `json:"BlockSites"`
	DirectSites       []string          `json:"DirectSites"`
	ProxySites        []string          `json:"ProxySites"`
	BlockIP           []string          `json:"BlockIp"`
	ProxyIP           []string          `json:"ProxyIp"`
	DirectIP          []string          `json:"DirectIp"`
}

// HappRoutingProfileJSON returns the routing profile as compact JSON: the
// payload behind both the deeplink and the public profile endpoint.
func HappRoutingProfileJSON(name string) ([]byte, error) {
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("happ routing profile: blank name, Happ would fall back to its built-in default profile")
	}

	profile := happRoutingProfile{
		Name:              name,
		GlobalProxy:       "true",
		RemoteDNSType:     "DoH",
		RemoteDNSDomain:   "https://dns.google/dns-query",
		RemoteDNSIP:       "8.8.8.8",
		DomesticDNSType:   "DoU",
		DomesticDNSDomain: "",
		DomesticDNSIP:     "77.88.8.8",
		DNSHosts:          map[string]string{"dns.google": "8.8.8.8"},
		DirectSites:       happDirectSites,
		DirectIP:          happDirectIPs,
		ProxySites:        happProxySites,
		// Empty lists must marshal as [], not null: Happ treats null as
		// "field absent" and would keep a stale list from a previous import.
		ProxyIP:        []string{},
		BlockSites:     []string{"geosite:category-ads-all"},
		BlockIP:        []string{},
		LastUpdated:    "",
		DomainStrategy: "IPIfNonMatch",
		FakeDNS:        "false",
		Geositeurl:     happGeositeURL,
		Geoipurl:       happGeoipURL,
	}

	payload, err := json.Marshal(profile)
	if err != nil {
		return nil, fmt.Errorf("happ routing profile: marshal: %w", err)
	}
	return payload, nil
}

// HappRoutingLink builds the Happ deeplink carrying the routing profile under
// the given profile name. The control plane hands the link to clients in the
// subscription response header, which binds the profile to the subscription it
// arrived with.
func HappRoutingLink(name string) (string, error) {
	payload, err := HappRoutingProfileJSON(name)
	if err != nil {
		return "", err
	}
	return happRoutingPrefix + base64.StdEncoding.EncodeToString(payload), nil
}
