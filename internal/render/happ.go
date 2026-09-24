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
// Known gap versus the sing-box client rules: the itdog "russia-outside" rule
// set and the custom "direct-v1" list are not in the Loyalsoldier datasets, so
// they cannot be expressed as geosite tags here and are omitted until a
// self-hosted xray-format geosite.dat carries them. Traffic that only those
// two lists matched is therefore proxied, not direct.
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
		// Empty lists must marshal as [], not null: Happ treats null as
		// "field absent" and would keep a stale list from a previous import.
		ProxySites:     []string{},
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
