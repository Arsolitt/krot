// Package render builds sing-box configurations from desired-state data:
// compiled per-node route profiles, typed inbound construction and the
// subscription share-link URIs. It is used by both the control plane (links)
// and the agents (full configs).
package render

import (
	"fmt"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// ProfileProxyServer is the compiled route profile replicating the v1 server
// set: RU/ads traffic rejected, everything else direct.
const ProfileProxyServer = "proxy-server"

// Shared tags and knobs of the proxy-server profile.
const (
	dnsLocalTag  = "dns-local"
	dnsRemoteTag = "dns-remote"
	directTag    = "direct"

	dotServer = "8.8.8.8"
	dotPort   = 853

	ruleSetBaseURL     = "https://raw.githubusercontent.com/Arsolitt/sing-box-rules/rule-set/"
	ruleSetUpdateEvery = 24 * time.Hour

	realityHandshakePort = 443
	hy2BandwidthMbps     = 1000
)

// Rule set tags referenced in more than one place of the profile.
const (
	tagGeositeRU     = "geosite-category-ru"
	tagRussiaOutside = "russia-outside"
)

// ruRejectTags are the rule sets whose traffic is dropped; order matters —
// it is reproduced verbatim from the v1 golden configuration.
var ruRejectTags = []string{
	"geoip-ru",
	"geosite-category-bank-ru",
	"geosite-category-ecommerce-ru",
	"geosite-category-entertainment-ru",
	"geosite-category-gov-ru",
	"geosite-category-media-ru",
	tagGeositeRU,
	"geosite-category-travel-ru",
	"geosite-dzen",
	"geosite-ozon",
	"geosite-mailru",
	"geosite-mailru-group",
	tagRussiaOutside,
}

// remoteRuleSets is the full rule_set list of the proxy-server profile in
// golden order; ads-all leads because the ads drop rule references it.
var remoteRuleSets = []string{
	"geosite-category-ads-all",
	tagGeositeRU,
	"geosite-category-bank-ru",
	"geosite-category-ecommerce-ru",
	"geosite-category-entertainment-ru",
	"geosite-category-gov-ru",
	"geosite-category-media-ru",
	"geosite-category-travel-ru",
	"geosite-dzen",
	"geosite-ozon",
	"geosite-mailru",
	"geosite-mailru-group",
	"geoip-ru",
	tagRussiaOutside,
}

// ruleSetURL maps a rule set tag to its remote .rs URL, mirroring the v1
// rulesets.jsonnet mapping: sagernet geosite/geoip mirrors and an itdog
// mirror for russia-outside.
func ruleSetURL(tag string) string {
	var file string
	switch {
	case tag == tagRussiaOutside:
		file = "itdog-russia_outside.srs"
	case len(tag) > 8 && tag[:7] == "geosite":
		file = "sagernet-" + tag + ".srs"
	case len(tag) > 6 && tag[:5] == "geoip":
		file = "sagernet-" + tag + ".srs"
	default:
		file = tag + ".srs"
	}
	return ruleSetBaseURL + file
}

// ValidProfile reports whether name selects a compiled route profile.
func ValidProfile(name string) bool {
	return name == ProfileProxyServer
}

// buildLog returns the fixed server log options.
func buildLog() *option.LogOptions {
	return &option.LogOptions{Level: "error", Timestamp: true}
}

// buildDNS returns the profile DNS block: local resolver for RU domains and
// DNS-over-TLS via Google for everything else.
func buildDNS() *option.DNSOptions {
	return &option.DNSOptions{
		RawDNSOptions: option.RawDNSOptions{
			Servers: []option.DNSServerOptions{
				{Type: "local", Tag: dnsLocalTag, Options: option.LocalDNSServerOptions{}},
				{
					Type: "tls",
					Tag:  dnsRemoteTag,
					Options: option.RemoteTLSDNSServerOptions{
						RemoteDNSServerOptions: option.RemoteDNSServerOptions{
							DNSServerAddressOptions: option.DNSServerAddressOptions{
								Server: dotServer, ServerPort: dotPort,
							},
							RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{
								DialerOptions: option.DialerOptions{Detour: directTag},
							},
						},
					},
				},
			},
			Rules: []option.DNSRule{{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultDNSRule{
					RawDefaultDNSRule: option.RawDefaultDNSRule{
						RuleSet: []string{tagGeositeRU},
					},
					DNSRuleAction: option.DNSRuleAction{
						Action:       C.RuleActionTypeRoute,
						RouteOptions: option.DNSRouteActionOptions{Server: dnsLocalTag},
					},
				},
			}},
			Final: dnsRemoteTag,
			DNSClientOptions: option.DNSClientOptions{
				Strategy: option.DomainStrategy(C.DomainStrategyPreferIPv4),
			},
		},
	}
}

// buildOutbounds returns the single direct outbound with dns-local as its
// domain resolver.
func buildOutbounds() []option.Outbound {
	opts := option.DirectOutboundOptions{
		DialerOptions: option.DialerOptions{
			DomainResolver: &option.DomainResolveOptions{Server: dnsLocalTag},
		},
	}
	return []option.Outbound{{Type: "direct", Tag: directTag, Options: &opts}}
}

// buildRoute returns the profile route block.
func buildRoute() *option.RouteOptions {
	ruleSets := make([]option.RuleSet, 0, len(remoteRuleSets))
	for _, tag := range remoteRuleSets {
		ruleSets = append(ruleSets, option.RuleSet{
			Type: "remote",
			Tag:  tag,
			RemoteOptions: option.RemoteRuleSet{
				URL:            ruleSetURL(tag),
				DownloadDetour: directTag,
				UpdateInterval: badoption.Duration(ruleSetUpdateEvery),
			},
		})
	}

	rejectDrop := option.RuleAction{
		Action:        C.RuleActionTypeReject,
		RejectOptions: option.RejectActionOptions{Method: "drop"},
	}

	return &option.RouteOptions{
		Rules: []option.Rule{
			{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{Protocol: []string{"dns"}},
					RuleAction:     option.RuleAction{Action: C.RuleActionTypeHijackDNS},
				},
			},
			{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{RuleSet: []string{"geosite-category-ads-all"}},
					RuleAction:     rejectDrop,
				},
			},
			{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{IPIsPrivate: true},
					RuleAction:     rejectDrop,
				},
			},
			{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{RuleSet: ruRejectTags},
					RuleAction:     rejectDrop,
				},
			},
		},
		RuleSet:               ruleSets,
		Final:                 directTag,
		AutoDetectInterface:   true,
		DefaultDomainResolver: &option.DomainResolveOptions{Server: dnsLocalTag},
	}
}

// buildExperimental returns the experimental block; nil when no cache file
// path is configured.
func buildExperimental(cacheFilePath string) *option.ExperimentalOptions {
	if cacheFilePath == "" {
		return nil
	}
	return &option.ExperimentalOptions{
		CacheFile: &option.CacheFileOptions{Enabled: true, Path: cacheFilePath},
	}
}

// errUnknownProfile is the renderer's rejection of an undeclared profile.
func errUnknownProfile(name string) error {
	return fmt.Errorf("unknown route profile %q", name)
}
