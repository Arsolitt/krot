package render

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// decodeHappRoutingLink validates the deeplink envelope and returns the parsed
// profile plus its compact JSON text.
func decodeHappRoutingLink(t *testing.T, link string) (map[string]any, string) {
	t.Helper()
	if !strings.HasPrefix(link, happRoutingPrefix) {
		t.Fatalf("link %q does not start with %q", link, happRoutingPrefix)
	}
	payload := strings.TrimPrefix(link, happRoutingPrefix)
	if strings.ContainsAny(payload, " \t\r\n") {
		t.Fatalf("payload is not single-line base64: %q", payload)
	}
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("payload is not standard padded base64: %v", err)
	}
	var profile map[string]any
	if err := json.Unmarshal(raw, &profile); err != nil {
		t.Fatalf("payload is not JSON: %v", err)
	}
	return profile, string(raw)
}

// happStringList reads a JSON array field as []string, failing when the field
// is missing or has another shape.
func happStringList(t *testing.T, profile map[string]any, key string) []string {
	t.Helper()
	values, ok := profile[key].([]any)
	if !ok {
		t.Fatalf("%s: got %#v, want a JSON array", key, profile[key])
	}
	list := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			t.Fatalf("%s: element %#v is not a string", key, value)
		}
		list = append(list, text)
	}
	return list
}

// happString reads a JSON string field.
func happString(t *testing.T, profile map[string]any, key string) string {
	t.Helper()
	text, ok := profile[key].(string)
	if !ok {
		t.Fatalf("%s: got %#v, want a JSON string", key, profile[key])
	}
	return text
}

func TestHappRoutingLink(t *testing.T) {
	const name = "Krot"
	link, err := HappRoutingLink(name)
	if err != nil {
		t.Fatalf("HappRoutingLink(%q): %v", name, err)
	}
	t.Logf("deeplink: %s", link)

	profile, _ := decodeHappRoutingLink(t, link)
	if got := happString(t, profile, "Name"); got != name {
		t.Errorf("Name: got %q, want %q", got, name)
	}
}

func TestHappRoutingProfileRouting(t *testing.T) {
	link, err := HappRoutingLink("Krot")
	if err != nil {
		t.Fatalf("HappRoutingLink: %v", err)
	}
	profile, raw := decodeHappRoutingLink(t, link)

	wantSites := []string{
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
	if got := happStringList(t, profile, "DirectSites"); !reflect.DeepEqual(got, wantSites) {
		t.Errorf("DirectSites:\n got %q\nwant %q", got, wantSites)
	}

	wantIPs := []string{
		"geoip:ru",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"224.0.0.0/4",
		"255.255.255.255",
	}
	if got := happStringList(t, profile, "DirectIp"); !reflect.DeepEqual(got, wantIPs) {
		t.Errorf("DirectIp:\n got %q\nwant %q", got, wantIPs)
	}

	wantBlock := []string{"geosite:category-ads-all"}
	if got := happStringList(t, profile, "BlockSites"); !reflect.DeepEqual(got, wantBlock) {
		t.Errorf("BlockSites:\n got %q\nwant %q", got, wantBlock)
	}

	// The profile is read by key, and a mistyped key is a silent no-op: Happ
	// drops the value and keeps whatever the previous profile held. Pin the
	// exact documented key set on the wire bytes, Happ's capitalisation
	// included (RemoteDNSIP/DomesticDNSIP, but DirectIp/ProxyIp/BlockIp).
	wantKeys := []string{
		"BlockIp", "BlockSites", "DirectIp", "DirectSites", "DnsHosts",
		"DomainStrategy", "DomesticDNSDomain", "DomesticDNSIP", "DomesticDNSType",
		"FakeDNS", "Geoipurl", "Geositeurl", "GlobalProxy", "LastUpdated",
		"Name", "ProxyIp", "ProxySites", "RemoteDNSDomain", "RemoteDNSIP",
		"RemoteDNSType",
	}
	gotKeys := make([]string, 0, len(profile))
	for key := range profile {
		gotKeys = append(gotKeys, key)
	}
	slices.Sort(gotKeys)
	if !reflect.DeepEqual(gotKeys, wantKeys) {
		t.Errorf("profile keys:\n got %q\nwant %q", gotKeys, wantKeys)
	}

	// An empty list has to survive as [], not null: null reads as "absent" and
	// the client keeps whatever the previous profile held. Assert on the wire
	// bytes, since both shapes unmarshal to the same empty slice here.
	for _, key := range []string{"ProxySites", "ProxyIp", "BlockIp"} {
		if !strings.Contains(raw, `"`+key+`":[]`) {
			t.Errorf("%s is not serialized as an empty array: %s", key, raw)
		}
		if got := happStringList(t, profile, key); len(got) != 0 {
			t.Errorf("%s: got %q, want empty", key, got)
		}
	}

	for key, want := range map[string]string{
		"GlobalProxy":    "true",
		"DomainStrategy": "IPIfNonMatch",
		"FakeDNS":        "false",
	} {
		if got := happString(t, profile, key); got != want {
			t.Errorf("%s: got %q, want %q", key, got, want)
		}
	}

	for key, want := range map[string]string{
		"RemoteDNSType":     "DoH",
		"RemoteDNSDomain":   "https://dns.google/dns-query",
		"RemoteDNSIP":       "8.8.8.8",
		"DomesticDNSType":   "DoU",
		"DomesticDNSDomain": "",
		"DomesticDNSIP":     "77.88.8.8",
	} {
		if got := happString(t, profile, key); got != want {
			t.Errorf("%s: got %q, want %q", key, got, want)
		}
	}

	hosts, ok := profile["DnsHosts"].(map[string]any)
	if !ok || len(hosts) != 1 || hosts["dns.google"] != "8.8.8.8" {
		t.Errorf("DnsHosts: got %#v, want {\"dns.google\": \"8.8.8.8\"}", profile["DnsHosts"])
	}

	// Tags are resolved from the client's own geofiles, so the profile must
	// point at the Loyalsoldier release assets the tags were verified against.
	for key, wantSuffix := range map[string]string{
		"Geositeurl": "/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
		"Geoipurl":   "/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
	} {
		got := happString(t, profile, key)
		if !strings.HasSuffix(got, wantSuffix) {
			t.Errorf("%s: got %q, want a URL ending in %q", key, got, wantSuffix)
		}
	}
}

func TestHappRoutingLinkRejectsBlankName(t *testing.T) {
	for _, name := range []string{"", " ", "\t\n"} {
		link, err := HappRoutingLink(name)
		if err == nil {
			t.Errorf("HappRoutingLink(%q): got link %q, want error", name, link)
			continue
		}
		if link != "" {
			t.Errorf("HappRoutingLink(%q): got link %q alongside error %v", name, link, err)
		}
	}
}
