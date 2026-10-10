package render

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arsolitt/krot/internal/model"
)

// goldenLinkSpec returns the srv-1 inbound rows with the golden link tags so
// fragments come out as srv-1-vless / srv-1-hysteria2 (matching the fixture).
func goldenLinkSpec(t *testing.T) []model.Inbound {
	t.Helper()
	inbounds := goldenInbounds(t)
	// v1 used the protocol names as tags in links; reuse the golden rows.
	inbounds[0].Tag = "vless"
	inbounds[1].Tag = "hysteria2"
	return inbounds
}

// goldenLinks parses the v1 subscriptions fixture and returns its user links.
func goldenLinks(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "golden_subscriptions.json"))
	if err != nil {
		t.Fatalf("read golden subscriptions: %v", err)
	}
	var subs struct {
		Users []struct {
			Links []string `json:"links"`
		} `json:"users"`
	}
	if err := json.Unmarshal(raw, &subs); err != nil {
		t.Fatalf("parse golden subscriptions: %v", err)
	}
	if len(subs.Users) != 1 || len(subs.Users[0].Links) != 2 {
		t.Fatalf("golden fixture shape drifted: %+v", subs)
	}
	return subs.Users[0].Links
}

func TestLinkGoldenURIs(t *testing.T) {
	inbounds := goldenLinkSpec(t)
	users := goldenUsers()
	want := goldenLinks(t)

	got := make([]string, 0, len(inbounds))
	for _, in := range inbounds {
		uri, err := Link("srv-1", in, users[0])
		if err != nil {
			t.Fatalf("Link(%s): %v", in.Tag, err)
		}
		got = append(got, uri)
	}

	// Spec order is vless first; the fixture lists hysteria2 first. The hy2
	// expectation rewrites the fixture's HPKP-style pin to the hex leaf-cert
	// pin Xray-core clients derive from the pinSHA256 parameter.
	if got[0] != want[1] {
		t.Errorf("vless URI:\n got %s\nwant %s", got[0], want[1])
	}
	wantPin, err := xrayCertPin(inbounds[1].CertPEM)
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	hy2 := want[0]
	i := strings.Index(hy2, "pinSHA256=") + len("pinSHA256=")
	j := strings.Index(hy2[i:], "&")
	wantHy2 := hy2[:i] + wantPin + hy2[i+j:]
	if got[1] != wantHy2 {
		t.Errorf("hysteria2 URI:\n got %s\nwant %s", got[1], wantHy2)
	}
}

// TestLinkHysteria2PinnedPin covers the static-mode shape: the control plane
// holds no certificate, so the pin comes from the stored pin_sha256 verbatim,
// URL-escaped (the slash in "sha256/<b64>" becomes %2F as in the fixture).
func TestLinkHysteria2PinnedPin(t *testing.T) {
	const pin = "sha256/HdDtNOYbrezybvBZq9CjXjY6QAw8apos4mhNsGqCw9Q"
	in := model.Inbound{
		Tag: "hy2-pinned", Type: model.InboundHysteria2,
		PublicEndpoint: "srv-1.example.com", PublicPort: wsPublicPort,
		SNI: "cdn.example.com", ObfsPassword: "obfs-pass",
		PinSHA256: pin,
	}

	got, err := Link("srv-1", in, model.User{Hy2Password: "hy2-pass"})
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	want := "hysteria2://hy2-pass@srv-1.example.com:443?alpn=h3&obfs=salamander" +
		"&obfs-password=obfs-pass&pinSHA256=sha256%2F" +
		"HdDtNOYbrezybvBZq9CjXjY6QAw8apos4mhNsGqCw9Q&sni=cdn.example.com#srv-1-hy2-pinned"
	if got != want {
		t.Errorf("pinned hysteria2 URI:\n got %s\nwant %s", got, want)
	}
}

// TestLinkHysteria2MissingPin covers the rejection rule: an inbound with
// neither a certificate nor a pin_sha256 cannot yield a client pin.
func TestLinkHysteria2MissingPin(t *testing.T) {
	in := model.Inbound{
		Tag: "hy2-bare", Type: model.InboundHysteria2,
		PublicEndpoint: "srv-1.example.com", PublicPort: wsPublicPort,
	}

	_, err := Link("srv-1", in, model.User{Hy2Password: "hy2-pass"})
	if err == nil {
		t.Fatal("hysteria2 inbound without certificate or pin must error")
	}
	if !strings.Contains(err.Error(), "has neither a certificate nor a pin_sha256") {
		t.Errorf("error must name both missing pin sources, got %v", err)
	}
}

func TestLinkVLESSWSURI(t *testing.T) {
	wsPath := "/up"
	in := model.Inbound{
		Tag: "vless-ws-ddg", Type: model.InboundVLESSWS,
		ListenPort: wsListenPort, SNI: "front.example.org",
		PublicEndpoint: "front.example.org", PublicPort: wsPublicPort,
		WSPath: &wsPath,
	}

	got, err := Link("srv-1", in, goldenUsers()[0])
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	want := "vless://" + goldenUserVLESS +
		"@front.example.org:443?type=ws&security=tls&sni=front.example.org" +
		"&host=front.example.org&path=%2Fup#srv-1-vless-ws-ddg"
	if got != want {
		t.Errorf("ws URI:\n got %s\nwant %s", got, want)
	}
}

func TestLinkUnknownType(t *testing.T) {
	in := model.Inbound{Tag: "x", Type: model.InboundType("bogus"), PublicPort: wsPublicPort}
	if _, err := Link("srv-1", in, model.User{}); err == nil {
		t.Error("unknown inbound type must error")
	}
}
