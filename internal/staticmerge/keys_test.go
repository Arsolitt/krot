package staticmerge

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"

	"github.com/Arsolitt/cheburbox/generate"

	"github.com/Arsolitt/krot/internal/model"
	"github.com/Arsolitt/krot/internal/render"
)

// TestDerivePublicKeyMatchesGenerate pins the local x25519 derivation to the
// control plane's generate.DerivePublicKey: the agent and the control plane
// must agree on the public key of one private key byte for byte, whatever
// base64 spelling the private key arrives in.
func TestDerivePublicKeyMatchesGenerate(t *testing.T) {
	privateKey, publicKey, err := generate.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	got, err := derivePublicKey(privateKey)
	if err != nil {
		t.Fatalf("derivePublicKey(%s): %v", privateKey, err)
	}
	if got != publicKey {
		t.Errorf("derivePublicKey = %q, want generate's %q", got, publicKey)
	}

	// The same key in the std spelling derives the same public key.
	raw, err := base64.RawURLEncoding.DecodeString(privateKey)
	if err != nil {
		t.Fatalf("decode raw-url key: %v", err)
	}
	std, err := derivePublicKey(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatalf("derivePublicKey(std spelling): %v", err)
	}
	if std != publicKey {
		t.Errorf("std spelling derived %q, want %q", std, publicKey)
	}

	if _, err := derivePublicKey("not base64!"); err == nil {
		t.Error("a malformed private key must error")
	}
}

// TestXrayCertPinMatchesLinks pins the pin the agent validates to the one the
// control plane puts in a hysteria2 link: validation and the link builder must
// agree byte for byte on the same certificate, and the value must be the hex
// form a pinSHA256 parameter carries rather than the HPKP form, which clients
// fail to hex-decode.
func TestXrayCertPinMatchesLinks(t *testing.T) {
	certPEM, _, err := generate.GenerateSelfSignedCertPEM("ams.example.com")
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}

	got, err := xrayCertPin(certPEM)
	if err != nil {
		t.Fatalf("xrayCertPin: %v", err)
	}
	if _, err := hex.DecodeString(got); err != nil {
		t.Fatalf("pin %q is not hex: %v", got, err)
	}
	if strings.HasPrefix(got, hpkpPinPrefix) {
		t.Errorf("pin %q must not carry the HPKP prefix", got)
	}

	uri, err := render.Link("ams-p-1", model.Inbound{
		Tag: "hy2-in", Type: model.InboundHysteria2, SNI: "ams.example.com",
		ListenPort: 443, PublicEndpoint: "ams.example.com", PublicPort: 443,
		ObfsPassword: "obfs-password", CertPEM: string(certPEM),
	}, model.User{Name: "u", Hy2Password: "password"})
	if err != nil {
		t.Fatalf("render.Link: %v", err)
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("parse link: %v", err)
	}
	if want := parsed.Query().Get("pinSHA256"); got != want {
		t.Errorf("xrayCertPin = %q, but the link carries pinSHA256=%q", got, want)
	}

	if _, err := xrayCertPin([]byte("not a certificate")); err == nil {
		t.Error("a malformed certificate must error")
	}
}
