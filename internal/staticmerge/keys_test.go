package staticmerge

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Arsolitt/cheburbox/generate"
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

// TestComputePinSHA256MatchesGenerate pins the local certificate pin to the
// control plane's generate.ComputePinSHA256, so the pin an operator declares
// is the one the control plane stores for the same certificate.
func TestComputePinSHA256MatchesGenerate(t *testing.T) {
	certPEM, _, err := generate.GenerateSelfSignedCertPEM("ams.example.com")
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}

	got, err := computePinSHA256(certPEM)
	if err != nil {
		t.Fatalf("computePinSHA256: %v", err)
	}
	want, err := generate.ComputePinSHA256(certPEM)
	if err != nil {
		t.Fatalf("generate.ComputePinSHA256: %v", err)
	}
	if got != want {
		t.Errorf("computePinSHA256 = %q, want %q", got, want)
	}
	if !strings.HasPrefix(got, pinPrefix) {
		t.Errorf("pin %q lacks the %q prefix", got, pinPrefix)
	}

	if _, err := computePinSHA256([]byte("not a certificate")); err == nil {
		t.Error("a malformed certificate must error")
	}
}
