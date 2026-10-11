package staticmerge

import (
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

// pinPrefix is the algorithm tag the control plane writes in front of a
// certificate pin, following the HPKP-style pinSHA256 form of the base
// deployment's own links.
const pinPrefix = "sha256/"

// derivePublicKey returns the public key of a base64 private key in the
// raw-url spelling the links carry. The private key may arrive in any base64
// spelling sing-box accepts (std, raw-std, raw-url). This mirrors the control
// plane's generate.DerivePublicKey; the two are pinned to each other by test,
// and the local copy keeps the agent from linking the whole cheburbox
// generator (jsonnet, tor, mieru and friends) for one x25519 operation.
func derivePublicKey(privateKeyBase64 string) (string, error) {
	raw, err := decodeBase64Key(privateKeyBase64)
	if err != nil {
		return "", err
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("x25519 private key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// computePinSHA256 returns the pin of a PEM certificate's public key:
// base64url(sha256(SPKI)) behind the "sha256/" tag. This mirrors the control
// plane's generate.ComputePinSHA256, pinned to it by test, so an operator can
// copy the pin the control plane computed from the same certificate.
func computePinSHA256(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", errors.New("decode certificate PEM: no block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal certificate public key: %w", err)
	}
	sum := sha256.Sum256(spki)
	return pinPrefix + base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
