package staticmerge

import (
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
)

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

// xrayCertPin returns the pin of a PEM certificate in the form a hysteria2
// link's pinSHA256 parameter carries: lowercase hex of sha256 over the leaf
// certificate DER. Xray hex-decodes that parameter, so the HPKP-style
// "sha256/<base64>" pin of a sing-box certificate_public_key_sha256 setting
// cannot ride in it. The dynamic render path derives the same value from the
// stored certificate; the two are pinned to each other by test.
func xrayCertPin(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", errors.New("decode certificate PEM: no block found")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}
