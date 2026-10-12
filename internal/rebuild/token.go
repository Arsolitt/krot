// Package rebuild turns a provider subscription into one that carries krot's
// own routing profile. The operator's knobs — the provider URL, the proxy
// outbound tag, the ads and route modes — are sealed into a self-contained
// capability token ("rbr_..."), so the rewrite endpoint needs no database
// lookup: the token is the only credential it accepts and the provider URL
// never appears in krot's own links or logs.
package rebuild

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"

	up "github.com/Arsolitt/krot/internal/upstream"
)

const (
	// tokenPrefix marks a rebuild capability token, keeping it recognizable
	// in URLs and distinguishable from subscription tokens.
	tokenPrefix = "rbr_" // #nosec G101 -- token prefix, not a credential.
	// sessionNamespace namespaces the session-id HMAC message so the rebuild
	// key cannot be reused against other HMAC schemes sharing it.
	sessionNamespace = "rebuild-session:" // #nosec G101 -- HMAC input namespace, not a credential.
	// sessionIDBytes is the advertised session-id length in bytes (128-bit
	// space), rendering as 22 base64url characters.
	sessionIDBytes = 16
)

// Seal encrypts spec into a self-contained capability token: the JSON spec
// sealed with XChaCha20-Poly1305 under key, 24-byte random nonce prepended to
// the ciphertext, base64url without padding, prefixed with "rbr_". The token
// embeds the provider URL and its query secrets, so it must never be logged.
func Seal(key []byte, s up.Spec) (string, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", fmt.Errorf("rebuild: seal: %w", err)
	}
	payload, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("rebuild: seal: %w", err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("rebuild: seal: %w", err)
	}
	sealed := make([]byte, 0, len(nonce)+len(payload)+aead.Overhead())
	sealed = append(sealed, nonce...)
	sealed = aead.Seal(sealed, nonce, payload, nil)
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Open reverses Seal with the same key: it authenticates and decrypts the
// token and returns the embedded spec. Any failure — missing prefix, bad
// base64url, a payload shorter than nonce plus tag, failed authentication, or
// invalid JSON — is reported as an error, so callers treat every error as an
// unknown token and never parse untrusted fields.
func Open(key []byte, token string) (up.Spec, error) {
	var spec up.Spec
	raw, ok := strings.CutPrefix(token, tokenPrefix)
	if !ok {
		return spec, errors.New("rebuild: token: missing prefix")
	}
	sealed, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return spec, fmt.Errorf("rebuild: token: %w", err)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return spec, fmt.Errorf("rebuild: token: %w", err)
	}
	if len(sealed) < chacha20poly1305.NonceSizeX+aead.Overhead() {
		return spec, errors.New("rebuild: token: payload too short")
	}
	nonce, ciphertext := sealed[:chacha20poly1305.NonceSizeX], sealed[chacha20poly1305.NonceSizeX:]
	payload, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return spec, fmt.Errorf("rebuild: token: %w", err)
	}
	if err := json.Unmarshal(payload, &spec); err != nil {
		return spec, fmt.Errorf("rebuild: token: %w", err)
	}
	return spec, nil
}

// SessionID derives the stable per-token session id relayed to upstream
// providers for device counting: base64url(HMAC-SHA256(key,
// "rebuild-session:"+token)[:16]). The unkeyed token is hashed, not embedded,
// so the provider sees a device identity that reveals nothing about the
// upstream subscription URL.
func SessionID(key []byte, token string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(sessionNamespace + token))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:sessionIDBytes])
}
