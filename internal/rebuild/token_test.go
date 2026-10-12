package rebuild

import (
	"encoding/base64"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

	up "github.com/Arsolitt/krot/internal/upstream"
)

// testKey is a fixed 32-byte key for deterministic token tests.
var testKey = []byte("0123456789abcdef0123456789abcdef")

// sessionIDChars is the advertised session-id length in base64url characters.
const sessionIDChars = 22

// testSpec is the spec exercised by the token tests, with every field set.
func testSpec() up.Spec {
	return up.Spec{
		UpstreamURL: "https://provider.example/sub?token=abc123",
		ProxyTag:    "proxy",
		AdsMode:     "full",
		RouteMode:   "replace",
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		spec up.Spec
	}{
		{"all fields", testSpec()},
		{"url only", up.Spec{UpstreamURL: "https://provider.example/sub"}},
		{"empty spec", up.Spec{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token, err := Seal(testKey, tc.spec)
			if err != nil {
				t.Fatalf("Seal() error = %v", err)
			}
			if !strings.HasPrefix(token, tokenPrefix) {
				t.Fatalf("Seal() = %q, want %q prefix", token, tokenPrefix)
			}
			if strings.Contains(token, "provider.example") {
				t.Fatalf("Seal() leaks the upstream URL: %q", token)
			}
			got, err := Open(testKey, token)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			if got != tc.spec {
				t.Fatalf("Open(Seal(spec)) = %+v, want %+v", got, tc.spec)
			}
		})
	}
}

func TestSealNonceUnique(t *testing.T) {
	first, err := Seal(testKey, testSpec())
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	second, err := Seal(testKey, testSpec())
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if first == second {
		t.Fatal("Seal() returned identical tokens for the same spec")
	}
}

func TestOpenRejects(t *testing.T) {
	base, err := Seal(testKey, testSpec())
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	sealed, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(base, tokenPrefix))
	if err != nil {
		t.Fatalf("decode sealed payload: %v", err)
	}
	// junk is a well-formed sealed token whose plaintext is not JSON: only a
	// holder of the key can produce it, so it reaches the payload-shape check
	// instead of failing authentication.
	aead, err := chacha20poly1305.NewX(testKey)
	if err != nil {
		t.Fatalf("NewX() error = %v", err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	junk := append(slices.Clone(nonce), aead.Seal(nil, nonce, []byte("not json"), nil)...)
	reencoded := func(b []byte) string { return tokenPrefix + base64.RawURLEncoding.EncodeToString(b) }

	cases := []struct {
		name  string
		token string
		key   []byte
	}{
		{"missing prefix", strings.TrimPrefix(base, tokenPrefix), testKey},
		{"empty token", "", testKey},
		{"prefix only", tokenPrefix, testKey},
		{"bad base64", tokenPrefix + "not*base64", testKey},
		{"payload shorter than nonce and tag", reencoded(sealed[:chacha20poly1305.NonceSizeX-1]), testKey},
		{"truncated ciphertext", reencoded(sealed[:len(sealed)-1]), testKey},
		{"tampered nonce", reencoded(flipByte(sealed, 0)), testKey},
		{"tampered ciphertext", reencoded(flipByte(sealed, len(sealed)-1)), testKey},
		{"wrong key", base, []byte("abcdef0123456789abcdef0123456789")},
		{"short key", base, testKey[:chacha20poly1305.KeySize-1]},
		{"valid ciphertext, invalid JSON", reencoded(junk), testKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Open(tc.key, tc.token)
			if err == nil {
				t.Fatalf("Open() = %+v, want error", got)
			}
			if got != (up.Spec{}) {
				t.Fatalf("Open() on failure = %+v, want zero spec", got)
			}
		})
	}
}

// flipByte returns a copy of b with the byte at i complemented.
func flipByte(b []byte, i int) []byte {
	out := slices.Clone(b)
	out[i] = ^out[i]
	return out
}

func TestSessionID(t *testing.T) {
	cases := []struct {
		name  string
		token string
		want  string
	}{
		// Golden values computed independently of this implementation:
		// base64url without padding of HMAC-SHA256(key,
		// "rebuild-session:"+token) truncated to 16 bytes.
		{"first", "rbr_test-token", "tXz81gW1avNWUVr66dmeKA"},
		{"second", "rbr_second-token", "kVFAWK4kB0SYf0cZ8WJJwA"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SessionID(testKey, tc.token)
			if got != tc.want {
				t.Fatalf("SessionID() = %q, want %q", got, tc.want)
			}
			if len(got) != sessionIDChars {
				t.Fatalf("SessionID() length = %d, want %d", len(got), sessionIDChars)
			}
			if again := SessionID(testKey, tc.token); again != got {
				t.Fatalf("SessionID() not deterministic: %q then %q", got, again)
			}
		})
	}

	first, err := Seal(testKey, testSpec())
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	second, err := Seal(testKey, testSpec())
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	ids := map[string]bool{
		SessionID(testKey, first):                                    true,
		SessionID(testKey, second):                                   true,
		SessionID([]byte("abcdef0123456789abcdef0123456789"), first): true,
	}
	if len(ids) != 3 {
		t.Fatalf("session ids collide across tokens or keys: %v", ids)
	}
}
