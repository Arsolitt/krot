package staticmerge

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/Arsolitt/cheburbox/generate"

	"github.com/Arsolitt/krot/internal/model"
)

// sing-box protocol and transport names the declared inbound types map to.
const (
	protocolVLESS     = "vless"
	protocolHysteria2 = "hysteria2"
	transportWS       = "ws"
)

// validateAll checks every declaration against the parsed base, in order.
func validateAll(doc *baseDoc, decls []model.InboundDecl, dataDir string) error {
	for i := range decls {
		if err := validateDecl(doc, &decls[i], dataDir); err != nil {
			return err
		}
	}
	return nil
}

// baseProtocol maps a declared inbound type to the sing-box inbound type its
// base inbound must carry. The second result is false for unknown types.
func baseProtocol(t model.InboundType) (string, bool) {
	switch t {
	case model.InboundVLESSReality, model.InboundVLESSWS:
		return protocolVLESS, true
	case model.InboundHysteria2:
		return protocolHysteria2, true
	default:
		return "", false
	}
}

// validateDecl checks one declaration against the base: its tag must name a
// base inbound whose protocol, port, SNI and pinned credentials agree with
// the declaration. Fields a declared type does not use are inert.
func validateDecl(doc *baseDoc, decl *model.InboundDecl, dataDir string) error {
	want, ok := baseProtocol(decl.Type)
	if !ok {
		return errField(decl.Tag, keyType, "unsupported declared inbound type %q", decl.Type)
	}
	in, ok := doc.byTag(decl.Tag)
	if !ok {
		return errField(decl.Tag, keyTag, "base config has no inbound with this tag")
	}
	if err := checkProtocol(doc.raw, in, decl, want); err != nil {
		return err
	}
	if err := checkPort(doc.raw, in, decl); err != nil {
		return err
	}
	if err := checkSNI(doc.raw, in, decl); err != nil {
		return err
	}
	if decl.Type == model.InboundVLESSReality {
		return checkReality(doc.raw, in, decl)
	}
	if decl.Type == model.InboundHysteria2 {
		return checkHysteria2(doc.raw, in, decl, dataDir)
	}
	// A vless_ws declaration pins no credentials, so nothing else to check.
	return nil
}

// checkProtocol requires the base inbound to carry the sing-box type the
// declaration maps to and the reality or ws shape the declared type implies.
func checkProtocol(raw []byte, in *baseInbound, decl *model.InboundDecl, want string) error {
	got, ok := in.text(raw, keyType)
	if !ok {
		return errField(decl.Tag, keyType, "base inbound has no string %q member", keyType)
	}
	if got != want {
		return errField(decl.Tag, keyType,
			"base inbound type %q does not match declared type %q (want %q)", got, decl.Type, want)
	}
	if decl.Type == model.InboundVLESSReality {
		if _, ok := in.member(raw, keyTLS, keyReality); !ok {
			return errField(decl.Tag, "tls.reality",
				"base inbound has no reality block required by the declared type")
		}
	}
	if decl.Type == model.InboundVLESSWS {
		if _, ok := in.member(raw, keyTLS, keyReality); ok {
			return errField(decl.Tag, "tls.reality",
				"base inbound is a reality inbound, which the declared type does not use")
		}
		if err := checkTransport(raw, in, decl); err != nil {
			return err
		}
	}
	return nil
}

// checkTransport requires a base inbound that carries a transport to use the
// ws transport, and only when the declared type implies it.
func checkTransport(raw []byte, in *baseInbound, decl *model.InboundDecl) error {
	value, ok := in.member(raw, keyTransport)
	if !ok {
		return nil
	}
	members, ok := rawMembers(value)
	if !ok {
		return errField(decl.Tag, "transport.type", "base inbound transport is not an object")
	}
	got, ok := rawString(members[keyType])
	if !ok {
		return errField(decl.Tag, "transport.type", "base inbound transport has no string %q member", keyType)
	}
	if got != transportWS {
		return errField(decl.Tag, "transport.type", "base transport type %q is not %q", got, transportWS)
	}
	return nil
}

// checkPort requires the declared port to be the one the base inbound binds.
func checkPort(raw []byte, in *baseInbound, decl *model.InboundDecl) error {
	base, ok := in.integer(raw, keyListenPort)
	if !ok {
		return errField(decl.Tag, keyListenPort, "base inbound has no integer %q member", keyListenPort)
	}
	if decl.ListenPort != base {
		return errField(decl.Tag, keyListenPort, "declared %d does not match base %d", decl.ListenPort, base)
	}
	return nil
}

// checkSNI requires the declared SNI to be the server_name the base inbound's
// TLS block carries.
func checkSNI(raw []byte, in *baseInbound, decl *model.InboundDecl) error {
	base, ok := in.text(raw, keyTLS, keyServerName)
	if !ok || base == "" {
		return errField(decl.Tag, "tls.server_name", "base inbound has no non-empty %q string", keyServerName)
	}
	if decl.SNI != base {
		return errField(decl.Tag, "sni", "declared %q does not match base tls.server_name %q", decl.SNI, base)
	}
	return nil
}

// checkReality requires the pinned reality credentials to match the base
// inbound's reality block: the public key is derived from the base's private
// key — any base64 spelling of the same key matches — and the short id must be
// one the base offers.
func checkReality(raw []byte, in *baseInbound, decl *model.InboundDecl) error {
	if decl.RealityPublicKey == "" {
		return errField(decl.Tag, "reality_public_key", "required for declared type %q", decl.Type)
	}
	privateKey, ok := in.text(raw, keyTLS, keyReality, keyPrivateKey)
	if !ok || privateKey == "" {
		return errField(decl.Tag, "tls.reality.private_key", "base inbound has no non-empty %q string", keyPrivateKey)
	}
	derived, err := generate.DerivePublicKey(privateKey)
	if err != nil {
		return fmt.Errorf("inbound %q: reality_public_key: derive base public key: %w", decl.Tag, err)
	}
	if !sameKey(decl.RealityPublicKey, derived) {
		return errField(decl.Tag, "reality_public_key",
			"does not match the public key of the base reality private key")
	}
	if decl.RealityShortID == "" {
		return errField(decl.Tag, "reality_short_id", "required for declared type %q", decl.Type)
	}
	return checkShortID(raw, in, decl)
}

// checkShortID requires the declared short id to be a member of the base's
// short_id list; the list is a JSON string when the base declares a single id.
func checkShortID(raw []byte, in *baseInbound, decl *model.InboundDecl) error {
	value, ok := in.member(raw, keyTLS, keyReality, keyShortID)
	if !ok {
		return errField(decl.Tag, "tls.reality.short_id", "base inbound has no %q member", keyShortID)
	}
	list, ok := rawStrings(value)
	if !ok || len(list) == 0 {
		return errField(decl.Tag, "tls.reality.short_id",
			"base %q is not a string or a non-empty array of strings", keyShortID)
	}
	if !slices.Contains(list, decl.RealityShortID) {
		return errField(decl.Tag, "reality_short_id", "%q is not in the base short_id list", decl.RealityShortID)
	}
	return nil
}

// checkHysteria2 requires the pinned obfs password and certificate pin to
// match the base inbound's obfs password and the certificate the base serves.
func checkHysteria2(raw []byte, in *baseInbound, decl *model.InboundDecl, dataDir string) error {
	if decl.ObfsPassword == "" {
		return errField(decl.Tag, "obfs_password", "required for declared type %q", decl.Type)
	}
	base, ok := in.text(raw, keyObfs, keyPassword)
	if !ok || base == "" {
		return errField(decl.Tag, "obfs.password", "base inbound has no non-empty %q string", keyPassword)
	}
	if decl.ObfsPassword != base {
		return errField(decl.Tag, "obfs_password", "does not match the base obfs password")
	}
	if decl.PinSHA256 == "" {
		return errField(decl.Tag, "pin_sha256", "required for declared type %q", decl.Type)
	}
	return checkPin(raw, in, decl, dataDir)
}

// checkPin requires the declared pin to equal the pin of the certificate the
// base inbound serves: certificate_path is used verbatim when absolute and
// resolved against the data directory when relative.
func checkPin(raw []byte, in *baseInbound, decl *model.InboundDecl, dataDir string) error {
	path, ok := in.text(raw, keyTLS, keyCertificatePath)
	if !ok || path == "" {
		return errField(decl.Tag, "tls.certificate_path", "base inbound has no non-empty %q string", keyCertificatePath)
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(dataDir, path)
	}
	certPEM, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("inbound %q: tls.certificate_path: read certificate %s: %w", decl.Tag, path, err)
	}
	pin, err := generate.ComputePinSHA256(certPEM)
	if err != nil {
		return fmt.Errorf("inbound %q: pin_sha256: compute certificate pin: %w", decl.Tag, err)
	}
	if decl.PinSHA256 != pin {
		return errField(decl.Tag, "pin_sha256", "does not match the base certificate pin")
	}
	return nil
}

// errField builds a validation error that names the merge target tag and the
// field the declaration disagrees with the base on.
func errField(tag string, field string, format string, args ...any) error {
	return fmt.Errorf("inbound %q: %s: %s", tag, field, fmt.Sprintf(format, args...))
}

// sameKey reports whether two base64 key spellings decode to the same bytes.
// The same key may be spelled std, raw-std or raw-url, so comparing the
// spellings themselves is not enough.
func sameKey(a string, b string) bool {
	decodedA, errA := decodeBase64Key(a)
	decodedB, errB := decodeBase64Key(b)
	return errA == nil && errB == nil && bytes.Equal(decodedA, decodedB)
}

// decodeBase64Key decodes a base64 key in any spelling sing-box accepts: std,
// raw-std or raw-url, mirroring generate.DerivePublicKey.
func decodeBase64Key(s string) ([]byte, error) {
	for _, encoding := range [...]*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	} {
		if decoded, err := encoding.DecodeString(s); err == nil {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("decode base64 key: all encodings failed for %q", s)
}
