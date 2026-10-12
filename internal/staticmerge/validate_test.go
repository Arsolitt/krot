package staticmerge

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arsolitt/cheburbox/generate"

	"github.com/Arsolitt/krot/internal/model"
)

// TestValidateTable covers one validation rule per case: every error names
// the merge target tag and the field that disagrees with the base.
func TestValidateTable(t *testing.T) {
	base := fixtureBase(t)
	valid := testDecls(t)
	publicKey := valid[0].RealityPublicKey
	shortID := valid[0].RealityShortID
	obfsPassword := valid[1].ObfsPassword
	_, otherPublicKey, err := generate.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	// Inline bases that isolate one rule each.
	wsBase := []byte(`{"inbounds":[{"type":"vless","tag":"vless-in","listen_port":443,"users":[],` +
		`"tls":{"server_name":"ams.example.com"}}]}`)
	transportBase := []byte(`{"inbounds":[{"type":"vless","tag":"vless-in","listen_port":443,"users":[],` +
		`"tls":{"server_name":"ams.example.com"},"transport":{"type":"http"}}]}`)
	noCertBase := fmt.Appendf(nil, `{"inbounds":[{"type":"hysteria2","tag":"hy2-in","listen_port":443,"users":[],`+
		`"obfs":{"type":"salamander","password":%q},"tls":{"server_name":"ams.example.com"}}]}`, obfsPassword)
	missingCertBase := fmt.Appendf(nil,
		`{"inbounds":[{"type":"hysteria2","tag":"hy2-in","listen_port":443,"users":[],`+
			`"obfs":{"type":"salamander","password":%q},`+
			`"tls":{"server_name":"ams.example.com","certificate_path":"certs/missing.crt"}}]}`, obfsPassword,
	)
	noPortBase := []byte(`{"inbounds":[{"type":"vless","tag":"vless-in","users":[],` +
		`"tls":{"server_name":"ams.example.com","reality":{"private_key":"` +
		fixtureString(t, base, "inbounds", 0, "tls", "reality", "private_key") + `","short_id":"` + shortID + `"}}}]}`)
	noSNIBase := fmt.Appendf(nil, `{"inbounds":[{"type":"hysteria2","tag":"hy2-in","listen_port":443,"users":[],`+
		`"obfs":{"type":"salamander","password":%q}}]}`, obfsPassword)
	badKeyBase := []byte(`{"inbounds":[{"type":"vless","tag":"vless-in","listen_port":443,"users":[],` +
		`"tls":{"server_name":"ams.example.com","reality":{"private_key":"not-base64!!","short_id":"deadbeef00"}}}]}`)

	wrongPort := valid[0]
	wrongPort.ListenPort = 8443
	wrongSNI := valid[0]
	wrongSNI.SNI = "other.example.com"
	noPublicKey := valid[0]
	noPublicKey.RealityPublicKey = ""
	wrongPublicKey := valid[0]
	wrongPublicKey.RealityPublicKey = otherPublicKey
	wrongShortID := valid[0]
	wrongShortID.RealityShortID = "deadbeef00"
	realityOnHy2 := valid[0]
	realityOnHy2.Tag = hy2Tag
	wsDecl := model.InboundDecl{Tag: vlessTag, Type: model.InboundVLESSWS, SNI: sni, ListenPort: 443}
	noObfs := valid[1]
	noObfs.ObfsPassword = ""
	wrongObfs := valid[1]
	wrongObfs.ObfsPassword = "not-the-base-obfs"
	noPin := valid[1]
	noPin.PinSHA256 = ""
	wrongPin := valid[1]
	wrongPin.PinSHA256 = strings.Repeat("ab", 32)
	hpkpPin := valid[1]
	hpkpPin.PinSHA256 = "sha256/0Ov4PXeAi3g0H7mTg7g4p8m5W0lJ7V9wD2hH3sQ1kZ0"

	cases := []struct {
		isErr  error
		name   string
		base   []byte
		decls  []model.InboundDecl
		fields []string
	}{
		{
			name: "missing tag",
			decls: []model.InboundDecl{
				{Tag: "nope", Type: model.InboundVLESSReality, RealityPublicKey: publicKey, RealityShortID: shortID},
			},
			fields: []string{"tag"},
		},
		{
			name:   "protocol mismatch",
			decls:  []model.InboundDecl{realityOnHy2},
			fields: []string{"type"},
		},
		{
			name:   "listen port mismatch",
			decls:  []model.InboundDecl{wrongPort},
			fields: []string{"listen_port"},
		},
		{
			name:   "sni mismatch",
			decls:  []model.InboundDecl{wrongSNI},
			fields: []string{"sni"},
		},
		{
			name:   "missing reality public key",
			decls:  []model.InboundDecl{noPublicKey},
			fields: []string{"reality_public_key"},
		},
		{
			name:   "incorrect reality public key",
			decls:  []model.InboundDecl{wrongPublicKey},
			fields: []string{"reality_public_key"},
		},
		{
			name:   "short id not in the base list",
			decls:  []model.InboundDecl{wrongShortID},
			fields: []string{"reality_short_id"},
		},
		{
			name:   "reality against a non-reality base",
			base:   wsBase,
			decls:  []model.InboundDecl{valid[0]},
			fields: []string{"tls.reality"},
		},
		{
			name:   "ws against a reality base",
			decls:  []model.InboundDecl{wsDecl},
			fields: []string{"tls.reality"},
		},
		{
			name:   "ws against a non-ws transport",
			base:   transportBase,
			decls:  []model.InboundDecl{wsDecl},
			fields: []string{"transport.type"},
		},
		{
			name:   "missing obfs password",
			decls:  []model.InboundDecl{noObfs},
			fields: []string{"obfs_password"},
		},
		{
			name:   "incorrect obfs password",
			decls:  []model.InboundDecl{wrongObfs},
			fields: []string{"obfs_password"},
		},
		{
			name:   "missing pin",
			decls:  []model.InboundDecl{noPin},
			fields: []string{"pin_sha256"},
		},
		{
			name:   "incorrect pin",
			decls:  []model.InboundDecl{wrongPin},
			fields: []string{"pin_sha256"},
		},
		{
			name:   "HPKP-form pin",
			decls:  []model.InboundDecl{hpkpPin},
			fields: []string{"pin_sha256", "HPKP"},
		},
		{
			name:   "missing certificate_path",
			base:   noCertBase,
			decls:  []model.InboundDecl{valid[1]},
			fields: []string{"certificate_path"},
		},
		{
			name:   "unreadable certificate",
			base:   missingCertBase,
			decls:  []model.InboundDecl{valid[1]},
			fields: []string{"certificate_path"},
			isErr:  fs.ErrNotExist,
		},
		{
			name:   "unsupported declared type",
			decls:  []model.InboundDecl{{Tag: "socks-in", Type: "socks", SNI: sni, ListenPort: 443}},
			fields: []string{"type"},
		},
		{
			name:   "base missing listen_port",
			base:   noPortBase,
			decls:  []model.InboundDecl{valid[0]},
			fields: []string{"listen_port"},
		},
		{
			name:   "base missing server_name",
			base:   noSNIBase,
			decls:  []model.InboundDecl{valid[1]},
			fields: []string{"tls.server_name"},
		},
		{
			name:   "base private key not base64",
			base:   badKeyBase,
			decls:  []model.InboundDecl{valid[0]},
			fields: []string{"reality_public_key"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			baseRaw := tc.base
			if baseRaw == nil {
				baseRaw = base
			}
			opts := Options{Base: baseRaw, DataDir: dataDir, Decls: tc.decls}
			err := Validate(opts)
			if err == nil {
				t.Fatal("Validate accepted an invalid declaration")
			}
			tag := tc.decls[0].Tag
			if !strings.Contains(err.Error(), tag) {
				t.Errorf("error %q does not name the tag %q", err, tag)
			}
			for _, field := range tc.fields {
				if !strings.Contains(err.Error(), field) {
					t.Errorf("error %q does not name the field %q", err, field)
				}
			}
			if tc.isErr != nil && !errors.Is(err, tc.isErr) {
				t.Errorf("error %q does not wrap %v", err, tc.isErr)
			}
		})
	}
}

// TestValidateBaseShape covers the base rule: the base must be valid JSON with
// a top-level inbounds array.
func TestValidateBaseShape(t *testing.T) {
	cases := []struct {
		name string
		base string
	}{
		{"invalid JSON", `{"inbounds":`},
		{"top level not an object", `[]`},
		{"missing inbounds array", `{"dns":{}}`},
		{"inbounds not an array", `{"inbounds":{}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Validate(Options{Base: []byte(tc.base)}); err == nil {
				t.Fatal("Validate accepted an invalid base config")
			}
		})
	}
	decls := []model.InboundDecl{{Tag: vlessTag, Type: model.InboundVLESSReality}}
	err := Validate(Options{Base: []byte(`{"inbounds":[]}`), Decls: decls})
	if err == nil || !strings.Contains(err.Error(), vlessTag) {
		t.Fatalf("Validate against an empty inbounds array: %v, want an error naming %q", err, vlessTag)
	}
}

// TestValidateAcceptsStringShortID covers the rule that a short_id spelled as
// a JSON string means the single id.
func TestValidateAcceptsStringShortID(t *testing.T) {
	privateKey := fixtureString(t, fixtureBase(t), "inbounds", 0, "tls", "reality", "private_key")
	publicKey, err := generate.DerivePublicKey(privateKey)
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	base := fmt.Appendf(nil, `{"inbounds":[{"type":"vless","tag":"vless-in","listen_port":443,"users":[],`+
		`"tls":{"server_name":"ams.example.com","reality":{"private_key":%q,"short_id":"deadbeef00"}}}]}`, privateKey)
	decl := model.InboundDecl{
		Tag: vlessTag, Type: model.InboundVLESSReality, SNI: sni, ListenPort: 443,
		RealityPublicKey: publicKey, RealityShortID: "deadbeef00",
	}
	if err := Validate(Options{Base: base, Decls: []model.InboundDecl{decl}}); err != nil {
		t.Fatalf("Validate rejected a string short_id: %v", err)
	}
	decl.RealityShortID = "deadbeef01"
	if err := Validate(Options{Base: base, Decls: []model.InboundDecl{decl}}); err == nil {
		t.Fatal("Validate accepted a short id the base does not offer")
	}
}

// TestValidateAcceptsKeySpellings covers the rule that std, raw-std and
// raw-url spellings of the same reality public key all validate.
func TestValidateAcceptsKeySpellings(t *testing.T) {
	decls := testDecls(t)
	raw, err := base64.RawURLEncoding.DecodeString(decls[0].RealityPublicKey)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	for _, spelling := range []string{
		decls[0].RealityPublicKey,
		base64.StdEncoding.EncodeToString(raw),
		base64.RawStdEncoding.EncodeToString(raw),
	} {
		decls[0].RealityPublicKey = spelling
		if err := Validate(Options{Base: fixtureBase(t), DataDir: dataDir, Decls: decls}); err != nil {
			t.Errorf("Validate rejected key spelling %q: %v", spelling, err)
		}
	}
}

// TestValidateAcceptsUppercasePin covers the rule that the declared pin is
// compared as hex, not as text: the same pin in upper case authenticates the
// same certificate and must pass.
func TestValidateAcceptsUppercasePin(t *testing.T) {
	decls := testDecls(t)
	decls[1].PinSHA256 = strings.ToUpper(decls[1].PinSHA256)
	if err := Validate(Options{Base: fixtureBase(t), DataDir: dataDir, Decls: decls}); err != nil {
		t.Fatalf("Validate rejected an upper-case hex pin: %v", err)
	}
}

// TestValidateAbsoluteCertificatePath covers the rule that an absolute
// certificate_path is used verbatim and never resolved against the data
// directory.
func TestValidateAbsoluteCertificatePath(t *testing.T) {
	absolute, err := filepath.Abs(filepath.Join(dataDir, "certs", sni+".crt"))
	if err != nil {
		t.Fatalf("resolve certificate path: %v", err)
	}
	pin, err := xrayCertPin(readCert(t))
	if err != nil {
		t.Fatalf("compute pin: %v", err)
	}
	base := fmt.Appendf(nil, `{"inbounds":[{"type":"hysteria2","tag":"hy2-in","listen_port":443,"users":[],`+
		`"obfs":{"type":"salamander","password":"fixture-obfs"},`+
		`"tls":{"server_name":"ams.example.com","certificate_path":%q}}]}`, absolute)
	decl := model.InboundDecl{
		Tag: hy2Tag, Type: model.InboundHysteria2, SNI: sni, ListenPort: 443,
		ObfsPassword: "fixture-obfs", PinSHA256: pin,
	}
	opts := Options{Base: base, DataDir: filepath.Join(t.TempDir(), "missing"), Decls: []model.InboundDecl{decl}}
	if err := Validate(opts); err != nil {
		t.Fatalf("Validate rejected an absolute certificate_path: %v", err)
	}
}

// TestValidateIgnoresInapplicablePinnedFields covers the rule that pinned
// fields a declared type does not use are inert.
func TestValidateIgnoresInapplicablePinnedFields(t *testing.T) {
	decls := testDecls(t)
	decls[0].ObfsPassword = "unused-obfs"
	decls[0].PinSHA256 = "sha256/unused"
	decls[1].RealityPublicKey = "unused-key"
	decls[1].RealityShortID = "unused-short-id"
	if err := Validate(Options{Base: fixtureBase(t), DataDir: dataDir, Decls: decls}); err != nil {
		t.Fatalf("Validate rejected inert pinned fields: %v", err)
	}
}
