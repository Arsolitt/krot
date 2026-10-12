package staticmerge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Arsolitt/cheburbox/generate"

	"github.com/Arsolitt/krot/internal/model"
)

// Fixture constants: the sanitized base config, the data directory its
// relative certificate_path resolves against, and the credentials the merge
// tests feed in.
const (
	basePath = "testdata/base.json"
	dataDir  = "testdata/data"
	sni      = "ams.example.com"

	vlessTag = "vless-in"
	hy2Tag   = "hy2-in"

	legacyVLESSUsers = 3
	legacyHy2Users   = 3

	legacyFlow = "xtls-rprx-vision"

	carolName = "carol"
	carolUUID = "c4a1f0e2-8ab3-4c0e-9b1b-7b8a1c2d3e4f"
	carolPass = "carol-hy2-pass"
	daveName  = "dave"
	daveUUID  = "d5b2c3d4-1234-4abc-9def-0123456789ab"
	davePass  = "dave-hy2-pass"

	// elementIndent is the fixture's users-array element indentation, which
	// appended entries must imitate.
	elementIndent = "        "
)

// TestRenderAppendsUsers covers the merge rule: both declared targets get the
// control plane users appended with the right element shape and the base's
// own flow, the base users and every other config part survive, and the base
// bytes are recoverable by cutting exactly the inserted text out.
func TestRenderAppendsUsers(t *testing.T) {
	base := fixtureBase(t)
	opts := Options{Base: base, DataDir: dataDir, Decls: testDecls(t), Users: inputUsers()}
	rendered, err := Render(opts)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	// Appended entries: name and credential from the input user, flow copied
	// from the base's first legacy entry.
	tree := fixtureTree(t, rendered)
	vlessUsers := fixtureUsers(t, fixtureInbound(t, tree, vlessTag))
	hy2Users := fixtureUsers(t, fixtureInbound(t, tree, hy2Tag))
	if got, want := len(vlessUsers), legacyVLESSUsers+len(inputUsers()); got != want {
		t.Fatalf("vless users = %d, want %d", got, want)
	}
	if got, want := len(hy2Users), legacyHy2Users+len(inputUsers()); got != want {
		t.Fatalf("hysteria2 users = %d, want %d", got, want)
	}
	wantVLESS := []map[string]any{
		{"name": carolName, "uuid": carolUUID, "flow": legacyFlow},
		{"name": daveName, "uuid": daveUUID, "flow": legacyFlow},
	}
	for i, want := range wantVLESS {
		if got := vlessUsers[legacyVLESSUsers+i]; !reflect.DeepEqual(got, want) {
			t.Errorf("appended vless user %d = %#v, want %#v", i, got, want)
		}
	}
	wantHy2 := []map[string]any{
		{"name": carolName, "password": carolPass},
		{"name": daveName, "password": davePass},
	}
	for i, want := range wantHy2 {
		if got := hy2Users[legacyHy2Users+i]; !reflect.DeepEqual(got, want) {
			t.Errorf("appended hysteria2 user %d = %#v, want %#v", i, got, want)
		}
	}

	// Legacy users are intact and every other config part survives: with the
	// appended tails removed, the rendered tree equals the base tree.
	baseTree := fixtureTree(t, base)
	if got := vlessUsers[:legacyVLESSUsers]; !reflect.DeepEqual(
		got,
		fixtureUsers(t, fixtureInbound(t, baseTree, vlessTag)),
	) {
		t.Error("legacy vless users changed")
	}
	if got := hy2Users[:legacyHy2Users]; !reflect.DeepEqual(got, fixtureUsers(t, fixtureInbound(t, baseTree, hy2Tag))) {
		t.Error("legacy hysteria2 users changed")
	}
	stripped := fixtureTree(t, rendered)
	for _, appended := range []struct {
		tag   string
		count int
	}{{vlessTag, len(inputUsers())}, {hy2Tag, len(inputUsers())}} {
		in := fixtureInbound(t, stripped, appended.tag)
		users := fixtureUsers(t, in)
		in["users"] = users[:len(users)-appended.count]
	}
	if !reflect.DeepEqual(stripped, baseTree) {
		t.Error("rendered config differs from the base outside the appended entries")
	}
	if fixtureInbound(t, tree, vlessTag)["x-unknown-marker"] == nil {
		t.Error("unknown inbound field dropped from the rendered config")
	}
	if tree["x-unknown-top-level"] == nil {
		t.Error("unknown top-level member dropped from the rendered config")
	}

	// The base bytes are recoverable: each inserted text occurs exactly once
	// and cutting it out restores the base byte for byte.
	restored := rendered
	insertedTexts := []string{
		insertedText(vlessEntryText(carolName, carolUUID), vlessEntryText(daveName, daveUUID)),
		insertedText(hy2EntryText(carolName, carolPass), hy2EntryText(daveName, davePass)),
	}
	for _, inserted := range insertedTexts {
		if count := bytes.Count(restored, []byte(inserted)); count != 1 {
			t.Fatalf("inserted text occurs %d times, want 1: %q", count, inserted)
		}
		restored = bytes.Replace(restored, []byte(inserted), nil, 1)
	}
	if !bytes.Equal(restored, base) {
		t.Error("cutting the inserted text out did not restore the base bytes")
	}
}

// TestRenderIdempotent covers the idempotency rule: identical inputs produce
// identical bytes, and re-rendering the merged output — which already carries
// the credentials — appends nothing.
func TestRenderIdempotent(t *testing.T) {
	base := fixtureBase(t)
	opts := Options{Base: base, DataDir: dataDir, Decls: testDecls(t), Users: inputUsers()}
	first, err := Render(opts)
	if err != nil {
		t.Fatalf("first render: %v", err)
	}
	second, err := Render(opts)
	if err != nil {
		t.Fatalf("second render: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Error("two renders of identical inputs differ")
	}
	third, err := Render(Options{Base: first, DataDir: dataDir, Decls: testDecls(t), Users: inputUsers()})
	if err != nil {
		t.Fatalf("third render: %v", err)
	}
	if !bytes.Equal(third, first) {
		t.Error("rendering the merged output changed it")
	}
}

// TestRenderNoUsers covers the rule that without users the base is returned
// verbatim.
func TestRenderNoUsers(t *testing.T) {
	base := fixtureBase(t)
	rendered, err := Render(Options{Base: base, DataDir: dataDir, Decls: testDecls(t)})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !bytes.Equal(rendered, base) {
		t.Error("render with no users did not return the base verbatim")
	}
}

// TestRenderNoDecls covers the rule that without declarations the base is
// returned verbatim.
func TestRenderNoDecls(t *testing.T) {
	base := fixtureBase(t)
	rendered, err := Render(Options{Base: base, DataDir: dataDir, Users: inputUsers()})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !bytes.Equal(rendered, base) {
		t.Error("render with no declarations did not return the base verbatim")
	}
}

// TestRenderDedup covers the dedup rules: a credential the base already
// serves — uuid compared case-insensitively, password exactly — a credential
// repeated within the input and an empty credential are all skipped.
func TestRenderDedup(t *testing.T) {
	base := fixtureBase(t)
	legacyUUID := fixtureString(t, base, "inbounds", 0, "users", 0, "uuid")
	legacyPass := fixtureString(t, base, "inbounds", 1, "users", 0, "password")
	users := []model.User{
		{Name: "base-duplicate", VLESSUUID: strings.ToUpper(legacyUUID), Hy2Password: legacyPass},
		{Name: carolName, VLESSUUID: carolUUID, Hy2Password: carolPass},
		{Name: "input-duplicate", VLESSUUID: strings.ToUpper(carolUUID), Hy2Password: carolPass},
		{Name: "no-credentials"},
	}
	rendered, err := Render(Options{Base: base, DataDir: dataDir, Decls: testDecls(t), Users: users})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	tree := fixtureTree(t, rendered)
	vlessUsers := fixtureUsers(t, fixtureInbound(t, tree, vlessTag))
	hy2Users := fixtureUsers(t, fixtureInbound(t, tree, hy2Tag))
	if got, want := len(vlessUsers), legacyVLESSUsers+1; got != want {
		t.Fatalf("vless users = %d, want %d", got, want)
	}
	if got, want := len(hy2Users), legacyHy2Users+1; got != want {
		t.Fatalf("hysteria2 users = %d, want %d", got, want)
	}
	lastVLESS, ok := vlessUsers[len(vlessUsers)-1].(map[string]any)
	if !ok || lastVLESS["uuid"] != carolUUID {
		t.Errorf("appended vless user = %#v, want uuid %q", lastVLESS, carolUUID)
	}
	lastHy2, ok := hy2Users[len(hy2Users)-1].(map[string]any)
	if !ok || lastHy2["password"] != carolPass {
		t.Errorf("appended hysteria2 user = %#v, want password %q", lastHy2, carolPass)
	}
	for _, users := range [][]any{vlessUsers, hy2Users} {
		assertUniqueCredentials(t, users)
	}
}

// TestRenderPasswordCaseSensitive covers the rule that passwords are compared
// exactly: a case variant of a base password is a new credential.
func TestRenderPasswordCaseSensitive(t *testing.T) {
	base := fixtureBase(t)
	legacyPass := fixtureString(t, base, "inbounds", 1, "users", 0, "password")
	users := []model.User{{Name: "case-variant", Hy2Password: strings.ToUpper(legacyPass)}}
	rendered, err := Render(Options{Base: base, DataDir: dataDir, Decls: testDecls(t), Users: users})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	hy2Users := fixtureUsers(t, fixtureInbound(t, fixtureTree(t, rendered), hy2Tag))
	if got, want := len(hy2Users), legacyHy2Users+1; got != want {
		t.Fatalf("hysteria2 users = %d, want %d", got, want)
	}
}

// TestRenderValidates covers the rule that rendering validates first: an
// invalid declaration fails the render before anything is spliced.
func TestRenderValidates(t *testing.T) {
	decls := testDecls(t)
	decls[0].SNI = "other.example.com"
	_, err := Render(Options{Base: fixtureBase(t), DataDir: dataDir, Decls: decls, Users: inputUsers()})
	if err == nil || !strings.Contains(err.Error(), "sni") {
		t.Fatalf("Render of an invalid declaration: %v, want an error naming the field", err)
	}
}

// TestRenderDoesNotMutateBase covers the rule that the caller's base slice is
// only read.
func TestRenderDoesNotMutateBase(t *testing.T) {
	base := fixtureBase(t)
	snapshot := bytes.Clone(base)
	opts := Options{Base: base, DataDir: dataDir, Decls: testDecls(t), Users: inputUsers()}
	if _, err := Render(opts); err != nil {
		t.Fatalf("render: %v", err)
	}
	if !bytes.Equal(base, snapshot) {
		t.Error("render mutated the caller's base slice")
	}
}

// TestRenderInsertsUsersMember covers the rule that an inbound without a
// users member gets one appended as its last member, compact and preceded by
// the comma that member needs.
func TestRenderInsertsUsersMember(t *testing.T) {
	base := []byte(`{
  "inbounds": [
    {
      "type": "hysteria2",
      "tag": "hy2-in",
      "listen_port": 443,
      "obfs": {
        "type": "salamander",
        "password": "fixture-obfs"
      },
      "tls": {
        "server_name": "ams.example.com",
        "certificate_path": "certs/ams.example.com.crt"
      },
      "masquerade": {
        "type": "proxy"
      }
    }
  ]
}
`)
	decls := []model.InboundDecl{hy2Decl(t, "fixture-obfs")}
	rendered, err := Render(Options{Base: base, DataDir: dataDir, Decls: decls, Users: inputUsers()[:1]})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	inserted := `,"users":[` + hy2EntryText(carolName, carolPass) + `]`
	if !bytes.Contains(rendered, []byte(inserted)) {
		t.Fatalf("rendered config does not carry %q:\n%s", inserted, rendered)
	}
	// The member lands right after the object's last existing member.
	if want := "      }" + inserted + "\n    }"; !bytes.Contains(rendered, []byte(want)) {
		t.Errorf("users member is not spliced after the last member:\n%s", rendered)
	}
	if restored := bytes.Replace(rendered, []byte(inserted), nil, 1); !bytes.Equal(restored, base) {
		t.Error("cutting the inserted users member did not restore the base")
	}
}

// TestRenderFillsEmptyUsersArray covers the rule that an empty users array is
// filled with compact entries and no leading comma.
func TestRenderFillsEmptyUsersArray(t *testing.T) {
	base := []byte(`{
  "inbounds": [
    {
      "type": "hysteria2",
      "tag": "hy2-in",
      "listen_port": 443,
      "users": [],
      "obfs": {
        "type": "salamander",
        "password": "fixture-obfs"
      },
      "tls": {
        "server_name": "ams.example.com",
        "certificate_path": "certs/ams.example.com.crt"
      }
    }
  ]
}
`)
	decls := []model.InboundDecl{hy2Decl(t, "fixture-obfs")}
	rendered, err := Render(Options{Base: base, DataDir: dataDir, Decls: decls, Users: inputUsers()})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	inserted := hy2EntryText(carolName, carolPass) + "," + hy2EntryText(daveName, davePass)
	if want := `"users": [` + inserted + "]"; !bytes.Contains(rendered, []byte(want)) {
		t.Fatalf("rendered config does not carry %q:\n%s", want, rendered)
	}
	if restored := bytes.Replace(rendered, []byte(inserted), nil, 1); !bytes.Equal(restored, base) {
		t.Error("cutting the inserted entries out did not restore the base")
	}
}

// TestRenderKeepsCompactLayout covers the rule that appended entries take no
// indentation when the base does not lay its array elements out on their own
// lines.
func TestRenderKeepsCompactLayout(t *testing.T) {
	base := []byte(`{"inbounds":[{"type":"hysteria2","tag":"hy2-in","listen_port":443,` +
		`"obfs":{"type":"salamander","password":"fixture-obfs"},` +
		`"tls":{"server_name":"ams.example.com","certificate_path":"certs/ams.example.com.crt"},` +
		`"users":[{"name":"legacy","password":"legacy-pass"}]}]}`)
	decls := []model.InboundDecl{hy2Decl(t, "fixture-obfs")}
	rendered, err := Render(Options{Base: base, DataDir: dataDir, Decls: decls, Users: inputUsers()[:1]})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	inserted := ",\n" + hy2EntryText(carolName, carolPass)
	if want := `{"name":"legacy","password":"legacy-pass"}` + inserted + "]"; !bytes.Contains(rendered, []byte(want)) {
		t.Fatalf("rendered config does not carry %q:\n%s", want, rendered)
	}
	if restored := bytes.Replace(rendered, []byte(inserted), nil, 1); !bytes.Equal(restored, base) {
		t.Error("cutting the inserted entry out did not restore the base")
	}
}

// TestRenderOmitsFlowWhenBaseHasNone covers the rule that appended vless
// entries omit the flow key when no base entry carries one.
func TestRenderOmitsFlowWhenBaseHasNone(t *testing.T) {
	privateKey := fixtureString(t, fixtureBase(t), "inbounds", 0, "tls", "reality", "private_key")
	publicKey, err := generate.DerivePublicKey(privateKey)
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	base := fmt.Appendf(nil, `{"inbounds":[{"type":"vless","tag":"vless-in","listen_port":443,`+
		`"users":[{"name":"legacy","uuid":"45977ea3-f264-4671-bec9-5195fa960936"}],`+
		`"tls":{"server_name":"ams.example.com","reality":{"private_key":%q,"short_id":"236205ea41fa19be"}}}]}`, privateKey)
	decls := []model.InboundDecl{{
		Tag: vlessTag, Type: model.InboundVLESSReality, SNI: sni, ListenPort: 443,
		RealityPublicKey: publicKey, RealityShortID: "236205ea41fa19be",
	}}
	rendered, err := Render(Options{Base: base, DataDir: dataDir, Decls: decls, Users: inputUsers()[:1]})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	inserted := ",\n" + fmt.Sprintf(`{"name":%q,"uuid":%q}`, carolName, carolUUID)
	if want := `{"name":"legacy","uuid":"45977ea3-f264-4671-bec9-5195fa960936"}` + inserted + "]"; !bytes.Contains(
		rendered,
		[]byte(want),
	) {
		t.Fatalf("rendered config does not carry %q:\n%s", want, rendered)
	}
	if bytes.Contains(rendered, []byte(`"flow"`)) {
		t.Errorf("appended entry carries a flow the base does not use:\n%s", rendered)
	}
	if restored := bytes.Replace(rendered, []byte(inserted), nil, 1); !bytes.Equal(restored, base) {
		t.Error("cutting the inserted entry out did not restore the base")
	}
}

// inputUsers returns the control plane users the merge tests feed in: one
// credential of each protocol family per user.
func inputUsers() []model.User {
	return []model.User{
		{Name: carolName, VLESSUUID: carolUUID, Hy2Password: carolPass},
		{Name: daveName, VLESSUUID: daveUUID, Hy2Password: davePass},
	}
}

// testDecls returns both fixture merge targets with pins derived from the
// base: the reality public key from the base's private key and the hysteria2
// pin from the certificate the base serves.
func testDecls(t *testing.T) []model.InboundDecl {
	t.Helper()
	base := fixtureBase(t)
	publicKey, err := generate.DerivePublicKey(
		fixtureString(t, base, "inbounds", 0, "tls", "reality", "private_key"))
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	return []model.InboundDecl{
		{
			Tag: vlessTag, Type: model.InboundVLESSReality, SNI: sni, ListenPort: 443,
			RealityPublicKey: publicKey,
			RealityShortID:   fixtureString(t, base, "inbounds", 0, "tls", "reality", "short_id", 0),
		},
		hy2Decl(t, fixtureString(t, base, "inbounds", 1, "obfs", "password")),
	}
}

// hy2Decl returns a hysteria2 declaration pinned to the fixture certificate
// with the given obfs password.
func hy2Decl(t *testing.T, obfsPassword string) model.InboundDecl {
	t.Helper()
	pin, err := xrayCertPin(readCert(t))
	if err != nil {
		t.Fatalf("compute pin: %v", err)
	}
	return model.InboundDecl{
		Tag: hy2Tag, Type: model.InboundHysteria2, SNI: sni, ListenPort: 443,
		ObfsPassword: obfsPassword, PinSHA256: pin,
	}
}

// fixtureBase reads the sanitized base config fixture.
func fixtureBase(t *testing.T) []byte {
	t.Helper()
	base, err := os.ReadFile(basePath)
	if err != nil {
		t.Fatalf("read base fixture: %v", err)
	}
	return base
}

// readCert reads the certificate the fixture base's relative path points at.
func readCert(t *testing.T) []byte {
	t.Helper()
	certPEM, err := os.ReadFile(filepath.Join(dataDir, "certs", sni+".crt"))
	if err != nil {
		t.Fatalf("read certificate fixture: %v", err)
	}
	return certPEM
}

// fixtureTree decodes raw into a generic JSON tree.
func fixtureTree(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var tree map[string]any
	if err := json.Unmarshal(raw, &tree); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	return tree
}

// fixtureInbound returns the decoded inbound with the given tag.
func fixtureInbound(t *testing.T, tree map[string]any, tag string) map[string]any {
	t.Helper()
	inbounds, ok := tree["inbounds"].([]any)
	if !ok {
		t.Fatal("config has no inbounds array")
	}
	for _, item := range inbounds {
		in, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if in["tag"] == tag {
			return in
		}
	}
	t.Fatalf("config has no inbound %q", tag)
	return nil
}

// fixtureUsers returns the users array of a decoded inbound.
func fixtureUsers(t *testing.T, in map[string]any) []any {
	t.Helper()
	users, ok := in["users"].([]any)
	if !ok {
		t.Fatalf("inbound %v has no users array", in["tag"])
	}
	return users
}

// fixtureValue walks a generic JSON path — string steps index objects, int
// steps index arrays — and returns the value found there.
func fixtureValue(t *testing.T, raw []byte, path ...any) any {
	t.Helper()
	var node any
	if err := json.Unmarshal(raw, &node); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	for _, step := range path {
		switch key := step.(type) {
		case string:
			obj, ok := node.(map[string]any)
			if !ok {
				t.Fatalf("path step %q: got %T, want object", key, node)
			}
			member, ok := obj[key]
			if !ok {
				t.Fatalf("path step %q: missing", key)
			}
			node = member
		case int:
			arr, ok := node.([]any)
			if !ok {
				t.Fatalf("path step %d: got %T, want array", key, node)
			}
			if key < 0 || key >= len(arr) {
				t.Fatalf("path step %d: out of range", key)
			}
			node = arr[key]
		default:
			t.Fatalf("unsupported path step %T", step)
		}
	}
	return node
}

// fixtureString returns the string at the given generic JSON path.
func fixtureString(t *testing.T, raw []byte, path ...any) string {
	t.Helper()
	value := fixtureValue(t, raw, path...)
	member, ok := value.(string)
	if !ok {
		t.Fatalf("value at path is %T, want string", value)
	}
	return member
}

// insertedText returns the exact text the merge appends to a non-empty users
// array of the fixture: a trailing comma, a newline and the base element
// indentation before each compact entry.
func insertedText(entries ...string) string {
	return ",\n" + elementIndent + strings.Join(entries, ",\n"+elementIndent)
}

// vlessEntryText renders the compact vless entry the merge appends for a user
// whose flow is copied from the base.
func vlessEntryText(name string, uuid string) string {
	return fmt.Sprintf(`{"name":%q,"uuid":%q,"flow":%q}`, name, uuid, legacyFlow)
}

// hy2EntryText renders the compact hysteria2 entry the merge appends.
func hy2EntryText(name string, password string) string {
	return fmt.Sprintf(`{"name":%q,"password":%q}`, name, password)
}

// assertUniqueCredentials fails when a users array serves a credential twice:
// uuid case-insensitively, password exactly.
func assertUniqueCredentials(t *testing.T, users []any) {
	t.Helper()
	seen := map[string]bool{}
	for _, item := range users {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for _, key := range []string{"uuid", "password"} {
			credential, ok := entry[key].(string)
			if !ok {
				continue
			}
			if key == "uuid" {
				credential = strings.ToLower(credential)
			}
			if seen[key+":"+credential] {
				t.Errorf("duplicate %s credential %q", key, credential)
			}
			seen[key+":"+credential] = true
		}
	}
}
