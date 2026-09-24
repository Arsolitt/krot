package store

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Arsolitt/krot/internal/model"
)

// testSpec is a valid two-inbound declaration used as the base of most cases.
func testSpec() model.Spec {
	return model.Spec{
		Server:       "vpn-dev1",
		Endpoint:     "vpn1.example.com",
		RouteProfile: "proxy-server",
		Inbounds: []model.InboundDecl{
			{Tag: "vless-in", Type: model.InboundVLESSReality, ListenPort: 443, SNI: "cdn.example.com"},
			{Tag: "hy2-in", Type: model.InboundHysteria2, ListenPort: 443, SNI: "cdn.example.com"},
		},
	}
}

// newTestStore resets the scratch database, migrates it and opens a store.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	url := os.Getenv("KROT_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("KROT_TEST_DATABASE_URL not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := Open(ctx, url)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.db.ExecContext(ctx, "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close reset handle: %v", err)
	}

	if err := Migrate(url); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	st, err := Open(ctx, url)
	if err != nil {
		t.Fatalf("open after migrate: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestMigrateIdempotent(t *testing.T) {
	st := newTestStore(t)
	_ = st
	if err := Migrate(mustTestURL(t)); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

func mustTestURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("KROT_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("KROT_TEST_DATABASE_URL not set")
	}
	return url
}

func TestDesiredStateCreatesSecrets(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	state, err := st.DesiredState(ctx, testSpec())
	if err != nil {
		t.Fatalf("DesiredState: %v", err)
	}

	if state.Hash == "" {
		t.Fatal("hash must be set")
	}
	if !state.Server.Enabled {
		t.Error("new server must be enabled")
	}
	if len(state.Inbounds) != 2 || len(state.Users) != 0 {
		t.Fatalf("state = %+v", state)
	}

	byTag := map[string]model.Inbound{}
	for _, in := range state.Inbounds {
		byTag[in.Tag] = in
	}

	vless := byTag["vless-in"]
	if vless.RealityPrivateKey == "" || vless.RealityPublicKey == "" || vless.RealityShortID == "" {
		t.Errorf("reality secrets not generated: %+v", vless)
	}
	if vless.PublicEndpoint != "vpn1.example.com" || vless.PublicPort != 443 {
		t.Errorf("defaults not applied: %+v", vless)
	}

	hy2 := byTag["hy2-in"]
	if hy2.ObfsPassword == "" || hy2.CertPEM == "" || hy2.KeyPEM == "" {
		t.Errorf("hy2 secrets not generated: %+v", hy2)
	}
	if !strings.HasPrefix(hy2.PinSHA256, "sha256/") {
		t.Errorf("pin = %q, want sha256/ prefix", hy2.PinSHA256)
	}
	block, _ := pem.Decode([]byte(hy2.CertPEM))
	if block == nil {
		t.Fatalf("cert PEM undecodable")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if cert.Subject.CommonName != "cdn.example.com" {
		t.Errorf("cert CN = %q", cert.Subject.CommonName)
	}
}

func TestDesiredStateStableHash(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	first, err := st.DesiredState(ctx, testSpec())
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := st.DesiredState(ctx, testSpec())
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first.Hash != second.Hash {
		t.Errorf("hash changed on identical spec: %s -> %s", first.Hash, second.Hash)
	}
}

func TestDesiredStateReconcile(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	spec := testSpec()
	first, err := st.DesiredState(ctx, spec)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	firstByTag := map[string]model.Inbound{}
	for _, in := range first.Inbounds {
		firstByTag[in.Tag] = in
	}

	// Change a non-secret param, drop the hy2 inbound, add a ws inbound.
	wsPath := "/up"
	spec.Inbounds = []model.InboundDecl{
		{Tag: "vless-in", Type: model.InboundVLESSReality, ListenPort: 8443, SNI: "cdn.example.com"},
		{Tag: "ws-in", Type: model.InboundVLESSWS, ListenPort: 2053, SNI: "front.example.org",
			PublicEndpoint: "front.example.org", PublicPort: 443, WSPath: wsPath},
	}
	second, err := st.DesiredState(ctx, spec)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	secondByTag := map[string]model.Inbound{}
	for _, in := range second.Inbounds {
		secondByTag[in.Tag] = in
	}

	if _, gone := secondByTag["hy2-in"]; gone {
		t.Error("undeclared hy2-in must be deleted")
	}
	vless := secondByTag["vless-in"]
	if vless.ListenPort != 8443 {
		t.Errorf("listen port not updated: %d", vless.ListenPort)
	}
	if vless.RealityPrivateKey != firstByTag["vless-in"].RealityPrivateKey {
		t.Error("reality keys must survive a param change")
	}
	if vless.RealityShortID != firstByTag["vless-in"].RealityShortID {
		t.Error("short id must survive a param change")
	}
	ws := secondByTag["ws-in"]
	if ws.WSPath == nil || *ws.WSPath != "/up" || ws.CertPEM != "" {
		t.Errorf("ws inbound wrong: %+v", ws)
	}
	if second.Hash == first.Hash {
		t.Error("hash must change when the state changes")
	}
}

func TestDesiredStateSNIRotatesCertOnly(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	spec := testSpec()
	first, err := st.DesiredState(ctx, spec)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	var firstHy2 model.Inbound
	for _, in := range first.Inbounds {
		if in.Tag == "hy2-in" {
			firstHy2 = in
		}
	}

	spec.Inbounds[1].SNI = "new-cdn.example.com"
	second, err := st.DesiredState(ctx, spec)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	var secondHy2 model.Inbound
	for _, in := range second.Inbounds {
		if in.Tag == "hy2-in" {
			secondHy2 = in
		}
	}

	if secondHy2.CertPEM == firstHy2.CertPEM {
		t.Error("SNI change must rotate the certificate")
	}
	if secondHy2.ObfsPassword != firstHy2.ObfsPassword {
		t.Error("obfs password must survive a SNI change")
	}
}

func TestDesiredStateValidation(t *testing.T) {
	tests := []struct {
		mut  func(*model.Spec)
		name string
	}{
		{name: "empty server", mut: func(s *model.Spec) { s.Server = "" }},
		{name: "empty endpoint", mut: func(s *model.Spec) { s.Endpoint = "" }},
		{name: "unknown profile", mut: func(s *model.Spec) { s.RouteProfile = "bogus" }},
		{name: "unknown type", mut: func(s *model.Spec) {
			s.Inbounds[0].Type = model.InboundType("bogus")
		}},
		{name: "empty tag", mut: func(s *model.Spec) { s.Inbounds[0].Tag = "" }},
		{name: "duplicate tag", mut: func(s *model.Spec) { s.Inbounds[1].Tag = s.Inbounds[0].Tag }},
		{name: "empty sni", mut: func(s *model.Spec) { s.Inbounds[0].SNI = "" }},
		{name: "port out of range", mut: func(s *model.Spec) { s.Inbounds[0].ListenPort = 70_000 }},
		{name: "public port out of range", mut: func(s *model.Spec) { s.Inbounds[0].PublicPort = 70_000 }},
		{name: "ws without path", mut: func(s *model.Spec) {
			s.Inbounds[1] = model.InboundDecl{
				Tag:        "ws-in",
				Type:       model.InboundVLESSWS,
				ListenPort: 2053,
				SNI:        "f.example.org",
			}
		}},
		{name: "tcp port collision", mut: func(s *model.Spec) {
			s.Inbounds[1] = model.InboundDecl{
				Tag:        "vless-2",
				Type:       model.InboundVLESSReality,
				ListenPort: 443,
				SNI:        "f.example.org",
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := newTestStore(t)
			spec := testSpec()
			tt.mut(&spec)
			_, err := st.DesiredState(context.Background(), spec)
			if !errors.Is(err, ErrInvalidSpec) {
				t.Fatalf("expected ErrInvalidSpec, got %v", err)
			}
		})
	}
}

func TestDesiredStateUDPTCPCoexist(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	state, err := st.DesiredState(ctx, testSpec())
	if err != nil {
		t.Fatalf("hy2 udp/443 + vless tcp/443 must coexist: %v", err)
	}
	if len(state.Inbounds) != 2 {
		t.Fatalf("inbounds = %d", len(state.Inbounds))
	}
}

func TestDesiredStateDisabledDrains(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	spec := testSpec()
	if _, err := st.DesiredState(ctx, spec); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := st.SyncUsers(ctx, []model.Member{{Username: "arsolitt", Subject: "uuid-1"}}); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE servers SET enabled = FALSE WHERE name = $1", spec.Server); err != nil {
		t.Fatalf("disable: %v", err)
	}

	state, err := st.DesiredState(ctx, spec)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if state.Server.Enabled {
		t.Error("server must stay disabled across declarations")
	}
	if len(state.Inbounds) != 0 || len(state.Users) != 0 {
		t.Errorf("disabled node must drain: %+v", state)
	}
	if state.Hash == "" {
		t.Error("drained state still needs a hash")
	}
}

func TestSyncUsersLifecycle(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	mkMembers := func(pairs ...[2]string) []model.Member {
		members := make([]model.Member, 0, len(pairs))
		for _, p := range pairs {
			members = append(members, model.Member{Username: p[0], Subject: p[1]})
		}
		return members
	}

	if err := st.SyncUsers(ctx, mkMembers([2]string{"arsolitt", "u-1"}, [2]string{"alice", "u-2"})); err != nil {
		t.Fatalf("sync create: %v", err)
	}
	users, err := st.Users(ctx)
	if err != nil {
		t.Fatalf("users: %v", err)
	}
	if len(users) != 2 || !users[0].Active || users[0].VLESSUUID == "" || users[0].Hy2Password == "" {
		t.Fatalf("users = %+v", users)
	}

	// Rename u-1; creds must stay.
	if err := st.SyncUsers(ctx, mkMembers([2]string{"renamed", "u-1"}, [2]string{"alice", "u-2"})); err != nil {
		t.Fatalf("sync rename: %v", err)
	}
	renamed, err := st.Users(ctx)
	if err != nil {
		t.Fatalf("users: %v", err)
	}
	if renamed[1].Name != "renamed" || renamed[1].VLESSUUID != users[1].VLESSUUID {
		t.Errorf("rename must keep creds: %+v", renamed[1])
	}

	// u-2 gone; then restored with the same creds.
	if err := st.SyncUsers(ctx, mkMembers([2]string{"renamed", "u-1"})); err != nil {
		t.Fatalf("sync drop: %v", err)
	}
	dropped, _ := st.Users(ctx)
	if dropped[0].Active {
		t.Error("absent member must be deactivated")
	}
	if err := st.SyncUsers(ctx, mkMembers([2]string{"renamed", "u-1"}, [2]string{"alice", "u-2"})); err != nil {
		t.Fatalf("sync restore: %v", err)
	}
	restored, _ := st.Users(ctx)
	if !restored[0].Active || restored[0].VLESSUUID != users[0].VLESSUUID {
		t.Errorf("re-adding must restore creds: %+v", restored[0])
	}

	// Empty group deactivates everyone.
	if err := st.SyncUsers(ctx, nil); err != nil {
		t.Fatalf("sync empty: %v", err)
	}
	emptied, _ := st.Users(ctx)
	for _, u := range emptied {
		if u.Active {
			t.Errorf("user %s must be deactivated", u.Name)
		}
	}

	state, err := st.SyncState(ctx)
	if err != nil {
		t.Fatalf("sync state: %v", err)
	}
	if state.LastSyncAt == nil || state.LastError != "" {
		t.Errorf("sync state = %+v", state)
	}

	if err := st.SetSyncError(ctx, "boom"); err != nil {
		t.Fatalf("set sync error: %v", err)
	}
	state, _ = st.SyncState(ctx)
	if state.LastError != "boom" {
		t.Errorf("last_error = %q", state.LastError)
	}
}

func TestHeartbeatAndStatus(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	spec := testSpec()
	if _, err := st.DesiredState(ctx, spec); err != nil {
		t.Fatalf("declare: %v", err)
	}
	members := []model.Member{{Username: "arsolitt", Subject: "u-1"}, {Username: "b", Subject: "u-2"}}
	if err := st.SyncUsers(ctx, members); err != nil {
		t.Fatalf("sync: %v", err)
	}

	hb := model.Heartbeat{
		Server: spec.Server, AgentVersion: "dev", AppliedHash: "h1",
		SingboxHealthy: true, UserCount: 2, ConfigError: "",
	}
	if err := st.Heartbeat(ctx, hb); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	hb.AppliedHash = "h2"
	if err := st.Heartbeat(ctx, hb); err != nil {
		t.Fatalf("heartbeat upsert: %v", err)
	}

	servers, err := st.ServersWithStatus(ctx)
	if err != nil {
		t.Fatalf("servers with status: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("servers = %+v", servers)
	}
	if servers[0].Status.AppliedHash != "h2" || !servers[0].Status.SingboxHealthy || servers[0].Status.UserCount != 2 {
		t.Errorf("status = %+v", servers[0].Status)
	}
	if servers[0].Status.LastSeen.IsZero() {
		t.Error("last_seen must be set")
	}

	unknown := hb
	unknown.Server = "ghost"
	if err := st.Heartbeat(ctx, unknown); !errors.Is(err, ErrUnknownServer) {
		t.Errorf("ghost heartbeat = %v, want ErrUnknownServer", err)
	}
}

func TestQueryViews(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	spec := testSpec()
	if _, err := st.DesiredState(ctx, spec); err != nil {
		t.Fatalf("declare: %v", err)
	}
	members := []model.Member{{Username: "arsolitt", Subject: "u-1"}, {Username: "bob", Subject: "u-2"}}
	if err := st.SyncUsers(ctx, members); err != nil {
		t.Fatalf("sync: %v", err)
	}

	active, err := st.ActiveUsers(ctx)
	if err != nil {
		t.Fatalf("active users: %v", err)
	}
	if len(active) != 2 || active[0].Name != "arsolitt" || active[1].Name != "bob" {
		t.Fatalf("active = %+v", active)
	}

	targets, err := st.EnabledServersWithInbounds(ctx)
	if err != nil {
		t.Fatalf("link targets: %v", err)
	}
	if len(targets) != 1 || targets[0].Server.Name != spec.Server || len(targets[0].Inbounds) != 2 {
		t.Fatalf("targets = %+v", targets)
	}
	if targets[0].Inbounds[0].Tag != "hy2-in" || targets[0].Inbounds[1].Tag != "vless-in" {
		t.Errorf("inbounds not ordered by tag: %+v", targets[0].Inbounds)
	}

	if err := st.Ping(ctx); err != nil {
		t.Errorf("ping: %v", err)
	}
}
