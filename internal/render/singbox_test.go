package render

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/Arsolitt/cheburbox/generate"

	"github.com/Arsolitt/krot/internal/model"
)

// v1 golden values (from testdata fixtures): user credentials and reality keys.
// The hysteria2 certificate is generated per test run instead of being checked
// in - a private key in the repository trips secret scanners for no benefit,
// and the pin is derived from the generated certificate rather than compared
// against a stored one.
const (
	goldenUserName     = "arsolitt"
	goldenUserVLESS    = "397fd10e-5e2c-4817-bd56-2d8e9a78d099"
	goldenUserHy2Pass  = "AHjqg-limyU2fS7RKr2OiR7hKqLuvmum"
	goldenRealityPriv  = "Ma1yM8SNr1ZHZCWzy4HDrkpmaLbCWJCOPP01WoOhWIk"
	goldenRealityPub   = "Gs3SCdZr9mwSoaG4BwBINH074ZGayszZraPKhtaNA2w"
	goldenRealitySID   = "8a07bf48dee3fecc"
	goldenHy2Obfs      = "dZHtPJO9bTmgR48hfGocE-7r1LfMqUUO"
	goldenEndpointSNI  = "cdn.example.com"
	normalizedCertPath = "certs/<normalized>"
	realityHandshakePt = 443
	hy2Bandwidth       = 1000
	wsListenPort       = 8443
	wsPublicPort       = 443
)

// goldenCert generates a self-signed certificate for goldenEndpointSNI and
// returns its PEM pair plus the pin the renderer derives from it.
func goldenCert(t *testing.T) ([]byte, []byte, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: goldenEndpointSNI},
		DNSNames:     []string{goldenEndpointSNI},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	pin, err := generate.ComputePinSHA256(certPEM)
	if err != nil {
		t.Fatalf("pin generated cert: %v", err)
	}
	return certPEM, keyPEM, pin
}

// goldenUsers is the v1 user list.
func goldenUsers() []model.User {
	return []model.User{{
		Name:        goldenUserName,
		VLESSUUID:   goldenUserVLESS,
		Hy2Password: goldenUserHy2Pass,
	}}
}

// goldenInbounds rebuilds the srv-1 inbound rows; reality keys come from the
// golden config itself, the hy2 certificate is generated for this run.
func goldenInbounds(t *testing.T) []model.Inbound {
	t.Helper()

	certPEM, keyPEM, pin := goldenCert(t)

	return []model.Inbound{
		{
			Tag: "vless-in", Type: model.InboundVLESSReality,
			ListenPort: realityHandshakePt, SNI: goldenEndpointSNI,
			PublicEndpoint: "srv-1.example.com", PublicPort: realityHandshakePt,
			RealityPrivateKey: goldenRealityPriv,
			RealityPublicKey:  goldenRealityPub,
			RealityShortID:    goldenRealitySID,
		},
		{
			Tag: "hy2-in", Type: model.InboundHysteria2,
			ListenPort: realityHandshakePt, SNI: goldenEndpointSNI,
			PublicEndpoint: "srv-1.example.com", PublicPort: realityHandshakePt,
			ObfsPassword: goldenHy2Obfs,
			CertPEM:      string(certPEM),
			KeyPEM:       string(keyPEM),
			PinSHA256:    pin,
		},
	}
}

// normalizeCertPaths rewrites the hy2 tls certificate paths in a parsed config
// to a sentinel so golden comparison is exact for everything else. v1 named
// cert files after the SNI; v2 names them after the inbound tag (collision-
// free for inbounds sharing an SNI) — the only intentional deviation.
func normalizeCertPaths(t *testing.T, cfg map[string]any) {
	t.Helper()
	inbounds, ok := cfg["inbounds"].([]any)
	if !ok {
		return
	}
	for _, ib := range inbounds {
		m, ok := ib.(map[string]any)
		if !ok {
			continue
		}
		tls, ok := m["tls"].(map[string]any)
		if !ok {
			continue
		}
		if _, ok := tls["certificate_path"].(string); ok {
			tls["certificate_path"] = normalizedCertPath
		}
		if _, ok := tls["key_path"].(string); ok {
			tls["key_path"] = normalizedCertPath
		}
	}
}

func TestSingboxGoldenConfig(t *testing.T) {
	opts, err := SingboxConfig(ProfileProxyServer, goldenInbounds(t), goldenUsers(), "")
	if err != nil {
		t.Fatalf("SingboxConfig: %v", err)
	}
	rendered, err := Marshal(context.Background(), opts)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join("testdata", "golden_srv1_config.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}

	var got, want any
	if err := json.Unmarshal(rendered, &got); err != nil {
		t.Fatalf("parse rendered: %v\n%s", err, rendered)
	}
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("parse golden: %v", err)
	}

	gotCfg := got.(map[string]any)
	wantCfg := want.(map[string]any)
	normalizeCertPaths(t, gotCfg)
	normalizeCertPaths(t, wantCfg)

	if !reflect.DeepEqual(gotCfg, wantCfg) {
		t.Errorf("rendered config != golden v1 config")
		dumpIfVerbose(t, rendered)
	}
}

// dumpIfVerbose prints the rendered config to help diagnose golden drift.
func dumpIfVerbose(t *testing.T, rendered []byte) {
	t.Helper()
	if testing.Verbose() {
		t.Logf("rendered:\n%s", rendered)
	}
}

func TestSingboxVLESSWSShape(t *testing.T) {
	wsPath := "/up"
	inbounds := []model.Inbound{{
		Tag: "vless-ws-ddg", Type: model.InboundVLESSWS,
		ListenPort: wsListenPort, SNI: "front.example.org",
		PublicEndpoint: "front.example.org", PublicPort: wsPublicPort,
		WSPath: &wsPath,
	}}

	opts, err := SingboxConfig(ProfileProxyServer, inbounds, goldenUsers(), "")
	if err != nil {
		t.Fatalf("SingboxConfig: %v", err)
	}
	rendered, err := Marshal(context.Background(), opts)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var cfg struct {
		Inbounds []map[string]any `json:"inbounds"`
	}
	if err := json.Unmarshal(rendered, &cfg); err != nil {
		t.Fatalf("parse rendered: %v", err)
	}
	if len(cfg.Inbounds) != 1 {
		t.Fatalf("inbounds = %d, want 1", len(cfg.Inbounds))
	}
	ib := cfg.Inbounds[0]

	transport, ok := ib["transport"].(map[string]any)
	if !ok || transport["type"] != "ws" || transport["path"] != wsPath {
		t.Errorf("transport = %v, want ws with path %s", ib["transport"], wsPath)
	}
	if _, hasTLS := ib["tls"]; hasTLS {
		t.Error("origin_tls=false must not render a tls block")
	}
	users, ok := ib["users"].([]any)
	if !ok || len(users) != 1 {
		t.Fatalf("users = %v, want one entry", ib["users"])
	}
	user := users[0].(map[string]any)
	if _, hasFlow := user["flow"]; hasFlow {
		t.Error("ws users must omit flow (xtls-rprx-vision is TCP-only)")
	}
	if user["uuid"] != goldenUserVLESS {
		t.Errorf("uuid = %v", user["uuid"])
	}
}

func TestSingboxVLESSWSOriginTLSShape(t *testing.T) {
	wsPath := "/up"
	inbounds := []model.Inbound{{
		Tag: "vless-ws-ddg", Type: model.InboundVLESSWS,
		ListenPort: wsListenPort, SNI: "front.example.org",
		PublicEndpoint: "front.example.org", PublicPort: wsPublicPort,
		WSPath: &wsPath, OriginTLS: true,
		CertPEM: "-----BEGIN CERTIFICATE-----", KeyPEM: "-----BEGIN PRIVATE KEY-----",
	}}

	opts, err := SingboxConfig(ProfileProxyServer, inbounds, goldenUsers(), "")
	if err != nil {
		t.Fatalf("SingboxConfig: %v", err)
	}
	rendered, err := Marshal(context.Background(), opts)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var cfg struct {
		Inbounds []map[string]any `json:"inbounds"`
	}
	if err := json.Unmarshal(rendered, &cfg); err != nil {
		t.Fatalf("parse rendered: %v", err)
	}
	tls, ok := cfg.Inbounds[0]["tls"].(map[string]any)
	if !ok {
		t.Fatal("origin_tls=true must render a tls block")
	}
	if tls["certificate_path"] != "certs/vless-ws-ddg.crt" || tls["key_path"] != "certs/vless-ws-ddg.key" {
		t.Errorf("cert paths = %v/%v", tls["certificate_path"], tls["key_path"])
	}
}

func TestSingboxConfigRejectsBadInput(t *testing.T) {
	if _, err := SingboxConfig("bogus", nil, nil, ""); err == nil {
		t.Error("unknown profile must error")
	}

	inbounds := goldenInbounds(t)
	dup := inbounds[1]
	dup.Tag = "hy2-dup"
	dup.Type = model.InboundVLESSWS
	inbounds = append(inbounds, dup)
	if _, err := SingboxConfig(ProfileProxyServer, inbounds, nil, ""); err == nil {
		t.Error("ws on 443/tcp must collide with reality 443/tcp")
	}
}

func TestWriteCerts(t *testing.T) {
	dir := t.TempDir()
	inbounds := goldenInbounds(t)
	if err := WriteCerts(dir, inbounds); err != nil {
		t.Fatalf("WriteCerts: %v", err)
	}

	crt, err := os.ReadFile(filepath.Join(dir, "certs", "hy2-in.crt"))
	if err != nil {
		t.Fatalf("read written cert: %v", err)
	}
	if string(crt) != inbounds[1].CertPEM {
		t.Error("written cert differs from inbound cert_pem")
	}

	info, err := os.Stat(filepath.Join(dir, "certs", "hy2-in.key"))
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %v, want 0600", info.Mode().Perm())
	}
}
