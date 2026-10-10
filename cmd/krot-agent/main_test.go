package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Arsolitt/cheburbox/generate"

	"github.com/Arsolitt/krot/internal/model"
)

// Fixture payloads. The fake sing-box rejects any config containing
// invalidMarker, so check outcomes are deterministic and offline.
const (
	validConfig   = `{"log": {"level": "info"}}`
	changedConfig = `{"log": {"level": "debug"}}`
	invalidMarker = `"valid": false`
	invalidConfig = `{"log": {"level": "info"}, "valid": false}`
	specFile      = "agent.yaml"
	testCPURL     = "http://127.0.0.1:1"
	testToken     = "unit-test-token"

	emptySpec = `server: static-node
endpoint: vpn.example
route_profile: proxy-server
inbounds: []
`

	inboundSpec = `server: static-node
endpoint: vpn.example
route_profile: proxy-server
inbounds:
  - tag: vless-in
    type: vless_reality
    listen_port: 443
    sni: cdn.example.com
`
)

// Merge-mode fixture payloads: the base serves two legacy vless users and one
// legacy hysteria2 user, and both inbounds are declared merge targets whose
// pinned values the tests derive from the base.
const (
	mergeSNI               = "ams.example.com"
	mergeVLESSTag          = "vless-in"
	mergeHy2Tag            = "hy2-in"
	mergeFlow              = "xtls-rprx-vision"
	mergeRealityPrivateKey = "IL2bdmlAR_0qZetL1YJb5Sta_sdIpI2oxpOUFirV1qo"
	mergeShortID           = "236205ea41fa19be"
	mergeObfsPassword      = "fixture-obfs-password"
	mergeListenPort        = 443
	mergeLegacyVLESSUsers  = 2
	mergeLegacyHy2Users    = 1
	mergeCarolName         = "carol"
	mergeCarolUUID         = "c4a1f0e2-8ab3-4c0e-9b1b-7b8a1c2d3e4f"
	mergeCarolPass         = "carol-hy2-pass"
	mergeDaveName          = "dave"
	mergeDaveUUID          = "d5b2c3d4-1234-4abc-9def-0123456789ab"
	mergeDavePass          = "dave-hy2-pass"

	// The fake sing-box logs its invocations after it starts, so assertions on
	// the run log poll for the expected line within this window.
	mergeLogTimeout = 5 * time.Second
	mergeLogPoll    = 10 * time.Millisecond
)

// mergeBaseConfig is the operator-owned base in the shape the chart renders: a
// vless reality inbound with a private key, a multi-id short id list and
// legacy users carrying a flow, plus a hysteria2 inbound with obfs and a
// certificate the -D data dir holds. It carries no invalidMarker, so the fake
// sing-box accepts it and every config rendered from it.
const mergeBaseConfig = `{
  "log": {
    "level": "fatal",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": 443,
      "users": [
        {
          "name": "svc-laptop",
          "uuid": "45977ea3-f264-4671-bec9-5195fa960936",
          "flow": "xtls-rprx-vision"
        },
        {
          "name": "svc-phone",
          "uuid": "6161ef9d-f402-4eef-a32f-4c8b7942a876",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "ams.example.com",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "ams.example.com",
            "server_port": 443
          },
          "private_key": "IL2bdmlAR_0qZetL1YJb5Sta_sdIpI2oxpOUFirV1qo",
          "short_id": [
            "236205ea41fa19be",
            "fd27ae508b2088d9"
          ]
        }
      }
    },
    {
      "type": "hysteria2",
      "tag": "hy2-in",
      "listen": "::",
      "listen_port": 443,
      "obfs": {
        "type": "salamander",
        "password": "fixture-obfs-password"
      },
      "users": [
        {
          "name": "svc-router",
          "password": "2totCg8fZ9NtrFoBIrHQkk5jDA3fJmbU"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "ams.example.com",
        "alpn": "h3",
        "certificate_path": "certs/ams.example.com.crt",
        "key_path": "certs/ams.example.com.key"
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
}
`

// singboxScript is the fake sing-box shared by all cycle tests: check exits 1
// when the config contains invalidMarker, run execs a long-lived sleep, and
// nothing ever touches the network. Every invocation is appended to
// SINGBOX_LOG when that variable is set, so tests can see which config the
// child was told to run.
const singboxScript = `#!/bin/sh
cmd="$1"
shift
[ -n "$SINGBOX_LOG" ] && echo "$cmd $*" >> "$SINGBOX_LOG"
cfg=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -c)
      cfg="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
case "$cmd" in
  check)
    if grep -q '` + invalidMarker + `' "$cfg"; then
      echo "fake sing-box: config ${cfg} rejected" >&2
      exit 1
    fi
    ;;
  run)
    exec sleep 300
    ;;
  *)
    echo "fake sing-box: unknown command ${cmd}" >&2
    exit 2
    ;;
esac
`

// TestStaticReconcileNeverWritesConfigDir covers contract rule 1: the config
// directory stays read-only, and applied.hash is the only file the agent
// writes (under the work dir).
func TestStaticReconcileNeverWritesConfigDir(t *testing.T) {
	tree := newStaticTree(t, validConfig)
	if err := os.Chmod(tree.cfgDir, 0o555); err != nil {
		t.Fatalf("chmod config dir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(tree.cfgDir, 0o755); err != nil {
			t.Errorf("restore config dir mode: %v", err)
		}
	})

	ag := testAgent(t, tree.workDir, tree.singbox, tree.cfgPath, tree.dataDir)
	cfgBefore := dirNames(t, tree.cfgDir)

	hash := ag.reconcileStatic(t.Context())

	requireChild(t, ag)
	if got := dirNames(t, tree.cfgDir); !slices.Equal(got, cfgBefore) {
		t.Errorf("config dir entries changed: %v -> %v", cfgBefore, got)
	}
	if got := readFileString(t, tree.cfgPath); got != validConfig {
		t.Errorf("config content changed: %q", got)
	}

	want := sha256Hex(validConfig)
	requireHash(t, hash, want)
	if got := dirNames(t, tree.workDir); !slices.Equal(got, []string{hashFileName}) {
		t.Errorf("work dir entries = %v, want only %s", got, hashFileName)
	}
	requireAppliedHash(t, tree.workDir, want)
}

// TestStaticReconcileMtimeTouchNoRestart covers rule 3: only the content hash
// decides, so a bare mtime touch must not restart the child.
func TestStaticReconcileMtimeTouchNoRestart(t *testing.T) {
	tree := newStaticTree(t, validConfig)
	ag, pid := startStaticChild(t, tree)

	if err := os.Chtimes(tree.cfgPath, time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	hash := ag.reconcileStatic(t.Context())

	if got := childPid(ag); got != pid {
		t.Errorf("child restarted on an mtime-only touch: pid %d -> %d", pid, got)
	}
	requireHash(t, hash, sha256Hex(validConfig))
	if got := ag.errorText(); got != "" {
		t.Errorf("unexpected error state: %q", got)
	}
}

// TestStaticReconcileContentChangeRestarts covers rule 3: a content change is
// re-validated and restarts the child, and the applied hash advances.
func TestStaticReconcileContentChangeRestarts(t *testing.T) {
	tree := newStaticTree(t, validConfig)
	ag, pid := startStaticChild(t, tree)

	if err := os.WriteFile(tree.cfgPath, []byte(changedConfig), 0o600); err != nil {
		t.Fatalf("rewrite config: %v", err)
	}
	hash := ag.reconcileStatic(t.Context())

	if got := childPid(ag); got == pid || got == 0 {
		t.Errorf("child not restarted on a content change: pid %d -> %d", pid, got)
	}
	want := sha256Hex(changedConfig)
	requireHash(t, hash, want)
	requireAppliedHash(t, tree.workDir, want)
}

// TestStaticReconcileFailedCheckKeepsChild covers rule 3: a config that fails
// check keeps the running child and reports the error.
func TestStaticReconcileFailedCheckKeepsChild(t *testing.T) {
	tree := newStaticTree(t, validConfig)
	ag, pid := startStaticChild(t, tree)
	oldHash := sha256Hex(validConfig)

	if err := os.WriteFile(tree.cfgPath, []byte(invalidConfig), 0o600); err != nil {
		t.Fatalf("rewrite config: %v", err)
	}
	hash := ag.reconcileStatic(t.Context())

	if got := childPid(ag); got != pid {
		t.Errorf("child replaced after a failed check: pid %d -> %d", pid, got)
	}
	requireHash(t, hash, oldHash)
	if got := ag.errorText(); !strings.Contains(got, "check") {
		t.Errorf("error state = %q, want a sing-box check error", got)
	}
	requireAppliedHash(t, tree.workDir, oldHash)
}

// TestNewAgentAcceptsStaticWithInboundSpec covers rule 4: a static node whose
// spec declares inbounds runs in merge mode, while a declaration-free spec
// stays a passthrough node.
func TestNewAgentAcceptsStaticWithInboundSpec(t *testing.T) {
	root := t.TempDir()
	cfgPath := writeFile(t, filepath.Join(root, configFileName), validConfig)
	t.Setenv("KROT_STATIC_CONFIG", cfgPath)
	t.Setenv("KROT_WORKDIR", root)

	t.Run("declared inbounds merge", func(t *testing.T) {
		specPath := writeFile(t, filepath.Join(root, specFile), inboundSpec)
		setenvCommon(t, specPath)

		ag, err := newAgent(discardLogger())
		if err != nil {
			t.Fatalf("newAgent: %v", err)
		}
		if !ag.mergeTargets {
			t.Error("mergeTargets = false, want true for a static node with declared inbounds")
		}
		if len(ag.spec.Inbounds) != 1 || ag.spec.Inbounds[0].Tag != "vless-in" {
			t.Errorf("spec inbounds = %#v, want the declared vless-in", ag.spec.Inbounds)
		}
	})

	t.Run("no declared inbounds passthrough", func(t *testing.T) {
		specPath := writeFile(t, filepath.Join(root, specFile), emptySpec)
		setenvCommon(t, specPath)

		ag, err := newAgent(discardLogger())
		if err != nil {
			t.Fatalf("newAgent: %v", err)
		}
		if ag.mergeTargets {
			t.Error("mergeTargets = true, want false for a static node without declared inbounds")
		}
	})
}

// TestNewAgentMissingStaticConfig covers rule 7: a missing static config fails
// fast with the path in the error.
func TestNewAgentMissingStaticConfig(t *testing.T) {
	root := t.TempDir()
	specPath := writeFile(t, filepath.Join(root, specFile), emptySpec)
	missing := filepath.Join(root, "missing.json")
	setenvCommon(t, specPath)
	t.Setenv("KROT_STATIC_CONFIG", missing)

	_, err := newAgent(discardLogger())
	if err == nil {
		t.Fatal("expected newAgent to reject a missing static config")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("error %q does not name the config path %s", err, missing)
	}
}

// TestNewAgentMissingStaticDataDir covers rule 7: a missing data dir fails
// fast with the path in the error.
func TestNewAgentMissingStaticDataDir(t *testing.T) {
	root := t.TempDir()
	specPath := writeFile(t, filepath.Join(root, specFile), emptySpec)
	cfgPath := writeFile(t, filepath.Join(root, configFileName), validConfig)
	missing := filepath.Join(root, "no-such-dir")
	setenvCommon(t, specPath)
	t.Setenv("KROT_STATIC_CONFIG", cfgPath)
	t.Setenv("KROT_STATIC_DATA_DIR", missing)

	_, err := newAgent(discardLogger())
	if err == nil {
		t.Fatal("expected newAgent to reject a missing static data dir")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("error %q does not name the data dir %s", err, missing)
	}
}

// TestStaticDataDirResolution covers rule 7: -D defaults to the config
// directory and an explicit KROT_STATIC_DATA_DIR is used verbatim.
func TestStaticDataDirResolution(t *testing.T) {
	root := t.TempDir()
	cfgDir := filepath.Join(root, "etc")
	mkdirAll(t, cfgDir)
	cfgPath := writeFile(t, filepath.Join(cfgDir, configFileName), validConfig)
	explicit := filepath.Join(root, "lib")
	mkdirAll(t, explicit)
	specPath := writeFile(t, filepath.Join(root, specFile), emptySpec)
	setenvCommon(t, specPath)
	t.Setenv("KROT_STATIC_CONFIG", cfgPath)

	t.Run("defaults to the config directory", func(t *testing.T) {
		t.Setenv("KROT_STATIC_DATA_DIR", "")
		ag, err := newAgent(discardLogger())
		if err != nil {
			t.Fatalf("newAgent: %v", err)
		}
		if ag.staticConfig != cfgPath {
			t.Errorf("staticConfig = %q, want %q", ag.staticConfig, cfgPath)
		}
		if ag.dataDir != cfgDir {
			t.Errorf("dataDir = %q, want %q", ag.dataDir, cfgDir)
		}
	})

	t.Run("honours an explicit data dir", func(t *testing.T) {
		t.Setenv("KROT_STATIC_DATA_DIR", explicit)
		ag, err := newAgent(discardLogger())
		if err != nil {
			t.Fatalf("newAgent: %v", err)
		}
		if ag.dataDir != explicit {
			t.Errorf("dataDir = %q, want %q", ag.dataDir, explicit)
		}
	})
}

// TestDynamicDefaultsAndBootstrap covers rule 9: without KROT_STATIC_CONFIG
// the agent is dynamic (dataDir == workDir) and still boots from the stored
// config.
func TestDynamicDefaultsAndBootstrap(t *testing.T) {
	root := t.TempDir()
	workDir := filepath.Join(root, "work")
	mkdirAll(t, workDir)
	writeFile(t, filepath.Join(workDir, configFileName), validConfig)
	specPath := writeFile(t, filepath.Join(root, specFile), emptySpec)
	singboxPath := fakeSingbox(t, root)
	setenvCommon(t, specPath)
	t.Setenv("KROT_WORKDIR", workDir)
	t.Setenv("KROT_SINGBOX", singboxPath)
	t.Setenv("KROT_STATIC_CONFIG", "")

	ag, err := newAgent(discardLogger())
	if err != nil {
		t.Fatalf("newAgent(dynamic): %v", err)
	}
	if ag.staticConfig != "" {
		t.Errorf("staticConfig = %q, want empty", ag.staticConfig)
	}
	if ag.dataDir != workDir {
		t.Errorf("dataDir = %q, want the work dir %q", ag.dataDir, workDir)
	}

	ag.ctx = t.Context()
	t.Cleanup(ag.stopChild)
	if err := ag.bootstrap(t.Context()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	requireChild(t, ag)
}

// TestStaticBootstrapFailsFastOnFailedCheck covers rules 3 and 7: a static
// config that fails check stops the agent before any child starts.
func TestStaticBootstrapFailsFastOnFailedCheck(t *testing.T) {
	tree := newStaticTree(t, invalidConfig)
	ag := testAgent(t, tree.workDir, tree.singbox, tree.cfgPath, tree.dataDir)

	err := ag.bootstrap(t.Context())
	if err == nil {
		t.Fatal("expected bootstrap to fail on a config that does not validate")
	}
	if ag.childRunning() {
		t.Error("child must not start from a config that failed check")
	}
	if !strings.Contains(err.Error(), "check") {
		t.Errorf("error %q does not mention the failed check", err)
	}
	if _, statErr := os.Stat(filepath.Join(tree.workDir, hashFileName)); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("applied hash must not be persisted, stat err = %v", statErr)
	}
}

// TestStaticBootstrapHashPreventsFirstPollRestart covers rules 4 and 8: the
// bootstrap records the hash, so the first poll keeps the fresh child.
func TestStaticBootstrapHashPreventsFirstPollRestart(t *testing.T) {
	tree := newStaticTree(t, validConfig)
	ag := testAgent(t, tree.workDir, tree.singbox, tree.cfgPath, tree.dataDir)

	if err := ag.bootstrap(t.Context()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	pid := requireChild(t, ag)
	want := sha256Hex(validConfig)
	requireAppliedHash(t, tree.workDir, want)

	hash := ag.reconcileStatic(t.Context())
	if got := childPid(ag); got != pid {
		t.Errorf("first poll restarted the fresh child: pid %d -> %d", pid, got)
	}
	requireHash(t, hash, want)
}

// TestStaticMergeBootstrap covers the merge-mode bootstrap rules: the stored
// render is preferred while it still belongs to the base, a stale or rejected
// one falls back to the base, and a declaration the base cannot serve fails
// fast before any child starts.
func TestStaticMergeBootstrap(t *testing.T) {
	t.Run("starts the stored render", func(t *testing.T) {
		tree := newMergeTree(t)
		ag := testMergeAgent(t, tree)
		ag.lastState.Users = mergeUsers()
		ag.reconcileMerged(t.Context())
		requireChild(t, ag)

		boot := testMergeAgent(t, tree)
		if err := boot.bootstrap(t.Context()); err != nil {
			t.Fatalf("bootstrap: %v", err)
		}
		requireChild(t, boot)
		requireLastRunConfig(t, tree.logPath, filepath.Join(tree.workDir, renderedFileName))

		renderedHash := sha256Hex(readFileString(t, filepath.Join(tree.workDir, renderedFileName)))
		if got := readFileString(t, filepath.Join(tree.workDir, renderedHashFileName)); got != renderedHash {
			t.Errorf("rendered hash = %q, want %q", got, renderedHash)
		}
		requireAppliedHash(t, tree.workDir, chainHashes(sha256Hex(mergeBaseConfig), renderedHash))
	})

	t.Run("starts the base when the stored base hash is stale", func(t *testing.T) {
		tree := newMergeTree(t)
		ag := testMergeAgent(t, tree)
		ag.lastState.Users = mergeUsers()
		ag.reconcileMerged(t.Context())
		requireChild(t, ag)

		// An inert change: the declarations still match the base and the
		// stored render still passes check, but it belongs to the old base.
		changed := strings.Replace(mergeBaseConfig, `"timestamp": true`, `"timestamp": false`, 1)
		writeFile(t, tree.cfgPath, changed)

		boot := testMergeAgent(t, tree)
		if err := boot.bootstrap(t.Context()); err != nil {
			t.Fatalf("bootstrap: %v", err)
		}
		requireChild(t, boot)
		requireLastRunConfig(t, tree.logPath, tree.cfgPath)

		baseHash := sha256Hex(changed)
		if got := readFileString(t, filepath.Join(tree.workDir, renderedHashFileName)); got != baseHash {
			t.Errorf("rendered hash = %q, want the base hash %q", got, baseHash)
		}
		requireAppliedHash(t, tree.workDir, chainHashes(baseHash, baseHash))
	})

	t.Run("starts the base when the stored render fails check", func(t *testing.T) {
		tree := newMergeTree(t)
		writeFile(t, filepath.Join(tree.workDir, renderedFileName), mergeBaseConfig+invalidMarker)
		writeFile(t, filepath.Join(tree.workDir, renderedBaseHashFileName), sha256Hex(mergeBaseConfig))

		boot := testMergeAgent(t, tree)
		if err := boot.bootstrap(t.Context()); err != nil {
			t.Fatalf("bootstrap: %v", err)
		}
		requireChild(t, boot)
		requireLastRunConfig(t, tree.logPath, tree.cfgPath)
	})

	t.Run("fails fast on a target mismatch", func(t *testing.T) {
		tree := newMergeTree(t)
		tree.decls[0].SNI = "other.example.com"
		ag := testMergeAgent(t, tree)

		err := ag.bootstrap(t.Context())
		if err == nil {
			t.Fatal("expected bootstrap to reject a declaration the base cannot serve")
		}
		if ag.childRunning() {
			t.Error("child must not start when a declaration does not match the base")
		}
		for _, want := range []string{mergeVLESSTag, "sni", tree.cfgPath} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not mention %q", err, want)
			}
		}
	})
}

// TestStaticMergeReconcile covers the merge reconcile: the desired users are
// appended into both declared targets with the base's shape and flow, the
// render is validated and activated, the child restarts, and all three merge
// hashes advance under the work dir.
func TestStaticMergeReconcile(t *testing.T) {
	tree := newMergeTree(t)
	ag := testMergeAgent(t, tree)
	if err := ag.bootstrap(t.Context()); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	basePid := requireChild(t, ag)

	ag.lastState.Users = mergeUsers()
	hash := ag.reconcileMerged(t.Context())

	pid := requireChild(t, ag)
	if pid == basePid {
		t.Error("child not restarted on a merged render")
	}
	if got := ag.errorText(); got != "" {
		t.Errorf("unexpected error state: %q", got)
	}
	rendered := readFileString(t, filepath.Join(tree.workDir, renderedFileName))
	renderedHash := sha256Hex(rendered)
	baseHash := sha256Hex(mergeBaseConfig)
	requireHash(t, hash, chainHashes(baseHash, renderedHash))
	if got := readFileString(t, filepath.Join(tree.workDir, renderedHashFileName)); got != renderedHash {
		t.Errorf("rendered hash = %q, want %q", got, renderedHash)
	}
	if got := readFileString(t, filepath.Join(tree.workDir, renderedBaseHashFileName)); got != baseHash {
		t.Errorf("rendered base hash = %q, want %q", got, baseHash)
	}
	requireAppliedHash(t, tree.workDir, chainHashes(baseHash, renderedHash))
	requireLastRunConfig(t, tree.logPath, filepath.Join(tree.workDir, renderedFileName))

	vlessUsers := inboundUsers(t, rendered, mergeVLESSTag)
	if got, want := len(vlessUsers), mergeLegacyVLESSUsers+len(mergeUsers()); got != want {
		t.Fatalf("vless users = %d, want %d", got, want)
	}
	for i, user := range mergeUsers() {
		want := map[string]any{"name": user.Name, "uuid": user.VLESSUUID, "flow": mergeFlow}
		if got := vlessUsers[mergeLegacyVLESSUsers+i]; !reflect.DeepEqual(got, want) {
			t.Errorf("appended vless user %d = %#v, want %#v", i, got, want)
		}
	}
	hy2Users := inboundUsers(t, rendered, mergeHy2Tag)
	if got, want := len(hy2Users), mergeLegacyHy2Users+len(mergeUsers()); got != want {
		t.Fatalf("hysteria2 users = %d, want %d", got, want)
	}
	for i, user := range mergeUsers() {
		want := map[string]any{"name": user.Name, "password": user.Hy2Password}
		if got := hy2Users[mergeLegacyHy2Users+i]; !reflect.DeepEqual(got, want) {
			t.Errorf("appended hysteria2 user %d = %#v, want %#v", i, got, want)
		}
	}
	if got := vlessUsers[0]["uuid"]; got != "45977ea3-f264-4671-bec9-5195fa960936" {
		t.Errorf("legacy vless users changed: first uuid = %v", got)
	}
}

// TestStaticMergeReconcileIdempotent covers the idempotency rule: unchanged
// inputs — including a bare mtime touch of the base — keep the child and the
// persisted hashes.
func TestStaticMergeReconcileIdempotent(t *testing.T) {
	tree := newMergeTree(t)
	ag := testMergeAgent(t, tree)
	ag.lastState.Users = mergeUsers()
	first := ag.reconcileMerged(t.Context())
	pid := requireChild(t, ag)

	if err := os.Chtimes(tree.cfgPath, time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	second := ag.reconcileMerged(t.Context())

	if got := childPid(ag); got != pid {
		t.Errorf("child restarted on unchanged inputs: pid %d -> %d", pid, got)
	}
	requireHash(t, second, first)
	requireAppliedHash(t, tree.workDir, first)
	if got := ag.errorText(); got != "" {
		t.Errorf("unexpected error state: %q", got)
	}
}

// TestStaticMergeRevocation covers user removal: a user dropped from the
// desired state disappears from the rendered config and the child restarts.
func TestStaticMergeRevocation(t *testing.T) {
	tree := newMergeTree(t)
	ag := testMergeAgent(t, tree)
	users := mergeUsers()
	ag.lastState.Users = users
	ag.reconcileMerged(t.Context())
	pid := requireChild(t, ag)

	ag.lastState.Users = users[:1]
	hash := ag.reconcileMerged(t.Context())

	if got := childPid(ag); got == pid || got == 0 {
		t.Errorf("child not restarted after a revocation: pid %d -> %d", pid, got)
	}
	rendered := readFileString(t, filepath.Join(tree.workDir, renderedFileName))
	for _, revoked := range []string{mergeDaveName, mergeDaveUUID, mergeDavePass} {
		if strings.Contains(rendered, revoked) {
			t.Errorf("revoked credential %q still present in the rendered config", revoked)
		}
	}
	requireHash(t, hash, chainHashes(sha256Hex(mergeBaseConfig), sha256Hex(rendered)))
	if got, want := len(inboundUsers(t, rendered, mergeVLESSTag)), mergeLegacyVLESSUsers+1; got != want {
		t.Errorf("vless users = %d, want %d", got, want)
	}
	if got, want := len(inboundUsers(t, rendered, mergeHy2Tag)), mergeLegacyHy2Users+1; got != want {
		t.Errorf("hysteria2 users = %d, want %d", got, want)
	}
}

// TestStaticMergeDrainedState covers the drained node: with zero desired users
// the rendered config is the base bytes again and the child restarts on it.
func TestStaticMergeDrainedState(t *testing.T) {
	tree := newMergeTree(t)
	ag := testMergeAgent(t, tree)
	ag.lastState.Users = mergeUsers()
	ag.reconcileMerged(t.Context())
	pid := requireChild(t, ag)

	ag.lastState.Users = nil
	hash := ag.reconcileMerged(t.Context())

	if got := childPid(ag); got == pid || got == 0 {
		t.Errorf("child not restarted on a drained state: pid %d -> %d", pid, got)
	}
	rendered := readFileString(t, filepath.Join(tree.workDir, renderedFileName))
	if rendered != mergeBaseConfig {
		t.Errorf("rendered config is not the base bytes:\n%s", rendered)
	}
	baseHash := sha256Hex(mergeBaseConfig)
	requireHash(t, hash, chainHashes(baseHash, baseHash))
}

// TestStaticMergeNeverWritesConfigDir covers the read-only rule: the base's
// directory and bytes survive a merge cycle, and the work dir ends up holding
// exactly the four merge files.
func TestStaticMergeNeverWritesConfigDir(t *testing.T) {
	tree := newMergeTree(t)
	if err := os.Chmod(tree.cfgDir, 0o555); err != nil {
		t.Fatalf("chmod config dir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(tree.cfgDir, 0o755); err != nil {
			t.Errorf("restore config dir mode: %v", err)
		}
	})
	ag := testMergeAgent(t, tree)
	cfgBefore := dirNames(t, tree.cfgDir)

	ag.lastState.Users = mergeUsers()
	hash := ag.reconcileMerged(t.Context())

	requireChild(t, ag)
	if hash == "" {
		t.Error("reconcile returned an empty applied hash")
	}
	if got := ag.errorText(); got != "" {
		t.Errorf("unexpected error state: %q", got)
	}
	if got := dirNames(t, tree.cfgDir); !slices.Equal(got, cfgBefore) {
		t.Errorf("config dir entries changed: %v -> %v", cfgBefore, got)
	}
	if got := readFileString(t, tree.cfgPath); got != mergeBaseConfig {
		t.Errorf("base config content changed: %q", got)
	}
	want := []string{hashFileName, renderedBaseHashFileName, renderedHashFileName, renderedFileName}
	if got := dirNames(t, tree.workDir); !slices.Equal(got, want) {
		t.Errorf("work dir entries = %v, want %v", got, want)
	}
}

// TestStaticMergeFailedCheckKeepsChild covers the staged-check rule: a render
// the fake sing-box rejects is discarded, the running child and the persisted
// hashes stay, and the error state names the failed check.
func TestStaticMergeFailedCheckKeepsChild(t *testing.T) {
	tree := newMergeTree(t)
	ag := testMergeAgent(t, tree)
	ag.lastState.Users = mergeUsers()
	applied := ag.reconcileMerged(t.Context())
	pid := requireChild(t, ag)
	renderedBefore := readFileString(t, filepath.Join(tree.workDir, renderedFileName))

	// The marker sits in the log section, which validation ignores, so only
	// the sing-box check can reject the new render.
	broken := strings.Replace(mergeBaseConfig, `"level": "fatal"`, `"level": "fatal", `+invalidMarker, 1)
	if broken == mergeBaseConfig {
		t.Fatal("fixture base does not carry the log level the test replaces")
	}
	writeFile(t, tree.cfgPath, broken)

	hash := ag.reconcileMerged(t.Context())

	if got := childPid(ag); got != pid {
		t.Errorf("child replaced after a failed check: pid %d -> %d", pid, got)
	}
	requireHash(t, hash, applied)
	requireAppliedHash(t, tree.workDir, applied)
	if got := readFileString(t, filepath.Join(tree.workDir, renderedFileName)); got != renderedBefore {
		t.Error("stored render advanced past a failed check")
	}
	if got := ag.errorText(); !strings.Contains(got, "check") {
		t.Errorf("error state = %q, want a sing-box check error", got)
	}
	if got := dirNames(t, tree.workDir); slices.Contains(got, renderedFileName+".new") {
		t.Errorf("staged render left behind in the work dir: %v", got)
	}
}

// mergeTree is one merge-mode temp layout: cfgDir holds the operator base,
// workDir the agent state, dataDir the sing-box -D directory with the
// certificate the base serves, logPath the fake sing-box invocation log.
type mergeTree struct {
	cfgDir  string
	workDir string
	dataDir string
	cfgPath string
	singbox string
	logPath string
	decls   []model.InboundDecl
}

// newMergeTree builds the layout, pins the declarations to the base and points
// the fake sing-box at a log the tests read to see which config it runs.
func newMergeTree(t *testing.T) mergeTree {
	t.Helper()
	root := t.TempDir()
	tree := mergeTree{
		cfgDir:  filepath.Join(root, "cfg"),
		workDir: filepath.Join(root, "work"),
		dataDir: filepath.Join(root, "data"),
		singbox: fakeSingbox(t, root),
		logPath: filepath.Join(root, "singbox.log"),
	}
	for _, dir := range []string{tree.cfgDir, tree.workDir, tree.dataDir} {
		mkdirAll(t, dir)
	}
	tree.cfgPath = writeFile(t, filepath.Join(tree.cfgDir, configFileName), mergeBaseConfig)
	tree.decls = mergeDecls(t, tree.dataDir)
	t.Setenv("SINGBOX_LOG", tree.logPath)
	return tree
}

// mergeDecls writes the certificate the base serves under dataDir and returns
// the declarations pinned to the base's reality key and that certificate.
func mergeDecls(t *testing.T, dataDir string) []model.InboundDecl {
	t.Helper()
	certPEM, keyPEM, err := generate.GenerateSelfSignedCertPEM(mergeSNI)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	certsDir := filepath.Join(dataDir, "certs")
	mkdirAll(t, certsDir)
	writeFile(t, filepath.Join(certsDir, mergeSNI+".crt"), string(certPEM))
	writeFile(t, filepath.Join(certsDir, mergeSNI+".key"), string(keyPEM))

	publicKey, err := generate.DerivePublicKey(mergeRealityPrivateKey)
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	pin, err := generate.ComputePinSHA256(certPEM)
	if err != nil {
		t.Fatalf("compute certificate pin: %v", err)
	}
	return []model.InboundDecl{
		{
			Tag: mergeVLESSTag, Type: model.InboundVLESSReality, SNI: mergeSNI, ListenPort: mergeListenPort,
			RealityPublicKey: publicKey, RealityShortID: mergeShortID,
		},
		{
			Tag: mergeHy2Tag, Type: model.InboundHysteria2, SNI: mergeSNI, ListenPort: mergeListenPort,
			ObfsPassword: mergeObfsPassword, PinSHA256: pin,
		},
	}
}

// mergeUsers returns the control plane users the merge tests feed in.
func mergeUsers() []model.User {
	return []model.User{
		{Name: mergeCarolName, VLESSUUID: mergeCarolUUID, Hy2Password: mergeCarolPass},
		{Name: mergeDaveName, VLESSUUID: mergeDaveUUID, Hy2Password: mergeDavePass},
	}
}

// testMergeAgent builds a merge-mode agent wired to the fake sing-box,
// stopping the child when the test ends.
func testMergeAgent(t *testing.T, tree mergeTree) *agent {
	t.Helper()
	ag := testAgent(t, tree.workDir, tree.singbox, tree.cfgPath, tree.dataDir)
	ag.mergeTargets = true
	ag.spec.Inbounds = tree.decls
	return ag
}

// staticTree is one temp layout: cfgDir holds the operator config, workDir the
// agent state, dataDir the sing-box -D directory.
type staticTree struct {
	cfgDir  string
	workDir string
	dataDir string
	cfgPath string
	singbox string
}

// newStaticTree builds the layout with content as the static config.
func newStaticTree(t *testing.T, content string) staticTree {
	t.Helper()
	root := t.TempDir()
	tree := staticTree{
		cfgDir:  filepath.Join(root, "cfg"),
		workDir: filepath.Join(root, "work"),
		dataDir: filepath.Join(root, "data"),
		singbox: fakeSingbox(t, root),
	}
	for _, dir := range []string{tree.cfgDir, tree.workDir, tree.dataDir} {
		mkdirAll(t, dir)
	}
	tree.cfgPath = writeFile(t, filepath.Join(tree.cfgDir, configFileName), content)
	return tree
}

// testAgent builds an agent literal wired to the fake sing-box, stopping the
// child when the test ends.
func testAgent(t *testing.T, workDir, singbox, staticConfig, dataDir string) *agent {
	t.Helper()
	ag := &agent{
		ctx:          t.Context(),
		logger:       discardLogger(),
		workDir:      workDir,
		singbox:      singbox,
		staticConfig: staticConfig,
		dataDir:      dataDir,
	}
	t.Cleanup(ag.stopChild)
	return ag
}

// startStaticChild reconciles the fixture once and returns the agent with the
// pid of the started child.
func startStaticChild(t *testing.T, tree staticTree) (*agent, int) {
	t.Helper()
	ag := testAgent(t, tree.workDir, tree.singbox, tree.cfgPath, tree.dataDir)
	ag.reconcileStatic(t.Context())
	return ag, requireChild(t, ag)
}

// fakeSingbox writes the executable stub sing-box into dir and returns its path.
func fakeSingbox(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "sing-box")
	if err := os.WriteFile(path, []byte(singboxScript), 0o755); err != nil {
		t.Fatalf("write fake sing-box: %v", err)
	}
	return path
}

// setenvCommon points newAgent at the spec and a control plane the tests never
// actually reach.
func setenvCommon(t *testing.T, specPath string) {
	t.Helper()
	t.Setenv("KROT_SPEC", specPath)
	t.Setenv("KROT_CP_URL", testCPURL)
	t.Setenv("KROT_AGENT_TOKEN", testToken)
}

// discardLogger returns a logger that drops every record.
func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// childPid returns the running child pid, or 0 when no child is running.
func childPid(a *agent) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.child == nil || a.child.Process == nil {
		return 0
	}
	return a.child.Process.Pid
}

// requireChild fails the test unless a child is running; it returns its pid.
func requireChild(t *testing.T, a *agent) int {
	t.Helper()
	pid := childPid(a)
	if pid == 0 {
		t.Fatal("child not started from the static config")
	}
	return pid
}

// requireHash fails the test unless the reconcile result matches want.
func requireHash(t *testing.T, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("reconcile hash = %q, want %q", got, want)
	}
}

// requireAppliedHash fails the test unless applied.hash holds want.
func requireAppliedHash(t *testing.T, workDir, want string) {
	t.Helper()
	if got := readFileString(t, filepath.Join(workDir, hashFileName)); got != want {
		t.Errorf("applied hash = %q, want %q", got, want)
	}
}

// requireLastRunConfig waits until the fake sing-box has logged a run of
// configPath as its most recent invocation: the child writes the log line only
// after it starts, so the first read may miss it.
func requireLastRunConfig(t *testing.T, logPath string, configPath string) {
	t.Helper()
	deadline := time.Now().Add(mergeLogTimeout)
	for {
		configs := runConfigs(t, logPath)
		if len(configs) > 0 && configs[len(configs)-1] == configPath {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("last run config = %v, want %q", configs, configPath)
		}
		time.Sleep(mergeLogPoll)
	}
}

// runConfigs returns the config path of every sing-box run the fake binary was
// asked to start, in order.
func runConfigs(t *testing.T, logPath string) []string {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("read sing-box log %s: %v", logPath, err)
	}
	var configs []string
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		if !strings.HasPrefix(line, "run ") {
			continue
		}
		_, configPath, ok := strings.Cut(line, " -c ")
		if !ok {
			t.Fatalf("sing-box log line %q carries no -c argument", line)
		}
		configs = append(configs, configPath)
	}
	return configs
}

// inboundUsers decodes a rendered config and returns the users array entries
// of the inbound with the given tag.
func inboundUsers(t *testing.T, raw string, tag string) []map[string]any {
	t.Helper()
	var tree struct {
		Inbounds []struct {
			Tag   string           `json:"tag"`
			Users []map[string]any `json:"users"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal([]byte(raw), &tree); err != nil {
		t.Fatalf("decode rendered config: %v", err)
	}
	for _, in := range tree.Inbounds {
		if in.Tag == tag {
			return in.Users
		}
	}
	t.Fatalf("rendered config has no inbound %q", tag)
	return nil
}

// dirNames returns a directory's entry names (os.ReadDir sorts them).
func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// mkdirAll creates dir, failing the test on error.
func mkdirAll(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
}

// writeFile writes content to path, failing the test on error.
func writeFile(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// readFileString returns a file's content, failing the test on error.
func readFileString(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// sha256Hex returns the hex sha256 of s, mirroring the agent's file hashing.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
