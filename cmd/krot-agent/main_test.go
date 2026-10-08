package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
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

// singboxScript is the fake sing-box shared by all cycle tests: check exits 1
// when the config contains invalidMarker, run execs a long-lived sleep, and
// nothing ever touches the network.
const singboxScript = `#!/bin/sh
cmd="$1"
shift
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

// TestNewAgentRejectsStaticWithInboundSpec covers rule 4: static nodes are
// operator-managed, so a spec that declares inbounds is a startup error.
func TestNewAgentRejectsStaticWithInboundSpec(t *testing.T) {
	root := t.TempDir()
	cfgPath := writeFile(t, filepath.Join(root, configFileName), validConfig)
	specPath := writeFile(t, filepath.Join(root, specFile), inboundSpec)
	setenvCommon(t, specPath)
	t.Setenv("KROT_STATIC_CONFIG", cfgPath)

	_, err := newAgent(discardLogger())
	if err == nil {
		t.Fatal("expected newAgent to reject a static node with declared inbounds")
	}
	for _, want := range []string{"inbounds", "static", specPath} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
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
