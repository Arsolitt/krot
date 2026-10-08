// Command krot-agent runs sing-box on a proxy node under control-plane
// management: it polls its declared spec, renders the sing-box config,
// validates it, and supervises the sing-box child process.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Arsolitt/krot/internal/agentapi"
	"github.com/Arsolitt/krot/internal/model"
	"github.com/Arsolitt/krot/internal/render"
)

// Defaults and fixed knobs.
const (
	defaultPollInterval = 30 * time.Second
	defaultSpecPath     = "/etc/krot/agent.yaml"
	defaultWorkDir      = "/etc/krot"
	defaultSingboxPath  = "/usr/local/bin/sing-box"
	defaultHealthAddr   = "127.0.0.1:18081"
	cacheFileName       = "cache.db"
	configFileName      = "config.json"
	hashFileName        = "applied.hash"
	filePerm0600        = 0o600
	termWait            = 10 * time.Second
	crashBackoff        = 5 * time.Second
	healthReadHeader    = 10 * time.Second
)

// agent bundles the runtime state of one node agent.
type agent struct {
	ctx          context.Context
	child        *exec.Cmd
	client       *agentapi.Client
	logger       *slog.Logger
	workDir      string
	singbox      string
	staticConfig string
	dataDir      string
	healthAddr   string
	lastError    string
	lastState    model.DesiredState
	spec         model.Spec
	interval     time.Duration
	mu           sync.Mutex
	stopping     bool
}

func main() {
	logger := slog.Default()

	ag, err := newAgent(logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "krot-agent: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ag.ctx = ctx
	go ag.serveHealth(ctx, logger)

	// Fast boot: start the last known config without waiting for the CP.
	if err := ag.bootstrap(ctx); err != nil {
		stop()
		fmt.Fprintf(os.Stderr, "krot-agent: %v\n", err)
		//nolint:gocritic // stop() releases the signal handler before the fatal exit.
		os.Exit(1)
	}

	ag.loop(ctx)
	ag.stopChild()
	logger.Info("agent stopped")
}

// newAgent reads the environment and the declared spec file.
func newAgent(logger *slog.Logger) (*agent, error) {
	specPath := envString("KROT_SPEC", defaultSpecPath)
	raw, err := os.ReadFile(specPath)
	if err != nil {
		return nil, fmt.Errorf("read spec: %w", err)
	}
	var spec model.Spec
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		return nil, fmt.Errorf("parse spec %s: %w", specPath, err)
	}

	// Static mode: KROT_STATIC_CONFIG points at an operator-owned sing-box
	// config the agent supervises verbatim and never renders, so a spec that
	// declares inbounds cannot be honoured.
	workDir := envString("KROT_WORKDIR", defaultWorkDir)
	staticConfig := os.Getenv("KROT_STATIC_CONFIG")
	dataDir := workDir
	if staticConfig != "" {
		if len(spec.Inbounds) > 0 {
			return nil, fmt.Errorf(
				"static config mode requires an inbounds-free spec: %s declares %d inbounds",
				specPath, len(spec.Inbounds),
			)
		}
		if err := validateStaticConfig(staticConfig); err != nil {
			return nil, err
		}
		dataDir = envString("KROT_STATIC_DATA_DIR", filepath.Dir(staticConfig))
		if err := validateStaticDataDir(dataDir); err != nil {
			return nil, err
		}
	}

	interval, err := time.ParseDuration(envString("KROT_POLL_INTERVAL", defaultPollInterval.String()))
	if err != nil {
		return nil, fmt.Errorf("parse poll interval: %w", err)
	}

	cpURL := os.Getenv("KROT_CP_URL")
	if cpURL == "" {
		return nil, errors.New("KROT_CP_URL is required")
	}
	token := os.Getenv("KROT_AGENT_TOKEN")
	if token == "" {
		return nil, errors.New("KROT_AGENT_TOKEN is required")
	}

	return &agent{
		client:       agentapi.New(cpURL, token, nil),
		spec:         spec,
		workDir:      workDir,
		singbox:      envString("KROT_SINGBOX", defaultSingboxPath),
		staticConfig: staticConfig,
		dataDir:      dataDir,
		healthAddr:   envString("KROT_HEALTH_ADDR", defaultHealthAddr),
		interval:     interval,
		logger:       logger,
	}, nil
}

// validateStaticConfig fails fast unless the operator-owned static config
// exists as a readable regular file.
func validateStaticConfig(path string) error {
	// #nosec G703 -- the path is operator configuration from env.
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("static config %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("static config %s: not a regular file", path)
	}
	// #nosec G703 -- the path is operator configuration from env.
	if _, err := os.ReadFile(path); err != nil {
		return fmt.Errorf("static config %s: %w", path, err)
	}
	return nil
}

// validateStaticDataDir fails fast unless the sing-box working directory (-D)
// exists and is readable.
func validateStaticDataDir(path string) error {
	// #nosec G703 -- the path is operator configuration from env.
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("static data dir %s: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("static data dir %s: not a directory", path)
	}
	// #nosec G703 -- the path is operator configuration from env.
	if _, err := os.ReadDir(path); err != nil {
		return fmt.Errorf("static data dir %s: %w", path, err)
	}
	return nil
}

// loop polls the control plane until the context is cancelled.
func (a *agent) loop(ctx context.Context) {
	a.pollOnce(ctx)

	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.pollOnce(ctx)
		}
	}
}

// pollOnce performs one desired-state cycle: fetch, compare hash, re-render,
// validate, restart the child, heartbeat. In static mode the control plane is
// only used for registration and heartbeats; the config never comes from it.
func (a *agent) pollOnce(ctx context.Context) {
	if a.staticConfig != "" {
		a.pollStatic(ctx)
		return
	}

	state, err := a.client.DesiredState(ctx, a.spec)
	if err != nil {
		a.logger.ErrorContext(ctx, "desired-state fetch failed", "error", err)
		if cfgErr, isCfg := errors.AsType[*agentapi.ConfigError](err); isCfg {
			a.setError(cfgErr.Message)
			a.heartbeat(ctx, "")
		}
		return
	}
	a.lastState = state

	if state.Hash == a.readAppliedHash() {
		a.heartbeat(ctx, "")
		return
	}

	if err := a.apply(ctx, state); err != nil {
		a.logger.ErrorContext(ctx, "apply failed", "error", err)
		a.setError(err.Error())
		a.heartbeat(ctx, "")
		return
	}

	a.setError("")
	a.persistAppliedHash(ctx, state.Hash)
	a.heartbeat(ctx, state.Hash)
	a.logger.InfoContext(ctx, "config applied", "hash", state.Hash,
		"inbounds", len(state.Inbounds), "users", len(state.Users))
}

// pollStatic performs one cycle in static mode: desired state is still fetched
// so the node registers and heartbeats, but it never influences the config,
// and a rejected spec must not clobber the supervised config's status.
func (a *agent) pollStatic(ctx context.Context) {
	state, err := a.client.DesiredState(ctx, a.spec)
	if err != nil {
		a.logger.ErrorContext(ctx, "desired-state fetch failed", "error", err)
	} else {
		a.lastState = state
	}

	a.heartbeat(ctx, a.reconcileStatic(ctx))
}

// reconcileStatic validates the operator-owned static config when its content
// changed and restarts the child on success. It returns the hash of the config
// considered applied: the new one on success, the running one on failure.
func (a *agent) reconcileStatic(ctx context.Context) string {
	hash, err := hashFile(a.staticConfig)
	if err != nil {
		err = fmt.Errorf("read static config: %w", err)
		a.logger.ErrorContext(ctx, "static config unreadable; keeping running child", "error", err)
		a.setError(err.Error())
		return a.readAppliedHash()
	}

	applied := a.readAppliedHash()
	if hash == applied {
		// Only the content counts: a bare mtime touch must not restart.
		a.setError("")
		return hash
	}

	if err := a.check(ctx, a.staticConfig); err != nil {
		err = fmt.Errorf("sing-box check: %w", err)
		a.logger.ErrorContext(ctx, "static config failed check; keeping running child", "error", err)
		a.setError(err.Error())
		return applied
	}

	a.restartChild(a.staticConfig)
	a.persistAppliedHash(ctx, hash)
	a.setError("")
	a.logger.InfoContext(ctx, "static config applied", "hash", hash)
	return hash
}

// apply renders, validates (sing-box check) and activates the new config.
// The running child is only replaced after the check passes.
func (a *agent) apply(ctx context.Context, state model.DesiredState) error {
	opts, err := render.SingboxConfig(
		a.spec.RouteProfile, state.Inbounds, state.Users, filepath.Join(a.workDir, cacheFileName),
	)
	if err != nil {
		return fmt.Errorf("render config: %w", err)
	}
	data, err := render.Marshal(ctx, opts)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	newPath := filepath.Join(a.workDir, configFileName+".new")
	if err := os.WriteFile(newPath, data, os.FileMode(filePerm0600)); err != nil {
		return fmt.Errorf("write staged config: %w", err)
	}
	if err := render.WriteCerts(a.workDir, state.Inbounds); err != nil {
		return fmt.Errorf("write certs: %w", err)
	}

	if err := a.check(ctx, newPath); err != nil {
		_ = os.Remove(newPath)
		return fmt.Errorf("sing-box check: %w", err)
	}

	finalPath := filepath.Join(a.workDir, configFileName)
	if err := os.Rename(newPath, finalPath); err != nil {
		return fmt.Errorf("activate config: %w", err)
	}

	a.restartChild(finalPath)
	return nil
}

// check runs sing-box check against a config file.
func (a *agent) check(ctx context.Context, configPath string) error {
	// #nosec G204 -- the binary path is operator configuration from env.
	cmd := exec.CommandContext(ctx, a.singbox, "check", "-D", a.dataDir, "-c", configPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, truncateOutput(out))
	}
	return nil
}

// bootstrap starts the child before the first successful poll: from the
// operator-owned static config in static mode, from the last stored config in
// dynamic mode. Static mode fails fast so a node never runs unvalidated.
func (a *agent) bootstrap(ctx context.Context) error {
	if a.staticConfig != "" {
		hash, err := hashFile(a.staticConfig)
		if err != nil {
			return fmt.Errorf("read static config: %w", err)
		}
		if err := a.check(ctx, a.staticConfig); err != nil {
			return fmt.Errorf("static config %s: sing-box check: %w", a.staticConfig, err)
		}
		a.startChild(a.staticConfig)
		if !a.childRunning() {
			return fmt.Errorf("static config %s: sing-box did not start", a.staticConfig)
		}
		a.setError("")
		a.persistAppliedHash(ctx, hash)
		a.logger.InfoContext(ctx, "static config started", "config", a.staticConfig, "hash", hash)
		return nil
	}

	configPath := filepath.Join(a.workDir, configFileName)
	if _, err := os.Stat(configPath); err != nil {
		a.logger.InfoContext(ctx, "no stored config; waiting for control plane")
		return nil //nolint:nilerr // a missing stored config is a normal dynamic-mode startup state.
	}
	if err := a.check(ctx, configPath); err != nil {
		a.logger.ErrorContext(ctx, "stored config failed check; waiting for control plane", "error", err)
		return nil
	}
	a.startChild(configPath)
	return nil
}

// restartChild stops any running child and starts a new one.
func (a *agent) restartChild(configPath string) {
	a.stopChild()
	a.startChild(configPath)
}

// startChild launches sing-box in its own process group and watches it: an
// unexpected exit restarts it from the same config with a backoff.
func (a *agent) startChild(configPath string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.child != nil {
		return
	}

	// #nosec G204 -- the binary path is operator configuration from env.
	cmd := exec.CommandContext(a.ctx, a.singbox, "run", "-D", a.dataDir, "-c", configPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		a.logger.Error("start sing-box failed", "error", err)
		return
	}
	a.child = cmd
	a.logger.Info("sing-box started", "pid", cmd.Process.Pid)

	go a.watchChild(cmd, configPath)
}

// watchChild waits for the child; any exit that was not an intentional
// stop (normal exit code, crash, or kill by signal) restarts it.
func (a *agent) watchChild(cmd *exec.Cmd, configPath string) {
	err := cmd.Wait()
	a.mu.Lock()
	if a.child == cmd {
		a.child = nil
	}
	stopping := a.stopping
	a.mu.Unlock()

	if stopping {
		return
	}
	a.logger.Error("sing-box exited unexpectedly; restarting", "error", err)
	time.Sleep(crashBackoff)
	a.startChild(configPath)
}

// stopChild terminates the running child (process group): SIGTERM, then
// SIGKILL after the grace window.
func (a *agent) stopChild() {
	a.mu.Lock()
	cmd := a.child
	a.child = nil
	a.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return
	}

	a.stopping = true
	pgid := -cmd.Process.Pid
	_ = syscall.Kill(pgid, syscall.SIGTERM)

	done := make(chan struct{})
	go func() {
		_, _ = cmd.Process.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(termWait):
		_ = syscall.Kill(pgid, syscall.SIGKILL)
		<-done
	}
	a.stopping = false
}

// serveHealth answers /healthz with 200 while the child runs.
func (a *agent) serveHealth(ctx context.Context, logger *slog.Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		if a.childRunning() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
			return
		}
		http.Error(w, "sing-box not running", http.StatusServiceUnavailable)
	})

	server := &http.Server{
		Addr: a.healthAddr, Handler: mux, ReadHeaderTimeout: healthReadHeader,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), termWait)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.ErrorContext(ctx, "health server failed", "error", err)
	}
}

// heartbeat reports the current status to the control plane.
func (a *agent) heartbeat(ctx context.Context, appliedHash string) {
	healthy := a.childRunning()

	if appliedHash == "" {
		appliedHash = a.readAppliedHash()
	}
	err := a.client.Heartbeat(ctx, model.Heartbeat{
		Server:         a.spec.Server,
		AgentVersion:   version,
		AppliedHash:    appliedHash,
		SingboxHealthy: healthy,
		UserCount:      len(a.lastState.Users),
		ConfigError:    a.errorText(),
	})
	if err != nil {
		a.logger.WarnContext(ctx, "heartbeat failed", "error", err)
	}
}

// persistAppliedHash records the hash of the config the child runs, so later
// cycles only restart it when the content actually changed.
func (a *agent) persistAppliedHash(ctx context.Context, hash string) {
	hashPath := filepath.Join(a.workDir, hashFileName)
	if err := os.WriteFile(hashPath, []byte(hash), os.FileMode(filePerm0600)); err != nil {
		a.logger.ErrorContext(ctx, "persist applied hash failed", "error", err)
	}
}

// readAppliedHash loads the persisted applied hash (empty when never applied).
func (a *agent) readAppliedHash() string {
	data, err := os.ReadFile(filepath.Join(a.workDir, hashFileName))
	if err != nil {
		return ""
	}
	return string(data)
}

// hashFile returns the hex-encoded sha256 of a file's content.
func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// version is the agent build identifier.
var version = "dev"

// setError records the last configuration error for heartbeats.
func (a *agent) setError(msg string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastError = msg
}

// errorText returns the last configuration error, if any.
func (a *agent) errorText() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastError
}

// childRunning reports whether the sing-box child is up.
func (a *agent) childRunning() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.child != nil
}

// envString reads an environment variable with a default.
func envString(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// maxOutput bounds embedded sing-box output in errors.
const maxOutput = 500

// truncateOutput bounds embedded sing-box output in errors.
func truncateOutput(out []byte) string {
	if len(out) > maxOutput {
		return string(out[:maxOutput]) + "... (truncated)"
	}
	return string(out)
}
