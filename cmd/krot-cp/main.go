// Command krot-cp is the krot control plane: the templ+htmx
// portal, the subscription endpoint, the agent API and the identity sync
// goroutine over a PostgreSQL store.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Arsolitt/krot/internal/authentik"
	"github.com/Arsolitt/krot/internal/cpapi"
	"github.com/Arsolitt/krot/internal/directory"
	"github.com/Arsolitt/krot/internal/oidc"
	"github.com/Arsolitt/krot/internal/render"
	"github.com/Arsolitt/krot/internal/store"
	"github.com/Arsolitt/krot/internal/sub"
	"github.com/Arsolitt/krot/internal/web"
	"github.com/Arsolitt/krot/internal/zitadel"
)

// Defaults for durations and literals.
const (
	keyLen = 32
	// discoveryRetry delays OIDC discovery retries; the server starts and
	// serves subscriptions and the agent API while the provider is down.
	discoveryRetry    = 10 * time.Second
	readHeaderTimeout = 10 * time.Second
	shutdownTimeout   = 5 * time.Second

	defaultCacheTTL     = 5 * time.Minute
	defaultGrace        = 24 * time.Hour
	defaultSessionTTL   = 720 * time.Hour
	defaultSyncInterval = 60 * time.Second

	// Identity providers accepted in KROT_IDP.
	idpAuthentik = "authentik"
	idpZitadel   = "zitadel"

	// Provider-scoped defaults: group names for authentik, role keys for
	// Zitadel. Both providers are expected to be configured with these
	// (KROT_AUTHENTIK_GROUP, KROT_ZITADEL_ROLE and the admin counterparts).
	defaultAuthentikGroup      = "krot::vpn"
	defaultAuthentikAdminGroup = "krot::admins"
	defaultZitadelRole         = "vpn"
	defaultZitadelAdminRole    = "vpn-admin"

	defaultProfileTitle    = "Krot VPN"
	defaultProfileSupport  = "https://"
	defaultUpdateIntervalH = 24
)

// config is the environment-derived configuration. Non-secret knobs come
// from the krot-cp-config ConfigMap, secrets from krot-cp-secrets
// (both injected with envFrom).
type config struct {
	IDP                 string
	ListenAddr          string
	ProfileTitle        string
	ClientID            string
	ClientSecret        string
	Issuer              string
	ProfileSupport      string
	BaseURL             string
	DatabaseURL         string
	AgentToken          string
	AuthentikURL        string
	AuthentikToken      string
	AuthentikGroup      string
	AuthentikAdminGroup string
	ZitadelURL          string
	ZitadelToken        string
	ZitadelProjectID    string
	ZitadelRole         string
	ZitadelAdminRole    string
	CookieKey           []byte
	TokenKey            []byte
	ProfileIntervalH    int
	CacheTTL            time.Duration
	Grace               time.Duration
	SessionTTL          time.Duration
	SyncInterval        time.Duration
}

// vpnRole returns the configured group (authentik) or role key (Zitadel)
// gating subscriptions.
func (c config) vpnRole() string {
	if c.IDP == idpZitadel {
		return c.ZitadelRole
	}
	return c.AuthentikGroup
}

// adminRole returns the configured group (authentik) or role key (Zitadel)
// gating the admin panel.
func (c config) adminRole() string {
	if c.IDP == idpZitadel {
		return c.ZitadelAdminRole
	}
	return c.AuthentikAdminGroup
}

// loadConfig reads the environment and fails with the full list of missing
// or malformed variables.
func loadConfig() (config, error) {
	idp := envString("KROT_IDP", idpAuthentik)
	var providerVars []string
	switch idp {
	case idpAuthentik:
		providerVars = []string{"KROT_AUTHENTIK_URL", "KROT_AUTHENTIK_TOKEN", "KROT_AUTHENTIK_GROUP"}
	case idpZitadel:
		providerVars = []string{
			"KROT_ZITADEL_URL",
			"KROT_ZITADEL_TOKEN",
			"KROT_ZITADEL_PROJECT_ID",
			"KROT_ZITADEL_ROLE",
		}
	default:
		return config{}, fmt.Errorf(
			"KROT_IDP: unsupported identity provider %q (want %q or %q)",
			idp,
			idpAuthentik,
			idpZitadel,
		)
	}

	required := append([]string{
		"KROT_TOKEN_KEY",
		"KROT_COOKIE_KEY",
		"KROT_OIDC_CLIENT_ID",
		"KROT_OIDC_CLIENT_SECRET",
		"KROT_OIDC_ISSUER",
		"KROT_BASE_URL",
		"KROT_DATABASE_URL",
		"KROT_AGENT_TOKEN",
	}, providerVars...)
	var missing []string
	for _, name := range required {
		if os.Getenv(name) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return config{}, fmt.Errorf("missing required env vars: %s", strings.Join(missing, ", "))
	}

	cfg := config{
		IDP:        idp,
		BaseURL:    os.Getenv("KROT_BASE_URL"),
		Issuer:     os.Getenv("KROT_OIDC_ISSUER"),
		ListenAddr: envString("KROT_LISTEN_ADDR", ":8080"),

		ClientID:     os.Getenv("KROT_OIDC_CLIENT_ID"),
		ClientSecret: os.Getenv("KROT_OIDC_CLIENT_SECRET"),
		DatabaseURL:  os.Getenv("KROT_DATABASE_URL"),
		AgentToken:   os.Getenv("KROT_AGENT_TOKEN"),

		AuthentikURL:        os.Getenv("KROT_AUTHENTIK_URL"),
		AuthentikToken:      os.Getenv("KROT_AUTHENTIK_TOKEN"),
		AuthentikGroup:      envString("KROT_AUTHENTIK_GROUP", defaultAuthentikGroup),
		AuthentikAdminGroup: envString("KROT_AUTHENTIK_ADMIN_GROUP", defaultAuthentikAdminGroup),
		ZitadelURL:          os.Getenv("KROT_ZITADEL_URL"),
		ZitadelToken:        os.Getenv("KROT_ZITADEL_TOKEN"),
		ZitadelProjectID:    os.Getenv("KROT_ZITADEL_PROJECT_ID"),
		ZitadelRole:         envString("KROT_ZITADEL_ROLE", defaultZitadelRole),
		ZitadelAdminRole:    envString("KROT_ZITADEL_ADMIN_ROLE", defaultZitadelAdminRole),

		ProfileTitle:     envString("KROT_PROFILE_TITLE", defaultProfileTitle),
		ProfileSupport:   envString("KROT_PROFILE_SUPPORT_URL", defaultProfileSupport),
		ProfileIntervalH: envInt("KROT_PROFILE_UPDATE_INTERVAL_HOURS", defaultUpdateIntervalH),
	}

	var err error
	if cfg.TokenKey, err = decodeKey("KROT_TOKEN_KEY"); err != nil {
		return config{}, err
	}
	if cfg.CookieKey, err = decodeKey("KROT_COOKIE_KEY"); err != nil {
		return config{}, err
	}
	durations := []struct {
		into *time.Duration
		name string
		def  time.Duration
	}{
		{into: &cfg.CacheTTL, name: "KROT_CACHE_TTL", def: defaultCacheTTL},
		{into: &cfg.Grace, name: "KROT_GRACE", def: defaultGrace},
		{into: &cfg.SessionTTL, name: "KROT_SESSION_TTL", def: defaultSessionTTL},
		{into: &cfg.SyncInterval, name: "KROT_SYNC_INTERVAL", def: defaultSyncInterval},
	}
	for _, d := range durations {
		if *d.into, err = envDuration(d.name, d.def); err != nil {
			return config{}, err
		}
	}

	return cfg, nil
}

func main() {
	flag.Parse()
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "krot-cp: %v\n", err)
		os.Exit(1)
	}
}

// run boots the control plane and blocks until it stops.
func run() error {
	logger := slog.Default()

	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	if err := store.Migrate(cfg.DatabaseURL); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()

	src, err := newSource(cfg, cfg.vpnRole())
	if err != nil {
		return err
	}
	adminSrc, err := newSource(cfg, cfg.adminRole())
	if err != nil {
		return err
	}
	checker := directory.Wrap(src, cfg.CacheTTL, cfg.Grace)
	adminChecker := directory.Wrap(adminSrc, cfg.CacheTTL, cfg.Grace)

	// The routing profile is static for the process lifetime; a build
	// failure (blank profile title) must abort startup rather than serve
	// subscriptions without routing.
	routingURI, err := render.HappRoutingLink(cfg.ProfileTitle)
	if err != nil {
		return fmt.Errorf("happ routing profile: %w", err)
	}
	routingProfile, err := render.HappRoutingProfileJSON(cfg.ProfileTitle)
	if err != nil {
		return fmt.Errorf("happ routing profile: %w", err)
	}

	subs := sub.New(cfg.TokenKey, sub.Profile{
		BaseURL:             cfg.BaseURL,
		Title:               cfg.ProfileTitle,
		SupportURL:          cfg.ProfileSupport,
		UpdateIntervalHours: cfg.ProfileIntervalH,
		RoutingURI:          routingURI,
	}, st, checker, logger)

	syncTrigger := make(chan struct{}, 1)
	go syncLoop(ctx, logger, st, src, cfg.SyncInterval, syncTrigger)

	var relyingParty atomicRP
	go discover(ctx, logger, cfg, &relyingParty)

	httpServer := &http.Server{
		Addr: cfg.ListenAddr,
		Handler: newMux(
			cfg,
			st,
			subs,
			checker,
			adminChecker,
			&relyingParty,
			syncTrigger,
			logger,
			routingURI,
			routingProfile,
		),
		ReadHeaderTimeout: readHeaderTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- httpServer.ListenAndServe()
	}()

	logger.Info("krot-cp listening",
		"addr", cfg.ListenAddr,
		"idp", cfg.IDP,
		"group", cfg.vpnRole(),
		"admin_group", cfg.adminRole(),
	)

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve: %w", err)
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
	}
	return nil
}

// atomicRP is the relying-party slot filled by the discover goroutine.
type atomicRP = atomic.Pointer[oidc.RP]

// syncLoop reconciles users from the configured directory group/role on every
// tick and on demand; API failures keep the last state and are recorded in
// sync_state.
func syncLoop(
	ctx context.Context,
	logger *slog.Logger,
	st *store.Store,
	src directory.Source,
	interval time.Duration,
	trigger chan struct{},
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		syncOnce(ctx, logger, st, src)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-trigger:
		}
	}
}

// syncOnce performs one directory group/role sync.
func syncOnce(ctx context.Context, logger *slog.Logger, st *store.Store, src directory.Source) {
	members, err := src.Members(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "identity sync fetch failed", "error", err)
		if serr := st.SetSyncError(ctx, err.Error()); serr != nil {
			logger.ErrorContext(ctx, "record sync error failed", "error", serr)
		}
		return
	}
	if err := st.SyncUsers(ctx, members); err != nil {
		logger.ErrorContext(ctx, "identity sync apply failed", "error", err)
		if serr := st.SetSyncError(ctx, err.Error()); serr != nil {
			logger.ErrorContext(ctx, "record sync error failed", "error", serr)
		}
		return
	}
	logger.InfoContext(ctx, "identity sync done", "members", len(members))
}

// discover keeps retrying OIDC provider discovery and installs the relying
// party once it succeeds.
func discover(ctx context.Context, logger *slog.Logger, cfg config, relyingParty *atomicRP) {
	// The redirect URL comes from configuration only: ingress TLS
	// termination is invisible to the app.
	redirectURL := cfg.BaseURL + "/callback"
	for {
		rp, err := oidc.New(ctx, cfg.Issuer, cfg.ClientID, cfg.ClientSecret, redirectURL, cfg.CookieKey, cfg.SessionTTL)
		if err == nil {
			relyingParty.Store(rp)
			logger.InfoContext(ctx, "oidc provider ready", "issuer", cfg.Issuer)
			return
		}
		logger.ErrorContext(ctx, "oidc discovery failed; retrying", "issuer", cfg.Issuer, "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(discoveryRetry):
		}
	}
}

// newSource builds the configured identity-provider client for one group or
// role.
func newSource(cfg config, role string) (directory.Source, error) {
	switch cfg.IDP {
	case idpZitadel:
		return zitadel.NewClient(cfg.ZitadelURL, cfg.ZitadelToken, cfg.ZitadelProjectID, role, nil), nil
	case idpAuthentik:
		return authentik.NewClient(cfg.AuthentikURL, cfg.AuthentikToken, role, nil), nil
	default:
		return nil, fmt.Errorf(
			"KROT_IDP: unsupported identity provider %q (want %q or %q)",
			cfg.IDP,
			idpAuthentik,
			idpZitadel,
		)
	}
}

// newMux wires every route: portal, admin, subscriptions, agent API, probes
// and the public Happ routing endpoints.
func newMux(
	cfg config,
	st *store.Store,
	subs *sub.Server,
	checker, adminChecker *directory.Cached,
	relyingParty *atomicRP,
	syncTrigger chan struct{},
	logger *slog.Logger,
	routingURI string,
	routingProfile []byte,
) *http.ServeMux {
	mux := http.NewServeMux()

	pages := &web.Deps{
		Sub:          subs,
		RP:           relyingParty,
		Checker:      checker,
		AdminChecker: adminChecker,
		Store:        st,
		Trigger: func() {
			select {
			case syncTrigger <- struct{}{}:
			default:
			}
		},
		BaseURL:            cfg.BaseURL,
		Logger:             logger,
		RoutingURI:         routingURI,
		RoutingProfileJSON: routingProfile,
		ProfileTitle:       cfg.ProfileTitle,
	}

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		if rp := relyingParty.Load(); rp == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		pages.Page(w, r)
	})
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		rp := relyingParty.Load()
		if rp == nil {
			http.Error(w, "login unavailable: identity provider still connecting", http.StatusServiceUnavailable)
			return
		}
		rp.LoginHandler()(w, r)
	})
	mux.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		rp := relyingParty.Load()
		if rp == nil {
			http.Error(w, "login unavailable: identity provider still connecting", http.StatusServiceUnavailable)
			return
		}
		rp.CallbackHandler(http.RedirectHandler("/", http.StatusFound).ServeHTTP)(w, r)
	})
	mux.HandleFunc("GET /logout", func(w http.ResponseWriter, r *http.Request) {
		if rp := relyingParty.Load(); rp != nil {
			rp.LogoutHandler()(w, r)
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
	})

	mux.HandleFunc("GET /admin", pages.AdminPage)
	mux.HandleFunc("GET /admin/panel", pages.AdminPanel)
	mux.HandleFunc("POST /admin/sync", pages.Sync)

	// Public by design: the Happ routing profile is identical for every
	// client and holds no per-user data.
	mux.HandleFunc("GET /routing", pages.RoutingPage)
	mux.HandleFunc("GET /routing.json", pages.RoutingProfile)
	mux.HandleFunc("GET /routing/import", pages.RoutingImport)

	cpapi.New(cfg.AgentToken, st, logger).Register(mux)

	mux.Handle("GET /sub/{token}", subs.Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := st.Ping(r.Context()); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ready\n"))
	})

	staticFS, err := fs.Sub(web.Static(), "static")
	if err != nil {
		logger.Error("static assets unavailable", "error", err)
	} else {
		mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(staticFS)))
	}

	return mux
}

// envString reads an environment variable with a default.
func envString(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// envInt reads an integer environment variable with a default.
func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// envDuration reads a duration variable with a default.
func envDuration(name string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return d, nil
}

// decodeKey decodes a base64-encoded 32-byte secret.
func decodeKey(name string) ([]byte, error) {
	raw, err := base64.RawStdEncoding.DecodeString(os.Getenv(name))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if len(raw) != keyLen {
		return nil, fmt.Errorf("%s: decoded %d bytes, want %d", name, len(raw), keyLen)
	}
	return raw, nil
}
