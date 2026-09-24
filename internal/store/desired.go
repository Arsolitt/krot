package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/Arsolitt/cheburbox/generate"
	"github.com/jmoiron/sqlx"

	"github.com/Arsolitt/krot/internal/model"
	"github.com/Arsolitt/krot/internal/render"
)

// Valid listen port bounds.
const (
	minPort = 1
	maxPort = 65535
)

// validateSpec checks a declaration before any database work. Every failure
// wraps ErrInvalidSpec so the agent API can answer 400 with the message.
func validateSpec(spec model.Spec) error {
	if spec.Server == "" {
		return fmt.Errorf("%w: empty server name", ErrInvalidSpec)
	}
	if spec.Endpoint == "" {
		return fmt.Errorf("%w: empty endpoint", ErrInvalidSpec)
	}
	if !render.ValidProfile(spec.RouteProfile) {
		return fmt.Errorf("%w: unknown route_profile %q", ErrInvalidSpec, spec.RouteProfile)
	}

	seenTags := make(map[string]struct{}, len(spec.Inbounds))
	seenBinds := make(map[model.InboundType]map[int]struct{})
	for _, decl := range spec.Inbounds {
		if err := validateInbound(decl, seenTags, seenBinds); err != nil {
			return err
		}
	}
	return nil
}

// validateInbound checks one declaration and records it in the seen sets.
func validateInbound(
	decl model.InboundDecl,
	seenTags map[string]struct{},
	seenBinds map[model.InboundType]map[int]struct{},
) error {
	if decl.Tag == "" {
		return fmt.Errorf("%w: inbound with empty tag", ErrInvalidSpec)
	}
	if _, dup := seenTags[decl.Tag]; dup {
		return fmt.Errorf("%w: duplicate inbound tag %q", ErrInvalidSpec, decl.Tag)
	}
	seenTags[decl.Tag] = struct{}{}

	if !decl.Type.Valid() {
		return fmt.Errorf("%w: unknown inbound type %q", ErrInvalidSpec, decl.Type)
	}
	if decl.SNI == "" {
		return fmt.Errorf("%w: inbound %q has empty sni", ErrInvalidSpec, decl.Tag)
	}
	if decl.ListenPort < minPort || decl.ListenPort > maxPort {
		return fmt.Errorf("%w: inbound %q listen_port %d out of range", ErrInvalidSpec, decl.Tag, decl.ListenPort)
	}
	if decl.PublicPort != 0 && (decl.PublicPort < minPort || decl.PublicPort > maxPort) {
		return fmt.Errorf("%w: inbound %q public_port %d out of range", ErrInvalidSpec, decl.Tag, decl.PublicPort)
	}
	if decl.Type == model.InboundVLESSWS && (decl.WSPath == "" || decl.WSPath[0] != '/') {
		return fmt.Errorf("%w: vless_ws inbound %q needs ws_path starting with '/'", ErrInvalidSpec, decl.Tag)
	}

	ports, ok := seenBinds[decl.Type]
	if !ok {
		ports = make(map[int]struct{})
		seenBinds[decl.Type] = ports
	}
	if _, clash := ports[decl.ListenPort]; clash {
		return fmt.Errorf(
			"%w: inbounds collide on %s port %d", ErrInvalidSpec, decl.Type.Transport(), decl.ListenPort,
		)
	}
	ports[decl.ListenPort] = struct{}{}
	return nil
}

// declaredInbound is a declaration with defaults applied, ready for storage.
type declaredInbound struct {
	publicEndpoint string
	decl           model.InboundDecl
	publicPort     int
}

// applyDefaults fills public_endpoint from the server endpoint and
// public_port from listen_port when the declaration omits them.
func applyDefaults(spec model.Spec) []declaredInbound {
	out := make([]declaredInbound, 0, len(spec.Inbounds))
	for _, decl := range spec.Inbounds {
		d := declaredInbound{decl: decl, publicEndpoint: decl.PublicEndpoint, publicPort: decl.PublicPort}
		if d.publicEndpoint == "" {
			d.publicEndpoint = spec.Endpoint
		}
		if d.publicPort == 0 {
			d.publicPort = decl.ListenPort
		}
		out = append(out, d)
	}
	return out
}

// secrets are the per-inbound credential columns of an inbound row. Empty
// strings mean "not applicable or cleared".
type secrets struct {
	realityPrivateKey string
	realityPublicKey  string
	realityShortID    string
	obfsPassword      string
	certPEM           string
	keyPEM            string
	pinSHA256         string
}

// freshSecrets generates a full secret set for a newly declared inbound.
func freshSecrets(decl model.InboundDecl) (secrets, error) {
	var sec secrets
	var err error

	switch decl.Type {
	case model.InboundVLESSReality:
		if sec.realityPrivateKey, sec.realityPublicKey, err = generate.GenerateX25519KeyPair(); err != nil {
			return sec, fmt.Errorf("generate reality keys: %w", err)
		}
		if sec.realityShortID, err = generate.GenerateShortID(); err != nil {
			return sec, fmt.Errorf("generate short id: %w", err)
		}
	case model.InboundHysteria2:
		if sec.obfsPassword, err = generate.GeneratePassword(); err != nil {
			return sec, fmt.Errorf("generate obfs password: %w", err)
		}
		if sec, err = withFreshCert(sec, decl.SNI); err != nil {
			return sec, err
		}
	case model.InboundVLESSWS:
		if decl.OriginTLS {
			if sec, err = withFreshCert(sec, decl.SNI); err != nil {
				return sec, err
			}
		}
	}

	return sec, nil
}

// withFreshCert generates a self-signed certificate for sni and pins it.
func withFreshCert(sec secrets, sni string) (secrets, error) {
	certPEM, keyPEM, err := generate.GenerateSelfSignedCertPEM(sni)
	if err != nil {
		return sec, fmt.Errorf("generate cert for %s: %w", sni, err)
	}
	pin, err := generate.ComputePinSHA256(certPEM)
	if err != nil {
		return sec, fmt.Errorf("pin cert for %s: %w", sni, err)
	}
	sec.certPEM, sec.keyPEM, sec.pinSHA256 = string(certPEM), string(keyPEM), pin
	return sec, nil
}

// needsCert reports whether the inbound type terminates TLS with a stored
// certificate: hysteria2 always, vless_ws only when origin_tls is set.
func needsCert(decl model.InboundDecl) bool {
	return decl.Type == model.InboundHysteria2 || (decl.Type == model.InboundVLESSWS && decl.OriginTLS)
}

// mergeSecrets derives the stored secrets for an updated declaration,
// preserving stable credentials across non-secret changes.
func mergeSecrets(decl model.InboundDecl, existing model.Inbound) (secrets, error) {
	sec := secrets{
		realityPrivateKey: existing.RealityPrivateKey,
		realityPublicKey:  existing.RealityPublicKey,
		realityShortID:    existing.RealityShortID,
		obfsPassword:      existing.ObfsPassword,
		certPEM:           existing.CertPEM,
		keyPEM:            existing.KeyPEM,
		pinSHA256:         existing.PinSHA256,
	}

	switch {
	case needsCert(decl) && (existing.SNI != decl.SNI || existing.CertPEM == ""):
		// A SNI change invalidates the certificate; reality keys and the
		// obfs password deliberately survive it.
		return withFreshCert(sec, decl.SNI)
	case !needsCert(decl):
		// A ws inbound switched away from origin TLS no longer needs a cert.
		sec.certPEM, sec.keyPEM, sec.pinSHA256 = "", "", ""
	}
	return sec, nil
}

// DesiredState reconciles the agent's declaration into the database (single
// transaction) and returns the full desired state for the node.
func (s *Store) DesiredState(ctx context.Context, spec model.Spec) (model.DesiredState, error) {
	if err := validateSpec(spec); err != nil {
		return model.DesiredState{}, err
	}

	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return model.DesiredState{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op.

	var enabled bool
	if err := tx.GetContext(ctx, &enabled, `
		INSERT INTO servers (name, endpoint, route_profile)
		VALUES ($1, $2, $3)
		ON CONFLICT (name) DO UPDATE
		SET endpoint = EXCLUDED.endpoint, route_profile = EXCLUDED.route_profile, updated_at = now()
		RETURNING enabled
	`, spec.Server, spec.Endpoint, spec.RouteProfile); err != nil {
		return model.DesiredState{}, fmt.Errorf("upsert server: %w", err)
	}

	if err := s.reconcileInbounds(ctx, tx, spec); err != nil {
		return model.DesiredState{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.DesiredState{}, fmt.Errorf("commit tx: %w", err)
	}

	state := model.DesiredState{
		Server: model.Server{
			Name:         spec.Server,
			Endpoint:     spec.Endpoint,
			RouteProfile: spec.RouteProfile,
			Enabled:      enabled,
		},
	}
	return s.buildDesiredState(ctx, spec.Server, state)
}

// reconcileInbounds replaces the server's inbound set to match the
// declaration exactly: new tags get fresh secrets, changed non-secret params
// update in place, undeclared tags are deleted.
func (s *Store) reconcileInbounds(ctx context.Context, tx *sqlx.Tx, spec model.Spec) error {
	current, err := s.selectInboundRows(ctx, tx,
		"SELECT "+inboundColumns+" FROM inbounds WHERE server_name = $1", spec.Server,
	)
	if err != nil {
		return err
	}
	currentByTag := make(map[string]model.Inbound, len(current))
	for _, in := range current {
		currentByTag[in.Tag] = in
	}

	declaredTags := make(map[string]struct{}, len(spec.Inbounds))
	for _, d := range applyDefaults(spec) {
		declaredTags[d.decl.Tag] = struct{}{}
		existing, ok := currentByTag[d.decl.Tag]

		sec, err := secretsFor(d.decl, existing, ok)
		if err != nil {
			return err
		}
		if err := s.putInbound(ctx, tx, spec.Server, d, sec); err != nil {
			return err
		}
	}

	for _, in := range current {
		if _, keep := declaredTags[in.Tag]; !keep {
			if _, err := tx.ExecContext(ctx,
				"DELETE FROM inbounds WHERE server_name = $1 AND tag = $2", spec.Server, in.Tag,
			); err != nil {
				return fmt.Errorf("delete inbound %s: %w", in.Tag, err)
			}
		}
	}
	return nil
}

// secretsFor derives the stored secrets for one declared inbound: fresh ones
// for a new (or retyped) tag, merged ones for a param change.
func secretsFor(decl model.InboundDecl, existing model.Inbound, exists bool) (secrets, error) {
	switch {
	case !exists:
		return freshSecrets(decl)
	case existing.Type != decl.Type:
		// A tag reused for a different inbound type is a new inbound:
		// replace the row wholesale with fresh secrets.
		return freshSecrets(decl)
	default:
		return mergeSecrets(decl, existing)
	}
}

// buildDesiredState assembles the response after a committed reconcile: the
// full inbound and active-user sets for an enabled server, drained sets for
// a disabled one.
func (s *Store) buildDesiredState(
	ctx context.Context,
	server string,
	state model.DesiredState,
) (model.DesiredState, error) {
	if !state.Server.Enabled {
		// Disabled node: the agent renders a drained configuration.
		state.Inbounds, state.Users = []model.Inbound{}, []model.User{}
		state.Hash = state.ComputeHash()
		return state, nil
	}

	inbounds, err := s.selectInboundRows(ctx, s.db,
		"SELECT "+inboundColumns+" FROM inbounds WHERE server_name = $1 ORDER BY tag", server,
	)
	if err != nil {
		return model.DesiredState{}, err
	}
	if err := s.db.SelectContext(ctx, &state.Users,
		`SELECT subject, name, vless_uuid, hy2_password, active, created_at, updated_at
		 FROM users WHERE active ORDER BY name`,
	); err != nil {
		return model.DesiredState{}, fmt.Errorf("select users: %w", err)
	}

	state.Inbounds = inbounds
	state.Hash = state.ComputeHash()
	return state, nil
}

// putInbound inserts or updates one inbound row in place.
func (s *Store) putInbound(
	ctx context.Context,
	q sqlx.ExtContext,
	server string,
	d declaredInbound,
	sec secrets,
) error {
	_, err := q.ExecContext(ctx, `
		INSERT INTO inbounds (
			server_name, tag, type, listen_port, sni,
			public_endpoint, public_port, ws_path, origin_tls,
			reality_private_key, reality_public_key, reality_short_id,
			obfs_password, cert_pem, key_pem, pin_sha256
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		ON CONFLICT (server_name, tag) DO UPDATE SET
			type = EXCLUDED.type,
			listen_port = EXCLUDED.listen_port,
			sni = EXCLUDED.sni,
			public_endpoint = EXCLUDED.public_endpoint,
			public_port = EXCLUDED.public_port,
			ws_path = EXCLUDED.ws_path,
			origin_tls = EXCLUDED.origin_tls,
			reality_private_key = EXCLUDED.reality_private_key,
			reality_public_key = EXCLUDED.reality_public_key,
			reality_short_id = EXCLUDED.reality_short_id,
			obfs_password = EXCLUDED.obfs_password,
			cert_pem = EXCLUDED.cert_pem,
			key_pem = EXCLUDED.key_pem,
			pin_sha256 = EXCLUDED.pin_sha256,
			updated_at = now()
	`,
		server, d.decl.Tag, d.decl.Type, d.decl.ListenPort, d.decl.SNI,
		d.publicEndpoint, d.publicPort, d.decl.WSPath, d.decl.OriginTLS,
		sec.realityPrivateKey, sec.realityPublicKey, sec.realityShortID,
		sec.obfsPassword, sec.certPEM, sec.keyPEM, sec.pinSHA256,
	)
	if err != nil {
		return fmt.Errorf("put inbound %s: %w", d.decl.Tag, err)
	}
	return nil
}

// ErrUnknownServer marks heartbeat or status writes for servers that never
// declared themselves. Agents always call desired-state first, so seeing this
// means an out-of-order or misconfigured agent.
var ErrUnknownServer = errors.New("unknown server")
