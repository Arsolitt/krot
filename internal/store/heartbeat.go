package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/Arsolitt/krot/internal/model"
)

// Heartbeat upserts the latest agent status for a server. The server must
// have declared itself via DesiredState first (foreign key on server_status);
// an unknown name yields ErrUnknownServer.
func (s *Store) Heartbeat(ctx context.Context, hb model.Heartbeat) error {
	var exists bool
	if err := s.db.GetContext(ctx, &exists, "SELECT TRUE FROM servers WHERE name = $1", hb.Server); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: %s", ErrUnknownServer, hb.Server)
		}
		return fmt.Errorf("lookup server: %w", err)
	}

	if _, err := s.db.NamedExecContext(ctx, `
		INSERT INTO server_status (server_name, agent_version, applied_hash, singbox_healthy, user_count, config_error, last_seen)
		VALUES (:server, :agent_version, :applied_hash, :singbox_healthy, :user_count, :config_error, now())
		ON CONFLICT (server_name) DO UPDATE SET
			agent_version = EXCLUDED.agent_version,
			applied_hash = EXCLUDED.applied_hash,
			singbox_healthy = EXCLUDED.singbox_healthy,
			user_count = EXCLUDED.user_count,
			config_error = EXCLUDED.config_error,
			last_seen = EXCLUDED.last_seen
	`, heartbeatParams(hb)); err != nil {
		return fmt.Errorf("upsert heartbeat: %w", err)
	}
	return nil
}

// heartbeatParams renames Heartbeat fields to the NamedExec parameter names.
func heartbeatParams(hb model.Heartbeat) map[string]any {
	return map[string]any{
		"server":          hb.Server,
		"agent_version":   hb.AgentVersion,
		"applied_hash":    hb.AppliedHash,
		"singbox_healthy": hb.SingboxHealthy,
		"user_count":      hb.UserCount,
		"config_error":    hb.ConfigError,
	}
}

// serversWithStatus loads every server joined with its status row.
func (s *Store) serversWithStatus(ctx context.Context, q sqlx.QueryerContext) ([]model.ServerWithStatus, error) {
	var servers []model.Server
	if err := sqlx.SelectContext(ctx, q, &servers,
		`SELECT name, endpoint, route_profile, enabled FROM servers ORDER BY name`,
	); err != nil {
		return nil, fmt.Errorf("select servers: %w", err)
	}

	var statuses []model.ServerStatus
	if err := sqlx.SelectContext(ctx, q, &statuses, `
		SELECT server_name, agent_version, applied_hash, singbox_healthy, user_count, config_error, last_seen
		FROM server_status
	`); err != nil {
		return nil, fmt.Errorf("select statuses: %w", err)
	}
	byServer := make(map[string]model.ServerStatus, len(statuses))
	for _, st := range statuses {
		byServer[st.ServerName] = st
	}

	out := make([]model.ServerWithStatus, 0, len(servers))
	for _, srv := range servers {
		st, ok := byServer[srv.Name]
		if !ok {
			st = model.ServerStatus{ServerName: srv.Name}
		}
		out = append(out, model.ServerWithStatus{Server: srv, Status: st})
	}
	return out, nil
}
