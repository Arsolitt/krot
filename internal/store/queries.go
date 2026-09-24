package store

import (
	"context"
	"fmt"

	"github.com/Arsolitt/krot/internal/model"
)

// userColumns is the shared column list for scanning model.User rows.
const userColumns = `subject, name, vless_uuid, hy2_password, active, created_at, updated_at`

// ActiveUsers returns the users currently synced from the configured
// directory group or role, ordered by name. The subscription endpoint derives
// tokens over this set.
func (s *Store) ActiveUsers(ctx context.Context) ([]model.User, error) {
	var users []model.User
	if err := s.db.SelectContext(ctx, &users,
		"SELECT "+userColumns+" FROM users WHERE active ORDER BY name",
	); err != nil {
		return nil, fmt.Errorf("select active users: %w", err)
	}
	return users, nil
}

// Users returns every known user, active or not, ordered by name. Inactive
// rows are kept so re-adding a group member restores the original
// subscription URL; the admin page shows both.
func (s *Store) Users(ctx context.Context) ([]model.User, error) {
	var users []model.User
	if err := s.db.SelectContext(ctx, &users,
		"SELECT "+userColumns+" FROM users ORDER BY name",
	); err != nil {
		return nil, fmt.Errorf("select users: %w", err)
	}
	return users, nil
}

// EnabledServersWithInbounds returns every enabled server with its full
// inbound list (secrets included) — the unit the subscription link builder
// iterates. Servers are ordered by name, inbounds by tag.
func (s *Store) EnabledServersWithInbounds(ctx context.Context) ([]model.ServerInbounds, error) {
	var servers []model.Server
	if err := s.db.SelectContext(ctx, &servers,
		`SELECT name, endpoint, route_profile, enabled FROM servers WHERE enabled ORDER BY name`,
	); err != nil {
		return nil, fmt.Errorf("select servers: %w", err)
	}
	if len(servers) == 0 {
		return []model.ServerInbounds{}, nil
	}

	var inbounds []model.Inbound
	if err := s.db.SelectContext(ctx, &inbounds,
		"SELECT "+inboundColumns+" FROM inbounds ORDER BY server_name, tag",
	); err != nil {
		return nil, fmt.Errorf("select inbounds: %w", err)
	}
	byServer := make(map[string][]model.Inbound, len(servers))
	for _, in := range inbounds {
		byServer[in.ServerName] = append(byServer[in.ServerName], in)
	}

	out := make([]model.ServerInbounds, 0, len(servers))
	for _, srv := range servers {
		ins := byServer[srv.Name]
		if ins == nil {
			ins = []model.Inbound{}
		}
		out = append(out, model.ServerInbounds{Server: srv, Inbounds: ins})
	}
	return out, nil
}

// ServersWithStatus returns every server paired with its last reported agent
// status; servers that never heartbeated get a zero status.
func (s *Store) ServersWithStatus(ctx context.Context) ([]model.ServerWithStatus, error) {
	return s.serversWithStatus(ctx, s.db)
}
