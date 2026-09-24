package store

import (
	"context"
	"fmt"

	"github.com/Arsolitt/cheburbox/generate"

	"github.com/Arsolitt/krot/internal/model"
)

// SyncUsers reconciles the users table with the current member list of the
// configured directory group/role, in one transaction:
//
//   - a new subject is inserted with freshly generated credentials (vless UUID
//     and hysteria2 password, global across all nodes) and active=true;
//   - an existing subject keeps its credentials forever; a rename updates only
//     the name (fixing the v1 wart where renames rotated credentials);
//   - a subject absent from the member list is deactivated, not deleted, so
//     re-adding the user restores the original subscription URL.
//
// On success the sync_state bookkeeping row records the timestamp and clears
// the last error. An empty member list deactivates everyone — an emptied
// group revokes every subscription.
func (s *Store) SyncUsers(ctx context.Context, members []model.Member) error {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op.

	for _, m := range members {
		vlessUUID, err := generate.GenerateUUID()
		if err != nil {
			return fmt.Errorf("generate vless uuid: %w", err)
		}
		hy2Password, err := generate.GeneratePassword()
		if err != nil {
			return fmt.Errorf("generate hy2 password: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO users (subject, name, vless_uuid, hy2_password)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (subject) DO UPDATE SET
				name = EXCLUDED.name,
				active = TRUE,
				updated_at = now()
		`, m.Subject, m.Username, vlessUUID, hy2Password); err != nil {
			return fmt.Errorf("upsert user %s: %w", m.Subject, err)
		}
	}

	subjects := make([]string, 0, len(members))
	for _, m := range members {
		subjects = append(subjects, m.Subject)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE users SET active = FALSE, updated_at = now()
		WHERE active AND NOT (subject = ANY($1))
	`, subjects); err != nil {
		return fmt.Errorf("deactivate absent users: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE sync_state SET last_sync_at = now(), last_error = ''
	`); err != nil {
		return fmt.Errorf("record sync: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// SyncState returns the singleton sync bookkeeping row.
func (s *Store) SyncState(ctx context.Context) (model.SyncState, error) {
	var state model.SyncState
	if err := s.db.GetContext(ctx, &state,
		`SELECT last_sync_at, last_error FROM sync_state WHERE id`,
	); err != nil {
		return model.SyncState{}, fmt.Errorf("read sync state: %w", err)
	}
	return state, nil
}

// SetSyncError records a failed sync attempt; the users table keeps the last
// good state (fail-open, mirroring directory.Cached).
func (s *Store) SetSyncError(ctx context.Context, msg string) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE sync_state SET last_error = $1`, msg,
	); err != nil {
		return fmt.Errorf("record sync error: %w", err)
	}
	return nil
}
