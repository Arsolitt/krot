// Package store is the sqlx-backed persistence layer of the krot control
// plane: agent declarations, per-inbound secrets, synced users and agent
// status, with schema migrations embedded and applied at startup.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5" // registers the pgx5 driver.
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the pgx sqlx driver.
	"github.com/jmoiron/sqlx"

	"github.com/Arsolitt/krot/internal/model"
)

// migrationsFS holds the embedded schema migrations.
//
//go:embed migrations/*.sql
var migrationsFS embed.FS

// ErrInvalidSpec marks a rejected agent declaration. The agent API maps it to
// HTTP 400 so agents keep their current config and surface the message.
var ErrInvalidSpec = errors.New("invalid agent spec")

// Migrate applies all embedded schema migrations to the database behind
// databaseURL. It is idempotent: a database already at the latest version is a
// success, not an error.
func Migrate(databaseURL string) error {
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("load migrations: %w", err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, pgxURL(databaseURL))
	if err != nil {
		return fmt.Errorf("init migrate: %w", err)
	}
	defer m.Close()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}

// pgxURL rewrites a postgres:// URL into the pgx5:// form the golang-migrate
// pgx/v5 driver registers.
func pgxURL(databaseURL string) string {
	return strings.Replace(databaseURL, "postgres://", "pgx5://", 1)
}

// Store wraps the database handle. All methods are safe for concurrent use.
type Store struct {
	db *sqlx.DB
}

// Open connects to the database behind databaseURL and verifies the
// connection. Run Migrate first; Open does not touch the schema.
func Open(ctx context.Context, databaseURL string) (*Store, error) {
	db, err := sqlx.ConnectContext(ctx, "pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("connect database: %w", err)
	}
	db.SetMaxOpenConns(poolMaxOpen)
	db.SetMaxIdleConns(poolMaxIdle)
	return &Store{db: db}, nil
}

// Pool sizing for a single-purpose control plane database.
const (
	poolMaxOpen = 10
	poolMaxIdle = 5
)

// Close releases the database handle.
func (s *Store) Close() error {
	return s.db.Close()
}

// Ping verifies the database connection; the readiness probe uses it.
func (s *Store) Ping(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, "SELECT 1"); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	return nil
}

// inboundColumns is the shared column list for scanning model.Inbound rows;
// nullable text columns are coalesced so the string fields scan directly.
const inboundColumns = `
	server_name,
	tag,
	type,
	listen_port,
	sni,
	COALESCE(public_endpoint, '')  AS public_endpoint,
	public_port,
	COALESCE(ws_path, '')          AS ws_path,
	COALESCE(origin_tls, FALSE)    AS origin_tls,
	COALESCE(reality_private_key,'') AS reality_private_key,
	COALESCE(reality_public_key,'')  AS reality_public_key,
	COALESCE(reality_short_id,'')    AS reality_short_id,
	COALESCE(obfs_password,'')       AS obfs_password,
	COALESCE(cert_pem,'')            AS cert_pem,
	COALESCE(key_pem,'')             AS key_pem,
	COALESCE(pin_sha256,'')          AS pin_sha256,
	created_at,
	updated_at
`

// selectInboundRows runs a query over inboundColumns and scans the rows.
func (s *Store) selectInboundRows(
	ctx context.Context,
	q sqlx.QueryerContext,
	query string,
	args ...any,
) ([]model.Inbound, error) {
	var rows []model.Inbound
	if err := sqlx.SelectContext(ctx, q, &rows, query, args...); err != nil {
		return nil, fmt.Errorf("select inbounds: %w", err)
	}
	return rows, nil
}
