CREATE TABLE servers (
  name          TEXT PRIMARY KEY,
  endpoint      TEXT NOT NULL,
  route_profile TEXT NOT NULL DEFAULT 'proxy-server',
  enabled       BOOLEAN NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE inbounds (
  server_name         TEXT NOT NULL REFERENCES servers(name) ON DELETE CASCADE,
  tag                 TEXT NOT NULL,
  type                TEXT NOT NULL CHECK (type IN ('vless_reality','hysteria2','vless_ws')),
  listen_port         INTEGER NOT NULL,
  sni                 TEXT NOT NULL,
  public_endpoint     TEXT NOT NULL,
  public_port         INTEGER NOT NULL,
  ws_path             TEXT,
  origin_tls          BOOLEAN NOT NULL DEFAULT FALSE,
  reality_private_key TEXT,
  reality_public_key  TEXT,
  reality_short_id    TEXT,
  obfs_password       TEXT,
  cert_pem            TEXT,
  key_pem             TEXT,
  pin_sha256          TEXT,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (server_name, tag)
);

CREATE TABLE users (
  authentik_uuid TEXT PRIMARY KEY,
  name           TEXT NOT NULL UNIQUE,
  vless_uuid     TEXT NOT NULL,
  hy2_password   TEXT NOT NULL,
  active         BOOLEAN NOT NULL DEFAULT TRUE,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE server_status (
  server_name     TEXT PRIMARY KEY REFERENCES servers(name) ON DELETE CASCADE,
  agent_version   TEXT NOT NULL DEFAULT '',
  applied_hash    TEXT NOT NULL DEFAULT '',
  singbox_healthy BOOLEAN NOT NULL DEFAULT FALSE,
  user_count      INTEGER NOT NULL DEFAULT 0,
  config_error    TEXT NOT NULL DEFAULT '',
  last_seen       TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01'
);

CREATE TABLE sync_state (
  id           BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
  last_sync_at TIMESTAMPTZ,
  last_error   TEXT NOT NULL DEFAULT ''
);

INSERT INTO sync_state (id) VALUES (TRUE) ON CONFLICT DO NOTHING;
