// Package model defines the domain types shared by the control plane and agents.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// InboundType enumerates the sing-box inbound kinds a node can declare.
type InboundType string

// Supported inbound types.
const (
	InboundVLESSReality InboundType = "vless_reality"
	InboundHysteria2    InboundType = "hysteria2"
	InboundVLESSWS      InboundType = "vless_ws"
)

// Valid reports whether t is a supported inbound type.
func (t InboundType) Valid() bool {
	switch t {
	case InboundVLESSReality, InboundHysteria2, InboundVLESSWS:
		return true
	default:
		return false
	}
}

// Transport returns the IP protocol the inbound type binds: hysteria2 is QUIC
// over UDP, the vless variants are TCP. A node may bind the same port for a
// TCP and a UDP inbound, but never twice for the same transport.
func (t InboundType) Transport() string {
	if t == InboundHysteria2 {
		return "udp"
	}
	return "tcp"
}

// InboundDecl is one inbound as declared by an agent: the helm values surface
// rendered into agent.yaml and POSTed to the control plane verbatim.
type InboundDecl struct {
	Tag            string      `json:"tag"                       yaml:"tag"`
	SNI            string      `json:"sni"                       yaml:"sni"`
	Type           InboundType `json:"type"                      yaml:"type"`
	PublicEndpoint string      `json:"public_endpoint,omitempty" yaml:"public_endpoint,omitempty"`
	WSPath         string      `json:"ws_path,omitempty"         yaml:"ws_path,omitempty"`
	ListenPort     int         `json:"listen_port"               yaml:"listen_port"`
	PublicPort     int         `json:"public_port,omitempty"     yaml:"public_port,omitempty"`
	OriginTLS      bool        `json:"origin_tls,omitempty"      yaml:"origin_tls,omitempty"`
}

// Spec is the agent's full declared node spec: the desired-state request body
// and the agent.yaml file rendered by the helm chart (same fields, two encodings).
type Spec struct {
	Server       string        `json:"server"        yaml:"server"`
	Endpoint     string        `json:"endpoint"      yaml:"endpoint"`
	RouteProfile string        `json:"route_profile" yaml:"route_profile"`
	Inbounds     []InboundDecl `json:"inbounds"      yaml:"inbounds"`
}

// Server is a proxy node row.
type Server struct {
	Name         string `json:"name"          db:"name"`
	Endpoint     string `json:"endpoint"      db:"endpoint"`
	RouteProfile string `json:"route_profile" db:"route_profile"`
	Enabled      bool   `json:"enabled"       db:"enabled"`
}

// Inbound is a full inbound row including per-inbound secrets. The JSON shape
// is the agent API payload; the server_name and timestamps never leave the store.
type Inbound struct {
	CreatedAt         time.Time   `json:"-"                             db:"created_at"`
	UpdatedAt         time.Time   `json:"-"                             db:"updated_at"`
	WSPath            *string     `json:"ws_path,omitempty"             db:"ws_path"`
	RealityPublicKey  string      `json:"reality_public_key,omitempty"  db:"reality_public_key"`
	ObfsPassword      string      `json:"obfs_password,omitempty"       db:"obfs_password"`
	Type              InboundType `json:"type"                          db:"type"`
	PublicEndpoint    string      `json:"public_endpoint"               db:"public_endpoint"`
	RealityPrivateKey string      `json:"reality_private_key,omitempty" db:"reality_private_key"`
	Tag               string      `json:"tag"                           db:"tag"`
	RealityShortID    string      `json:"reality_short_id,omitempty"    db:"reality_short_id"`
	SNI               string      `json:"sni"                           db:"sni"`
	CertPEM           string      `json:"cert_pem,omitempty"            db:"cert_pem"`
	KeyPEM            string      `json:"key_pem,omitempty"             db:"key_pem"`
	PinSHA256         string      `json:"pin_sha256,omitempty"          db:"pin_sha256"`
	ServerName        string      `json:"-"                             db:"server_name"`
	ListenPort        int         `json:"listen_port"                   db:"listen_port"`
	PublicPort        int         `json:"public_port"                   db:"public_port"`
	OriginTLS         bool        `json:"origin_tls,omitempty"          db:"origin_tls"`
}

// User is a VPN user row. The JSON shape is the agent API payload: the
// directory subject and liveness fields never leave the control plane.
type User struct {
	CreatedAt   time.Time `json:"-"            db:"created_at"`
	UpdatedAt   time.Time `json:"-"            db:"updated_at"`
	Subject     string    `json:"-"            db:"subject"`
	Name        string    `json:"name"         db:"name"`
	VLESSUUID   string    `json:"vless_uuid"   db:"vless_uuid"`
	Hy2Password string    `json:"hy2_password" db:"hy2_password"`
	Active      bool      `json:"-"            db:"active"`
}

// Member is one directory user: the provider subject (users.subject, the OIDC
// "sub" claim) and the display name synced onto users.name.
type Member struct {
	Subject  string
	Username string
}

// ServerStatus is the latest agent heartbeat for a server.
type ServerStatus struct {
	LastSeen       time.Time `json:"last_seen"       db:"last_seen"`
	ServerName     string    `json:"server"          db:"server_name"`
	AgentVersion   string    `json:"agent_version"   db:"agent_version"`
	AppliedHash    string    `json:"applied_hash"    db:"applied_hash"`
	ConfigError    string    `json:"config_error"    db:"config_error"`
	UserCount      int       `json:"user_count"      db:"user_count"`
	SingboxHealthy bool      `json:"singbox_healthy" db:"singbox_healthy"`
}

// SyncState is the singleton authentik sync bookkeeping row.
type SyncState struct {
	LastSyncAt *time.Time `json:"last_sync_at" db:"last_sync_at"`
	LastError  string     `json:"last_error"   db:"last_error"`
}

// Heartbeat is the agent status report POSTed to the control plane.
type Heartbeat struct {
	Server         string `json:"server"`
	AgentVersion   string `json:"agent_version"`
	AppliedHash    string `json:"applied_hash"`
	ConfigError    string `json:"config_error"`
	UserCount      int    `json:"user_count"`
	SingboxHealthy bool   `json:"singbox_healthy"`
}

// DesiredState is the agent API response: the full rendered truth for a node.
type DesiredState struct {
	Hash     string    `json:"hash"`
	Server   Server    `json:"server"`
	Inbounds []Inbound `json:"inbounds"`
	Users    []User    `json:"users"`
}

// ServerWithStatus pairs a server with its last reported agent status.
type ServerWithStatus struct {
	Server Server       `json:"server"`
	Status ServerStatus `json:"status"`
}

// ServerInbounds pairs an enabled server with its full inbound list: the unit
// the subscription link builder iterates.
type ServerInbounds struct {
	Server   Server    `json:"server"`
	Inbounds []Inbound `json:"inbounds"`
}

// ComputeHash returns the sha256 hex digest of the JSON encoding of d with an
// empty hash field. Agents compare it against the persisted applied hash to
// decide whether to re-render; Go struct marshaling is field-order stable.
func (d DesiredState) ComputeHash() string {
	d.Hash = ""
	b, err := json.Marshal(d)
	if err != nil {
		// The model types marshal without error by construction.
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
