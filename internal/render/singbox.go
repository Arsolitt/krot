package render

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/Arsolitt/krot/internal/model"
)

// Cert file naming: one file pair per cert-bearing inbound under the agent
// working directory (sing-box runs with -D pointing there). Tag-based names
// keep two inbounds that share an SNI from clobbering each other's files.
const (
	certDir      = "certs"
	certSuffix   = ".crt"
	keySuffix    = ".key"
	filePerm0600 = 0o600
	dirPerm0700  = 0o700
)

// ErrPortCollision marks two inbounds binding the same transport and port.
var ErrPortCollision = errors.New("inbound port collision")

// toPort converts a validated 1..65535 port to the option struct width.
func toPort(v int) uint16 {
	return uint16(v) //nolint:gosec // G115: ports are validated 1..65535 upstream.
}

// listenAll is the sing-box listen address for server inbounds.
var listenAll = badoption.Addr(netip.MustParseAddr("::"))

// SingboxConfig builds the full sing-box configuration for one node. An empty
// cacheFilePath omits the experimental block; agents pass a path under their
// working directory so remote rule sets survive restarts.
func SingboxConfig(
	profile string, inbounds []model.Inbound, users []model.User, cacheFilePath string,
) (option.Options, error) {
	if !ValidProfile(profile) {
		return option.Options{}, errUnknownProfile(profile)
	}
	if err := checkBindCollisions(inbounds); err != nil {
		return option.Options{}, err
	}

	built := make([]option.Inbound, 0, len(inbounds))
	for _, in := range inbounds {
		ib, err := buildInbound(in, users)
		if err != nil {
			return option.Options{}, err
		}
		built = append(built, ib)
	}

	return option.Options{
		Log:          buildLog(),
		DNS:          buildDNS(),
		Inbounds:     built,
		Outbounds:    buildOutbounds(),
		Route:        buildRoute(),
		Experimental: buildExperimental(cacheFilePath),
	}, nil
}

// buildInbound converts one inbound row plus the user list into the typed
// sing-box inbound of its protocol.
func buildInbound(in model.Inbound, users []model.User) (option.Inbound, error) {
	switch in.Type {
	case model.InboundVLESSReality:
		return buildVLESSReality(in, users), nil
	case model.InboundHysteria2:
		return buildHysteria2(in, users), nil
	case model.InboundVLESSWS:
		return buildVLESSWS(in, users), nil
	default:
		return option.Inbound{}, fmt.Errorf("unknown inbound type %q", in.Type)
	}
}

// buildVLESSReality mirrors the v1 reality inbound: vision flow users,
// reality TLS handshaking to the SNI, multiplex enabled.
func buildVLESSReality(in model.Inbound, users []model.User) option.Inbound {
	vlessUsers := make([]option.VLESSUser, 0, len(users))
	for _, u := range users {
		vlessUsers = append(vlessUsers, option.VLESSUser{
			Name: u.Name, UUID: u.VLESSUUID, Flow: "xtls-rprx-vision",
		})
	}
	sortVLESSUsers(vlessUsers)

	opts := option.VLESSInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     &listenAll,
			ListenPort: toPort(in.ListenPort),
		},
		Users: vlessUsers,
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{
				Enabled:    true,
				ServerName: in.SNI,
				Reality: &option.InboundRealityOptions{
					Enabled:    true,
					PrivateKey: in.RealityPrivateKey,
					ShortID:    badoption.Listable[string]{in.RealityShortID},
					Handshake: option.InboundRealityHandshakeOptions{
						ServerOptions: option.ServerOptions{Server: in.SNI, ServerPort: realityHandshakePort},
					},
				},
			},
		},
		Multiplex: &option.InboundMultiplexOptions{Enabled: true},
	}
	return option.Inbound{Type: "vless", Tag: in.Tag, Options: &opts}
}

// buildHysteria2 mirrors the v1 hysteria2 inbound: salamander obfs, h3 TLS
// with the stored certificate, proxy masquerade to the SNI site.
func buildHysteria2(in model.Inbound, users []model.User) option.Inbound {
	hy2Users := make([]option.Hysteria2User, 0, len(users))
	for _, u := range users {
		hy2Users = append(hy2Users, option.Hysteria2User{Name: u.Name, Password: u.Hy2Password})
	}
	slices.SortFunc(hy2Users, func(a, b option.Hysteria2User) int {
		return strings.Compare(a.Name, b.Name)
	})

	opts := option.Hysteria2InboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     &listenAll,
			ListenPort: toPort(in.ListenPort),
		},
		UpMbps:   hy2BandwidthMbps,
		DownMbps: hy2BandwidthMbps,
		Obfs:     &option.Hysteria2Obfs{Type: "salamander", Password: in.ObfsPassword},
		Users:    hy2Users,
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{
				Enabled:         true,
				ServerName:      in.SNI,
				ALPN:            badoption.Listable[string]{"h3"},
				CertificatePath: certPath(in.Tag, certSuffix),
				KeyPath:         certPath(in.Tag, keySuffix),
			},
		},
		Masquerade: &option.Hysteria2Masquerade{
			Type: "proxy",
			ProxyOptions: option.Hysteria2MasqueradeProxy{
				URL:         "https://" + in.SNI,
				RewriteHost: true,
			},
		},
	}
	return option.Inbound{Type: "hysteria2", Tag: in.Tag, Options: &opts}
}

// buildVLESSWS builds the CDN-fronted vless inbound: websocket transport,
// vision flow omitted (it is TCP-only). TLS is terminated on origin only
// when the inbound declares origin_tls.
func buildVLESSWS(in model.Inbound, users []model.User) option.Inbound {
	vlessUsers := make([]option.VLESSUser, 0, len(users))
	for _, u := range users {
		vlessUsers = append(vlessUsers, option.VLESSUser{Name: u.Name, UUID: u.VLESSUUID})
	}
	sortVLESSUsers(vlessUsers)

	wsPath := "/"
	if in.WSPath != nil && *in.WSPath != "" {
		wsPath = *in.WSPath
	}

	opts := option.VLESSInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     &listenAll,
			ListenPort: toPort(in.ListenPort),
		},
		Users: vlessUsers,
		Transport: &option.V2RayTransportOptions{
			Type:             "ws",
			WebsocketOptions: option.V2RayWebsocketOptions{Path: wsPath},
		},
	}
	if in.OriginTLS {
		opts.InboundTLSOptionsContainer.TLS = &option.InboundTLSOptions{
			Enabled:         true,
			ServerName:      in.SNI,
			CertificatePath: certPath(in.Tag, certSuffix),
			KeyPath:         certPath(in.Tag, keySuffix),
		}
	}
	return option.Inbound{Type: "vless", Tag: in.Tag, Options: &opts}
}

// sortVLESSUsers orders vless users by name for deterministic output.
func sortVLESSUsers(users []option.VLESSUser) {
	slices.SortFunc(users, func(a, b option.VLESSUser) int {
		return strings.Compare(a.Name, b.Name)
	})
}

// certPath returns the config-relative path of one inbound's cert file.
func certPath(tag, suffix string) string {
	return certDir + "/" + tag + suffix
}

// checkBindCollisions re-verifies that no two inbounds share a transport and
// listen port (the store validated the declaration; the renderer double-checks).
func checkBindCollisions(inbounds []model.Inbound) error {
	binds := make(map[string]struct{}, len(inbounds))
	for _, in := range inbounds {
		key := fmt.Sprintf("%s/%d", in.Type.Transport(), in.ListenPort)
		if _, clash := binds[key]; clash {
			return fmt.Errorf("%w: %s port %d", ErrPortCollision, in.Type.Transport(), in.ListenPort)
		}
		binds[key] = struct{}{}
	}
	return nil
}

// WriteCerts materializes the certificate files of every cert-bearing inbound
// under dir/certs with 0600 permissions.
func WriteCerts(dir string, inbounds []model.Inbound) error {
	certs := filepath.Join(dir, certDir)
	for _, in := range inbounds {
		if in.CertPEM == "" || in.KeyPEM == "" {
			continue
		}
		if err := os.MkdirAll(certs, os.FileMode(dirPerm0700)); err != nil {
			return fmt.Errorf("create cert dir: %w", err)
		}
		certFile := filepath.Join(certs, in.Tag+certSuffix)
		if err := os.WriteFile(certFile, []byte(in.CertPEM), os.FileMode(filePerm0600)); err != nil {
			return fmt.Errorf("write cert %s: %w", in.Tag, err)
		}
		keyFile := filepath.Join(certs, in.Tag+keySuffix)
		if err := os.WriteFile(keyFile, []byte(in.KeyPEM), os.FileMode(filePerm0600)); err != nil {
			return fmt.Errorf("write key %s: %w", in.Tag, err)
		}
	}
	return nil
}

// Marshal serializes a sing-box configuration using the JSON engine the
// option types are built for (context-aware marshaling).
func Marshal(ctx context.Context, opts option.Options) ([]byte, error) {
	data, err := singjson.MarshalContext(ctx, &opts)
	if err != nil {
		return nil, fmt.Errorf("marshal sing-box config: %w", err)
	}
	return data, nil
}
