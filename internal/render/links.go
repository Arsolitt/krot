package render

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/Arsolitt/krot/internal/model"
)

// Link builds the subscription share-link URI for one enabled (server,
// inbound) pair, using the inbound's public endpoint and port. Parameter
// order and encoding reproduce the v1 subscription format byte for byte.
func Link(server string, in model.Inbound, u model.User) (string, error) {
	fragment := server + "-" + in.Tag

	switch in.Type {
	case model.InboundVLESSReality:
		return fmt.Sprintf(
			"vless://%s@%s?flow=xtls-rprx-vision&fp=chrome&pbk=%s&security=reality&sid=%s&sni=%s&type=tcp#%s",
			u.VLESSUUID, net.JoinHostPort(in.PublicEndpoint, strconv.Itoa(in.PublicPort)),
			url.QueryEscape(in.RealityPublicKey), url.QueryEscape(in.RealityShortID),
			url.QueryEscape(in.SNI), fragment,
		), nil
	case model.InboundHysteria2:
		pin, err := xrayCertPin(in.CertPEM)
		if err != nil {
			return "", fmt.Errorf("hysteria2 link: %w", err)
		}
		return fmt.Sprintf(
			"hysteria2://%s@%s?alpn=h3&obfs=salamander&obfs-password=%s&pinSHA256=%s&sni=%s#%s",
			u.Hy2Password, net.JoinHostPort(in.PublicEndpoint, strconv.Itoa(in.PublicPort)),
			url.QueryEscape(in.ObfsPassword), pin,
			url.QueryEscape(in.SNI), fragment,
		), nil
	case model.InboundVLESSWS:
		return fmt.Sprintf(
			"vless://%s@%s?type=ws&security=tls&sni=%s&host=%s&path=%s#%s",
			u.VLESSUUID, net.JoinHostPort(in.PublicEndpoint, strconv.Itoa(in.PublicPort)),
			url.QueryEscape(in.SNI), url.QueryEscape(in.SNI),
			url.QueryEscape(wsPathOf(in)), fragment,
		), nil
	default:
		return "", fmt.Errorf("unknown inbound type %q", in.Type)
	}
}

// wsPathOf returns the inbound's websocket path, "/" when unset.
func wsPathOf(in model.Inbound) string {
	if in.WSPath != nil && *in.WSPath != "" {
		return *in.WSPath
	}
	return "/"
}

// xrayCertPin returns the certificate pin Xray-core expects in a
// pinSHA256 link parameter: lowercase hex of sha256 over the leaf
// certificate DER bytes. Xray hex-decodes the value, so the HPKP-style
// base64 SPKI pin cannot ride in this parameter.
func xrayCertPin(certPEM string) (string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", errors.New("pin: certificate PEM missing or unparsable")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}
