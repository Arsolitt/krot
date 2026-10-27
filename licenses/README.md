# Third-party licenses

This directory collects the license texts of every third-party Go module linked
into the released krot binaries: `krot-cp` (the control plane) and `krot-agent`
(the node agent). One directory per module, named after the module's resolved
path and version, the license files inside copied verbatim from the module's own
directory.

The module set is what `go list -deps` reports for `./cmd/krot-cp` and
`./cmd/krot-agent` on `linux/amd64`, the only platform the released binaries are
built for. The paths and versions are the resolved ones: where `go.mod` replaces
an upstream module with a fork, the fork's path and version are the ones named,
because the fork is the source that is compiled into the binaries. The sources
are the upstream repositories at those versions.

krot itself is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). Copyright (C) 2026 Arsolitt <https://arsolitt.tech/>.

krot's own license text is [`../LICENSE`](../LICENSE).

Two notes on what is in here:

- `GPL-3.0.txt` is the canonical text of the GNU GPL v3.0. The sing-ecosystem
  modules listed below ship only short grant notices of their own, not the full
  license text those notices refer to, so that text ships once, alongside them.
- Both container images install this directory at `/licenses/`. The `krot-agent`
  image additionally ships the standalone `sing-box` binary, which is a release
  artifact rather than a Go module, so its license is not one of the directories
  below but `/licenses/sing-box/LICENSE` in the image, next to
  `/licenses/sing-box/SOURCE`, which names the exact release it came from.

Module identity is `path@version`. `Binaries` names the released binaries that
link the module; `License files` lists the files copied from its directory.

| Module | Version | Binaries | License files |
| --- | --- | --- | --- |
| `github.com/AdguardTeam/golibs` | `v0.32.7` | `krot-cp` | `LICENSE` |
| `github.com/AliRizaAynaci/gorl/v2` | `v2.2.0` | `krot-cp` | `LICENSE` |
| `github.com/Arsolitt/amnezigo` | `v1.0.0` | `krot-cp` | `LICENSE`, `NOTICE` |
| `github.com/Arsolitt/cheburbox` | `v0.4.0` | `krot-cp` | `LICENSE`, `NOTICE` |
| `github.com/OneOfOne/xxhash` | `v1.2.8` | `krot-cp` | `LICENSE` |
| `github.com/a-h/templ` | `v0.3.1001` | `krot-cp` | `LICENSE` |
| `github.com/ajg/form` | `v1.5.1` | `krot-cp` | `LICENSE` |
| `github.com/ameshkov/dnsstamps` | `v1.0.3` | `krot-cp` | `LICENSE` |
| `github.com/andybalholm/brotli` | `v1.2.0` | `krot-cp` | `LICENSE` |
| `github.com/anytls/sing-anytls` | `v0.0.11` | `krot-cp` | `LICENSE` |
| `github.com/caddyserver/certmagic` | `v0.25.3-0.20260421143802-60d9d8b415d6` | `krot-cp` | `LICENSE.txt` |
| `github.com/caddyserver/zerossl` | `v0.1.5` | `krot-cp` | `LICENSE` |
| `github.com/cespare/xxhash/v2` | `v2.3.0` | `krot-cp` | `LICENSE.txt` |
| `github.com/coder/websocket` | `v1.8.14` | `krot-cp` | `LICENSE.txt` |
| `github.com/coreos/go-oidc/v3` | `v3.20.0` | `krot-cp` | `LICENSE`, `NOTICE` |
| `github.com/cretz/bine` | `v0.2.0` | `krot-cp` | `LICENSE` |
| `github.com/database64128/netx-go` | `v0.1.1` | `krot-cp` | `LICENSE` |
| `github.com/database64128/tfo-go/v2` | `v2.3.2` | `krot-cp` | `LICENSE` |
| `github.com/dgryski/go-rendezvous` | `v0.0.0-20200823014737-9f7001d12a5f` | `krot-cp` | `LICENSE` |
| `github.com/enfein/mieru/v3` | `v3.33.0` | `krot-cp` | `LICENSE` |
| `github.com/florianl/go-nfqueue/v2` | `v2.1.0` | `krot-cp` | `LICENSE` |
| `github.com/fsnotify/fsnotify` | `v1.9.0` | `krot-cp` | `LICENSE` |
| `github.com/go-chi/chi/v5` | `v5.2.5` | `krot-cp` | `LICENSE` |
| `github.com/go-chi/render` | `v1.0.3` | `krot-cp` | `LICENSE` |
| `github.com/go-jose/go-jose/v4` | `v4.1.4` | `krot-cp` | `LICENSE` |
| `github.com/gobwas/httphead` | `v0.1.0` | `krot-cp` | `LICENSE` |
| `github.com/gobwas/pool` | `v0.2.1` | `krot-cp` | `LICENSE` |
| `github.com/godbus/dbus/v5` | `v5.2.2` | `krot-cp` | `LICENSE` |
| `github.com/gofrs/uuid/v5` | `v5.5.1` | `krot-cp` | `LICENSE` |
| `github.com/golang-migrate/migrate/v4` | `v4.19.1` | `krot-cp` | `LICENSE` |
| `github.com/google/btree` | `v1.1.3` | `krot-cp` | `LICENSE` |
| `github.com/google/go-jsonnet` | `v0.22.0` | `krot-cp` | `LICENSE` |
| `github.com/google/gopacket` | `v1.1.19` | `krot-cp` | `LICENSE` |
| `github.com/hashicorp/yamux` | `v0.1.2` | `krot-cp` | `LICENSE` |
| `github.com/huin/goupnp` | `v1.3.0` | `krot-cp` | `LICENSE` |
| `github.com/jackc/pgerrcode` | `v0.0.0-20220416144525-469b46aa5efa` | `krot-cp` | `LICENSE` |
| `github.com/jackc/pgpassfile` | `v1.0.0` | `krot-cp` | `LICENSE` |
| `github.com/jackc/pgservicefile` | `v0.0.0-20240606120523-5a60cdf6a761` | `krot-cp` | `LICENSE` |
| `github.com/jackc/pgx/v5` | `v5.8.0` | `krot-cp` | `LICENSE` |
| `github.com/jackc/puddle/v2` | `v2.2.2` | `krot-cp` | `LICENSE` |
| `github.com/jackpal/go-nat-pmp` | `v1.0.2` | `krot-cp` | `LICENSE` |
| `github.com/jmoiron/sqlx` | `v1.4.0` | `krot-cp` | `LICENSE` |
| `github.com/jsimonetti/rtnetlink` | `v1.4.1` | `krot-cp` | `LICENSE.md` |
| `github.com/klauspost/compress` | `v1.19.1` | `krot-cp` | `LICENSE` |
| `github.com/klauspost/cpuid/v2` | `v2.3.0` | `both` | `LICENSE` |
| `github.com/koron/go-ssdp` | `v0.0.4` | `krot-cp` | `LICENSE` |
| `github.com/libdns/libdns` | `v1.1.1` | `krot-cp` | `LICENSE` |
| `github.com/libp2p/go-nat` | `v1.0.1-0.20250821073202-01afc089f138` | `krot-cp` | `LICENSE` |
| `github.com/libp2p/go-netroute` | `v0.2.1` | `krot-cp` | `LICENSE` |
| `github.com/logrusorgru/aurora` | `v2.0.3+incompatible` | `krot-cp` | `LICENSE` |
| `github.com/mdlayher/netlink` | `v1.11.2` | `krot-cp` | `LICENSE.md` |
| `github.com/mdlayher/socket` | `v0.6.0` | `krot-cp` | `LICENSE.md` |
| `github.com/metacubex/utls` | `v1.8.7` | `krot-cp` | `LICENSE` |
| `github.com/mholt/acmez/v3` | `v3.1.6` | `krot-cp` | `LICENSE` |
| `github.com/miekg/dns` | `v1.1.72` | `both` | `COPYRIGHT`, `LICENSE` |
| `github.com/panjf2000/ants/v2` | `v2.12.0` | `krot-cp` | `LICENSE` |
| `github.com/pires/go-proxyproto` | `v0.11.0` | `krot-cp` | `LICENSE` |
| `github.com/quic-go/qpack` | `v0.6.0` | `krot-cp` | `LICENSE.md` |
| `github.com/redis/go-redis/v9` | `v9.8.0` | `krot-cp` | `LICENSE` |
| `github.com/sagernet/bbolt` | `v0.0.0-20260915102804-500ee1e84832` | `krot-cp` | `LICENSE` |
| `github.com/sagernet/cors` | `v1.2.1` | `krot-cp` | `LICENSE` |
| `github.com/sagernet/fswatch` | `v0.1.2` | `krot-cp` | `LICENSE` |
| `github.com/sagernet/netlink` | `v0.0.0-20260814022025-64455d367bbf` | `krot-cp` | `LICENSE` |
| `github.com/sagernet/nftables` | `v0.3.0-mod.4` | `krot-cp` | `LICENSE` |
| `github.com/sagernet/quic-go` | `v0.61.0-sing-box-mod.9` | `krot-cp` | `LICENSE` |
| `github.com/sagernet/sing-quic` | `v0.7.2-0.20261002084117-75c3ac4fa12b` | `krot-cp` | `LICENSE` |
| `github.com/sagernet/sing-shadowsocks2` | `v0.2.2-0.20260929152114-a69d1086332b` | `krot-cp` | `LICENSE` |
| `github.com/sagernet/sing-shadowsocks` | `v0.2.9-0.20260929204512-65740e0f0e3e` | `krot-cp` | `LICENSE` |
| `github.com/sagernet/sing-shadowtls` | `v0.2.2-0.20260928201441-a9c0127d5c99` | `krot-cp` | `LICENSE` |
| `github.com/sagernet/sing-snell` | `v0.0.0-20260904135315-bc5a12ac736f` | `krot-cp` | `LICENSE` |
| `github.com/sagernet/sing-tun` | `v0.9.7-0.20261009020158-bca4bf029237` | `krot-cp` | `LICENSE` |
| `github.com/sagernet/smux` | `v1.5.50-sing-box-mod.1` | `krot-cp` | `LICENSE` |
| `github.com/sagernet/ws` | `v0.0.0-20231204124109-acfe8907c854` | `krot-cp` | `LICENSE` |
| `github.com/shtorm-7/dnscrypt/v2` | `v2.4.0-extended-1.0.0` | `krot-cp` | `LICENSE` |
| `github.com/shtorm-7/go-cache/v2` | `v2.1.0-extended-1.2.0` | `krot-cp` | `LICENSE` |
| `github.com/shtorm-7/mtg-multi` | `v1.12.0-extended-1.0.0` | `krot-cp` | `LICENSE` |
| `github.com/shtorm-7/rmux` | `v1.0.1` | `krot-cp` | `LICENSE` |
| `github.com/shtorm-7/sing-box-extended` | `v1.14.3-extended-2.7.3` | `both` | `LICENSE` |
| `github.com/shtorm-7/sing-mux` | `v0.3.10-extended-1.1.0` | `krot-cp` | `LICENSE` |
| `github.com/shtorm-7/sing-vmess` | `v0.2.9-extended-1.0.0` | `krot-cp` | `LICENSE` |
| `github.com/shtorm-7/sing` | `v0.9.7-extended-1.2.1` | `both` | `LICENSE` |
| `github.com/tylertreat/BoomFilters` | `v0.0.0-20251117164519-53813c36cc1b` | `krot-cp` | `LICENSE` |
| `github.com/vishvananda/netns` | `v0.0.5` | `krot-cp` | `LICENSE` |
| `github.com/zeebo/blake3` | `v0.2.4` | `krot-cp` | `LICENSE` |
| `go.uber.org/multierr` | `v1.11.0` | `krot-cp` | `LICENSE.txt` |
| `go.uber.org/zap/exp` | `v0.3.0` | `krot-cp` | `LICENSE` |
| `go.uber.org/zap` | `v1.28.0` | `krot-cp` | `LICENSE` |
| `go.yaml.in/yaml/v2` | `v2.4.4` | `krot-cp` | `LICENSE`, `LICENSE.libyaml`, `NOTICE` |
| `go4.org/netipx` | `v0.0.0-20231129151722-fdeea329fbba` | `both` | `LICENSE` |
| `golang.org/x/crypto` | `v0.57.0` | `krot-cp` | `LICENSE` |
| `golang.org/x/exp` | `v0.0.0-20260410095643-746e56fc9e2f` | `krot-cp` | `LICENSE` |
| `golang.org/x/mod` | `v0.41.0` | `krot-cp` | `LICENSE` |
| `golang.org/x/net` | `v0.58.0` | `both` | `LICENSE` |
| `golang.org/x/oauth2` | `v0.36.0` | `krot-cp` | `LICENSE` |
| `golang.org/x/sync` | `v0.23.0` | `krot-cp` | `LICENSE` |
| `golang.org/x/sys` | `v0.48.0` | `both` | `LICENSE` |
| `golang.org/x/text` | `v0.42.0` | `krot-cp` | `LICENSE` |
| `golang.org/x/time` | `v0.15.0` | `krot-cp` | `LICENSE` |
| `google.golang.org/genproto/googleapis/rpc` | `v0.0.0-20251202230838-ff82c1b0f217` | `krot-cp` | `LICENSE` |
| `google.golang.org/grpc` | `v1.79.1` | `krot-cp` | `LICENSE`, `NOTICE.txt` |
| `google.golang.org/protobuf` | `v1.36.11` | `krot-cp` | `LICENSE` |
| `gopkg.in/yaml.v3` | `v3.0.1` | `both` | `LICENSE`, `NOTICE` |
| `lukechampine.com/blake3` | `v1.4.1` | `krot-cp` | `LICENSE` |
| `sigs.k8s.io/yaml` | `v1.6.0` | `krot-cp` | `LICENSE` |

104 modules, 112 license files.
