# krot

krot is a self-hosted substitute for a commercial VPN subscription backend. An
identity-aware control plane is the single source of truth for users and
per-node credentials: it hands out per-user sing-box subscription links
(VLESS-Reality, Hysteria2, TLS/WebSocket) and syncs membership from an
identity provider. Proxy nodes run agents that poll the control plane, render
their own sing-box configuration, validate it (`sing-box check`) and supervise
the sing-box child process.

Adding a user to one group (or assigning one role) is the entire user
lifecycle; removing it revokes the subscription on the next sync.

## Architecture

```text
cmd/krot-cp/             control plane: portal, subscriptions, agent API, identity sync
cmd/krot-agent/          node agent: poll desired state, render, validate, supervise sing-box
internal/directory/      identity-directory contract: Source per provider + shared verdict cache
internal/authentik/      authentik API v3 client (group members, live membership)
internal/zitadel/        Zitadel API v2 client (Connect-JSON ListAuthorizations)
internal/oidc/           OIDC relying party for portal login (PKCE, signed session cookie)
internal/store/          PostgreSQL store (users, servers, inbounds, server status, sync state)
internal/store/migrations/  embedded golang-migrate migrations, applied at startup
internal/model/          domain types shared by the control plane and the agents
internal/render/         sing-box config renderer, share-link builders, Happ routing profile
internal/staticmerge/    validate + splice the active users into an operator-owned base config
internal/sub/            subscription token derivation and /sub/{token} endpoint
internal/web/            templ + htmx portal (user page, read-only admin, routing page)
internal/cpapi/          control-plane side of the agent API (bearer auth, desired state, heartbeat)
internal/agentapi/       agent-side HTTP client for the agent API
charts/krot-control/     Helm chart for the control plane
charts/krot-agent/       Helm chart for node agents (one Deployment per node)
```

### The directory contract

`internal/directory` defines the only interface the control plane has towards
an identity provider:

```go
type Source interface {
	Members(ctx context.Context) ([]model.Member, error)
	Allowed(ctx context.Context, subject string) (bool, error)
}
```

`Members` lists every subject holding the configured group or role (the sync
loop calls it once per `KROT_SYNC_INTERVAL`); `Allowed` answers whether one
subject still holds it, and is what `/sub/{token}` and the admin page consult
per request. Every provider client (`internal/authentik`, `internal/zitadel`)
implements `Source` and nothing else.

`directory.Cached` wraps a `Source` with the verdict cache and the fail-open
grace window every consumer sees: a verdict younger than `KROT_CACHE_TTL` is
served from cache, a stale one is revalidated, and while the provider API is
unreachable a previously allowed subject stays allowed until `KROT_GRACE` has
passed since that subject's last successful check. Any other provider failure
surfaces as an error, so a wrong answer is never cached. The wrapper is shared
by all consumers, so provider clients stay free of cache logic.

The sync loop materializes membership into PostgreSQL (`users`), and the
control plane reads that table for links and identity; the per-request verdict
comes from `directory.Cached`, not from a fresh provider API call.

## Identity providers

The control plane is provider-agnostic. `KROT_IDP` selects the provider
(`authentik`, the default, or `zitadel`) and therefore which provider
variables are required. Both providers are connected to the same OIDC issuer
used for portal login, so the group/role you sync and the login you perform
resolve against the same directory.

### authentik

1. Create a group for VPN users and one for administrators
   (`krot::vpn` and `krot::admins` by default).
2. Create an API token on a user that can read groups and users.
3. Configure:

```sh
KROT_IDP=authentik
KROT_AUTHENTIK_URL=https://auth.example.com
KROT_AUTHENTIK_TOKEN=<api token>
KROT_AUTHENTIK_GROUP=krot::vpn
KROT_AUTHENTIK_ADMIN_GROUP=krot::admins
```

### Zitadel

1. Create a project, add the roles `vpn` and `vpn-admin`, and assign them to
   the users (a role assignment can come from a project grant in another
   organization as well; the client deduplicates by user).
2. Create a machine user and a personal access token for it. The token needs
   `user.grant.read`, which Zitadel grants to organization-level manager roles
   such as `ORG_OWNER` and `ORG_USER_MANAGER`.
3. Create an OIDC Web application with redirect URI `<KROT_BASE_URL>/callback`.
4. Configure:

```sh
KROT_IDP=zitadel
KROT_ZITADEL_URL=https://zitadel.example.com
KROT_ZITADEL_TOKEN=<personal access token>
KROT_ZITADEL_PROJECT_ID=<project id>
KROT_ZITADEL_ROLE=vpn
KROT_ZITADEL_ADMIN_ROLE=vpn-admin
```

Verify the token and the project id before starting the control plane. The
client and this check speak the same endpoint — the Connect-JSON encoding of
Zitadel's `ListAuthorizations`:

```sh
curl -sS -X POST "$KROT_ZITADEL_URL/zitadel.authorization.v2.AuthorizationService/ListAuthorizations" \
  -H "Authorization: Bearer $KROT_ZITADEL_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Connect-Protocol-Version: 1" \
  -d '{"pagination":{"limit":10,"asc":true},"filters":[{"projectId":{"id":"'"$KROT_ZITADEL_PROJECT_ID"'"}},{"roleKey":{"key":"vpn"}}]}'
```

A healthy response is `200` with a `pagination` object and an `authorizations`
array. A non-`200` answer carries a `{"code": ..., "message": ...}` body and means
the token or the project id is wrong.

### Portal login

The login flow is plain OIDC and works with any standards-compliant provider
connected to the same directory:

```sh
KROT_OIDC_ISSUER=https://idp.example.com
KROT_OIDC_CLIENT_ID=krot
KROT_OIDC_CLIENT_SECRET=<client secret>
KROT_BASE_URL=https://vpn.example.com
```

The redirect URI to register at the provider is `<KROT_BASE_URL>/callback`. The
control plane starts serving subscriptions and the agent API even while the
provider is unreachable; discovery retries in the background and the portal
answers `503` until it succeeds.

## Configuration

### Control plane (`krot-cp`)

| Variable | Default | Required | Description |
| --- | --- | --- | --- |
| `KROT_TOKEN_KEY` | — | always | Unpadded base64 of exactly 32 bytes (`openssl rand -base64 32 \| tr -d '='`); HMAC key for derived subscription tokens. |
| `KROT_TOKEN_NAMESPACE` | `krot-sub:` | no | HMAC namespace prefix of subscription tokens, used verbatim; set `cheburnet-sub:` to keep subscription URLs issued by a pre-rename corporate instance valid. |
| `KROT_COOKIE_KEY` | — | always | Unpadded base64 of exactly 32 bytes; key for the signed session cookie. |
| `KROT_OIDC_CLIENT_ID` | — | always | OIDC client id of the portal application. |
| `KROT_OIDC_CLIENT_SECRET` | — | always | OIDC client secret. |
| `KROT_OIDC_ISSUER` | — | always | Issuer URL of the OIDC provider (discovery document is fetched from it). |
| `KROT_BASE_URL` | — | always | Public base URL; the OIDC redirect URI is `<base>/callback`. |
| `KROT_DATABASE_URL` | — | always | PostgreSQL DSN; migrations run at startup. |
| `KROT_AGENT_TOKEN` | — | always | Bearer token the node agents present; must equal the agent's value. |
| `KROT_IDP` | `authentik` | no | Identity provider: `authentik` or `zitadel`. Selects which of the provider variables below are required. |
| `KROT_AUTHENTIK_URL` | — | with `KROT_IDP=authentik` | authentik base URL. |
| `KROT_AUTHENTIK_TOKEN` | — | with `KROT_IDP=authentik` | API token with read access to groups and users. |
| `KROT_AUTHENTIK_GROUP` | `krot::vpn` | no | Group whose members get a subscription. |
| `KROT_AUTHENTIK_ADMIN_GROUP` | `krot::admins` | no | Group whose members may open `/admin`. |
| `KROT_ZITADEL_URL` | — | with `KROT_IDP=zitadel` | Zitadel base URL. |
| `KROT_ZITADEL_TOKEN` | — | with `KROT_IDP=zitadel` | Personal access token of a machine user (needs `user.grant.read`). |
| `KROT_ZITADEL_PROJECT_ID` | — | with `KROT_IDP=zitadel` | Project the role assignments live in. |
| `KROT_ZITADEL_ROLE` | `vpn` | no | Project role whose holders get a subscription. |
| `KROT_ZITADEL_ADMIN_ROLE` | `vpn-admin` | no | Project role whose holders may open `/admin`. |
| `KROT_CACHE_TTL` | `5m` | no | How long an allowed/denied verdict is trusted before revalidation. |
| `KROT_GRACE` | `24h` | no | Fail-open window: a previously allowed subject stays allowed while the provider API is unreachable, until this much time has passed since its last successful check. |
| `KROT_SESSION_TTL` | `720h` | no | Portal session lifetime. |
| `KROT_SYNC_INTERVAL` | `60s` | no | Interval between directory syncs (`Members`). |
| `KROT_PROFILE_TITLE` | `Krot VPN` | no | Profile name in the subscription headers and in the Happ routing profile. |
| `KROT_PROFILE_SUPPORT_URL` | — (empty) | no | `support-url` header value of a subscription response. Empty sends no header. |
| `KROT_PROFILE_UPDATE_INTERVAL_HOURS` | `24` | no | `profile-update-interval` header value, in hours. |
| `KROT_REBUILD_KEY` | derived from `KROT_TOKEN_KEY` | no | Unpadded base64 of exactly 32 bytes; key sealing the `/rbr` capability tokens of the subscription re-builder. Unset derives it as `SHA-256(KROT_TOKEN_KEY + "krot-rebuild:")`, so existing `/rbr` links survive upgrades; setting a dedicated key, or rotating the token key, revokes every issued link at once. |
| `KROT_REBUILD_SECRET` | — (empty) | no | Access secret gating `POST /rebuild`, the only writer of new `/rbr` links. Empty leaves the form open to anyone who can reach it; the `/rbr` links themselves are never gated. |
| `KROT_LISTEN_ADDR` | `:8080` | no | HTTP listen address. |

An unknown `KROT_IDP` is rejected at startup, as is any missing variable the
selected provider needs; the error lists every missing name at once.

### Agent (`krot-agent`)

| Variable | Default | Required | Description |
| --- | --- | --- | --- |
| `KROT_CP_URL` | — | always | Control-plane base URL. |
| `KROT_AGENT_TOKEN` | — | always | Bearer token for the agent API; must equal the control plane's value. |
| `KROT_POLL_INTERVAL` | `30s` | no | Desired-state poll interval. |
| `KROT_SPEC` | `/etc/krot/agent.yaml` | no | Declared node spec (server name, endpoint, inbounds). |
| `KROT_WORKDIR` | `/etc/krot` | no | Work directory: rendered `config.json`, staged config, certs, applied hash, sing-box cache; in static mode also the injected `rendered.json` with `rendered.hash`/`rendered.base.hash`. Must be writable. |
| `KROT_STATIC_CONFIG` | — | no | Path to an operator-owned sing-box config JSON; enables static config passthrough and user injection (see below). |
| `KROT_STATIC_DATA_DIR` | dir of `KROT_STATIC_CONFIG` | no | sing-box data directory passed as `-D` in static mode; set it explicitly when certs/rule-sets live outside the config's directory (reference layout: config `/etc/sing-box/config.json`, data `/var/lib/sing-box`). |
| `KROT_SINGBOX` | `/usr/local/bin/sing-box` | no | sing-box binary used for `check` and `run`. |
| `KROT_HEALTH_ADDR` | `127.0.0.1:18081` | no | Health endpoint address (`/healthz`). |

### Static config passthrough and user injection (`krot-agent`)

Some nodes serve credentials that are pinned by clients already deployed — not
a config krot may re-render. Setting `KROT_STATIC_CONFIG` to such a config's
path puts the agent into static mode: the operator-owned file is the single
source of truth for that node, the agent never writes it or its directory and
reads it as input only. The node declares the inbounds the control plane's
users are injected into (its merge targets), and a static node does emit
`/sub` links for the inbounds it declares. It still registers and heartbeats
like any other node.

- `KROT_STATIC_CONFIG` — path to the operator-owned sing-box config JSON;
  static mode is enabled exactly when the variable is set.
- `KROT_STATIC_DATA_DIR` — the sing-box data directory (certs, rule-sets)
  passed as `-D`, defaulting to the directory of the config file. It is the
  data directory, not the config's directory: in the reference layout the
  config lives at `/etc/sing-box/config.json` while certs and rule-sets live
  under `/var/lib/sing-box`, so such a deployment sets
  `KROT_STATIC_DATA_DIR=/var/lib/sing-box` explicitly.

A merge target pins the credentials the base config already serves, so the
control plane can hand out links without inventing or rotating anything:

- a `vless_reality` target pins `reality_public_key` and `reality_short_id`:
  the public key of the base's `tls.reality.private_key` and one id out of the
  base's `tls.reality.short_id` list. The control plane stores both verbatim
  and leaves `reality_private_key` untouched — empty for a fresh row — since
  the base config holds the private key;
- a `hysteria2` target pins `obfs_password` and `pin_sha256`: the base's obfs
  password and the certificate's Xray pin — hex of the sha256 over the leaf
  certificate DER, any case, the value a client hex-decodes out of the link's
  `pinSHA256` parameter. The control plane stores both verbatim and leaves
  `cert_pem`/`key_pem` empty, since the base config holds the certificate; the
  inbound's subscription links carry the pinned value as their `pinSHA256`
  parameter. The HPKP-style `sha256/<base64>` pin a sing-box
  `certificate_public_key_sha256` setting uses is **not** that value and is
  rejected with an error naming the field, rather than emitting a link no
  client can parse. (Managed hysteria2 inbounds keep their historical
  `pin_sha256` column value; only injected links read it.)

The pins are never generated and never rotated — an `sni` change does not
touch them — and the pins of a type are all-or-nothing: a partial set is
rejected with `400` naming the missing field. Fields that do not apply to a
declaration's type are inert.

Before injecting anything the agent validates every merge target against the
base config: the tag has to name an inbound of the base and the declared type
has to match its protocol, `listen_port` and `sni` have to agree with it, the
pinned reality public key has to be the one derived from the base's private
key, the pinned short id has to be a member of the base's `short_id` list, the
pinned obfs password has to equal the base's `obfs.password`, and the pinned
certificate pin has to be the Xray pin of the certificate the base's
`tls.certificate_path` resolves to. Any mismatch fails fast, naming the tag and
the field, before anything is written or restarted.

The merge is append-only: the control plane's active users are appended to the
declared inbounds' `users` arrays and nothing else in the base changes — the
rest of the file survives verbatim, the operator's own users are never edited,
credentials the base already carries are deduplicated, a revoked user simply
stops being appended, and a node whose user set is drained merges none.

In this mode the agent runs `sing-box check` and `sing-box run` with
`-D <KROT_STATIC_DATA_DIR> -c <KROT_WORKDIR>/rendered.json`, where
`rendered.json` is that merged copy of the base config. The base config and
its directory are never written. The child is re-validated and restarted only
when the rendered bytes change — an mtime-only touch of the base does nothing
— and a failed check keeps the currently running child and reports the error.
Heartbeats carry the applied hash, which now covers the base and the rendered
config together; the agent writes `<KROT_WORKDIR>/rendered.hash` (the hash of
the bytes the child runs) and `<KROT_WORKDIR>/rendered.base.hash` (the base
hash of the last successful render) alongside `<KROT_WORKDIR>/applied.hash`,
so `KROT_WORKDIR` must be writable and must not be the config's directory.

Startup fails fast with a clear error on a missing or unreadable config file,
an unreadable data directory, or a failing `sing-box check` of the config it
starts from. Desired state keeps being polled for registration, heartbeats and
the active-user set; before the first successful poll the agent starts the
child from the last render whose base hash is unchanged, or from the base
config as-is when there is none, so a static node boots offline.

Pin the sing-box build the operator's config needs with `KROT_SINGBOX`; the
live servers run `1.13.14-aa119e82` builds.

An example deployment, mirroring the reference `arsolitt/sing-box-extended`
compose file:

```yaml
services:
  krot-agent:
    image: ghcr.io/arsolitt/krot-agent:<version>
    network_mode: host
    user: root
    cap_add: [NET_ADMIN, NET_RAW, NET_BIND_SERVICE, SYS_PTRACE]
    volumes:
      - ./sing-box/etc:/etc/sing-box:ro
      - ./sing-box/data:/var/lib/sing-box
      - ./krot:/var/lib/krot
      - ./agent.yaml:/etc/krot/agent.yaml:ro
      - /dev/net/tun:/dev/net/tun
    environment:
      KROT_CP_URL: "https://vpn.example.com"
      KROT_AGENT_TOKEN: "<agent token>"
      KROT_SPEC: "/etc/krot/agent.yaml"
      KROT_WORKDIR: "/var/lib/krot"
      KROT_STATIC_CONFIG: "/etc/sing-box/config.json"
      KROT_STATIC_DATA_DIR: "/var/lib/sing-box"
```

The `agent.yaml` next to it, declaring the two merge targets of the reference
deployment; the pin values are placeholders for the credentials of that base
config:

```yaml
server: vpn1
endpoint: vpn1.example.com
route_profile: proxy-server
inbounds:
  - tag: vless-in
    type: vless_reality
    listen_port: 443
    sni: vpn1.example.com
    reality_public_key: "<public key of the base config's reality private key>"
    reality_short_id: "<one short id of the base config's short_id list>"
  - tag: hy2-in
    type: hysteria2
    listen_port: 443
    sni: vpn1.example.com
    obfs_password: "<obfs password of the base config>"
    pin_sha256: "<certificate pin of the base config>"
```

## Subscriptions and the public Happ routing routes

`GET /sub/{token}` renders the user's links live from the database — one URI
per enabled (server, inbound) pair — and answers `404` for an unknown token, a
revoked user, or a subject that no longer holds the group/role. The token is
derived, never stored: `base64url(HMAC-SHA256(KROT_TOKEN_KEY,
KROT_TOKEN_NAMESPACE + subject)[:16])`, where `KROT_TOKEN_NAMESPACE` defaults to
`krot-sub:` and is used verbatim, so it is stable across restarts and
unguessable without the key.

Response headers:

| Header | Value |
| --- | --- |
| `profile-title` | `KROT_PROFILE_TITLE` |
| `profile-update-interval` | `KROT_PROFILE_UPDATE_INTERVAL_HOURS` |
| `support-url` | `KROT_PROFILE_SUPPORT_URL` |
| `routing` | the `happ://routing/onadd/<base64 profile>` deeplink |

The routing profile splits traffic on the client: RU geosite categories,
`geoip:ru` and the private ranges go direct, `geosite:category-ads-all` is
blocked, the international service sets the client-side rules proxy ride
`ProxySites` (the Google and AI/dev suites, Telegram, Discord and the cloud,
CDN and hosting providers), and everything else is tunnelled (`GlobalProxy`).
Geofile sources are the Loyalsoldier release assets, which Happ keeps in sync
by default; the itdog and custom rule sets of the sing-box client profile are
not carried by any published dataset and stay out of the Happ profile.

Because the profile is identical for every client and holds no per-user data,
it is also served unauthenticated:

| Route | Purpose |
| --- | --- |
| `GET /routing` | Landing page with an "Add to Happ" button and a copy button for the deeplink. |
| `GET /routing.json` | The raw profile as `application/json` — for scripts and clients that fetch it directly. |
| `GET /routing/import` | `302` to the `happ://routing/onadd/...` deeplink, so a plain `https://` URL can be pasted into a phone. |

`/routing` matches only that exact path; it does not swallow `/routing.json`
or `/routing/import`.

## Subscription re-builder (`/rebuild` and `/rbr`)

Happ hands a JSON subscription to Xray 1:1 and does not apply routing-profile
rules to it, so a client whose provider serves an Xray JSON subscription
cannot use krot's routing profile — the profile only exists for link-list
subscriptions. The re-builder closes that gap server-side: krot fetches the
provider subscription itself, rewrites it with the krot routing profile, and
serves the result.

| Route | Purpose |
| --- | --- |
| `GET /rebuild` | Form: paste a provider subscription URL, optionally name the proxy outbound tag, pick the block list. Gated by `KROT_REBUILD_SECRET` when one is set. |
| `POST /rebuild` | Seals the form into a `/rbr` link and renders it. |
| `GET /rbr/{token}` | Fetches the provider subscription the token embeds, rewrites it, and serves it with the Happ management headers. The token is a capability: no other auth. |

What the rewrite does depends on the provider payload, which is also how the
same endpoint serves both halves of a provider's catalogue:

- **Xray JSON config** (single object or array): the provider's `outbounds`
  survive verbatim; the config gets krot's `dns` block and krot's routing
  rules mapped onto the provider's own outbound tags, prepended ahead of the
  provider's rules, whose balancers keep their default route. The proxy tag is
  the one the routing rules point the tunneled traffic at; it resolves in this
  order: the `proxy_tag` field of the form when filled — a hint that must name
  an outbound of the provider config, rejected by name if it does not; then
  the first outbound that is neither direct/block/DNS-plumbing by tag, nor a
  selector/urltest/balancer aggregate, nor a tunnel-less protocol
  (freedom/blackhole/dns); finally, for configs whose only concrete outbound
  is loopback or freedom-adjacent, the first remaining non-plumbing outbound.
  When nothing resolves, the request fails closed with the available outbound
  tags named, never a config with broken references.
- **Link list** (plain or base64): re-emitted as-is with the
  `happ://routing/onadd/<base64>` deeplink prepended and advertised in the
  `routing` header, exactly like a `/sub` response.
- Anything else fails closed: an unrecognized payload is never served as a
  subscription.

To verify the proxy tag resolution without a client, the emitted rules are
plain JSON — fetch them through the `routing` header, which carries the
`happ://routing/onadd/...` deeplink (its base64 decodes to the profile), or
through the baked config itself. Only the provider's own JSON shows its
outbound tags; the rebuilt response shows both the tags and what the rules
reference, and the two must agree:

```sh
# Outbound tags of the provider config (via your own access to it):
curl -s '<provider subscription URL>' | jq -r '.. | objects | select(has("outbounds")) | .outbounds[].tag'

# Referenced tags vs available tags of the rebuilt response: ok=true means
# every rule target exists. Provider rules that route via a balancer carry a
# balancerTag instead of an outboundTag, so both reference kinds are checked
# against their own namespace — outbound rules against the config's outbound
# tags, balancer rules against its registered routing.balancers.
curl -s -H 'User-Agent: Happ' 'https://vpn.example/rbr/<token>' |
  jq -r '[.. | objects | select(has("routing")) | .routing.rules[] | select(has("outboundTag")) | .outboundTag] as $refs |
         ([.. | objects | select(has("outbounds")) | .outbounds[].tag] | unique) as $tags |
         ([.. | objects | select(has("routing")) | .routing.rules[] | select(has("balancerTag")) | .balancerTag] | unique) as $brefs |
         ([.. | objects | select(has("routing")) | .routing.balancers[]?.tag] | unique) as $bal |
         {ok: (($refs - $tags | length) == 0 and ($brefs - $bal | length) == 0),
          missing_outbound: ($refs - $tags), missing_balancer: ($brefs - $bal)}'
```

The rebuilt response is also the only place the picked tag is stated on a
success: the control plane's `subscription rebuilt` log line names both the
`proxy_tag` it targeted and the `outbound_tags` the config carried (plus
`proxy_tag_hint` when the form named one), so an operator reading the logs
gets the mapping without decoding the body. A bad `proxy_tag` from the form
is not rejected up front — the seal stores it verbatim and the failure
surfaces on the first `/rbr` fetch — and the `/rbr` answer for any failure is
the generic short message, with the detail (including the available tags of an
unresolvable config) in the same log line.

The definitive check is the client's core: an Xray-based client refuses to
start a config with an unknown rule target, so an imported rebuilt
subscription that connects *and* routes as intended is proof the mapping
holds. If the auto-detection picked the wrong outbound — an unusual config
with several concrete tunnels, where the first one is not the intended proxy —
re-generate the link with the `proxy_tag` field of the form naming the right
tag.

The fetch relays the identity headers a provider's device accounting reads —
`User-Agent`, `HWID`/`X-Hwid`, `X-Ver-Os`, `X-Ver`, `X-Device-Model`,
`Device`, `Device-Model` — from the requesting client upstream, and only
those: cookies, credentials and control-plane headers stay behind. The
provider URL never appears in a log line, an error or the rendered page: the
sealed token is the only place it lives, and it is what the link carries.

The fetch is shaped for provider uptime rather than freshness at any cost: a
per-URL cache with a short TTL, `ETag` revalidation, one in-flight request per
URL, and a stale copy served while the provider fails. The upstream URL is
vetted against SSRF: HTTPS only, the standard port only, every resolved
address public (IPv4 and IPv6, including the transition ranges that embed
IPv4), redirects re-vetted hop by hop, and a dial-time re-check so a
rebinding resolver cannot slip past the pre-flight. Responses are bounded:
at most 8 concurrent fetches, a 2 MiB per-response cap, a 16 MiB total cache
budget with oldest-first eviction, and a per-URL-and-session cache key so one
rebuilt subscription never receives the body fetched under another's device
identity.

Because the provider is untrusted, the served `Content-Type` is krot's own
classification of the rewritten payload — `application/json` for a baked
config, `text/plain` for a link list — never the provider's header, and every
`/rbr` response carries `X-Content-Type-Options: nosniff`: a hostile provider
cannot turn the control-plane origin into an HTML renderer. `POST /rebuild`
spends a per-IP failure budget (10 attempts, refilling at 10/min) and compares
the gate secret by SHA-256 digest, so neither the secret's length nor an
unlimited guessing rate is observable. When `KROT_REBUILD_SECRET` is unset the
form stays open by design, as the owner chose; the failure budget is the only
brake on that path. The budget keys on the request's remote address, never on
forwarding headers, so behind the chart's ingress it degrades to one shared
bucket for all callers — a deliberate trade-off: already-issued `/rbr` links
are unaffected, and the form is a convenience path rather than a serving one.
Concurrent rebuilds are bounded too (8 in flight; excess answers `503` with
`Retry-After`), so a burst of parallel requests cannot pile decode-and-marshal
work onto the control plane even when the fetch itself is a cache hit.

## Charts

Both charts live in this repository and are published as plain Helm charts
(no repository index is required — install them from a checkout).

```sh
helm install krot-control charts/krot-control \
  --namespace krot --create-namespace \
  --set ingress.enabled=true \
  --set ingress.host=vpn.example.com \
  --set ingress.tlsSecret=vpn-example-com-tls \
  --set config.KROT_BASE_URL=https://vpn.example.com \
  --set config.KROT_OIDC_ISSUER=https://idp.example.com \
  --set config.KROT_AUTHENTIK_URL=https://auth.example.com
```

Notes for `charts/krot-control`:

- `image.repository` defaults to `ghcr.io/arsolitt/krot-cp`; `image.tag` empty
  means the chart `appVersion`.
- `ingress.enabled` defaults to `false`: no Ingress object is rendered unless
  you opt in, and the TLS block appears only when `ingress.tlsSecret` is set.
- `gatewayAPI.enabled` defaults to `false`: the Gateway API alternative to
  `ingress`. `gatewayAPI.gatewayName` (required when enabled) names the Gateway
  the `krot-cp` HTTPRoute attaches to, `gatewayAPI.gatewayNamespace` covers a
  Gateway in another namespace, and `gatewayAPI.host` (also required when
  enabled) is the route's hostname — a hostless HTTPRoute would match every
  host the listener serves, capturing traffic meant for other routes on a
  shared Gateway. The Gateway's listener terminates TLS — the chart renders no
  certificate. `ingress` and `gatewayAPI` are independent opt-ins.
- `imagePullSecrets` (a list) and `podAnnotations` / `podLabels` (maps) are
  passed through to the Deployment.
- `config` is rendered verbatim into the `krot-cp-config` ConfigMap (the
  chart's default map sets the non-secret `KROT_*` values, including
  `KROT_CACHE_TTL: 60s`, which overrides the binary's `5m` default), and
  `secretName` (default `krot-cp-secrets`) is consumed with `envFrom`. Create
  that Secret out of band — it must carry `KROT_TOKEN_KEY`, `KROT_COOKIE_KEY`,
  `KROT_OIDC_CLIENT_ID`, `KROT_OIDC_CLIENT_SECRET`, `KROT_DATABASE_URL`,
  `KROT_AGENT_TOKEN`, and the provider token
  (`KROT_AUTHENTIK_TOKEN` or `KROT_ZITADEL_TOKEN`).
- `databaseTLS.enabled` defaults to `false`: PostgreSQL TLS material is mounted
  read-only at `/etc/krot/pg-tls`, and `PGSSLROOTCERT` and `PGSSLMODE`
  (`verify-full` by default, `verify-ca` also supported) are exported into the
  container, so `KROT_DATABASE_URL` needs no inline TLS parameters.
  `databaseTLS.caSecretName` (required when enabled) is the CA Secret, key
  `databaseTLS.caKey` (default `ca.crt`); an optional
  `databaseTLS.clientSecretName` adds a client certificate and exports
  `PGSSLCERT`/`PGSSLKEY` (`certKey`/`keyKey`, defaults `tls.crt`/`tls.key`).
  An explicit `sslmode` or `sslrootcert` in the DSN wins over the environment.

```yaml
# Gateway API instead of an Ingress, and PostgreSQL TLS for verify-full;
# KROT_DATABASE_URL itself stays free of TLS parameters:
gatewayAPI:
  enabled: true
  gatewayName: krot-gateway
  # gatewayNamespace: gateway-system
  host: vpn.example.com
databaseTLS:
  enabled: true
  sslmode: verify-full
  caSecretName: pg-core-ca          # CNPG: the cluster's <cluster>-ca secret
  clientSecretName: krot-cp-pg-tls  # optional, keys tls.crt/tls.key
```

```sh
# Gateway API instead of an Ingress
helm install krot-control charts/krot-control --namespace krot \
  --set gatewayAPI.enabled=true \
  --set gatewayAPI.gatewayName=krot-gateway \
  --set gatewayAPI.gatewayNamespace=gateway-system \
  --set gatewayAPI.host=vpn.example.com

# PostgreSQL TLS from a CNPG-style CA secret (kubectl get secret pg-core-ca)
helm install krot-control charts/krot-control --namespace krot \
  --set databaseTLS.enabled=true \
  --set databaseTLS.caSecretName=pg-core-ca \
  --set databaseTLS.clientSecretName=krot-cp-pg-tls
```

```sh
helm install krot-agent charts/krot-agent \
  --namespace krot \
  --set cpUrl=http://krot-cp:8080 \
  --set nodes[0].name=vpn1 \
  --set nodes[0].node=worker-1 \
  --set nodes[0].endpoint=vpn1.example.com \
  --set nodes[0].routeProfile=proxy-server \
  --set nodes[0].inbounds[0].tag=vless-in \
  --set nodes[0].inbounds[0].type=vless_reality \
  --set nodes[0].inbounds[0].listenPort=8443 \
  --set nodes[0].inbounds[0].sni=cdn.example.com
```

Notes for `charts/krot-agent`:

- One Deployment and one spec ConfigMap per entry of `nodes`; the agent pod is
  `hostNetwork` with `Recreate` strategy, so a rolling update never collides on
  the node ports.
- `agentTokenSecretName` (default `krot-agent`, key `token`) holds the agent's
  `KROT_AGENT_TOKEN`; `cpUrl` is the control-plane base URL; `dnsPolicy`
  defaults to `Default` (use `ClusterFirstWithHostNet` when `cpUrl` points at
  an in-cluster Service).
`nodes[]` entries:

| Field | Description |
| --- | --- |
| `name` | Server name in the control plane. |
| `node` | Kubernetes node hostname (`nodeSelector`). |
| `endpoint` | Public DNS name pointing at the node's IP. |
| `routeProfile` | Routing profile compiled into the agent (default `proxy-server`). |
| `tolerations` | Optional taints to tolerate on the pinned node. |
| `inbounds[]` | What the node serves: `tag`, `type` (`vless_reality`, `hysteria2`, `vless_ws`), `listenPort`, `sni`, and for `vless_ws` `publicEndpoint`, `publicPort`, `wsPath`, `originTls`. |

- `inbounds` of type `vless_ws` additionally get a Service and an Ingress
  (`wsIngress.className`, `wsIngress.tlsSecretName`, `wsIngress.readTimeout`),
  so a CDN edge can reach the agent through the cluster ingress instead of
  node ports.
- `gatewayAPI.enabled` defaults to `false` and is the Gateway API alternative
  to `wsIngress`: every (node, `vless_ws` inbound) pair gets an HTTPRoute on
  the node's Service — hostname `sni`, path `wsPath` (default `/`) —
  attached to the Gateway named by `gatewayAPI.gatewayName` (required when
  enabled; `gatewayAPI.gatewayNamespace` when it lives in another namespace).
  The Gateway's listener terminates TLS. The values are configured
  independently of `wsIngress`.
- `image.repository` defaults to `ghcr.io/arsolitt/krot-agent`; `image.tag`
  empty means the chart `appVersion`; `imagePullSecrets`, `podAnnotations` and
  `podLabels` behave as in the control chart.

## Release flow

A release exists only because a tag was pushed, and the tag carries the version
— nothing in the tree is bumped by hand. Both tracks are cut from `main` and the
tag is created by [`hack/release.sh`](hack/release.sh):

| Track | Tag | GitHub release |
| --- | --- | --- |
| stable | `v0.2.0` | normal, takes "Latest" |
| release candidate | `v0.2.0-rc.1` | pre-release, never "Latest" |

1. Write the section the release body comes from: `## [<version>]` in
   [`CHANGELOG.md`](CHANGELOG.md). A candidate reuses the section of the version
   it is a candidate of, so `0.2.0-rc.1` publishes `## [0.2.0]`.
2. Cut the tag with `hack/release.sh <version>` (for example
   `hack/release.sh 0.2.0-rc.1`). It refuses a version of any other shape, a
   missing CHANGELOG section, a dirty working tree, a `HEAD` that is not the tip
   of `origin/main`, and a tag that exists locally or on `origin`. Since GitHub
   creates no run at all for a push whose head commit carries a workflow-skip
   token, it also steps past the `chore(release): record <tag> [skip ci]`
   record commits and refuses to cut the tag from a commit carrying one — such a
   tag would silently release nothing. `hack/release.sh --check <version>`
   validates without pushing.
3. Pushing the tag starts the single workflow,
   [`.github/workflows/ci.yml`](.github/workflows/ci.yml). `release-tag`
   resolves the version, the channel and the section, refusing a tag that is not
   an ancestor of `origin/main`; the gates run on the same push, and so does
   `images` (`ghcr.io/arsolitt/krot-cp` and `krot-agent`, `linux/amd64`).
   `release` needs all of them, so a red gate blocks publication instead of
   failing alongside it: it packages both charts at the tag's version
   (`helm package --version --app-version`, so the packaged charts' default
   image tag is the version this run built), creates the GitHub release with the
   CHANGELOG section as its body, attaches the license bundle
   (`krot-licenses-<version>.tar.gz`, carrying `LICENSE` and `licenses/`) as an
   extra asset, and publishes the chart repository index on the `gh-pages`
   branch with `helm repo index --merge` — not chart-releaser, whose
   already-indexed check misreads a prerelease chart version (`0.2.0-rc.1`)
   and cannot index a candidate's two charts without duplicating one.
4. `release` then records the released version in both `charts/*/Chart.yaml` on
   `main`, in a `chore(release): record <tag> [skip ci]` commit — the tag is the
   source of truth and the branch follows it.
5. Consumers pick the version up with `helm repo update`. A candidate is
   opt-in: it stays invisible to an unqualified `helm install` and is reached
   with `helm search repo krot/krot-control --versions --devel` and
   `helm install … --version 0.2.0-rc.1`.

Nothing else is a release: a merge publishes nothing, so documentation, CI and
even a chart change are safe until a tag is pushed.

The images are built for `linux/amd64` only: the arm64 leg needed QEMU emulation
and dominated the release wall-clock time. Re-add `linux/arm64` to `platforms`
in [`ci.yml`](.github/workflows/ci.yml) and the
`docker/setup-qemu-action` step to publish it.

### CI gates

Every pull request runs six jobs; the first five are the ones worth marking as
required checks, and `release-tag` runs on a version tag (`v[0-9]*`) push only.
On that tag push the same gates run and the `release` job needs every one of
them, so a red gate blocks the release instead of failing alongside it:

| Job | What it proves |
| --- | --- |
| `lint` | `golangci-lint` and `go tool templ fmt -fail .` over the Go tree. |
| `test` | `go vet ./...`, the test suite against a PostgreSQL service, and `make build`. |
| `charts` | `helm lint --strict` for both charts and every scenario, then `helm template` + `kubeconform -strict` for the defaults and every scenario on the Kubernetes versions in the workflow's `env:` block. |
| `schema` | `charts/*/ci/invalid/*.yaml` is still refused by `values.schema.json`, `charts/*/ci/invalid-render/*.yaml` is still refused by the chart's own template guards, and every supported scenario still renders. |
| `licenses` | The committed bundle is current: `make licenses` regenerates `licenses/` and the charts' `LICENSE` copies for the modules linked into the released binaries, and the job fails on any diff in those paths — run `make licenses` and commit the result after a dependency change. |
| `release-tag` | A version tag (`v[0-9]*`) push only: resolves the version, the channel and the CHANGELOG section the `release` job consumes, and refuses a tag that is not an ancestor of `origin/main`. |

The chart fixtures come in three categories, one meaning each — a fixture in the
wrong folder makes the job that owns it fail, not pass:

| Folder | What the fixture must do | Owning job |
| --- | --- | --- |
| `charts/*/ci/*-values.yaml` | render `helm template` | `charts`, `schema` |
| `charts/*/ci/invalid/*.yaml` | be rejected by `values.schema.json` | `schema` |
| `charts/*/ci/invalid-render/*.yaml` | be rejected by a template `fail`, naming the value in its `# expect-error:` line | `schema` |

## Development

```sh
make build   # templ generate + build/krot-cp and build/krot-agent
make test    # go test ./... (store tests need KROT_TEST_DATABASE_URL)
make lint    # golangci-lint + templ fmt -fail
make fmt     # gofmt + templ fmt
make licenses # regenerate licenses/ and the charts' LICENSE copies
```

The chart gates, runnable locally:

```sh
# Lint both charts, including values.schema.json validation
helm lint --strict charts/krot-control charts/krot-agent

# Every supported scenario must render
for chart in charts/krot-control charts/krot-agent; do
  for f in "$chart"/ci/*-values.yaml; do helm template ci "$chart" -f "$f" > /dev/null || exit 1; done
done

# The schema must reject these
for chart in charts/krot-control charts/krot-agent; do
  for f in "$chart"/ci/invalid/*.yaml; do
    helm template ci "$chart" -f "$f" > /dev/null && echo "unexpectedly accepted: $f"
  done
done

# These must be rejected by a template guard, not by the schema
for chart in charts/krot-control charts/krot-agent; do
  for f in "$chart"/ci/invalid-render/*.yaml; do
    helm template ci "$chart" -f "$f" > /dev/null && echo "unexpectedly accepted: $f"
  done
done
```

Tests that touch the store need a scratch PostgreSQL and skip when
`KROT_TEST_DATABASE_URL` is unset:

```sh
docker run -d --name krot-test-pg \
  -e POSTGRES_PASSWORD=krot -e POSTGRES_DB=krot \
  -p 127.0.0.1:5433:5432 postgres:17.5

KROT_TEST_DATABASE_URL='postgres://postgres:krot@127.0.0.1:5433/krot?sslmode=disable' make test
```

Web templates are templ sources: run `go tool templ generate ./internal/web`
after editing `internal/web/web.templ` (`make build` does it too; the generated
`web_templ.go` is tracked).

The toolchain is pinned to go1.26.4 by `GOTOOLCHAIN` in the Makefile: the
`go-json-experiment` alias used by the sing-box option types breaks on newer
Go releases.

## License

krot is released under the GNU Affero General Public License v3.0 or later
(AGPL-3.0-or-later). Copyright (C) 2026 Arsolitt <https://arsolitt.tech/>.
The full text is in [LICENSE](LICENSE); the license texts of every third-party
module the released binaries link are collected in
[`licenses/`](licenses/README.md).
