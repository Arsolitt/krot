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
| `KROT_WORKDIR` | `/etc/krot` | no | Work directory: rendered `config.json`, staged config, certs, applied hash, sing-box cache. |
| `KROT_SINGBOX` | `/usr/local/bin/sing-box` | no | sing-box binary used for `check` and `run`. |
| `KROT_HEALTH_ADDR` | `127.0.0.1:18081` | no | Health endpoint address (`/healthz`). |

## Subscriptions and the public Happ routing routes

`GET /sub/{token}` renders the user's links live from the database — one URI
per enabled (server, inbound) pair — and answers `404` for an unknown token, a
revoked user, or a subject that no longer holds the group/role. The token is
derived, never stored: `base64url(HMAC-SHA256(KROT_TOKEN_KEY, "krot-sub:" +
subject)[:16])`, so it is stable across restarts and unguessable without the
key.

Response headers:

| Header | Value |
| --- | --- |
| `profile-title` | `KROT_PROFILE_TITLE` |
| `profile-update-interval` | `KROT_PROFILE_UPDATE_INTERVAL_HOURS` |
| `support-url` | `KROT_PROFILE_SUPPORT_URL` |
| `routing` | the `happ://routing/onadd/<base64 profile>` deeplink |

The routing profile splits traffic on the client: RU geosite categories,
`geoip:ru` and the private ranges go direct, `geosite:category-ads-all` is
blocked, and everything else is tunnelled (`GlobalProxy`). Geofile sources are
the Loyalsoldier release assets, which Happ keeps in sync by default.

Because the profile is identical for every client and holds no per-user data,
it is also served unauthenticated:

| Route | Purpose |
| --- | --- |
| `GET /routing` | Landing page with an "Add to Happ" button and a copy button for the deeplink. |
| `GET /routing.json` | The raw profile as `application/json` — for scripts and clients that fetch it directly. |
| `GET /routing/import` | `302` to the `happ://routing/onadd/...` deeplink, so a plain `https://` URL can be pasted into a phone. |

`/routing` matches only that exact path; it does not swallow `/routing.json`
or `/routing/import`.

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
- `image.repository` defaults to `ghcr.io/arsolitt/krot-agent`; `image.tag`
  empty means the chart `appVersion`; `imagePullSecrets`, `podAnnotations` and
  `podLabels` behave as in the control chart.

## Release flow

A release exists only because a tag was pushed, and the tag carries the version
— nothing in the tree is bumped by hand. Both tracks are cut from `main` and the
tag is created by [`hack/release.sh`](hack/release.sh):

| Track | Tag | GitHub release |
| --- | --- | --- |
| stable | `release-0.2.0` | normal, takes "Latest" |
| release candidate | `release-0.2.0-rc.1` | pre-release, never "Latest" |

1. Write the section the release body comes from: `## [<version>]` in
   [`CHANGELOG.md`](CHANGELOG.md). A candidate reuses the section of the version
   it is a candidate of, so `0.2.0-rc.1` publishes `## [0.2.0]`.
2. Cut the tag with `hack/release.sh <version>` (for example
   `hack/release.sh 0.2.0-rc.1`). It refuses a version of any other shape, a
   missing CHANGELOG section, a dirty working tree, a `HEAD` that is not the tip
   of `origin/main`, and a tag that exists locally or on `origin`;
   `hack/release.sh --check <version>` validates without pushing.
3. Pushing the tag starts the pipeline. `ci` runs `lint`, `test`, `charts`,
   `schema` and `release-tag` — the last one resolves the version, the channel
   and the section and refuses a tag that is not an ancestor of `origin/main`.
   `release` then builds and pushes `ghcr.io/arsolitt/krot-cp` and
   `ghcr.io/arsolitt/krot-agent` for `linux/amd64`, packages both charts at the
   tag's version (`helm package --version`), creates the GitHub release with the
   CHANGELOG section as its body, and publishes the chart repository index on
   the `gh-pages` branch.
4. The job then records the released version in both `charts/*/Chart.yaml` on
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
in [`.github/workflows/release.yml`](.github/workflows/release.yml) and the
`docker/setup-qemu-action` step to publish it.

### CI gates

Every pull request runs five jobs, and the first four are the ones worth marking
as required checks:

| Job | What it proves |
| --- | --- |
| `lint` | `golangci-lint` and `go tool templ fmt -fail .` over the Go tree. |
| `test` | `go vet ./...`, the test suite against a PostgreSQL service, and `make build`. |
| `charts` | `helm lint --strict` for both charts and every scenario, then `helm template` + `kubeconform -strict` for the defaults and every scenario on the Kubernetes versions in the workflow's `env:` block. |
| `schema` | `charts/*/ci/invalid/*.yaml` is still refused by `values.schema.json`, `charts/*/ci/invalid-render/*.yaml` is still refused by the chart's own template guards, and every supported scenario still renders. |
| `release-tag` | A `release-*` tag push only: the version shape, the CHANGELOG section and the branch the tag was cut from. |

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

krot is released under the GNU Affero General Public License v3.0 (AGPL-3.0).
See [LICENSE](LICENSE) for the full text.
