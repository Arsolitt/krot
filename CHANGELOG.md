# Changelog

All notable changes to krot. The section for a released version is published as
that GitHub release's body by the `release` job in
`.github/workflows/ci.yml`.

Versions come from the git tag, not from a hand-edited `Chart.yaml`: the tag is
`v<version>`, where `<version>` is either a stable release (`0.2.0`) or a
release candidate (`0.2.0-rc.1`). The section published is `## [<version>]` - a
candidate publishes the section of the version it is a candidate of, so
`0.2.0-rc.1` publishes `## [0.2.0]`. Write the section before cutting the first
tag of the version; its heading date is the day the section was opened.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.4.1] - 2026-10-12

### Fixed

- The Happ management headers (`Profile-Title`, `Profile-Update-Interval`,
  `Support-Url`, `Routing`) are now set and read in canonical spelling:
  identical on the wire — HTTP header names are case-insensitive and Go
  canonicalizes them anyway — but the canonicalheader check in the pinned
  golangci-lint v2.13.2 rejected the lowercase spelling while the older local
  v2.12.2 stayed silent, and the release run of v0.4.0 failed on it.
- The lint backlog the pinned linter surfaced is cleared: the repeated
  DNS/resolver, protocol and proto3-JSON literals in `internal/render` and
  `internal/zitadel` are named constants, and the byte-slice fixtures in the
  `internal/staticmerge` tests build with `fmt.Appendf` instead of
  `[]byte(fmt.Sprintf(...))`. `golangci-lint run ./cmd/... ./internal/...`
  reports zero issues under both v2.12.2 and the pinned v2.13.2.

### Changed

- `make lint` refuses to run when the installed `golangci-lint` version differs
  from the workflow's `GOLANGCI_LINT_VERSION` pin, naming both versions and the
  install command: the mismatch is what let a locally green run pass a tree the
  pinned CI linter then failed.

## [0.4.0] - 2026-10-12

### Added

- Conditional navigation on every page (portal, routing, re-builder, admin):
  a shared nav bar renders Portal and Rebuild always, Admin only for members
  of the admin group/role (checked without touching the response writer), and
  Sign in or Sign out according to the session, so the public pages carry no
  session-only entries and the admin page loses its hand-rolled identity line.

- Subscription re-builder: `GET /rebuild` serves a form that seals a provider
  subscription URL into a `/rbr` capability token (XChaCha20-Poly1305 under
  `KROT_REBUILD_KEY`, derived from `KROT_TOKEN_KEY` when unset, so issued
  links survive upgrades), and `GET /rbr/{token}` fetches that provider
  subscription and serves it rebuilt with the krot routing profile. The form
  is gated by `KROT_REBUILD_SECRET` when one is configured; the link itself is
  never gated, exactly as `/sub` treats its token. An Xray JSON payload (a
  single config or an array) keeps the provider's outbounds and gets krot's
  `dns` and routing rules mapped onto the provider's outbound tags
  (auto-detected, or named in the form), prepended ahead of the provider's own
  rules; a link list gets the `happ://routing/onadd` deeplink prepended and
  advertised in the `routing` header; anything else fails closed. The fetch
  relays the client's identification headers (`User-Agent`, `HWID`/`X-Hwid`,
  `X-Ver-Os`, `X-Ver`, `X-Device-Model`, `Device`, `Device-Model`) upstream for
  the provider's device accounting, and is vetted against SSRF (HTTPS, port
  443, every resolved address public, redirects re-vetted per hop, dial-time
  re-check), cached per URL with `ETag` revalidation and single-flight, and
  served stale while the provider fails. Provider URLs and tokens stay out of
  logs, errors and rendered pages. The served `Content-Type` is krot's
  classification of the rewritten payload rather than the provider's header,
  `/rbr` answers with `X-Content-Type-Options: nosniff`, fetches are bounded
  (8 concurrent, 2 MiB per response, 16 MiB cache budget, cache keys separated
  per rebuilt subscription), and `POST /rebuild` carries a per-IP failure
  budget and compares the gate secret by digest.

### Fixed

- The `subscription rebuilt` log line now reports the tag mapping the JSON
  path applied: `proxy_tag` (the tag every krot rule targets), `outbound_tags`
  (the tags the provider config carried) and `proxy_tag_hint` when the form
  named one — the only place the picked tag is stated on a success. The
  link-list path carries no tag fields, and a failure states its detail
  (including the available tags of an unresolvable config) in the separate
  `subscription rebuild failed` line, since `/rbr` answers with a generic
  message.

- The re-builder's `Rewrite` entry point tolerates a nil logger, defaulting to
  the process logger instead of dereferencing nil on its first log line; a
  no-op in the control plane, which always supplies one, but the exported API
  should not panic on a call shape it accepts.

## [0.3.0] - 2026-10-11

### Added

- User injection into the declared inbounds of a node running an
  operator-owned base config (`KROT_STATIC_CONFIG`): a static node declares its
  merge targets in the spec, pinning the credentials the base already serves -
  `reality_public_key` and `reality_short_id` on a `vless_reality` inbound,
  `obfs_password` and `pin_sha256` on a `hysteria2` one. The pins are stored
  verbatim, never generated and never rotated by an `sni` change: a pinned
  reality inbound keeps `reality_private_key` untouched and a pinned hysteria2
  inbound keeps `cert_pem`/`key_pem` empty, since the base config holds the
  private key and the certificate, and a partial pin set is rejected `400`
  naming the missing field. The agent validates every merge target against the
  base (tag and protocol, `listen_port`, `sni`, the reality public key derived
  from the base's private key, short-id membership, the obfs password and the
  certificate pin - the last in the Xray form a `pinSHA256` parameter carries,
  hex of the sha256 over the leaf certificate DER, with the HPKP-style
  `sha256/<base64>` spelling that sing-box pins elsewhere rejected naming the
  field) and fails fast naming the tag and field on a mismatch, then
  merges the active users append-only into the declared inbounds - the rest of
  the base survives verbatim, credentials are deduplicated, the operator's own
  users are never edited, revoked users simply stop being appended and a
  drained node merges none - and runs the merged copy as
  `<KROT_WORKDIR>/rendered.json` under the unchanged `-D` data dir, restarting
  the child only when the rendered bytes change and booting offline from a
  render whose base is unchanged. Static nodes that declare merge targets now
  emit `/sub` links.
- Hysteria2 subscription links fall back to the inbound's pinned `pin_sha256`
  when it carries no stored certificate, so an injected static inbound yields a
  `pinSHA256` parameter without the control plane holding the certificate. The
  pinned value is the Xray pin, so the parameter is parseable by the clients
  that hex-decode it.

## [0.2.0] - 2026-10-08

### Added

- Static config passthrough on the node agent: `KROT_STATIC_CONFIG` points at an
  operator-owned sing-box config JSON that the agent supervises as-is (never
  renders, merges or writes it), with `KROT_STATIC_DATA_DIR` as the `sing-box -D`
  working directory; the config is re-validated and the child restarted only when
  the file's content hash changes, a failed check keeps the running child, and
  startup fails fast on a missing/unreadable config, an unreadable data
  directory, a failing check or a spec that declares inbounds. Static nodes
  register and heartbeat normally and emit no subscription links.
- Gateway API (HTTPRoute) support in both charts, opt-in alongside the
  Ingress: `charts/krot-control` routes the portal and subscription endpoints
  to `krot-cp`, and `charts/krot-agent` routes every `vless_ws` inbound to its
  node's Service, each attached to an operator-provided Gateway whose listener
  terminates TLS.
- PostgreSQL TLS certificate mounting on `charts/krot-control`: `databaseTLS`
  mounts a CA (and, optionally, a client certificate) read-only at
  `/etc/krot/pg-tls` and exports `PGSSLROOTCERT`, `PGSSLMODE` (and, with a
  client secret, `PGSSLCERT`/`PGSSLKEY`), so `KROT_DATABASE_URL` can use
  `sslmode=verify-full` or `verify-ca` without inline TLS parameters.

### Changed

- The public Happ routing profile (and the subscription `routing:` header)
  names the international service sets explicitly: the Google and AI/dev
  suites, Telegram, Discord and the cloud/CDN/hosting tags ride `ProxySites`
  ahead of the global proxy, so a service that also matches a direct rule
  stays tunnelled. The itdog and custom rule sets of the sing-box client
  profile are not carried by any published geodataset and remain out of the
  Happ profile.

### Fixed

- The `gh-pages` chart index is generated with `helm repo index --merge`
  instead of chart-releaser: `cr index` v1.8.1 splits an asset name on the
  last dash, so a prerelease chart version (`0.2.0-rc.1`) never matched its
  already-indexed check, duplicating one chart of the release and dropping
  the other.
- The Zitadel client failed to decode a live v4 ListAuthorizations response:
  Connect-JSON encodes int64 as a string, so `pagination.totalResult` (`"2"`)
  broke the identity sync with `json: cannot unmarshal string into ... of
  type int`. The field now accepts both encodings, and the test stub emits
  the real string form.

## [0.1.3] - 2026-10-02

### Fixed

- The packaged charts resolve their default image tag to the released version:
  `helm package --app-version` stamps `.Chart.AppVersion`, which
  `charts/krot-control` and `charts/krot-agent` fall back to when `image.tag`
  is empty. The 0.1.2 packages resolve to the previous image
  (`krot-cp:0.1.1` / `krot-agent:0.1.1`) - use 0.1.3, or set `image.tag`
  explicitly on 0.1.2.

### Changed

- The release pipeline is one workflow and the publish job depends on every
  gate, so a red gate blocks the release instead of failing alongside it.
- `hack/release.sh` tags the commit below the release job's
  `chore(release): record <tag> [skip ci]` record commits and refuses to cut a
  tag from a commit carrying a workflow-skip token, because GitHub creates no
  run for such a push — the tag would silently release nothing.
- The gh-pages index is published with pinned chart-releaser
  (`--release-name-template 'release-{{ .Version }}'`) instead of the
  hand-rolled `helm repo index` step.

## [0.1.2] - 2026-10-02

### Added

- `KROT_TOKEN_NAMESPACE` on the control plane: the HMAC namespace prefix of
  derived subscription tokens, used verbatim and defaulting to `krot-sub:`.
  Setting `cheburnet-sub:` keeps subscription URLs issued by a pre-rename
  corporate instance valid byte-for-byte.

## [0.1.1] - 2026-09-25

### Added

- Zitadel as a second identity provider next to authentik, selected with
  `KROT_IDP`. Both sit behind the provider-agnostic `internal/directory`
  contract (`Source` plus the shared verdict cache and fail-open grace window),
  so a provider client carries no cache logic of its own.
- Public Happ routing routes, served without a login: `GET /routing` (landing
  page), `GET /routing.json` (the raw profile) and `GET /routing/import` (a
  `302` to the `happ://routing/onadd/...` deeplink, so a plain `https://` URL
  can be pasted into a phone). The profile is identical for every client and
  holds no per-user data, which is why it is public.
- `charts/krot-control` and `charts/krot-agent` carry a `values.schema.json`, so
  unknown keys and impossible values are rejected by `helm lint`,
  `helm template` and `helm install` instead of being silently ignored.

### Changed

- The project is `krot` throughout: Go module `github.com/Arsolitt/krot`, the
  `KROT_` environment prefix, binaries `krot-cp` and `krot-agent`, charts
  `krot-control` and `krot-agent`, images `ghcr.io/arsolitt/krot-*`.
- The subscription-token HMAC namespace is `krot-sub:`, which invalidates every
  previously issued subscription URL - expected, since the instance starts
  fresh.
- `users.authentik_uuid` is `users.subject` (migration `0002`), and the shared
  member type is `model.Member`. Migration `0002` is one-way for old binaries.
- `KROT_BASE_URL` and `KROT_CP_URL` are required: the corporate defaults are
  gone and the agent fails fast with `KROT_CP_URL is required`.
- The identity sync is provider-agnostic in its wording and its logs
  (`identity sync fetch failed`, `identity sync apply failed`,
  `identity sync done`), and the admin page heading is `Identity sync`.
- Releases are cut from a tag and nothing in the tree is bumped by hand: the
  tag is `release-<version>`, `hack/release.sh` is the only thing that creates
  one, the release job stamps the version into both packaged charts and `main`
  records it afterwards in a `chore(release): record <tag> [skip ci]` commit.
- CI runs on GitHub Actions only, with images published to GHCR. The GitLab
  pipeline is gone.

### Fixed

- The Happ routing profile carries its split-DNS resolvers under the keys Happ
  actually reads (`RemoteDNSIP`/`DomesticDNSIP`), so the domestic DoU resolver
  is no longer dropped from the profile.
- `charts/krot-control` renders no Ingress unless `ingress.enabled` is set, and
  the TLS block appears only when `ingress.tlsSecret` is non-empty.
- The release images are built for `linux/amd64` only: the arm64 leg ran under
  QEMU emulation and dominated the release wall-clock time.

## [0.1.0] - 2026-09-24

### Added

- Initial release: the krot control plane (`krot-cp`) with the templ+htmx
  portal, per-user Happ subscription links, the agent API and the identity sync
  goroutine over PostgreSQL, plus the node agent (`krot-agent`) that renders and
  supervises sing-box from the control plane's desired state.
- authentik as the identity provider, with the group membership gate on both
  the subscription endpoint and the admin page.
- `charts/krot-control` and `charts/krot-agent`, and a GitHub Actions pipeline
  that publishes both images to GHCR on a tag.
