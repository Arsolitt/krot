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

### Fixed

- The `gh-pages` chart index is generated with `helm repo index --merge`
  instead of chart-releaser: `cr index` v1.8.1 splits an asset name on the
  last dash, so a prerelease chart version (`0.2.0-rc.1`) never matched its
  already-indexed check, duplicating one chart of the release and dropping
  the other.

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
