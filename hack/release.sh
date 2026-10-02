#!/usr/bin/env bash
#
# Cut a release tag: the only way a release happens. The tag carries the
# version, so nothing in the repository is bumped by hand - the release job
# stamps it into the packaged charts (`helm package --version`) and records it in
# both `charts/*/Chart.yaml` on main afterwards.
#
#   hack/release.sh <version>            e.g. 0.2.0 or 0.2.0-rc.1
#   hack/release.sh --check <version>    validate only, print the release facts
#
# Two tracks, two shapes, nothing else - a version is either
#   <major>.<minor>.<patch>            the stable track
#   <major>.<minor>.<patch>-rc.<n>     the release candidate track
# and the track decides the rest: a candidate is a GitHub pre-release, it is
# never "Latest", and its release body is the `## [<major>.<minor>.<patch>]`
# section of CHANGELOG.md - write the section for the version you will ship,
# then cut candidates of it.
#
# The tag is `release-<version>`; <version> may carry that prefix
# (`release-0.2.0-rc.1`), so the release job can pass `$GITHUB_REF_NAME`
# straight through.
#
# --check prints, on stdout and only on success, the four facts the release job
# turns into step outputs (`key=value` lines, appended to `$GITHUB_OUTPUT`):
#
#   version=0.2.0-rc.1
#   channel=rc
#   section=0.2.0
#   tag=release-0.2.0-rc.1
#
# Checks, in order - each one exits before anything is created:
#   1. the version has one of the two shapes above;
#   2. CHANGELOG.md carries the section the release body comes from
#      (hack/release-notes.sh is the reader, so the rule the release job applies
#      is the rule this checks);
# and, in the releasing form only:
#   3. the working tree is clean;
#   4. HEAD is the tip of origin/main - the tag is cut from what main serves,
#      stepping past the release job's own record commit when that is the tip
#      (see "The commit the tag names" below);
#   5. the tag does not exist, locally or on origin;
#   6. the commit the tag will name carries no workflow-skip token - GitHub
#      creates no run at all for a push whose head commit carries one, and a tag
#      push is a push.
#
# The commit the tag names: a release pushes a record commit of its own to main
# last (`chore(release): record release-<version> [skip ci]` - bookkeeping, the
# version in `charts/*/Chart.yaml` and nothing else), written by the `release`
# job in `ci.yml`. So the tip a maintainer finds after a candidate is exactly
# the commit GitHub refuses to run a workflow for. A tag on it is a release that
# never happens, silently: no run, no failure, no release. The tag therefore
# names the commit below those record commits - the tree the release was cut
# from, which is also what makes a stable release of a candidate identical to
# the candidate. Any other commit that carries a skip token is refused rather
# than stepped over, since content below it would be left out of the release.
#
# Exit codes: 0 success; 1 a precondition failed; 2 usage or version shape.
#
# Needs bash and git.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(dirname -- "$script_dir")"

check=false
if [ "${1:-}" = "--check" ]; then
  check=true
  shift
fi

if [ "$#" -ne 1 ] || [ -z "${1:-}" ]; then
  echo "usage: hack/release.sh [--check] <version>   (e.g. 0.2.0, 0.2.0-rc.1 or release-0.2.0-rc.1)" >&2
  exit 2
fi

# The charts the release packages: every directory under charts/ with a
# Chart.yaml. The version is stamped into each of them, so a chart added later
# is released without touching this script.
chart_dirs=()
for candidate in "$repo_root"/charts/*/Chart.yaml; do
  [ -f "$candidate" ] || continue
  chart_dirs+=("$(dirname -- "$candidate")")
done
if [ "${#chart_dirs[@]}" -eq 0 ]; then
  echo "no chart metadata under ${repo_root}/charts/*/Chart.yaml: there is nothing to release" >&2
  exit 2
fi

arg="$1"
case "$arg" in
  release-*) version="${arg#release-}" ;;
  *) version="$arg" ;;
esac

if [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  channel=stable
  section="$version"
elif [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+$ ]]; then
  channel=rc
  section="${version%-rc.*}"
else
  echo "version '${version}' is neither '<major>.<minor>.<patch>' nor '<major>.<minor>.<patch>-rc.<n>': the stable track and the release candidate track are the only two this repository releases" >&2
  exit 2
fi

tag="release-${version}"

# The section is the release body: a missing one has to fail here, before a tag
# exists, not in the release job after the gates.
"$script_dir/release-notes.sh" "$version" "$section" > /dev/null

if [ "$check" = true ]; then
  printf 'version=%s\nchannel=%s\nsection=%s\ntag=%s\n' "$version" "$channel" "$section" "$tag"
  exit 0
fi

if [ -n "$(git -C "$repo_root" status --porcelain)" ]; then
  echo "the working tree has uncommitted changes - commit or stash them first, the tag has to name a commit main serves" >&2
  exit 1
fi

git -C "$repo_root" fetch --quiet origin main
# FETCH_HEAD rather than origin/main: the comparison must not depend on the
# remote-tracking ref being updated by a named-ref fetch.
if [ "$(git -C "$repo_root" rev-parse HEAD)" != "$(git -C "$repo_root" rev-parse FETCH_HEAD)" ]; then
  echo "HEAD is not the tip of origin/main - run 'git pull --ff-only' first, the tag is cut from what main serves" >&2
  exit 1
fi

if git -C "$repo_root" rev-parse --quiet --verify "refs/tags/${tag}" > /dev/null; then
  echo "tag ${tag} already exists locally" >&2
  exit 1
fi

if git -C "$repo_root" ls-remote --exit-code --quiet --tags origin "refs/tags/${tag}" > /dev/null; then
  echo "tag ${tag} already exists on origin" >&2
  exit 1
fi

# The commit the tag names: past the release job's own record commits, and never
# one that carries a workflow-skip token. Both are explained in the header -
# briefly, a tag on a `[skip ci]` commit releases nothing at all, because GitHub
# creates no run for a push whose head commit carries the token.
target="$(git -C "$repo_root" rev-parse HEAD)"
while [[ "$(git -C "$repo_root" show -s --format=%s "$target")" =~ ^chore\(release\):\ record\ release- ]]; do
  echo "stepping past $(git -C "$repo_root" rev-parse --short "$target") ($(git -C "$repo_root" show -s --format=%s "$target"))"
  parent="$(git -C "$repo_root" rev-parse --quiet --verify "${target}^")" || parent=""
  if [ -z "$parent" ]; then
    echo "every commit from HEAD back is a release record commit - there is nothing left to cut ${tag} from" >&2
    exit 1
  fi
  target="$parent"
done

if [[ "$(git -C "$repo_root" show -s --format=%B "$target")" =~ \[skip\ ci\]|\[ci\ skip\]|\[no\ ci\]|\[skip\ actions\]|\[actions\ skip\]|skip-checks: ]]; then
  echo "${tag} would name $(git -C "$repo_root" rev-parse --short "$target") ($(git -C "$repo_root" show -s --format=%s "$target")), which carries a workflow-skip token: GitHub creates no run for it, so the release would never happen" >&2
  echo "push a commit without the token and cut the tag again, or tag a commit that already has none" >&2
  exit 1
fi

git -C "$repo_root" tag "$tag" "$target"
git -C "$repo_root" push --quiet origin "refs/tags/${tag}"

echo "pushed ${tag} (${channel} track) at $(git -C "$repo_root" rev-parse --short "$target"); the release runs once the gates pass:"
echo "  gh run list --workflow=ci.yml --limit 1"
