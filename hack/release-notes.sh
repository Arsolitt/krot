#!/usr/bin/env bash
#
# Print the GitHub release body for one release: the `## [<section version>]`
# section of CHANGELOG.md, plus a compare link when the tags can be resolved.
#
# The `release` job in .github/workflows/release.yml runs this once per tag it
# has just published (`hack/release-notes.sh <version> <section version>`) and
# pipes the output into `gh release create --notes-file`; `hack/release.sh` runs
# it in `--check` mode, before a tag exists, because a missing section has to
# fail there rather than in the release job after the gates.
#
# The version and the section are two arguments because the two tracks read
# CHANGELOG.md differently: a stable release `0.2.0` publishes `## [0.2.0]`,
# while a candidate `0.2.0-rc.1` publishes the section of the version it is a
# candidate of, `## [0.2.0]` - the section is written once per version and the
# candidates of it share it.
#
# The section *is* the release body, which is what keeps the notes in the
# repository and the notes on the GitHub release from drifting apart: editing
# CHANGELOG.md is how release notes are written, nothing is generated from
# commit messages.
#
#   1. locate the section for <section version> - from the `## [<version>]`
#      heading up to (excluding) the next `## ` heading, with leading and
#      trailing blank lines trimmed. A version whose heading is absent exits
#      non-zero and prints nothing: the release job must go red, not publish a
#      release whose body silently stayed empty;
#   2. print the section;
#   3. append the `**Full Changelog**: <compare URL>` line when the repository,
#      the `release-<version>` tag and a previous `release-*` tag are all
#      resolvable. The previous tag follows the release's own track - a
#      candidate compares against the tag that preceded it, a stable release
#      against the previous stable one, so its compare range is the whole line
#      and not just what changed since the last candidate. That part is best
#      effort: any of them missing just means the section is printed alone,
#      still with exit 0.
#
# usage: hack/release-notes.sh <version> [<section-version>]   (e.g. 0.2.0, or
#                                              0.2.0-rc.1 0.2.0 for a candidate)
#        CHANGELOG_FILE=<path>                 (default: CHANGELOG.md at the repo root,
#                                               resolved from this script's own location
#                                               rather than from $PWD; set for tests)
#
# The tag prefix is `release-`, the same string `hack/release.sh` pushes and the
# release job attaches to.
#
# Needs bash and awk. Exits 0 with the body on stdout; 1 with a message on
# stderr and nothing on stdout when the section is missing; 2 on a usage error.
set -euo pipefail

# Repo root from this script's own location: the workflow calls the script from
# the checkout root, but a manual run should not depend on the caller's cwd.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(dirname -- "$script_dir")"

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ] || [ -z "$1" ]; then
  echo "usage: hack/release-notes.sh <version> [<section-version>]   (e.g. 0.2.0, or 0.2.0-rc.1 0.2.0 for a candidate)" >&2
  exit 2
fi
version="$1"
section_version="${2:-$1}"

changelog="${CHANGELOG_FILE:-$repo_root/CHANGELOG.md}"
if [ ! -f "$changelog" ]; then
  echo "no changelog file ${changelog}: it holds the release body for ${version}" >&2
  exit 1
fi

# The heading is matched by literal prefix rather than as a regex, so a version
# like `0.2.0` cannot match `0x2y0`; the character after the closing bracket has
# to be a space (the ` - <date>` separator) or the end of the line, so looking
# for `0.1.0` does not pick up a `0.1.0-rc1` heading above it.
section="$(
  awk -v version="$section_version" '
    BEGIN { prefix = "## [" version "]" }
    !in_section {
      if (index($0, prefix) == 1 && (length($0) == length(prefix) || substr($0, length(prefix) + 1, 1) == " ")) {
        in_section = 1
      }
      next
    }
    /^## / { exit }
    { body[count++] = $0 }
    END {
      if (!in_section) exit 1
      last = count
      while (last > 0 && body[last - 1] ~ /^[[:space:]]*$/) last--
      first = 0
      while (first < last && body[first] ~ /^[[:space:]]*$/) first++
      for (i = first; i < last; i++) print body[i]
    }
  ' "$changelog"
)" || {
  echo "no '## [${section_version}]' section in ${changelog}: add it before releasing ${version}, the GitHub release body is taken from it" >&2
  exit 1
}

if [ -n "$section" ]; then
  printf '%s\n' "$section"
fi

# Everything below is the compare link, which is a nicety and never a reason to
# fail: a missing remote, a checkout without tags or a repository that cannot be
# read each leave the body as the section alone.

# `owner/repo`, from the workflow's environment or from the checkout's origin.
# Both the scp-like and the URL forms of a GitHub remote are accepted.
repo="${GITHUB_REPOSITORY:-}"
if [ -z "$repo" ]; then
  remote="$(git -C "$repo_root" remote get-url origin 2>/dev/null || true)"
  case "$remote" in
    git@github.com:*) repo="${remote#git@github.com:}" ;;
    ssh://git@github.com/*) repo="${remote#ssh://git@github.com/}" ;;
    https://github.com/*) repo="${remote#https://github.com/}" ;;
    http://github.com/*) repo="${remote#http://github.com/}" ;;
    git://github.com/*) repo="${remote#git://github.com/}" ;;
    *) repo="" ;;
  esac
fi
repo="${repo%.git}"

# The tag, from the fixed prefix: a release tag is `release-<version>`, the same
# string `hack/release.sh` pushes and the release job attaches to.
tag="release-${version}"

# The previous release tag: the newest tag that is *older* than the released
# version, so the compare range is the step that release made. A candidate
# compares against whatever preceded it, a stable release against the previous
# *stable* one - its body is the whole section, not just what changed since the
# last candidate. The released tag itself is excluded whether or not it exists
# yet (the script also runs by hand before the tag is cut), and the comparison
# is by version rather than by list position, so a tag that sorts above the
# released one can never be picked as its predecessor.
skip_prereleases=1
case "$version" in
  *-*) skip_prereleases=0 ;;
esac
previous=""
if [ -n "$repo" ]; then
  if tags="$(git -C "$repo_root" tag --list 'release-*' 2>/dev/null)" && [ -n "$tags" ]; then
    previous="$(awk -v version="$version" -v prefix="release-" -v skip_pre="$skip_prereleases" '
      function older(a, b,   i, n, x, y) {
        # Version comparison on the numeric fields, with a release candidate
        # ranking below the release it is a candidate of.
        n = split(a, x, ".")
        split(b, y, ".")
        for (i = 1; i <= n; i++) {
          xa = x[i] + 0; ya = y[i] + 0
          if (xa != ya) return xa < ya
        }
        return 0
      }
      {
        candidate = $0
        sub("^" prefix, "", candidate)
        if (candidate == version) next
        if (skip_pre == 1 && candidate ~ /-/) next
        if (!older(candidate, version)) next
        if (best == "" || older(best, candidate)) best = candidate
      }
      END { if (best != "") print prefix best }
    ' <<<"$tags")"
  fi
fi

if [ -n "$previous" ]; then
  printf '\n**Full Changelog**: https://github.com/%s/compare/%s...%s\n' "$repo" "$previous" "$tag"
fi
