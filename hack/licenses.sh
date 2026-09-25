#!/usr/bin/env bash
#
# Regenerate the third-party license bundle.
#
#   hack/licenses.sh
#
# Writes, from the working tree and the Go module cache alone - the go command
# fetches what the cache is missing, nothing here reaches the network itself:
#
#   licenses/README.md                  the index: one row per module
#   licenses/GPL-3.0.txt                the canonical GNU GPL v3.0 text
#   licenses/<path>@<version>/<files>   the license files of each module
#   charts/krot-control/LICENSE         verbatim copy of the root LICENSE
#   charts/krot-agent/LICENSE           verbatim copy of the root LICENSE
#
# The module set is exactly what `go list -deps` reports for the two released
# binaries on linux/amd64, the only platform they are built for: a module is in
# the bundle when a shipped binary links it, not when go.mod mentions it. The
# recorded identity is the resolved one - go.mod's replace directives point at
# forks (github.com/sagernet/* -> github.com/shtorm-7/*), the fork is the code
# that is compiled, so the fork's path and version are what the bundle is keyed
# by.
#
# GPL-3.0.txt is committed at hack/license-texts/GPL-3.0.txt: byte for byte the
# text published at <https://www.gnu.org/licenses/gpl-3.0.txt>, checked against
# the sha256 below on every run. It ships because the sing-ecosystem modules
# carry only short grant notices rather than the license text those notices
# refer to.
#
# The output is deterministic - same tree, same files - so the whole workflow is
# "run this after a dependency change and commit the result"; CI runs it and
# fails on `git diff`. A module with no license file is not an error: it is
# warned about here and listed as `none` in the index.
#
# Needs bash, go, find and sha256sum.
set -euo pipefail

# sha256 of the canonical GPL-3.0 text, i.e. of hack/license-texts/GPL-3.0.txt.
gpl3_sha256=3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986

# What hack/licenses.sh asks go list for, per module: the declared path and
# version, the directory that is actually built, and - when go.mod replaces the
# module with a fork - the replacement's path and version, which are the identity
# that ships. One line per module and binary, tab-separated, as go list is.
list_format='{{with .Module}}{{if .Dir}}{{.Path}}{{"\t"}}{{.Version}}{{"\t"}}{{.Dir}}{{"\t"}}{{if .Replace}}{{.Replace.Path}}{{"\t"}}{{.Replace.Version}}{{end}}{{end}}{{end}}'

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(dirname -- "$script_dir")"

die() {
    echo "licenses: $*" >&2
    exit 1
}

[ -f "$repo_root/go.mod" ] || die "$repo_root does not look like the krot repository (no go.mod)"
[ -f "$repo_root/LICENSE" ] || die "$repo_root/LICENSE is missing"
for target in krot-cp krot-agent; do
    [ -d "$repo_root/cmd/$target" ] || die "$repo_root/cmd/$target is missing"
done
for chart in krot-control krot-agent; do
    [ -d "$repo_root/charts/$chart" ] || die "$repo_root/charts/$chart is missing"
done
command -v go > /dev/null 2>&1 || die "go is not on PATH"

gpl3_src="$script_dir/license-texts/GPL-3.0.txt"
[ -f "$gpl3_src" ] || die "$gpl3_src is missing"
gpl3_actual="$(sha256sum "$gpl3_src" | cut -d ' ' -f 1)"
[ "$gpl3_actual" = "$gpl3_sha256" ] ||
    die "$gpl3_src is not the canonical GPL-3.0 text (sha256 $gpl3_actual, expected $gpl3_sha256)"

main_module="$(awk '$1 == "module" { print $2; exit }' "$repo_root/go.mod")"
[ -n "$main_module" ] || die "cannot read the module path from go.mod"

work="$(mktemp -d "${TMPDIR:-/tmp}/krot-licenses.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# 1. The shipped modules: what each released binary links, resolved through
#    go.mod's replace directives. The main module is the project itself and has
#    no third-party license to carry. The go list output is tab-separated - that
#    is its own format - while the files below are pipe-separated, so that a
#    module without a version leaves no empty field for `read` to collapse
#    (which it does for a tab, a whitespace delimiter).
: > "$work/deps.tsv"
for target in krot-cp krot-agent; do
    (cd "$repo_root" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go list -deps -f "$list_format" "./cmd/$target") |
        awk -F '\t' -v binary="$target" -v main="$main_module" '
            $3 == "" { next }   # no directory: not a module on disk
            $1 == main { next } # the project itself
            {
                path = ($4 == "" ? $1 : $4)
                version = ($4 == "" ? $2 : $5)
                ident = (version == "" ? path : path "@" version)
                printf "%s|%s|%s|%s|%s\n", ident, path, version, $3, binary
            }
        ' >> "$work/deps.tsv"
done
LC_ALL=C sort -u -o "$work/deps.tsv" "$work/deps.tsv"
[ -s "$work/deps.tsv" ] || die "go list reported no dependencies for ./cmd/krot-cp and ./cmd/krot-agent"

awk -F '[|]' '
    {
        ident = $1
        if (ident in module_dir && module_dir[ident] != $4) {
            printf "licenses: %s resolves to both %s and %s\n", ident, module_dir[ident], $4 > "/dev/stderr"
            failed = 1
            next
        }
        module_dir[ident] = $4
        module_path[ident] = $2
        module_version[ident] = $3
        if ($5 == "krot-cp") { linked_cp[ident] = 1 } else { linked_agent[ident] = 1 }
        seen[ident] = 1
    }
    END {
        if (failed) { exit 1 }
        for (ident in seen) {
            if (linked_cp[ident] && linked_agent[ident]) { binaries = "both" }
            else if (linked_cp[ident]) { binaries = "krot-cp" }
            else { binaries = "krot-agent" }
            printf "%s|%s|%s|%s|%s\n", ident, module_path[ident], module_version[ident], binaries, module_dir[ident]
        }
    }
' "$work/deps.tsv" | LC_ALL=C sort > "$work/modules.tsv"

# 2. One directory per module, holding the module's own license files verbatim.
#    Everything under licenses/ is generated, so the tree is rebuilt from scratch
#    rather than merged.
rm -rf "$repo_root/licenses"
mkdir -p "$repo_root/licenses"

module_count=0
file_count=0
: > "$work/missing"
: > "$work/rows.tsv"

while IFS='|' read -r ident module_path module_version binaries module_dir; do
    dest="$repo_root/licenses/$ident"
    mkdir -p "$dest"
    find "$module_dir" -maxdepth 1 -type f \( \
        -iname 'LICENSE*' -o -iname 'LICENCE*' -o -iname 'COPYING*' \
        -o -iname 'NOTICE*' -o -iname 'UNLICENSE*' -o -iname 'COPYRIGHT*' \
        \) -exec basename {} \; | LC_ALL=C sort -u > "$work/names"
    files=""
    while IFS= read -r name; do
        cp -p "$module_dir/$name" "$dest/$name"
        files="$files${files:+, }\`$name\`"
        file_count=$((file_count + 1))
    done < "$work/names"
    if [ -z "$files" ]; then
        files=none
        echo "$ident" >> "$work/missing"
    fi
    printf '%s|%s|%s|%s\n' "$module_path" "$module_version" "$binaries" "$files" >> "$work/rows.tsv"
    module_count=$((module_count + 1))
done < "$work/modules.tsv"

# 3. The index, the canonical GPL-3.0 text and the charts' LICENSE copies. The
#    index carries no timestamps and no environment data, so it regenerates
#    byte-identically.
{
    cat << 'EOF'
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
EOF

    while IFS='|' read -r module_path module_version binaries files; do
        [ -n "$module_version" ] || module_version='—'
        printf '| `%s` | `%s` | `%s` | %s |\n' "$module_path" "$module_version" "$binaries" "$files"
    done < "$work/rows.tsv"

    printf '\n%s modules, %s license files.\n' "$module_count" "$file_count"
} > "$repo_root/licenses/README.md"

cp -p "$gpl3_src" "$repo_root/licenses/GPL-3.0.txt"
cp -p "$repo_root/LICENSE" "$repo_root/charts/krot-control/LICENSE"
cp -p "$repo_root/LICENSE" "$repo_root/charts/krot-agent/LICENSE"
cmp -s "$repo_root/LICENSE" "$repo_root/charts/krot-control/LICENSE" ||
    die "charts/krot-control/LICENSE does not match LICENSE"
cmp -s "$repo_root/LICENSE" "$repo_root/charts/krot-agent/LICENSE" ||
    die "charts/krot-agent/LICENSE does not match LICENSE"

bundle_bytes="$(find "$repo_root/licenses" -type f -exec cat {} + | wc -c | tr -d ' ')"

echo "licenses: ${module_count} modules, ${file_count} license files, ${bundle_bytes} bytes in licenses/"
echo "licenses: copied LICENSE to charts/krot-control/LICENSE and charts/krot-agent/LICENSE"
if [ -s "$work/missing" ]; then
    while IFS= read -r ident; do
        echo "licenses: warning: ${ident} ships no license file (listed as none)" >&2
    done < "$work/missing"
fi
