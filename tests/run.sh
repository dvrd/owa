#!/usr/bin/env bash
# Run the tests of a library in the src/ layout without modifying the checkout.
# The library's own src/ provides its shared:<name> self-imports; every other
# shared:<dependency> comes from the shared collection (the imported copies).
set -euo pipefail
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
compiler=${ODIN:-odin}
dependency_source=${WEBTOOLS_SHARED:-$HOME/dev/oss/Odin/shared}
selected=all
internal_only=false
while (($#)); do
    case "$1" in
        --odin) compiler=$2; shift 2 ;;
        --shared) dependency_source=$2; shift 2 ;;
        --package) selected=$2; shift 2 ;;
        --internal-only) internal_only=true; shift ;;
        --) shift; break ;;
        --help|-h) printf 'Usage: %s [--odin PATH] [--shared DIR] [--package PATH] [--internal-only] -- [Odin flags]\n' "$0"; exit ;;
        *) break ;;
    esac
done
for argument do
    case "$argument" in -collection:shared=*) dependency_source=${argument#-collection:shared=} ;; esac
done
[[ -d "$root/src" ]] || { printf 'No src/ in %s\n' "$root" >&2; exit 2; }
[[ -d "$dependency_source" ]] || { printf 'No shared collection at %s\n' "$dependency_source" >&2; exit 2; }
dependency_source=$(CDPATH='' cd -- "$dependency_source" && pwd -P)
library_root=$root
if [[ -e "$root/.git" ]]; then
    common=$(git -C "$root" rev-parse --git-common-dir)
    [[ "$common" == /* ]] || common=$root/$common
    library_root=$(CDPATH='' cd -- "$(dirname -- "$common")" && pwd -P)
fi
library=$(basename -- "$library_root")
compiler=$(command -v "$compiler" || printf '%s' "$compiler")
compiler=$(CDPATH='' cd -- "$(dirname -- "$compiler")" && printf '%s/%s' "$PWD" "$(basename -- "$compiler")")
work=$(mktemp -d "${TMPDIR:-/tmp}/odin-library-tests.XXXXXX")
work=$(CDPATH='' cd -- "$work" && pwd -P)
child='' timer=''
cleanup() {
    trap - EXIT
    for pid in "$child" "$timer"; do
        [[ -z "$pid" ]] || { kill -TERM -- "-$pid" 2>/dev/null || :; kill -KILL -- "-$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; }
    done
    rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM

# Suites: every directory under tests/ holding a *_test.odin file.
: > "$work/suites"
while IFS= read -r directory; do
    relative=${directory#"$root"/}
    private=false
    case "$relative" in
        tests/internal) owner=.; private=true ;;
        tests/*/internal) owner=${relative#tests/}; owner=${owner%/internal}; private=true ;;
        tests) owner=. ;;
        tests/*) owner=${relative#tests/} ;;
        *) continue ;;
    esac
    [[ "$selected" == all || "$selected" == "$owner" ]] || continue
    [[ "$internal_only" == false || "$private" == true ]] || continue
    printf '%s\t%s\n' "$relative" "$private" >> "$work/suites"
done < <(find "$root/tests" -type d \( -name .git -o -name __pycache__ \) -prune -o -type f -name '*_test.odin' -exec dirname {} \; | sort -u)
[[ -s "$work/suites" ]] || { printf 'No matching test suites\n' >&2; exit 2; }

# copy_tree SOURCE TARGET: tracked and untracked unignored files of a Git
# checkout, or every non-hidden file of a plain directory (an imported copy).
copy_tree() {
    local source=$1 target=$2
    mkdir -p "$target"
    if [[ -e "$source/.git" ]]; then
        while IFS= read -r -d '' path; do
            [[ ! -f "$source/$path" ]] || printf '%s\0' "$path"
        done < <(git -C "$source" ls-files --cached --others --exclude-standard -z) > "$work/files"
    else
        (cd "$source" && find . -type d \( -name .git -o -name __pycache__ -o -name '.*' ! -name . \) -prune -o -type f ! -name '.*' -print0) > "$work/files"
    fi
    (cd "$source" && tar --null -T "$work/files" -cf -) | (cd "$target" && tar -xf -)
}

# Stage the repository with its geometry intact (src/ beside tests/), so paths
# relative to tests/<package>/ resolve as they do in the checkout.
repository=$work/repository
copy_tree "$root" "$repository"
shared=$work/shared
mkdir -p "$shared"
ln -s "$repository/src" "$shared/$library"

# Dependencies: transitive closure of literal shared:<name> imports, taken from
# the shared collection. The library itself always resolves to its own src/.
imports_of() {
    { grep -rhoE '"shared:[A-Za-z0-9_]+' --include='*.odin' "$@" 2>/dev/null || :; } | sed 's/^"shared://' | sort -u
}

# normalize PATH: absolute path with . and .. segments removed lexically.
normalize() {
    local IFS=/ part
    local -a out=()
    set -f
    for part in $1; do
        case "$part" in
            ''|.) ;;
            ..) ((${#out[@]} == 0)) || unset 'out[${#out[@]}-1]' ;;
            *) out+=("$part") ;;
        esac
    done
    set +f
    printf '/%s' "${out[@]}"
    printf '\n'
}

# escaping_imports TREE [SCAN]: "file<TAB>resolved" for each relative import in
# SCAN (default TREE) whose target lies outside TREE (old-layout libraries
# import siblings as "../surf").
escaping_imports() {
    local tree=$1 scan=${2:-$1} location file path resolved
    while IFS= read -r location; do
        file=${location%%:*}
        path=${location#*\"}
        path=${path%\"}
        resolved=$(normalize "$(dirname -- "$file")/$path")
        [[ "$resolved" == "$tree" || "$resolved" == "$tree"/* ]] || printf '%s\t%s\n' "$file" "$resolved"
    done < <(grep -roE --include='*.odin' -H 'import( +[A-Za-z0-9_]+)? +"\.\.?/[^"]*"' "$scan" 2>/dev/null || :)
}

# The library's own sources must reach other libraries through shared:<name>.
escapes=$(escaping_imports "$repository/src"; escaping_imports "$repository" "$repository/tests")
if [[ -n "$escapes" ]]; then
    printf 'Relative imports leave the repository; use shared:<library> instead:\n%s\n' "${escapes//$repository\//}" >&2
    exit 2
fi
# The compiler's own packages may import shared:<name> too (core:net/quic
# imports shared:async); those dependencies are staged as well.
sdk=$("$compiler" root)
sdk_imports=$({ grep -rhoE '"shared:[A-Za-z0-9_]+' --include='*.odin' --exclude='*_test.odin' --exclude-dir=tests "$sdk/core" "$sdk/vendor" 2>/dev/null || :; } | sed 's/^"shared://' | sort -u)
pending="$(imports_of "$repository/src" "$repository/tests") $sdk_imports"
seen=" $library "
while [[ -n "$pending" ]]; do
    next=''
    for name in $pending; do
        [[ "$seen" != *" $name "* ]] || continue
        seen="$seen$name "
        [[ -d "$dependency_source/$name" ]] || { printf 'Missing dependency shared:%s in %s\n' "$name" "$dependency_source" >&2; exit 2; }
        copy_tree "$dependency_source/$name" "$shared/$name"
        next="$next $(imports_of "$shared/$name")"
        while IFS=$'\t' read -r _ resolved; do
            [[ "$resolved" == "$shared"/* ]] || { printf 'shared:%s imports outside the collection: %s\n' "$name" "$resolved" >&2; exit 2; }
            resolved=${resolved#"$shared"/}
            next="$next ${resolved%%/*}"
        done < <(escaping_imports "$shared/$name")
    done
    pending=$next
done
printf 'Library %s from %s/src; dependencies from %s:%s\n' "$library" "$root" "$dependency_source" "${seen# $library}"

# Private tests: tests/internal into src/, tests/<package>/internal into src/<package>/.
while IFS= read -r directory; do
    package=${directory#"$repository"/tests}
    package=${package%internal}
    package=${package#/}
    package=${package%/}
    target=$repository/src${package:+/$package}
    # A package outside src/ (tools/<name>: not part of the library API) is staged in place.
    [[ -d "$target" || -z "$package" || ! -d "$repository/$package" ]] || target=$repository/$package
    [[ -d "$target" ]] || { printf 'Private tests %s have no package %s\n' "${directory#"$repository"/}" "src/$package" >&2; exit 2; }
    for file in "$directory"/*.odin; do
        [[ ! -f "$file" ]] || cp "$file" "$target/"
    done
done < <(find "$repository/tests" -type d \( -path "$repository/tests/internal" -o -path "$repository/tests/*/internal" \) | sort)

# Harnesses that invoke $ODIN see the staged collection.
for collection in base core vendor; do
    ln -s "$sdk/$collection" "$work/$collection"
done
{
    printf '#!/usr/bin/env bash\nset -euo pipefail\ncompiler=%q\nstaged_root=%q\n' "$compiler" "$work"
    cat <<'WRAPPER'
if [[ "$*" == root && $# == 1 ]]; then printf '%s\n' "$staged_root"; exit; fi
args=()
for argument do
    case "$argument" in -collection:shared=*) ;; *) args+=("$argument") ;; esac
done
if [[ "${args[0]:-}" != version ]]; then args+=("-collection:shared=$staged_root/shared"); fi
exec "$compiler" "${args[@]}"
WRAPPER
} > "$work/odin"
chmod +x "$work/odin"
export ODIN=$work/odin
flags=("-collection:shared=$shared")
has_output=false
for argument do
    case "$argument" in
        -collection:shared=*) ;;
        -out:*) has_output=true; flags+=("$argument") ;;
        *) flags+=("$argument") ;;
    esac
done
[[ "$has_output" == true ]] || flags+=("-out:$work/tests")

set -m
cd "$repository"
while IFS=$'\t' read -r relative private; do
    target=$repository/$relative
    if [[ "$private" == true ]]; then
        package=${relative#tests}
        package=${package%internal}
        package=${package#/}
        package=${package%/}
        target=$repository/src${package:+/$package}
        [[ -d "$target" || -z "$package" || ! -d "$repository/$package" ]] || target=$repository/$package
    fi
    printf 'Testing %s\n' "$relative"
    "$compiler" test "$target" "${flags[@]}" </dev/null & child=$!
    (sleep 300; printf 'Test timeout: %s\n' "$relative" >&2; kill -TERM -- "-$child" 2>/dev/null || :; sleep 5; kill -KILL -- "-$child" 2>/dev/null || :) & timer=$!
    status=0
    wait "$child" || status=$?
    child=''
    kill -TERM -- "-$timer" 2>/dev/null || :
    wait "$timer" 2>/dev/null || :
    timer=''
    [[ "$status" == 0 ]] || exit "$status"
done < "$work/suites"
