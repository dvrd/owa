#!/usr/bin/env bash
# Stage private tests without exposing library internals or modifying the checkout.
set -euo pipefail
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
compiler=${ODIN:-odin}
selected=all
internal_only=false
while (($#)); do
    case "$1" in
        --odin) compiler=$2; shift 2 ;;
        --package) selected=$2; shift 2 ;;
        --internal-only) internal_only=true; shift ;;
        --) shift; break ;;
        --help|-h) printf 'Usage: %s [--odin PATH] [--package PATH] [--internal-only] -- [Odin flags]\n' "$0"; exit ;;
        *) break ;;
    esac
done
library_root=$root
if [[ -e "$root/.git" ]]; then
    common=$(git -C "$root" rev-parse --git-common-dir)
    [[ "$common" == /* ]] || common=$root/$common
    library_root=$(CDPATH='' cd -- "$(dirname -- "$common")" && pwd -P)
fi
library=$(basename -- "$library_root")
source_shared=$(dirname -- "$library_root")
[[ "$library" != async || "$selected" != async ]] || selected=.
compiler=$(command -v "$compiler" || printf '%s' "$compiler")
compiler=$(CDPATH='' cd -- "$(dirname -- "$compiler")" && printf '%s/%s' "$PWD" "$(basename -- "$compiler")")
work=$(mktemp -d "${TMPDIR:-/tmp}/odin-library-tests.XXXXXX")
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
shared=$work/shared
mkdir -p "$shared"
: > "$work/suites"
while IFS= read -r directory; do
    relative=${directory#"$root"/}
    private=false
    case "$relative" in
        tests/internal) owner=.; private=true ;;
        */tests/internal) owner=${relative%/tests/internal}; private=true ;;
        */*) owner=${relative%/*} ;;
        *) owner=. ;;
    esac
    if [[ "$library" == async ]]; then
        case "$owner" in .|connection|offload|signal) ;; *) continue ;; esac
    fi
    [[ "$selected" == all || "$selected" == "$owner" ]] || continue
    [[ "$internal_only" == false || "$private" == true ]] || continue
    printf '%s\t%s\n' "$relative" "$private" >> "$work/suites"
done < <(find "$root" -type d \( -name .git -o -name __pycache__ \) -prune -o -type f -name '*_test.odin' -exec dirname {} \; | sort -u)
[[ -s "$work/suites" ]] || { printf 'No matching test suites\n' >&2; exit 2; }
for source in "$source_shared"/*; do
    [[ -d "$source" ]] || continue
    name=$(basename -- "$source")
    [[ "$name" != metalized ]] || continue
    [[ "$name" != "$library" ]] || source=$root
    if [[ -e "$root/.git" && ! -e "$source/.git" ]]; then continue; fi
    mkdir -p "$shared/$name"
    if [[ -e "$source/.git" ]]; then
        while IFS= read -r -d '' path; do
            [[ ! -f "$source/$path" ]] || printf '%s\0' "$path"
        done < <(git -C "$source" ls-files --cached --others --exclude-standard -z) > "$work/files"
    else
        (cd "$source" && find . -type d \( -name .git -o -name __pycache__ -o -name '.*' ! -name . \) -prune -o -type f ! -name '.*' -print0) > "$work/files"
    fi
    (cd "$source" && tar --null -T "$work/files" -cf -) | (cd "$shared/$name" && tar -xf -)
done
sdk=$("$compiler" root)
for collection in base core vendor; do ln -s "$sdk/$collection" "$work/$collection"; done
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
staged=$shared/$library
while IFS= read -r directory; do
    target=$(dirname -- "$(dirname -- "$directory")")
    for file in "$directory"/*.odin; do [[ ! -f "$file" ]] || cp "$file" "$target/"; done
done < <(find "$shared" -type d -path "*/tests/internal" | sort)
set -m
cd "$shared"
while IFS=$'\t' read -r relative private; do
    target=$staged/$relative
    if [[ "$private" == true ]]; then target=${target%/tests/internal}; fi
    printf 'Testing %s\n' "$relative"
    "$compiler" test "$target" "${flags[@]}" </dev/null & child=$!
    (sleep 300; printf 'Test timeout: %s\n' "$relative" >&2; kill -TERM -- "-$child" 2>/dev/null || :; sleep 5; kill -KILL -- "-$child" 2>/dev/null || :) & timer=$!
    status=0
    wait "$child" || status=$?
    child=''

    kill -TERM -- "-$timer" 2>/dev/null || :
    wait "$timer" 2>/dev/null || :
    child='' timer=''
    [[ "$status" == 0 ]] || exit "$status"
done < "$work/suites"
