#!/bin/sh
set -eu
umask 077
here=$(CDPATH= cd -- "$(dirname -- "$0")/../../../tools/native_ci" && pwd -P)
work=$(mktemp -d "${TMPDIR:-/tmp}/owa-bootstrap-fixtures.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
mkdir "$work/assets" "$work/sdk" "$work/dependencies"
printf '#!/bin/sh\nprintf compiler-fixture\\n\n' > "$work/sdk/odin"
chmod 755 "$work/sdk/odin"
mkdir "$work/dependencies/surf" "$work/dependencies/http"
printf 'package surf\n' > "$work/dependencies/surf/http.odin"
printf 'package http\n' > "$work/dependencies/http/http.odin"
record() { bytes=$(wc -c < "$1" | tr -d ' '); hash=$(shasum -a 256 "$1" | cut -d ' ' -f1); jq -cn --arg name "$(basename "$1")" --arg sha "$hash" --argjson bytes "$bytes" '{name:$name,bytes:$bytes,sha256:$sha}'; }
manifest() { root=$1; shift; for name do bytes=$(wc -c < "$root/$name" | tr -d ' '); hash=$(shasum -a256 "$root/$name" | cut -d ' ' -f1); jq -cn --arg name "$name" --arg sha "$hash" --argjson bytes "$bytes" '{key:$name,value:{bytes:$bytes,sha256:$sha}}'; done | jq -s from_entries; }
manifest "$work/sdk" odin > "$work/assets/sdk.json"
manifest "$work/dependencies" surf/http.odin http/http.odin > "$work/assets/dependencies.json"
(cd "$work" && tar -czf "$work/assets/sdk.tgz" sdk/odin && tar -czf "$work/assets/dependencies.tgz" dependencies/surf/http.odin dependencies/http/http.odin)
make_pin() {
 sdk_archive=$(record "$work/assets/sdk.tgz"); sdk_manifest=$(record "$work/assets/sdk.json"); deps_archive=$(record "$work/assets/dependencies.tgz"); deps_manifest=$(record "$work/assets/dependencies.json")
 jq -n --argjson sa "$sdk_archive" --argjson sm "$sdk_manifest" --argjson da "$deps_archive" --argjson dm "$deps_manifest" '{schema:1,repository:"dvrd/owa",release_tag:"offline-fixture",platforms:{"macos-arm64":{archive:$sa,manifest:$sm,top:"sdk"}},dependencies:{archive:$da,manifest:$dm,top:"dependencies"}}' > "$work/pin.json"
}
make_pin
"$here/bootstrap.sh" --pin "$work/pin.json" --platform macos-arm64 --assets-dir "$work/assets" --work "$work/good" > "$work/good.log"
cmp "$work/sdk/odin" "$work/good/sdk/odin"
cmp "$work/dependencies/http/http.odin" "$work/good/sdk/shared/http/http.odin"
[ -x "$work/good/sdk/odin" ]
# Hash mismatch, duplicate members, symlinks and traversal records must fail closed.
printf changed >> "$work/assets/sdk.tgz"
if "$here/bootstrap.sh" --pin "$work/pin.json" --platform macos-arm64 --assets-dir "$work/assets" --work "$work/hash" > "$work/hash.log" 2>&1; then exit 1; fi
(cd "$work" && tar -czf "$work/assets/sdk.tgz" sdk/odin sdk/odin)
make_pin
if "$here/bootstrap.sh" --pin "$work/pin.json" --platform macos-arm64 --assets-dir "$work/assets" --work "$work/duplicate" > "$work/duplicate.log" 2>&1; then exit 1; fi
ln -s odin "$work/sdk/link"
(cd "$work" && tar -czf "$work/assets/sdk.tgz" sdk/link)
make_pin
if "$here/bootstrap.sh" --pin "$work/pin.json" --platform macos-arm64 --assets-dir "$work/assets" --work "$work/symlink" > "$work/symlink.log" 2>&1; then exit 1; fi
jq '{"../outside":.odin}' "$work/assets/sdk.json" > "$work/bad-manifest"
mv "$work/bad-manifest" "$work/assets/sdk.json"
make_pin
if "$here/bootstrap.sh" --pin "$work/pin.json" --platform macos-arm64 --assets-dir "$work/assets" --work "$work/traversal" > "$work/traversal.log" 2>&1; then exit 1; fi
for pair in 'hash:OBJECT_SIZE_OR_TYPE_MISMATCH' 'duplicate:ARCHIVE_DUPLICATE_MEMBER' 'symlink:ARCHIVE_MEMBER_TYPE_INVALID' 'traversal:MANIFEST_INVALID'; do
 name=${pair%%:*}; reason=${pair#*:}
 case $(cat "$work/$name.log") in *"OWA_BOOTSTRAP_$reason"*) ;; *) printf '%s\n' "Missing expected bootstrap failure: $reason" >&2; exit 1;; esac
done
printf '%s\n' 'Bootstrap offline controls: PASS'
