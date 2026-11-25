#!/usr/bin/env bash
set -euo pipefail
umask 077
root=$(pwd -P)
compiler=$(command -v "${ODIN:-odin}")
pin=$(cat ODIN_VERSION)
version=$("$compiler" version)
revision=${version##*:}
[[ $revision =~ ^[0-9a-f]{7,40}$ && $pin == "$revision"* ]] || {
    echo "Odin $pin required, found $version" >&2
    exit 1
}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/consumer/.krs" "$work/sdk/shared"
if [[ -n ${OWA_LOCKED_SHARED:-} ]]; then
    for name in $(python3 -c 'import json; print(*(p["name"] for p in json.load(open(".krs/packages.json"))["packages"]))'); do
        cp -R "$OWA_LOCKED_SHARED/$name/." "$work/sdk/shared/$name"
    done
else
    cp .krs/packages.json "$work/consumer/.krs/"
    # Resolve only the dependencies. The test packages import owa itself.
    python3 - <<'PY' > "$work/consumer/main.odin"
import json
print("package consumer")
for dep in json.load(open(".krs/packages.json"))["packages"]:
    print(f'import "shared:{dep["name"]}"')
PY
    (cd "$work/consumer" && krs install --frozen --yes --root="$work/sdk")
fi
python3 tools/ci/verify-packages.py "$work/sdk/shared"
export WEBTOOLS_SHARED="$work/sdk/shared"
ln -s "$root/src" "$WEBTOOLS_SHARED/whatsapp"
task check 2>&1 | tee "$work/results"
"$compiler" check examples/private_audio "-collection:shared=$WEBTOOLS_SHARED" -no-entry-point -vet -warnings-as-errors
awk '/^Testing / { group = ($2 == "tests/unit" ? "Library" : ($2 == "tests/unit/protocol_watcher" ? "Watcher" : "E2E")) }
     /Finished [0-9]+ tests?/ { for (i=1;i<=NF;i++) if ($i == "Finished") count[group] += $(i+1) }
     END { for (g in count) print g, count[g]; print "Private audio example compiled" }' "$work/results" | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
