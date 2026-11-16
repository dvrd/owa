#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/odin-test-peer.XXXXXX")
child=
cleanup() {
    if [ -n "$child" ]; then
        kill "$child" 2>/dev/null || :
        wait "$child" 2>/dev/null || :
    fi
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT HUP
trap 'exit 143' TERM
run() {
    "$@" & child=$!
    status=0
    wait "$child" || status=$?
    child=
    return "$status"
}
run "${ODIN:-odin}" build "$root" -thread-count:1 -warnings-as-errors -out:"$work/peer"
run "$work/peer" "$@"
