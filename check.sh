#!/bin/sh
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
exec bash "$root/tests/run.sh" --odin "${ODIN:-odin}" -- "$@"
