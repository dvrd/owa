#!/bin/sh
# ODIN selects the compiler; WEBTOOLS_SHARED or -collection:shared=DIR selects
# the shared collection that provides dependencies; remaining arguments apply
# to every test suite.
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
exec bash "$root/tests/run.sh" --odin "${ODIN:-odin}" -- "$@"
