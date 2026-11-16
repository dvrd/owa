#!/bin/sh
set -eu
umask 077
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
mode=${1-}
[ "$#" -gt 0 ] || { printf '%s\n' 'PROTOCOL_COMMAND_REQUIRED' >&2; exit 2; }
shift
odin=${OWA_ODIN_BIN-odin}
shared=${OWA_SHARED_ROOT-}
binary=
while [ "$#" -gt 0 ]; do
 case $1 in
  --odin|--shared-root|--binary) [ "$#" -ge 2 ] || exit 2; case $1 in --odin) odin=$2;; --shared-root) shared=$2;; --binary) binary=$2;; esac; shift 2;;
  *) break;;
 esac
done
if [ -z "$shared" ]; then shared=$(CDPATH= cd -- "$here/../../.." && pwd -P); fi
[ -x "$odin" ] || command -v "$odin" >/dev/null 2>&1 || { printf '%s\n' 'ODIN_COMPILER_REQUIRED' >&2; exit 2; }
[ -d "$shared/surf" ] && [ -d "$shared/http" ] || { printf '%s\n' 'SHARED_DEPENDENCIES_REQUIRED' >&2; exit 2; }
case $mode in
 test)
  [ "$#" -eq 0 ] || exit 2
  work=$(mktemp -d "${TMPDIR:-/tmp}/owa-protocol-tests.XXXXXX")
  trap 'rm -rf "$work"' EXIT HUP INT TERM
  "$odin" test "$here/tests" "-collection:shared=$shared" -thread-count:1 -vet -warnings-as-errors -define:ODIN_TEST_THREADS=1 -define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true "-out:$work/tests"
  ;;
 build|watch|ci|linear|promotion|schedule)
  if [ -z "$binary" ]; then
   [ "$mode" != build ] || { printf '%s\n' 'BUILD_BINARY_PATH_REQUIRED' >&2; exit 2; }
   work=$(mktemp -d "${TMPDIR:-/tmp}/owa-protocol-command.XXXXXX")
   trap 'rm -rf "$work"' EXIT HUP INT TERM
   binary=$work/protocol-watch
  fi
  "$odin" build "$here/cmd" "-collection:shared=$shared" -thread-count:1 -vet -warnings-as-errors "-out:$binary"
  if [ "$mode" != build ]; then "$binary" "$mode" "$@"; fi
  ;;
 *) printf '%s\n' 'PROTOCOL_COMMAND_INVALID' >&2; exit 2;;
esac
