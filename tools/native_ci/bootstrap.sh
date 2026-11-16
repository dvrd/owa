#!/bin/sh
set -eu
umask 077
fail() { printf '%s\n' "OWA_BOOTSTRAP_$1" >&2; exit 2; }
for utility in jq curl tar shasum wc awk sed sort uniq cmp cut paste mkdir cp chmod mv date tr dirname uname head; do command -v "$utility" >/dev/null 2>&1 || fail DEPENDENCY_MISSING; done
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
pin=$here/pin.json
work=
assets=
platform=
while [ "$#" -gt 0 ]; do
 case $1 in
  --work|--assets-dir|--platform|--pin) [ "$#" -ge 2 ] || fail ARGUMENTS_INVALID; case $1 in --work) work=$2;; --assets-dir) assets=$2;; --platform) platform=$2;; --pin) pin=$2;; esac; shift 2;;
  *) fail ARGUMENTS_INVALID;;
 esac
done
case $work in /*) ;; *) fail WORK_PATH_INVALID;; esac
if [ -z "$platform" ]; then case $(uname -s)/$(uname -m) in Darwin/arm64) platform=macos-arm64;; Linux/x86_64) platform=linux-amd64;; *) fail PLATFORM_UNSUPPORTED;; esac; fi
case $platform in macos-arm64|linux-amd64) ;; *) fail PLATFORM_UNSUPPORTED;; esac
jq -e --arg platform "$platform" '
 def name: type=="string" and test("^[A-Za-z0-9._-]+$") and .!="." and .!="..";
 def record: type=="object" and (keys==["bytes","name","sha256"]) and (.name|name) and (.bytes|type=="number" and floor==. and .>0 and .<=2147483648) and (.sha256|type=="string" and test("^[0-9a-f]{64}$"));
 .schema==1 and .repository=="dvrd/owa" and (.release_tag|name) and (.platforms[$platform].top|name) and (.dependencies.top|name) and (.platforms[$platform].archive|record) and (.platforms[$platform].manifest|record) and (.dependencies.archive|record) and (.dependencies.manifest|record)
' "$pin" >/dev/null || fail OBJECT_PIN_INVALID
[ ! -e "$work" ] && [ ! -L "$work" ] || fail WORK_EXISTS
mkdir "$work" "$work/objects"
record() { jq -cer "$1" "$pin"; }
verify() (
 target=$1; expected=$2
 [ -f "$target" ] && [ ! -L "$target" ] || fail OBJECT_SIZE_OR_TYPE_MISMATCH
 [ "$(wc -c < "$target" | tr -d ' ')" = "$(printf '%s' "$expected" | jq -r .bytes)" ] || fail OBJECT_SIZE_OR_TYPE_MISMATCH
 [ "$(shasum -a 256 "$target" | cut -d ' ' -f1)" = "$(printf '%s' "$expected" | jq -r .sha256)" ] || fail OBJECT_HASH_MISMATCH
)
fetch() (
 expected=$1; name=$(printf '%s' "$expected" | jq -r .name); target=$work/objects/$name
 if [ -n "$assets" ]; then verify "$assets/$name" "$expected"; cp "$assets/$name" "$target"
 else
  tag=$(jq -r .release_tag "$pin"); url=https://github.com/dvrd/owa/releases/download/$tag/$name
  bytes=$(printf '%s' "$expected" | jq -r .bytes); hops=0
  while :; do
   case $url in https://github.com/*|https://release-assets.githubusercontent.com/*|https://objects.githubusercontent.com/*) ;; *) fail DOWNLOAD_REDIRECT_REFUSED;; esac
   code=$(curl --disable --proto '=https' --max-time 30 --max-filesize "$bytes" --silent --show-error --output "$target" --dump-header "$work/headers" --write-out '%{http_code}' "$url") || fail DOWNLOAD_FAILED
   case $code in 200) break;; 301|302|303|307|308) hops=$((hops+1)); [ "$hops" -le 5 ] || fail DOWNLOAD_BOUND_EXCEEDED; url=$(awk 'tolower($1)=="location:" {sub(/^[^:]*:[ \t]*/,"");sub(/\r$/,"");print}' "$work/headers");; *) fail DOWNLOAD_FAILED;; esac
  done
 fi
 verify "$target" "$expected"
 printf '%s\n' "$target"
)
install() (
 entry=$1; destination=$2
 expected_manifest=$(printf '%s' "$entry" | jq -c .manifest); expected_archive=$(printf '%s' "$entry" | jq -c .archive); top=$(printf '%s' "$entry" | jq -r .top)
 manifest=$(fetch "$expected_manifest"); archive=$(fetch "$expected_archive")
 [ "$(wc -c < "$manifest" | tr -d ' ')" -le 4194304 ] || fail MANIFEST_TOO_LARGE
 jq -e '
 def relative: type=="string" and length>0 and (contains("\\")|not) and (explode|all(.>=32 and .!=127)) and (startswith("/")|not) and (split("/")|all(.!="" and .!="." and .!=".."));
 (if type=="object" and keys==["files","packages"] then if (.packages|type)=="array" then .files else null end else . end) as $files |
 ($files|type)=="object" and ($files|length)>0 and ($files|length)<=50000 and
 ($files|to_entries|all((.key|relative) and (.value|type)=="object" and (.value|keys)==["bytes","sha256"] and (.value.bytes|type)=="number" and (.value.bytes|floor)==.value.bytes and .value.bytes>=0 and .value.bytes<=536870912 and (.value.sha256|type)=="string" and (.value.sha256|test("^[0-9a-f]{64}$")))) and ([$files[].bytes]|add)<=2147483648
 ' "$manifest" >/dev/null || fail MANIFEST_INVALID
 jq 'if keys==["files","packages"] then .files else . end' "$manifest" > "$work/expected.json"
 tar -tzf "$archive" > "$work/members" || fail ARCHIVE_INVALID
 tar -tvzf "$archive" > "$work/verbose" || fail ARCHIVE_INVALID
 case $(tar --version 2>/dev/null | head -1) in *bsdtar*) size_column=5;; *GNU*) size_column=3;; *) fail TAR_UNSUPPORTED;; esac
 awk -v column="$size_column" '{print substr($1,1,1),$1,$column}' "$work/verbose" > "$work/types"
 [ "$(wc -l < "$work/members" | tr -d ' ')" -le 100000 ] || fail ARCHIVE_TOO_MANY_MEMBERS
 [ "$(wc -l < "$work/members" | tr -d ' ')" = "$(wc -l < "$work/types" | tr -d ' ')" ] || fail ARCHIVE_INVALID
 sed 's:/$::' "$work/members" | sort | uniq -d > "$work/duplicates"; [ ! -s "$work/duplicates" ] || fail ARCHIVE_DUPLICATE_MEMBER
 paste "$work/types" "$work/members" > "$work/typed-members"
 jq -r --arg top "$top" 'keys[]|$top+"/"+.' "$work/expected.json" | sort > "$work/expected-members"
 : > "$work/seen-files"
 while IFS="$(printf '\t')" read -r type name; do
  kind=${type%% *}; rest=${type#* }; mode=${rest%% *}; size=${rest##* }
  case $name in "$top"|"$top/"|"$top/"*) ;; *) fail ARCHIVE_TOP_MISMATCH;; esac
  case $name in /*|*\\*|*'//'*) fail PATH_INVALID;; esac
  inner=${name#"$top"}; inner=${inner#/}; inner=${inner%/}
  case /$inner/ in */../*|*/./*) fail PATH_INVALID;; esac
  case $kind in
   d) [ -z "$inner" ] || jq -e --arg prefix "$inner/" 'keys|any(startswith($prefix))' "$work/expected.json" >/dev/null || fail ARCHIVE_DIRECTORY_UNEXPECTED;;
   -) case $mode in *s*|*S*|*t*|*T*) fail ARCHIVE_MEMBER_TYPE_INVALID;; esac; [ -n "$inner" ] || fail ARCHIVE_FILE_MISMATCH; [ "$size" = "$(jq -r --arg name "$inner" '.[$name].bytes // -1' "$work/expected.json")" ] || fail ARCHIVE_FILE_MISMATCH; printf '%s\n' "$name" >> "$work/seen-files";;
   *) fail ARCHIVE_MEMBER_TYPE_INVALID;;
  esac
 done < "$work/typed-members"
 sort "$work/seen-files" > "$work/seen-sorted"; cmp -s "$work/expected-members" "$work/seen-sorted" || fail ARCHIVE_FILES_MISSING
 mkdir "$destination"
 tar -xzf "$archive" -C "$destination" --strip-components=1 --no-same-owner --no-same-permissions || fail ARCHIVE_FILE_MISMATCH
 jq -r 'keys[]' "$work/expected.json" > "$work/file-names"
 while IFS= read -r name; do
  target=$destination/$name; mkdir -p "$(dirname -- "$target")"
  expected=$(jq -cer --arg name "$name" '.[$name]' "$work/expected.json"); verify "$target" "$expected"
  mode=$(awk -F '\t' -v name="$top/$name" '$2==name {print $1}' "$work/typed-members")
  case $mode in *x*) chmod 755 "$target";; *) chmod 644 "$target";; esac
 done < "$work/file-names"
)
sdk=$(record ".platforms[\"$platform\"]")
install "$sdk" "$work/sdk"
install "$(record '.dependencies')" "$work/sdk/shared"
printf '%s\n' "$work/sdk"
