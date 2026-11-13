# Immutable native OWA CI

This gate builds and executes OWA on native Ubuntu24.04 amd64 and macOS15 arm64.
Both ASan and TSan must first build **and execute** an empty program. Then the
gate runs the native WhatsApp package tests, qualification-tool tests, synthetic
TCP/WebSocket/Noise fixture, disposable SIGKILL/recovery campaign and a small
public API consumer. This is OWA validation, not full Webtools/Mesa certification
or live WhatsApp qualification. The Noise wire fixture explicitly uses its
legacy synthetic certificate hook; strict genuine-certificate tests are separate
native unit cases. No account, provider credentials or external messages are used.

`pin.json` binds the existing frontend compiler/version, modified Core source,
platform runtime archives and every dependency file. The archive/manifests are
verified by exact byte count and SHA256 before extraction; extracted trees are
verified file by file. Traversal, links, duplicate members, unexpected/missing
files, changed cache objects and unsupported hosts fail rather than rebaseline.
Only public GitHub release URLs are downloaded, with HTTPS host-limited redirects.

The dependency archive contains eleven sibling packages from five owning repos:
ascii, async, http, surf and websocket. Their committed source hashes/revisions
and existing notices are retained in `provenance.json`. OWA itself comes from
the actual checkout. Native inputs, compiler identity, copied/original source
guards, commands and bounded logs are retained as artifacts for30 days. The
recovery campaign uses an external scorecard instead of changing its tracked TSV.

## Prepare publication locally

```sh
python3 tools/native_ci/prepare.py --mesa-root "$MESA_ROOT" \
  --shared-root "$SHARED_ROOT" --output "$NEW_ASSET_DIRECTORY" \
  --release-tag native-sdk-2e8d3048-v1
```

This writes eight objects and `publication-review.json`, plus the committed pin.
It never uploads, creates a release, commits or pushes. Review the exact contents,
hashes, provenance and notices before publishing only the eight objects named in
the review document to the declared OWA release. Do not upload that review file
or the original full source archive. The filtered compiler/Core source archive
excludes parent reports, shared guidance, Git metadata and private application
paths; compiler/build files, standard/vendor source, tests and notices remain.
The source export preserves the original committed bytes; it does not promise
bit-identical rebuilding across unpinned hosts/toolchains.

## Execute

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s tools/native_ci -p 'test_*.py' -v
python3 tools/native_ci/run.py --work "$NEW_WORK_DIRECTORY" \
  --evidence "$NEW_EVIDENCE_DIRECTORY"
```

Work/evidence directories must be fresh, external and separate. CI requires a
clean committed checkout and the matching real host. For explicit local candidate
validation add `--allow-local --allow-dirty --assets-dir "$NEW_ASSET_DIRECTORY"`;
the report records that scope/dirty status and still rejects changing source.
Set `OWA_NATIVE_CLANG` to the explicit upstream Clang executable (LLVM22 on
macOS, Ubuntu Clang18 on Linux). The gate controls the effective `clang` PATH,
records ambient/selected versions and byte identities, hashes both sanitizer
runtimes and checks they stay unchanged. macOS additionally verifies the LLVM
ASan ABI symbol and actual loaded ASan/TSan dylib paths during empty execution.
Apple Clang's vendor ASan ABI is incompatible with this LLVM22 compiler's
`__asan_version_mismatch_check_v8`; implicit CLT selection is refused.

Local execution is not a hosted CI pass. `--sanitizers address` can select one
debugging leg; the maintained workflow always requires both.

Public runner labels are pinned by OS rather than `latest`; actual architecture
and Ubuntu release are checked at runtime. Linux installs the explicit Clang18
sanitizer runtime and the shared libraries required by bundled LLVM22. macOS
uses explicit upstream LLVM22 and the bundled compiler LLVM/zstd dylibs. Every child has a
finite timeout and16MiB log cap. No OpenAI key or Linear secret is passed to
native test children. Failures retain a failing qualification/checksum report.

Each sanitizer also runs the offline same-format cross-commit compatibility
check. Checkout fetches history containing pinned producer
`fa2734f60b60cc9770809bb1be873cea60fe3c12`. The copied fixture has no `.git`;
the gate passes `--repository` pointing to the original read-only checkout,
`--current-revision` containing its exact captured commit SHA, and the already
verified local SDK objects directory. The child performs no downloads or account
calls. Normal producer/consumer exits and byte-identical old state/prekey files
are required. `compatibility-*.json` receipts bind both runtime owners and are
included with existing source-bound evidence. Manual invocation keeps its explicit
`1d5160f384d3055eef314557c31c912bea5ce557` consumer default; CI supplies its own
exact checkout commit. This adds same-format compatibility, not schema migration
or full-stack upgrade certification.
