# Offline Linux canary bundle and first-install preflight

This phase packages reviewed public inputs and produces a **read-only dry-run
plan**. It implements no installation, rollback execution, account creation,
unit writes, activation, uploads, pairing or sends. The next phase must implement
and validate the privileged apply transaction and ownership receipt before host
installation can be proposed. A successful plan is not installation approval.

## Exact public inputs

Use an independently reviewed hosted Linux-amd64 `native-owa-ubuntu-24.04`
artifact that contains the new `owa-live-linux-amd64` executable. Older native
CI evidence without that executable cannot be substituted. Supply its exact
runtime commit, run ID, report SHA256 and binary SHA256 from the independent
review, not values guessed from moving HEAD or self-generated fixture metadata.
The report and binary digest arguments are explicit trust anchors; offline
packaging does not authenticate GitHub or establish who produced those anchors.

The packer checks the artifact's full top-level checksum inventory, command log
hashes/exits, both native sanitizer gate sets, unchanged checkout/SDK/runner/
linker flags, compiler/Core/dependency pin identities, every reported runtime
checkout file against its exact local Git blob, and the binary's source binding.
It inspects the existing public ELF loader report, requiring Linux-amd64,
`/lib64/ld-linux-x86-64.so.2`, GLIBC at most2.39 and only the reviewed standard
shared-library names. It never executes the supplied binary. The original CI
report remains in the bundle for inspection; this phase does not reconstruct
all SDK source files or replace independent review of the hosted campaign.

Only these public helper source files are exported from an exact local Git
commit, each with its own Git blob ID, SHA256 and byte count:

- `tools/reliability/supervisor.py`
- `tools/reliability/progress.py`
- `tools/reliability/finish_soak.py`
- `tools/reliability/periodic_canary.py`
- `tools/reliability/systemd_canary.py`
- `tools/live_qualification/qr_display.py`

The QR helper is public source code, not pairing/QR payload data. Helper source
and compiled-runtime commits are recorded separately and may differ; a newer
helper revision does not relabel the native binary's provenance. `finish_soak`
is included for its metadata evaluator dependency; its separate API-writing
entry point must not be invoked by deployment or the scheduled service.

Alongside those six files, the bundle contains only the native executable,
original qualification report and loader report. A SHA256/byte/mode manifest
covers that exact inventory, and its deterministic release ID binds both source
revisions and every packaged component. Extra files, directories, symlinks,
hard-linked files and modifications are rejected by verification. No auth,
session, operational config, QR image/token, keys, private reports or credentials
are selected. No directory/archive discovery or extraction is used.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/deployment/bundle.py pack \
  --repository /ABSOLUTE/PUBLIC/owa \
  --runtime-revision "$EXACT_REVIEWED_RUNTIME_COMMIT" \
  --helper-revision "$EXACT_REVIEWED_HELPER_COMMIT" \
  --expected-run-id "$REVIEWED_CI_RUN" \
  --expected-report-sha256 "$REVIEWED_QUALIFICATION_SHA256" \
  --expected-binary-sha256 "$REVIEWED_BINARY_SHA256" \
  --artifact-dir /private/tmp/REVIEWED_LINUX_ARTIFACT \
  --output /private/tmp/FRESH_PRIVATE_OWA_BUNDLE
```

The output must not already exist. It is private0700; the manifest is0600,
public helper/evidence files0444 and the binary0555. The retained original
public report may contain public CI paths and synthetic loopback evidence; it
must not be replaced with a private live qualification receipt. A write failure
may leave an incomplete private output, which verification refuses; it never
overlays or silently repairs an existing bundle. Never use `/tmp` or a broad
workspace as a build context. No container image build is part of this tool.

## First-install dry-run gates

`plan` is read-only and requires root, Linux x86_64, exactly glibc2.39,
Ubuntu24.04 and a mandatory independently reviewed expected instance ID matched to the local
cloud-init metadata file. It makes no metadata-service or AWS call. It verifies
an independently reviewed bundle-manifest digest and refuses existing `owa`
entries in local passwd/group, any `/opt/owa` or `/var/lib/owa` resource, any of
the three proposed units in persistent/runtime/vendor unit directories, unsafe
path ancestors or a missing expected loader. Ubuntu's regular
`/usr/lib/os-release` is used instead of following its usual `/etc` symlink.
No systemd or application process is invoked by the plan. Actual private instance
identifiers are never embedded in public source or the runtime bundle.

```sh
# Future approved host preflight, not an installation or a command run by this phase:
python3 /REVIEWED/bundle.py plan \
  --bundle /REVIEWED/PRIVATE/BUNDLE \
  --expected-manifest-sha256 "$INDEPENDENTLY_REVIEWED_MANIFEST_SHA256" \
  --expected-instance-id "$INDEPENDENTLY_REVIEWED_STAGING_INSTANCE"
```

`--host-root` supports synthetic filesystem fixtures; it does not bypass actual
root/Linux/architecture/libc gates. Tests inject those platform probes only in
Python. The proposed layout is root-owned immutable
`/opt/owa/releases/<manifest-bound-release>` plus distinct owa-owned0700
`/var/lib/owa/{auth-linux,primary,primary-proof,periodic,controller}`. No mutable
`current` link, inherited Mac session, default operational config or automatic
unit generation is created. Unit settings, scope, binary digest, independently
paired Linux identity and recipient confirmation require their own review.

The future apply transaction must recheck account existence through NSS and all
filesystem/unit gates immediately before each exclusive creation; a saved plan
is not a lock. It must persist an exact ownership receipt for every created
resource and never overwrite an existing object. Future first-install rollback
may stop/disable only receipt-owned units whose digests still match, on this
exact host/release. It must retain auth/session/key/journal/qualification state
and the immutable release for investigation. This phase records that rollback
plan and explicitly labels its executor **unimplemented**. It must not stop
Mesa services, use wildcard/PID-based cleanup, erase state, or uninstall another
operator's resource.

## Pairing, delivery and rollout remain separate

The existing artifact-bucket/SSM delivery design is not implemented or invoked.
A future reviewed delivery must verify the independent manifest digest before
exclusive extraction/copy, use existing narrowly scoped access and avoid
shell/stdout interpolation of any private data. No new AWS grants are implied.

Pair independently on Linux after installation approval. Do not run pairing or
retrieve QR bytes through SSM RunShellScript output, GitHub Actions logs, chat,
public artifacts or copied auth directories. Use a separately approved,
authenticated interactive channel with private terminal/PNG handling and host
identity verification. The phone must scan the fresh Linux device QR; one
process owns that auth directory throughout. Terminate/reap the pairing owner
before another process opens the same directory. Never run Mac and Linux against
one auth store or duplicate session keys to avoid pairing. If the secure
interactive channel is unavailable, pairing is blocked rather than logged.

Independent Linux pairing, fresh text/PDF confirmation, the full24-hour primary
qualification, exact host loader/library compatibility and alert ownership/
rollout remain mandatory. The earlier ARM64 synthetic systemd cgroup proof does
not qualify an AMD64 host/live account. No background agent or vendor API key
belongs in the service environment. No automatic start/enable/resume/send occurs.

## Offline validation

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s tools/deployment -p 'test_*.py' -v
```

Tests generate disposable local Git repositories, clearly synthetic ELF/report
fixtures and synthetic host roots. They do not call network/cloud/provider
APIs, execute a supplied native binary or use real account data. They verify
exact separate source revisions, independent digest anchors, manifests and file
modes, ELF/ABI and sanitizer gate failures, malformed/unlisted/symlink inputs,
source mutation, root/host/OS/architecture/libc mismatch, account/unit/path
collisions and no changes to the dry-run host. Generated fixture receipts must
never be used as actual hosted source proof.
