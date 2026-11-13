# Independent Linux canary deployment plan

> Optional diagnostic tooling. OWA does not require or schedule a continuous
> soak, recurring live canary, or server installation. Use the
> [manual release checklist](RELEASE_CHECKLIST.md) for routine qualification.

This is a focused preparation plan, not an installed service or a Linux live
qualification. No host connection, credential/session transfer, unit activation
or additional message send is part of this preparation. The existing Mac
observation and CI protocol fixtures cannot qualify a Linux live account job.

## Immutable Linux input

Use a pinned OWA commit and the released Linux-amd64 compiler/Core/dependency
closure in `tools/native_ci/pin.json`. Build the live qualification entry point
natively on the existing Ubuntu24.04 amd64 CI runner after its ASan/TSan gates:

```sh
"$SDK/odin" build "$COPIED_OWNER/tools/live_qualification" \
  -collection:shared="$SDK/shared" -thread-count:1 -vet -warnings-as-errors \
  -O:speed -out:"$EVIDENCE/owa-live-linux-amd64"
readelf -h -l -d "$EVIDENCE/owa-live-linux-amd64"
sha256sum "$EVIDENCE/owa-live-linux-amd64"
```

Record the exact OWA commit, compiler binary and source revision, Core revision,
SDK/dependency manifest hashes, build flags, native target, ELF interpreter/shared
library requirements and output SHA256 beside the binary. Retain the existing
source/runner/SDK guards. This build contains public code and synthetic payloads;
no account or API credential enters CI. Existing native CI proves Linux offline
execution; its qualification-tools *test* executable is not this live binary.

Architecture alone does not establish deployment compatibility. Confirm the
chosen host's OS, libc, loader, certificate roots and required libraries before
activation. Nothing in this plan claims that the target host has been checked.
Do not alter Mesa's application service or ports to install this independent job.

## Separate Linux account and primary proof

Use a dedicated non-root service account and distinct Linux-only directories,
for example `/var/lib/owa/auth-linux`, `primary`, `primary-proof`, `periodic`, and
`controller`. Freeze the reviewed public helper bundle and binary together under
an immutable versioned `/opt/owa` directory. Private state directories are0700
and files0600 under the same service user. Actual paths are selected/reviewed at
installation; the examples do not authorize creating host resources now.

Pair the Linux device independently through the phone with
`tools/live_qualification/qr_display.py` and the Linux-native binary. Never copy
Mac account, prekey, ratchet, message-ID ledger, recipient confirmation or primary
receipt files. Do not operate a Linux auth directory from two processes or jobs.
The existing supervisor/session locks must remain authoritative.

Confirm a new synthetic text and working PDF in the approved isolated group,
including the duplicate count. Bind that confirmation to this Linux binary,
Linux scope and negotiated public version. Then prepare a new primary supervisor
configuration for86400 seconds, the approved exact group, explicit send/scoped
retry opt-ins and a21600-second canary interval. Start it once explicitly; do not
supply `--resume` or any unknown-intent override automatically. A new qualified
receipt needs the full Linux duration, clean health/gap coverage, required fresh
text/PDF cycles and Linux recipient confirmation. The Mac3700-second no-send
observation supplies none of those Linux-specific bindings.

Keep Linear/API credentials out of the service environment. Qualification can be
evaluated with the existing `finish_soak.evaluate` metadata gate and a private
proof receipt; root owns any separate Linear update. Do not run an API-writing
finish controller merely to produce a scheduling prerequisite. The receipt's
proof hash must be computed from the evaluator result, not copied or hand-labeled
QUALIFIED. Periodic controller already re-evaluates its original source metadata.

## Service ownership must survive detached launch

`periodic_canary.poll` may return STARTED immediately after the supervisor forks.
A naive oneshot service that only invokes `poll` then becomes inactive and may
terminate the new descendants through systemd's default cgroup cleanup. Changing
KillMode to process/none would hide those children from service ownership.
Neither is an acceptable template.

`systemd_canary.py` implements a foreground monitor around the existing periodic
controller. Its offline-tested contracts are:

1. One initial poll may start at most one finite180-second native job. WAITING,
   NOT_DUE, SUSPENDED and a pre-existing ACTIVE job return without starting or
   modifying another job. The existing qualified Linux primary proof is required.
2. After this invocation starts a job, keep the foreground process alive while
   observing that same run. Subsequent polls must use a launcher that refuses a
   second launch. The existing controller accepts only verified completed cycles
   and advances cadence from fresh ACKs; it never retries an uncertain intent.
3. Bound periodic foreground observation to240 seconds. Before returning on
   timeout, invalid metadata, cancellation or an unknown outcome, retain the pre-spawn durable monitor guard and persist a latched suspension
   without clearing journals
   or changing account keys. A future timer tick can inspect the suspension but
   cannot resume or send again. Preserve the existing supervisor's ownership and
   cleanup; never discover or kill arbitrary PIDs.
4. Use a foreground monitor for the initial24-hour supervisor as well. Its outer
   observation budget is86520 seconds; it must not exit immediately after the
   detached start. Interrupted/unknown primary work requires operator review;
   automatic restart/resume is forbidden.
5. Return only fixed status/reason categories. No raw nodes, addresses, message
   IDs, pairing material, tokens or credential files enter logs or unit contents.

Generated service settings for the foreground monitor are Type=exec,
Restart=no, KillMode=control-group, TimeoutStopSec=30s, UMask=0077 and an explicit
non-root User. The periodic service RuntimeMaxSec is300s, leaving time after the
monitor's240-second deadline for suspension and graceful cleanup. The one-time
primary service RuntimeMaxSec is86640s, above its86520-second monitor budget.
The stop allowance exceeds the owned supervisor's bounded graceful cleanup. These
units have structural validation and the ARM64 synthetic systemd evidence below;
AMD64 host/live-account execution remains unverified. Do not point them at the existing returning `poll` command.

The periodic timer should use OnBootSec=60s and OnUnitActiveSec=900s with
AccuracySec=1s. There is no catch-up loop and no automatic restart. An already
active service is left running. The native ledger/controller decide whether one
pair is due; a timer firing alone does not authorize a send. Do not enable the
periodic timer until the independent Linux primary proof qualifies.

## Required offline evidence before installation

Use only synthetic metadata, fake launchers and disposable Linux processes:

- A newly launched finite child remains in the service cgroup after the launcher
  returns; the foreground monitor stays alive through completion and reaps it.
- WAITING/NOT_DUE/pre-existing ACTIVE launch nothing. One due run launches once;
  healthy completion advances cadence. Repeated timer polls never create a burst.
- Hung child, cancellation, malformed evidence, zero cycles, changed version,
  unknown launch and expired monitor budget latch suspension. Later timer polls
  cannot send, reset state, override uncertainty or resume that run.
- Conflicting controller/session ownership refuses a second writer. Timeout/stop
  affects only the owned service cgroup; no host-wide PID matching is used.
- Unit generation rejects control/specifier/environment injection in user/path
  arguments, writes private artifacts only, and never installs or starts units.
- Validate generated units with the target systemd version's `systemd-analyze
  verify`. Verify argv separation without a shell and the finite timeouts.

Root reviews the resulting generator, monitor, tests and native artifact before
any installation/start decision. The generator/monitor has synthetic offline coverage, including real owned
disposable subprocesses, and the isolated ARM64 systemd proof below. It has not
been installed on an application host or used with a Linux live account.
No host-native live binary has been produced by this plan. Those remaining
checks precede independent pairing and the full primary24-hour run. Existing callbacks/CI tests and Mac evidence
must retain their narrower labels.

References: [systemd.service](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html),
[systemd.kill](https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html),
[systemd.timer](https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html).

## Preparing private units

Run generation locally with reviewed Linux deployment paths and bindings. The
four metadata directories must be distinct, nonnested and separate from account
storage. This command creates private files only; it does not read account
material, install a unit or start any job. Use the exact binary/scope SHA256 and
new Linux primary run ID, not the Mac bindings:

```sh
python3 tools/reliability/systemd_canary.py generate --mode periodic \
  --user owa --python /usr/bin/python3 \
  --monitor-path /opt/owa/REVIEWED/tools/reliability/systemd_canary.py \
  --primary-state-dir /var/lib/owa/primary \
  --primary-finish-dir /var/lib/owa/primary-proof \
  --state-dir /var/lib/owa/periodic \
  --controller-dir /var/lib/owa/controller \
  --expected-binary-sha256 "$LINUX_BINARY_SHA256" \
  --expected-scope-sha256 "$LINUX_SCOPE_SHA256" \
  --expected-primary-run-id "$LINUX_PRIMARY_RUN_ID" \
  --output-dir /tmp/owa-private-periodic-units
```

For the initial one-time primary, use `--mode primary`, omit the unknown primary
run ID, and choose a fresh output directory. The generator emits no primary timer
or install target. Its runtime refuses any previously started primary metadata;
it never supplies `--resume`. Prepare the primary configuration separately with
the existing supervisor, then review the generated unit before installation.

The foreground monitor retains the actual `Popen` returned by the additive
`supervisor.start_owned` API and reaps that exact child. It never signals a PID
read from metadata. An ARMED `monitor-latch.json` is durable before spawn; all
ordinary periodic polls reject it, including after hard monitor death or a failed
suspension write. Only the current monitor's private in-memory token permits its
own bounded observation polls. Successful evidence plus reaping removes the
guard. Cancellation, timeout and unknown outcomes leave it latched. There is no
automatic reset/resume operation: an operator must inspect both supervisor and
controller evidence before deciding how to recover. Never delete the guard or
reuse state just to make a timer run.

A primary monitor reporting COMPLETE proves its owned supervisor completed and
was reaped; it does not create a QUALIFIED receipt. Run the existing evaluator and
recipient-confirmation process separately. Periodic polls still require and
re-evaluate that independent qualified Linux primary proof.

Offline controls (no account/network/systemd access):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s tools/reliability -p 'test_*.py' -v
```

Before installation, run `systemd-analyze verify` on the generated service/timer
on the target Linux system, then use a disposable non-account child to verify
actual cgroup retention, cancellation, reaping and finite timeout behavior. The
Python subprocess/INI controls alone do not substitute for that Linux evidence.
The following isolated ARM64 result establishes a narrower ownership contract.

## Isolated Linux systemd evidence and remaining rollout gates

The candidate was checked on the existing local ARM64 Podman VM using an ordinary
network-isolated Ubuntu24.04 container, with no added capabilities, privileged
mode or host mounts. Official ARM64 Ubuntu base digest:
`sha256:c92376659a7f14cc1f51615d73c9f4b7d8e18d59f370e02b4ed683ab4485c66c`.
The locally built derivative image was
`69d583cea7a5dfbf4cf4520889b31ff667303e0f95250dde423cd7ba208914f5`, with
systemd255.4-1ubuntu8.18 and Python3.12.3. Public package retrieval occurred only
while building the derivative from a fresh empty context; validation had no
network. No account/session data was needed.

Actual `systemd-analyze verify` accepted the generated primary service and
periodic service/timer (exit0). All71 then-current synthetic controls passed as
non-root UID1001. An actual generated primary service launched a sleeping Python
fake native process with an empty generated auth directory. The foreground
monitor, supervisor and fake native child stayed ACTIVE in the same delegated
cgroup. Explicit service cancellation completed in0.183 seconds, reaped all three
owned processes and left that cgroup empty. Its durable SUSPENDED monitor guard
blocked a subsequent ordinary periodic poll. The fake auth directory contained
only the ownership lock. These results prove synthetic ARM64 Linux ownership and
cancellation, without proving any WhatsApp protocol or delivery behavior.

The earlier AMD64 derivative image passed71 synthetic controls and unit
verification on the ARM64 VM, but its ordinary systemd PID1 container exited139
without diagnostics. That emulated attempt does not establish AMD64 cgroup proof.
The native ARM64 check did not require a host workaround or expanded privileges.
Only the named owned test containers were stopped/removed; no host service or
pre-existing container was changed. Local derivative images remain available for
reviewed reuse.

Record one preparation uncertainty: an initial, interrupted build mistakenly
selected `/tmp` as its context. It was cancelled before any build STEP output,
then the successful builds used an explicit fresh empty context with no COPY/ADD.
It is not established whether any temporary-context bytes reached the local VM
before cancellation. No zero-transfer claim is made, and no image was published
externally. Future builds must always use an explicit fresh empty context.

Before rollout, independently verify the exact AMD64 host/native binary and its
loader/libraries, pair a separate Linux device, obtain the full24-hour Linux
primary proof and recipient confirmation, and review alert delivery/ownership.
There has been no application-host installation, service activation, credential
transfer, live Linux send or alert rollout. The synthetic systemd result and Mac
proof must retain their separate labels. Runtime metadata paths are rejected if
they equal, contain or sit inside the declared auth directory; ordinary periodic
polls reject such nesting before creating lock files.
