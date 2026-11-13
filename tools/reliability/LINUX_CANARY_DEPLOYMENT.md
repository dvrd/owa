# Independent Linux canary deployment plan

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

Before generating installable units, implement a small foreground service monitor
around the existing periodic controller, with these exact contracts:

1. One initial poll may start at most one finite180-second native job. WAITING,
   NOT_DUE, SUSPENDED and a pre-existing ACTIVE job return without starting or
   modifying another job. The existing qualified Linux primary proof is required.
2. After this invocation starts a job, keep the foreground process alive while
   observing that same run. Subsequent polls must use a launcher that refuses a
   second launch. The existing controller accepts only verified completed cycles
   and advances cadence from fresh ACKs; it never retries an uncertain intent.
3. Bound periodic foreground observation to240 seconds. Before returning on
   timeout, invalid metadata, cancellation or an unknown outcome, take the existing
   controller lock and persist a latched suspension/alert without clearing journals
   or changing account keys. A future timer tick can inspect the suspension but
   cannot resume or send again. Preserve the existing supervisor's ownership and
   cleanup; never discover or kill arbitrary PIDs.
4. Use a foreground monitor for the initial24-hour supervisor as well. Its outer
   observation budget is86520 seconds; it must not exit immediately after the
   detached start. Interrupted/unknown primary work requires operator review;
   automatic restart/resume is forbidden.
5. Return only fixed status/reason categories. No raw nodes, addresses, message
   IDs, pairing material, tokens or credential files enter logs or unit contents.

Proposed service settings for the foreground monitor are Type=exec,
Restart=no, KillMode=control-group, TimeoutStopSec=20s, UMask=0077 and an explicit
non-root User. The periodic service RuntimeMaxSec is300s, leaving time after the
monitor's240-second deadline for suspension and graceful cleanup. The one-time
primary service RuntimeMaxSec is86640s, above its86520-second monitor budget.
These are design values, not already tested/installed units. Do not point them
at the existing returning `poll` command without the monitor.

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
any installation/start decision. No systemd generator/monitor is implemented by
this document, and no host-native live binary has been produced by this plan.
Those are the concrete next preparation items, followed by independent pairing
and the full primary24-hour run. Existing callbacks/CI tests and Mac evidence
must retain their narrower labels.

References: [systemd.service](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html),
[systemd.kill](https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html),
[systemd.timer](https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html).
