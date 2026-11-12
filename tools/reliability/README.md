# Finite watch supervisor

This supervisor runs one reviewed native `watch` child for an explicit session and
exact group. By default it does not enable new sends. Optional canary mode delegates fixed
synthetic text/PDF cycles and durable message IDs to the native implementation.
The supervisor never generates message IDs or retries ambiguous operations.
`--allow-scoped-retries` is opt-in: the native watch may service protocol retries
of already acknowledged, journal-bound content using its original message IDs.
Native admission and reconnect policy remain authoritative.

`prepare` only writes configuration. `start --live` explicitly starts the detached
worker. The default duration is 86400 seconds; accepted durations are 60–172800.
The native runtime plus a 30-second margin is the outer watchdog. A separate
monotonic 180-second progress watchdog kills a child that stops producing valid
phases/health events; status also derives a stale-progress local alert. There is no
supervisor retry loop. A failure stops the job and writes a private local alert.

Set these variables to explicit absolute paths outside Git; no session or private
locator is included in this repository:

```sh
python3 whatsapp/tools/reliability/supervisor.py prepare \
  --state-dir "$STATE_DIR" --auth-dir "$AUTH_DIR" --binary "$REVIEWED_BINARY" \
  --group-subject "$TEST_GROUP" --duration-seconds 86400 --allow-scoped-retries
python3 whatsapp/tools/reliability/supervisor.py start --state-dir "$STATE_DIR" --live
python3 whatsapp/tools/reliability/supervisor.py status --state-dir "$STATE_DIR"
python3 whatsapp/tools/reliability/supervisor.py stop --state-dir "$STATE_DIR"
```

State/auth directories must be owned private directories (0700). State, status,
lock, event and alert files use 0600. Config contains paths/group scope, not
credentials. The native binary SHA-256 is pinned during preparation and verified
before launch. A state lock survives the detached handoff; a separate session
lock prevents two supervisors with different state directories sharing a session.
The native storage lock also excludes other native tools.

`status.json` records the durable run ID, worker/native PIDs and final result.
`version-warning.json` records VERSION_PINNED as a nonterminal warning, exposed
as `status` field `version_fallback`. Only VERSION_DISCOVERED clears it. This
means feed discovery fell back to the pin; it is not reported as discovery success.
`events.json` retains the latest 128 typed events, capped at 64 KiB. Raw child
stdout/stderr, account identifiers, group names, content and keys are never
retained. Only exact approved phases, numeric counters and bounded typed errors
are accepted. `alert.json` is a local failure artifact; no external alert is sent.

`stop` writes a private request. The worker checks it at least once per second,
terminates the child and escalates to kill after five seconds. SIGTERM/SIGINT use
the same cleanup. The supervisor never signals a PID read from an old status file.
A forcibly killed worker or reboot can leave INTERRUPTED status; `status` creates
a local alert. A surviving native child remains bounded by its own runtime and
native storage ownership. Inspect it before resuming. This is finite detached
supervision, not a reboot-resilient service installation.

An interrupted/failed run requires explicit `start --live --resume`; its run ID is
preserved. This does not create fresh message intent or bypass native admission.
No account job is started by tests, help, preparation, status or stop.

Offline verification:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s whatsapp/tools/reliability -p 'test_*.py' -v
```

## Optional recurring canaries and evidence

To enable new synthetic cycles in the explicitly bound test group, add all three
prepare flags: `--send --allow-scoped-retries --canary-interval-seconds 21600`.
Intervals are limited to 3600–86400 seconds. Missing consent flags fail closed.
The supervisor never enables `--retry-unknown-canary`; ambiguous native intent
requires a separate explicit operator decision with the original IDs.

`progress.json` keeps bounded aggregate evidence independently of the event ring:
run start/finish and observed process duration, first/last health, reconnects,
health gaps and observed heartbeat intervals, actual version/fallback, durable
canary counter baseline/latest, and last text/PDF ACK observations. Native elapsed
seconds are labeled `process_elapsed_seconds`; they do not establish availability.
`observed_seconds` sums consecutive healthy heartbeat intervals of at most 90s.
Reconnects and larger heartbeat gaps invalidate continuous coverage.

A canary-enabled successful exit also requires at least
`max(0, duration_seconds // canary_interval_seconds - 1)` newly completed durable
cycles. A 24-hour/6-hour job therefore requires at least three, actual run duration,
(within five seconds of the configured duration), and qualified heartbeat coverage. Otherwise it fails with a typed coverage reason.
A short smoke may require zero cycles and records that zero explicitly; it does
not qualify delivery. Native server ACKs remain separate from human receipt/PDF
confirmation. A completed run cannot be resumed to reuse its prior proof.

Keep the Mac awake for a continuous soak. Both monotonic and wall-clock silence
of 180s trigger CHILD_STALLED before fresh post-wake output is drained. Sleep,
restart, reconnect gaps and incomplete cycles must not be counted as a clean 24h
qualification. This tool does not change the user's power policy.

## Continuing after qualification

`periodic_canary.py` polls metadata every15 minutes and waits for a completed,
qualified primary soak. Pin its primary run ID, binary SHA256 and scope SHA256.
Use distinct primary state, primary finish, periodic state and controller
directories. `plist` prepares a private launchd plist; it does not install it.
`poll` performs one check. The public helper and its reviewed dependencies must
remain together in the frozen bundle.

After qualification, a pair is due six hours after the latest durable pair ACK.
The controller starts one finite180-second supervisor run, retaining native
message-ID ownership and exact group verification. A new successful cycle,
fresh text/PDF ACKs, health coverage and the qualified version are required.
Active jobs are left alone; failed, interrupted, unknown or changed evidence
suspends the controller with a local alert. Durable launch intent prevents blind
retries when a launcher outcome is uncertain. There is no automatic resume or
unknown-message override. Recipient receipt is not inferred from a server ACK.

The jobs depend on this Mac/user environment and do not establish a deployed
always-on service. Inspect a suspension before making an explicit recovery
decision; never clear account stores or controller state merely to pass a gate.
