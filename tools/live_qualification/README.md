# Library-only WhatsApp qualification

This tool qualifies a freshly linked test device through the native WhatsApp
library. It does not import Mesa, its configuration, business handlers, database,
alerts, or provider integrations. No command, `--help`, and `preview` perform no
network or session initialization.

Strict compilation and offline tests pass. These are preparation checks, not
live pairing, send, delivery, or general protocol qualification. Live operations
require a separate explicit operator decision and a phone scan.

## Build and preview

From `shared/`, using its matching compiler:

```sh
../odin build whatsapp/tools/live_qualification -thread-count:1 \
  -warnings-as-errors -vet -out:/tmp/whatsapp-live-qualification
/tmp/whatsapp-live-qualification --help
/tmp/whatsapp-live-qualification preview
```

Preview reports `PREVIEW_READY` without opening storage or making requests. The
fixed payloads can be inspected before authorizing sends:

- [Text](payloads/qualification.txt):
  `Mesa WhatsApp qualification: synthetic text transport check.`
  The file has a final newline; the sent text does not.
- [PDF](payloads/qualification.pdf): 686 bytes, one page containing
  `Mesa WhatsApp qualification`, `Synthetic transport-only sample.`, and
  `No financial records.`
  SHA-256: `8c4e8293b4af7d0f01c356cb5999bcfcb65b973d0df9bf53e981b1cd95f2923d`.

The document is sent as `mesa-qualification.pdf`, MIME `application/pdf`, with
caption `Synthetic PDF transport check.`. No business records are used.

## Pair a fresh device

These commands are operator instructions. Select an absolute path to a fresh
leaf directory under an existing private parent. Never use, copy, or fork Mesa's
existing session. The tool creates and exclusively locks its own directory,
checks owner and permissions, and binds its marker to that directory and generated
identity. Copying its files into a new directory does not create an admissible
session.

```sh
python3 whatsapp/tools/live_qualification/qr_display.py --live \
  --binary /tmp/whatsapp-live-qualification \
  --auth-dir /absolute/private/whatsapp-qualification-406 pair -- \
  --group-subject 'Bot Testing Env' --timeout-seconds 300
```

`--live` belongs to the Python launcher. Native flags follow `--`. Replace the
example path with the selected fresh directory. Group subject is an explicit
CLI input, not built into the tool. An existing complete, owned, unpaired session
can resume pairing; a registered session cannot run `pair` again.

On `QR_RENDERED`, open `<auth-dir>/qr.png` locally and scan through the phone's
linked-device flow. Both matrix `qr.json` and rendered `qr.png` are private 0600
files in a 0700 directory. They encode a pairing credential: do not upload,
commit, or share them. Raw QR tokens are never printed. Normal native cleanup
removes `qr.json`; the PNG may remain private until removed. A forced stop can
also leave the matrix. Pairing restart creates a fresh socket while retaining
the same owned stores and exclusive lock.

Pairing sends authentication and protocol traffic, but no human messages or
pending outbound content. Unexpected QR requests outside pair mode fail closed.

## Inspect or explicitly send

After pairing, inspect the unique exact group subject using the same owned
session. The tool queries participating groups and fresh metadata; duplicate
matching subjects or a changed subject/JID fail closed.

```sh
python3 whatsapp/tools/live_qualification/qr_display.py --live \
  --binary /tmp/whatsapp-live-qualification \
  --auth-dir /absolute/private/whatsapp-qualification-406 inspect -- \
  --group-subject 'Bot Testing Env' --timeout-seconds 60
```

Only `qualify --send` authorizes the synthetic text and PDF:

```sh
python3 whatsapp/tools/live_qualification/qr_display.py --live \
  --binary /tmp/whatsapp-live-qualification \
  --auth-dir /absolute/private/whatsapp-qualification-406 qualify -- \
  --group-subject 'Bot Testing Env' --send --timeout-seconds 120
```

`qualify` without `--send` behaves as inspection. Pair, inspect, and any non-send
invocation reject **all** retained outbound content or pending wire before version
discovery or login: login can automatically replay durable outbox work. They never
clear state to make inspection possible.

Explicit send admission permits only this tool's journal-bound destination and
IDs. It persists a stable intent and ID before each send. The fingerprint binds
the fixed payload and immutable template, document MIME, filename, and caption.
Retries retain the same IDs; changed intents are rejected. Do not edit or delete
the journal or outbox to manufacture a clean run.

Text goes first. The tool waits for a successful authenticated server ACK and
persists that journal transition before starting PDF; PDF has its own bounded
ACK wait. A negative message ACK returns `Message_Rejected`, fails the run, and
retains the pending intent.
`SERVER_ACKED` means server acceptance, **not recipient delivery or a read
receipt**. `ACK_PENDING` and `RESUME_UNKNOWN` are not success. Missing pending wire
on startup does not prove an ACK. Explicit resumption may resend an unknown intent
with its existing ID; this does not claim exactly-once recipient delivery.

## Bounds and evidence

`--hold-seconds 0..300` (default 0) pumps the existing connection after `ONLINE`,
before pair completion or the group query. `CONNECTED_HOLD` marks the interval.
It is limited by the remaining overall budget. Budget expiry or a requested
restart fails closed, without silently reconnecting. This tests connection
duration; it does not prove history synchronization or fix phone loading.

Native timeout is 10–600 seconds (default 300). Polls, scoped reads, queries, QR
refresh, and restart attempts are bounded. Native system DNS/TCP dial cannot be
interrupted by this timeout; use the Python launcher, whose outer 615-second
watchdog also bounds a stalled child. The launcher requires `--live`, filters
output to typed phases/errors, and never echoes raw diagnostic content.

TLS uses system trust and Noise uses the library's strict default pinned
certificate policy. Bounded version discovery may report its explicit pinned
version fallback. Incoming protocol traffic and application messages can arrive
while linking; the tool does not render unrelated contents or run business
handlers. Durable inbox work remains in this owned session.

`COMPLETE` reports completion of the requested mode. Record commands, typed
phases, compiler/source identity, and explicit ACK outcomes separately from
recipient observations. Do not include session files, QR artifacts, keys, phone
numbers, message IDs, or unrelated personal content in reports. Stopping the
process does not unlink the device; remove it through the phone's linked-device
controls when qualification finishes.

## Retarget an unused qualification session offline

When the selected test group changes, explicitly name both the previously bound
subject and the new exact subject. This command is offline: it locks and verifies
the existing owned registered session, updates only the tool's scope journal,
and exits before trust loading, version discovery, or connection setup.

```sh
/tmp/whatsapp-live-qualification retarget \
  --auth-dir /absolute/private/whatsapp-qualification-406 \
  --previous-group-subject 'Bot Testing Env' --group-subject 'botlab'
```

Retarget refuses an already resolved target or any prepared or retained outbound
intent. It never clears work to permit a target change, changes auth/prekey/state
files, or sends a message. `--send`, `--preview`, `--hold-seconds`, and
`--timeout-seconds` are rejected. A subsequent inspection must still resolve the
unique new exact subject and confirm fresh group metadata.

## Persistent connection watch

`watch` keeps one authenticated socket pumping, verifies the unique exact group
and fresh metadata on each connection, and emits sanitized health counters once
per minute. It generates no new text, PDF, intent IDs, or journal entries. Default
runtime is 86400 seconds (24 hours); `--timeout-seconds` accepts 60–172800 for
watch only. Reaching the runtime normally emits `WATCH_COMPLETE`; that means the
requested observation interval ended, not that every protocol feature passed.

The reviewed supervisor in `../reliability/` should launch this command and apply
an external watchdog. The QR launcher has a 615-second cap and is unsuitable for
a 24-hour watch. A native invocation for the separately authorized operator is:

```sh
/tmp/whatsapp-live-qualification watch \
  --auth-dir /absolute/private/whatsapp-qualification-406 \
  --group-subject 'botlab' --timeout-seconds 86400 --allow-scoped-retries
```

Watch rejects all outbound content unless `--allow-scoped-retries` is explicit.
With that flag, it admits only retained content whose original ID and destination
are bound to a journal intent with a persisted successful ACK. Startup still
rejects any pending outbound wire or unacknowledged journal intent. The flag
permits automatic protocol-requested retransmission of those existing synthetic
messages with their original IDs; it does not permit new logical messages. On
reconnection, pending wire generated by such a retry must match the same known
ACKed intent and exact target. No retained content or journal is deleted.

Only recognized transport EOF/timeout, peer closure, connection loss, or TCP-dial
failure reconnects. Backoff grows from one to thirty seconds plus up to 500ms
jitter. Eight consecutive failures, 1000 total reconnects, or any authentication,
identity, certificate, schema, server rejection, or storage error stops the run.
A connection must remain up for a minute to reset its consecutive failure count.
A protocol restart request is terminal rather than silently treated as a retry.

Inbound messages remain private durable inbox work without business processing.
The tool stops at 49152 state records or 48MiB of record names and content, checked
once a minute; the native store also enforces its own hard limits. Neither a
health line nor an open connection is a recipient-delivery claim. The existing
system DNS/TCP dial timeout caveat still requires the supervisor's outer watchdog.
Periodic new canary messages and journal rotation are not implemented by watch.

## Recurring synthetic canaries in the same watch connection

A watch creates no new messages by default. Explicitly add all three flags to
send the reviewed fixed text/PDF pair initially and then every six hours:

```sh
/tmp/whatsapp-live-qualification watch \
  --auth-dir /absolute/private/whatsapp-qualification-406 \
  --group-subject 'botlab' --timeout-seconds 86400 \
  --allow-scoped-retries --send --canary-interval-seconds 21600
```

The interval accepts 3600–86400 seconds and is bound into the first private
`canary.ledger`. A later different interval fails rather than silently changing
an existing schedule. This uses the same socket, identity stores and exclusive
lock as watch. Never start a second sender beside it. `WATCH_VERSION` reports
only the public discovered version triple, which remains fixed across reconnects
for that run. It reports no phone or account metadata.

Each cycle's two immutable IDs and full payload/metadata fingerprints are saved
together before a send. Queued status is saved before each library call; an
observed positive text ACK is persisted before starting PDF. Both ACKs and no
pending wire are required before a new cycle can be prepared. The next due time
is set from completion, so restart does not cause a burst of missed cycles.
Backward completion-clock movement stops the sender. Every due or resumed pair
requires fresh exact-subject metadata verification, admitted with at least 90
seconds left. A new pair is not persisted with less than 60 seconds remaining.

The legacy eight-entry `scope.journal` remains unchanged. The atomic checksummed
sidecar binds the same generated identity, marker nonce, subject and exact target.
It retains a monotonic cycle counter and at most 512 intent records. Archive
metadata can be compacted only for complete ACKed pairs after the native durable
store already lacks their content and pending wire. Native seven-day retention
alone owns content pruning; this tool never deletes retained content or crypto
records. Pending, unknown, malformed or capacity-limited states fail closed.

`CANARY_TEXT_ACKED`, `CANARY_PDF_ACKED`, `CANARY_COMPLETE`, and numeric
`CANARY_STATUS` counters describe server ACK evidence, not recipient
receipt or readability. `CANARY_UNKNOWN` stops ordinary automation. A Queued
journal with absent pending wire on startup never becomes an ACK. The normal
supervisor must never enable unknown retries.

For a separately authorized recovery of that already existing unknown item,
repeat the same watch arguments with `--retry-unknown-canary`. This flag is
accepted only with watch, explicit interval, send and scoped retries, and only
when an active unknown item exists. It retries that item's original ID and
fingerprint, consumes the recovery authorization before that send, and cannot
advance to a fresh cycle until both ACKs are persisted. It can duplicate what a
recipient already received; it is not an exactly-once-delivery guarantee.

Canary status contains both per-run `completed_cycles` and durable cumulative
`durable_completed_cycles`, plus `first_ack_unix_seconds` and
`last_ack_unix_seconds`. The cumulative prefix and first/last completed-pair ACK times survive
restarts and archive compaction. A baseline is emitted after group verification;
the supervisor must persist these independently of its bounded event ring.
`WATCH_HEALTH uptime_seconds` measures elapsed watch time including reconnects
and backoff, not connection availability. During a run, a monotonic deadline also
protects the interval from forward wall-clock jumps; at most 48 cycles complete
per run. On restart, persisted due time permits one due cycle, without catch-up.

## Terminal session diagnostics

Server failures retain fixed node/detail categories and an unknown-child count
through the existing protocol observer before the SDK frees its document. Only
allowlisted enums and a count capped at32 are emitted; raw attributes, child tags,
addresses and content are never printed. Code0 remains ambiguous and does not
become retryable. Other errors retain their existing output and stop policy.
The supervisor carries these typed fields into the private failure handoff.
These categories aid diagnosis; they do not prove the cause of an earlier run.

`Ack` identifies a terminal `ack` child using the fixed category only; it does
not retain the child's class, type, IDs, or routing attributes and cannot by
itself establish a missing status ACK. Top-level `status` deliveries now receive
a plain transport ACK during online and provisioning/offline processing. This
sends no viewed receipt and emits no chat event. Offline encrypted fixture tests
cover the protocol behavior; a fresh long live soak is required to assess the
50-minute failure. Reference behavior: [whatsmeow status handler](https://github.com/tulir/whatsmeow/commit/a238105488)
and the [Baileys incident report](https://github.com/WhiskeySockets/Baileys/issues/2858).
