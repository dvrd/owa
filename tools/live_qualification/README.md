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
