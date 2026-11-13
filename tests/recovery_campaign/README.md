# Disposable recovery campaign

Run from `shared/` with the matching repository compiler:

```sh
python3 whatsapp/tests/recovery_campaign/run.py --odin "$PWD/../odin" \
  --sanitize address --report /tmp/whatsapp-recovery-address.json
python3 whatsapp/tests/recovery_campaign/run.py --odin "$PWD/../odin" \
  --sanitize thread --report /tmp/whatsapp-recovery-thread.json
```

The runner owns every child, listener and synthetic temporary store. It accepts
no account path, provider endpoint, or live WhatsApp credentials. Native child
paths must begin `/tmp/wa-recovery-` or its `/private/tmp` equivalent. The only
network leg is the existing `loopback_noise` fixture's fresh localhost listener.
The launcher requires permission to bind that test-owned listener.

Before each fault, the previous recovery must have passed. A normal child/reopen
control establishes steady state and tests deletion of the owned temporary tree.
Five experiments stop at an explicit completed durability boundary, print a
readiness marker, and wait. The parent sends SIGKILL only through that unreaped
`Popen` object, requires exit status `-SIGKILL`, reopens the same store in a new
process, verifies it, and removes the disposable directory. Failures halt the
campaign and leave a failing JSON gate rather than continuing silently.

The process campaign models a caller journal separately from the native state
store. It uses native atomic saves and native outbox/ACK processing. Its ratchet
record is a sentinel, not a generated Signal session. Pending replay uses the
public `socket_send_group` path and independently decodes the actual resulting
in-memory WebSocket/Noise packet, checking the exact inner packet and original
ID without new ratchet state or metadata queries. No external delivery occurs.

The five boundaries are before native commit, after durable caller intent,
after native pending-wire commit, after positive server ACK but before caller
ACK persistence, and after caller ACK persistence. The fourth is deliberately
UNKNOWN: queued journal plus absent pending wire must not become delivery or
automatic resend evidence. Even a persisted ACK does not establish recipient
delivery. Every reopen rejects a mismatching state identity.

Separate evidence runs all existing immutable-ID, negative-ACK, media retry,
media deadline, and strict-certificate policy regression tests. The owned Noise
loopback executes normal, truncated EOF, stalled partial frame and fresh normal
connections. Its synthetic certificate uses an explicit legacy compatibility
hook; it does not qualify strict TLS or account reconnection. The fresh normal
connection proves transport recovery after failures, not replay of a real account.

The JSON includes exact commands, compiler binary/root/version identity,
source pre/post hashes (including SDK Core/base/zlib), binary hash, child kill
receipts, elapsed times, results, gaps, and `candidate_release_gate`. Source or
compiler changes make that gate false. The repository TSV logs each experiment;
detailed artifacts and executables stay under `/tmp`.

Compiler invocations have a separate 300-second bound. Focused tests are built
with `-build-mode:test`, then executed with the existing 120-second runtime bound;
the campaign's shorter child and wire deadlines are unchanged. Timed-out commands
remain in the receipt and are never retried automatically. Use `--scorecard` with
an absolute path outside the checkout to retain the TSV without changing it.

See [experiment definitions](../../docs/chaos/recovery-experiments.md) and
[resilience scope](../../docs/chaos/recovery-resilience-report.md). Linux, real
power loss, disk-full/corruption, network partition/DNS failure, live Signal
ratchet recovery and recipient exactly-once delivery remain unqualified.
