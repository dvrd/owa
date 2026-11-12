# Recovery resilience scope — OKAMI-410

Qualification is limited to synthetic disposable processes and owned loopback
connections. It is not a production-readiness or exactly-once-delivery claim.

The first completed native leg confirmed all five crash hypotheses and 23 focused
regressions under ASan. Its network leg could not bind localhost inside the
restricted sandbox, so that candidate gate correctly remained false. A prior
fixture attempt asserted on fsync of a stdout pipe; the child trapped before the
planned kill. The fixture now treats stdout flush separately and records the
actual child exit signal. This was a harness defect, not a library recovery defect.
No personal/account state was touched. Final full gate receipts follow after
permitted owned loopback execution.

## Coverage boundaries

Process checks use the real native state store and outbox/ACK implementation,
but a synthetic caller journal and ratchet sentinel. They kill only after a
completed explicit operation; they do not sample arbitrary filesystem atomicity
windows. Pending replay goes through public native send and actual in-memory
Noise/WebSocket framing. Existing focused cases cover conflicting IDs, pending
replay, retained media, upload deadlines, negative ACKs and strict certificate
policy. The real-stream loopback's separate synthetic legacy certificate hook
must not be mistaken for current strict TLS/account interoperability.

Not qualified: power failure, disk full/corruption, production filesystem crash
semantics, live Signal ratchet/key-rotation recovery, network partition or DNS
failure, full account reconnect, live media provider retry, recipient delivery,
Linux/Windows, and a finished 24-hour soak. Those remain distinct gates.

## Final executed evidence

Both complete campaigns passed on Darwin arm64 with the matching repository
compiler `dev-2026-11:c826157de`:

- `/tmp/whatsapp-recovery-campaign-address.json`: ASan, five SIGKILL/reopen
  experiments CONFIRMED, 23 focused regressions, four owned TCP/WebSocket/Noise
  modes passed; `source_unchanged`, `compiler_unchanged` and
  `candidate_release_gate` are true.
- `/tmp/whatsapp-recovery-campaign-thread.json`: the same five experiments,
  23 regressions and four wire modes passed under TSan, with both guards and
  the candidate gate true.

Each report binds 2049 source/fixture inputs, the exact compiler binary/root and
version, compiled fixture hash, commands and owned child exit receipts. All five
fault children exited from the requested SIGKILL; every separate verification
process reopened the same durable store successfully. The synthetic queued
journal after ACK was explicitly reported UNKNOWN with no delivery or automatic
send. Positive ACK nodes are injected directly into native `socket_process_node`;
that leg does not represent an authenticated ACK received from a remote server.

| Failure domain | Grade within executed scope | Evidence |
| --- | --- | --- |
| Process crash at completed durability boundaries | A | Five distinct states, same-store reopen, original intent and packet preserved |
| Store identity mismatch | A | Reopen refuses the wrong identity at every boundary |
| Pending replay after crash | A | Public send path, one Noise write, exact decoded inner packet, unchanged ratchet sentinel and query sequence |
| ACK versus unknown versus delivery | A | Absent pending wire with Queued journal remains UNKNOWN; ACKed journal never claims delivery |
| Owned stream EOF/stall/recovery | A | Normal, truncated EOF, partial-frame timeout, fresh normal; key cleanup and allocation checks |
| Production filesystem, network partition, live account recovery | Not run | Explicitly outside this campaign |

**Overall: RESILIENT within the executed synthetic scope.** This is a narrow
candidate regression gate, not broad production resilience certification. No
library or live-tool behavior changed in this campaign. Final documentation was
written after execution; native and harness code inputs remain unchanged.
