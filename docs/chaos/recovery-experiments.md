# WhatsApp recovery fault campaign — OKAMI-410

The fault target is a new synthetic store and its unreaped child process, never
an account, Mesa, another process, or a production service. No system-wide network
or disk fault is injected. The finite campaign covers five distinct durability
states, so each adds a new failure mode even after preceding confirmations.

## Steady state and rollback

A no-fault child completes intent, pending-wire, positive-ACK and caller-ACK
persistence. Another process reopens it, verifies its fixed content, ID, state
identity and ACK status, and exits. The temporary tree is then deleted and its
absence checked. Readiness, process completion and verification each have a
10-second bound; compilation and focused suites have a 120-second bound. Wire
qualification has a 180-second outer bound plus its own finite per-peer waits.

Before each kill, the runner requires this steady state and every prior recovery
to have passed. A failed boundary, wrong exit signal, recovery assertion, source
mutation or unavailable loopback permission halts the candidate gate. Cleanup
kills only the still-owned child, waits for it, and deletes its disposable tree.
There are no arbitrary PID searches, account paths, global firewall changes,
external messages, or business handlers. Root owns commits and release decisions.

## Hypotheses declared before injection

| Experiment | Fault boundary | Required result after new-process reopen |
| --- | --- | --- |
| before-commit | In-memory ratchet change, before native save | Original durable sentinel; no intent, content or pending wire |
| after-intent | Caller Prepared intent fsynced/renamed | Same fixed ID and content digest; no native pending wire; no delivery |
| after-pending-wire | Native ratchet/content/wire saved | Original pending packet and ID; public pending replay does no new state/query work |
| after-positive-ack | Native ACK removed pending, caller journal still Queued | Retained content and same ID, but UNKNOWN; no fabricated ACK/delivery or automatic send |
| after-ack-journal | Caller Acknowledged status fsynced | Same persisted ACK evidence; still no recipient-delivery assertion |

Each experiment's blast radius is one owned child and disposable directory.
Injection is one SIGKILL following exact readiness, not a random instruction or
filesystem syscall. The replay leg uses real native Noise/WebSocket framing in
memory with synthetic keys; the sentinel only measures atomic co-presence.

## Separate network and regression legs

The existing owned loopback verifies fragmented encrypted exchange, truncated
EOF, partial-frame stall deadline, key erasure and a fresh successful connection.
It explicitly uses the old issuer-only certificate hook for its synthetic
transcript; strict trust is covered separately by the certificate regression
suite. Focused immutable-ID, retained-media, negative-ACK and media deadline
cases run under the selected sanitizer. No circuit breaker implementation is
claimed; bounded watch retry policy has its separate tool tests.

## Operator plan

One runner is facilitator and observer. It establishes the control, injects and
verifies each fault sequentially, runs focused regressions and loopback, then
emits its scorecard. Abort on any failed recovery or guard. Repeat under ASan and
TSan before considering this narrow candidate gate passed. Do not extend this
procedure to a live session without a separately reviewed experiment and consent.
