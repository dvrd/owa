# OKAMI-429 owned prekey policy qualification

Three new tests pass against unchanged owned runtime ebe2189. Full package: 52 tests pass under address sanitizer, vet and warnings-as-errors, one test thread. No RED regression claim: no runtime defect or patch was found for this finite source-drift question.

The tests exercise actual key generation to the 1024-key bound, explicit capacity/ID exhaustion without mutation, actual persisted Pending store recovery after a simulated lost upload response, exact key/ID reuse and persistence gating on retry, stale versus matching IQ publication, pending-reclamation refusal, and valid missing highest consumed key across save/load without ID reuse. Consumption authority itself remains the existing independently durable socket transaction contract; the lower-level reclamation test explicitly models that precondition and does not fabricate it.

No runtime source, provider/account/session operations, server rotation, upstream execution or messages. The no-action scope is stock/refill/retry/consumption policy; future digest/signed-key rotation requirements still need their own retained-generation and reconciliation contract.

## Integrated qualification

The final combined library passes78 tests with speed optimization and AddressSanitizer under the accepted matching compiler. This uses physical copies of the current ascii, async, http, surf and websocket sources; hashes match their unchanged canonical repositories. Four owned localhost Noise modes, optimized ASan API consumer and11 encrypted native-TCP crash/recovery stages pass. This validates the finite existing key policy, not an unimplemented server rotation/digest API or a current phone session.

[Receipt and compressed evidence](evidence/prekey-lifecycle-20261115/receipt.json). The source investigation is retained in [the spike decision report](login-key-spike-decisions-20261115.md). No RED defect is claimed for this test-only no-action issue.
