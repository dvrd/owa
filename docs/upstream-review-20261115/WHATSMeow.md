# OKAMI-422 — immutable whatsmeow client.go observations

Reviewed 2026-11-15 against OWA `b90209116c13427c00d65b55996affbac0cdcc38`. Conclusion: **no OWA runtime update is required by either recorded client.go observation**. This closes the investigation of these two observations only; it does not certify current WhatsApp server interoperability or all changes elsewhere in whatsmeow.

## Exact source and integrity

All three fetched files match the SHA256 values originally recorded by the Linear reports:

| Revision | SHA256 | Bytes |
| --- | --- | ---: |
| `c88388f983b4bc43dfd0bcc2b46969fcde82d61f` | `4b8a21d7db26be100996078fc0674a3f9035c80a86bce22679bcc0d580639d06` | 36165 |
| `1956f9683795cfb695f2e5d37ee5818c9961d266` | `67c29b7ff93b46d9b7a42819fbcc41ead999482f209655c5b54473961dc25ddd` | 36440 |
| `fcb7bdeb35921905b60984025945a571eb8f39b6` | `61865c3ff20032b7625d3e220b4cc0cbd2ccc19566736b158e0a0c853851d3b0` | 36556 |

Primary sources: [historical client.go](https://github.com/tulir/whatsmeow/blob/c88388f983b4bc43dfd0bcc2b46969fcde82d61f/client.go), [first observed client.go](https://github.com/tulir/whatsmeow/blob/1956f9683795cfb695f2e5d37ee5818c9961d266/client.go), [second observed client.go](https://github.com/tulir/whatsmeow/blob/fcb7bdeb35921905b60984025945a571eb8f39b6/client.go).

## First observation: Facebook Messenger logout support

The complete historical-to-first-observed diff changes only `Logout`. It replaces an early Messenger rejection with a Messenger-specific `fbid:devices` removal request. For ordinary WhatsApp, the existing `md` request, own-device JID and user-initiated reason remain unchanged; successful request handling still disconnects and deletes the store. See [first-observed Logout, lines 751–795](https://github.com/tulir/whatsmeow/blob/1956f9683795cfb695f2e5d37ee5818c9961d266/client.go#L751-L795).

OWA is a WhatsApp Web client, as documented in `README.md:3`; `Socket_Config` (`socket.odin:65`) and `Payload_Config` (`protobuf.odin:541`) expose no Messenger mode. A search across owned runtime Odin files finds no Messenger configuration or logout/remove-companion-device API (the generic binary dictionary contains Facebook token strings, which is not an implemented Messenger mode). OWA's session closure is local transport shutdown (`pairing.odin:595`), not a remote-device logout implementation.

**Disposition: no action for OWA's supported WhatsApp scope.** Adding Facebook Messenger support or a new remote logout API would be a separate feature decision, not a compatibility repair justified by this observation. Do not send remote logout requests as a test.

## Second observation: keepalive debug-log filtering

The first-to-second-observed diff adds `lastKeepAliveID` and guards the existing receive/send debug logs with `isKeepAliveNode`. The same parsed node continues through the existing receive handlers; the same serialized payload is returned to `sock.SendFrame`. No keepalive wire payload, scheduling or timeout change appears in the monitored file. See [field at line 203](https://github.com/tulir/whatsmeow/blob/fcb7bdeb35921905b60984025945a571eb8f39b6/client.go#L203), [receive path lines 891–916](https://github.com/tulir/whatsmeow/blob/fcb7bdeb35921905b60984025945a571eb8f39b6/client.go#L891-L916), and [send path lines 1005–1013](https://github.com/tulir/whatsmeow/blob/fcb7bdeb35921905b60984025945a571eb8f39b6/client.go#L1005-L1013).

OWA has no built-in all-node send/receive debug logger in these paths. It already constructs keepalives in `session_keepalive` (`pairing.odin:710`) and schedules them independently in `session_tick` (`pairing.odin:538`). The optional node observer is an application-selected callback (`pairing.odin:59`, `pairing.odin:325`), not the upstream built-in logger. Preserving observer visibility remains appropriate; globally hiding keepalives from that callback would change a different API contract.

**Disposition: no action.** This is upstream observability noise reduction with no corresponding built-in OWA logging behavior to repair. No native regression test is warranted for an unchanged runtime. If a caller later adds broad node logging, it can filter ping observations as a caller policy and test that logging policy locally.

## Validation and limits

Reviewed both complete adjacent diffs, the full changed function contexts, and corresponding owned API/keepalive/transport paths; verified all three source hashes against the recorded reports. Local receipt: `whatsmeow/review-receipt.json`; exact adjacent patches: `whatsmeow/c88388f9-1956f968.patch` and `whatsmeow/1956f968-fcb7bdeb.patch` under the same evidence directory.

No upstream code was executed, no runtime code was modified, no compiler/native/live tests were run for this static no-action determination, and no account, session, messages or logout operations were accessed. Changes in unmonitored files or server-only changes remain outside this review. In particular, the helper's implementation elsewhere is not claimed reviewed; its use in these monitored `client.go` deltas is limited to log guards.
