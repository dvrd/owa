# OWA upstream review — 2026-11-15

Reviewed all nine distinct observations recorded by OKAMI-412/422: seven Baileys file differences and two successive whatsmeow client.go differences. All 23 repeated before/after hash pairs in the original three reports match the fetched immutable sources. Owned baseline: `b90209116c13427c00d65b55996affbac0cdcc38`.

Two focused OWA fixes are justified. Neither whatsmeow observation requires an update for the current WhatsApp-only scope. Three separate questions remain spikes; no blanket protocol-version or generated-schema update is justified.

| Follow-up | Disposition | Scope |
| --- | --- | --- |
| [OKAMI-425](https://linear.app/devoured/issue/OKAMI-425/owa-reject-unsupported-encrypted-content-without-recording-delivery) | Todo | reject unsupported encrypted content without recording delivery success |
| [OKAMI-426](https://linear.app/devoured/issue/OKAMI-426/owa-align-hosted-pairing-signature-domains-with-signed-device-type) | Todo | align hosted pairing signature domains with signed device type |
| [OKAMI-427](https://linear.app/devoured/issue/OKAMI-427/owa-spike-define-authenticated-pnlid-discovery-and-session-migration) | Backlog | SPIKE — define authenticated PN/LID discovery and session migration |
| [OKAMI-428](https://linear.app/devoured/issue/OKAMI-428/owa-spike-assess-login-payload-and-pairing-profile-compatibility) | Backlog | SPIKE — assess login payload and pairing profile compatibility |
| [OKAMI-429](https://linear.app/devoured/issue/OKAMI-429/owa-spike-assess-prekey-stock-and-signed-key-lifecycle-gaps) | Backlog | SPIKE — assess prekey stock and signed-key lifecycle gaps |

The review spike OKAMI-412 is complete as triage and follow-up organization; its implementation tasks remain open. OKAMI-422 is complete as no action for its two recorded observations. OKAMI-423 remains a duplicate of422. These dispositions do not claim the fixes are implemented.

- [Message and schema review](BAILEYS-MESSAGES.md): unsupported encrypted content success-marking gap; authenticated PN/LID mapping question; existing/optional behavior.
- [Transport and pairing review](BAILEYS-TRANSPORT.md): hosted signature-domain mismatch, existing certificate/Noise/durable-prekey safeguards, unresolved initialization/profile/key lifecycle questions.
- [whatsmeow review](WHATSMeow.md): Messenger logout and keepalive logging changes have no corresponding OWA compatibility defect.
- [Immutable upstream source inventory](sources.json) and [owned-source/hash receipt](review-inputs.json).

This is static source evidence. No native tests, upstream code execution, live account/session operations, WhatsApp messages or runtime changes occurred. Proposed regressions are acceptance criteria for the follow-ups, not passing test results. The review covers the recorded revisions, not later upstream heads, server-only rollouts or every unmonitored helper. Local commits only; this review does not activate the separate pending workflow change or integrate vendor copies into Mesa.
