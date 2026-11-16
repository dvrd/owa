# OKAMI-427: authenticated inbound PN/LID discovery policy

Reviewed 2026-11-15 against clean owned OWA `b90209116c13427c00d65b55996affbac0cdcc38` and pinned Baileys `81345beb67ca3fb0eb79a2c20cd4ac24da517929`. Static investigation only; no runtime source edited, native tests executed, accounts accessed, messages sent or upstream code executed.

## Decision

A focused inbound-alias fix is justified. The missing path is demonstrated in owned receive control flow; its authoritative envelope contract is now available from the pinned upstream decoder. This is not a requirement to change OWA's canonical PN-backed record layout or to adopt newer protocol/version defaults. Implementation should stage alias discovery atomically with successful existing decryption and reuse current mapping-conflict/identity-pin enforcement.

## Exact upstream contract

[`extractAddressingContext`, decoder lines106–132](https://github.com/WhiskeySockets/Baileys/blob/81345beb67ca3fb0eb79a2c20cd4ac24da517929/src/Utils/decode-wa-message.ts#L106-L132) selects sender as stanza participant, otherwise from. Explicit `addressing_mode` chooses `lid` versus `pn`; absent mode is derived from the sender domain. LID mode selects an alternate PN from `participant_pn`, `sender_pn`, then `peer_recipient_pn`; PN mode selects an alternate LID from `participant_lid`, `sender_lid`, then `peer_recipient_lid`. Recipient aliases are separately decoded and must not be confused with sender aliases. [`decodeMessageNode`, lines228–241](https://github.com/WhiskeySockets/Baileys/blob/81345beb67ca3fb0eb79a2c20cd4ac24da517929/src/Utils/decode-wa-message.ts#L228-L241) attaches senderAlt to participantAlt in groups or remoteJidAlt otherwise.

**Important device detail:** comments identify the alternate as lacking device data; transferDevice is explicitly commented out. Therefore a sender `LID:device@lid` with a bare `PN@s.whatsapp.net` must not be rejected merely because alternate device=0. Normalize mapping identity to bare PN/LID, then preserve the primary sender's device for cryptographic state selection. A nonzero alternate device inconsistent with the primary must be refused rather than silently reassigned.

[`messages-recv.ts`, lines1604–1621](https://github.com/WhiskeySockets/Baileys/blob/81345beb67ca3fb0eb79a2c20cd4ac24da517929/src/Socket/messages-recv.ts#L1604-L1621) records the alias and migrates session before calling decrypt. The decoder's `storeMappingFromEnvelope` lines31–50 also learns PN→LID before decryption. OWA should preserve stronger atomicity than copying the upstream eager persistence literally.

## Owned gap and existing safeguards

- `receive.odin:257–283` validates group/from/participant/id but never ingests alternate-address fields.
- `receive.odin:979–992` computes inbox identity from the existing original socket store; adding migration only later in payload decryption would leave duplicate keys inconsistent.
- `receive.odin:471–519` resolves signal address against the provided staged candidate store, so decryption already has an appropriate isolated store seam.
- `addressing.odin:1147–1203` has bounded PN/LID syntax, same-device validation, reverse mappings and conflict refusal. Supply normalized bare identities because envelope alternate identifiers commonly omit device data.
- `addressing.odin:1205–1289` migrates Identity before Session and validates session remote identity against the destination pin. `addressing.odin:1349–1445` refuses identity collisions, archives compatible sessions and remaps inbox/processed keys. Reuse these safeguards.
- `socket_record_lid_mapping` commits independently; **do not call it eagerly from receive**, because malformed ciphertext could otherwise persist alias hints. Use `socket_lid_mapping_stage` and `socket_lid_migrate` inside the existing message candidate.

A source-level counterexample is an incoming group stanza whose participant is an unknown LID and whose participant_pn is an already pinned PN with a valid persisted pairwise session. No prior group-metadata fetch occurred. Existing receive resolves the unknown LID literally and fails to find the PN session, despite the authoritative envelope carrying its alternate. The inverse case with a session stored under LID also requires migration to the canonical PN layout. This counterexample needs an owned encrypted fixture before claiming execution evidence.

## Minimal implementation policy

1. Validate original message route and supported encrypted-content policy first. Status/unsupported/unavailable stanzas must not gain independent mapping commits.
2. Parse bounded sender alternate hints only for the authenticated message route. Distinguish group participant and direct sender contexts. Explicit addressing_mode must agree with primary domain; alternate must use the opposite ordinary PN/LID domain. Normalize c.us to s.whatsapp.net. Reject conflicting recognized aliases, invalid/mismatched domains and nonzero device disagreement; do not silently select among conflicting claims.
3. Treat these fields as metadata authenticated by the existing server Noise transport, not as independent cryptographic proof. Mandatory signal identity pins and ciphertext authentication remain the final gate. Mapping headers never bypass existing pin checks or establish that a message decrypted.
4. Clone candidate, stage bare PN/LID mapping and invoke existing pin-safe migration against the original store. Compute canonical inbox key and duplicate/inbox lookups against that candidate, retaining primary device suffix. Do not mutate original state during validation.
5. Decrypt/install distribution into candidate using the existing owned receiver. Persist mapping, migrated state, ratchet and inbox/processed success in the same existing successful commit. On decryption, identity, parse or persistence failure, preserve original records and no success receipt/event.
6. Existing durable duplicates may remain no-op/acknowledged without separately committing new hints; there is no need to create a successful mapping side effect from duplicate metadata.
7. Document supported sender hint fields. If limiting the initial fix to ordinary group participant/direct sender aliases, explicitly exclude hosted/peer-recipient shapes pending a fixture; do not guess their authority or silently reinterpret recipient aliases as sender aliases.

## Required owned regression evidence

- Direct and group PN→LID and LID→PN, existing session before any metadata query, primary nonzero device with bare alternate.
- Existing reciprocal mapping is unchanged; no-hint path unchanged; missing optional hint is allowed.
- Same primary represented under alternate route produces one canonical inbox/event across duplicate delivery and reconnect.
- Malformed domains/IDs, explicit mode mismatch, conflicting hints, unrelated nonzero device suffix and opposite cryptographic identity pins are refused with original state unchanged.
- Decryption failure and save failure leave mapping/Identity/Session/inbox/revision unchanged and do not send a successful delivery claim.
- Supported distribution-only control remains valid; unknown/msmsg handling from OKAMI-425 is not reintroduced as a success path.
- Run focused owned unit/ASan and encrypted loopback plus consumer checks for the candidate. These tests are proposed acceptance, not executed by this review.

## Self-login boundary

Current `socket_login_provision_start` (`socket.odin:514–540`) stores a self LID marker and `socket_sender_is_self` uses it. Upstream also stores reciprocal self mapping and migrates its session (`socket.ts:959–983`); source difference alone does not demonstrate that every OWA self session requires that path. No separate eager self-login change is required to fix the incoming-peer counterexample. Keep it out of the minimal receive fix unless a synthetic self-session case establishes a second requirement. Also note current login self marker save uses direct store mutation; any later atomicity fix should be separately reproduced and scoped.

## Source integrity

Decoder fetched by root for this expressly requested investigation. SHA256: `f700193d37723fd69a5e7558531408817a9a88f39b1db4d6eceff3c739e616a1`. Other exact source hashes are retained by the preceding review manifest. This result resolves the policy question and supplies a ready focused implementation plan; it does not claim that implementation or live qualification has occurred.
