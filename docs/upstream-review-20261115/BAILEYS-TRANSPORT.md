# Baileys transport/authentication triage — 2026-11-15

Reviewed owned OWA `b90209116c13427c00d65b55996affbac0cdcc38` and the exact historical Baileys reference `e05b16b4aa0d7d3eb2594677e015454af1225b75` versus observed `81345beb67ca3fb0eb79a2c20cd4ac24da517929`. Scope is four files: socket.ts, validate-connection.ts, noise-handler.ts, baileys-version.json. This is a static compatibility investigation; no upstream code, account, message, or live server was executed/accessed. No tests were run by this reviewer.

## Decision

A blanket “update WhatsApp” is unjustified. Most transport changes are JavaScript implementation refactors or optional APIs. One concrete hosted-identity interoperability mismatch merits a focused implementation issue. Login/LID initialization and ancillary initialization features merit scoped spikes because a newer upstream implementation is not proof the existing tested personal-account profile requires the change. Nothing here proves live regression or universal compatibility.

## Ready to implement: hosted pairing identity prefix semantics

Current Baileys [`validate-connection.ts` lines184–218](https://github.com/WhiskeySockets/Baileys/blob/81345beb67ca3fb0eb79a2c20cd4ac24da517929/src/Utils/validate-connection.ts#L184-L218) separates three concepts: wrapper accountType selects the account-HMAC prefix; signed ADVDeviceIdentity.deviceType selects the account-signature prefix; the generated companion device signature always uses the standard device-signature prefix. The old implementation derived the companion prefix from wrapper account type and always used the ordinary account-signature prefix.

OWA retains the old distinction at `pairing.odin:1128`, `pairing.odin:1269`–`1297`, and `pairing.odin:1424`–`1454`. It already decodes the signed `device_type` at `protobuf.odin:1135`–`1184`, but discards that choice when calling `pairing_success_signatures_prepare`: the function receives only `wrapper.account_type`. A valid current hosted-device identity will therefore encounter the wrong account-signature domain, and wrapper-hosted companions generate the old device-signature domain. Both initial pairing and persisted-account validation must be reviewed together; changing only initial verification would break reloading.

Proposed task: align signed-identity domain selection with signed deviceType while preserving historical persisted account readability under an explicitly versioned policy. Preserve HMAC validation and mandatory signature verification; never add a “try any prefix” acceptance fallback. Derive exact constant bytes from the pinned upstream Defaults declarations during implementation (the four-file scope did not fetch those declarations).

Acceptance:

1. Generate owned synthetic identity fixtures for ordinary and hosted signed deviceType, independently varying wrapper accountType; prove account signature uses signed deviceType rather than wrapper accountType.
2. Verify generated companion device signature uses the standard companion domain; reject altered HMAC, account signature, signed details and unrelated domains.
3. Test account encode/save/load validation with current and historical fixture states; document any storage-version migration and preserve old state files. Never roll back live Signal/auth state.
4. Execute focused package tests and owned loopback Noise/consumer checks against the changed code. A fresh hosted live pairing would add interoperability evidence but is not assumed or authorized by this review.

This is a concrete source-supported feature gap in OWA's advertised hosted parsing; it is not evidence the user's working ordinary account is currently broken.

## Four-file coverage matrix

| Difference | Owned implementation evidence | Disposition |
| --- | --- | --- |
| Noise handler now verifies intermediate and leaf signatures | `connection.odin:592`–`616` already validates both signatures against the pinned root, leaf/server-static binding, serial chain and validity times; `certificate_policy_test.odin` and `socket_certificate_verifier_test.odin` exist | Already covered; do not port weaker/different upstream checks |
| Noise splits synchronous handshake keys into independent transport counters, removes handshake AAD, buffers while JS async split runs | `connection.odin:1518`–`1575` synchronously derives/splits, rejects second split, and resets directional counters; `connection.odin:1658`–`1693` selects transport receive counter and handshake-only AAD. Owned code has no asynchronous split window | Refactor already substantively covered; no JS buffering port justified |
| Faster frame handling, preallocated IV/introduction buffers, async event teardown | Native owner has explicit bounded client/socket/session lifecycle, not JS promises/event emitters | Implementation-specific; no required protocol update |
| Query timeout catches return undefined and event-listener cleanup changes | Native provisioning/request state validates response IDs, has explicit deadline/error paths; no JS listener model | Do not port changed error swallowing; retain native fail-closed behavior |
| Prekey generation persisted before upload; in-flight upload reuse; retry self-deadlock fix | `socket.odin:598`–`640` persists pending keys before write, `auth.odin:778`–`861` prepares/retries pending IDs; socket state machine serializes provisioning | Core safety objective already covered |
| Prekey count-dependent upload size, missing-last-key check, digest and signed-prekey rotation helpers | Native refresh currently uses threshold/pending-batch state (`socket.odin:598`); count notification `socket.odin:900`–`920`. No new digest/rotation helper found in owned source | Scope as key-lifecycle spike: assess stock exhaustion and durable rotation contract, not copy retries blindly |
| Pairing and login LID-PN storage/migration | Native login persists `LID_Mapping/self` at `socket.odin:519`–`540`; `Paired_Account` at `pairing.odin:789` does not retain pair-success LID. Current upstream stores explicit PN↔LID mapping/device list and migrates self Signal session (`socket.ts:959`–`983`) | Partial coverage, important scoped LID interoperability spike; include addressing owner review before declaring a fix |
| Login passive false→true and explicit lidDbMigrated:false | Native common payload still explicitly passive false (`protobuf.odin:813`), no migration field (`protobuf.odin:825` onward) | Deliberate historical payload diverges. Spike: determine required login sequence with owned reference decode/fixture and controlled qualification; do not infer server requirement from diff alone |
| Android userAgent/omitted webInfo; Windows WIN32→WIN_HYBRID; Desktop guard; platform fallback CHROME; pushName and extra DeviceProps/version fields | Native payload fixed WEB (`protobuf.odin:777`); Windows4 and no Desktop guard (`protobuf.odin:788`); DeviceProps encodes pinned historical fields (`protobuf.odin:712`–`750`) | Browser/profile feature gaps, not demonstrated regression for existing WEB profile. Group into payload-profile spike with explicit supported-profile decision |
| QR data construction moved to buildPairingQRData(browser) | Native QR explicitly four fields at `pairing.odin:922`–`950`. New helper implementation is outside the fetched four-file scope | Remains narrow uncertainty: helper inspection needed before asserting QR format change; no blanket QR fix justified |
| Server time offset and unified_session telemetry after pair/login | No matching native telemetry helper found. Upstream explicitly calls it telemetry and catches failure (`socket.ts:1067`–`1112`) | Optional telemetry, not mandatory connection behavior established; no automatic port |
| New usync helpers/onWhatsApp, account restriction/new-chat cap query APIs, WAM buffer/export helpers | New APIs rather than observed transport compatibility requirement | Optional feature backlog only if product needs them; no eager requests or restriction circumvention |
| Optional routing-info ED introduction | Native explicitly excludes it (`connection.odin:1059`); existing Baileys routing behavior predates this diff | Existing declared scope, not a newly introduced gap |
| Version JSON `[2,3000,1023223821]`→`[2,3000,1043857760]` | Pinned default at `pairing.odin:121`; explicit caller version and opt-in discovery at `pairing.odin:2106`–`2154` | Existing selection/discovery handles version choice. No automatic pin bump without runtime qualification |

## Primary references

- [Observed socket implementation](https://github.com/WhiskeySockets/Baileys/blob/81345beb67ca3fb0eb79a2c20cd4ac24da517929/src/Socket/socket.ts).
- [Historical socket implementation](https://github.com/WhiskeySockets/Baileys/blob/e05b16b4aa0d7d3eb2594677e015454af1225b75/src/Socket/socket.ts).
- [Observed validation](https://github.com/WhiskeySockets/Baileys/blob/81345beb67ca3fb0eb79a2c20cd4ac24da517929/src/Utils/validate-connection.ts).
- [Observed Noise](https://github.com/WhiskeySockets/Baileys/blob/81345beb67ca3fb0eb79a2c20cd4ac24da517929/src/Utils/noise-handler.ts).
- [Observed version](https://github.com/WhiskeySockets/Baileys/blob/81345beb67ca3fb0eb79a2c20cd4ac24da517929/src/Defaults/baileys-version.json).

Immutable downloaded source hashes are in the root review's `sources.json`; local evidence above refers to clean owned OWA b902091. This report does not review messages-send/messages-recv/WAProto (another reviewer/root owns that scope), nor default-branch changes after the issue's observed revisions.
