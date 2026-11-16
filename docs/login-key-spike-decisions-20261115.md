# OWA login/profile and prekey spike decisions — 2026-11-15

Owned baseline: OWA `b90209116c13427c00d65b55996affbac0cdcc38`. Reviewed Baileys immutable observation `81345beb67ca3fb0eb79a2c20cd4ac24da517929` versus historical `e05b16b4aa0d7d3eb2594677e015454af1225b75`. This is a bounded static source review. No compiler/runtime/live tests, upstream execution, accounts, session state or messages were used. Acceptance scenarios mentioned below are reasoning and proposed future tests, not executed results.

## OKAMI-428 — login payload and pairing profile

**Disposition: resolve the login/profile questions as no automatic payload change, and implement one narrowly scoped QR compatibility extension under an explicit format policy.** A current QR representation is demonstrably missing; legacy QR support is not proven broken.

### Concrete QR format support gap

The exact pinned [companion registration helper](https://github.com/WhiskeySockets/Baileys/blob/81345beb67ca3fb0eb79a2c20cd4ac24da517929/src/Utils/companion-reg-client-utils.ts#L37-L47) builds a linked-device URL: the `https://wa.me/settings/linked_devices#` prefix followed by five comma-separated fields (reference, base64 Noise public key, identity public key, ADV secret, companion web-client type). OWA `pairing_qr_encode` (`pairing.odin:922–950`) writes only the historical four comma-separated fields and accepts no companion/profile argument. This is an exact encoder feature gap, not a guess about a new field's wire meaning.

The helper defines a companion-web-client enum separate from DeviceProps.PlatformType. Its mapping is Chrome1, Edge2, Firefox3, IE4, Opera5, Safari6, Desktop/Windows8, Desktop/otherOS7, and other9 (`companion-reg-client-utils.ts:3–35`). Do not reuse the DeviceProps platform enum: the numeric spaces describe different concepts.

Ready implementation acceptance:

1. Define explicit legacy and current linked-device QR format selection. Retain the existing four-field encoding API/default for source and existing account/profile compatibility; expose a current-format API or clearly named opt-in format on session configuration.
2. Current output exactly matches the reviewed URL prefix, all five fields and companion mapping. Test every mapping, especially Windows Desktop8 versus other Desktop7 and unknown9. Do not infer Android profile support from the browser string.
3. Preserve reference validation, key base64 and deterministic required-size reporting, with destination unchanged on undersized/invalid inputs. Test prefix/extra-field size boundaries and repeated QR references.
4. Plumb selected format/profile through the owned QR event without changing credential/private state or global payload/passive/version defaults. Regression tests prove existing legacy output unchanged.
5. Qualify the owned encoder/session tests and consumer/loopback. Static byte parity is not live phone scan interoperability; do not claim the old QR is rejected or run a new pairing without the relevant account authorization.

Root fetched this precise extra helper and browser-utils.ts under the same immutable observation after the original four-file review flagged the unknown helper. No helper code was executed. The source digest is recorded below.

### Login/profile payload differences

The [observed login builder](https://github.com/WhiskeySockets/Baileys/blob/81345beb67ca3fb0eb79a2c20cd4ac24da517929/src/Utils/validate-connection.ts#L74-L86) changes `passive` to true and emits `lidDbMigrated:false`. The latter is explicitly marked an investigated-later choice by its owner. OWA `protobuf.odin:762–832` deliberately preserves its pinned historical login and registration encoding, including explicit passive false and login pull true. The available sources establish different initialization policy, not that OWA's current qualified WEB account profile requires a different server contract. PN/LID alias/session authority and migration are separately owned by OKAMI-427, so this issue must not create a second copy of that work.

Observed `getUserAgent/getWebInfo/getPlatformType` additionally support Android, select WIN_HYBRID only for Windows Desktop full-history profiles, and use CHROME fallback. OWA `Payload_Config` (`protobuf.odin:541`) exposes browser strings but `payload_common` currently encodes WEB; the historical Windows full-history value4 remains a declared WIN32 enum in the observed schema (WIN_HYBRID is5). These are profile/feature policy differences, not a universal reason to rewrite every existing WEB payload. A future Android/Desktop API should use an explicit profile contract and fixture-bound registration/login tests rather than interpreting a browser label as permission to impersonate another platform.

The new DeviceProps version and history capability fields in [observed registration](https://github.com/WhiskeySockets/Baileys/blob/81345beb67ca3fb0eb79a2c20cd4ac24da517929/src/Utils/validate-connection.ts#L100-L158) advertise optional behavior. OWA `device_props_encode` (`protobuf.odin:712–750`) preserves historical fields and unknown-field skipping in decoders. Copying additional capability assertions without their corresponding implementation is not an interoperability repair. There is no observed login rejection, owned failing payload fixture, specified server requirement or profile-support request establishing a necessary change here.

Disposition for these non-QR differences: no automatic runtime change. Keep the historical default and its tested profile. This decision is limited to the source drift in the issue, not a guarantee against future server rollout. If a new requirement emerges, the next task must bind an exact registration/login field requirement, test unsupported/accepted profile selection, decode round-trip the owned payload and separately qualify the intended account/profile. No automatic version bump is justified.

## OKAMI-429 — prekey stock, digest and signed-key lifecycle

**Disposition: close the bounded spike as no immediate runtime change justified by the recorded source drift.** Existing owned mechanisms cover durable stock replenishment and retries; the additional source helpers do not establish a missing mandatory wire requirement. This is not a claim that all future signed-key lifecycle features are implemented.

### Stock exhaustion and failed-upload/reconnect safety are already represented

OWA `socket_provision_count` (`socket.odin:584–648`) validates a matching count response and replenishes when the server count is at/below5 or a pending batch exists. The upload batch is30 rather than the observed upstream initial/minimum-dependent batch. A zero count still enters the replenish branch; batch size affects reserve/performance, not whether replenishment occurs. Online server count notifications (`socket.odin:881–920`) trigger a fresh query when below5, rather than trusting the notification as a successful upload. Failure is surfaced through the explicit socket state machine; no success is invented.

`prekey_upload_prepare` (`auth.odin:778–835`) selects unpublished keys, generates only the missing suffix, marks a bounded contiguous Pending batch and advances a revision. `socket_provision_count` saves it before encoding or sending. `prekey_upload_validate` (`auth.odin:952–978`) refuses non-durable revisions. A failed write or lost response leaves the Pending batch; `prekey_upload_retry` (`auth.odin:837–870`) retains the private keys and IDs while changing only the persisted IQ correlation ID. `prekey_upload_handle_response` (`auth.odin:981–1023`) requires the matching successful IQ before changing keys to Published, followed by another save. This already avoids the JS in-flight-promise self-deadlock class because provisioning has one serialized owner and explicit stage.

### Missing highest ID is not the correct OWA corruption invariant

The [observed upstream check](https://github.com/WhiskeySockets/Baileys/blob/81345beb67ca3fb0eb79a2c20cd4ac24da517929/src/Socket/socket.ts#L544-L585) tests whether `nextPreKeyId - 1` exists and uploads if missing. OWA intentionally removes one-time keys after an independently durable consumed marker/session transaction: `socket_cleanup_consumed_prekeys` (`receive.odin:1277–1322`) and `prekey_store_remove_consumed` (`auth.odin:1634–1680`). A valid state can therefore have the last allocated key durably consumed and absent. Its absence alone is not proof of a damaged store or server inventory mismatch; blindly importing this check can cause needless key generation.

The owned store instead validates identity binding, sorted/nonduplicated allocated IDs, keypair consistency, pending contiguity and revision state (`auth.odin:1367–1490`). Reclamation skips pending keys and reclaims only authoritative consumed keys, preserving capacity without reusing their IDs. A bounded store reaching capacity or ID exhaustion returns an explicit error (`prekey_generation_validate`, `auth.odin:1493–1511`), rather than overwriting keys or silently reusing IDs. Additional monitoring for approaching capacity could be a future operational feature, but the observed source difference does not justify deleting unconsumed published private keys.

### Digest is a new health probe, not independently demonstrated bundle validation

The [observed `digestKeyBundle`](https://github.com/WhiskeySockets/Baileys/blob/81345beb67ca3fb0eb79a2c20cd4ac24da517929/src/Socket/socket.ts#L237-L249) sends an encrypt/get digest query and checks only for a `digest` child. It does not compare a local key hash or validate bundle contents in the reviewed function. Missing child causes upload and an error; login catches the error and continues (`socket.ts:939–950`). This optional probe adds diagnostic coverage but is not evidence that current count-query/durable-publication behavior is invalid. Porting it should not be described as cryptographic consistency verification.

### Signed-key rotation requires a separate retained-generation contract

The [observed `rotateSignedPreKey`](https://github.com/WhiskeySockets/Baileys/blob/81345beb67ca3fb0eb79a2c20cd4ac24da517929/src/Socket/socket.ts#L251-L270) is an exposed opt-in helper; the reviewed socket has no automatic invocation. It generates an incremented signed prekey, sends rotate, then emits credential update. Its comment promises a fallback not implemented in the function; source comments alone are not the contract. There is no expiry/lifetime requirement in the reviewed schema or helper proving that OWA must now rotate on a schedule.

OWA `Device_Credentials` currently stores one signed-prekey generation. `socket_pairwise_decrypt` (`receive.odin:614–624`) supplies that credential to prekey decryption, while existing established sessions have their own durable generation. The owned recovery fixture `recovery_rotated_signed_prekey_keeps_existing_session_generation` (`tests/encrypted_recovery/recovery_test.odin:140–195`) documents preserving established generations across independently supplied rotation; its presence is not proof of a server rotation API or retained old signed-key acceptance. Blindly replacing current credentials can make a delayed initiation for an old advertised signed key undecryptable. A future rotation feature must define bounded retained generations, monotonic IDs, crash/uncertain-ACK reconciliation, server activation versus local persistence, authenticated old-generation selection, expiration policy and delayed-message regression fixtures. None should be guessed from this source drift.

### Spike exit and future trigger

The issue's finite questions are answered: existing stock/refill and durable retry behavior maps to the new upstream safety goals; missing-highest-key cannot be imported as an OWA invariant; digest and rotation are optional APIs without a newly established requirement. No failing owned counterexample requiring a patch was found. No follow-up fix is created solely to make the implementations look identical. Reopen a focused requirement if an actual stock-replenishment failure, explicit key-expiry contract, unsupported account/profile requirement or bundle mismatch appears. Preserve the stronger owned pinning and durable state policy.

## Additional pinned helper integrity

- `browser-utils.ts`: 1009 bytes; SHA256 `4bb7f4d3a2ea0140a8cf6960ce10d48aa149233001d9e214449a5b9db08b9b0f`.
- `companion-reg-client-utils.ts`: 1325 bytes; SHA256 `f2320d7295339b838330f3389dcc4c35ce2c000263f92c977594961de3353514`.
