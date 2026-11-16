# Hosted pairing signature domains

OKAMI-426 changes new pair-success processing to distinguish the HMAC wrapper account type from the signed device type. The immutable reviewed Baileys revision `81345beb67ca3fb0eb79a2c20cd4ac24da517929` defines ordinary account `[6,0]`, companion `[6,1]`, hosted account `[6,5]` and historical hosted companion `[6,6]` in [Defaults/index.ts, lines18–21](https://github.com/WhiskeySockets/Baileys/blob/81345beb67ca3fb0eb79a2c20cd4ac24da517929/src/Defaults/index.ts#L18-L21). [Its pair-success validator](https://github.com/WhiskeySockets/Baileys/blob/81345beb67ca3fb0eb79a2c20cd4ac24da517929/src/Utils/validate-connection.ts#L184-L218) uses wrapper accountType for HMAC only, signed ADVDeviceIdentity.deviceType for the account signature, and standard companion domain for the generated signature.

New pairings select `Pairing_Signature_Policy.Current`. Unknown wrapper types, unknown current signed device types, altered HMAC/details or invalid signatures fail before publishing account state. Companion signatures always use `[6,1]`. Validation never retries other domains.

## Persistence and compatibility

Auth format2 adds one explicit signature-policy byte following the hosted byte for a valid account. Old format1 loads deterministically as `Legacy`, with exactly the historical ordinary-account domain and wrapper-dependent companion domain. Re-encoding writes format2 while retaining `Legacy` and the original signatures. New `Current` accounts retain Current on save/load. Both signatures remain mandatory under either explicitly selected policy; there is no permissive domain fallback and no automatic re-signing.

**Old binaries cannot read auth format2.** Source/runtime and state format must be upgraded together. Rolling code back after a format2 write requires a separately reviewed compatibility plan; do not roll back live authentication or Signal state. This change did not read, rewrite or migrate any real account files. All file operations in the regressions use newly created temporary synthetic files.

Unregistered format1 state (no account/policy bytes) remains readable. Invalid versions/policies, malformed or truncated bodies and rejected signatures leave the decode destination unchanged. The existing checksum remains corruption detection, not authentication or encryption of state.

## Validation

The new wrapper/signed-device matrix failed against the unchanged runtime: hosted signed identities were rejected under the ordinary account domain, and wrapper-hosted companions had the obsolete `[6,6]` domain. The remaining49 baseline package tests passed. The fix then passed all57 package tests, including8 new methods, and the full package under AddressSanitizer. See [the receipt](evidence/pairing-domains-20261115/receipt.json) and retained compressed logs.

Coverage includes ordinary/hosted wrapper×signed-device combinations plus an absent device-type default; current-domain tamper/unknown-enum refusal; all four historical wrapper/device combinations; v1 decode→v2 rewrite without re-signing; current and legacy real temporary disk save/load; invalid policy/version/truncation atomicity; and unregistered v1 state. Ordinary historical and current domains intentionally coincide, while hosted differences do not gain fallback acceptance.

These are owned synthetic and package tests, not live hosted-account interoperability. No upstream source was executed, account/session accessed, messages sent, protocol version changed or Mesa vendor copy integrated. The earlier unfinished external oracle worktree was preserved and was not used as evidence. Root-owned loopback/consumer qualification is recorded separately before accepting the issue.

Root acceptance: all owned source/test hashes match the57-test receipt; four ASan localhost Noise modes and executable ASan consumer pass. [Root acceptance](evidence/pairing-domains-20261115/root-acceptance.json).
