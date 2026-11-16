# Reviewed OWA reliability updates — 2026-11-15

The nine recorded upstream observations were reviewed against owned source and organized into focused work. All five follow-ups have verified finite acceptance in Linear.

| Issue | Result | Local owning commit | Evidence |
| --- | --- | --- | --- |
| OKAMI-425 | Unsupported/mixed ciphertext receives negative ACK without durable success | ebe2189 | [Receive](unsupported-encryption-20261115.md) |
| OKAMI-426 | Current hosted pairing domains and explicit preserved Legacy auth policy | 02f673a | [Pairing](pairing-domains-20261115.md) |
| OKAMI-427 | Atomic sender PN/LID discovery before canonical lookup, pin-safe migration | 7c82682 | [Aliases](inbound-alias-20261115.md) |
| OKAMI-428 | Opt-in current linked-device QR format, legacy defaults preserved | c3908ef | [QR](linked-device-qr-20261115.md) |
| OKAMI-429 | Existing bounded prekey policy qualified; no runtime patch justified | 6f6441f | [Prekeys](prekey-lifecycle-20261115.md) |

Final integrated qualification passes78 optimized AddressSanitizer tests with strict vet/warnings and allocation tracking, four owned localhost Noise modes, an optimized ASan API consumer and11 encrypted native-TCP crash/recovery boundaries. The final physical closure matches current ascii9dc54364, asyncddb7c48c, http4b619c7e, surf2e3bedd8 and websocket57ced4f2. Tests use the previously accepted isolated matched compiler949d528/SHA654bec73 and its own standard library; the installed compiler and Mesa SDK/pins are unchanged. Source hashes and compressed logs are retained in [the final receipt](evidence/prekey-lifecycle-20261115/receipt.json).

Historical auth state remains readable; newly saved format2 requires the updated reader. There is no signature-domain guessing, automatic re-signing or real-account migration in this work. The QR change is explicitly opt-in; protocol version, login payload and advertised capabilities remain at their existing defaults.

Evidence is Darwin arm64 and synthetic/local. No upstream code, live account/session, phone pairing or external messages were used. No Linux/current-service interoperability claim or application vendor-copy/deployment integration is implied. Commits remain local. The separate tooling-only candidate (OKAMI-424, head0e1d22c) was subsequently published through PR1 and its real scan/handoff verified; see [publication evidence](protocol-triage-publication-20261116.md). The newer runtime fixes and coupled local ownership refinements remain unpublished.
