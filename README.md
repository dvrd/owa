# Native WhatsApp client

This package implements the WhatsApp Web protocol in Odin: authenticated
TLS/WebSocket transport, Noise, Signal sessions and group Sender Keys,
pairing/prekeys, persistent protocol state, group messages and image/document
media. It is an unofficial protocol client, with a pinned Baileys 6.7.23
reference and independent synthetic fixtures. It is not Meta's Cloud API.

## Reliability contracts

- Keep `Socket`, auth and stores at stable addresses. One caller owns the
  socket/event pump; HTTP workers do not access its mutable protocol state.
- Reconnect with a fresh socket and the same persisted auth, prekeys and state.
  Preserve the entire set together. Server login success alone is not Online.
- Sending returns an owned message ID. Retain any nonempty ID even on error:
  persistence can succeed before the wire write fails. Pending messages retain
  their original encrypted stanza for recovery; local send success is not
  delivery or application completion.
- Explicit IDs identify immutable destination/media/content while retained.
  Conflicting reuse fails before replacing pending intent. An ordinary repeat
  of identical pending content reuses the saved packet rather than advancing
  Signal state. Receipt-triggered per-device retries retain their separate
  membership/identity checks and encryption path. Retained content without a
  pending packet is not, by itself, an authoritative delivery receipt.
- Incoming application messages remain in the durable inbox until the caller
  invokes `socket_message_complete`. Destroying the owned message alone does
  not establish that its business operation completed. The application must
  deduplicate its own external effects across crash recovery.
- Media downloads authenticate encrypted hash, MAC, length and plaintext hash
  before exposing bytes. Upload host fallback shares one timeout budget; zero
  selects 30 seconds. Earlier uncertain upload effects remain uncertain even
  if a later host fails before sending. Injected executors must honor supplied
  bounds and deadlines; they cannot be forcibly interrupted by this package.

## Authentication policy

Trusted TLS roots are required. `Socket_Config.verify_certificate` optionally
passes the decrypted Noise certificate payload and server static key to the
existing `Certificate_Verifier` callback. A rejection terminates the handshake
before ClientFinish. Callback input borrows handshake storage for that call.

Nil selects native verification of root/intermediate/leaf signatures, issuer
linkage, validity windows and constant-time leaf-key binding to the decrypted
Noise server static key. Signatures cover the original serialized details.
The pinned public root and policy provenance are recorded in
`tests/certificate_policy/root-pin.json`, from pinned Whatsmeow and Baileys
sources. A genuine public server certificate independently verified with
Whatsmeow/libsignal qualifies this implementation against the published pin;
this does not establish an independent Meta trust-distribution guarantee.

`strict_certificate_policy_at` accepts an explicit clock for deterministic
qualification. Normal handshakes use the system clock. Explicit verifier callbacks
replace this policy and own their trust decisions. `baileys_certificate_policy`
retains the old issuer-only behavior for explicit compatibility fixtures; it
does not verify signatures, key binding or validity and is not the default.
The synthetic TCP fixture selects that compatibility callback explicitly;
separate genuine-chain tests exercise the strict policy. None of these tests
constitutes an independent cryptographic audit.

## Offline checks

From the parent shared directory, use its matching compiler:

```sh
../odin test whatsapp -vet -warnings-as-errors -sanitize:address \
  -define:ODIN_TEST_THREADS=1 -out:/tmp/whatsapp-unit
python3 whatsapp/tests/loopback_noise/run.py --odin "$PWD/../odin" \
  --shared-root "$PWD" --sanitize address --report /tmp/whatsapp-loopback.json
```

The maintained loopback fixture uses synthetic public keys/transcripts and a
test-owned TCP listener. See its README for exact coverage and exclusions.
It never pairs an account or sends an external WhatsApp message.

## Remaining qualification

Passing fixtures and loopback do not establish current service interoperability.
Before broad operational reliance, qualify an explicitly authorized test account
and isolated group: pairing/restart, sustained receipt/delivery processing,
disconnect/reconnect, process termination around persistence, media expiration,
device changes and key rotation. Retain source-bound, redacted evidence without
credentials, account identifiers, message contents or private session material.
Independent crypto review and ongoing protocol-version tracking remain necessary.

Current scope excludes calls, audio/video/stickers, polls, group administration
and full history/contact import. These are feature boundaries, not live-provider
failure claims. Mesa installs its own source copy; changing this repository alone
does not update the application.
