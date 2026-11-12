# Public Noise certificate qualification

`certificate.bin` and `server-static.bin` are public server-authentication data
captured from `web.whatsapp.com` over verified native system TLS, WebSocket and
Noise on 2026-11-12. The probe sent only its independently generated ClientHello
and protocol controls, rejected the certificate deliberately before ClientFinish,
and used no account credentials, session stores or messages. No private Noise key
was persisted. See `capture.json`.

The 241-byte certificate has SHA256
`3321532755975827b85240de9072caf92a9c440261d81077c5b6eab8ec30644b`.
The controlled test time is capture Unix milliseconds `1794504045498`. Tests use
that time so the captured chain can qualify the verifier after its real expiry;
this is not a perpetual live-validity assertion.

An independent Go oracle ran the exact pinned Whatsmeow certificate verifier
with actual `go.mau.fi/libsignal v0.2.2`; both signatures, issuer linkage, static-key
binding and validity passed. Its dependency/build receipt and result are in
`whatsmeow-verification.json`.

The production root is the identical published Signal Curve25519 key in:

- [Whatsmeow handshake.go, c88388f983b4bc43dfd0bcc2b46969fcde82d61f](https://github.com/tulir/whatsmeow/blob/c88388f983b4bc43dfd0bcc2b46969fcde82d61f/handshake.go).
- [Baileys Defaults, 81345beb67ca3fb0eb79a2c20cd4ac24da517929](https://github.com/WhiskeySockets/Baileys/blob/81345beb67ca3fb0eb79a2c20cd4ac24da517929/src/Defaults/index.ts).

`root-pin.json` records the key and source hashes. The strict policy verifies the
original protobuf detail bytes using Signal signatures, not raw Ed25519.
