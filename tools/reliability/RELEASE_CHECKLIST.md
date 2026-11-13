# Manual OWA release qualification

Routine maintenance uses GitHub-hosted CI and the daily public protocol scan.
There is no required server, local timer, automated live send or continuous soak.
OWA does not depend on Mesa's server, credentials or application checkout.

Before a release, or after a significant protocol change:

1. Record the exact candidate commit and matching native CI run. Require both
   Linux/macOS sanitizer jobs, synthetic wire/recovery checks and consumer checks
   to pass. Resolve relevant upstream-review issues; scan success alone does not
   establish compatibility. Do not substitute a CI run from older runtime code.
2. Use one explicitly authorized test session and the isolated `botlab` group.
   Verify the group identity before sending. Keep the session outside Git and CI;
   never copy/fork it between concurrent processes or roll its keys/state back.
   New accounts or destinations require their own authorization.
3. With the reviewed live tool, connect using that session. Send one synthetic
   text and one small PDF to the verified group. Record server ACKs separately
   from the recipient's confirmation that both arrived once and the PDF opens.
4. Stop cleanly and reopen the same persisted session with the same candidate.
   Verify it reconnects and does not duplicate the prior pair. An uncertain send
   requires inspection of its original durable ID; do not create replacement
   intent or clear state to obtain a passing result.
5. Record candidate/binary/compiler identities, CI and upstream-review links,
   observation duration, restart outcome, recipient confirmation and duplicate
   count in private, redacted release evidence. Keep account identifiers, message
   contents, credentials, QR payloads and session files out of public artifacts.
   Use the existing promotion gate when preparing integration receipts.

A failed or incomplete check blocks live interoperability qualification for that
candidate. Open a scoped Webtools issue with redacted evidence and reproduce it
with an offline fixture where possible. Do not silently retry ambiguous effects.

These checks establish bounded observations only. Uninterrupted 24-hour
connectivity, automatic recovery from every service change, media expiration,
device/key rotation and independent cryptographic review remain unqualified
unless separately tested. Optional soak/deployment helpers retain their original
strict acceptance rules; this policy does not relabel any failed soak as passed.
