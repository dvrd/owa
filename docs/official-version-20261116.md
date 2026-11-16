# Official WhatsApp Web version discovery

Promoted Mesa's version-selection behavior into OWA. Runtime discovery makes one GET to `https://web.whatsapp.com/sw.js` through native Surf, extracts the exact unsigned `client_revision` literal and returns version `{2, 3000, revision}`. It no longer queries WPPConnect or Baileys version feeds. The browser User-Agent and Sec-Fetch-Site headers match the existing Mesa request contract.

The helper returns `.WhatsApp` on successful extraction and `.Pinned` with typed `fetch_error` on transport/status/body/parser failure. Existing tested compiled defaults remain the fallback; no automatic protocol-pin change occurs. Explicit application versions bypass discovery, and socket settings preserve supplied triplets. Caller TLS/deadline/redirect settings are forwarded. A tighter positive caller body limit is retained, with an absolute4MiB maximum; owned responses are released on every path.

The bounded allocation-free scanner accepts ordinary or singly escaped quotes, whitespace around the colon, u32 revisions above zero, and repeated identical declarations. It rejects conflicting declarations, mismatched quoting, noninteger/overflow/negative/zero values and numeric prefixes followed by junk. It requires a comma or closing object delimiter after optional whitespace, so an incomplete response is not adopted. Longer unrelated property names are ignored. This is exact literal extraction, not JavaScript execution or complete JavaScript parsing.

## API migration

`Web_Version_Source` is now `.WhatsApp`/`.Pinned`. `Web_Version_Result.fetch_error` replaces the two obsolete third-party attempt errors. Runtime third-party URL constants and JSON-feed decoding APIs were removed. The live-qualification caller already uses the `.Pinned` distinction and compiles unchanged. The separate public upstream maintenance monitor can still compare historical Baileys/whatsmeow code and version metadata; it never selects the runtime connection version.

## Validation

The new discovery regression fails against the original runtime:79 tests, one focused failure; the old function issues two third-party calls and retains the pin instead of adopting the official revision. A separate regression fails against Mesa's original parser for whitespace/key/literal/conflict boundaries. The corrected full package and ASan results are retained in [the receipt](evidence/official-version-20261116/receipt.json). Tests cover exact official endpoint/single request, parsing bounds, status/transport fallback, supplied version preservation, tighter body budget, no allocator requirement, and owned response cleanup.

All validation is synthetic/offline; no live WhatsApp account, session, messages or service-worker fetch was performed. The source implementation and initial fixtures came from the user's existing uncommitted Mesa change; that checkout was read only and its work was preserved. No push, installed compiler/SDK change or application deployment occurred.

Owned wire qualification also passes: native Surf sends GET `/sw.js` with exactly one expected browser User-Agent and `Sec-Fetch-Site: none` to a synthetic localhost peer. The same fixture fails the old request due to missing headers. The client is reaped, peer joined and listener closed. The native CI sanitizer loop now includes this fixture;21 offline CI control tests pass. No current-service HTTP fetch occurred.
