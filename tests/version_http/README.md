# Official-version request wire fixture

This fixture uses the public `version_fetch_http` helper through native Surf and
one owned localhost HTTP peer. The peer verifies GET `/sw.js`, exactly one expected
browser User-Agent and `Sec-Fetch-Site: none`. It returns a synthetic worker body;
the current client checks the status and decoded revision under AddressSanitizer.
No real service worker, account, session, credentials or WhatsApp message is used.

```sh
python3 tests/version_http/run.py --odin /path/to/matching/odin \
  --shared-root /path/to/shared --report /tmp/owa-version-http.json
```

`--legacy-decoder` permits compiling the same transport fixture against the old
runtime without its new decoder API. It does not change the peer's header checks:
the old request still fails. Child execution, socket waits and thread joins are
bounded; the report records client reaping and listener/thread cleanup.

`--sanitize address` is the default; `--sanitize thread` selects TSan. The native
CI gate runs this same fixture in both requested sanitizer modes, with a bounded
180-second outer command budget and the tighter inner process/socket deadlines.
