# Deterministic completion handoff

`finish_soak.py` is a finite local controller for a launchd `StartInterval` of
300 seconds. It does not launch agents, use models, read account files, send
WhatsApp messages, restart work, or change deployments. Root/operator installs
and starts the timer after review; tests install nothing.

```sh
python3 whatsapp/tools/reliability/finish_soak.py \
  --state-dir "$SOAK_STATE_DIR" --controller-dir "$SOAK_CONTROLLER_DIR" \
  --expected-run-id "$FRESH_SUPERVISOR_RUN_ID" \
  --expected-binary-sha256 "$REVIEWED_BINARY_SHA256" \
  --expected-duration-seconds 86400 --expected-canary-interval-seconds 21600 \
  --minimum-cycles 3 --issue OKAMI-408 --linear
```

Use separate private 0700 supervisor/controller directories outside Git. The
controller reads fixed supervisor config/status/progress metadata and its own
confirmation/idempotency files. It never follows `auth_dir` or signals processes
from account status. Files must be owner-only regular 0600 files without symlinks
or hardlinks. Input size and duplicate JSON fields are checked. A separate lock
prevents overlapping invocations.

The gate requires the exact expected run/binary/duration/cadence, COMPLETE status,
24 hours within the explicit five-second tolerance using wall and observed
monotonic time, at least three new durable canary pairs, qualified health coverage
without recorded gaps/errors, and a public version triple. New config cannot be
paired with an older COMPLETE result. Elapsed process time is not availability.

## Initial recipient confirmation

Only the operator writes `recipient-confirmation.json` in the controller directory
after actual confirmation. The controller never synthesizes it:

```json
{
  "schema": 1,
  "binary_sha256": "<reviewed lowercase SHA-256>",
  "scope_sha256": "<configured session/group scope SHA-256>",
  "version": {"major": 2, "minor": 3000, "patch": 1043857760},
  "recipient_confirmed": true,
  "confirmed_unix": 1794517195
}
```

Replace illustrative time/version with actual initial-smoke confirmation evidence.
Scope is SHA-256 of UTF-8 compact sorted JSON containing exactly `auth_dir` and
`group_subject` strings from config; `scope_hash(config)` implements it without
opening that path. Prior initial-smoke proof applies to a later run only for the
same binary, configured session/group, and public version. Missing/mismatched
proof stays PENDING_HUMAN_CONFIRMATION. Receipts contain hashes, not raw scope,
phone, message IDs or keys. Periodic server ACKs do not prove recipient delivery.

## Receipts and optional Linear completion

Active work produces WAITING. Failed/stale/malformed evidence creates a local
`handoff.json`; no credential is fetched and nothing is marked Done. Sanitized
`receipt.json` records qualification and counters. `finish-state.json` binds
run/binary/proof plus durable mutation intentions; changed bindings fail closed.

Without `--linear`, or with unavailable credentials/network, local evidence can
be QUALIFIED with `linear_update_pending: true`. This is not remote Done. With
`--linear`, the credential comes from process environment `LINEAR_API` or a
five-second bounded `wayu const get LINEAR_API`. Never put it in arguments,
repository files or launchd plist. Configure a public PATH that finds Wayu;
background Keychain failure leaves the update pending. The key stays in memory
and an owned HTTPS worker's pipe, never disk or argv. A 15-second outer worker
bound includes stuck DNS. Redirects are rejected; the GraphQL endpoint is fixed.

Before writing, the controller queries the explicit issue/project, Done state,
and unique run/binary comment marker. It fsyncs intention before mutation. A
possibly committed comment/Done result makes future polls query-only rather than
blindly repeat it. Existing markers/Done states are observed, not rewritten.
Ambiguity remains pending for verification or operator review. COMPLETE with
`linear_done_verified: true` requires a final query verifying both marker and
Done. It does not upgrade code or close other issues.

Suggested launchd configuration: reviewed absolute Python/script paths and
arguments, `RunAtLoad=true`, `StartInterval=300`, no KeepAlive retry loop, and
private output/error paths. Root owns installation and actual job paths. These
are deterministic local checks, without agent/model polling. Interrupted,
slept-through, failed or short runs are never qualified automatically.

Offline validation uses fake metadata, credentials and HTTP only:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s whatsapp/tools/reliability -p test_finish_soak.py -v
```
