# Protocol compatibility maintenance

`watch.py` compares 17 selected public Baileys/whatsmeow protocol files at immutable
commits. It retains historical-reference drift and changes since the last successful
observation separately. Observations never approve compatibility, update runtime
versions or touch credentials, session state or application source.

Baileys v6.7.23 is the historical wire reference. The whatsmeow pin is a certificate
oracle; other files at that pin are comparison starting points, not Odin parity.
Unmonitored paths, server-only rollouts and account-specific changes can escape
detection. A passing check is not complete protocol qualification.

```sh
python3 tools/protocol_watch/watch.py --state-dir /absolute/private/protocol-state
python3 -m unittest discover -s tools/protocol_watch -p 'test_*.py'
```

Owner-only state has an exclusive lock. `report.json`/`observed.json` contain public
metadata; `last_attempt.json` distinguishes failed checks from previous successful
evidence. Failures never advance observations. Invalid heads, version feeds,
redirects or missing paths on both revisions fail closed. Exit 3 means review
required, 2 means failed, and 0 means no monitored reference drift.

Responses are capped at 4 MiB, manifests at two sources/16 paths each, reports at
256 KiB. A 180-second admission budget spans requests, each with at most ten seconds
of socket timeout. Platform DNS/body trickle can exceed admission deadlines; use a
process watchdog for unattended execution.

## Automated triage and change coverage

The scanner binds supplied upstream bytes to the local Odin owners before filing
work. It does not execute upstream code or change runtime versions/source.

- **NO_ACTION:** supported lexical/JSON equivalence proves only safely ignored
  formatting/comments changed, or the strict token-table contract is already
  implemented locally. Newlines, literals, operators, build/compiler directives
  and license changes are not blindly stripped. Uncertain syntax is not ignored.
- **FIX:** a Todo task requires an explicitly selected, independently reviewed
  local target contract, not merely newer upstream bytes. Initially this supports
  a strict236-entry token dictionary: the approved target hash plus an owned
  indexed comparison must prove a local gap. The task includes complete affected
  indices, current local source hashes, immutable links, implementation scope and
  regression acceptance. Legacy/default-version behavior must be preserved.
- **SPIKE:** other behavior changes remain explicit investigation questions,
  mapped to local Odin owners and existing checks, with a checklist for deciding
  no action versus a focused fix. Unsupported parsing/mapping is a spike rather
  than an invented compatibility conclusion.

Dictionary drift without an approved requirement remains a SPIKE, retaining
complete indices and a conditional implementation plan. An already matching local
table needs no action. The workflow ships with no approved target declaration;
it cannot manufacture approval from an upstream head or a fixture copied from it.

An explicitly reviewed declaration may be supplied with `--approved-contract
 tools/protocol_watch/contracts/NAME.json` to `watch.py` or `ci.py`. Its schema1
contains `source`, `path`, canonical `target_table_sha256`, a `requirement` record
with repo-relative Markdown path/SHA256 under that contracts directory, and an
optional owned `fixture` path/SHA256 under `tests/`. Paths are bounded, contained
and symlink-refused. The tracker revalidates the requirement and current local
owners before treating a new finding as FIX. This verifies trusted local policy
bindings and an indexed counterexample; it does not authenticate human review,
prove a live server requirement or fabricate native/compiler execution evidence.

Coverage is keyed by repository/path and the reference/current content hashes,
not the aggregate upstream snapshot, head commit, time or workflow run. Previously
reported Baileys changes therefore do not reappear when only whatsmeow changes.
The tracker reads bounded paginated review metadata, including archived/closed
issues, and recognizes the old v1 generator's immutable links/hash records.
New evidence for an open investigation is appended with deterministic comment IDs;
human descriptions/comments are preserved. Completed, canceled, duplicate or archived reviews are not reopened. If an
open spike later gains valid FIX evidence for the same change, readiness is
appended once to that same issue while preserving human state and text. Unknown mutation outcomes are read back and never blindly replayed.
Malformed/incomplete metadata or exhausted bounds fail the job rather than
silently asserting successful coverage. Exact current limits are in the tracker.

A green daily run means bounded observation, conservative assessment and durable
handoff succeeded. It does not certify WhatsApp interoperability. Native CI and
manual release qualification remain separate. No agent or paid model API is used.

## Legacy local agent runner (not installed)

`schedule.py plist --state-dir ABS` prepares, but does not install, a launchd job
for 09:00 local time. `schedule.py run --state-dir ABS` checks upstream first, then
runs a read-only ephemeral Codex task on bounded public metadata. At most ten
structured recommendations are retained; raw stdout/stderr is discarded. The agent
cannot approve compatibility or downgrade deterministic drift. Agent time is
capped at 600 seconds. Existing CLI auth is used without copying credentials;
no model is pinned. See [official CLI scheduling guidance](https://learn.chatgpt.com/docs/non-interactive-mode).

`review-agent/agent-review.json` and `alert.json` are local artifacts, not delivered
email/Slack alerts. The Mac, repository, CLI and authentication must remain
available. A missed run proves nothing; inspect timestamps. Uninstall with
`launchctl bootout gui/$(id -u) <installed-plist>` and remove only that plist.

## Promotion gate

Run `promotion_gate.py --source-root ABS --offline-receipt OFFLINE.json
--live-receipt LIVE.json --evidence-dir ABS` before integration. It binds the root
runtime `.odin` set to compiler-bound PASS results for `unit_asan`, `noise_loopback`,
`consumer` and `protocol_review`. Live evidence separately requires exact-group
verification, text/PDF ACKs, recipient/openable-PDF confirmation, original IDs after
restart and no reported duplicates. Source or evidence changes and skipped checks
block promotion; ACK alone is insufficient.

Receipts carry `candidate_source_digest` from `source_digest`. Offline has
`compiler_sha256` and a `checks` map; each check has `status`, the same candidate
digest, `evidence_file` and `evidence_sha256`. Live has the booleans in `evaluate`
and its evidence file/hash. Evidence files must exist under the selected directory
and match their hashes. This checks trusted execution receipts, not authenticity
of their assertions. The source set excludes tools/tests and does not certify
the Core/Surf closure; retain the consumer gate's full closure evidence too.

Success means `ELIGIBLE_FOR_REVIEW`, never deployment authorization. Preserve the
historical reference when proposing a reviewed baseline update. Roll back code
only with known persisted-state compatibility; never roll Signal/auth state back
or fork a live session to make an older build appear healthy.

## GitHub Actions

`.github/workflows/protocol-review.yml` runs on GitHub-hosted Linux at15:00 UTC
(09:00 Mexico City), manually, and when protocol tooling changes are pushed.
Pull requests run only the offline Python tooling tests, without a scan or
Linear credential. Default-branch scheduled/manual/push runs also perform a bounded public scan, retaining
public evidence for30 days. No agent or OpenAI API key is used. Each runner
starts a fresh observation; historical-reference differences remain visible.
No account pairing, canary sending, session state or production deployment runs
in CI. This workflow does not build or qualify the Odin/native dependency stack.

Store `LINEAR_API` as an encrypted repository Actions secret. Only the default
branch performs upstream scans or accesses the Linear credential. Pull requests
and feature-branch pushes run offline tooling tests only. Writer runs are
serialized; public scan/triage evidence and the linked task/spike results are
retained for30days. Existing credentials/session/account state are not read.

The tracker creates or appends only new findings, keeping actionable FIX work
separate from unresolved SPIKE investigations. No source/baseline/version adoption,
review completion, account rollback or automatic live send is performed.
`linear-result.json` and the Actions summary link the relevant work. API/credential
failures fail the job and retain the public scan report for investigation, without
printing private API responses or credentials.

Scheduling requires the workflow on the default branch and Actions enabled.
GitHub can delay/drop scheduled runs under load; public repositories may have
schedules disabled after60 days of inactivity. This removes the laptop uptime
dependency, not the need to monitor job timestamps/results. No local daily job or recurring live canary is required. Hosted execution has
been verified; live checks are manual before releases or significant protocol
changes. See [the release checklist](../reliability/RELEASE_CHECKLIST.md).
