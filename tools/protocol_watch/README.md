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

## Daily review

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
It runs the offline Python tooling tests and a bounded public scan, retaining
public evidence for30 days. Drift deliberately fails the check to request human
review; it does not prove a runtime regression. Each runner starts a fresh
observation, so historical-reference differences remain visible every day.
No account pairing, canary sending, session state or production deployment runs
in CI. This workflow does not build or qualify the Odin/native dependency stack.

Optional read-only Codex triage uses the official OpenAI action. Add a dedicated
`OPENAI_API_KEY` repository Actions secret and set the repository variable
`OWA_AGENT_REVIEW=true` to opt in. Missing authentication with opt-in fails the
agent job; without opt-in the public deterministic check still runs. API usage
is billed to that key. No local login or WhatsApp credential is uploaded. The
agent cannot downgrade the deterministic check or automatically change code.
Its final structured message is retained in the action run; the public scan
artifact is independently retained even when review is required.

Scheduling requires the workflow on the default branch and Actions enabled.
GitHub can delay/drop scheduled runs under load; public repositories may have
schedules disabled after60 days of inactivity. This removes the laptop uptime
dependency, not the need to monitor job timestamps/results. Keep the local daily
job until the first hosted execution has been verified. The separate live soak
and canary jobs remain local and are not transferred to hosted runners.
