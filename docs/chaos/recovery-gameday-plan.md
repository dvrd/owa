# Disposable recovery game day

Facilitator and observer: the finite `tests/recovery_campaign/run.py` process.
The parent agent owns review, issue updates and commits. No customer/team
notifications are sent because no production, account or shared service is
included in the blast radius.

1. Verify matching compiler identity and a successful no-fault child/reopen.
2. Test cleanup of that child's temporary tree; retain no account material.
3. For each declared boundary, require prior recovery success, await the exact
   marker, SIGKILL only the owned child, reopen and verify, then remove its tree.
4. Run focused native regressions and the existing owned-loopback fixture.
5. Check source/compiler guards, candidate gate and sanitizer diagnostics.
6. Repeat under the other sanitizer, then review the report and remaining gaps.

Abort on failed control, unexpected child signal, timeout, failed recovery,
unavailable listener permission or changed source/compiler. Clean up only owned
children and disposable trees. Do not use this plan against a live account.
The completed local ASan and TSan campaigns are recorded in the resilience report.
