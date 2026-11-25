# Publishing owa

Use `develop`, the default branch, for daily commits and feature PRs. Push to `develop` as often as needed. Each push updates the open release PR for that branch.

When preparing a release, open one PR from this repository's `develop` into `main`. You can keep it in draft while collecting changes. Choose a title that reflects the largest change in the batch, mark it ready, and merge. Use **Create a merge commit** to preserve the ancestry of the long-lived branches. The merge publishes one Git tag and one GitHub Release at the merged commit. Consumers can pin that tag in KRS.

The release PR title determines the bump:

| PR title | Example starting at `v0.2.0` |
| --- | --- |
| `feat: add contact lookup` or `feat(contacts): add lookup` | `v0.3.0` |
| `feat!: change the contact API` or `fix(contacts)!: change lookup results` | `v1.0.0` |
| Any other title, including `fix:`, `docs:` and `ci:` | `v0.2.1` |

If publication fails, rerun **Release owa** in GitHub Actions. It resumes from the last published version and processes outstanding merges in order. The protocol watcher keeps its own checksum-based tags.

## Checking the release inputs

Run `task check:locked` with the compiler revision in `ODIN_VERSION`, Task, Python 3 and KRS. Configure KRS with the checkout of WebSocket and access to the tagged async and surf repositories. The task installs the revisions in `.krs/packages.json` into a temporary collection, verifies each package digest, runs the library, protocol watcher and end-to-end suites, and checks the private audio example as a consumer of this checkout. To reuse an installed KRS collection offline, set `OWA_LOCKED_SHARED` to its shared directory.

The GitHub Actions job `owa locked tests` targets pull requests to develop and main. It requires a read-only deploy key for async in `OWA_ASYNC_DEPLOY_KEY` and a base64-encoded gzip tar archive in `OWA_WEBSOCKET_B64`. Create the archive from the locked WebSocket package with `tar -czf websocket.tar.gz -C "$OWA_LOCKED_SHARED/websocket" ascii.odin websocket.odin` in a private directory. Both dependency inputs are checked against the lock before running the tests. Require the job on both branches after its first successful hosted run.
