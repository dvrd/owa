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

The Taskfile invokes the Odin program in `tools/ci`. To run the tools directly, build once with `odin build tools/ci -out:/tmp/owa-ci` and invoke the binary from the repository root. For example, `/tmp/owa-ci test --package tests/unit` runs the library suite and `/tmp/owa-ci locked` runs the release checks.

Run `task check:locked` with the compiler revision in `ODIN_VERSION`. Configure KRS with the WebSocket checkout and access to the tagged async and surf repositories, or set `OWA_LOCKED_SHARED` to an installed KRS shared directory for offline use. The runner verifies each package digest, runs the library, protocol watcher and end-to-end suites, and compiles the private audio example against this checkout.

The GitHub Actions job `owa locked tests` targets pull requests to develop and main. It requires a read-only deploy key for async in `OWA_ASYNC_DEPLOY_KEY` and a base64-encoded gzip tar archive in `OWA_WEBSOCKET_B64`. Create the archive from the locked WebSocket package with `tar -czf websocket.tar.gz -C "$OWA_LOCKED_SHARED/websocket" ascii.odin websocket.odin` in a private directory. Both dependency inputs are checked against the lock before running the tests. Require the job on both branches after its first successful hosted run.
