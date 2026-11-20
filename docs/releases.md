# Publishing owa

Each pull request merged into `main` publishes a Git tag and a GitHub Release at that merge's exact commit. Merge commits, squash merges and rebase merges are supported. Direct pushes are skipped. Consumers can pin the resulting `vMAJOR.MINOR.PATCH` tag in KRS.

The pull request title determines the bump:

| PR title | Example starting at `v0.2.0` |
| --- | --- |
| `feat: add contact lookup` or `feat(contacts): add lookup` | `v0.3.0` |
| `feat!: change the contact API` or `fix(contacts)!: change lookup results` | `v1.0.0` |
| Any other title, including `fix:`, `docs:` and `ci:` | `v0.2.1` |

If publication fails, rerun **Release owa** in GitHub Actions. It resumes from the last published version and processes outstanding merges in order. The protocol watcher keeps its own checksum-based tags.
