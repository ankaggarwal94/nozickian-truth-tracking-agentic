# GitHub repository presentation

This README explains the repository-facing layout. It is intentionally separate from runtime component directories.

## Suggested repository view

- `README.md` — public landing page and command summary.
- `docs/README.md` — documentation hub.
- `SECURITY.md` — security and responsible-use notes.
- `TEAM_INTERNAL_USE.md` — internal review protocol.
- `AUDIT_REPORT.md` — tabulated validation and residual-risk report.
- `RELEASE_LOCK.json` — required release commands and review gates.
- `STABLE_RELEASE_MANIFEST.json` — stable file inventory and hashes.

## Directory READMEs

GitHub renders a `README.md` when browsing a directory. The package uses that feature under `docs/` and `self_validation/` so humans can navigate the project without adding ambiguous runtime files to `agents/` or skill component directories.

## Issue and pull request policy

For a team/internal repository, require reviewers to include validation output, stale-token scan results, and a statement about whether the change affects runtime surface, evidence semantics, or documentation only. A documentation-only pull request should still pass the validator because docs are part of the stable release inventory.
