# Self-validation artifacts

This directory contains package-local validation evidence and generated ledgers. It is included for reviewer inspection, but generated outputs should be rerun during release review.

## Important files

| File or directory | Purpose |
|---|---|
| `self_certificate.json` | Active certificate evaluated by `ntt_gate.py`. |
| `evidence/` | Structured local evidence JSON bound to package artifacts and SHA-256 hashes. |
| `evidence_artifacts/` | Human-readable supplemental evidence summaries. |
| `GATE_RESULT.md` and `gate_result.json` | Bundled strict-gate result for the active certificate. |
| `SELF_VALIDATION_REPORT.md` and package validation JSON | Bundled package-validator outputs. |
| `formal_invocation_dry_run/` | Prompt material written by the formal runner when Claude Code is not invoked. |

## Trust rule

Do not treat these files as self-authenticating. Rerun the release-lock commands, compare outputs, and check that strict local evidence hashes still match the cited artifacts. Generated outputs may be excluded from the stable release manifest when they are intentionally volatile, but the certificate and structured evidence remain hash-checked package artifacts.

## Runtime status

A bundled dry run or deterministic self-test does not certify live Claude Code behavior. Live runtime remains `UNVERIFIED_RUNTIME` unless an external run captures authenticated stream-json transcripts.
