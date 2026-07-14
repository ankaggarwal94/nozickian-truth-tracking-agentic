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
| `formal_invocation_dry_run/` | Canonical `formal_result.json`, normalized prompt, and immutable target snapshot written by the production formal runner when Claude Code is not invoked. |
| `promotion_certifier_contract_results.json` and `promotion_certifier_contract_stdout.json` | Volatile ledgers for the 36-case synthetic promotion aggregate when generated during final release refresh. |

## Trust rule

Do not treat these files as self-authenticating. Rerun the release-lock commands, compare outputs, and check that strict local evidence hashes still match the cited artifacts. Generated outputs may be excluded from the stable release manifest when they are intentionally volatile, but the certificate and structured evidence remain hash-checked package artifacts.

## Runtime status

A bundled dry run or deterministic self-test does not certify live Claude Code behavior. Live runtime remains `UNVERIFIED_RUNTIME` unless an external run captures authenticated stream-json transcripts.

Likewise, `36/36` from `run_promotion_certifier_contract_tests.py` is synthetic contract evidence. It proves that the baseline and all negative cases invoked the production certifier CLI; it does not authenticate a real runtime. In v1.0.3 the complete modeled baseline is expected to return nonzero with `PASS-SCOPED`, `CAPPED`, `promotion_authorized: false`, and both unresolved Issue #5 obligations.

The final checked-in deterministic ledgers record 1724/1724 package self-test checks, 63/63 rejected false-world mutations, 10/10 retained true-world variants, 78/78 gate contracts, 73/73 formal-runner contracts, 166/166 regression checks, and 36/36 promotion aggregate cases with 244 checks in the complete synthetic baseline. Raw CLI stdout and explicit result files each parse directly as one JSON document; no line stripping, tail extraction, or multi-document postprocessing is part of evidence generation.
