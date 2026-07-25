# Self-validation artifacts

This directory contains package-local validation evidence and generated ledgers. It is included for reviewer inspection, but generated outputs should be rerun during release review.

## Important files

| File or directory | Purpose |
|---|---|
| `self_certificate.json` | Active certificate evaluated by `ntt_gate.py`. |
| `evidence/` | Structured local evidence JSON bound to package artifacts and SHA-256 hashes. |
| `current_observations.json` | Versioned release-declaration ledger; every modal wrapper names one exact proposition- and case-bound deduplication record. |

## Trust rule

Do not treat these files as self-authenticating. Rerun the release-lock commands, compare outputs, and check that strict local evidence hashes still match the cited artifacts. The certificate, release-declaration ledger, and structured evidence are current stable-release inventory; bulky command stdout is intentionally regenerated outside the package tree. Observation records are proposition- and case-bound declarations used as deduplication identities. They are not execution provenance, and the fresh self-test outcomes are established separately without per-record reconciliation to this ledger.

## Runtime status

A bundled dry run or deterministic self-test does not certify live Claude Code behavior. Live runtime remains `UNVERIFIED_RUNTIME` unless an external run captures authenticated stream-json transcripts.

Likewise, `46/46` from `run_promotion_certifier_contract_tests.py` is synthetic contract evidence. It proves that the baseline and all negative cases invoked the production certifier CLI; it does not authenticate a real runtime. In v1.0.3 the complete modeled baseline is expected to return nonzero with `PASS-SCOPED`, `CAPPED`, `promotion_authorized: false`, and both unresolved Issue #5 obligations.

The current fixed point records 1827/1827 basic package checks, 2017/2017 full self-test checks, 83/83 rejected false worlds, 12/12 retained true worlds, 232/232 gate contracts, 231/231 formal-runner contracts, and 166/166 regression checks. The authoritative required-before-re-review promotion aggregate passes 46/46 cases with a 252/252 capped baseline. Raw machine-readable CLI output must parse directly as one JSON document; no line stripping, tail extraction, or multi-document postprocessing is part of evidence generation.
