# Nozickian Gate Result

Certificate: `self_validation/self_certificate.json`
Status: **PASS-SCOPED**

## Summary

| Metric | Value |
|---|---:|
| claims | 7 |
| failed_claims | 0 |
| critical_failed | 0 |
| major_failed | 0 |
| scope_limitations | 32 |
| certificate_method_unknowns | 1 |
| certificate_method_completeness | 1.0 |
| evidence_root_checked | True |
| strict_evidence | True |
| structured_evidence_required | True |
| derived_or_downstream_claims | 3 |
| downstream_nonclosure_violations | 0 |

## Claim results

| Claim | Importance | Status | Sensitivity | Adherence | Method | Evidence | Structured evidence | False tests | True tests | Reasons |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| C-structure | critical | PASS | 1.00 | 1.00 | 1.00 | 2 | 2 | 5 | 1 | — |
| C-gate-hardening | critical | PASS | 1.00 | 1.00 | 1.00 | 2 | 2 | 32 | 3 | — |
| C-validator-sensitivity | critical | PASS | 1.00 | 1.00 | 1.00 | 2 | 2 | 3 | 1 | — |
| C-formal-invocation | critical | PASS | 1.00 | 1.00 | 1.00 | 2 | 2 | 36 | 3 | — |
| C-pass-tracked-upgrade-audit | critical | PASS | 1.00 | 1.00 | 1.00 | 2 | 2 | 3 | 1 | — |
| C-github-readme-documentation | major | PASS | 1.00 | 1.00 | 1.00 | 2 | 2 | 1 | 1 | — |
| C-charter-caps | critical | PASS | 1.00 | 1.00 | 1.00 | 2 | 2 | 2 | 1 | — |

This deterministic result checks declared fields, thresholds, tests, outcomes, local evidence-ref containment, unique canonical evidence-ref and modal-test counting, structured evidence binding for every cited local ref, and exact SHA-256 equality between artifact_path and hash_or_version, and URI-scheme rejection for both evidence refs and artifact_path. It does not independently prove expert-level semantic adequacy of every evidence artifact or perturbation.
