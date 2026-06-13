# Output templates

## Verification report

```markdown
# Nozickian verification report

## Scope
- Artifact:
- Version/hash:
- Verification scope:
- Explicit exclusions:

## Method M
| Component | Value | Evidence | Unknowns |
|---|---|---|---|

## Claim table
| ID | Claim | Importance | Truth | Method completeness | Sensitivity | Adherence | Status |
|---|---|---:|---|---:|---:|---:|---|

## False-world tests
| Claim | Nearby false world | Expected rejection | Observed behavior | Evidence | Result |
|---|---|---|---|---|---|

## True-world tests
| Claim | Nearby true world | Expected retention | Observed behavior | Evidence | Result |
|---|---|---|---|---|---|


## Derived/downstream claims

A verified source claim does not automatically verify an entailed or operational downstream claim. Record downstream claims separately rather than allowing closure-style status inheritance.

| ID | From claim IDs | Derived/downstream claim | Independent method M supplied? | Independent modal tests supplied? | Status | Reason |
|---|---|---|---|---|---|---|
| D-001 | C-001 | Example deployment/safety/action claim inferred from C-001 | no | no | UNVERIFIED | Entailed but untested; requires its own method, evidence, false-world tests, true-world tests, contradiction review, and residual-risk assessment. |

## Contradictions and residual risks

## Gate result

```

## Certificate skeleton

Use `assets/certificate-template.json` for a machine-readable skeleton. Gate scripts require substantive tests and evidence for critical and major claims. Certificate authors should include `derived_or_downstream_claims` whenever they mention entailed, summarized, downstream, deployment, safety, compliance, or action-authorizing conclusions that are not independently verified as claims.

## PASS-TRACKED upgrade certificate skeleton

```json
{
  "upgrade_from_status": "PASS-SCOPED",
  "requested_status": "PASS-TRACKED",
  "package_version": "1.0.1",
  "package_sha256": "sha256:...",
  "method_m_upgrade": {
    "claude_code_version": "...",
    "plugin_load": "--plugin-dir <package-root>",
    "model": "...",
    "effort": "...",
    "deterministic_commands": ["..."],
    "live_fixture_command": "...",
    "formal_artifact_commands": ["..."],
    "official_validator_commands": ["..."]
  },
  "evidence_refs": [
    "deterministic/package_validation.json",
    "live_fixtures/live_runtime_eval_result.json",
    "formal_artifacts/artifact-001/formal_result.json"
  ],
  "derived_or_downstream_claims": [
    {
      "id": "D-PROD-001",
      "from_claim_ids": ["C-UPGRADE-001"],
      "derived_claim": "The verified package is safe for production deployment.",
      "status": "UNVERIFIED",
      "reason": "Deployment safety requires its own method M, action-space review, false-world tests, true-world tests, contradiction review, and residual-risk assessment."
    }
  ]
}
```
