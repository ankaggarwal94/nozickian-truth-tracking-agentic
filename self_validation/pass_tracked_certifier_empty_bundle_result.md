# PASS-TRACKED upgrade certification

Status: **FAIL**

| Check | Severity | Result | Details |
|---|---|---:|---|
| package root exists | critical | PASS | "<package-root>" |
| audit bundle exists | critical | PASS | "<tmp-v103-final-outputs>" |
| deterministic artifact present: package_validation | critical | FAIL | "deterministic/package_validation.json" |
| deterministic artifact present: gate_result | critical | FAIL | "deterministic/gate_result.json" |
| deterministic artifact present: regression | critical | FAIL | "deterministic/regression_eval_result.json" |
| deterministic artifact present: gate_contract | critical | FAIL | "deterministic/gate_contract_results.json" |
| deterministic artifact present: formal_contract | critical | FAIL | "deterministic/formal_runner_contract_results.json" |
| deterministic artifact present: manifest_check | critical | FAIL | "deterministic/manifest_check.txt" |
| official validator present: claude_plugin_validate | critical | FAIL | "missing official validator output; retaining scope limitation if allowed" |
| official validator present: skills_ref_validate | critical | FAIL | "missing official validator output; retaining scope limitation if allowed" |
| live runtime eval result present | critical | FAIL | "<tmp-v103-final-outputs>/live_fixtures/live_runtime_eval_result.json" |
| at least one formal artifact result present | critical | FAIL | [] |
| promotion certificate present | critical | FAIL | "<tmp-v103-final-outputs>/promotion_certificate.json" |
| no stale local path or prior-version tokens in package/bundle evidence | critical | PASS | [] |
| current plugin version is semver | critical | PASS | "1.0.3" |
