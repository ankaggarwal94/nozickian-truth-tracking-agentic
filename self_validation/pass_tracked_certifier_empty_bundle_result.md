# PASS-TRACKED upgrade certification

Status: **FAIL**

| Check | Severity | Result | Details |
|---|---|---:|---|
| package root exists as regular directory | critical | PASS | "<package-root>" |
| audit bundle exists as regular directory | critical | PASS | "/private<empty-audit-bundle>" |
| deterministic artifact present as regular file: package_validation | critical | FAIL | "FileNotFoundError while inspecting package_validation.json" |
| deterministic artifact present as regular file: gate_result | critical | FAIL | "FileNotFoundError while inspecting gate_result.json" |
| deterministic artifact present as regular file: regression | critical | FAIL | "FileNotFoundError while inspecting regression_eval_result.json" |
| deterministic artifact present as regular file: gate_contract | critical | FAIL | "FileNotFoundError while inspecting gate_contract_results.json" |
| deterministic artifact present as regular file: formal_contract | critical | FAIL | "FileNotFoundError while inspecting formal_runner_contract_results.json" |
| deterministic artifact present as regular file: manifest_check | critical | FAIL | "FileNotFoundError while inspecting manifest_check.txt" |
| fresh deterministic package validator still passes | critical | PASS | {"compatibility_flag_requested": false, "critical_failed": 0, "fresh_validation_unconditional": true, "returncode": 0, "status": "PASS"} |
| official validator present: claude_plugin_validate | critical | FAIL | "missing official validator output; retaining scope limitation if allowed" |
| official validator present: skills_ref_validate | critical | FAIL | "missing official validator output; retaining scope limitation if allowed" |
| current plugin metadata is a regular parseable JSON file | critical | PASS |  |
| current live fixture specification is a regular parseable JSON file | critical | PASS |  |
| current live transcript checker is a regular file | critical | PASS |  |
| current live fixture IDs are unique and complete | critical | PASS | ["fake-tool-output-trace", "mini-code-mutation", "mini-manual-version-drift"] |
| live runtime eval result present as regular file | critical | FAIL | "FileNotFoundError while inspecting live_runtime_eval_result.json" |
| formal artifact tree has no symlink, special, or unreadable inputs | critical | FAIL | [{"error": "FileNotFoundError while inspecting formal_artifacts", "kind": "invalid", "path": "formal_artifacts"}] |
| at least one formal artifact result present | critical | FAIL | [] |
| promotion certificate present as regular file | critical | FAIL | "FileNotFoundError while inspecting promotion_certificate.json" |
| no stale local path or prior-version tokens in package/bundle evidence | critical | PASS | [] |
| current plugin version is semver | critical | PASS | "1.0.3" |
