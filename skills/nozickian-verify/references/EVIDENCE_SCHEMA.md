# Structured Evidence Artifact Schema

When `--evidence-root` is supplied, strict local evidence mode treats every cited `evidence_ref` as part of the provenance boundary. Every cited local ref must resolve to a nonempty JSON evidence file under `evidence_root`; remote refs, absolute refs, path traversal, missing files, non-JSON files, wrong claim/test bindings, and wrong hashes fail. One valid evidence ref cannot mask another invalid cited ref.

Required fields:

```json
{
  "evidence_schema_version": "1.0",
  "claim_id": "C-001",
  "test_id": "FW-001",
  "applies_to_claims": ["C-001"],
  "applies_to_tests": ["FW-001"],
  "artifact_path": "relative/path/under/evidence_root/to/the/evidence/source",
  "command_or_source": "command, file, trace, source URL, or manual audit record that produced the observation",
  "observed_result": "what was actually observed",
  "support_summary": "why this observation supports the claim or modal test",
  "timestamp_utc": "2026-05-25T00:00:00Z",
  "hash_or_version": "sha256:<64-hex digest of artifact_path>"
}
```

For claim-level evidence, `test_id` may be omitted if `applies_to_tests` is not relevant. For test-level evidence, either `test_id` must match the modal test ID or `applies_to_tests` must include the test ID or `*`. The `claim_id` must match the claim being evaluated, or `applies_to_claims` must include the claim ID or `*`.

This prevents unrelated nonempty files such as `README.md`, `LICENSE`, a stale report, an out-of-root evidence JSON, or a partially fabricated ref set from counting as evidence for arbitrary claims. It does not replace expert semantic review; it is a deterministic binding check that forces each evidence reference to stay in the reviewed evidence root, state what it supports, and bind to an exact artifact digest.

## Promotion certificate v2 evidence graph

The claim-level schema above remains unchanged for ordinary `ntt_gate.py` certificates. Promotion certificate v2 uses a different evidence boundary and rejects legacy flat promotion `evidence_refs`.

```json
{
  "promotion_schema_version": "2.0",
  "upgrade_from_status": "PASS-SCOPED",
  "requested_status": "PASS-TRACKED",
  "package_version": "1.0.3",
  "package_tree_sha256": "sha256:<64 lowercase hex>",
  "method_m_upgrade": {},
  "live_result_bindings": {},
  "evidence": {
    "schema_version": "promotion-evidence-v2",
    "nodes": {
      "deterministic.package_validation": {
        "path": "deterministic/package_validation.json",
        "sha256": "sha256:<64 lowercase hex>",
        "depends_on": []
      },
      "deterministic.gate_result": {
        "path": "deterministic/gate_result.json",
        "sha256": "sha256:<64 lowercase hex>",
        "depends_on": ["deterministic.package_validation"]
      },
      "deterministic.regression": {
        "path": "deterministic/regression_eval_result.json",
        "sha256": "sha256:<64 lowercase hex>",
        "depends_on": ["deterministic.package_validation"]
      },
      "deterministic.gate_contract": {
        "path": "deterministic/gate_contract_results.json",
        "sha256": "sha256:<64 lowercase hex>",
        "depends_on": ["deterministic.gate_result"]
      },
      "deterministic.formal_contract": {
        "path": "deterministic/formal_runner_contract_results.json",
        "sha256": "sha256:<64 lowercase hex>",
        "depends_on": ["deterministic.gate_contract"]
      },
      "official.claude_plugin_validate": {
        "path": "official_validators/claude_plugin_validate.policy.json",
        "sha256": "sha256:<64 lowercase hex>",
        "depends_on": ["deterministic.package_validation"]
      },
      "official.skills_ref_validate": {
        "path": "official_validators/skills_ref_validate.policy.json",
        "sha256": "sha256:<64 lowercase hex>",
        "depends_on": ["deterministic.package_validation"]
      },
      "live.runtime": {
        "path": "live_fixtures/live_runtime_eval_result.json",
        "sha256": "sha256:<64 lowercase hex>",
        "depends_on": [
          "deterministic.package_validation",
          "official.claude_plugin_validate"
        ]
      },
      "formal.result": {
        "path": "formal_artifacts/artifact-001/formal_result.json",
        "sha256": "sha256:<64 lowercase hex>",
        "depends_on": ["live.runtime", "deterministic.gate_result"]
      }
    }
  },
  "claims": [
    {
      "id": "C-UPGRADE-001",
      "text": "The exact package snapshot satisfies the independently evaluated promotion contract.",
      "importance": "critical",
      "artifact_location": "promotion_claims/C-UPGRADE-001",
      "truth_status": "executed_confirmed",
      "method_m": {
        "producer": "recorded promotion workflow",
        "checker": "production strict gate and promotion certifier",
        "artifacts": ["promotion_certificate.json", "formal_result.json"],
        "environment": ["immutable package snapshot"],
        "tools": ["ntt_gate.py", "SHA-256"],
        "evidence_process": "Claim and modal records bind exact local bytes.",
        "graders_or_tests": ["strict gate", "false/true-world tests"],
        "trace_or_logs": ["complete stream-json transcript"]
      },
      "evidence_refs": [
        "promotion_claims/C-UPGRADE-001/claim-runtime.json",
        "promotion_claims/C-UPGRADE-001/claim-formal.json"
      ],
      "false_world_tests": [
        {
          "id": "FW-C-UPGRADE-001-STALE",
          "kind": "false_world",
          "target_claim": "C-UPGRADE-001",
          "perturbation": "Use stale package bytes.",
          "expected_behavior": "The strict gate rejects the claim.",
          "observed_behavior": "The strict gate rejected the claim.",
          "outcome": "rejected_false_claim",
          "result": "pass",
          "evidence_refs": ["promotion_claims/C-UPGRADE-001/FW-stale.json"]
        },
        {
          "id": "FW-C-UPGRADE-001-UNBOUND",
          "kind": "false_world",
          "target_claim": "C-UPGRADE-001",
          "perturbation": "Remove independent formal evidence.",
          "expected_behavior": "The strict gate blocks the claim.",
          "observed_behavior": "The strict gate blocked the claim.",
          "outcome": "blocked",
          "result": "pass",
          "evidence_refs": ["promotion_claims/C-UPGRADE-001/FW-unbound.json"]
        }
      ],
      "true_world_tests": [
        {
          "id": "TW-C-UPGRADE-001-EQUIVALENT",
          "kind": "true_world",
          "target_claim": "C-UPGRADE-001",
          "variant": "Use equivalent independently bound evidence.",
          "expected_behavior": "The strict gate retains the claim.",
          "observed_behavior": "The strict gate retained the claim.",
          "outcome": "retained_true_claim",
          "result": "pass",
          "evidence_refs": ["promotion_claims/C-UPGRADE-001/TW-equivalent.json"]
        }
      ],
      "unresolved_contradictions": [],
      "residual_risks": []
    }
  ],
  "derived_or_downstream_claims": [],
  "downstream_review": {
    "performed": true,
    "claims_identified": [],
    "none_identified_reason": "C-UPGRADE-001 is limited to the exact promotion contract; no derived operational claim was identified."
  }
}
```

`promotion_schema_version` has exact string type and value `"2.0"`. The other required top-level fields have exact JSON types: `upgrade_from_status`, `requested_status`, `package_version`, and `package_tree_sha256` are strings; `method_m_upgrade`, `live_result_bindings`, `evidence`, and `downstream_review` are objects; and `claims` plus `derived_or_downstream_claims` are arrays. `claims` must contain at least one well-formed unique claim; each is evaluated through the canonical strict gate, and modeled completion requires a nonempty all-passing result set.

The nine roles shown above are the complete fixed role set. Each node contains exactly `path`, `sha256`, and `depends_on`. Paths are canonical relative POSIX paths to bundle-local regular non-symlink files. The digest binds exact bytes. Dependencies must equal this environment-independent bounded acyclic graph. Different roles may have equal content bytes, but they may not alias one path or file identity.

Each role has lane-specific validation. Deterministic captures use `deterministic-capture-v2` and are compared with fresh fixed-argv suite execution through typed semantic projections. Official-policy nodes identify allowlisted validators that the certifier executes fresh; Claude uses exact strict argv and real ANSI-normalized success parsing. Complete stdout/stderr bytes determine semantics, hashes, and byte counts; bounded excerpts and truncation flags do not authorize. Text captures do not authorize. If an executable is absent and the explicit scope flag is supplied, the fresh execution record may say unavailable/scoped, but both official policy nodes and every dependency above remain mandatory. The formal role points directly to formal result `2.0`, which binds the immutable standalone target snapshot and the exact report, gate, certificate, ledger, complete transcript, prompt, and target-snapshot companion manifest.

Malformed or empty claims and other malformed bundle input produce canonical `status: "FAIL"` with a separate `failure_kind` (`INVALID_INPUT`, `CHECK_FAILED`, or `INTERNAL_ERROR`) rather than an unhandled traceback.


### v0.7.2 patch note
This regeneration closes the remaining strict-evidence nearby-false-world gaps: every cited evidence ref must be a valid local JSON file under `evidence_root`; wrong-hash, remote, absolute-path, path-escaping, missing, or otherwise invalid refs fail even if another cited ref is valid. Plugin agent closure remains recursive over `agents/**/*.md`, and formal trace authentication still requires native Agent/Task tool-use plus successful matching tool-result/completion events before PASS-TRACKED.
