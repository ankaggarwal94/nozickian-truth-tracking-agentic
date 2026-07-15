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
| D-001 | C-001 | Example deployment/safety/action claim inferred from C-001 | no | no | UNKNOWN | Entailed but untested; requires its own method, evidence, false-world tests, true-world tests, contradiction review, and residual-risk assessment. |

## Contradictions and residual risks

## Consistency sweep
- Sweep ran: yes/no (mandatory whenever the artifact is a revision of previously corrected material, or any claim was corrected or refuted during this verification - the activation predicate in SKILL.md activation checklist step 9; if no, state the explicit reason it did not apply and what correction evidence was affirmatively checked)
- Corrected claims swept:

| Affected claim IDs | Superseded wording | Echo locations | Fragment | In true sentence | Classification | Recommended edit | Resolution | Edited locations | Replacement evidence |
|---|---|---|---|---|---|---|---|---|---|

- Machine mapping: `Affected claim IDs` is `affected_claim_ids` (a nonempty, duplicate-free array of canonical current `claims[].id` values), `Echo locations` is `locations` (a nonempty, duplicate-free array), and `Recommended edit` is `recommended_edit`. An artifact-global intentional reference may enumerate all current claim IDs; do not use a synthetic `"all claims"` ID.
- Canonical locator strings are `path:line` or `path:start-end` for current text and `git:<40-hex-commit>:<path>` for deleted or binary historical entries. Use one array element per exact location; do not use duplicates, wildcards, parenthetical selectors, semicolon-joined paths, unversioned deleted paths, or fabricated historical line numbers.
- `Resolution` values: `resolved` / `unresolved` / `accepted-intentional-reference`. Classification and resolution are paired: `live-claim` and `stale-echo` may be `resolved` or `unresolved`; `intentional-reference` must be `accepted-intentional-reference`. A resolved record must include a nonempty, duplicate-free `edited_locations` array in the same canonical form and substantive `replacement_evidence`. Unresolved and accepted-intentional-reference records must not fabricate completion evidence. An unresolved `stale-echo` caps the artifact at `PASS-SCOPED`; an unresolved `live-claim` returns every affected claim to adjudication.
- Explicit `none found` if the sweep ran and found no echoes.

## Remote escalations
- `REMOTE_GROUND_TRUTH_REQUIRED` entries raised, or explicit `none`:

| Claim | Why remote | Fetch spec | Local mirror | Mirror provenance | Staleness risk | Resolution (unresolved / fetched-and-readjudicated / left-unknown) |
|---|---|---|---|---|---|---|

For every `fetched-and-readjudicated` row, include the complete companion-evidence table. For `unresolved` or `left-unknown`, use null/empty companion values and keep the claim `UNKNOWN`.

| Claim | Validated fetch request (scheme / host / method / revision) | Fetched artifact SHA-256 | Fetched at UTC | Fetched evidence refs | Readjudicated truth status | Readjudication evidence refs |
|---|---|---|---|---|---|---|

## Gate result

```

## Certificate skeleton

Use `assets/certificate-template.json` for a machine-readable skeleton. Gate scripts require substantive tests and evidence for critical and major claims. Certificate authors should include `derived_or_downstream_claims` whenever they mention entailed, summarized, downstream, deployment, safety, compliance, or action-authorizing conclusions that are not independently verified as claims.

The template's `consistency_sweep` and `remote_escalations` fields are parent-enforced record-keeping for the report contract above: `ntt_gate.py` ignores unknown certificate fields (verified against its parsing code and the self-certificate fixture) and does not evaluate them, and the formal runner (`run_formal_artifact_verification.py`) does not read or evaluate them either. The consistency-sweep and remote-escalation rules are applied by the parent and audited by `ntt-gate-auditor`, including affected-ID membership, recommended-edit presence, canonical locator shape, and resolution-conditional evidence. Neither the gate script nor the formal runner mechanically enforces these fields or caps. Wiring these caps into mechanical enforcement remains deferred to issue #5.

## PASS-TRACKED upgrade certificate skeleton

```json
{
  "promotion_schema_version": "2.0",
  "upgrade_from_status": "PASS-SCOPED",
  "requested_status": "PASS-TRACKED",
  "package_version": "<plugin.json version>",
  "package_tree_sha256": "sha256:<lowercase digest from ntt-stable-release-tree-v1>",
  "method_m_upgrade": {
    "claude_code_version": "...",
    "plugin_load": "--plugin-dir <package-root>",
    "model": "...",
    "effort": "...",
    "deterministic_commands": ["..."],
    "live_fixture_command": "...",
    "formal_artifact_commands": ["..."],
    "official_validator_commands": [
      "claude plugin validate <package-root> --strict",
      "skills-ref validate skills/nozickian-verify"
    ]
  },
  "live_result_bindings": {
    "package_tree_algorithm": "ntt-stable-release-tree-v1",
    "package_tree_sha256": "<64 lowercase hex from current shared validator helper>",
    "fixture_spec_sha256": "<64 lowercase hex over exact evals.json bytes>",
    "run_config": {
      "max_turns": 20,
      "output_format": "json",
      "plugin_dir": "<package-root>",
      "print_mode": true
    },
    "preflight_argv": [
      ["<claude-cli>", "--version"],
      ["<claude-cli>", "plugin", "validate", "<package-root>"]
    ],
    "fixture_artifacts": [
      {
        "fixture_id": "...",
        "artifact_sha256": "<64 lowercase hex over exact artifact bytes>"
      }
    ]
  },
  "evidence": {
    "schema_version": "promotion-evidence-v2",
    "nodes": {
      "deterministic.package_validation": {
        "path": "deterministic/package_validation.json",
        "sha256": "sha256:<exact file bytes>",
        "depends_on": []
      },
      "deterministic.gate_result": {
        "path": "deterministic/gate_result.json",
        "sha256": "sha256:<exact file bytes>",
        "depends_on": ["deterministic.package_validation"]
      },
      "deterministic.regression": {
        "path": "deterministic/regression_eval_result.json",
        "sha256": "sha256:<exact file bytes>",
        "depends_on": ["deterministic.package_validation"]
      },
      "deterministic.gate_contract": {
        "path": "deterministic/gate_contract_results.json",
        "sha256": "sha256:<exact file bytes>",
        "depends_on": ["deterministic.gate_result"]
      },
      "deterministic.formal_contract": {
        "path": "deterministic/formal_runner_contract_results.json",
        "sha256": "sha256:<exact file bytes>",
        "depends_on": ["deterministic.gate_contract"]
      },
      "official.claude_plugin_validate": {
        "path": "official_validators/claude_plugin_validate.policy.json",
        "sha256": "sha256:<exact file bytes>",
        "depends_on": ["deterministic.package_validation"]
      },
      "official.skills_ref_validate": {
        "path": "official_validators/skills_ref_validate.policy.json",
        "sha256": "sha256:<exact file bytes>",
        "depends_on": ["deterministic.package_validation"]
      },
      "live.runtime": {
        "path": "live_fixtures/live_runtime_eval_result.json",
        "sha256": "sha256:<exact file bytes>",
        "depends_on": ["deterministic.package_validation", "official.claude_plugin_validate"]
      },
      "formal.result": {
        "path": "formal_artifacts/artifact-001/formal_result.json",
        "sha256": "sha256:<exact file bytes>",
        "depends_on": ["live.runtime", "deterministic.gate_result"]
      }
    }
  },
  "claims": [
    {
      "id": "C-UPGRADE-001",
      "text": "The exact package snapshot satisfies the independently evaluated promotion contract.",
      "proposition_sha256": "sha256:<SHA-256 of the canonical claim text>",
      "importance": "critical",
      "artifact_location": "promotion_claims/C-UPGRADE-001",
      "truth_status": "executed_confirmed",
      "method_m": {
        "producer": "The recorded live and formal promotion workflow.",
        "checker": "The production strict gate and promotion certifier.",
        "artifacts": [
          "promotion_certificate.json",
          "formal_artifacts/artifact-001/formal_result.json"
        ],
        "environment": [
          "recorded Claude Code environment",
          "immutable package and target snapshots"
        ],
        "tools": [
          "fixed-argv subprocesses",
          "ntt_gate.py",
          "SHA-256"
        ],
        "evidence_process": "Claim and modal-test records bind distinct exact local artifact bytes.",
        "graders_or_tests": [
          "strict claim gate",
          "nearby false-world rejection",
          "nearby true-world retention"
        ],
        "trace_or_logs": [
          "complete formal stream-json transcript",
          "promotion certification result"
        ]
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
          "perturbation": "Replace the package binding with stale bytes.",
          "expected_behavior": "The strict gate rejects the stale promotion claim.",
          "observed_behavior": "The strict gate rejected the stale promotion claim.",
          "outcome": "rejected_false_claim",
          "result": "pass",
          "evidence_refs": [
            "promotion_claims/C-UPGRADE-001/FW-stale.json"
          ]
        },
        {
          "id": "FW-C-UPGRADE-001-UNBOUND",
          "kind": "false_world",
          "target_claim": "C-UPGRADE-001",
          "perturbation": "Remove the independent formal evidence binding.",
          "expected_behavior": "The strict gate blocks the unbound promotion claim.",
          "observed_behavior": "The strict gate blocked the unbound promotion claim.",
          "outcome": "blocked",
          "result": "pass",
          "evidence_refs": [
            "promotion_claims/C-UPGRADE-001/FW-unbound.json"
          ]
        }
      ],
      "true_world_tests": [
        {
          "id": "TW-C-UPGRADE-001-EQUIVALENT",
          "kind": "true_world",
          "target_claim": "C-UPGRADE-001",
          "variant": "Retain equivalent independently bound package and formal evidence.",
          "expected_behavior": "The strict gate retains the true promotion claim.",
          "observed_behavior": "The strict gate retained the true promotion claim.",
          "outcome": "retained_true_claim",
          "result": "pass",
          "evidence_refs": [
            "promotion_claims/C-UPGRADE-001/TW-equivalent.json"
          ]
        }
      ],
      "unresolved_contradictions": [],
      "residual_risks": []
    }
  ],
  "downstream_review": {
    "performed": true,
    "claims_identified": [],
    "none_identified_reason": "The independently evaluated C-UPGRADE-001 claim is limited to this exact package promotion contract and asserts no derived deployment, safety, compliance, or action-authorizing conclusion."
  },
  "derived_or_downstream_claims": []
}
```

The certifier requires exact-string `promotion_schema_version: "2.0"` and exact JSON types for every required top-level field. `claims` is a required nonempty array: every entry must be an object with the exact claim field types shown above, a unique canonical ID, `proposition_sha256`, complete method M, local evidence, modal tests, contradiction review, and residual-risk review. Every cited claim wrapper repeats the canonical claim digest; every modal wrapper adds the canonical case digest and a verified observation-ledger record as defined in `EVIDENCE_SCHEMA.md`. The certifier evaluates the claim array through the canonical strict gate and requires a nonempty all-passing result set. `claims` remains distinct from `derived_or_downstream_claims`, whose entries cannot inherit verification from an upstream claim. A performed review may use empty `claims_identified` and `derived_or_downstream_claims` arrays only with a substantive `none_identified_reason`. The certifier does not accept `package_sha256` as an alias or flat promotion `evidence_refs`. Each of the fixed nine typed nodes contains exactly `path`, `sha256`, and `depends_on`; it resolves to a distinct canonical bundle-local regular non-symlink file, binds exact bytes, uses the canonical role path, and participates in the one environment-independent bounded acyclic dependency graph. Equal bytes across distinct roles are allowed; path and file-identity aliases are not.

Deterministic captures cannot authorize by themselves: the certifier runs the fixed suites fresh and compares typed semantic projections. Allowlisted official validators also run fresh. Claude uses the exact strict argv shown above; after ANSI normalization its real `✔ Validation passed` form succeeds only when neither complete output stream contradicts it. Full bytes determine status, byte counts, and SHA-256; bounded excerpts and truncation flags are presentation metadata. Prewritten text captures do not authorize, absent tools scope only through the explicit flag while both official-policy nodes and fixed dependencies remain mandatory, and installed failures fail. Formal result `2.0` binds the immutable standalone target snapshot, exact report/gate/certificate/ledger/complete-transcript/prompt/target-snapshot companion manifest, package-tree identity, run ID, and target identities. Promotion uses the typed `formal.result` path and never basename, glob-first, or tail-only substitution; unrelated nonreserved files may remain.

For an empty `claims_identified` array, add a substantive `none_identified_reason`. Malformed or empty claims and other malformed bundle data return canonical `FAIL` plus `failure_kind`, not a traceback. Caller-supplied output paths reject links, special files, and symlinked ancestors with structured invalid-input results. Existing private regular `--json` files are intentionally regenerated with same-directory exclusive temporary files and atomic replacement; an output directory must be a real or safely created directory.

### v1.0.3 certifier result

A complete modeled v1.0.3 result has this authorization envelope:

```json
{
  "status": "PASS-SCOPED",
  "outcome": "CAPPED",
  "promotion_authorized": false,
  "satisfied_profile": "promotion-contract-v2-complete",
  "unresolved_charter_obligations": [
    "Issue #5 consistency-sweep activation and resolution mechanics remain parent-enforced.",
    "Issue #5 REMOTE_GROUND_TRUTH_REQUIRED escalation mechanics remain parent-enforced."
  ]
}
```

The process exits nonzero. This cap is certifier-only; generic gate/formal `PASS-TRACKED` semantics remain unchanged. The 36-case aggregate invokes the production certifier CLI for its complete baseline and every negative, but remains synthetic contract evidence rather than runtime authentication.
