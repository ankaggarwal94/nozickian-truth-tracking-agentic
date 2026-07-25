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
- Every `corrected_claims[]` record pairs its duplicate-free `correction_locations` array one-for-one with `correction_location_bindings` objects of the exact shape `{"locator":"<same canonical locator>","expected_excerpt_sha256":"<64 lowercase hex>"}`. For a current locator, hash the selected logical UTF-8 lines joined by LF with one final LF. Current targets are opened component-wise through held no-follow directory capabilities, rechecked against their lexical identities after hashing, and bounded to 2,048 selected lines, a 1 MiB canonical excerpt, and a 16 MiB source file. Recompute these bindings after the final source/certificate serialization; the package validator rejects missing/deleted/out-of-range current targets, changed excerpts, ancestor/file substitution, special files, within-record duplicates, and noncanonical or bare paths. One exact source span may support distinct correction records when that reuse is intentional and separately bound. A historical Git locator binds a declared historical blob digest because a Git-free release archive cannot reconstruct Git objects. The parent and gate auditor must still confirm that every bound excerpt or historical blob is the claimed semantic correction.
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

Strict claim-contract schema `1.1` binds the complete claim and the
certificate-assurance payload, including the full canonical downstream-policy
object. Modal world-contract schema `1.1` authorizes only through its closed
typed operator, target, and outcome fields. `outcome` and
`observed_outcome` are separate modal-digest inputs and must agree when both
are present; world and behavior prose remains digest-bound explanation, never
a polarity oracle. For this package's `package-self` gate, the
certificate-wide modal ID multiset must contain all 80 immutable reviewed
transitions exactly once with their pinned claim/kind assignments and complete
transition payloads.

The template's `consistency_sweep` and `remote_escalations` fields remain parent-enforced record-keeping for the report contract above: `ntt_gate.py` ignores unknown certificate fields (verified against its parsing code and the self-certificate fixture) and does not evaluate them, and the formal runner (`run_formal_artifact_verification.py`) does not read or evaluate them either. The package validator mechanically validates recorded corrected-claim locator grammar, uniqueness, current-file resolution/range bounds, and excerpt SHA-256 bindings. It does not infer whether the sweep was activated when required, whether the bound excerpt is the correct semantic target, whether all stale echoes were found, or whether the resulting claim adjudication is sound. Those semantic consistency-sweep rules and all remote-escalation rules remain applied by the parent and audited by `ntt-gate-auditor`. Neither the gate script nor the formal runner applies these caps; full mechanical enforcement remains deferred to issue #5.

## PASS-TRACKED upgrade certificate skeleton

```json
{
  "promotion_schema_version": "2.0",
  "origin": "runtime-observed",
  "upgrade_from_status": "PASS-SCOPED",
  "requested_status": "PASS-TRACKED",
  "package_version": "<plugin.json version>",
  "package_tree_sha256": "sha256:<lowercase digest from ntt-stable-release-tree-v2>",
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
    "package_tree_algorithm": "ntt-stable-release-tree-v2",
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
      "claim_contract_schema_version": "1.1",
      "claim_contract_sha256": "sha256:<SHA-256 of the assurance-bound claim contract>",
      "scope": "The exact identified package snapshot and independently evaluated promotion contract only.",
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
          "endpoint-checked permission-hardened package and target copies; temporal immutability is not enforced; Linux subreaper/process-group containment is required before execution"
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
          "target_claim_ids": ["C-UPGRADE-001"],
          "perturbation": "Replace the package binding with stale bytes.",
          "world_contract": {
            "schema_version": "1.1",
            "semantic_equivalence_class": "stale-package-bytes",
            "operator": "replace",
            "target": "artifact.identity",
            "precondition": "The claim is bound to the current package bytes.",
            "state_delta": "Substitute bytes from a stale package snapshot.",
            "oracle": "Recompute and compare the bound package identity.",
            "expected_outcome": "rejected_false_claim"
          },
          "expected_behavior": "The strict gate rejects the stale promotion claim.",
          "observed_behavior": "The strict gate rejected the stale promotion claim.",
          "outcome": "rejected_false_claim",
          "observed_outcome": "rejected_false_claim",
          "result": "pass",
          "evidence_refs": [
            "promotion_claims/C-UPGRADE-001/FW-stale.json"
          ]
        },
        {
          "id": "FW-C-UPGRADE-001-UNBOUND",
          "kind": "false_world",
          "target_claim_ids": ["C-UPGRADE-001"],
          "perturbation": "Remove the independent formal evidence binding.",
          "world_contract": {
            "schema_version": "1.1",
            "semantic_equivalence_class": "formal-evidence-absent",
            "operator": "remove",
            "target": "certificate.evidence_refs",
            "precondition": "The claim cites independently bound formal evidence.",
            "state_delta": "Delete the formal evidence binding.",
            "oracle": "Evaluate the strict promotion evidence graph.",
            "expected_outcome": "blocked"
          },
          "expected_behavior": "The strict gate blocks the unbound promotion claim.",
          "observed_behavior": "The strict gate blocked the unbound promotion claim.",
          "outcome": "blocked",
          "observed_outcome": "blocked",
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
          "target_claim_ids": ["C-UPGRADE-001"],
          "variant": "Retain equivalent independently bound package and formal evidence.",
          "world_contract": {
            "schema_version": "1.1",
            "semantic_equivalence_class": "equivalent-independent-evidence",
            "operator": "preserve",
            "target": "evidence_wrapper.identity",
            "precondition": "The original evidence is independently bound and valid.",
            "state_delta": "Retain semantically equivalent independently bound evidence.",
            "oracle": "Re-evaluate exact bindings and the strict claim contract.",
            "expected_outcome": "retained_true_claim"
          },
          "expected_behavior": "The strict gate retains the true promotion claim.",
          "observed_behavior": "The strict gate retained the true promotion claim.",
          "outcome": "retained_true_claim",
          "observed_outcome": "retained_true_claim",
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

The certifier requires exact-string `promotion_schema_version: "2.0"`, required string `origin`, and exact JSON types for every required top-level field. `claims` is a required nonempty array: every entry must be an object with the exact claim field types shown above, a unique canonical ID, nonempty `scope`, claim-contract schema/digest `1.1`, `proposition_sha256`, complete method M, local evidence, complete modal world contracts, contradiction review, and residual-risk review. Every cited claim wrapper repeats the canonical claim digest; every modal wrapper adds the canonical case digest and a verified observation-ledger record as defined in `EVIDENCE_SCHEMA.md`. The certifier evaluates the claim array through the canonical strict gate and requires a nonempty all-passing result set. `claims` remains distinct from `derived_or_downstream_claims`, whose entries cannot inherit verification from an upstream claim. A performed review may use empty `claims_identified` and `derived_or_downstream_claims` arrays only with a substantive `none_identified_reason`. The certifier does not accept `package_sha256` as an alias or flat promotion `evidence_refs`. Each of the fixed nine typed nodes contains exactly `path`, `sha256`, and `depends_on`; it resolves to a distinct canonical bundle-local regular non-symlink file, binds exact bytes, uses the canonical role path, and participates in the one environment-independent bounded acyclic dependency graph. Equal bytes across distinct roles are allowed; path and file-identity aliases are not. The declared origin must match live provenance schema `2.0` and formal `evidence_origin`; the certifier reconstructs that cross-binding in `promotion-method-m-v2`.

Deterministic captures cannot authorize by themselves: the certifier runs the fixed suites fresh and compares typed semantic projections. Allowlisted official validators also run fresh. Claude uses the exact strict argv shown above; after ANSI normalization its real `✔ Validation passed` form succeeds only when neither complete output stream contradicts it. Full bytes determine status, byte counts, and SHA-256; bounded excerpts and truncation flags are presentation metadata. Prewritten text captures do not authorize, absent tools scope only through the explicit flag while both official-policy nodes and fixed dependencies remain mandatory, and installed failures fail. Formal result `2.0` binds the standalone endpoint-checked target copy, exact report/gate/certificate/ledger/complete-transcript/prompt/target-copy companion manifest, package-tree identity, run ID, target endpoint identities, schema-`2.0` `evidence_origin`, `temporal_immutability_enforced: false`, and successful `linux-child-subreaper-plus-process-group` containment with no detached survivor and complete cleanup. Its terminal SDK ResultMessage must be the single final successful record after all lanes, use canonical nonempty `result`, reject non-null `api_error_status`, `deferred_tool_use`, and non-structured `structured_output`, and permit non-null `terminal_reason`/`stop_reason` only as exact `completed`/`end_turn`. Its exact output-check projection is recomputed from the bound report, certificate, ledger, and gate and must be nonempty and all passing; arbitrary self-attested checks and coherently rehashed empty report or gate companions fail closed. An otherwise `PASS-TRACKED` formal result is capped at `PASS-SCOPED`; unavailable process containment refuses execution.

Gate Markdown, certifier JSON/Markdown, formal output plus compatibility JSON, live transcripts plus optional JSON, validator Markdown, gate/formal/regression/promotion wrapper JSON, and fixed behavior/stable-release manifests retain held no-follow parents from before long-running work through descriptor-relative exclusive creation, link/rename installation as applicable, and directory fsync. Role and alias classification is frozen against held identities. Direct/ancestor links, special or hardlink sentinels, cross-output aliases, and lexical-parent substitution cannot redirect writes and fail closed; validator Markdown must remain outside the package tree. These checks bind output destinations but are not temporal isolation. Formal children receive only authenticated runner-owned `/proc/<runner-pid>/fd/N`; child-FD close/rebind and self/unrelated/noncanonical/closed/file capability forms fail, while unavailable procfd support yields `INVALID_INPUT` before requested output mutation. Promotion uses the typed `formal.result` path and never basename, glob-first, or tail-only substitution; unrelated nonreserved files may remain.

For an empty `claims_identified` array, add a substantive `none_identified_reason`. Malformed or empty claims and other malformed bundle data return canonical `FAIL` plus `failure_kind`, not a traceback. Each output enforces its declared fresh-versus-replaceable final-name policy. Existing private regular `--json` files are intentionally regenerated through held-parent exclusive temporaries and descriptor-relative atomic replacement; gate Markdown requires a fresh final name, validator Markdown requires a held external parent, a formal output directory must be real or safely created, and missing procfd support fails before requested output mutation.

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

The process exits nonzero. The modeled-promotion cap is certifier-specific; generic `ntt_gate.py` `PASS-TRACKED` semantics remain unchanged. The formal runner separately applies its endpoint/containment cap. The 46-case aggregate invokes the production certifier CLI for its complete baseline and every negative, but remains synthetic contract evidence rather than runtime authentication.
