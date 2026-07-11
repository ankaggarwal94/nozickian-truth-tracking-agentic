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

## Consistency sweep
- Sweep ran: yes/no (mandatory whenever the artifact is a revision of previously corrected material, or any claim was corrected or refuted during this verification - the activation predicate in SKILL.md activation checklist step 9; if no, state the explicit reason it did not apply and what correction evidence was affirmatively checked)
- Corrected claims swept:

| Affected claim IDs | Superseded wording | Echo locations | Fragment | In true sentence | Classification | Recommended edit | Resolution |
|---|---|---|---|---|---|---|---|

- Machine mapping: `Affected claim IDs` is `affected_claim_ids` (a nonempty, duplicate-free array of canonical current `claims[].id` values), `Echo locations` is `locations` (a nonempty, duplicate-free array), and `Recommended edit` is `recommended_edit`. An artifact-global intentional reference may enumerate all current claim IDs; do not use a synthetic `"all claims"` ID.
- Canonical locator strings are `path:line` or `path:start-end` for current text and `git:<40-hex-commit>:<path>` for deleted or binary historical entries. Use one array element per exact location; do not use duplicates, wildcards, parenthetical selectors, semicolon-joined paths, unversioned deleted paths, or fabricated historical line numbers.
- `Resolution` values: `resolved` / `unresolved` / `accepted-intentional-reference`. Classification and resolution are paired: `live-claim` and `stale-echo` may be `resolved` or `unresolved`; `intentional-reference` must be `accepted-intentional-reference`. A resolved record must include a nonempty, duplicate-free `edited_locations` array in the same canonical form and substantive `replacement_evidence`. Unresolved and accepted-intentional-reference records must not fabricate completion evidence. An unresolved `stale-echo` caps the artifact at `PASS-SCOPED`; an unresolved `live-claim` returns every affected claim to adjudication.
- Explicit `none found` if the sweep ran and found no echoes.

## Remote escalations
- `REMOTE_GROUND_TRUTH_REQUIRED` entries raised, or explicit `none`:

| Claim | Why remote | Fetch spec | Local mirror | Mirror provenance | Staleness risk | Resolution (unresolved / fetched-and-readjudicated / left-unknown) |
|---|---|---|---|---|---|---|

## Gate result

```

## Certificate skeleton

Use `assets/certificate-template.json` for a machine-readable skeleton. Gate scripts require substantive tests and evidence for critical and major claims. Certificate authors should include `derived_or_downstream_claims` whenever they mention entailed, summarized, downstream, deployment, safety, compliance, or action-authorizing conclusions that are not independently verified as claims.

The template's `consistency_sweep` and `remote_escalations` fields are parent-enforced record-keeping for the report contract above: `ntt_gate.py` ignores unknown certificate fields (verified against its parsing code and the self-certificate fixture) and does not evaluate them, and the formal runner (`run_formal_artifact_verification.py`) does not read or evaluate them either. The consistency-sweep and remote-escalation rules are applied by the parent and audited by `ntt-gate-auditor`, including affected-ID membership, recommended-edit presence, canonical locator shape, and resolution-conditional evidence. Neither the gate script nor the formal runner mechanically enforces these fields or caps. Wiring these caps into mechanical enforcement remains deferred to issue #5.

## PASS-TRACKED upgrade certificate skeleton

```json
{
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
    "official_validator_commands": ["..."]
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
  "evidence_refs": [
    "deterministic/package_validation.json",
    "deterministic/gate_result.json",
    "official_validators/claude_plugin_validate.json",
    "live_fixtures/live_runtime_eval_result.json",
    "formal_artifacts/artifact-001/formal_result.json",
    "formal_artifacts/artifact-001/example_NOZICKIAN_FORMAL_TRANSCRIPT.stream.jsonl"
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

The certifier does not accept `package_sha256` as an alias. Both the live harness and certifier invoke the current package-local `validate_package.compute_stable_release_tree` helper, which executes `iter_release_inventory_files`, requires the manifest inventory path set and volatile file/prefix exclusion arrays to equal the current executable policy exactly, and verifies every independently derived regular-file hash and byte count. It then hashes canonical JSON containing algorithm `ntt-stable-release-tree-v1`, the manifest identity (`schema_version`, package and release versions, self file/hash, and file count), and sorted actual `{path, sha256, bytes}` entries. Canonical JSON uses sorted keys, compact separators, UTF-8, and `ensure_ascii=false`; the certificate value is exactly `sha256:<lowercase hex>`. Final certification also reruns the current basic package validator unconditionally; `--run-fresh-package-validator` remains a compatibility flag, not an opt-in gate.

`evidence_refs` contains at least five unique relative paths to existing regular non-symlink files inside the audit bundle. Absolute paths, URI schemes, traversal, missing files, and duplicate raw or canonical paths are invalid. Each live fixture uses a distinct canonical transcript under `live_fixtures/transcripts/<basename>`, records the exact transcript-file and current artifact-byte SHA-256 values, and binds its exact fixture ID and expected artifact to the current `build_fixture_prompt` text. `prompt_sha256` is computed over the exact UTF-8 bytes of that canonical normalized-display prompt after deterministic `<package-root>` substitution. The live result also records the shared current package-tree digest, exact `evals.json` digest, and positive integer `max_turns`. The certifier requires exact normalized preflight argv and exact fixture argv `["<claude-cli>", "--plugin-dir", "<package-root>", "-p", "--output-format", "json", "--max-turns", "<recorded integer>", "<canonical normalized prompt>"]`; prompt-only, missing, extra, reordered, wrong-format, or wrong-turn argv fails independently of prompt/report checks. A package, fixture spec, or artifact byte change after capture fails stale evidence even after manifest refresh. These hashes bind bundle consistency but do not authenticate the transcript producer or an official binary. Each formal result's transcript, certificate, invocation ledger, and evidence root are resolved only inside that result directory.
