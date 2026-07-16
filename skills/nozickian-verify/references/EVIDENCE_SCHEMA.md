# Structured Evidence Artifact Schema

When `--evidence-root` is supplied, strict local evidence mode treats every cited `evidence_ref` as part of the provenance boundary. Every cited local ref must resolve to a nonempty JSON evidence file under `evidence_root`; remote refs, absolute refs, path traversal, missing files, non-JSON files, wrong claim/test bindings, and wrong hashes fail. One valid evidence ref cannot mask another invalid cited ref.

Required fields:

```json
{
  "evidence_schema_version": "1.0",
  "claim_id": "C-001",
  "claim_proposition_sha256": "sha256:<digest of the canonical certificate claim text>",
  "artifact_path": "relative/path/under/evidence_root/to/the/evidence/source",
  "command_or_source": "command, file, trace, source URL, or manual audit record that produced the observation",
  "observed_result": "what was actually observed",
  "support_summary": "why this observation supports the claim or modal test",
  "timestamp_utc": "2026-05-25T00:00:00Z",
  "hash_or_version": "sha256:<64-hex digest of artifact_path>"
}
```

The package writes wrapper schema `1.0`. The gate requires a nonempty
`evidence_schema_version`; the separately versioned observation-ledger field
described below is checked for the exact value `"1.0"`. `claim_id` must match the
claim being evaluated, or optional `applies_to_claims` must contain that claim ID
or `*`.

In strict local-evidence mode, the certificate claim itself must declare
`proposition_sha256`, and every claim-level and test-level wrapper must declare
the same proposition identity as `claim_proposition_sha256`. The digest input is
the claim's `text` after Unicode NFC normalization, replacing each run of
whitespace with one ASCII space, and stripping leading and trailing whitespace.
The gate hashes the UTF-8 bytes of that canonical text with SHA-256. A declared
digest may be 64 hexadecimal characters or may use a `sha256:` or `sha256=`
prefix; hexadecimal case is normalized, but writers should emit lowercase
`sha256:<64-hex>` values. An empty or non-string proposition cannot be
canonicalized.

Test-level wrappers add the modal bindings shown here:

```json
{
  "evidence_schema_version": "1.0",
  "claim_id": "C-001",
  "claim_proposition_sha256": "sha256:<canonical claim digest>",
  "test_id": "FW-001",
  "modal_case_sha256": "sha256:<canonical modal-case digest>",
  "observation_id": "obs.C-001.FW-001",
  "artifact_path": "observations/current_observations.json",
  "command_or_source": "the exact command or source that produced this case observation",
  "observed_result": "the exact observation text copied into the named ledger record",
  "support_summary": "why this observation supports this particular nearby-world case",
  "timestamp_utc": "2026-05-25T00:00:00Z",
  "hash_or_version": "sha256:<digest of the complete observation-ledger bytes>"
}
```

For test-level evidence, `test_id` must match the modal test ID, or optional
`applies_to_tests` must contain that test ID or `*`. `modal_case_sha256` is the
SHA-256 of the following object serialized as UTF-8 JSON with sorted keys,
`ensure_ascii=false`, and compact separators (`,` and `:`):

```json
{
  "claim_proposition": "<canonical claim text>",
  "kind": "<lowercase stripped test kind, falling back to the expected kind>",
  "test_id": "<stripped id, falling back to test_id>",
  "target_claim_ids": ["<sorted unique stripped target IDs>"],
  "variation_field": "perturbation",
  "variation": "<canonical perturbation or variant text>",
  "expected_behavior": "<canonical expected_behavior>",
  "observed_behavior": "<canonical observed_behavior>",
  "observed_result": "<canonical evidence-wrapper observed_result>",
  "outcome": "<lowercase stripped outcome or observed_outcome>",
  "result": "<lowercase stripped result>"
}
```

`target_claim_ids` comes from `target_claim_ids` when that field is present,
otherwise from `target_claim`; a scalar is treated as a one-element list before
the values are stripped, deduplicated, and sorted. `variation_field` is
`perturbation` when that value is nonempty and otherwise is `variant`. The four
prose values use the same NFC/whitespace canonicalization as claim text. In
particular, `observed_result` comes from the evidence wrapper, so changing either
the case declaration or the observation text changes the modal-case digest.

## Observation ledger binding

`observation_id` is optional, but when present it must be an already stripped,
1-to-128-character identifier matching
`[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`. Its wrapper's `artifact_path` must identify a
JSON ledger with this shape:

```json
{
  "observation_schema_version": "1.0",
  "observations": {
    "obs.C-001.FW-001": {
      "claim_id": "C-001",
      "test_id": "FW-001",
      "kind": "false_world",
      "claim_proposition_sha256": "sha256:<canonical claim digest>",
      "modal_case_sha256": "sha256:<canonical modal-case digest>",
      "result": "pass",
      "outcome": "rejected_false_claim",
      "observed_result": "the exact observation text copied into the evidence wrapper"
    }
  }
}
```

The ledger must have exact `observation_schema_version: "1.0"` and an
`observations` object containing the named record. The record's `claim_id`,
`test_id`, and `kind` must exactly equal the evaluated claim ID, modal test ID,
and expected kind (`false_world` or `true_world`). Its two digests must match the
gate-derived claim and modal-case digests. `result`, after stripping and
lowercasing, must be `pass`. Outcome comparison also strips and lowercases. The
accepted false-world outcomes are
`rejected_false_claim`, `withheld`, `flagged`, `failed_as_expected`, `downgraded`,
`corrected`, `blocked`, and `not_certified`. The accepted true-world outcomes are
`retained_true_claim`, `accepted_equivalent`, `passed_benign_variant`,
`correctly_updated`, `preserved`, `recovered`, and `not_overfit`. The ledger
`observed_result`, after outer whitespace is stripped, must be at least ten
characters and exactly equal the stripped wrapper `observed_result`.

A named, verified `observation_id` is the modal observation identity used for
independence counting. Without one, the gate falls back to the cited artifact's
SHA-256, so multiple wrappers over the same aggregate bytes do not create
multiple observations merely by using different filenames or test labels.

## Byte-backed local evidence

Both an `evidence_ref` and its wrapper `artifact_path` must be canonical relative
POSIX paths beneath `evidence_root`. Strict mode rejects absolute paths, `.` or
`..` segments, backslashes, control characters, alias suffixes, URI schemes,
missing paths, directories, special files, and any path that traverses a
symlink. The wrapper must be a nonempty regular JSON file; the artifact must be a
regular non-symlink file. Wrappers are limited to 1 MiB, and a named observation
ledger is limited to 8 MiB and bounded to depth 64, 100,000 JSON nodes, and
100,000 object fields. No-follow descriptor reads bind the opened regular file,
reject an inode swap before open, and reject size or modification-time changes
to that opened file during the read. `hash_or_version` must be an actual SHA-256
digest of the complete artifact bytes. When `observation_id` is present, those
same hashed artifact bytes must parse as the bounded observation ledger above.

Evidence sufficiency is byte-backed too: byte-identical wrappers collapse to one
structured reference, and claim evidence that requires multiple sources must
also resolve to distinct artifact SHA-256 values. Thus copied wrappers, hardlink
aliases, or differently named files with identical bytes cannot inflate the
minimum evidence count.

This prevents unrelated nonempty files such as `README.md`, `LICENSE`, a stale report, an out-of-root evidence JSON, or a partially fabricated ref set from counting as evidence for arbitrary claims. It does not replace expert semantic review; it is a deterministic binding check that forces each evidence reference to stay in the reviewed evidence root, state what it supports, and bind to an exact artifact digest.

## Passing downstream proposition binding

A `derived_or_downstream_claims` record with a passing status must name a
distinct `own_claim_id` whose claim independently evaluates `PASS`. It must also
carry:

```json
{
  "proposition_binding": {
    "schema_version": "1.0",
    "canonical_text_sha256": "sha256:<canonical downstream proposition digest>"
  }
}
```

The downstream `derived_claim` and the independent claim's `text` must
canonicalize to the same proposition, and `canonical_text_sha256` must match
both. The gate does not infer semantic equivalence or allow a source claim to be
reused as the independent claim. Non-passing downstream statuses instead require
a nonempty reason and do not claim automatic closure.

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
      "proposition_sha256": "sha256:<digest of the canonical claim text>",
      "importance": "critical",
      "artifact_location": "promotion_claims/C-UPGRADE-001",
      "truth_status": "executed_confirmed",
      "method_m": {
        "producer": "recorded promotion workflow",
        "checker": "production strict gate and promotion certifier",
        "artifacts": ["promotion_certificate.json", "formal_result.json"],
        "environment": ["endpoint-checked permission-hardened package copy; temporal immutability not enforced"],
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

Each role has lane-specific validation. Deterministic captures use `deterministic-capture-v2` and are compared with fresh fixed-argv suite execution through typed semantic projections. Official-policy nodes identify allowlisted validators that the certifier executes fresh; Claude uses exact strict argv and real ANSI-normalized success parsing. Complete stdout/stderr bytes determine semantics, hashes, and byte counts; bounded excerpts and truncation flags do not authorize. Text captures do not authorize. If an executable is absent and the explicit scope flag is supplied, the fresh execution record may say unavailable/scoped, but both official policy nodes and every dependency above remain mandatory. The formal role points directly to formal result `2.0`, which binds the standalone endpoint-checked target copy and the exact report, gate, certificate, ledger, complete transcript, prompt, and target-copy companion manifest. Its output-check projection is recomputed from the exact bound report, certificate, ledger, and gate and must be nonempty and all passing; arbitrary self-attested checks and coherently rehashed empty report or gate companions fail closed. Its execution identity must truthfully record `temporal_immutability_enforced: false`, `process_containment.mechanism: linux-child-subreaper-plus-process-group`, `detached_session_descendants_contained: true`, `detached_descendant_survivor: false`, and `process_containment_cleanup_complete: true`. Temporal immutability caps an otherwise `PASS-TRACKED` result at `PASS-SCOPED`; unavailable containment fails before execution.

Gate Markdown, certifier JSON/Markdown, formal output plus compatibility JSON, live transcripts plus optional JSON, validator Markdown, deterministic contract/regression JSON wrappers, and the fixed behavior/stable-release manifests acquire component-wise `O_DIRECTORY`/`O_NOFOLLOW` parent capabilities before their long-running work. Writes retain those capabilities through descriptor-relative exclusive creation, link/rename installation as applicable, and directory fsync. Role/alias decisions are frozen against held identities; formal canonical-result classification is not recomputed after writes, certifier JSON/Markdown aliases fail, and live JSON cannot alias a selected transcript. Direct/ancestor links, special or hardlink sentinels, and lexical-parent replacement cannot redirect writes; validator Markdown also rechecks that its held parent remains outside the package tree. Endpoint and capability observations are not temporal isolation, so a same-UID mutation between checks remains outside the claim.

Formal children receive only runner-owned `/proc/<runner-pid>/fd/N` through `pass_fds`; procfs-visible `Pid:` must equal the gate child's direct-parent `PPid:`. Child-FD close/rebind, self/unrelated PIDs, noncanonical or nonpositive PID/FD tokens, extra components, closed descriptors, and file descriptors fail closed. Unavailable procfd support yields `INVALID_INPUT` before requested output mutation.

Malformed or empty claims and other malformed bundle input produce canonical `status: "FAIL"` with a separate `failure_kind` (`INVALID_INPUT`, `CHECK_FAILED`, or `INTERNAL_ERROR`) rather than an unhandled traceback.


### v0.7.2 patch note
This regeneration closes the remaining strict-evidence nearby-false-world gaps: every cited evidence ref must be a valid local JSON file under `evidence_root`; wrong-hash, remote, absolute-path, path-escaping, missing, or otherwise invalid refs fail even if another cited ref is valid. Plugin agent closure remains recursive over `agents/**/*.md`, and formal trace authentication still requires native Agent/Task tool-use plus successful matching tool-result/completion events before PASS-TRACKED.
