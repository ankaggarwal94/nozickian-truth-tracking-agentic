# Structured Evidence Artifact Schema

When `--evidence-root` is supplied, strict local evidence mode treats every cited `evidence_ref` as part of the provenance boundary. Every cited local ref must resolve to a nonempty JSON evidence file under `evidence_root`; remote refs, absolute refs, path traversal, missing files, non-JSON files, wrong claim/test bindings, and wrong hashes fail. One valid evidence ref cannot mask another invalid cited ref.

Required fields:

```json
{
  "evidence_schema_version": "1.1",
  "claim_id": "C-001",
  "claim_proposition_sha256": "sha256:<digest of the canonical certificate claim text>",
  "claim_contract_schema_version": "1.1",
  "claim_contract_sha256": "sha256:<digest of the canonical assurance-bound claim contract>",
  "artifact_path": "relative/path/under/evidence_root/to/the/evidence/source",
  "command_or_source": "command, file, trace, source URL, or manual-audit context declared by the wrapper",
  "observed_result": "result text declared by the wrapper",
  "support_summary": "why the wrapper claims support for the claim or modal test",
  "timestamp_utc": "2026-05-25T00:00:00Z",
  "hash_or_version": "sha256:<64-hex digest of artifact_path>"
}
```

The package writes and the gate requires exact wrapper schema `1.1`. Legacy
wrapper `1.0` lacks the assurance-bound claim binding and fails closed. The
separately versioned observation-ledger field described below is checked for
the exact value `"1.2"`. `claim_id` must match the
claim being evaluated, or optional `applies_to_claims` must contain that claim ID
or `*`.

Every required wrapper field above is an already-canonical nonempty JSON
string; booleans, numbers, containers, Unicode/whitespace aliases, and empty
strings fail closed. The only optional wrapper keys are `applies_to_claims`,
`applies_to_tests`, `test_id`, `modal_case_sha256`, and `observation_id`; no
unknown keys are admitted. Each present `applies_to_*` value is a nonempty,
duplicate-free JSON array of canonical strings. Modal evaluation additionally
requires a canonical `test_id` or a canonical `applies_to_tests` binding. Every
present `test_id` is independently required to be a canonical nonempty string,
and every present `modal_case_sha256` must be a string-typed SHA-256 identity;
a malformed optional field fails closed even when another canonical binder
authorizes the evaluated test. A canonical primary `test_id` and a canonical
`applies_to_tests` list retain their documented OR semantics for shared wrappers.

In strict local-evidence mode, the certificate claim itself must declare
`proposition_sha256`, `claim_contract_schema_version: "1.1"`, and
`claim_contract_sha256`. Every claim-level and test-level wrapper must declare
the same identities. The proposition digest input is
the claim's `text` after Unicode NFC normalization, replacing each run of
whitespace with one ASCII space, and stripping leading and trailing whitespace.
The gate hashes the UTF-8 bytes of that canonical text with SHA-256. A declared
digest may be 64 hexadecimal characters or may use a `sha256:` or `sha256=`
prefix; hexadecimal case is normalized, but writers should emit lowercase
`sha256:<64-hex>` values. An empty or non-string proposition cannot be
canonicalized.

The assurance-bound claim contract is the following object serialized as UTF-8
JSON with sorted keys, `ensure_ascii=false`, and compact separators (`,` and
`:`):

```json
{
  "schema_version": "1.1",
  "id": "<canonical claim id>",
  "text": "<canonical claim text>",
  "scope": "<canonical nonempty claim scope>",
  "artifact_location": "<canonical nonempty artifact or referent locator>",
  "importance": "critical|major|minor",
  "method_m": {"<complete method M>": "<canonical JSON>"},
  "truth_status": "<lowercase stripped truth status>",
  "method_completeness": null,
  "unresolved_contradictions": [],
  "residual_risks": [],
  "evidence_refs": [],
  "false_world_tests": [],
  "true_world_tests": [],
  "certificate_assurance": {
    "schema_version": "1.0",
    "downstream_policy": {
      "name": "generic",
      "require_records": false,
      "require_review": false,
      "require_own_claim_field": false
    },
    "method_manifest": {},
    "scope_limitations": [],
    "unknowns": [],
    "method_unknowns": [],
    "gate_thresholds": null,
    "derived_or_downstream_claims": [],
    "downstream_review": null,
    "claim_inventory": [
      {
        "id": "<canonical claim id>",
        "local_claim_contract_sha256": "<64 lowercase hex>"
      }
    ]
  }
}
```

The downstream-policy value is the complete selected policy object, not its
name alone. The canonical settings are `generic` = `(false, false, false)`,
`package-self` = `(true, false, false)`, and `promotion-v2` =
`(false, true, true)` in `require_records`, `require_review`,
`require_own_claim_field` order. Changing either the name or any policy control
therefore changes every assurance-bound claim digest.

The claim `id`, `scope`, and `artifact_location` must be exact canonical
nonempty JSON strings; `importance` must have the exact lowercase value shown;
and `method_m` must be an object. A claim ID is never coerced from a scalar or
accepted through a Unicode/whitespace alias. Claim `evidence_refs` is a
duplicate-free JSON array of canonical nonempty strings, never a scalar alias.
`residual_risks`, `false_world_tests`, and `true_world_tests` are required JSON
arrays, including for minor claims whose valid modal arrays may be empty. At
least one of `unresolved_contradictions` or the legacy `contradictions` alias is
required, and every present spelling must be a JSON array; `null`, scalar, and
missing required collection shapes fail closed.
Every string at any depth uses the
proposition NFC/whitespace canonicalization. Arrays retain
their order because command, grader, and trace ordering can be part of method
M. JSON object order is immaterial. `unresolved_contradictions` combines the
canonical field and the legacy `contradictions` alias additively, so one spelling
cannot hide the other. The local digest in `claim_inventory` uses this same
claim payload with `certificate_assurance` set to `null`; this breaks recursion
while binding every surviving wrapper to the complete claim inventory. The gate
hashes the full canonical compact JSON bytes with SHA-256. As a result, deleting
a limitation or failed claim, changing truth/method state, editing evidence or
modal obligations, or changing downstream policy/state invalidates the existing
strict wrappers. Even minor strict claims require one structured wrapper so a
certificate cannot downgrade a claim and delete every externalized binding.

Test-level wrappers add the modal bindings shown here:

```json
{
  "evidence_schema_version": "1.1",
  "claim_id": "C-001",
  "claim_proposition_sha256": "sha256:<canonical claim digest>",
  "claim_contract_schema_version": "1.1",
  "claim_contract_sha256": "sha256:<canonical assurance-bound claim digest>",
  "test_id": "FW-001",
  "modal_case_sha256": "sha256:<canonical modal-case digest>",
  "observation_id": "obs.C-001.FW-001",
  "artifact_path": "observations/current_observations.json",
  "command_or_source": "declared source context for this case; not authenticated by the declaration ledger",
  "observed_result": "declared release result copied into the named ledger record; not execution provenance",
  "support_summary": "why this case-bound release declaration supports this nearby-world case",
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
  "claim_contract_sha256": "<64 lowercase hex characters>",
  "kind": "<lowercase stripped test kind, falling back to the expected kind>",
  "test_id": "<stripped id, falling back to test_id>",
  "target_claim_ids": ["<sorted unique stripped target IDs>"],
  "variation_field": "perturbation",
  "variation": "<canonical perturbation or variant text>",
  "world_contract": {
    "schema_version": "1.1",
    "semantic_equivalence_class": "<reviewer-assigned-lowercase-ascii-slug>",
    "operator": "mutate|preserve|remove|replace",
    "target": "<member of the closed canonical target vocabulary>",
    "precondition": "<canonical pre-state>",
    "state_delta": "<canonical state change>",
    "oracle": "<canonical decision procedure>",
    "expected_outcome": "<canonical expected result>"
  },
  "expected_behavior": "<canonical expected_behavior>",
  "observed_behavior": "<canonical observed_behavior>",
  "observed_result": "<canonical evidence-wrapper observed_result>",
  "outcome": "<lowercase stripped declared outcome>",
  "observed_outcome": "<separately lowercased observed outcome, or empty when absent>",
  "result": "<lowercase stripped result>"
}
```

Exactly one target field is present. `target_claim` is one exact canonical
nonempty string; `target_claim_ids` is a nonempty duplicate-free array of exact
canonical strings. Members are never coerced or silently stripped. Likewise,
the modal `id`/legacy `test_id` identity is an exact canonical nonempty string;
simultaneous aliases may not conflict, and modal `evidence_refs` is a
duplicate-free canonical string array. `variation_field` is
`perturbation` when that value is nonempty and otherwise is `variant`. The four
prose values use the same NFC/whitespace canonicalization as claim text. In
particular, `observed_result` comes from the evidence wrapper, so changing
either the case declaration or its declared release-result text changes the
modal-case digest. For ledger-backed modal wrappers, neither this text nor
`command_or_source` authenticates execution.

`outcome` and `observed_outcome` occupy separate positions in this payload, so
adding, removing, or changing the observed field changes `modal_case_sha256`.
When both typed fields are present they must agree; every present typed outcome
must also agree with `world_contract.expected_outcome`.

The closed `world_contract` is required for every modal test. Schema `1.1`
restricts `operator` to `mutate`, `preserve`, `remove`, or `replace`; `target`
must be a member of the gate's closed `WORLD_MUTATION_TARGETS` vocabulary; and
`expected_outcome` must be a canonical false- or true-world outcome. The three
explanatory prose fields remain nonempty canonical strings, while the
equivalence class remains an exact reviewer-assigned lowercase ASCII slug.
The closed target vocabulary is:

```text
artifact.digest
artifact.identity
artifact.path
certificate.assurance
certificate.claim_contract
certificate.evidence_refs
certificate.modal_tests
certificate.thresholds
claim.presentation
documentation.claim
evidence_wrapper.artifact_digest
evidence_wrapper.identity
evidence_wrapper.path
filesystem.entry
filesystem.parent
fixture.contract
manifest.entry
markdown.output
process.containment
process.output
release.archive
runtime.envelope
runtime.trace
workflow.command
workflow.step
```

Coverage must independently meet its threshold for (a) distinct
claim/kind/equivalence-class identities and (b) distinct typed
`(operator, target, expected_outcome)` identities. Free-form precondition,
state-delta, oracle, expected-behavior, and observed-behavior prose never
contributes to the diversity fingerprint and is never interpreted as a
polarity oracle. Those strings must be substantive and remain digest-bound
explanations for human review; deterministic authorization comes only from the
closed typed fields. The complete contract, including prose and class, remains
bound in `modal_case_sha256`. Thus punctuation, paraphrase, quoted negation, or
class relabeling cannot manufacture another nearby world. A reviewer must still
adjudicate whether a declaration chose the semantically correct operator,
target, and outcome.

Under the `package-self` downstream policy, minimum counts are not the
authorization boundary. The certificate-wide modal-test ID multiset must equal
the immutable reviewed 80-transition registry exactly: every reviewed ID
appears once, no ID is deleted or duplicated, no extra or unreviewed ID is
added, and the registry-pinned claim/kind assignment cannot move between
claims. Each pin hashes the complete canonical transition payload: registry
version, claim, test ID, kind, targets, variation field/value, full
schema-`1.1` world contract including explanatory prose, expected and observed
behavior, declared and observed outcomes, result, and optional fixture digest.
A known registry ID under a generic policy is not a fallback authorization
path.

## Observation ledger binding

`observation_id` is optional, but when present it must be an already stripped,
1-to-128-character identifier matching
`[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`. Its wrapper's `artifact_path` must identify a
JSON ledger with this shape:

```json
{
  "observation_schema_version": "1.2",
  "observations": {
    "obs.C-001.FW-001": {
      "claim_id": "C-001",
      "test_id": "FW-001",
      "kind": "false_world",
      "claim_proposition_sha256": "sha256:<canonical claim digest>",
      "claim_contract_sha256": "sha256:<canonical assurance-bound claim digest>",
      "modal_case_sha256": "sha256:<canonical modal-case digest>",
      "result": "pass",
      "outcome": "rejected_false_claim",
      "observed_result": "the exact declared release-result text copied into the evidence wrapper"
    }
  }
}
```

The ledger must have exact `observation_schema_version: "1.2"` and exactly two
top-level fields: `observation_schema_version` and `observations`. Each named
record must have exactly these fields and no others: `claim_id`, `test_id`,
`kind`, `claim_proposition_sha256`, `claim_contract_sha256`,
`modal_case_sha256`, `result`, `outcome`, and `observed_result`. Every record
value must be a JSON string. The record's `claim_id`,
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

A named, verified `observation_id` is a distinct proposition- and case-bound
release-declaration identity used for threshold deduplication. It is not
execution provenance and does not establish that a named test suite or source
case ran. Fresh self-test outcomes are established separately; this ledger does
not reconcile them per record. Without an `observation_id`, the gate falls back
to the cited artifact's SHA-256, so multiple wrappers over the same aggregate
bytes do not create multiple identities merely by using different filenames or
test labels.

## Byte-backed local evidence

Both an `evidence_ref` and its wrapper `artifact_path` must be canonical relative
POSIX paths beneath `evidence_root`. Strict mode rejects absolute paths, `.` or
`..` segments, backslashes, control characters, alias suffixes, URI schemes,
missing paths, directories, special files, and any path that traverses a
symlink. The wrapper must be a nonempty regular JSON file; the artifact must be a
regular non-symlink file. Wrappers are limited to 1 MiB, generic cited artifacts
to 64 MiB, and a named observation ledger to 8 MiB and depth 64, 100,000 JSON
nodes, and 100,000 object fields. No-follow component traversal and descriptor reads bind
whichever regular file is opened and reject size or modification-time changes
to that opened file during the read; they do not bind an earlier resolved inode
across separate opens. `hash_or_version` must be an actual SHA-256
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

The strict claim-level contract above applies both to ordinary `ntt_gate.py`
certificates and to claims embedded in promotion certificate v2. Promotion v2
uses a different top-level evidence graph and rejects legacy flat promotion
`evidence_refs`.

```json
{
  "promotion_schema_version": "2.0",
  "origin": "runtime-observed",
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
      "claim_contract_schema_version": "1.1",
      "claim_contract_sha256": "sha256:<digest of the full assurance-bound claim contract>",
      "scope": "The exact identified package snapshot and independently evaluated promotion contract only.",
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
          "target_claim_ids": ["C-UPGRADE-001"],
          "perturbation": "Use stale package bytes.",
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
          "expected_behavior": "The strict gate rejects the claim.",
          "observed_behavior": "The strict gate rejected the claim.",
          "outcome": "rejected_false_claim",
          "observed_outcome": "rejected_false_claim",
          "result": "pass",
          "evidence_refs": ["promotion_claims/C-UPGRADE-001/FW-stale.json"]
        },
        {
          "id": "FW-C-UPGRADE-001-UNBOUND",
          "kind": "false_world",
          "target_claim_ids": ["C-UPGRADE-001"],
          "perturbation": "Remove independent formal evidence.",
          "world_contract": {
            "schema_version": "1.1",
            "semantic_equivalence_class": "formal-evidence-absent",
            "operator": "remove",
            "target": "certificate.evidence_refs",
            "precondition": "The promotion claim cites independently bound formal evidence.",
            "state_delta": "Delete the formal evidence binding.",
            "oracle": "Evaluate the strict promotion evidence graph.",
            "expected_outcome": "blocked"
          },
          "expected_behavior": "The strict gate blocks the claim.",
          "observed_behavior": "The strict gate blocked the claim.",
          "outcome": "blocked",
          "observed_outcome": "blocked",
          "result": "pass",
          "evidence_refs": ["promotion_claims/C-UPGRADE-001/FW-unbound.json"]
        }
      ],
      "true_world_tests": [
        {
          "id": "TW-C-UPGRADE-001-EQUIVALENT",
          "kind": "true_world",
          "target_claim_ids": ["C-UPGRADE-001"],
          "variant": "Use equivalent independently bound evidence.",
          "world_contract": {
            "schema_version": "1.1",
            "semantic_equivalence_class": "equivalent-independent-evidence",
            "operator": "preserve",
            "target": "evidence_wrapper.identity",
            "precondition": "The original evidence is independently bound and valid.",
            "state_delta": "Replace it with semantically equivalent independently bound evidence.",
            "oracle": "Re-evaluate exact bindings and the strict claim contract.",
            "expected_outcome": "retained_true_claim"
          },
          "expected_behavior": "The strict gate retains the claim.",
          "observed_behavior": "The strict gate retained the claim.",
          "outcome": "retained_true_claim",
          "observed_outcome": "retained_true_claim",
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

The promotion certificate top-level key set is closed. In particular,
certificate-authored aliases such as `promotion_authorized`, `runtime_evidence`,
`status`, `outcome`, or `error` are invalid even when the canonical fields are
also present. `origin` is not trusted in isolation: the certifier derives the
same value from `live.runtime.provenance.evidence_origin` and
`formal.result.evidence_origin`, requires both hashed lane artifacts to agree,
and requires the declaration to match. The reconstructed
`promotion-method-m-v2` record includes that origin and the corresponding
runtime-evidence classification. This provenance classification does not remove
the release's independent `promotion_authorized: false` cap.

`promotion_schema_version` has exact string type and value `"2.0"`. The other required top-level fields have exact JSON types: `origin`, `upgrade_from_status`, `requested_status`, `package_version`, and `package_tree_sha256` are strings; `method_m_upgrade`, `live_result_bindings`, `evidence`, and `downstream_review` are objects; and `claims` plus `derived_or_downstream_claims` are arrays. `claims` must contain at least one well-formed unique claim; each includes nonempty `scope`, exact claim-contract `1.1` fields, complete modal world contracts, and is evaluated through the canonical strict gate. Modeled completion requires a nonempty all-passing result set.

The nine roles shown above are the complete fixed role set. Each node contains exactly `path`, `sha256`, and `depends_on`. Paths are canonical relative POSIX paths to bundle-local regular non-symlink files. The digest binds exact bytes. Dependencies must equal this environment-independent bounded acyclic graph. Different roles may have equal content bytes, but they may not alias one path or file identity.

Each role has lane-specific validation. Deterministic captures use `deterministic-capture-v2` and are compared with fresh fixed-argv suite execution through typed semantic projections. Official-policy nodes identify allowlisted validators that the certifier executes fresh; Claude uses exact strict argv and real ANSI-normalized success parsing. Complete stdout/stderr bytes determine semantics, hashes, and byte counts; bounded excerpts and truncation flags do not authorize. Text captures do not authorize. If an executable is absent and the explicit scope flag is supplied, the fresh execution record may say unavailable/scoped, but both official policy nodes and every dependency above remain mandatory. The formal role points directly to formal result `2.0`, which binds the standalone endpoint-checked target copy and the exact report, gate, certificate, ledger, complete transcript, prompt, and target-copy companion manifest. Trace authentication requires exactly one canonical successful SDK ResultMessage after all lane results and as the final record, with nonempty `result`, empty permission denials, null-or-absent `api_error_status`, `deferred_tool_use`, and non-structured `structured_output`, plus exact `completed`/`end_turn` for any present non-null `terminal_reason`/`stop_reason`. Its output-check projection is recomputed from the exact bound report, certificate, ledger, and gate and must be nonempty and all passing; arbitrary self-attested checks and coherently rehashed empty report or gate companions fail closed. Its execution identity must truthfully record schema-`2.0` `evidence_origin`, `temporal_immutability_enforced: false`, `process_containment.mechanism: linux-child-subreaper-plus-process-group`, `detached_session_descendants_contained: true`, `detached_descendant_survivor: false`, and `process_containment_cleanup_complete: true`. Temporal immutability caps an otherwise `PASS-TRACKED` result at `PASS-SCOPED`; unavailable containment fails before execution.

Gate Markdown, certifier JSON/Markdown, formal output plus compatibility JSON, live transcripts plus optional JSON, validator Markdown, deterministic contract/regression JSON wrappers, and the fixed behavior/stable-release manifests acquire component-wise `O_DIRECTORY`/`O_NOFOLLOW` parent capabilities before their long-running work. Writes retain those capabilities through descriptor-relative exclusive creation, link/rename installation as applicable, and directory fsync. Role/alias decisions are frozen against held identities; formal canonical-result classification is not recomputed after writes, certifier JSON/Markdown aliases fail, and live JSON cannot alias a selected transcript. Direct/ancestor links, special or hardlink sentinels, and lexical-parent replacement cannot redirect writes; validator Markdown also rechecks that its held parent remains outside the package tree. Endpoint and capability observations are not temporal isolation, so a same-UID mutation between checks remains outside the claim.

Formal children receive only runner-owned `/proc/<runner-pid>/fd/N` through `pass_fds`; procfs-visible `Pid:` must equal the gate child's direct-parent `PPid:`. Child-FD close/rebind, self/unrelated PIDs, noncanonical or nonpositive PID/FD tokens, extra components, closed descriptors, and file descriptors fail closed. Unavailable procfd support yields `INVALID_INPUT` before requested output mutation.

Malformed or empty claims and other malformed bundle input produce canonical `status: "FAIL"` with a separate `failure_kind` (`INVALID_INPUT`, `CHECK_FAILED`, or `INTERNAL_ERROR`) rather than an unhandled traceback.


### v0.7.2 patch note
This regeneration closes the remaining strict-evidence nearby-false-world gaps: every cited evidence ref must be a valid local JSON file under `evidence_root`; wrong-hash, remote, absolute-path, path-escaping, missing, or otherwise invalid refs fail even if another cited ref is valid. Plugin agent closure remains recursive over `agents/**/*.md`, and formal trace authentication still requires native Agent/Task tool-use plus successful matching tool-result/completion events before PASS-TRACKED.
