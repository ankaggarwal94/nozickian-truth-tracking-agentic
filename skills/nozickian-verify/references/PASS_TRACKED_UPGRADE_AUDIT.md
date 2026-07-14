# PASS-SCOPED to PASS-TRACKED upgrade audit

This document is the normative audit plan for upgrading a Nozickian verification result from `PASS-SCOPED` to `PASS-TRACKED` in Claude Code. It is intentionally stricter than the ordinary package self-test. A scoped pass says that deterministic package evidence is good while runtime or method limitations remain. A tracked pass says that the actual production method has been exercised and the claim-level gate has no remaining material scope limitations.

## Non-negotiable rule

Do not promote `PASS-SCOPED` to `PASS-TRACKED` by interpretation, confidence, human approval, transcript presence, or source plausibility. Promotion requires a separate PASS-TRACKED upgrade audit bundle with machine-readable artifacts. A `PASS-SCOPED` result for package structure, trace authentication, source verification, or fixture success does not automatically verify a downstream production, safety, compliance, or action-authorizing claim.

For v1.0.3, this audit models the complete promotion contract but does not authorize promotion. Even when every modeled check passes, `certify_pass_tracked_upgrade.py` returns `status: PASS-SCOPED`, `outcome: CAPPED`, `promotion_authorized: false`, `satisfied_profile: promotion-contract-v2-complete`, both unresolved Issue #5 obligations, and a nonzero exit. This cap applies only to the v1.0.3 certifier; generic `ntt_gate.py` and `run_formal_artifact_verification.py` retain their ordinary `PASS-TRACKED` semantics.

The emitted `unresolved_charter_obligations` array is ordered and exact:

1. `Issue #5 consistency-sweep activation and resolution mechanics remain parent-enforced.`
2. `Issue #5 REMOTE_GROUND_TRUTH_REQUIRED escalation mechanics remain parent-enforced.`

## Required environment

Run the upgrade audit in a clean checkout or unpacked release tree. Record the package-tree hash, exact fixture-specification byte hash, each fixture artifact's exact byte hash, Python version, operating system, Claude Code version output, observed executable SHA-256 fingerprints before and after all fixtures, fingerprint stability, authentication status, model, effort level, exact normalized argv, and all output paths. Resolve `claude` once, fingerprint the absolute regular non-symlink target, and execute that exact target for version, plugin validation, and every fixture even when subprocess working directories change. The executable fingerprints are observational evidence only (`authentication_status=observed-not-cryptographically-authenticated`), not cryptographic proof that a binary is an official Claude build. Load the package explicitly with `--plugin-dir`; do not rely on ambient user or project configuration. Use `--output-format stream-json` and `--include-hook-events` for formal runs so the runtime transcript contains auditable event boundaries.

A certification machine must have:

- Claude Code installed and authenticated.
- Python 3.10 or newer.
- No unreviewed local edits to the release tree.
- A separate evidence bundle directory outside the package tree.
- The package loaded through `--plugin-dir` for every live or formal invocation.
- No general-purpose replacement for required native `ntt-*` lanes.

## Required audit bundle layout

Create an external directory, for example:

```text
pass_tracked_audit_bundle/
  environment.json
  commands.md
  deterministic/
    package_validation.json
    gate_result.json
    regression_eval_result.json
    gate_contract_results.json
    formal_runner_contract_results.json
    manifest_check.txt
  official_validators/
    claude_plugin_validate.policy.json
    skills_ref_validate.policy.json
  live_fixtures/
    live_runtime_eval_result.json
    transcripts/
  formal_artifacts/
    artifact-001/
      formal_result.json
      *_NOZICKIAN_REPORT.md
      *_NOZICKIAN_certificate.json
      *_NOZICKIAN_GATE.md
      *_NOZICKIAN_INVOCATION_LEDGER.md
      *_NOZICKIAN_FORMAL_TRANSCRIPT.stream.jsonl
      *_NOZICKIAN_FORMAL_PROMPT.md
      *_NOZICKIAN_TARGET_SNAPSHOT.bin
  promotion_certificate.json
  promotion_gate.md
```

The directory may contain additional nonreserved files, but typed promotion locators must select every required artifact without relying on prose-only claims, basename substitution, or glob-first selection. The promotion evidence role inventory and dependencies are fixed: all five deterministic roles, both official-policy roles, `live.runtime`, and `formal.result` remain present in every certificate.

## Required command sequence

Run these commands from the package root, writing outputs outside the package tree unless the command explicitly updates release manifests as part of a release build.

### 1. Deterministic package and gate checks

```bash
python3 skills/nozickian-verify/scripts/validate_package.py . --self-test --markdown /tmp/ntt_v101_self_validation_report.md > pass_tracked_audit_bundle/deterministic/package_validation.json
python3 skills/nozickian-verify/scripts/ntt_gate.py self_validation/self_certificate.json --evidence-root . --strict-evidence --markdown pass_tracked_audit_bundle/deterministic/gate_result.md > pass_tracked_audit_bundle/deterministic/gate_result.json
python3 skills/nozickian-verify/scripts/run_regression_evals.py . --json pass_tracked_audit_bundle/deterministic/regression_eval_result.json
python3 skills/nozickian-verify/scripts/run_gate_contract_tests.py . --json pass_tracked_audit_bundle/deterministic/gate_contract_results.json
python3 skills/nozickian-verify/scripts/run_formal_runner_contract_tests.py . --json pass_tracked_audit_bundle/deterministic/formal_runner_contract_results.json
sha256sum -c MANIFEST.sha256 > pass_tracked_audit_bundle/deterministic/manifest_check.txt
```

Wrap each captured result in `deterministic-capture-v2` metadata: exact normalized argv, exact integer-zero return code, current package-tree identity, stdout SHA-256, canonical result SHA-256, and the structured result. During certification, the certifier reruns every deterministic suite with fixed argv and compares suite-specific semantic projections. Captures cannot authorize alone, and presentation-only fields are not treated as semantics.

### 2. Official Claude Code validators

Create the typed official-policy nodes required by `promotion-evidence-v2`. During certification, the certifier resolves and executes each allowlisted validator itself:

```bash
claude plugin validate . --strict
skills-ref validate skills/nozickian-verify
```

Prewritten text or minimal JSON captures never authorize. Claude is invoked with the exact ordered argv `claude plugin validate <package-root> --strict`; losing, moving, or changing `--strict` fails. After ANSI normalization, the observed real success form `✔ Validation passed` is accepted, while negative or contradictory output anywhere on either stream dominates. `skills-ref` remains strict to its observed contract without inventing unobserved success formats. The final result records fresh normalized argv, exact integer return code, resolved executable fingerprint, package tree, and separate full-stream stdout/stderr hashes and byte counts.

All status decisions and SHA-256 values use the complete captured bytes, never a bounded excerpt or tail. Public machine results may expose sanitized bounded excerpts with explicit `stdout_truncated` / `stderr_truncated` flags and full byte/hash metadata. If a capture exceeds the explicit safety ceiling, certification fails closed; it does not discard an early failure and authenticate a valid-looking tail.

If an allowlisted validator executable is absent, certification may scope its fresh execution out only when the caller supplies the explicit official-scope-exclusion flag. This changes only the fresh execution record to unavailable/scoped: both official-policy evidence nodes and the fixed canonical dependencies remain mandatory. If the executable is installed, every nonzero return, negative/ambiguous output, or execution failure remains a failure and cannot be scoped away.

### 3. Live plugin fixture evals

```bash
python3 skills/nozickian-verify/scripts/run_live_skill_evals.py . \
  --run-fixtures \
  --require-claude \
  --output-dir pass_tracked_audit_bundle/live_fixtures/transcripts \
  --json pass_tracked_audit_bundle/live_fixtures/live_runtime_eval_result.json
```

Required result: status is `PASS-SCOPED`; provenance schema is `1.0`; provenance status is `observed-current-run`; `source_release` exactly equals the current plugin version; `carried_forward` is false; `observed_at_utc` is a valid UTC timestamp; top-level `package_tree_algorithm` is exactly `ntt-stable-release-tree-v1`; top-level `package_tree_sha256` is the current shared-validator digest; top-level `fixture_spec_sha256` hashes the exact current `evals.json` bytes; `run_config.max_turns` is a positive integer and the remaining fixed invocation settings are recorded; aggregate preflight is successful; the pre/post executable fingerprints are 64 lowercase hex, equal, and accompanied by `fingerprint_stable=true`; recorded version output matches the fixed version pattern; both version and plugin-validation commands return zero; and the observational authentication limitation remains explicit.

The two preflight transcript commands must contain exactly these normalized argv arrays, in this order, with no extra or missing argument:

```json
["<claude-cli>", "--version"]
["<claude-cli>", "plugin", "validate", "<package-root>"]
```

The result must contain exactly the fixture IDs currently declared in `skills/nozickian-verify/evals/evals.json`, each once. A partial `--max-fixtures` run cannot promote a package with more fixtures. Every fixture record contains its unique ID, normalized artifact display, lowercase `artifact_sha256` over the exact current artifact bytes, normalized prompt display, `prompt_sha256`, normalized `transcript_file`, and `transcript_sha256`. The prompt digest is over the exact UTF-8 bytes of the canonical normalized-display prompt written into the result and transcript command: the exact package root is replaced with `<package-root>` and all other prompt bytes are preserved. The transcript digest is over the exact JSON file bytes written by the harness. These self-recorded hashes bind fixture/result/transcript consistency inside the bundle; they do not cryptographically authenticate the transcript producer or prove that the executable is an official binary.

Each fixture must resolve to a distinct canonical bundle-local transcript path at `live_fixtures/transcripts/<basename>`; sharing one transcript across fixture IDs is a critical failure even when its report mentions every artifact. Every transcript must be a regular non-symlink file and match that fixture's `transcript_sha256`. The certifier parses the transcript `cmd`, rebuilds the current prompt with `run_live_skill_evals.build_fixture_prompt`, applies the same deterministic `<package-root>` display normalization, and requires exact prompt text plus SHA-256 agreement with the fixture record. It also requires the transcript command to equal this exact normalized argv, in this exact order, with no extra or missing argument:

```json
["<claude-cli>", "--plugin-dir", "<package-root>", "-p", "--output-format", "json", "--max-turns", "<recorded positive integer>", "<canonical normalized prompt>"]
```

Prompt presence alone is insufficient. Missing `--plugin-dir`, a wrong output format or max-turn count, an extra argument, or reordered arguments is a critical failure even if the final prompt and report are otherwise valid. Prompt text/hash, transcript bytes/hash, fixture ID, artifact path, artifact bytes/hash, report replay, and exact argv remain independently checked.

Before replaying reports, the certifier recomputes the current shared package-tree digest, exact `evals.json` digest, and exact artifact digest for every expected fixture. Changing an artifact, changing `evals.json`, or changing any other stable package behavior source after capture invalidates stale live evidence even if both manifests are refreshed and current package validation passes.

After those bindings pass or fail independently, the certifier still replays the current harness's `transcript_checks` against each transcript's recorded `stdout` and requires exact agreement with the self-reported checks. The replay must establish a structured JSON envelope, no error envelope, a substantive `result` or `content` report, artifact identity, and `passed=true`. External absolute transcript paths, fabricated check summaries, shared transcripts, and prompt/hash substitutions are not fallback evidence.

### 4. Formal artifact verification with native trace authentication

Run at least one representative real artifact. More artifacts are required if the claims being promoted cover multiple methods, domains, or action surfaces.

```bash
python3 skills/nozickian-verify/scripts/run_formal_artifact_verification.py \
  . /path/to/representative-artifact.md \
  --require-claude \
  --require-trace-auth \
  --evidence-root pass_tracked_audit_bundle/formal_artifacts/artifact-001 \
  --output-dir pass_tracked_audit_bundle/formal_artifacts/artifact-001 \
  --json pass_tracked_audit_bundle/formal_artifacts/artifact-001/formal_result.json
```

Required result: `formal_result_schema_version` is `2.0`; the generic formal result and generated strict gate are `PASS-TRACKED`; the runtime transcript authenticates every required native `ntt-*` lane; and no substitution was used. The result binds an immutable standalone target snapshot, exact companion manifest (report, gate, certificate, ledger, complete transcript, prompt, and target snapshot), package-tree identity, run ID, target snapshot identity, and target pre/post stability. The complete stream-json transcript is written and hashed before authentication; neither tail truncation nor a display excerpt can establish a lane. Relative sibling context from the mutable source location is explicitly unavailable in this mode.

The promotion certificate points to the canonical `formal_result.json` through its typed `formal.result` node. The certifier does not substitute a basename or choose a first glob match. Undeclared reserved companions fail, while unrelated nonreserved files may remain.

### 5. Promotion certificate and machine certification

Create `promotion_certificate.json` describing the exact upgrade claim. It must not merely copy the package self-certificate. It must include:

- Exact-string `promotion_schema_version: "2.0"`.
- `upgrade_from_status: PASS-SCOPED`.
- `requested_status: PASS-TRACKED`.
- Package version and exact `package_tree_sha256`.
- Object-valued `method_m_upgrade`, `live_result_bindings`, `evidence`, and `downstream_review`; array-valued `claims` and `derived_or_downstream_claims`; and string-valued status/version/hash fields.
- `evidence.schema_version: promotion-evidence-v2`.
- A typed `evidence.nodes` map whose fixed nine semantic roles contain exactly `path`, `sha256`, and `depends_on`.
- Canonical role dependencies forming a bounded acyclic graph.
- Exact byte/SHA-256 binding and role-specific validation for every deterministic, official-policy, live, and formal node.
- At least one promotion claim. Every `claims` entry is an object with exact required field types, a unique canonical ID, a complete method manifest, local evidence, false-world tests, true-world tests, contradiction review, and residual-risk review.
- `downstream_review` with `performed: true`, `claims_identified`, and `none_identified_reason` when the list is empty.
- Claim-local scope limitations, if any.
- Derived/downstream claims with `UNVERIFIED` status unless independently verified.

Legacy flat promotion `evidence_refs` fail. Missing/wrong-type top-level schema fields, non-object claim entries, null or boolean aliases, duplicate/invalid IDs, and an empty claims array fail with canonical `FAIL` plus `INVALID_INPUT`. The certifier evaluates every well-formed claim through the canonical `ntt_gate.evaluate_certificate` path using the bundle evidence root and promotion policy. Modeled completion requires a nonempty claim-result set whose entries all pass before the actual results are passed to promotion-strict downstream non-closure evaluation. An explicitly empty downstream-conclusions list remains valid when the certificate has a real passing promotion claim and a substantive performed-review reason. Every typed node path must be canonical, relative, bundle-local, regular, and non-symlink. Absolute paths, URI schemes, traversal, aliases by canonical path or file identity, missing files, wrong bytes, wrong hashes, wrong role paths, and noncanonical dependencies fail. Distinct semantic roles may contain equal bytes, but they may not alias the same path or file identity.

### Deterministic package-tree hash

The package-local `validate_package.compute_stable_release_tree` helper is the single source for `package_tree_sha256` algorithm identifier `ntt-stable-release-tree-v1`; both the live harness and certifier invoke it:

1. Read `STABLE_RELEASE_MANIFEST.json` only as a regular non-symlink file.
2. Recompute its self-hash from canonical JSON (`sort_keys=true`, separators `,` and `:`, UTF-8 with `ensure_ascii=false`) after setting `self_hash_sha256` to null, and require exact lowercase-hex equality.
3. Independently execute the helper's current `iter_release_inventory_files(package_root)` policy and derive `VOLATILE_RELEASE_EXCLUSION_FILES` plus `VOLATILE_RELEASE_EXCLUSION_PREFIXES` from the current validator; require the manifest's `volatile_generated_exclusions.files` and `.prefixes` arrays to equal the sorted current policy exactly.
4. Require the manifest `file_inventory` path set to equal the independently derived path set exactly. Manifest-authored exclusions never decide which stable files exist, so adding a behavior file to the manifest exclusion arrays and removing its inventory row still fails.
5. Walk without following links to reject unsafe entries. For every independently derived path, require a regular non-symlink file and exact lowercase SHA-256 and byte-count equality with its manifest row.
6. Build this canonical payload:

```json
{
  "algorithm": "ntt-stable-release-tree-v1",
  "manifest_identity": {
    "schema_version": "...",
    "package": "...",
    "plugin_version": "...",
    "release_lock_version": "...",
    "self_file": "STABLE_RELEASE_MANIFEST.json",
    "self_hash_sha256": "...",
    "file_count_excluding_self": 0
  },
  "actual_inventory": [
    {"path": "...", "sha256": "...", "bytes": 0}
  ]
}
```

The inventory is sorted by path, then the whole payload is serialized with the same canonical JSON settings and SHA-256 hashed. The certificate must contain exactly `package_tree_sha256: "sha256:<lowercase hex>"`. `package_sha256` aliases and arbitrary `sha256:` strings are ignored.

Then run:

```bash
python3 skills/nozickian-verify/scripts/certify_pass_tracked_upgrade.py \
  . pass_tracked_audit_bundle \
  --json pass_tracked_audit_bundle/pass_tracked_certification_result.json
```

Required v1.0.3 result for a complete modeled bundle: `status: PASS-SCOPED`, `outcome: CAPPED`, `promotion_authorized: false`, `satisfied_profile: promotion-contract-v2-complete`, both exact unresolved Issue #5 obligations, and exit code `2`. Any malformed or failed modeled check returns canonical `status: FAIL` plus `failure_kind`; untrusted bundle values must not produce an unhandled traceback.

## PASS-TRACKED promotion criteria

The upgrade certifier must reject promotion unless all of the following are true:

1. The captured package validator, strict evidence gate, regression evals, gate contracts, and formal-runner contracts all match fresh fixed-argv executions through suite-specific semantic projections.
2. Fresh allowlisted official validators pass. Only absent executables may be explicitly scoped; scoped absence retains both official-policy nodes and the same fixed role DAG, while installed failures fail.
3. Live fixture evals executed through the one fingerprinted absolute Claude target rather than being skipped or dry-run, after exact normalized version/plugin preflight argv, with current-run provenance, stable pre/post fingerprints, the current shared package-tree digest, exact current `evals.json` bytes, exact current fixture-ID coverage, each current artifact's exact bytes, distinct canonical bundle-local transcripts, exact transcript-byte hashes, exact normalized fixture argv using recorded `max_turns`, and canonical prompt text/hash binding to each exact fixture ID and expected artifact before independent transcript replay. These observations do not cryptographically authenticate the executable as official.
4. Formal result `2.0` executed through Claude Code against the immutable standalone target snapshot, with exact package/run/target identities and every typed companion self-contained under its bundle result directory.
5. The runtime transcript is `stream-json` or equivalent structured event output and includes authentic assistant-origin tool-use events plus matching user-origin tool-result/completion events for every required native `ntt-*` lane.
6. The generated formal certificate is evaluated by `ntt_gate.py` in strict local evidence mode and returns `PASS-TRACKED`.
7. No critical or major claim has method unknowns, unresolved contradictions, wrong hashes, missing evidence, missing modal tests, bad evidence refs, or unsupported pass labels.
8. No downstream, deployment, safety, compliance, or action-authorizing claim inherits pass status from an upstream claim without its own method, evidence, false-world tests, true-world tests, contradiction review, and residual-risk assessment.
9. The promotion certificate's exact `package_tree_sha256` matches the current-validator-derived package tree; manifest inventory paths and volatile exclusion arrays exactly match executable policy; and every typed evidence role binds a distinct canonical regular non-symlink bundle file by exact bytes and SHA-256.
10. All audit inputs are regular no-follow files; unreadable, symlink, FIFO, socket, device, or other special inputs fail checks and are never followed.
11. All audit artifacts are package-local or bundle-local with stable SHA-256 provenance; absolute machine-local build paths and stale release-version references are not accepted as evidence.
12. The final certification result includes a negative-control review explaining which nearby false-worlds would have been rejected and a true-world adherence review explaining which benign variations were retained.
13. The promotion certificate supplies explicit `downstream_review` and does not use a fake or self-referential independent claim ID.
14. v1.0.3 applies the mandatory certifier-only cap after all modeled checks pass; it does not implement or claim closure of Issue #5.

### Safe output destinations

Caller-supplied certifier `--json`, formal `--output-dir`, and formal compatibility `--json` paths are validated lexically component by component without resolving through attacker-controlled links. Symlinked ancestors, direct symlinks, special files, and hardlink aliases fail with bounded structured invalid-input output and no external overwrite. An explicitly supplied existing private regular `--json` file is intentionally replaceable for normal regeneration: bytes are written to a same-directory exclusive no-follow temporary and installed with atomic replacement. An existing regular file is never accepted as `--output-dir`; that path must be a real directory or a safely created new directory.

## Aggregate contract evidence

Run:

```bash
python3 skills/nozickian-verify/scripts/run_promotion_certifier_contract_tests.py .
```

The expected result is `36/36`. The suite invokes the production certifier CLI for the complete synthetic baseline and every negative case. It verifies exact top-level schema types, the fixed typed DAG under both validator-available and explicitly scoped-unavailable states, exact strict-validator argv and real ANSI-normalized success output, early official failure after more than 50KB of neutral output, fresh deterministic/official execution policy, a real distinct independently passing downstream claim, malformed and empty claims, formal v2 bindings including an early disallowed event before more than 50KB of valid-looking tail, complete transcript hashes/byte counts, output-path safety and atomic regular-file replacement, structured failures, the exact ordered Issue #5 obligations, and the mandatory cap. Synthetic origin is fully evaluated and then capped; this suite is not real runtime authentication.

## Downgrade rules

Use the strongest applicable downgrade:

- `UNVERIFIED_RUNTIME`: Claude Code was unavailable, not authenticated, or not invoked.
- `PASS-SCOPED`: deterministic and some live evidence passed, but any runtime, official-validator, representative-artifact, method, or scope limitation remains.
- `LIMITED`: no critical failure, but major evidence, modal tests, or trace-authentication elements are incomplete.
- `FAIL`: critical claim failure, gate failure, formal runner failure, spoofed trace, stale evidence, unsupported pass label, or automatic downstream closure.

## Audit report table

Every promotion report must include this table shape:

| Promotion condition | Evidence artifact | Hash | Result | Residual risk |
|---|---|---:|---|---|
| Deterministic package validator | deterministic/package_validation.json | sha256:... | PASS | none |
| Strict package self-gate | deterministic/gate_result.json | sha256:... | PASS-SCOPED or PASS-TRACKED | explain |
| Live fixture runtime | live_fixtures/live_runtime_eval_result.json | sha256:... | PASS/FAIL | explain |
| Formal runtime trace auth | formal_artifacts/artifact-001/formal_result.json | sha256:... | PASS-TRACKED/FAIL | explain |
| Generated formal gate | formal_artifacts/artifact-001/*_GATE.md | sha256:... | PASS-TRACKED/FAIL | explain |
| Official validators | official_validators/* | sha256:... | PASS/FAIL/MISSING | explain |
| Downstream claims | promotion_certificate.json | sha256:... | UNVERIFIED or independently verified | explain |

## Anti-hallucination requirements for Claude Code

Claude Code must quote file paths, command lines, exit codes, and hashes from the bundle. It must not infer success from absence of errors. It must not summarize a transcript as authenticated unless the trace parser authenticates native tool-use/result event pairs. It must not use prose from the report as a substitute for strict-gate JSON. It must not upgrade merely because a prior package release was already `PASS-SCOPED`.

No automatic promotion or no automatic downstream status transmission is allowed in this audit path.
