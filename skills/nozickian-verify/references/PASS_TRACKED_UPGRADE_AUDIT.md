# PASS-SCOPED to PASS-TRACKED upgrade audit

This document is the normative audit plan for upgrading a Nozickian verification result from `PASS-SCOPED` to `PASS-TRACKED` in Claude Code. It is intentionally stricter than the ordinary package self-test. A scoped pass says that deterministic package evidence is good while runtime or method limitations remain. A tracked pass says that the actual production method has been exercised and the claim-level gate has no remaining material scope limitations.

## Non-negotiable rule

Do not promote `PASS-SCOPED` to `PASS-TRACKED` by interpretation, confidence, human approval, transcript presence, or source plausibility. Promotion requires a separate PASS-TRACKED upgrade audit bundle with machine-readable artifacts. A `PASS-SCOPED` result for package structure, trace authentication, source verification, or fixture success does not automatically verify a downstream production, safety, compliance, or action-authorizing claim.

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
    claude_plugin_validate.json
    skills_ref_validate.json
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
  promotion_certificate.json
  promotion_gate.md
```

The directory may contain additional files, but the promotion certifier must be able to find every required artifact without relying on prose-only claims.

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

Required result: every deterministic check passes. These commands are necessary but not sufficient for `PASS-TRACKED`. During final certification, `certify_pass_tracked_upgrade.py` unconditionally reruns the current package's basic `validate_package.py`; a captured passing JSON file cannot substitute for that fresh run. The legacy `--run-fresh-package-validator` certifier flag remains accepted for command compatibility but no longer controls whether validation runs.

### 2. Official Claude Code validators

When the relevant validator commands are installed, capture their raw JSON or text output and exit codes:

```bash
claude plugin validate . --strict > pass_tracked_audit_bundle/official_validators/claude_plugin_validate.txt 2>&1
skills-ref validate skills/nozickian-verify > pass_tracked_audit_bundle/official_validators/skills_ref_validate.txt 2>&1
```

If an official validator is unavailable, the upgrade audit cannot certify global runtime compatibility. Record the missing validator as a scope limitation and retain `PASS-SCOPED`.

For JSON captures, success requires `type(returncode) is int and returncode == 0` plus an explicit status field equal, case-insensitively, to `pass`, `passed`, `valid`, or `success`; booleans, floats, strings, nulls, and any explicit `fail`, `failed`, `failure`, `invalid`, `error`, or `not-ok` status fail. For text captures, anchored negative statuses and anchored nonzero numeric summaries such as `1 error`, `2 errors`, `1 failure`, or `3 failed` are rejected before positive markers. Only an anchored standalone positive status line (optionally prefixed by `validation`, `validator`, `status`, or `result`) or an explicit `0 failed` line can pass. Zero summaries may accompany an anchored pass, while substrings such as `valid` inside `invalid` never count.

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

Required result: the formal result status is `PASS-TRACKED`, the strict gate result for the generated certificate is `PASS-TRACKED`, the runtime transcript authenticates every required native `ntt-*` lane, and the invocation ledger says no substitution was used. Each formal result directory must be self-contained under `formal_artifacts/...`: the transcript, generated certificate, invocation ledger, and all strict-gate evidence must be regular non-symlink files in that result directory. The certifier ignores producer-machine `output_dir`, `transcript_file`, and `evidence_root` parents; an external-only companion never satisfies promotion.

### 5. Promotion certificate and machine certification

Create `promotion_certificate.json` describing the exact upgrade claim. It must not merely copy the package self-certificate. It must include:

- `upgrade_from_status: PASS-SCOPED`.
- `requested_status: PASS-TRACKED`.
- Package version, exact `package_tree_sha256`, and release tree path.
- Deterministic command evidence refs.
- Official validator evidence refs.
- Live fixture evidence refs.
- Formal artifact evidence refs.
- Trace-authentication evidence refs.
- Claim-local scope limitations, if any.
- Derived/downstream claims with `UNVERIFIED` status unless independently verified.

`evidence_refs` must contain at least five unique relative paths. Every ref must resolve to an existing regular non-symlink file inside the audit bundle. Absolute paths, URI schemes, traversal, missing files, and duplicate raw or canonical paths fail certification.

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

Required result: `status: PASS-TRACKED`. Anything else must retain `PASS-SCOPED`, `LIMITED`, `FAIL`, or `UNVERIFIED_RUNTIME` as reported.

## PASS-TRACKED promotion criteria

The upgrade certifier must reject promotion unless all of the following are true:

1. The captured package validator, strict evidence gate, regression evals, gate contracts, formal-runner contracts, and manifest check all pass, and a fresh current basic package validator rerun also passes unconditionally during certification.
2. Official Claude Code validators pass or the declared certification scope explicitly excludes official runtime compatibility. If excluded, the result is not a full PASS-TRACKED upgrade for runtime compatibility.
3. Live fixture evals executed through the one fingerprinted absolute Claude target rather than being skipped or dry-run, after exact normalized version/plugin preflight argv, with current-run provenance, stable pre/post fingerprints, the current shared package-tree digest, exact current `evals.json` bytes, exact current fixture-ID coverage, each current artifact's exact bytes, distinct canonical bundle-local transcripts, exact transcript-byte hashes, exact normalized fixture argv using recorded `max_turns`, and canonical prompt text/hash binding to each exact fixture ID and expected artifact before independent transcript replay. These observations do not cryptographically authenticate the executable as official.
4. Formal artifact verification executed through Claude Code, not a hand-written report, with every companion and strict-gate evidence file self-contained under its bundle result directory.
5. The runtime transcript is `stream-json` or equivalent structured event output and includes authentic assistant-origin tool-use events plus matching user-origin tool-result/completion events for every required native `ntt-*` lane.
6. The generated formal certificate is evaluated by `ntt_gate.py` in strict local evidence mode and returns `PASS-TRACKED`.
7. No critical or major claim has method unknowns, unresolved contradictions, wrong hashes, missing evidence, missing modal tests, bad evidence refs, or unsupported pass labels.
8. No downstream, deployment, safety, compliance, or action-authorizing claim inherits pass status from an upstream claim without its own method, evidence, false-world tests, true-world tests, contradiction review, and residual-risk assessment.
9. The promotion certificate's exact `package_tree_sha256` matches the current-validator-derived package tree; manifest inventory paths and volatile exclusion arrays exactly match the executable current policy; and all unique evidence refs are relative regular non-symlink files inside the audit bundle.
10. All audit inputs are regular no-follow files; unreadable, symlink, FIFO, socket, device, or other special inputs fail checks and are never followed.
11. All audit artifacts are package-local or bundle-local with stable SHA-256 provenance; absolute machine-local build paths and stale release-version references are not accepted as evidence.
12. The final certification result includes a negative-control review explaining which nearby false-worlds would have been rejected and a true-world adherence review explaining which benign variations were retained.

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
