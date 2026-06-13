# PASS-SCOPED to PASS-TRACKED upgrade audit

This document is the normative audit plan for upgrading a Nozickian verification result from `PASS-SCOPED` to `PASS-TRACKED` in Claude Code. It is intentionally stricter than the ordinary package self-test. A scoped pass says that deterministic package evidence is good while runtime or method limitations remain. A tracked pass says that the actual production method has been exercised and the claim-level gate has no remaining material scope limitations.

## Non-negotiable rule

Do not promote `PASS-SCOPED` to `PASS-TRACKED` by interpretation, confidence, human approval, transcript presence, or source plausibility. Promotion requires a separate PASS-TRACKED upgrade audit bundle with machine-readable artifacts. A `PASS-SCOPED` result for package structure, trace authentication, source verification, or fixture success does not automatically verify a downstream production, safety, compliance, or action-authorizing claim.

## Required environment

Run the upgrade audit in a clean checkout or unpacked release tree. Record the package hash, Python version, operating system, Claude Code version, authentication status, model, effort level, exact command line, and all output paths. Load the package explicitly with `--plugin-dir`; do not rely on ambient user or project configuration. Use `--output-format stream-json` and `--include-hook-events` for formal runs so the runtime transcript contains auditable event boundaries.

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

Required result: every deterministic check passes. These commands are necessary but not sufficient for `PASS-TRACKED`.

### 2. Official Claude Code validators

When the relevant validator commands are installed, capture their raw JSON or text output and exit codes:

```bash
claude plugin validate . --strict > pass_tracked_audit_bundle/official_validators/claude_plugin_validate.txt 2>&1
skills-ref validate skills/nozickian-verify > pass_tracked_audit_bundle/official_validators/skills_ref_validate.txt 2>&1
```

If an official validator is unavailable, the upgrade audit cannot certify global runtime compatibility. Record the missing validator as a scope limitation and retain `PASS-SCOPED`.

### 3. Live plugin fixture evals

```bash
python3 skills/nozickian-verify/scripts/run_live_skill_evals.py . \
  --run-fixtures \
  --require-claude \
  --output-dir pass_tracked_audit_bundle/live_fixtures/transcripts \
  --json pass_tracked_audit_bundle/live_fixtures/live_runtime_eval_result.json
```

Required result: status is not `UNVERIFIED_RUNTIME`, all fixture command return codes are zero, every transcript check passes, and no transcript substitutes an informal imitation for the plugin skill.

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

Required result: the formal result status is `PASS-TRACKED`, the strict gate result for the generated certificate is `PASS-TRACKED`, the runtime transcript authenticates every required native `ntt-*` lane, and the invocation ledger says no substitution was used.

### 5. Promotion certificate and machine certification

Create `promotion_certificate.json` describing the exact upgrade claim. It must not merely copy the package self-certificate. It must include:

- `upgrade_from_status: PASS-SCOPED`.
- `requested_status: PASS-TRACKED`.
- Package version, package hash, and release tree path.
- Deterministic command evidence refs.
- Official validator evidence refs.
- Live fixture evidence refs.
- Formal artifact evidence refs.
- Trace-authentication evidence refs.
- Claim-local scope limitations, if any.
- Derived/downstream claims with `UNVERIFIED` status unless independently verified.

Then run:

```bash
python3 skills/nozickian-verify/scripts/certify_pass_tracked_upgrade.py \
  . pass_tracked_audit_bundle \
  --json pass_tracked_audit_bundle/pass_tracked_certification_result.json
```

Required result: `status: PASS-TRACKED`. Anything else must retain `PASS-SCOPED`, `LIMITED`, `FAIL`, or `UNVERIFIED_RUNTIME` as reported.

## PASS-TRACKED promotion criteria

The upgrade certifier must reject promotion unless all of the following are true:

1. The package validator, strict evidence gate, regression evals, gate contracts, formal-runner contracts, and manifest check all pass.
2. Official Claude Code validators pass or the declared certification scope explicitly excludes official runtime compatibility. If excluded, the result is not a full PASS-TRACKED upgrade for runtime compatibility.
3. Live fixture evals executed through Claude Code rather than being skipped or dry-run.
4. Formal artifact verification executed through Claude Code, not a hand-written report.
5. The runtime transcript is `stream-json` or equivalent structured event output and includes authentic assistant-origin tool-use events plus matching user-origin tool-result/completion events for every required native `ntt-*` lane.
6. The generated formal certificate is evaluated by `ntt_gate.py` in strict local evidence mode and returns `PASS-TRACKED`.
7. No critical or major claim has method unknowns, unresolved contradictions, wrong hashes, missing evidence, missing modal tests, bad evidence refs, or unsupported pass labels.
8. No downstream, deployment, safety, compliance, or action-authorizing claim inherits pass status from an upstream claim without its own method, evidence, false-world tests, true-world tests, contradiction review, and residual-risk assessment.
9. All audit artifacts are package-local or bundle-local with stable SHA-256 provenance; absolute machine-local build paths and stale release-version references are not accepted as evidence.
10. The final certification result includes a negative-control review explaining which nearby false-worlds would have been rejected and a true-world adherence review explaining which benign variations were retained.

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
