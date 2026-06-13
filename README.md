# Nozickian Verification — Team/Internal Reuse

A closed-surface Claude Code plugin for method-relative, Nozickian truth-tracking verification. It packages one `nozickian-verify` skill, specialist `ntt-*` subagents, deterministic validators, regression fixtures, strict local evidence gates, formal-runner trace authentication, and a PASS-SCOPED to PASS-TRACKED upgrade-audit protocol.

**Current release:** `v1.0.1`  
**Current status:** `PASS-SCOPED`  
**Intended audience:** trusted team/internal reviewers  
**Runtime posture:** closed by default; no hooks, MCP servers, commands, monitors, bins, or broad skill tool grants

## Documentation map

| Topic | File |
|---|---|
| Full documentation hub | [`docs/README.md`](docs/README.md) |
| Install and deterministic checks | [`docs/quickstart/README.md`](docs/quickstart/README.md) |
| Nozickian / CoVe audit model | [`docs/audit-model/README.md`](docs/audit-model/README.md) |
| Evidence and certificates | [`docs/evidence/README.md`](docs/evidence/README.md) |
| PASS-SCOPED to PASS-TRACKED audit | [`docs/pass-tracked-upgrade/README.md`](docs/pass-tracked-upgrade/README.md) |
| Runtime trace authentication | [`docs/runtime-trace-auth/README.md`](docs/runtime-trace-auth/README.md) |
| Security and threat model | [`docs/security/README.md`](docs/security/README.md) |
| Development and release workflow | [`docs/development/README.md`](docs/development/README.md), [`docs/release/README.md`](docs/release/README.md) |
| GitHub repository presentation | [`docs/github/README.md`](docs/github/README.md) |
| Bundled self-validation artifacts | [`self_validation/README.md`](self_validation/README.md) |

## What this package verifies

The package operationalizes a narrow truth-tracking standard for factual artifacts. A claim is verified only when the specified method **M** identifies the claim, binds it to local evidence, rejects nearby false worlds, retains nearby true worlds, and survives a strict gate with no unresolved critical contradictions.

The package also explicitly rejects automatic epistemic closure. A pass for claim `p` does not automatically verify an entailed, summarized, downstream, deployment, safety, compliance, or action-authorizing claim `q`. Downstream claims must be represented independently or remain `UNVERIFIED`.

## Install / load locally

```bash
claude --plugin-dir .
```

Invoke the skill:

```text
/nozickian-verification-team-internal:nozickian-verify <artifact path or verification task>
```

## Deterministic validation

Run from the package root:

```bash
python3 skills/nozickian-verify/scripts/validate_package.py . --self-test --markdown self_validation/SELF_VALIDATION_REPORT.md
python3 skills/nozickian-verify/scripts/ntt_gate.py self_validation/self_certificate.json --evidence-root . --strict-evidence --markdown self_validation/GATE_RESULT.md
python3 skills/nozickian-verify/scripts/run_regression_evals.py . --json self_validation/regression_eval_result.json
python3 skills/nozickian-verify/scripts/run_gate_contract_tests.py . --json self_validation/gate_contract_results.json
python3 skills/nozickian-verify/scripts/run_formal_runner_contract_tests.py . --json self_validation/formal_runner_contract_results.json
```

Optional official validators when installed:

```bash
claude plugin validate . --strict
skills-ref validate skills/nozickian-verify
```

Optional live Claude runtime evaluation:

```bash
python3 skills/nozickian-verify/scripts/run_live_skill_evals.py . --run-fixtures --require-claude --json self_validation/live_runtime_eval_result.json
```

If `claude` is unavailable, live runtime remains `UNVERIFIED_RUNTIME` and the package must not be promoted to PASS-TRACKED.

## Formal artifact invocation

For a machine-gated run on a real artifact:

```bash
python3 skills/nozickian-verify/scripts/run_formal_artifact_verification.py \
  . /path/to/artifact.md \
  --output-dir /path/to/formal_out \
  --require-claude \
  --require-trace-auth \
  --json /path/to/formal_out/formal_result.json
```

Use `--dry-run` only to validate deterministic prechecks and write the formal prompt. A dry run cannot establish runtime tracking.

## PASS-TRACKED upgrade audit

This package ships explicit instructions and a machine certifier for a future upgrade from `PASS-SCOPED` to `PASS-TRACKED`:

```bash
python3 skills/nozickian-verify/scripts/certify_pass_tracked_upgrade.py \
  . pass_tracked_audit_bundle \
  --json pass_tracked_audit_bundle/pass_tracked_certification_result.json \
  --markdown pass_tracked_audit_bundle/pass_tracked_certification_result.md
```

The certifier requires an external audit bundle with deterministic checks, official-validator evidence or scoped exclusions, live fixture transcripts, formal artifact traces, strict-gate PASS-TRACKED output, stale-token scans, and downstream non-closure records.

## GitHub README policy

GitHub-facing README files live under `docs/` and `self_validation/`. They are deliberately not placed in `agents/` or the skill runtime directories, because those locations are part of the plugin component surface. Documentation should help humans navigate the repository without adding runtime ambiguity.

## Release language

- `PASS-TRACKED`: all required claim-level evidence, method completeness, false-world tests, true-world tests, live runtime traces, and downstream non-closure checks passed.
- `PASS-SCOPED`: deterministic evidence passed, but one or more scoped unknowns remain, such as unavailable live Claude Code runtime.
- `LIMITED`: no critical failures, but important limitations remain.
- `FAIL`: one or more critical claims fail the gate.

Normal internal reuse should keep the package at `PASS-SCOPED` unless the PASS-TRACKED upgrade audit bundle is complete and certified.
