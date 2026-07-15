# Nozickian Verification — Team/Internal Reuse

A closed-surface Claude Code plugin for method-relative, Nozickian truth-tracking verification. It packages one `nozickian-verify` skill, specialist `ntt-*` subagents, deterministic validators, regression fixtures, strict local evidence gates, formal-runner trace authentication, and a PASS-SCOPED to PASS-TRACKED upgrade-audit protocol.

**Current release:** `v1.0.3`  
**Current status:** `PASS-SCOPED`  
**Intended audience:** trusted team/internal reviewers  
**Runtime posture:** closed by default; no hooks, MCP servers, commands, monitors, bins, or broad skill tool grants

Final checked-in release evidence records 1459/1459 package self-test checks, 119/119 gate contracts, 119/119 formal-runner contracts, 166/166 regression checks, and the 36/36 synthetic promotion aggregate whose complete baseline traverses 248 certifier checks. The self-test rejects 76/76 false worlds and retains 12/12 nearby true worlds. Every machine-readable release CLI is also checked to emit exactly one directly parseable JSON document.

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

The package also explicitly rejects automatic epistemic closure. A pass for claim `p` does not automatically verify an entailed, summarized, downstream, deployment, safety, compliance, or action-authorizing claim `q`. Downstream claims must be represented independently or remain `UNKNOWN`; `UNVERIFIED` is reserved for a whole-artifact gate result.

## Install / load locally

```bash
claude --plugin-dir .
```

Invoke the skill:

```text
/nozickian-truth-tracking-agentic:nozickian-verify <artifact path or verification task>
```

## Deterministic validation

Run from the package root:

```bash
python3 skills/nozickian-verify/scripts/validate_package.py . --self-test --markdown /tmp/ntt_SELF_VALIDATION_REPORT.md
python3 skills/nozickian-verify/scripts/ntt_gate.py self_validation/self_certificate.json --evidence-root . --strict-evidence --markdown /tmp/ntt_GATE_RESULT.md
python3 skills/nozickian-verify/scripts/run_regression_evals.py . --json /tmp/ntt_regression_eval_result.json
python3 skills/nozickian-verify/scripts/run_gate_contract_tests.py . --json /tmp/ntt_gate_contract_results.json
python3 skills/nozickian-verify/scripts/run_formal_runner_contract_tests.py . --json /tmp/ntt_formal_runner_contract_results.json
python3 skills/nozickian-verify/scripts/run_promotion_certifier_contract_tests.py .
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

Promotion certificate v2 requires exact-string `promotion_schema_version: "2.0"`, exact JSON types for every required top-level field, and at least one well-formed claim. Every promotion claim is evaluated through the canonical strict `ntt_gate.py` path; modeled completion requires a nonempty claim-result set whose entries all pass. Its `evidence` map has `schema_version: "promotion-evidence-v2"` and exactly nine fixed semantic roles: five deterministic captures, both official-validator policies, `live.runtime`, and `formal.result`. Every node records one canonical bundle-local regular non-symlink path, the exact `sha256:` digest of that file, and the environment-independent canonical dependencies. An explicit performed `downstream_review` may conclude that no downstream claims were identified when it supplies a substantive reason.

Deterministic suites and allowlisted official validators run fresh during certification. The Claude validator argv is exactly `claude plugin validate <package-root> --strict`; after ANSI normalization, the observed `✔ Validation passed` line is accepted, while a negative or contradictory line on either complete stream dominates. Prewritten text captures never authorize. Decisions, byte counts, and SHA-256 values use complete captured stdout/stderr bytes, with bounded public excerpts, explicit truncation metadata, and fail-closed capture limits rather than tail-only parsing. An absent official tool can be excluded only through the explicit scope flag; that changes the fresh execution result to unavailable/scoped but never removes either official-policy node or a dependency. An installed validator failure remains a failure.

Formal result `2.0` binds a standalone immutable target snapshot; exact report, gate, certificate, ledger, complete stream-json transcript, prompt, and target-snapshot companion paths/hashes/byte counts; run identity; package-tree identity; and target pre/post identity. Trace authentication reads the complete transcript, never only a tail. Typed promotion locators select `formal_result.json`; basename substitution and glob-first selection are forbidden, while unrelated nonreserved files may remain.

Malformed or empty promotion claims, failed canonical claim evaluations, and malformed bundle values produce canonical `status: "FAIL"` with `failure_kind` set to `INVALID_INPUT`, `CHECK_FAILED`, or `INTERNAL_ERROR`; they do not produce an unhandled traceback.

Caller-supplied certifier/formal output paths are checked lexically without resolving through symlinked ancestors. Symlink, special-file, hardlink-alias, or symlink-ancestor destinations return bounded structured invalid-input failures and do not overwrite external sentinels. An explicitly supplied existing private regular `--json` file is intentionally regenerated through a same-directory exclusive temporary plus atomic replacement; `--output-dir` must be a real directory or a safely created new directory.

For v1.0.3, the promotion certifier alone never authorizes `PASS-TRACKED`. A complete modeled bundle returns `status: "PASS-SCOPED"`, `outcome: "CAPPED"`, `promotion_authorized: false`, `satisfied_profile: "promotion-contract-v2-complete"`, the two explicit unresolved Issue #5 charter obligations, and a nonzero exit. Generic `ntt_gate.py` and formal-runner `PASS-TRACKED` semantics remain unchanged.

The synthetic aggregate suite exercises the production certifier CLI for its complete baseline and every negative case. Its expected `36/36` result is contract evidence, not real runtime authentication.

## GitHub README policy

GitHub-facing README files live under `docs/` and `self_validation/`. They are deliberately not placed in `agents/` or the skill runtime directories, because those locations are part of the plugin component surface. Documentation should help humans navigate the repository without adding runtime ambiguity.

## Release language

- `PASS-TRACKED`: all required claim-level evidence, method completeness, false-world tests, true-world tests, live runtime traces, and downstream non-closure checks passed.
- `PASS-SCOPED`: deterministic evidence passed, but one or more scoped unknowns remain, such as unavailable live Claude Code runtime.
- `LIMITED`: no critical failures, but important limitations remain.
- `FAIL`: one or more critical claims fail the gate.

Normal internal reuse keeps v1.0.3 at `PASS-SCOPED`. A complete v2 audit bundle demonstrates the modeled promotion contract, but the v1.0.3 certifier still applies the mandatory Issue #5 cap.
