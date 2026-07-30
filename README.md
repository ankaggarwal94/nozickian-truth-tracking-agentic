# Nozickian Verification — Team/Internal Reuse

A closed-surface Claude Code plugin for method-relative, Nozickian truth-tracking verification. It packages one `nozickian-verify` skill, specialist `ntt-*` subagents, deterministic validators, regression fixtures, strict local evidence gates, formal-runner trace authentication, and a PASS-SCOPED to PASS-TRACKED upgrade-audit protocol.

**Current release:** `v1.0.3`  
**Current status:** `PASS-SCOPED`  
**Intended audience:** trusted team/internal reviewers  
**Runtime posture:** closed by default; no hooks, MCP servers, commands, monitors, bins, or broad skill tool grants

Final checked-in release evidence records 1827/1827 basic package checks, 2017/2017 package self-test checks, 232/232 gate contracts, 231/231 formal-runner contracts, and 166/166 regression checks. The authoritative required-before-re-review promotion aggregate passes 46/46 cases with a complete 252/252 certifier baseline. The self-test rejects 83/83 false worlds and retains 12/12 nearby true worlds. Every machine-readable release CLI is also checked to emit exactly one directly parseable JSON document.

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
python3 skills/nozickian-verify/scripts/ntt_gate.py self_validation/self_certificate.json --evidence-root . --strict-evidence --downstream-policy package-self --markdown /tmp/ntt_GATE_RESULT.md
python3 skills/nozickian-verify/scripts/run_regression_evals.py . --json /tmp/ntt_regression_eval_result.json
python3 skills/nozickian-verify/scripts/run_gate_contract_tests.py . --json /tmp/ntt_gate_contract_results.json
python3 skills/nozickian-verify/scripts/run_formal_runner_contract_tests.py . --json /tmp/ntt_formal_runner_contract_results.json
python3 skills/nozickian-verify/scripts/run_promotion_certifier_contract_tests.py .
```

On macOS, the `/tmp` output paths above are rejected by design: `/tmp` and `/var` are symlinks, and output-path hardening refuses symlinked ancestry. `validate_package.py` additionally needs a symlink-free `TMPDIR` and a `.git`-free copy of the tree, and `--self-test` plus fresh promotion certification require a Linux host. See the [macOS portability caveats](docs/quickstart/README.md#macos-portability-caveats) for the working recipe and exact boundaries.

The checked-in gate command deliberately selects `package-self`. Claim-contract
schema `1.1` binds each complete claim to a certificate-assurance payload whose
`downstream_policy` is the full canonical policy object, not a string label.
Modal world-contract schema `1.1` uses closed typed operators, targets, and
outcomes; separately hashed `outcome` and `observed_outcome` fields must agree
with the typed world outcome. Explanatory prose remains digest-bound for human
review but is never a polarity oracle. Package-self additionally requires the
certificate-wide modal ID multiset to equal all 80 immutable reviewed
transitions exactly once, including their pinned claim/kind assignments and
complete transition payloads.

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

Promotion certificate v2 requires exact-string `promotion_schema_version: "2.0"`, required string `origin`, exact JSON types and a closed top-level key set, and at least one well-formed claim with nonempty `scope`, claim-contract `1.1`, and complete modal world contracts. Every promotion claim is evaluated through the canonical strict `ntt_gate.py` path; modeled completion requires a nonempty claim-result set whose entries all pass. Its `evidence` map has `schema_version: "promotion-evidence-v2"` and exactly nine fixed semantic roles: five deterministic captures, both official-validator policies, `live.runtime`, and `formal.result`. Every node records one canonical bundle-local regular non-symlink path, the exact `sha256:` digest of that file, and the environment-independent canonical dependencies. Promotion derives `evidence_origin` from the hashed live and formal lane artifacts, requires both lanes and the certificate declaration to agree, and records it in `promotion-method-m-v2`; provenance classification does not remove the independent nonauthorization cap. An explicit performed `downstream_review` may conclude that no downstream claims were identified when it supplies a substantive reason.

Deterministic suites and allowlisted official validators run fresh during certification. The Claude validator argv is exactly `claude plugin validate <package-root> --strict`; after ANSI normalization, the observed `✔ Validation passed` line is accepted, while a negative or contradictory line on either complete stream dominates. Prewritten text captures never authorize. Decisions, byte counts, and SHA-256 values use complete captured stdout/stderr bytes, with bounded public excerpts, explicit truncation metadata, and fail-closed capture limits rather than tail-only parsing. An absent official tool can be excluded only through the explicit scope flag; that changes the fresh execution result to unavailable/scoped but never removes either official-policy node or a dependency. An installed validator failure remains a failure.

Formal result `2.0` binds a standalone endpoint-checked target copy; exact report, gate, certificate, ledger, complete stream-json transcript, prompt, and target-snapshot companion paths/hashes/byte counts; run identity; evidence origin; package-tree identity; and target pre/post endpoint identity. Trace authentication requires exactly one canonical successful SDK ResultMessage (`type=result`, `subtype=success`, `is_error=false`, empty `permission_denials`, canonical nonempty `result`) after every lane result and as the final record. `api_error_status`, `deferred_tool_use`, and non-structured-harness `structured_output` must be null or absent; a present non-null `terminal_reason` must be exact `completed`, and a present non-null `stop_reason` must be exact `end_turn`. Missing, duplicate, error, premature, aliased, API/deferred, or nested contradictory controls fail closed. Live provenance and formal `evidence_origin` use schema `2.0` and are cross-bound into `promotion-method-m-v2`. The copy is permission-hardened, but `temporal_immutability_enforced` is `false`: same-UID A→B→A mutation between checks is not mechanically excluded, so an otherwise `PASS-TRACKED` result is capped at `PASS-SCOPED`. Capture establishes supported Linux `PR_SET_CHILD_SUBREAPER` plus bounded `/proc` adopted-child tracking before `Popen`; after leader exit it kills and reaps both same-group and detached-session descendants and records `linux-child-subreaper-plus-process-group`. If containment cannot be established, execution is refused; any survivor or incomplete cleanup fails closed. Trace authentication reads the complete transcript, never only a tail. Typed promotion locators select `formal_result.json`; basename substitution and glob-first selection are forbidden, while unrelated nonreserved files may remain.

The package validator starts from one immutable, bounded, no-follow snapshot that captures every regular file's bytes. Directory, total-entry, depth, per-file, aggregate-file, and independent path/metadata ceilings apply before certification; Git discovery/index subprocesses additionally have independent time, combined-output-byte, and index-entry limits. Regular files must be private single-link entries, so an external hardlink cannot import mutable outside bytes. All authorization reads and every self-test fixture are derived from captured bytes; fixtures are materialized from that snapshot rather than copied from a later lexical package path. Finalization independently re-snapshots both the held source root and the private materialized mirror. Yielded-directory symlink substitution, outside-secret provenance substitution, transient mirror A→B→A changes, and fixture-copy races fail closed; these checks still do not claim hostile-kernel or mount-namespace isolation.

Output safety is capability-based across gate Markdown, certifier JSON/Markdown, formal output plus compatibility JSON, live transcripts plus optional JSON, validator Markdown, the four deterministic contract/regression `--json` wrappers, and the fixed behavior/stable-release manifests. Each parent is acquired component-by-component with `O_DIRECTORY`/`O_NOFOLLOW` before the corresponding long-running work and held through descriptor-relative exclusive temporary or new-file creation, link/rename installation as applicable, and directory fsync. Output-role and alias classifications are frozen from lexical names plus held identities: the formal canonical-result decision is not recomputed after writes, certifier JSON/Markdown aliases fail, and live JSON cannot alias a selected transcript. Direct or ancestor links, special/hardlink sentinels, and symlink or real-directory parent substitution cannot redirect writes; the declared fresh-versus-replaceable final-name policy still applies per output. Validator Markdown also rechecks that its held parent remains outside the package tree. These endpoint and capability checks detect and fail closed on observed substitution; they are not temporal isolation and do not mechanically exclude a same-UID mutation between observations.

Formal coordinator and gate children receive the runner-owned directory only through `/proc/<runner-pid>/fd/N` and `pass_fds`; the runner reads its procfs-visible `Pid:` and the gate requires that PID to equal its procfs-visible direct-parent `PPid:`. Child descriptor close/rebind, self or unrelated PIDs, noncanonical or nonpositive PID/FD spellings, extra components, closed descriptors, and file descriptors cannot substitute the capability. Live formal execution is Linux/procfs-specific at this boundary: unavailable POSIX procfd inheritance returns `INVALID_INPUT` before creating either the requested output directory or JSON file.

Malformed or empty promotion claims, failed canonical claim evaluations, and malformed bundle values produce canonical `status: "FAIL"` with `failure_kind` set to `INVALID_INPUT`, `CHECK_FAILED`, or `INTERNAL_ERROR`; they do not produce an unhandled traceback.

Caller-supplied output paths are traversed without following symlinked ancestors and are installed through their held parent capability. Unsafe final entries or parent substitutions return bounded structured failures without redirected overwrite. An explicitly supplied existing private regular `--json` file is intentionally regenerated through a same-directory exclusive temporary plus atomic replacement. Gate Markdown output requires a fresh final name, validator Markdown must remain outside the measured package tree, and formal `--output-dir` must be a real directory or a safely created new directory.

For v1.0.3, the promotion certifier never authorizes `PASS-TRACKED`. A complete modeled bundle returns `status: "PASS-SCOPED"`, `outcome: "CAPPED"`, `promotion_authorized: false`, `satisfied_profile: "promotion-contract-v2-complete"`, the two explicit unresolved Issue #5 charter obligations, and a nonzero exit. Generic `ntt_gate.py` `PASS-TRACKED` semantics remain unchanged. The formal runner separately caps an otherwise `PASS-TRACKED` result at `PASS-SCOPED` because temporal immutability is not mechanically enforced; unavailable process containment fails before execution rather than producing a scoped run.

The synthetic aggregate suite exercises the production certifier CLI for its complete baseline and every negative case. Its expected `46/46` result is contract evidence, not real runtime authentication.

## GitHub README policy

GitHub-facing README files live under `docs/` and `self_validation/`. They are deliberately not placed in `agents/` or the skill runtime directories, because those locations are part of the plugin component surface. Documentation should help humans navigate the repository without adding runtime ambiguity.

## Release language

- `PASS-TRACKED`: all required claim-level evidence, method completeness, false-world tests, true-world tests, live runtime traces, and downstream non-closure checks passed.
- `PASS-SCOPED`: deterministic evidence passed, but one or more scoped unknowns remain, such as unavailable live Claude Code runtime.
- `LIMITED`: no critical failures, but important limitations remain.
- `FAIL`: one or more critical claims fail the gate.

Normal internal reuse keeps v1.0.3 at `PASS-SCOPED`. A complete v2 audit bundle demonstrates the modeled promotion contract, but the v1.0.3 certifier still applies the mandatory Issue #5 cap.

Open Issues #6 and #7 remain additional explicit assurance limits: remote fetch specifications are not yet mechanically declarative/SSRF-guarded, and semantic charter presence is not yet enforced beyond manifest sealing. The current CI validates an unpacked Git tar archive; it does not produce or verify a release ZIP.
