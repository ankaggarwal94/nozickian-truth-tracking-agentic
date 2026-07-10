# Team/Internal Reuse Policy

This package is scoped for team/internal reuse, not public marketplace distribution.

## Assurance target

Use the package as a structured Nozickian verification scaffold with deterministic package validation, release-lock checks, manifest hashing, regression fixtures, and optional live Claude Code runtime evals.

It is not intended to prove against a hostile maintainer who can rewrite the validator, manifests, certificates, and CI at once. It is intended to catch ordinary team-reuse failures: accidental runtime-surface expansion, unsafe tool grants, missing modal tests, stale manifests, broken fixture paths, degraded verifier prompts, and unreviewed changes.

## Required team workflow

Before sharing a changed package internally:

1. Review the diff of `SKILL.md`, `agents/**/*.md`, `scripts/*.py`, `evals/evals.json`, `PACKAGE_SURFACE.json`, `RELEASE_LOCK.json`, and `.claude-plugin/plugin.json`.
2. Run deterministic validation:

```bash
python3 skills/nozickian-verify/scripts/validate_package.py . --self-test --markdown self_validation/SELF_VALIDATION_REPORT.md
python3 skills/nozickian-verify/scripts/ntt_gate.py self_validation/self_certificate.json --evidence-root . --strict-evidence --markdown self_validation/GATE_RESULT.md
python3 skills/nozickian-verify/scripts/run_regression_evals.py . --json self_validation/regression_eval_result.json
```

3. On machines with Claude Code installed, run live fixture checks:

```bash
python3 skills/nozickian-verify/scripts/run_live_skill_evals.py . --run-fixtures --json self_validation/live_runtime_eval_result.json
```

4. Treat `PASS-SCOPED` as the normal team-internal release label until live runtime fixture transcripts are present and reviewed.

## Scope boundary

The validator intentionally rejects plugin-root hooks, bins, monitors, MCP/LSP configs, settings activation, broad skill `allowed-tools`, dynamic skill shell substitutions, manifest-declared runtime components, and unmanifested agents. Those can be added later, but only by explicitly changing the surface policy, adding focused tests, and raising the review tier.

## Formal invocation addendum

A prose audit that applies this skill's protocol is useful, but a formal package invocation requires the additional machine-gated artifacts:

- invocation through the `ntt-formal-coordinator` main agent or an explicit downgrade if that agent cannot run;
- native `ntt-*` lane use, with `FORMAL_SUBAGENT_FAILURE` if any lane is unavailable or replaced by `general-purpose`;
- a report, a machine-readable certificate JSON, a gate Markdown file produced by `ntt_gate.py`, and an invocation ledger;
- a saved transcript when `run_formal_artifact_verification.py` invokes Claude Code.

For internal review, do not promote an artifact-verification run to `PASS-TRACKED` if the run only produced prose, skipped `certificate.json`, skipped `ntt_gate.py`, or used role-equivalent fallback agents without recording the downgrade.


### Trace-authentication regeneration patch note (`v1.0.1_patch_notes` release)
That regeneration closed the remaining trace-authentication and URI-scheme edge cases found after the late pre-1.0 hardening series. Team review should verify that `nested_tool_result_inside_tool_input_does_not_authenticate`, `nested_tool_result_inside_arguments_does_not_authenticate`, `tool_result_before_tool_use_does_not_authenticate`, and `same_event_input_embedded_result_does_not_authenticate` pass in `formal_runner_contract_results.json`. Strict local evidence mode now rejects any non-empty URI scheme, including uppercase and mixed-case `HTTPS://`, `DOI:`, `URN:`, and scheme-like refs; review `uppercase_https_evidence_ref_rejected`, `mixed_case_https_evidence_ref_rejected`, `uppercase_doi_urn_refs_rejected`, and `scheme_like_evidence_ref_rejected_in_strict_mode` in `gate_contract_results.json`.

## Release idempotence addendum

Normal release-lock validation must not write generated formal-runner artifacts into the package tree. Use the external `../ntt_release_formal_invocation_dry_run` paths from `RELEASE_LOCK.json`, or choose another out-of-tree directory. In-tree generated outputs are allowed only when `run_formal_artifact_verification.py` is invoked with `--refresh-release-manifest`, after which the stable release manifest must be reviewed again.


## Release-lock idempotence note

The release-lock command chain invokes `validate_package.py . --self-test` inside the idempotence regression so the command list can be replayed without recursively spawning another release-lock replay. A normal maintainer self-test without that flag still exercises the release-lock idempotence check.


### Trace-authentication addendum

PASS-TRACKED trace authentication must parse only recognized stream-json event positions. Do not count fake `tool_result` dictionaries embedded inside `tool_use.input`, `arguments`, `args`, or `parameters`; they are tool input data, not runtime completion events. A successful result/completion must explicitly match the native tool-use id and appear after that tool-use event. Strict local evidence mode rejects all URI-scheme evidence refs case-insensitively, including uppercase HTTPS/DOI/URN and arbitrary scheme-like refs.


## Trace/evidence hardening note

PASS-TRACKED runtime promotion requires authentic tool-use/tool-result event types, exact structured ntt-* selectors, matching post-call result IDs, no unexpected Agent/Task calls, and no text/message masquerade. Strict local evidence rejects URI-scheme evidence_refs and URI-scheme artifact_path values.

## Reviewer note
Check formal traces for payload-bearing result content, not merely success-like metadata. Check strict evidence ledgers for unique evidence-file identities and unique artifact/hash identities; duplicate refs or aliases should not satisfy critical claim evidence minima.

## Release-provenance hygiene addendum

Before reuse, review the validator output for the release-provenance hygiene check. Bundled audit and self-validation artifacts must not contain stale prior-version package roots, stale targeted-probe names, or machine-local build paths. This check is intentionally about release evidence hygiene; it does not promote the package beyond PASS-SCOPED without live runtime traces.

This package remains deliberately closed-surface. It is not a general validator for all platform-supported plugin extension points; adding hooks, MCP/LSP surfaces, commands, bins, monitors, manifest component-path fields, dynamic skill shell, or broad tool grants is a policy change requiring new evidence and review.


## No automatic downstream closure

Do not treat `PASS-SCOPED` or `PASS-TRACKED` for a source claim as inherited proof of an entailed deployment, safety, compliance, production-readiness, or action-authorizing claim. Record each such downstream conclusion as its own claim or as a `derived_or_downstream_claims` record. Untested downstream claims are `UNVERIFIED`.

## PASS-TRACKED promotion protocol

Do not label a run `PASS-TRACKED` merely because this package validates or because a previous release was `PASS-SCOPED`. For promotion, create an external `pass_tracked_audit_bundle/` using `skills/nozickian-verify/references/PASS_TRACKED_UPGRADE_AUDIT.md`, run live Claude Code fixture evals, run at least one formal artifact verification with `--require-claude` and `--require-trace-auth`, capture official validator outputs, then run `certify_pass_tracked_upgrade.py` against the bundle.

If the certifier returns anything other than `PASS-TRACKED`, retain the returned downgrade status. Missing Claude Code CLI, missing official validators, missing native `ntt-*` subagent trace authentication, dry-run-only formal results, or automatic downstream pass inheritance are promotion blockers.


## GitHub README documentation review

For this release line, GitHub-facing README files belong under `docs/` and `self_validation/`. Do not add README files to plugin-loadable runtime component directories such as `agents/` or `skills/nozickian-verify/` unless the closed-surface policy and validator are intentionally redesigned. Reviewers should treat documentation as stable release content: it must be included in the stable release manifest and must not contain stale package roots, local build paths, or status inflation from PASS-SCOPED to PASS-TRACKED.
