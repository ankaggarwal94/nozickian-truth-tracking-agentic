---
name: nozickian-verify
description: 'Verify factual artifacts, code, technical manuals, RAG answers, tool outputs, and agent traces using a strict Nozickian truth-tracking standard: identify atomic claims, reconstruct the real method M, test nearby false-world rejection, test nearby true-world adherence, and issue a scoped gate result. Use when the user asks to verify factual writing, claims, docs, generated code behavior, or agentic workflow outputs.'
compatibility: 'Designed for Claude Code plugins and standalone Agent Skills. Requires Python 3.10+ for deterministic gate scripts; live evals require Claude Code CLI and explicit fixture invocation.'
---

# Nozickian Verify

This package is closed-surface by default: it does not ship hooks, monitors, MCP/LSP configs, bins, settings.json, commands, or extra agents. Treat additions to those plugin-loadable surfaces as a separate method M that requires new verification.

Use this skill to verify artifacts under a method-relative truth-tracking standard. Do not treat citations, groundedness, confidence, human approval, or passing examples as sufficient by themselves. Verification requires evidence that the actual production method would reject nearby falsehoods and retain nearby truths within an explicit scope.

## Required references

Before doing nontrivial verification, read these support files as needed:

- `references/STANDARD.md` - formal verification standard and gate levels.
- `references/SUBAGENT_PROTOCOLS.md` - delegation plan and subagent output contracts.
- `references/ARTIFACT_GUIDE.md` - code/prose/manual/RAG/trace-specific perturbations.
- `references/OUTPUT_TEMPLATES.md` - report and certificate templates.
- `references/EVAL_BEST_PRACTICES.md` - deterministic eval and live-eval guidance.
- `references/PASS_TRACKED_UPGRADE_AUDIT.md` - required audit workflow for certifying an upgrade from PASS-SCOPED to PASS-TRACKED.
- `references/SOURCES.md` - provenance for the standard and tooling assumptions.

## Activation checklist

1. Identify the artifact and scope. If the artifact is missing or ambiguous, state the ambiguity and proceed only on clearly identified material.
2. Reconstruct method `M`: prompts/instructions, model, retrieval corpus, tool versions, execution environment, trace, graders, human approvals, and release constraints.
3. Decompose the artifact into atomic factual claims and behavioral claims. Include code comments, docstrings, manual steps, output statements, hidden assumptions, tool-result claims, and any entailed downstream or action-authorizing conclusions. Do not let a verified claim transmit status automatically to a downstream claim without its own method, evidence, and modal tests.
4. Classify each claim: critical, major, or minor. Critical claims affect safety, correctness, security, legality, money, medical/legal/financial advice, release gating, or user action.
5. For each critical and major claim, require evidence of:
   - Truth or scoped truth.
   - Method completeness.
   - Nearby false-world rejection.
   - Nearby true-world adherence.
   - Unresolved contradictions and residual risk.
6. Use subagents aggressively for large artifacts. Keep the parent context focused on decisions, evidence summaries, and gate state.
7. Run deterministic scripts where applicable:

```bash
python3 skills/nozickian-verify/scripts/ntt_gate.py <certificate.json> --markdown <gate.md>
python3 skills/nozickian-verify/scripts/validate_package.py <plugin-root> --self-test --markdown <report.md>
```

8. If the user asks to certify or promote PASS-SCOPED to PASS-TRACKED, require the separate PASS-TRACKED upgrade audit bundle, live Claude Code fixture run, formal artifact run with trace authentication, official validator outputs, and `certify_pass_tracked_upgrade.py`; otherwise retain PASS-SCOPED or lower.
9. Report a gate result using only these statuses: `PASS-TRACKED`, `PASS-SCOPED`, `LIMITED`, `FAIL`, or `UNVERIFIED`.

## Delegation pattern

Use the following subagents when available:

- `ntt-method-cartographer`: reconstruct method M and identify unknowns.
- `ntt-claim-extractor`: extract and rank atomic claims.
- `ntt-source-verifier`: verify source/provenance claims and detect stale or context-only support.
- `ntt-code-verifier`: test code behavior, build/test commands, dependency drift, and mutation-resistant evidence.
- `ntt-false-world-adversary`: construct and test nearby false worlds.
- `ntt-true-world-adherence`: construct and test nearby true worlds.
- `ntt-gate-auditor`: independently audit the certificate and gate result.
- `ntt-skill-self-auditor`: validate this package or another skill/plugin against the same standard.

For complex codebases or documents, dispatch many narrow subagent tasks rather than asking one agent to hold the entire artifact. Ask each subagent to return only claim IDs, evidence IDs, pass/fail/unknown status, and residual risks.

## Nozickian minimums

A claim is not verified merely because it is cited, plausible, grounded to retrieved context, approved by a human, or accepted by an LLM judge. It is verified only when the certificate shows:

- `p` is true or conditionally true within stated scope.
- The real method `M` that produced and checked `p` is identified.
- In relevant nearby worlds where `p` is false, `M` rejects, revises, or flags `p`.
- In relevant nearby worlds where `p` remains true, `M` retains or recovers `p`.
- The gate thresholds are met and not self-relaxed by the certificate.

## Required output

Always include:

1. Scope and artifact identity.
2. Method `M` summary and unknowns.
3. Claim table with importance and status.
4. False-world sensitivity evidence.
5. True-world adherence evidence.
6. Contradictions and residual risks.
7. Derived/downstream claims, if any, with independent status rather than inherited closure.
8. Final gate result.
9. Commands run and artifacts generated.

If live runtime testing was not performed, say so explicitly and downgrade to `PASS-SCOPED`, `LIMITED`, or `UNVERIFIED` as appropriate.

## Formal invocation mode

Use formal invocation mode when the user asks for a perfect formal run, machine-gated verification, or proof that the package itself was invoked rather than informally imitated.

Formal mode requires:

1. Main-thread coordinator: `ntt-formal-coordinator`.
2. Native `ntt-*` lanes, not silent `general-purpose` substitution.
3. A Markdown report.
4. A machine-readable certificate JSON.
5. A gate Markdown file generated by `ntt_gate.py`.
6. An invocation ledger recording skill name, coordinator, native subagents requested/completed, substitutions, commands, output paths, gate status, and downgrade reasons.
7. A saved runtime transcript when invoked through the CLI runner.
8. For `PASS-TRACKED`, trace-authenticated native Agent/Task tool-use events for every required `ntt-*` lane; a ledger assertion alone is insufficient.
9. Structured local evidence artifacts bound to claim IDs and test IDs for gate evidence refs.

The formal runner is:

```bash
python3 skills/nozickian-verify/scripts/run_formal_artifact_verification.py \
  <plugin-root> <target-artifact> \
  --output-dir <formal-output-dir> \
  --require-claude
```

If native `ntt-*` agents are unavailable or the stream-json transcript does not authenticate their Agent/Task tool-use events, write `FORMAL_SUBAGENT_FAILURE` or a trace-authentication downgrade and do not claim `PASS-TRACKED`. Do not treat a role-equivalent general-purpose subagent pass as a perfect formal invocation. If `certificate.json` or the `ntt_gate.py` output is missing, the run is protocol-level only and cannot be `PASS-TRACKED`.


### v1.0.1 patch note
This regeneration hardens formal trace authentication beyond exact tool-use id matching. A `PASS-TRACKED` formal run requires native `ntt-*` Agent/Task tool-use events from recognized stream-json event positions, followed by separate successful result/completion events whose explicit `tool_use_id` or `tool_call_id` matches the tool-use id. Result-shaped objects nested inside `input`, `arguments`, or same-event data do not authenticate a lane, and result-before-call ordering is rejected. Strict local evidence rejects case-insensitive and scheme-like URI refs in addition to lowercase remote refs.


## v1.0.1 release-lock idempotence note

The release-lock command chain invokes `validate_package.py . --self-test` inside the idempotence regression so the command list can be replayed without recursively spawning another release-lock replay. A normal maintainer self-test without that flag still exercises the release-lock idempotence check.


### v1.0.1 trace-authentication addendum

PASS-TRACKED trace authentication must parse only recognized stream-json event positions. Do not count fake `tool_result` dictionaries embedded inside `tool_use.input`, `arguments`, `args`, or `parameters`; they are tool input data, not runtime completion events. A successful result/completion must explicitly match the native tool-use id and appear after that tool-use event. Strict local evidence mode rejects all URI-scheme evidence refs case-insensitively, including uppercase HTTPS/DOI/URN and arbitrary scheme-like refs.


## v1.0.1 trace/evidence hardening note

PASS-TRACKED runtime promotion requires authentic tool-use/tool-result event types, exact structured ntt-* selectors, matching post-call result IDs, no unexpected Agent/Task calls, and no text/message masquerade. Strict local evidence rejects URI-scheme evidence_refs and URI-scheme artifact_path values.

## v1.0.1 strict evidence addendum
Critical evidence sufficiency is uniqueness-based. Count canonical evidence files and underlying artifact/hash identities, not raw ref strings; aliases and duplicate wrappers are false-world probes, not independent evidence.

## v1.0.1 release-provenance hygiene note

Do not treat bundled generated validation ledgers as current evidence if they contain stale package-root names, previous-version artifact names, or machine-local build paths. The package validator includes a release-provenance hygiene check over bundled audit/self-validation artifacts; stale ledger provenance must downgrade or fail release validation rather than being hand-waved as cosmetic.
