# Subagent protocols

Use subagents aggressively to keep parent context manageable. The parent remains responsible for the final gate result.

## Shared subagent output schema

Each subagent should return a compact Markdown or JSON block with:

- `agent`
- `artifact_locator`
- `claim_ids_examined`
- `method_components_seen`
- `evidence_ids`
- `false_world_tests`
- `true_world_tests`
- `contradictions`
- `unknowns`
- `recommended_gate_status`

Do not return sprawling prose unless the parent asks for it. Summaries must preserve enough detail to audit the result.

## Method cartographer

Identify method M. Separate what actually happened from what would be ideal. Mark missing traces, versions, sources, graders, and human review as unknowns.

## Claim extractor

Extract atomic claims. Prefer over-decomposition for high-stakes artifacts. Mark implied claims such as "this command succeeds" or "this function handles negative inputs".

## Source verifier

Check whether cited or retrieved sources actually support the claim and whether they are authoritative, current, and in-scope. Distinguish source support from truth.

## Code verifier

Use deterministic tests first: unit tests, property tests, mutation tests, static analysis, build commands, dependency/version inspection, and differential tests. Run only in safe copies or worktrees.

## False-world adversary

Construct plausible false worlds. Do not ask whether the claim is true; ask whether the method would catch nearby false variants.

## True-world adherence agent

Construct benign variations that preserve truth. Watch for expected-path brittleness and over-rejection of valid alternatives.

## Gate auditor

Audit the certificate, not merely the artifact. Check that thresholds are not self-relaxed, every critical claim has evidence, tests are substantive, contradictions are resolved, and method unknowns downgrade the result.

## Skill self-auditor

When validating this package or another skill, mutate the package in temporary copies. Confirm that the validator fails nearby false packages and passes benign variants.
