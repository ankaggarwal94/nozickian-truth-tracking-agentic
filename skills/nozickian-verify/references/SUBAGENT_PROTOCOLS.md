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

## Echo-sweep mode (ntt-claim-extractor)

Run this mode after per-claim adjudication whenever the artifact is a revision of previously corrected material or any claim was corrected or refuted during verification. It targets consistency-class defects - stale echoes of superseded wording - that per-claim truth-testing does not surface. Enforcement is parent-owned and audited by the gate auditor; `ntt_gate.py` does not mechanically check that the sweep ran.

Input from the parent:

- Corrected-claims list: for each correction, the claim id, old wording/value, new wording/value, and correction location.
- Artifact paths to sweep.

Method: Grep the whole artifact for old-wording fragments - verbatim strings, quoted forms, case and format variants, and key identifiers/enums/numbers from the superseded wording. Classify each hit as:

- `live-claim`: the old wording is still asserted as true - a substantive defect, route back to adjudication.
- `stale-echo`: a residue of the superseded wording embedded in otherwise-current text, even inside a sentence whose main proposition is true - a consistency defect.
- `intentional-reference`: a passage that deliberately quotes the superseded wording to explain a correction or root cause - NOT a defect; record and move on.

Output per echo:

- Location (file:line).
- The matched fragment.
- Embedded-in-true-sentence: yes/no.
- Classification (`live-claim` / `stale-echo` / `intentional-reference`).
- Recommended edit.

An explicit `none found` statement is required when the sweep finds nothing. Never omit the output section because it is empty.

## Remote ground-truth escalation (ntt-source-verifier)

The source verifier is local-only (Read, Grep, Glob). When the authoritative ground truth for a claim is remote-only - a hosted schema or repo file, a Confluence or Jira page, live API or service state - and no local copy with freshness provenance exists, do not verify the claim. Emit a `REMOTE_GROUND_TRUTH_REQUIRED` escalation entry instead, with these fields:

- `claim_id`
- `why_remote`: why the authoritative ground truth is remote-only.
- `exact_fetch_spec`: the URL, host, API call, or CLI command the parent can run to fetch it.
- `local_mirror`: path of any local copy, or `none`.
- `mirror_provenance`: pinned commit/date, or `unproven`.
- `staleness_risk`: how the local mirror could be wrong.

Rules: an unresolved escalation means the claim is UNKNOWN, never verified. A local mirror with `mirror_provenance: unproven` is not evidence. Leaving a remote-only claim UNKNOWN does not waive the entry: every remote-only claim must carry its `REMOTE_GROUND_TRUTH_REQUIRED` entry regardless of its status label, so the parent always receives the `exact_fetch_spec` needed to resolve it. The parent must fetch the remote evidence (directly or via a web-capable general-purpose verifier) and return it for re-adjudication, or leave the claim UNKNOWN; `ntt_gate.py` does not mechanically enforce this - the parent and gate auditor own it.

A `REMOTE ESCALATIONS` output section is mandatory in every source-verifier report, with an explicit `none` when no escalation was raised.
