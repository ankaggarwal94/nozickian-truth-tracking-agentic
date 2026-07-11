# PASS-SCOPED to PASS-TRACKED upgrade audit

This README summarizes the package-level promotion protocol. The full normative reference is:

```text
skills/nozickian-verify/references/PASS_TRACKED_UPGRADE_AUDIT.md
```

## Promotion principle

A **PASS-SCOPED** package has deterministic evidence but retains one or more explicit limitations, usually live Claude Code runtime execution. A **PASS-TRACKED** package requires live runtime evidence showing that the method tracks the relevant claims in the actual Claude Code environment.

## Required bundle

A promotion bundle should contain deterministic validator outputs, strict gate output, regression output, gate-contract output, formal-runner contract output, official validator output or a scoped exclusion, the current shared package-tree digest, the exact `evals.json` byte digest, one exact artifact-byte digest plus one distinct transcript-byte digest and exact normalized argv per current live fixture, formal artifact verification output, strict-gate result for the generated formal certificate, trace-authentication evidence, stale-token scans, and a promotion certificate with downstream non-closure records.

## Certifier

Run the machine checker against the external bundle:

```bash
python3 skills/nozickian-verify/scripts/certify_pass_tracked_upgrade.py \
  . pass_tracked_audit_bundle \
  --json pass_tracked_audit_bundle/pass_tracked_certification_result.json \
  --markdown pass_tracked_audit_bundle/pass_tracked_certification_result.md
```

The certifier reruns the current basic package validator unconditionally and invokes the same package-local stable-tree helper as the live harness; that helper independently derives stable inventory paths plus volatile exclusions from the current validator. Every successful return-code check requires exact integer zero, excluding booleans, floats, strings, and nulls; official text output rejects anchored nonzero error/failure summaries before pass markers. It must also reject empty bundles, dry-run-only bundles, a stale package/fixture-spec/artifact binding even after manifest refresh, prompt-only or malformed fixture argv, wrong preflight argv, shared/swapped/unhashed or wrong-prompt live transcripts, manifest inventory/exclusion drift, fresh-validator failure, missing official validators without scoped exclusion, unauthenticated formal traces, strict-gate results below PASS-TRACKED, stale provenance, and downstream pass inheritance.

## Non-closure reminder

PASS-TRACKED for the package or for a formal trace does not automatically certify deployment safety, compliance, policy authorization, or final business action. Those downstream claims need their own claim records.
