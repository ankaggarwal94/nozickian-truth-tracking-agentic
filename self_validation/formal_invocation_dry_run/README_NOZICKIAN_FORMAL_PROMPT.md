/nozickian-verification-team-internal:nozickian-verify <package-root>/README.md

FORMAL_INVOCATION_REQUIRED.

Target artifact:
<package-root>/README.md

Required output artifacts:
- <tmp-v101-final-outputs>
- <tmp-v101-final-outputs>
- <tmp-v101-final-outputs>
- <tmp-v101-final-outputs>

Formal invocation rules:
1. Use the loaded plugin skill /nozickian-verification-team-internal:nozickian-verify, not an informal imitation.
2. You are expected to be running as the main-thread agent `ntt-formal-coordinator`. If not, write FORMAL_COORDINATOR_MISMATCH in the ledger and downgrade.
3. Before verification, confirm whether these native plugin subagents are available:
   - ntt-method-cartographer
   - ntt-claim-extractor
   - ntt-source-verifier
   - ntt-code-verifier
   - ntt-false-world-adversary
   - ntt-true-world-adherence
   - ntt-gate-auditor
4. If any required native ntt-* subagent is unavailable, do not substitute general-purpose silently. Mark FORMAL_SUBAGENT_FAILURE in the report and ledger and gate the run as LIMITED or UNVERIFIED.
5. Reconstruct method M for the target artifact.
6. Extract claim IDs and rank them as critical, major, or minor.
7. For every critical and major claim, produce structured certificate entries with: claim_id/id, text, importance, artifact_location, truth_status, method_m, method_completeness, evidence_refs, false_world_tests, true_world_tests, unresolved_contradictions, and residual_risks.
8. For every local evidence reference intended to satisfy the gate, write a structured evidence artifact with fields: evidence_schema_version, claim_id, test_id or applies_to_tests, artifact_path, command_or_source, observed_result, support_summary, timestamp_utc, and hash_or_version.
9. Run exactly this gate command after writing the certificate:
   python3 <package-root>/skills/nozickian-verify/scripts/ntt_gate.py <tmp-v101-final-outputs> --evidence-root <package-root> --strict-evidence --markdown <tmp-v101-final-outputs>
10. The final report must include scope, artifact identity, method M, claim table, false-world sensitivity, true-world adherence, contradictions, residual risks, commands run, subagents actually used, gate status, and explicit downgrade reasons.
11. The invocation ledger must include:
    Skill invoked: /nozickian-verification-team-internal:nozickian-verify
    Main coordinator: ntt-formal-coordinator
    Native subagents requested: ntt-method-cartographer, ntt-claim-extractor, ntt-source-verifier, ntt-code-verifier, ntt-false-world-adversary, ntt-true-world-adherence, ntt-gate-auditor
    Native subagents completed: ...
    Substitution used: none OR FORMAL_SUBAGENT_FAILURE
    Machine gate run: yes
    Gate script: <package-root>/skills/nozickian-verify/scripts/ntt_gate.py
    Gate output: <tmp-v101-final-outputs>
    Runtime transcript: <tmp-v101-final-outputs>
12. Do not claim PASS-TRACKED unless ntt_gate.py returns PASS-TRACKED, no method/runtime/subagent unknowns remain, and the runtime transcript contains native Agent/Task tool-use events plus successful matching tool-result/completion events for every required ntt-* lane. If ntt_gate.py returns PASS-SCOPED, do not promote it.
13. For any PASS-SCOPED to PASS-TRACKED promotion claim, follow references/PASS_TRACKED_UPGRADE_AUDIT.md: require deterministic outputs, official validator outputs, live fixture outputs, this formal artifact run, strict-gate PASS-TRACKED, trace authentication, promotion_certificate.json, and downstream non-closure review.
