# Structured Evidence Artifact Schema

When `--evidence-root` is supplied, strict local evidence mode treats every cited `evidence_ref` as part of the provenance boundary. Every cited local ref must resolve to a nonempty JSON evidence file under `evidence_root`; remote refs, absolute refs, path traversal, missing files, non-JSON files, wrong claim/test bindings, and wrong hashes fail. One valid evidence ref cannot mask another invalid cited ref.

Required fields:

```json
{
  "evidence_schema_version": "1.0",
  "claim_id": "C-001",
  "test_id": "FW-001",
  "applies_to_claims": ["C-001"],
  "applies_to_tests": ["FW-001"],
  "artifact_path": "relative/path/under/evidence_root/to/the/evidence/source",
  "command_or_source": "command, file, trace, source URL, or manual audit record that produced the observation",
  "observed_result": "what was actually observed",
  "support_summary": "why this observation supports the claim or modal test",
  "timestamp_utc": "2026-05-25T00:00:00Z",
  "hash_or_version": "sha256:<64-hex digest of artifact_path>"
}
```

For claim-level evidence, `test_id` may be omitted if `applies_to_tests` is not relevant. For test-level evidence, either `test_id` must match the modal test ID or `applies_to_tests` must include the test ID or `*`. The `claim_id` must match the claim being evaluated, or `applies_to_claims` must include the claim ID or `*`.

This prevents unrelated nonempty files such as `README.md`, `LICENSE`, a stale report, an out-of-root evidence JSON, or a partially fabricated ref set from counting as evidence for arbitrary claims. It does not replace expert semantic review; it is a deterministic binding check that forces each evidence reference to stay in the reviewed evidence root, state what it supports, and bind to an exact artifact digest.


### v0.7.2 patch note
This regeneration closes the remaining strict-evidence nearby-false-world gaps: every cited evidence ref must be a valid local JSON file under `evidence_root`; wrong-hash, remote, absolute-path, path-escaping, missing, or otherwise invalid refs fail even if another cited ref is valid. Plugin agent closure remains recursive over `agents/**/*.md`, and formal trace authentication still requires native Agent/Task tool-use plus successful matching tool-result/completion events before PASS-TRACKED.
