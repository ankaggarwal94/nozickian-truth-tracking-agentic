# Evidence and certificate guide

This README explains how to read the package evidence files without treating them as magic. The strict gate is local and artifact-bound: evidence references must resolve under the package root, structured evidence files must be JSON, and `hash_or_version` must match the SHA-256 of the cited `artifact_path`.

## Main certificate

The active package certificate is:

```text
self_validation/self_certificate.json
```

It contains package identity, method manifest, claim records, downstream non-closure records, scope limitations, and PASS-TRACKED upgrade-audit metadata.

## Structured evidence

Structured evidence lives under:

```text
self_validation/evidence/
```

Each evidence file states the claim it supports, the canonical claim-proposition SHA-256, the local artifact path it binds to, the command or source that produced the observation, an observed result, a support summary, a timestamp, and the expected artifact SHA-256. Claim text is canonicalized with Unicode NFC normalization, whitespace-run collapse, and outer-whitespace stripping before its UTF-8 bytes are hashed. In strict mode the certificate claim's `proposition_sha256` and every cited wrapper's `claim_proposition_sha256` must equal that derived digest.

Modal-test wrappers also bind `modal_case_sha256`. That digest covers the canonical claim text, kind, test ID, sorted unique target claim IDs, perturbation-or-variant field and text, expected and observed behavior, the wrapper's observed result, outcome, and result using sorted compact UTF-8 JSON. This makes edits to either the nearby-world declaration or its recorded observation detectable. The exact construction and accepted digest spellings are defined in [the structured evidence schema](../../skills/nozickian-verify/references/EVIDENCE_SCHEMA.md).

A modal wrapper may name an `observation_id` in its hashed `artifact_path`. In that case the artifact must be a JSON ledger with exact `observation_schema_version: "1.0"` and an `observations` object. The named record must exactly bind the claim ID, test ID, expected kind, claim digest, and modal-case digest; its normalized `result` must be `pass`; its outcome must belong to the gate's false-world or true-world allowlist; and its stripped `observed_result` must exactly equal the wrapper's. Named records, rather than multiple wrappers over one aggregate file, supply independent modal observation identities. Without a verified observation ID, independence falls back to the artifact SHA-256.

Both wrapper references and `artifact_path` values are canonical relative POSIX paths under the evidence root. Strict reads reject URI schemes, traversal, symlinks, non-regular files, pre-open inode swaps, mutation of the opened file during the read, and stale digests. `hash_or_version` hashes the complete artifact bytes; byte-identical wrappers and artifacts collapse for evidence sufficiency, so copies or hardlink aliases cannot inflate counts.

Passing downstream records have a separate non-closure guard: `proposition_binding.schema_version` must be `"1.0"`, and `canonical_text_sha256` must match both the downstream proposition and a distinct independently evaluated claim's canonical text. A source claim cannot automatically confer its status on a derived claim.

## Promotion certificate v2 evidence

Ordinary gate claims continue to use `evidence_refs`. Promotion certificate v2 does not: it requires exact-string `promotion_schema_version: "2.0"` and uses `evidence.schema_version: promotion-evidence-v2` with exactly nine typed semantic-role nodes. Each node contains exactly `path`, `sha256`, and `depends_on`. Paths must be canonical bundle-local regular non-symlink files, digests bind exact bytes, and dependencies must equal the fixed environment-independent acyclic role graph. Both official-policy nodes remain present when unavailable fresh execution is explicitly scope-excluded. The certifier validates deterministic, official-policy, live, and formal roles against their own lane semantics.

Formal result `2.0` is reached only through the `formal.result` typed promotion locator. It binds the immutable standalone target snapshot; exact report, gate, certificate, ledger, complete transcript, prompt, and target-snapshot companion paths/hashes/byte counts; package-tree identity; run ID; target identity; and pre/post stability. Stream decisions and SHA-256 values use complete captured bytes, while machine results expose bounded sanitized excerpts, explicit truncation flags, and full byte/hash metadata. The certifier rejects basename substitution, glob-first selection, and tail-only authentication but allows unrelated files whose names are not reserved formal companions.

Promotion certificates require at least one well-formed claim. The certifier evaluates every claim through the canonical strict gate and passes the actual nonempty claim results into promotion-strict downstream non-closure review. Malformed, duplicate, invalid, or empty claims return `status: FAIL` plus a bounded `failure_kind`; malformed external data is not allowed to escape as a traceback.

## Current observation ledger

The active modal records live in `self_validation/current_observations.json`. Human-readable summaries are carried in each structured wrapper's `support_summary` and in the audit report; redundant text mirrors are deliberately not shipped because they can drift from the proposition- and case-bound JSON records.

## Volatile outputs

Validation stdout and dry-run outputs in `self_validation/` are useful audit ledgers, but the stable release manifest marks several generated outputs as volatile. A reviewer should rerun the commands from `RELEASE_LOCK.json` and compare the new results rather than blindly trusting old generated logs.

Promotion aggregate result/stdout ledgers are volatile for the same reason. The aggregate suite's expected `36/36` is synthetic contract evidence and does not authenticate a real Claude Code runtime.
