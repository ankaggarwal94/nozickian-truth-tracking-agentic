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

Each evidence file states the claim it supports, the canonical claim-proposition SHA-256, claim-contract schema and SHA-256, the local artifact path it binds to, command/source context, a result declaration, a support summary, a timestamp, and the expected artifact SHA-256. For ledger-backed modal wrappers, the context and result are case-bound release declarations, not authenticated execution provenance. Claim text is canonicalized with Unicode NFC normalization, whitespace-run collapse, and outer-whitespace stripping before its UTF-8 bytes are hashed. The versioned claim contract additionally binds canonical claim text, explicit scope, artifact referent, importance, and method M. In strict mode the certificate and every cited wrapper must match both derived digests.

Modal-test wrappers also bind `modal_case_sha256`. That digest covers the canonical claim text and claim-contract digest; kind; test ID; sorted unique target claim IDs; perturbation-or-variant field and text; the closed `world_contract` 1.0 fields; expected and observed behavior; the wrapper's declared result text; outcome; and result using sorted compact UTF-8 JSON. This makes edits to either the method-relative claim, structured nearby world, or case-bound release declaration detectable; it does not prove that the named suite ran. Coverage must remain distinct both by reviewer-assigned semantic-equivalence class and by the structural world fingerprint. The exact construction and accepted digest spellings are defined in [the structured evidence schema](../../skills/nozickian-verify/references/EVIDENCE_SCHEMA.md).

A modal wrapper may name an `observation_id` in its hashed `artifact_path`. In that case the artifact must be a JSON ledger with exact `observation_schema_version: "1.2"`, exact top-level fields `observation_schema_version` and `observations`, and no others. Every named record has the exact closed field set documented in the structured evidence schema. It must bind the claim ID, test ID, expected kind, claim-proposition digest, claim-contract digest, and modal-case digest; its normalized `result` must be `pass`; its outcome must belong to the gate's false-world or true-world allowlist; and its stripped `observed_result` must exactly equal the wrapper's. Named records supply distinct case-bound release-declaration identities for threshold deduplication. They are not execution provenance and do not claim that a suite result was reconciled to a ledger record. Without a verified observation ID, deduplication falls back to the artifact SHA-256.

Both wrapper references and `artifact_path` values are canonical relative POSIX paths under the evidence root. Strict reads reject URI schemes, traversal, symlinks and non-regular files, mutation of an opened file during its bounded read, and stale digests. Traversal remains anchored to the held evidence-root capability; later phases are bound by bytes and hashes, but no temporal identity is claimed across distinct opens of an in-root path. `hash_or_version` hashes the complete artifact bytes; byte-identical wrappers and artifacts collapse for evidence sufficiency, so copies or hardlink aliases cannot inflate counts.

Passing downstream records have a separate non-closure guard: `proposition_binding.schema_version` must be `"1.0"`, and `canonical_text_sha256` must match both the downstream proposition and a distinct independently evaluated claim's canonical text. A source claim cannot automatically confer its status on a derived claim.

## Promotion certificate v2 evidence

Ordinary gate claims continue to use `evidence_refs`. Promotion certificate v2 does not: it requires exact-string `promotion_schema_version: "2.0"` and uses `evidence.schema_version: promotion-evidence-v2` with exactly nine typed semantic-role nodes. Each node contains exactly `path`, `sha256`, and `depends_on`. Paths must be canonical bundle-local regular non-symlink files, digests bind exact bytes, and dependencies must equal the fixed environment-independent acyclic role graph. Both official-policy nodes remain present when unavailable fresh execution is explicitly scope-excluded. The certifier validates deterministic, official-policy, live, and formal roles against their own lane semantics.

Formal result `2.0` is reached only through the `formal.result` typed promotion locator. It binds the standalone endpoint-checked target copy; exact report, gate, certificate, ledger, complete transcript, prompt, and target-snapshot companion paths/hashes/byte counts; package-tree identity; run ID; target identity; and pre/post endpoint stability. The certifier recomputes the exact nonempty all-passing formal output-check projection from the bound report, certificate, ledger, and gate; arbitrary self-attested checks and coherently rehashed empty report or gate companions fail closed. Permission hardening and matching endpoint checks are observations, not temporal immutability: `temporal_immutability_enforced` is `false`, so an otherwise `PASS-TRACKED` formal result is capped at `PASS-SCOPED`. Capture establishes supported Linux child-subreaper setup plus bounded `/proc` adopted-child tracking before `Popen`, then kills and reaps same-group and detached-session descendants after leader exit. Unavailable containment refuses execution, and incomplete cleanup or any survivor fails closed. Stream decisions and SHA-256 values use complete captured bytes, while machine results expose bounded sanitized excerpts, explicit truncation flags, and full byte/hash metadata. The certifier rejects basename substitution, glob-first selection, and tail-only authentication but allows unrelated files whose names are not reserved formal companions.

Output evidence is bound to held directory capabilities, not repeated lexical path resolution. Gate Markdown, certifier JSON/Markdown, formal output plus compatibility JSON, live transcripts plus optional JSON, validator Markdown, deterministic contract/regression JSON wrappers, and the fixed behavior/stable-release manifests use component-wise `O_DIRECTORY`/`O_NOFOLLOW` traversal before long-running work, followed by descriptor-relative exclusive creation, link/rename installation as applicable, and directory fsync. Role and alias decisions are frozen against held identities; formal canonical-result classification is not recomputed after writes, certifier aliases fail, and live JSON cannot alias a selected transcript. Symlink and real-directory ancestor substitution cannot redirect writes, and validator Markdown rechecks that its held parent remains outside the package tree. Observed mismatch fails closed, but these endpoint/capability observations are not temporal isolation.

Formal coordinator and gate children receive only `/proc/<runner-pid>/fd/N` through `pass_fds`. The runner derives that canonical positive PID from procfs-visible `Pid:`; the gate requires it to match the gate process's procfs-visible direct-parent `PPid:` and rejects child-FD close/rebind, self/unrelated PIDs, noncanonical or nonpositive PID/FD tokens, extra components, closed descriptors, and file descriptors. Missing POSIX procfd inheritance returns formal `INVALID_INPUT` before requested output creation.

Promotion certificates require at least one well-formed claim. The certifier evaluates every claim through the canonical strict gate and passes the actual nonempty claim results into promotion-strict downstream non-closure review. Malformed, duplicate, invalid, or empty claims return `status: FAIL` plus a bounded `failure_kind`; malformed external data is not allowed to escape as a traceback.

## Current observation ledger

The active modal release declarations live in `self_validation/current_observations.json`. Human-readable summaries are carried in each structured wrapper's `support_summary` and in the audit report; redundant text mirrors are deliberately not shipped because they can drift from the proposition- and case-bound JSON records. Fresh deterministic suite outcomes come from the separate release commands. The ledger neither stores nor authenticates those outputs, and no per-record suite reconciliation is claimed.

## Volatile outputs

Validation stdout and dry-run outputs in `self_validation/` are useful audit ledgers, but the stable release manifest marks several generated outputs as volatile. A reviewer should rerun the commands from `RELEASE_LOCK.json` and compare the new results rather than blindly trusting old generated logs.

Promotion aggregate result/stdout ledgers are volatile for the same reason. The aggregate suite's expected `44/44` is synthetic contract evidence and does not authenticate a real Claude Code runtime.
