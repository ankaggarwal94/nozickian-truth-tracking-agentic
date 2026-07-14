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

Each evidence file states the claim it supports, the local artifact path it binds to, the command or source that produced the observation, an observed result, a support summary, a timestamp, and the expected artifact SHA-256. The gate checks these fields in strict mode.

## Promotion certificate v2 evidence

Ordinary gate claims continue to use `evidence_refs`. Promotion certificate v2 does not: it requires exact-string `promotion_schema_version: "2.0"` and uses `evidence.schema_version: promotion-evidence-v2` with exactly nine typed semantic-role nodes. Each node contains exactly `path`, `sha256`, and `depends_on`. Paths must be canonical bundle-local regular non-symlink files, digests bind exact bytes, and dependencies must equal the fixed environment-independent acyclic role graph. Both official-policy nodes remain present when unavailable fresh execution is explicitly scope-excluded. The certifier validates deterministic, official-policy, live, and formal roles against their own lane semantics.

Formal result `2.0` is reached only through the `formal.result` typed promotion locator. It binds the immutable standalone target snapshot; exact report, gate, certificate, ledger, complete transcript, prompt, and target-snapshot companion paths/hashes/byte counts; package-tree identity; run ID; target identity; and pre/post stability. Stream decisions and SHA-256 values use complete captured bytes, while machine results expose bounded sanitized excerpts, explicit truncation flags, and full byte/hash metadata. The certifier rejects basename substitution, glob-first selection, and tail-only authentication but allows unrelated files whose names are not reserved formal companions.

Promotion certificates require at least one well-formed claim. The certifier evaluates every claim through the canonical strict gate and passes the actual nonempty claim results into promotion-strict downstream non-closure review. Malformed, duplicate, invalid, or empty claims return `status: FAIL` plus a bounded `failure_kind`; malformed external data is not allowed to escape as a traceback.

## Human-readable evidence artifacts

Supplemental text evidence lives under:

```text
self_validation/evidence_artifacts/
```

These files are for reviewer inspection and stable-release inventory. They are not a substitute for structured evidence JSON cited by a claim or modal test.

## Volatile outputs

Validation stdout and dry-run outputs in `self_validation/` are useful audit ledgers, but the stable release manifest marks several generated outputs as volatile. A reviewer should rerun the commands from `RELEASE_LOCK.json` and compare the new results rather than blindly trusting old generated logs.

Promotion aggregate result/stdout ledgers are volatile for the same reason. The aggregate suite's expected `36/36` is synthetic contract evidence and does not authenticate a real Claude Code runtime.
