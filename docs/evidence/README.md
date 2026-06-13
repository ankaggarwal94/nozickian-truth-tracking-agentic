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

## Human-readable evidence artifacts

Supplemental text evidence lives under:

```text
self_validation/evidence_artifacts/
```

These files are for reviewer inspection and stable-release inventory. They are not a substitute for structured evidence JSON cited by a claim or modal test.

## Volatile outputs

Validation stdout and dry-run outputs in `self_validation/` are useful audit ledgers, but the stable release manifest marks several generated outputs as volatile. A reviewer should rerun the commands from `RELEASE_LOCK.json` and compare the new results rather than blindly trusting old generated logs.
