# Release guide

This package uses a release lock, behavior manifest, stable release manifest, self-validation artifacts, and zip-level checks. v1.0.3 remains **PASS-SCOPED** even when a separate promotion bundle satisfies every modeled check, because the certifier must apply its Issue #5 cap.

## Required local checks

Run the commands in `RELEASE_LOCK.json`. At minimum, run package validation, strict gate validation, regression evals, gate contract tests, formal-runner contract tests, the 36-case promotion aggregate through the production certifier CLI, and a formal dry run that writes output outside the package tree. Run the promotion aggregate both from the checkout and from the unpacked Git archive.

## Manifest model

`MANIFEST.sha256` covers behavior-affecting package files. `STABLE_RELEASE_MANIFEST.json` covers stable package files except itself and declared volatile generated outputs. Its fixed `generated_utc` is the reproducible-build epoch `2026-05-26T00:00:00Z`, `generated_utc_kind` is `reproducible-build-epoch`, and `generated_utc_semantics` records that this is not wall-clock generation time. This documented reproducible-build epoch resolves the v1.0.3 generated-time ambiguity tracked by Issue #8 for package semantics; it does not claim that the remote issue is closed. The validator preflights Git modes/stages and no-follow physical entry types before `--update-manifest`; both manifest writers use fresh same-directory files and atomic replacement so a destination link is replaced rather than followed. Both manifests must be refreshed after release edits.

Promotion certificate v2 requires exact-string `promotion_schema_version: "2.0"`, exact required top-level JSON types, at least one well-formed independently gate-evaluated claim, and the fixed nine-role `promotion-evidence-v2` DAG rather than flat promotion `evidence_refs`. The live harness and certifier share `validate_package.compute_stable_release_tree`; deterministic suites and allowlisted official validators run fresh. Claude validation uses exact strict argv and recognizes the ANSI-normalized `✔ Validation passed` form only when neither complete output stream contradicts it. Decisions and hashes bind complete captured bytes; public records expose bounded output plus truncation and full byte/hash metadata. Explicit unavailable-tool scope changes only fresh execution evidence and leaves both official-policy nodes and canonical dependencies intact. Formal result `2.0` binds a standalone immutable target snapshot plus the complete transcript and exact report, gate, certificate, ledger, prompt, target-snapshot, execution-package-snapshot, and resolved-entrypoint identities. The entrypoint binding is not a transitive interpreter/shared-library/kernel/host attestation. Malformed or empty claims return canonical `FAIL` plus `failure_kind`.

Caller-supplied `--json` and `--output-dir` paths reject symlinked ancestors, direct links, and special files with structured invalid-input output. Existing private regular `--json` files are intentionally replaced atomically; an existing regular file is never a valid output directory.

The v1.0.3 certifier always caps a complete modeled bundle at `PASS-SCOPED` / `CAPPED`, with `promotion_authorized: false`, `satisfied_profile: promotion-contract-v2-complete`, two unresolved Issue #5 obligations, and a nonzero exit. Generic gate/formal `PASS-TRACKED` semantics remain unchanged. The aggregate's expected `36/36` is synthetic contract evidence, not runtime authentication.

## Zip packaging

A release zip should contain exactly one top-level package directory. It must not include path traversal entries, symlinks, caches, temporary work directories, absolute build paths, or stale prior-version package roots.

## Review before publishing

Review the root README, the documentation hub, `PACKAGE_SURFACE.json`, `AUDIT_REPORT.md`, `TEAM_INTERNAL_USE.md`, `SECURITY.md`, and the validation summary. Confirm that documentation additions did not create plugin runtime components.
