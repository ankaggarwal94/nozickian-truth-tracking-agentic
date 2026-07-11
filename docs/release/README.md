# Release guide

This package uses a release lock, behavior manifest, stable release manifest, self-validation artifacts, and zip-level checks. The release status should remain **PASS-SCOPED** unless a separate PASS-TRACKED upgrade bundle is certified.

## Required local checks

Run the commands in `RELEASE_LOCK.json`. At minimum, run package validation, strict gate validation, regression evals, gate contract tests, formal-runner contract tests, and a formal dry run that writes output outside the package tree.

## Manifest model

`MANIFEST.sha256` covers behavior-affecting package files. `STABLE_RELEASE_MANIFEST.json` covers stable package files except itself and declared volatile generated outputs. Its fixed `generated_utc` is the reproducible-build epoch `2026-05-26T00:00:00Z`, `generated_utc_kind` is `reproducible-build-epoch`, and `generated_utc_semantics` records that this is not wall-clock generation time. The validator preflights Git modes/stages and no-follow physical entry types before `--update-manifest`; both manifest writers use fresh same-directory files and atomic replacement so a destination link is replaced rather than followed. Both manifests must be refreshed after release edits.

For a PASS-TRACKED promotion, the live harness and `certify_pass_tracked_upgrade.py` invoke one shared `validate_package.compute_stable_release_tree` helper. It executes the current release-inventory policy, requires the manifest inventory and volatile exclusion arrays to match that policy exactly, and verifies every independently derived regular-file path/hash/byte count before computing the documented `ntt-stable-release-tree-v1` canonical `package_tree_sha256`. The promotion certificate must match that exact lowercase digest; generic `package_sha256` aliases are not accepted. The certifier also reruns the current basic validator unconditionally, recomputes exact `evals.json` and artifact-byte digests, and requires exact ordered preflight/fixture argv plus one distinct byte-hashed transcript and canonical prompt/fixture/artifact binding per live fixture. Refreshing both manifests after changing package, fixture-specification, or artifact bytes does not refresh stale live evidence.

## Zip packaging

A release zip should contain exactly one top-level package directory. It must not include path traversal entries, symlinks, caches, temporary work directories, absolute build paths, or stale prior-version package roots.

## Review before publishing

Review the root README, the documentation hub, `PACKAGE_SURFACE.json`, `AUDIT_REPORT.md`, `TEAM_INTERNAL_USE.md`, `SECURITY.md`, and the validation summary. Confirm that documentation additions did not create plugin runtime components.
