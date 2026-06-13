# Release guide

This package uses a release lock, behavior manifest, stable release manifest, self-validation artifacts, and zip-level checks. The release status should remain **PASS-SCOPED** unless a separate PASS-TRACKED upgrade bundle is certified.

## Required local checks

Run the commands in `RELEASE_LOCK.json`. At minimum, run package validation, strict gate validation, regression evals, gate contract tests, formal-runner contract tests, and a formal dry run that writes output outside the package tree.

## Manifest model

`MANIFEST.sha256` covers behavior-affecting package files. `STABLE_RELEASE_MANIFEST.json` covers stable package files except itself and declared volatile generated outputs. Both must be refreshed after release edits.

## Zip packaging

A release zip should contain exactly one top-level package directory. It must not include path traversal entries, symlinks, caches, temporary work directories, absolute build paths, or stale prior-version package roots.

## Review before publishing

Review the root README, the documentation hub, `PACKAGE_SURFACE.json`, `AUDIT_REPORT.md`, `TEAM_INTERNAL_USE.md`, `SECURITY.md`, and the validation summary. Confirm that documentation additions did not create plugin runtime components.
