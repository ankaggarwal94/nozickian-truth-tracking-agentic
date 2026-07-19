# Release guide

This package uses a release lock, behavior manifest, stable release manifest, self-validation artifacts, and unpacked-tree checks. v1.0.3 remains **PASS-SCOPED** even when a separate promotion bundle satisfies every modeled check, because the certifier must apply its Issue #5 cap.

## Required local checks

Run the commands in `RELEASE_LOCK.json`. At minimum, run package validation, strict gate validation, regression evals, gate contract tests, formal-runner contract tests, the 46-case promotion aggregate through the production certifier CLI, and a formal dry run that writes output outside the package tree. In CI, run the full validator `--self-test` against both the checkout and the unpacked Git archive, with each Markdown output outside the measured tree; run the promotion aggregate after each corresponding full self-test.

The release gate is specifically `--evidence-root . --strict-evidence
--downstream-policy package-self`. Its assurance-bound claim-contract `1.1`
includes the full downstream-policy object. Its modal world-contract `1.1`
uses closed typed operator/target/outcome values, hashes `outcome` and
`observed_outcome` separately, and treats all world/behavior prose as
explanation-only. The complete package certificate must present the immutable
reviewed 80-transition modal ID multiset exactly once with no deletion,
duplication, reassignment, or unreviewed extension.

The checked-in workflow uses exact commit identities for `actions/checkout` and `actions/setup-python`; the validator rejects mutable action tags and any unreviewed action substitution. A dependency upgrade therefore requires an intentional SHA review plus workflow, validator-policy, evidence, and manifest regeneration.

## Manifest model

`MANIFEST.sha256` covers behavior-affecting package files. Schema 1.1 `STABLE_RELEASE_MANIFEST.json` covers stable package files except itself and declared volatile generated outputs. Its canonical self-hash binds its own JSON content, while exact `self_mode: "100644"` separately requires the installed manifest to remain non-executable. Its fixed `generated_utc` is the reproducible-build epoch `2026-05-26T00:00:00Z`, `generated_utc_kind` is `reproducible-build-epoch`, and `generated_utc_semantics` records that this is not wall-clock generation time. This documented reproducible-build epoch resolves the v1.0.3 generated-time ambiguity tracked by Issue #8 for package semantics; it does not claim that the remote issue is closed. The validator preflights Git modes/stages and no-follow physical entry types before `--update-manifest`; both manifest writers use fresh same-directory files and atomic replacement so a destination link is replaced rather than followed. Both manifests must be refreshed after release edits.

Package validation authorizes from one immutable initial captured-byte
snapshot, not from later lexical reopens. The validator materializes every
self-test fixture from those captured bytes and independently revalidates both
the held source root and its private mirror at finalization. Package traversal
has independent path/metadata and aggregate byte budgets; Git discovery/index
capture has bounded runtime, combined output, and index cardinality. Preserve
these limits and the source-plus-mirror final checks when refreshing release
mechanics.

Promotion certificate v2 requires exact-string `promotion_schema_version: "2.0"`, required `origin`, exact required top-level JSON types, at least one scoped claim carrying claim-contract `1.1`, and the fixed nine-role `promotion-evidence-v2` DAG rather than flat promotion `evidence_refs`. The live harness and certifier share `validate_package.compute_stable_release_tree`; deterministic suites and allowlisted official validators run fresh. Claude validation uses exact strict argv and recognizes the ANSI-normalized `✔ Validation passed` form only when neither complete output stream contradicts it. Decisions and hashes bind complete captured bytes; public records expose bounded output plus truncation and full byte/hash metadata. Explicit unavailable-tool scope changes only fresh execution evidence and leaves both official-policy nodes and canonical dependencies intact. Live provenance schema `2.0` and formal result `2.0` must agree on `evidence_origin`, which is reconstructed into `promotion-method-m-v2`. Formal result `2.0` binds a standalone endpoint-checked target copy plus the complete transcript and exact report, gate, certificate, ledger, prompt, target-copy, execution-package-copy, and resolved-entrypoint identities. Its single final successful ResultMessage uses canonical nonempty `result`; official controls `api_error_status`, `deferred_tool_use`, `structured_output`, `terminal_reason`, and `stop_reason` must satisfy the non-error/non-deferred/non-structured completed/end-turn policy. The certifier recomputes the exact nonempty all-passing formal output-check projection from the bound report, certificate, ledger, and gate; arbitrary self-attested checks and coherently rehashed empty report or gate companions fail closed. Permission hardening does not make the copies temporally immutable to a same-UID actor, so an otherwise `PASS-TRACKED` formal result is capped at `PASS-SCOPED`. Execution establishes supported Linux child-subreaper setup and bounded `/proc` adopted-child tracking before `Popen`; after leader exit it kills and reaps same-group and detached-session descendants. Unavailable containment refuses execution, and survivor or cleanup failure fails closed. The entrypoint binding is not a transitive interpreter/shared-library/kernel/host attestation. Malformed or empty claims return canonical `FAIL` plus `failure_kind`.

Caller-controlled outputs use parent capabilities acquired before long-running work. Existing private regular `--json` files are intentionally replaced atomically under their held parents. Gate Markdown requires a fresh final name, validator Markdown must remain outside the measured package tree, live JSON cannot alias a selected fixture transcript, and an existing regular file is never a valid formal output directory.

Gate Markdown, certifier JSON/Markdown, formal output plus compatibility JSON, live transcripts plus optional JSON, validator Markdown, all four deterministic contract/regression JSON wrappers, and the fixed behavior/stable-release manifests hold component-wise no-follow parent capabilities from before their long-running work through descriptor-relative exclusive creation, link/rename installation as applicable, and directory fsync. Role and alias decisions are frozen against held identities. Ancestor substitution cannot redirect output to a symlink or replacement real directory; observed mismatch fails closed. These checks bind destinations but are not temporal isolation and do not exclude every same-UID mutation between observations.

Formal coordinator and gate subprocesses receive only the runner-owned `/proc/<runner-pid>/fd/N` alias through `pass_fds`; the procfs-visible runner `Pid:` must equal the gate child's procfs-visible direct-parent `PPid:`. Child-FD close/rebind, self/unrelated PIDs, noncanonical or nonpositive PID/FD tokens, extra components, closed descriptors, and file descriptors are rejected. Live formal output requires POSIX `O_DIRECTORY`/`O_NOFOLLOW` plus procfd inheritance; unsupported environments return `INVALID_INPUT` before creating the requested output directory or JSON file.

The v1.0.3 certifier always caps a complete modeled bundle at `PASS-SCOPED` / `CAPPED`, with `promotion_authorized: false`, `satisfied_profile: promotion-contract-v2-complete`, two unresolved Issue #5 obligations, and a nonzero exit. Generic `ntt_gate.py` `PASS-TRACKED` semantics remain unchanged; the formal runner separately caps an otherwise `PASS-TRACKED` result at `PASS-SCOPED` because temporal immutability is not mechanically enforced. The aggregate's expected `46/46` is synthetic contract evidence, not runtime authentication.

## Zip packaging

A release zip should contain exactly one top-level package directory. It must not include path traversal entries, symlinks, caches, temporary work directories, absolute build paths, or stale prior-version package roots. This is not currently an automated CI claim: if a ZIP is published, validate its central-directory entries and extracted tree separately and publish its SHA-256 as an external release record.

## Review before publishing

Review the root README, the documentation hub, `PACKAGE_SURFACE.json`, `AUDIT_REPORT.md`, `TEAM_INTERNAL_USE.md`, `SECURITY.md`, and the validation summary. Confirm that documentation additions did not create plugin runtime components.
