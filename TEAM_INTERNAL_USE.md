# Team/Internal Reuse Policy

This package is scoped for team/internal reuse, not public marketplace distribution.

## Assurance target

Use the package as a structured Nozickian verification scaffold with deterministic package validation, release-lock checks, manifest hashing, regression fixtures, and optional live Claude Code runtime evals.

It is not intended to prove against a hostile maintainer who can rewrite the validator, manifests, certificates, and CI at once. It is intended to catch ordinary team-reuse failures: accidental runtime-surface expansion, unsafe tool grants, missing modal tests, stale manifests, broken fixture paths, degraded verifier prompts, and unreviewed changes.

## Required team workflow

Before sharing a changed package internally:

1. Review the diff of `SKILL.md`, `agents/**/*.md`, `scripts/*.py`, `evals/evals.json`, `PACKAGE_SURFACE.json`, `RELEASE_LOCK.json`, and `.claude-plugin/plugin.json`.
2. Run deterministic validation:

```bash
python3 skills/nozickian-verify/scripts/validate_package.py . --self-test --markdown /tmp/ntt_SELF_VALIDATION_REPORT.md
python3 skills/nozickian-verify/scripts/ntt_gate.py self_validation/self_certificate.json --evidence-root . --strict-evidence --markdown /tmp/ntt_GATE_RESULT.md
python3 skills/nozickian-verify/scripts/run_regression_evals.py . --json /tmp/ntt_regression_eval_result.json
python3 skills/nozickian-verify/scripts/run_promotion_certifier_contract_tests.py .
```

3. On machines with Claude Code installed, run live fixture checks:

```bash
python3 skills/nozickian-verify/scripts/run_live_skill_evals.py . --run-fixtures --json /tmp/ntt_live_runtime_eval_result.json
```

4. Treat `PASS-SCOPED` as the v1.0.3 team-internal release label. Live runtime fixture transcripts remain necessary evidence, but the certifier's two Issue #5 obligations still prevent authorization.

Manifest refreshes are fail-closed. `--update-manifest` first checks the no-follow physical surface plus Git index stage and mode evidence; symlinks, FIFOs, gitlinks/submodules, conflict stages, and other non-regular modes block the refresh. Manifest output is written through a fresh same-directory temporary file and atomically replaces the fixed destination.

Live fixture evidence is also fail-closed. The harness resolves `claude` once to an absolute regular non-symlink target, executes that exact target for version/plugin/fixture commands under every working directory, and requires equal pre/post SHA-256 fingerprints before `PASS-SCOPED`. At run start it records the shared `ntt-stable-release-tree-v2` package digest, which binds every stable file's path, bytes, content digest, and Git-compatible executable mode, plus exact `evals.json` bytes, fixed run config including `max_turns`, and each fixture artifact's exact bytes. Promotion additionally requires current-run provenance, exact normalized version/plugin preflight argv, the exact current fixture-ID set once each, exact ordered fixture argv with no extra or missing argument, a distinct canonical bundle-local transcript and exact transcript-byte digest per fixture, and canonical prompt text/hash binding before stdout replay. The fingerprints and version output remain observational identity evidence with `authentication_status=observed-not-cryptographically-authenticated`; they do not prove that the binary is an official Claude build.

## Scope boundary

The validator intentionally rejects plugin-root hooks, bins, monitors, MCP/LSP configs, settings activation, broad skill `allowed-tools`, dynamic skill shell substitutions, manifest-declared runtime components, and unmanifested agents. Those can be added later, but only by explicitly changing the surface policy, adding focused tests, and raising the review tier.

## Formal invocation addendum

A prose audit that applies this skill's protocol is useful, but a formal package invocation requires the additional machine-gated artifacts:

- invocation through the `ntt-formal-coordinator` main agent or an explicit downgrade if that agent cannot run;
- native `ntt-*` lane use, with `FORMAL_SUBAGENT_FAILURE` if any lane is unavailable or replaced by `general-purpose`;
- a report, a machine-readable certificate JSON, a gate Markdown file produced by `ntt_gate.py`, and an invocation ledger;
- a saved transcript when `run_formal_artifact_verification.py` invokes Claude Code.

For internal review, do not promote an artifact-verification run to `PASS-TRACKED` if the run only produced prose, skipped `certificate.json`, skipped `ntt_gate.py`, or used role-equivalent fallback agents without recording the downgrade.


### Trace-authentication regeneration patch note (`v1.0.1_patch_notes` release)
That regeneration closed the remaining trace-authentication and URI-scheme edge cases found after the late pre-1.0 hardening series. Team review should verify that `nested_tool_result_inside_tool_input_does_not_authenticate`, `nested_tool_result_inside_arguments_does_not_authenticate`, `tool_result_before_tool_use_does_not_authenticate`, and `same_event_input_embedded_result_does_not_authenticate` pass in `formal_runner_contract_results.json`. Strict local evidence mode now rejects any non-empty URI scheme, including uppercase and mixed-case `HTTPS://`, `DOI:`, `URN:`, and scheme-like refs; review `uppercase_https_evidence_ref_rejected`, `mixed_case_https_evidence_ref_rejected`, `uppercase_doi_urn_refs_rejected`, and `scheme_like_evidence_ref_rejected_in_strict_mode` in `gate_contract_results.json`.

## Release idempotence addendum

Normal release-lock validation must not write generated formal-runner artifacts into the package tree. Use the `mktemp`-created external `../ntt_release_formal_invocation_dry_run.XXXXXX` workspace from `RELEASE_LOCK.json`, or choose another unique out-of-tree directory. In-tree generated outputs are allowed only when `run_formal_artifact_verification.py` is invoked with `--refresh-release-manifest`, after which the stable release manifest must be reviewed again.


## Release-lock stable-tree note

The validator reports `release-lock stable-tree property holds for the actual self-test and two literal deterministic CLI passes`. The outer maintainer invocation is the actual `validate_package.py . --self-test` run and is bound by complete no-follow non-cruft path/type/mode/link-target/hardlink/byte snapshots. Two non-recursive subprocess passes then invoke the reviewed deterministic CLIs with unique external outputs, name the optional/runtime commands they exclude, and compare the package entry tree before, between, and after. A self-test Markdown destination must resolve outside the package and is atomically replaced, so even an external hardlink cannot modify a package inode after the completion snapshot.


### Trace-authentication addendum

PASS-TRACKED trace authentication must parse only recognized stream-json event positions. Do not count fake `tool_result` dictionaries embedded inside `tool_use.input`, `arguments`, `args`, or `parameters`; they are tool input data, not runtime completion events. A successful result/completion must explicitly match the native tool-use id and appear after that tool-use event. Strict local evidence mode rejects all URI-scheme evidence refs case-insensitively, including uppercase HTTPS/DOI/URN and arbitrary scheme-like refs.


## Trace/evidence hardening note

PASS-TRACKED runtime promotion requires authentic tool-use/tool-result event types, exact structured ntt-* selectors, matching post-call result IDs, no unexpected Agent/Task calls, and no text/message masquerade. Strict local evidence rejects URI-scheme evidence_refs and URI-scheme artifact_path values.

## Reviewer note
Check formal traces for payload-bearing result content, not merely success-like metadata. Check strict evidence ledgers for unique evidence-file identities and unique artifact/hash identities; duplicate refs or aliases should not satisfy critical claim evidence minima.

## Release-provenance hygiene addendum

Before reuse, review the validator output for the release-provenance hygiene check. The fixed-pattern scanner targets stale prior-version package roots, stale targeted-probe names, the exact current package root, and known machine-local build/workspace roots used as current bundled provenance. A line may preserve full configured prior package/work-root text only when, after leading whitespace, it begins with the exact case-insensitive marker `Historical provenance reference:`. Merely including words such as "historical" elsewhere on a line grants no exemption, and the exact current package root is never exempt. Raw external runtime transcripts may truthfully retain resolved tool paths; bundled summaries normalize package-root/output-directory substrings and executable paths, label them `representation=normalized-display`, and preserve an explicit raw-external-transcript policy rather than pretending placeholders were literal argv. This check is intentionally about release evidence hygiene; it does not promote the package beyond PASS-SCOPED without live runtime traces.

This package remains deliberately closed-surface. It is not a general validator for all platform-supported plugin extension points; adding hooks, MCP/LSP surfaces, commands, bins, monitors, manifest component-path fields, dynamic skill shell, or broad tool grants is a policy change requiring new evidence and review.


## No automatic downstream closure

Do not treat `PASS-SCOPED` or `PASS-TRACKED` for a source claim as inherited proof of an entailed deployment, safety, compliance, production-readiness, or action-authorizing claim. Record each such downstream conclusion as its own claim or as a `derived_or_downstream_claims` record. Untested downstream claims are `UNKNOWN`; `UNVERIFIED` is a whole-artifact gate status.

## PASS-TRACKED promotion protocol

Do not label a run `PASS-TRACKED` merely because this package validates or because a previous release was `PASS-SCOPED`. Promotion certificate v2 requires `promotion_schema_version: "2.0"`, a `promotion-evidence-v2` typed role map/DAG, exact bytes and SHA-256 for canonical bundle-local regular non-symlink files, role-specific deterministic/official/live/formal validation, and an explicit `downstream_review`. Ordinary gate claim `evidence_refs` remain unchanged; the typed DAG is specific to the promotion certificate.

The certifier reruns deterministic suites and allowlisted official validators. Claude validation uses exact strict argv and accepts the real ANSI-normalized `✔ Validation passed` form only when neither complete output stream contradicts it. Full captured bytes determine status, byte counts, and SHA-256; bounded excerpts and truncation flags are presentation metadata, not an authentication substitute. Prewritten text captures do not authorize. Missing official tools may be scoped only through the explicit flag; installed failures fail. Formal result `2.0` is selected only through its typed locator and binds a standalone endpoint-checked target copy, complete transcript, exact companion manifest, package tree, run, and target endpoint identities. The copy records `temporal_immutability_enforced: false`, which caps an otherwise `PASS-TRACKED` result at `PASS-SCOPED`. Capture establishes supported Linux child-subreaper adoption plus bounded `/proc` adopted-child tracking before `Popen`; after the leader exits, it kills and reaps same-group and detached-session descendants. Unavailable containment refuses execution, and any survivor or incomplete cleanup fails closed. Unrelated nonreserved files may remain, but basename substitution, glob-first selection, and tail-only transcript authentication are forbidden.

Gate Markdown, certifier JSON/Markdown, formal output plus compatibility JSON, live transcripts plus optional JSON, validator Markdown, all four deterministic contract/regression `--json` wrappers, and the fixed behavior/stable-release manifests open their parent component-by-component with `O_DIRECTORY`/`O_NOFOLLOW` before long-running work and retain the descriptor through descriptor-relative exclusive creation, link/rename installation as applicable, and directory fsync. Role and alias decisions are frozen from lexical names plus held identities: formal canonical-result classification is not recomputed after writes, certifier JSON/Markdown aliases fail, and live JSON cannot alias a selected transcript. Direct/ancestor links, special or hardlink sentinels, and lexical-parent replacement cannot redirect writes; validator Markdown also rechecks that the held parent remains outside the package tree. Observed mismatch fails closed, but endpoint/capability checks are not temporal isolation and do not exclude every same-UID mutation between observations.

Formal coordinator and gate children use only `/proc/<runner-pid>/fd/N` with `pass_fds`; the runner takes its procfs-visible PID from `/proc/self/status` `Pid:`, and the gate requires that canonical positive PID to match its procfs-visible direct-parent `PPid:`. Closing/rebinding the child FD number cannot alter the runner-owned capability, and self/unrelated PIDs, noncanonical or nonpositive PID/FD tokens, extra components, closed descriptors, and file descriptors are rejected. Missing POSIX procfd support returns `INVALID_INPUT` before any requested formal output is created.

Promotion requires at least one well-formed claim and a nonempty all-passing canonical strict-gate result set. Malformed, duplicate, invalid, or empty claims return canonical `FAIL` plus `failure_kind`. A performed downstream review may explicitly identify no downstream conclusions only when it records a substantive reason.

Caller-controlled output destinations enforce their declared fresh-versus-replaceable final-name policy through held parent capabilities and bounded structured failures. Existing private regular `--json` files are intentionally regenerated by same-directory exclusive temporary plus atomic replacement; validator Markdown must stay outside the package tree, and an output directory must be a real directory or safely created new directory.

For v1.0.3, a complete modeled result is deliberately capped at `status: PASS-SCOPED`, `outcome: CAPPED`, `promotion_authorized: false`, and `satisfied_profile: promotion-contract-v2-complete`, with a nonzero exit and both unresolved Issue #5 obligations: consistency-sweep activation/resolution mechanics and `REMOTE_GROUND_TRUTH_REQUIRED` escalation mechanics remain parent-enforced. Generic `ntt_gate.py` `PASS-TRACKED` semantics remain unchanged. Independently, the formal runner caps an otherwise `PASS-TRACKED` result at `PASS-SCOPED` because temporal immutability remains unenforced; unavailable process containment refuses execution.

The 44-case aggregate suite invokes the production certifier CLI for the baseline and all negative cases. Treat `44/44` as synthetic contract evidence, never as live runtime authentication.


## GitHub README documentation review

For this release line, GitHub-facing README files belong under `docs/` and `self_validation/`. Do not add README files to plugin-loadable runtime component directories such as `agents/` or `skills/nozickian-verify/` unless the closed-surface policy and validator are intentionally redesigned. Reviewers should treat documentation as stable release content: it must be included in the stable release manifest and must not contain stale package roots, local build paths, or status inflation from PASS-SCOPED to PASS-TRACKED.
