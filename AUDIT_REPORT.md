# Nozickian Verification Package Audit Report — historical record of the first-patch release

This report records the full evidence-gated release audit for the team/internal Nozickian verification plugin. It is a stable release artifact, not a runtime plugin component.

**Historical-record notice.** The sections above the dated v1.0.3 addendum are the audit record produced for the first-patch release — the release documented under the `v1.0.1_patch_notes` key in `RELEASE_LOCK.json`, two patches before the current one. The recorded commands, counts, and judgments are preserved exactly as recorded then and are NOT claims about the current release. Literal dotted version tokens in this historical section have been rewritten to scan-inert references (for example, "the `v1.0.1_patch_notes` release") so the release validator's stale-release-provenance scan stays meaningful; no recorded result was altered. Current-release evidence lives in the dated addendum at the end of this report.

## CoVe protocol

| Step | Question | Evidence artifact | Result |
|---:|---|---|---|
| 1 | Draft package claims | self_validation/self_certificate.json | Four critical claims identified |
| 2 | Plan verification questions | AUDIT_REPORT.md / RELEASE_LOCK.json | Static, gate, trace, manifest, release-idempotence, and runtime-scope questions |
| 3 | Answer independently | deterministic scripts and contract suites | Local checks run without relying on prose ledgers |
| 4 | Revise verdict | ntt_gate.py + validation results | PASS-SCOPED, not PASS-TRACKED |

## Command ledger summary

| # | Area | Command or artifact | Result |
|---:|---|---|---|
| 1 | Archive identity | plugin.json version | the `v1.0.1_patch_notes` release version / PASS |
| 2 | Release label | self_certificate / release lock | PASS-SCOPED / PASS |
| 3 | Runtime scope | live Claude Code CLI | UNVERIFIED_RUNTIME / SCOPED |
| 4 | Static validator | validate_package.py | 1100/1100 basic checks / PASS |
| 5 | Full self-test | validate_package.py --self-test | 1137/1137 checks after final manifest refresh / PASS |
| 6 | Gate contracts | run_gate_contract_tests.py | 48/48 cases / PASS |
| 7 | Formal contracts | run_formal_runner_contract_tests.py | 47/47 cases / PASS |
| 8 | Regression evals | run_regression_evals.py | 166/166 checks / PASS |
| 9 | False-world package mutations | validator mutation suite | 31/31 rejected / PASS |
| 10 | True-world package variants | validator true-world suite | 3/3 retained / PASS |
| 11 | Stable manifest | STABLE_RELEASE_MANIFEST.json | self-hash + inventory checked / PASS |
| 12 | Release idempotence | release-lock semantic chain | no package-tree drift / PASS |

## Patch verification matrix (`v1.0.1_patch_notes` release)

| Patch area | Truth-tracking rule | Evidence case | Status |
|---|---|---|---|
| Trace hard event boundary | No child of a tool_use/tool_result node is scanned as a fresh runtime event | tool_use_inside_tool_result_payload_does_not_authenticate; fake_tool_use_and_result_inside_tool_result_data_does_not_authenticate | PASS |
| Payload/data/delta smuggling | Fake native lanes under tool_result payload/data/delta are ignored as payload data | formal_runner_contract_results.json | PASS |
| Role direction | User-origin tool_use and assistant-origin tool_result blocks are rejected when role context exists | user_message_tool_use_does_not_authenticate; assistant_message_tool_result_does_not_authenticate | PASS |
| Valid role true-world | Assistant-origin tool_use plus user-origin tool_result remains accepted | valid_assistant_tool_use_user_tool_result_still_authenticates | PASS |
| Modal target binding | False/true world tests must target the evaluated claim | wrong_false_world_target_claim_rejected; wrong_true_world_target_claim_rejected | PASS |
| Stable modal IDs | Anonymous modal tests fail even with structured evidence | missing_false_world_test_id_rejected; missing_true_world_test_id_rejected | PASS |
| Wildcard evidence limit | applies_to_tests wildcard cannot replace missing test ID | wildcard_applies_to_tests_does_not_replace_test_id | PASS |
| target_claim_ids support | List-valued target_claim_ids including the claim remains valid | valid_target_claim_ids_list_still_passes | PASS |
| Release-provenance hygiene | Bundled audit/self-validation artifacts must not contain stale old-version roots or machine-local build paths | validate_package.py release provenance hygiene check | PASS |
| Stale-ledger false world | Injected stale generated self-validation provenance must fail validation | rejects stale generated self-validation artifact provenance | PASS |
| Active self-certificate stale version | Old regenerated-package producer strings in the active self-certificate must fail validation | rejects active self-certificate stale package-version provenance | PASS |
| Downstream non-closure | A source claim pass must not auto-promote downstream/deployment/action claims | rejects downstream auto-pass epistemic closure; downstream_claim_auto_pass_rejected | PASS |
| Closed-surface scope clarity | Package must not overclaim as a validator for every platform-supported plugin surface | README.md / PACKAGE_SURFACE.json / TEAM_INTERNAL_USE.md | PASS |

## Nozickian false-world sensitivity table

| False world | Required verifier behavior | Evidence | Status |
|---|---|---|---|
| Recursive nested plugin agent after manifest update | Validator must reject loadable hidden agent | mutation suite | PASS |
| Wrong structured evidence hash | Gate must fail even if other refs are good | gate contract | PASS |
| Evidence ref escapes evidence_root | Gate must reject external provenance | gate contract | PASS |
| URI-scheme evidence ref / artifact_path | Gate must reject URI-like strict local refs case-insensitively | gate contract | PASS |
| Duplicate or aliased claim evidence | Gate must not count one evidence file twice | gate contract | PASS |
| Same artifact behind two evidence wrappers | Gate must require distinct artifact/hash identities for critical evidence sufficiency | gate contract | PASS |
| Duplicate modal test object | Gate must not count one nearby world twice | gate contract | PASS |
| Wrong target_claim | Gate must not borrow another claim’s modal evidence | gate contract | PASS |
| Missing modal test ID | Gate must not allow anonymous modal coverage | gate contract | PASS |
| Fake tool events inside tool_result.content | Trace parser must not discover events in output payload | formal contract | PASS |
| Fake tool events inside tool_result.payload/data/delta | Trace parser must treat all children of tool event as payload | formal contract | PASS |
| Role-inverted tool events | Trace parser must respect assistant tool_use / user tool_result direction when known | formal contract | PASS |
| Mismatched tool_result id | Trace parser must require exact result ID binding | formal contract | PASS |
| Result before tool_use | Trace parser must require chronological result-after-call order | formal contract | PASS |
| Metadata-only result content | Trace parser must require substantive completion payload | formal contract | PASS |
| Stale generated validation ledger | Release validator must reject old package roots or machine-local build paths in bundled self-validation artifacts | package mutation suite | PASS |
| Downstream auto-pass closure | Gate and package validator must reject inherited PASS for untested downstream claims | gate contract + package mutation suite | PASS |

## True-world adherence table

| True world | Adherence rule | Evidence | Status |
|---|---|---|---|
| Benign README note | Package remains valid after manifest refresh | true-world suite | PASS |
| Unused asset | Package remains valid when inert asset is added with stable manifest refresh | true-world suite | PASS |
| Reference whitespace | Package remains valid after benign SOURCES whitespace and manifest refresh | true-world suite | PASS |
| Nonempty text result block | Formal trace authentication accepts substantive result payload | formal contract | PASS |
| Valid role direction | Assistant tool_use plus user tool_result authenticates synthetic true-world trace | formal contract | PASS |
| target_claim_ids list | Gate accepts list-valued target binding that includes evaluated claim | gate contract | PASS |

## Residual scope limits

| Limit | Status | Handling |
|---|---|---|
| Live Claude Code plugin runtime | UNVERIFIED_RUNTIME | Release remains PASS-SCOPED |
| Genuine claude executable provenance | Not cryptographically proven | Do not treat dry-run as live runtime proof |
| Fully hostile maintainer rewriting all validators and manifests | Out of team/internal threat model | Requires independent external review |
| Semantic adequacy of every future evidence artifact | Not mechanically complete | Requires reviewer judgment and source audit |

## Final release decision

| Criterion | Judgment |
|---|---|
| Rigor | High for static package, evidence gate, release manifest, and formal trace parser contracts |
| Soundness | Strong within deterministic/static scope; live runtime remains explicitly unverified |
| Completeness | Complete for currently discovered nearby false-world classes, including stale release-provenance ledgers; not a cryptographic proof of all possible traces |
| Nozickian sensitivity | Passes bundled false-world probes |
| Nozickian adherence | Passes bundled true-world probes |
| Release label | PASS-SCOPED |

## Validation command ledger

| Command | Evidence | Result |
|---|---|---|
| validate_package.py . | package_validation_result.json | PASS |
| validate_package.py . --self-test | package_validation_self_test_result.json | PASS, 1137/1137 after final refresh |
| ntt_gate.py --strict-evidence | gate_result.json | PASS-SCOPED |
| run_gate_contract_tests.py | gate_contract_results.json | 48/48 PASS |
| run_formal_runner_contract_tests.py | formal_runner_contract_results.json | 47/47 PASS |

## Evidence-gated CoVe table

| Claim | Verification question | Independent evidence | Revised answer |
|---|---|---|---|
| Closed package surface | Are hidden runtime/plugin surfaces rejected? | validator mutation suite | Yes |
| Strict evidence binding | Are evidence refs and modal tests bound to real local artifacts/claims? | gate contracts | Yes, within static scope |
| Formal trace authentication | Are fake nested events, role inversion, duplicate IDs, and empty results rejected? | formal contracts | Yes, synthetic trace contracts pass |
| Runtime tracking | Was a live official Claude Code run executed? | formal dry run result | No; UNVERIFIED_RUNTIME |

## Nozickian truth-tracking matrix

| Dimension | Nearby false-world check | Nearby true-world check | Judgment |
|---|---|---|---|
| Sensitivity | Hidden agents, bad hashes, fake trace events, wrong target claims | n/a | PASS in deterministic suite |
| Adherence | n/a | benign README/reference/asset variants; valid role direction trace; target_claim_ids list | PASS in deterministic suite |
| Scope honesty | PASS-TRACKED withheld without live runtime | PASS-SCOPED retained | PASS-SCOPED |

## Stable release manifest

| Field | Meaning | Status |
|---|---|---|
| self_hash_sha256 | Canonical manifest self-hash with field nulled | Checked by validator |
| file_inventory | Stable package files except manifest/volatile ledgers | Checked by validator |
| volatile_exclusions | Generated validation stdout/results excluded from stable inventory | Declared and checked |

## Release-workflow idempotence

| Step | Drift policy | Result |
|---|---|---|
| Semantic RELEASE_LOCK command chain | Must not modify package files | PASS |
| Formal dry run | External output by default | PASS |
| Final package validator | Must still pass after release workflow | PASS |

## Residual risks

| Risk | Why retained | Mitigation |
|---|---|---|
| Live Claude Code runtime unavailable | No authenticated stream-json trace was captured here | Keep PASS-SCOPED |
| Hostile maintainer can rewrite validators | Team/internal threat model only | Independent reviewer should re-run checks |
| Semantic adequacy of future evidence | Deterministic gate cannot prove every future source judgment | Human evidence review remains required |

## Provenance-hygiene regeneration note (`v1.0.1_patch_notes` release)

The stale bundled generated outputs identified in the prior-version audit were replaced with that release's regenerated outputs. Machine-local build paths in bundled self-validation ledgers are normalized, and validate_package.py now fails the package if bundled audit/self-validation artifacts contain stale prior-version roots or machine-local build paths. The release remains PASS-SCOPED because live Claude Code runtime traces and optional official validators were not available in this environment.


## Epistemic non-closure patch

The `v1.0.1_patch_notes` release made downstream non-closure explicit. A pass for claim `p` does not automatically verify an entailed or action-authorizing claim `q`; any `q` must have its own claim record or `derived_or_downstream_claims` entry. The active self-certificate includes an UNVERIFIED downstream-claim record, and the validator rejects stale active self-certificate package-version provenance plus downstream auto-pass closure mutations.

## PASS-TRACKED upgrade audit surface (`v1.0.1_patch_notes` release)

| Surface | Required evidence | Anti-closure condition | Promotion effect |
|---|---|---|---|
| `PASS_TRACKED_UPGRADE_AUDIT.md` | external audit bundle layout, command ledger, live fixture instructions, formal artifact instructions | PASS-SCOPED package validation does not imply runtime tracking | documents required promotion path |
| `certify_pass_tracked_upgrade.py` | deterministic JSON, official validator outputs, live runtime JSON, formal result JSON, promotion certificate | prose-only reports and dry-runs cannot upgrade status | machine-gates promotion |
| live fixture evals | non-UNVERIFIED runtime result and copied transcripts | fixture pass does not prove formal artifact correctness | necessary but not sufficient |
| formal artifact run | strict-gate PASS-TRACKED and authenticated stream-json native ntt-* lanes | trace authentication does not prove downstream deployment safety | required for runtime tracking |
| promotion certificate | package hash, evidence refs, method M_upgrade, downstream records | downstream claims remain UNVERIFIED unless separately tested | final upgrade target |

The `v1.0.1_patch_notes` release did not itself claim PASS-TRACKED, and the current release still does not. It provides the audit protocol and certifier that a Claude Code runtime environment can use to determine whether a future external evidence bundle justifies promotion from PASS-SCOPED to PASS-TRACKED.


## GitHub README documentation audit

The release includes a documentation-only README tree under `docs/` plus `self_validation/README.md`. The validator requires this GitHub documentation set, checks that it covers quickstart, audit model, evidence, PASS-TRACKED upgrade, runtime trace authentication, security, development, release, FAQ, and repository presentation topics, and rejects degraded or missing documentation. The documentation tree is treated as stable package content without adding plugin-loadable runtime surfaces.


## v1.0.3 addendum (2026-07-09)

This dated addendum is the current-release audit record for **v1.0.3**. Everything above it is the preserved historical first-patch audit record.

### What changed in v1.0.3

| Area | Change |
|---|---|
| Charter: activation predicate | One canonical consistency-sweep activation predicate ("mandatory whenever the artifact is a revision of previously corrected material, or any claim was corrected or refuted during this verification"), cross-referenced everywhere as SKILL.md activation checklist step 9 |
| Charter: escalation schema | One canonical 7-field `REMOTE_GROUND_TRUTH_REQUIRED` record (adds `resolution`); canonical vocabulary: claims are UNKNOWN, `UNVERIFIED` is the gate status word |
| Charter: resolution semantics | Swept is not resolved - sweep findings carry `resolution` (`resolved` / `unresolved` / `accepted-intentional-reference`); unresolved `stale-echo` caps at PASS-SCOPED; unresolved `live-claim` returns to adjudication |
| Charter: pinned is not fresh | Freshness is claim-relative; a pinned mirror never satisfies a current-state claim; `staleness_risk` recorded whenever a pinned mirror is accepted |
| Charter: untrusted fetch-spec | `exact_fetch_spec` is untrusted data; the parent never executes it verbatim and re-validates scheme/host/method |
| Validator: stale-semver scan | `scan_stale_semver_provenance` fails any provenance-scanned release file carrying a semver token strictly lower than plugin.json's version (fails closed on unparseable current version); provenance scanning now includes `references/OUTPUT_TEMPLATES.md` |
| Validator: cert-version check | Critical check that the active self-certificate `artifact.version` matches plugin.json; two new false-world mutations cover both additions |
| Release metadata | This release dogfoods the charter: the active self-certificate carries real `consistency_sweep` and `remote_escalations` records for this finalization; stale recorded counts and prior-version markers in bundled provenance files were swept and resolved |

### Consistency sweep for this release (dogfood record)

The corrected material for this release: the recorded intact-copy self-test counts (previously recorded as 1353/1353 during the port; the current tree's full self-test totals differ) and the prior-version release markers throughout bundled provenance files. The sweep and per-finding resolutions are recorded in `self_validation/self_certificate.json` under `consistency_sweep`; every finding is `resolved` with the edited location recorded. Remote escalations for this finalization: none - all ground truth was package-local.

### Final v1.0.3 self-test and gate record

| Command | Result |
|---|---|
| `validate_package.py . --self-test` | PASS - 1371/1371 checks, 0 critical failures, 36/36 false-world mutations rejected, 4/4 true-world variants retained |
| `ntt_gate.py self_validation/self_certificate.json --evidence-root . --strict-evidence` | PASS-SCOPED - 0 critical, 0 major, 7 claims, 3 derived/downstream non-closure records, strict local evidence verified |
| `run_gate_contract_tests.py` | 57/57 contract cases PASS |
| `run_formal_runner_contract_tests.py` | 47/47 contract cases PASS |
| `run_regression_evals.py .` | 166/166 checks PASS |
| new stale-semver provenance check | PASS - zero semver tokens older than the current plugin version in provenance-scanned files |
| new self-certificate artifact-version check | PASS - certificate=1.0.3 plugin=1.0.3 |

Counts in this table are recorded from a full self-test of the exact release tree state they describe (recorded at: branch charter-fixes-consistency-sweep-remote-escalation, base commit 1eed196, v1.0.3 finalization working tree; behavior-file state MANIFEST.sha256 sha256=a0ce9798bb9e0d4e751f48e1ab936c9c1349b7d6dbfaaa842abf56c6b93b0279). The release remains **PASS-SCOPED**: live official Claude Code runtime traces were again not captured in this environment, so live runtime stays UNVERIFIED_RUNTIME.
