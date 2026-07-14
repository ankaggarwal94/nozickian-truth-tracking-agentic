# Nozickian Verification Package Audit Report — historical record of the first-patch release

This report records the full evidence-gated release audit for the team/internal Nozickian verification plugin. It is a stable release artifact, not a runtime plugin component.

**Historical-record notice.** The sections above the dated v1.0.3 addendum are the audit record produced for the v1.0.1 release — the first-patch release, documented under the `v1.0.1_patch_notes` key in `RELEASE_LOCK.json`, two patches before the current one. The recorded commands, counts, and judgments are preserved exactly as recorded then and are NOT claims about the current release. Current-release evidence lives in the dated v1.0.3 addendum at the end of this report.

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
| 1 | Archive identity | plugin.json version | v1.0.1 release version / PASS |
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

## Patch verification matrix (v1.0.1 release)

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

## Provenance-hygiene regeneration note (v1.0.1 release)

The stale bundled generated outputs identified in the prior-version audit were replaced with that release's regenerated outputs. Machine-local build paths in bundled self-validation ledgers are normalized, and validate_package.py now fails the package if bundled audit/self-validation artifacts contain stale prior-version roots or machine-local build paths. The release remains PASS-SCOPED because live Claude Code runtime traces and optional official validators were not available in this environment.


## Epistemic non-closure patch

The v1.0.1 release made downstream non-closure explicit. A pass for claim `p` does not automatically verify an entailed or action-authorizing claim `q`; any `q` must have its own claim record or `derived_or_downstream_claims` entry. The active self-certificate includes an UNVERIFIED downstream-claim record, and the validator rejects stale active self-certificate package-version provenance plus downstream auto-pass closure mutations.

## PASS-TRACKED upgrade audit surface (v1.0.1 release)

| Surface | Required evidence | Anti-closure condition | Promotion effect |
|---|---|---|---|
| `PASS_TRACKED_UPGRADE_AUDIT.md` | external audit bundle layout, command ledger, live fixture instructions, formal artifact instructions | PASS-SCOPED package validation does not imply runtime tracking | documents required promotion path |
| `certify_pass_tracked_upgrade.py` | deterministic JSON, official validator outputs, live runtime JSON, formal result JSON, promotion certificate | prose-only reports and dry-runs cannot upgrade status | machine-gates promotion |
| live fixture evals | non-UNVERIFIED runtime result and copied transcripts | fixture pass does not prove formal artifact correctness | necessary but not sufficient |
| formal artifact run | strict-gate PASS-TRACKED and authenticated stream-json native ntt-* lanes | trace authentication does not prove downstream deployment safety | required for runtime tracking |
| promotion certificate | package hash, evidence refs, method M_upgrade, downstream records | downstream claims remain UNVERIFIED unless separately tested | final upgrade target |

The v1.0.1 release did not itself claim PASS-TRACKED, and the current release still does not. It provides the audit protocol and certifier that a Claude Code runtime environment can use to determine whether a future external evidence bundle justifies promotion from PASS-SCOPED to PASS-TRACKED.


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
| Validator: mode-aware package surface | Git evidence is classified as verified root worktree, genuine Git-free package/export, or Git-evidence failure. `git ls-files --stage -z` preserves typed path/mode/object/stage entries; nonzero stages and every mode outside 100644/100755 fail, including index-only mode 160000 gitlinks and mode 120000 links. Every physical symlink or unsupported special entry fails in verified and Git-free trees before content reads |
| Validator: safe manifest writes | `--update-manifest` runs no-follow physical and typed Git preflight before writing. Both fixed manifest writers use fresh same-directory temporary files plus `os.replace`; the external-sentinel self-test proves a symlinked MANIFEST fails unchanged and direct atomic replacement does not follow the target |
| Validator: isolated checkout fixtures | Checkout tests copy package content with symlinks preserved but no `.git`, initialize and baseline-stage a fresh disposable repository, verify its top level and index are inside the copy before mutation-specific adds, and prove the source status/index are unchanged |
| Validator: observational source snapshot | The source index path and SHA-256 are captured before status; status runs with `GIT_OPTIONAL_LOCKS=0`; any before/after index hash change is a probe failure |
| Validator: entry type and allowlist parity | Package traversal uses no-follow entry typing. Every declared allowed/forbidden `PACKAGE_SURFACE` set, including CI files, plugin-manifest files, skill runtime directories, runtime fields, and forbidden surfaces, must be a unique string set exactly equal to executable policy; contradictions and unknown schema keys fail |
| Validator: reachable schema and harness errors | `PACKAGE_SURFACE` must be an object and `allowed_agents` a unique string array. Non-UTF-8 provenance becomes a named critical hit. Validator-copy exceptions are `HARNESS_ERROR`, never successful false-world rejection evidence |
| Validator: single-document stdout | All seven fixed package-local dynamic loaders contain import-time stdout. The PASS-TRACKED certifier pass-stub mutation asserts empty outer stdout while the copied validator still completes with ordinary FAIL/nonzero behavior. Raw basic/full validation, gate, contract, regression, aggregate, and formal dry-run result streams are accepted only when direct `json.load` consumes exactly one document |
| Validator: CI semantic reachability | Required workflow commands count only when they are direct top-level commands in active named `run:` blocks. Statically false job conditions, conditional steps, comments, heredocs, functions, loops, conditionals, case statements, and shell grouping cannot satisfy checkout/archive aggregate policy. Dedicated false worlds disable the entire job and hide both exact aggregate commands inside `if false`; each must fail the three intended aggregate assertions |
| Validator: historical-version adherence | The two context-free bare-version patterns were removed because they rejected legitimate history and were future-brittle. Context-bearing stale package/work/artifact markers and the field-aware self-certificate/plugin version equality check remain; explicit historical prose for both prior versions is a retained true world |
| Validator: cert-version check (kept) | Critical field-aware check that the active self-certificate `artifact.version` equals plugin.json's version (the real fix for the version-provenance issue); its false-world mutation is retained |
| CI: archive validation | The deterministic workflow now creates a Git archive, unpacks it, and runs the package validator against that Git-free tree. This source-level audit does not claim that a hosted CI run occurred in this local redress |
| Semantic evidence contracts | Charter observed behavior uses citation-only prose rather than volatile digest echoes. Consistency records require unique canonical `affected_claim_ids`, unique `locations`/`edited_locations`, classification/resolution pairings, recommended edits, and resolution-conditional evidence; these remain parent/auditor-enforced and are not mechanically checked by `ntt_gate.py` or the formal runner (issue #5 deferred) |
| Runtime evidence provenance | New harness runs require zero-returning version/plugin preflight, fingerprint the resolved executable, and accept only a structured JSON object whose substantive `result`/`content` report alone satisfies status/term/artifact checks. Provenance schema is 1.0 and identity explicitly says `observed-not-cryptographically-authenticated`; no official-binary proof is claimed. Legacy checked-in summaries retain unknown producing-run release/time/identity with null `carried_forward` and remain `UNVERIFIED_RUNTIME` |
| Boundary-aware display normalization | Validator, gate, regression, and live harness normalize an exact package root or rooted child path while preserving adjacent lookalikes such as `/tmp/root-old` |
| Reproducible manifest epoch / Issue #8 semantics | `STABLE_RELEASE_MANIFEST.json.generated_utc` is fixed at deterministic epoch `2026-05-26T00:00:00Z`; exact `generated_utc_kind=reproducible-build-epoch`, value, and non-wall-clock semantics are validated with no caller override. This resolves the v1.0.3 generated-time ambiguity for package semantics without claiming that the remote Issue #8 is closed |
| Slice F: exact executable identity | `shutil.which("claude")` is consumed once; its absolute regular target is fingerprinted and used for every version, plugin, and fixture subprocess. A relative-PATH/two-cwd false world proves the alternate fixture-cwd binary is never executed. Equal pre/post hashes and `fingerprint_stable=true` are required before PASS-SCOPED |
| Slice F: current transcript-backed live promotion | The certifier requires schema 1.0 current-run provenance, exact current release, non-carried timestamped evidence, successful preflight, stable fingerprints, and the exact current `evals.json` fixture IDs once each. Every bundle-local transcript stdout is replayed through the current checker and must exactly match self-reported checks |
| Promotion v2: fresh deterministic and official execution | `deterministic-capture-v2` records are non-authorizing and are compared through exact typed suite projections against fresh fixed-argv executions. Claude uses exact ordered strict argv and accepts the real ANSI-normalized `✔ Validation passed` form only when neither complete stream contradicts it. Full captured bytes determine decisions, hashes, and byte counts; public excerpts carry explicit truncation metadata. Text captures do not authorize; absent tools scope only through the explicit flag while both official-policy nodes and their dependencies remain present; installed failures fail |
| Promotion v2: typed evidence DAG | Exact-string `promotion_schema_version="2.0"` and exact required top-level field types are enforced. `evidence.schema_version=promotion-evidence-v2` replaces flat promotion refs. The fixed nine semantic roles bind distinct canonical regular non-symlink bundle files by exact bytes and SHA-256, carry one environment-independent bounded acyclic dependency graph, receive role-specific validation, and require explicit `downstream_review` |
| Promotion v2: canonical claims/downstream review | `claims` is nonempty; every entry has exact required types and a unique canonical ID, is evaluated through the canonical strict gate at the bundle evidence root, and must produce a nonempty all-PASS result set before the actual results enter promotion-strict downstream non-closure evaluation. Empty downstream conclusions remain valid only with a real passing promotion claim, performed review, and substantive reason |
| Formal result 2.0 | Promotion follows only the typed `formal.result` locator. The result binds the immutable standalone target snapshot, exact report/gate/certificate/ledger/complete-transcript/prompt/target-snapshot manifest, package-tree identity, run identity, and target pre/post identity. Complete transcript bytes are written, hashed, and authenticated; capture-limit excess fails closed and tail-only authentication is forbidden. No basename/glob-first selection is allowed; unrelated nonreserved files may remain |
| Structured promotion failures | Malformed, duplicate, invalid, or empty claims and other malformed bundle data return canonical `FAIL` plus `failure_kind` (`INVALID_INPUT`, `CHECK_FAILED`, or `INTERNAL_ERROR`) rather than an unhandled traceback |
| Safe certifier/formal output paths | Caller-supplied paths reject symlinked ancestors, direct links, special files, and hardlink aliases with bounded structured invalid-input results and no external overwrite. Existing private regular `--json` files are intentionally regenerated via same-directory exclusive temporary plus atomic replacement; `--output-dir` must be a real or safely created directory |
| v1.0.3 certifier-only cap | Every complete modeled result is `PASS-SCOPED` / `CAPPED`, `promotion_authorized=false`, `satisfied_profile=promotion-contract-v2-complete`, records both exact unresolved Issue #5 obligations, and exits nonzero. Generic `ntt_gate.py` and formal-runner `PASS-TRACKED` semantics remain unchanged |
| Aggregate promotion contract | The dedicated synthetic suite expects 36/36 and invokes the production certifier CLI for the complete baseline and every negative. It covers exact strict-validator argv/real output, complete-stream early failures, fixed-DAG retention under explicit unavailable-validator scope, canonical positive downstream evaluation, malformed/empty claims, safe output paths, exact ordered Issue #5 obligations, and complete formal transcript binding. It is contract evidence, not real runtime authentication |
| Slice F: path boundaries | Validator, gate, regression, and live normalization retain `root@sibling`, `root old`, Unicode suffixes, and `root-old`, while still normalizing root and rooted child paths |
| Slice G: one-to-one live binding | Every live fixture records the exact canonical normalized-display prompt SHA-256 and exact written transcript JSON byte SHA-256. Promotion requires distinct canonical transcript paths, regular non-symlink files, exact transcript bytes, and transcript-command prompt text/hash binding to the exact current fixture ID plus expected artifact before independent stdout replay |
| Slice G: independent inventory policy | `package_tree_sha256` loads the current regular `validate_package.py`, executes `iter_release_inventory_files`, and requires manifest inventory paths plus volatile file/prefix exclusions to equal the current executable policy exactly. Manifest-authored exclusions cannot remove a behavior or stable file |
| Slice G: unconditional fresh validation | Every promotion attempt reruns the current basic package validator and treats failure as critical. `--run-fresh-package-validator` remains accepted only for compatibility and cannot disable or newly enable the check |
| Slice H: live bytes bind current package | `validate_package.compute_stable_release_tree` is the single `ntt-stable-release-tree-v1` implementation used by live capture and certification. Live results also hash exact `evals.json` and artifact bytes; certification recomputes each binding, so refreshed manifests cannot rescue stale live evidence after a package, fixture-spec, artifact, or non-artifact behavior-source change |
| Slice H: exact normalized argv | Live results record `run_config.max_turns`; certification requires exactly two ordered preflight argv arrays and each exact ordered fixture argv array with plugin directory, print mode, JSON output, recorded max turns, and canonical prompt. Prompt-only, missing, extra, reordered, wrong-format, wrong-turn, and wrong-preflight argv fail independently of prompt/report replay |
| Slice I: exact return-code type | Every certifier success check now requires exact integer zero (`type(value) is int and value == 0`), including official JSON validators, the unconditional fresh validator, live preflight commands and aggregate summary, fixture summaries, and transcript/result agreement. Focused false worlds reject `false`, `true`, `0.0`, `"0"`, and `null`; integer `0` remains valid |
| Slice I: contradictory text counts | Official text validation rejects anchored nonzero numeric `error`/`errors`/`failure`/`failures`/`failed` summaries before positive markers, case-insensitively and with punctuation. Focused controls reject pass-plus-nonzero contradictions, retain pass-plus-zero summaries, and preserve the `invalid`/`valid` boundary |
| Slice J: index-derived tracked cruft | Verified worktree validation classifies cruft from every typed Git index entry with `_is_cruft_relpath`, independently of the physical walker that intentionally does not descend into `__pycache__`. The exact historical `skills/nozickian-verify/scripts/__pycache__/ntt_gate.cpython-312.pyc` checkout false world is force-added and must produce one ordinary critical failure at the named cruft check, whose details enumerate every tracked cruft index path; ignored untracked checkout bytecode remains a retained true world |

### Consistency sweep for this release (dogfood record)

The final sweep covers top-level schema enforcement, the environment-independent nine-role DAG, nonempty canonical promotion claim evaluation, real strict-validator argv/output, complete-stream decisions and transcript binding, lexical output-path safety, the complete formal companion tree, separation of June historical evidence from current v2 provenance, exact ordered obligations, Issue #8 wording, CI semantic reachability, the corrected 36-case documentation, a structurally valid representative `C-UPGRADE-001` skeleton with explicit empty downstream conclusions, the v1.0.3 certifier cap, and regenerated release evidence. The two 2026-06-06 modal evidence files remain immutable history; current observations use separately dated aggregate-certifier and promotion-v2-reference records. Every current `file:line[-line]` locator in `self_validation/self_certificate.json` is re-resolved after final serialization and checked against its semantic target; Git-qualified historical locators remain immutable references. Dated v1.0.1 and 2026-07-09 1369/35/4 observations remain intentional history.

### Final v1.0.3 self-test and gate record

| Command | Result |
|---|---|
| checked-in `validate_package.py . --self-test` | PASS - 1724/1724 checks, 0 critical failures, 63/63 false-world mutations rejected, 10/10 true-world variants retained; raw stdout parses directly as one JSON document |
| checked-in basic `validate_package.py .` | PASS - 1618/1618 checks, 0 critical failures; raw stdout parses directly as one JSON document |
| checked-in `ntt_gate.py self_validation/self_certificate.json --evidence-root . --strict-evidence` | PASS-SCOPED - 0 critical, 0 major, 7 claims, 3 derived/downstream non-closure records, strict local evidence verified |
| `run_gate_contract_tests.py` | 78/78 contract cases PASS |
| `run_formal_runner_contract_tests.py` | 73/73 contract cases PASS |
| `run_regression_evals.py .` | 166/166 checks PASS |
| installed official validator | `claude plugin validate . --strict` PASS with Claude Code 2.1.207; `skills-ref` was not installed and was not executed |
| mode-aware package-surface checks | PASS - clean Git-free export and ignored untracked bytecode retained; all tracked cruft paths are derived from typed index entries independently of physical traversal; exported/direct force-tracked/exact historical nested bytecode and untracked non-bytecode cruft, Git-evidence failure, tracked/Git-free/untracked symlinks, untracked/Git-free FIFOs, nonzero stages, and index-only gitlink mode 160000 rejected before later reads; the exact nested probe failed only the named critical cruft check and its details contained every tracked cruft index path |
| safe manifest writes | PASS - symlinked MANIFEST update failed before write; external sentinel bytes and source checkout stayed unchanged; atomic fixed-path writer replaced the link without following its target |
| isolated checkout fixtures | PASS - disposable top level/index resolved inside the copy; source status and index hash remained unchanged; source status used `GIT_OPTIONAL_LOCKS=0` and before/after index hashes matched |
| allowlist and plugin-field parity | PASS - all declared unique-string sets exactly equal executable policy order-insensitively; omitted, contradictory, unknown-key, drift, and undeclared opaque `experimental` mutations rejected |
| context-bearing provenance hygiene | PASS - exact current-root leakage, active stale markers, and non-UTF-8 provenance rejected as named failures; full prior package/work-root text retained only behind the exact `Historical provenance reference:` line marker |
| mutation harness integrity | PASS - validator exceptions classify as `HARNESS_ERROR`; only completed FAIL/critical results count as false-world rejection, and true worlds require completed PASS |
| live harness contracts | PASS (offline controls) - valid structured report accepted; recursive metadata echo and non-object JSON rejected; fixed fake CLI plugin-preflight failure returned normal FAIL without fixture execution. No real Claude runtime was invoked |
| producer display normalization | PASS - validator, gate, regression, and live-harness serialized displays normalize exact roots/rooted children and preserve adjacent prefix lookalikes |
| exact live executable controls | PASS (offline controls) - relative-PATH candidates under distinct producer/fixture working directories executed only the fingerprinted absolute target for all five version/plugin/fixture calls; pre/post fingerprint remained stable; no resolved executable path was bundled |
| promotion aggregate contracts | PASS - 36/36 synthetic cases invoked the production certifier CLI for the complete baseline and all negatives. The complete modeled baseline traversed all 244 checks, retained the exact fixed role DAG, evaluated a real promotion claim, recorded both ordered Issue #5 obligations, and returned the mandatory `PASS-SCOPED` / `CAPPED` non-authorizing result; this is not real runtime authentication |
| shared package-tree implementation | PASS - live capture and certification both invoke `validate_package.compute_stable_release_tree`; no second `ntt-stable-release-tree-v1` algorithm body remains |
| promotion package/formal false worlds | PASS - missing/wrong-type promotion schema, wrong-tree deterministic capture, wrong strict-validator argv, realistic ANSI success plus complete-stream contradictions, decoy/swapped formal companions, an untyped existing DAG node, malformed/empty claim arrays, duplicate/invalid IDs, failed canonical claims, unsafe output targets/ancestors, a transcript with an early disallowed event before a large valid-looking tail, missing formal trace-authentication metadata, noncanonical paths, graph bounds, and target/package identity defects failed their exact named checks without unrelated failures |
| independent inventory derivation | PASS - 255 manifest paths exactly matched 255 paths returned by the current validator policy, including the new runner and both current evidence records; volatile file/prefix arrays exactly matched current constants; every derived path was regular/non-symlink with matching hash and byte count |
| unconditional fresh package validation | PASS - omission of the compatibility flag still ran the current basic validator; the fixed stale-package false world returned FAIL with one critical failure |
| official-validator controls | PASS - allowlisted validators execute fresh; prewritten text cannot authorize; absent tools scope only through the explicit flag while both official policy nodes and the canonical DAG remain intact; installed failures fail. Exact integer zero is required and structured/plain/JSONL negative status on either stream dominates positive output |
| certifier no-follow controls | PASS - fixed symlink/FIFO inputs were recorded as critical failures, external sentinel content was not consumed, and plugin.json symlink/FIFO cases failed cleanly |
| reproducible manifest epoch | PASS - exact deterministic epoch, `generated_utc_kind`, and explicit non-wall-clock semantics validated |
| self-certificate artifact-version equality check | PASS - certificate=1.0.3 plugin=1.0.3 |
| unpacked Git archive workflow | CONFIGURED - CI archives, unpacks, and validates the Git-free package; no hosted-CI execution is claimed by this local record |
| consistency-sweep record contract | PASS - the final certificate records schema/DAG/formal-tree/provenance/obligation/Issue-8, CI reachability, documentation/template/cap-wording, stdout-containment, and regenerated-output corrections; an iterative post-serialization resolver verified every current locator against its semantic target |

Counts in this table come from the checked-in final release-evidence fixed point. `MANIFEST.sha256`, `STABLE_RELEASE_MANIFEST.json`, structured evidence hashes, formal dry-run records, and generated self-validation outputs were regenerated together and then checked for two-pass idempotence. The release remains **PASS-SCOPED**: live official Claude Code fixture traces were not captured, the producing-run lineage of the legacy bundled runtime summaries remains unknown, and the v1.0.3 certifier cannot discharge the two Issue #5 charter obligations. Live runtime stays UNVERIFIED_RUNTIME; the aggregate suite does not change that.
