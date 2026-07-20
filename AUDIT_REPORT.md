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
| file_inventory | Stable package files except manifest/volatile ledgers, with path, bytes, content digest, and Git-compatible executable mode | Checked by validator |
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
| Issue #6 declarative fetch specification remains open | `exact_fetch_spec` still relies on textual non-execution/SSRF guidance rather than a mechanically typed schema | Keep remote fetches parent-reconstructed and untrusted; implement the issue before claiming mechanical enforcement |
| Issue #7 semantic charter-presence enforcement remains open | Hash sealing does not prove that regenerated manifests retain the required charter semantics | Keep charter review parent/auditor-enforced and add semantic mutation tests before closing the gap |
| Release ZIP is not produced or verified by CI | The hosted workflow validates an unpacked Git tar archive only | Do not claim ZIP-level validation; separately validate entries and publish a digest if a ZIP is released |
| Hostile maintainer can rewrite validators | Team/internal threat model only | Independent reviewer should re-run checks |
| Semantic adequacy of future evidence | Deterministic gate cannot prove every future source judgment | Human evidence review remains required |

## Provenance-hygiene regeneration note (v1.0.1 release)

The stale bundled generated outputs identified in the prior-version audit were replaced with that release's regenerated outputs. Machine-local build paths in bundled self-validation ledgers are normalized, and validate_package.py now fails the package if bundled audit/self-validation artifacts contain stale prior-version roots or machine-local build paths. The release remains PASS-SCOPED because live Claude Code runtime traces and optional official validators were not available in this environment.


## Epistemic non-closure patch

The v1.0.1 release made downstream non-closure explicit. A pass for claim `p` does not automatically verify an entailed or action-authorizing claim `q`; any `q` must have its own claim record or `derived_or_downstream_claims` entry. The active self-certificate includes an UNKNOWN downstream-claim record, and the validator rejects stale active self-certificate package-version provenance plus downstream auto-pass closure mutations. `UNVERIFIED` is reserved for a whole-artifact gate result.

## PASS-TRACKED upgrade audit surface (v1.0.1 release)

| Surface | Required evidence | Anti-closure condition | Promotion effect |
|---|---|---|---|
| `PASS_TRACKED_UPGRADE_AUDIT.md` | external audit bundle layout, command ledger, live fixture instructions, formal artifact instructions | PASS-SCOPED package validation does not imply runtime tracking | documents required promotion path |
| `certify_pass_tracked_upgrade.py` | deterministic JSON, official validator outputs, live runtime JSON, formal result JSON, promotion certificate | prose-only reports and dry-runs cannot upgrade status | machine-gates promotion |
| live fixture evals | non-UNVERIFIED runtime result and copied transcripts | fixture pass does not prove formal artifact correctness | necessary but not sufficient |
| formal artifact run | strict-gate PASS-TRACKED and authenticated stream-json native ntt-* lanes | trace authentication does not prove downstream deployment safety | required for runtime tracking |
| promotion certificate | package hash, evidence refs, method M_upgrade, downstream records | downstream claims remain UNKNOWN unless separately tested | final upgrade target |

The v1.0.1 release did not itself claim PASS-TRACKED, and the current release still does not. It provides the audit protocol and certifier that a Claude Code runtime environment can use to determine whether a future external evidence bundle justifies promotion from PASS-SCOPED to PASS-TRACKED.


## GitHub README documentation audit

The release includes a documentation-only README tree under `docs/` plus `self_validation/README.md`. The validator requires this GitHub documentation set, checks that it covers quickstart, audit model, evidence, PASS-TRACKED upgrade, runtime trace authentication, security, development, release, FAQ, and repository presentation topics, and rejects degraded or missing documentation. The documentation tree is treated as stable package content without adding plugin-loadable runtime surfaces.


## v1.0.3 addendum (updated 2026-07-18)

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
| Validator: CI semantic reachability | Required workflow commands count only when they are direct top-level commands in active named `run:` blocks. Statically false job conditions, conditional steps, comments, heredocs, functions, loops, conditionals, case statements, and shell grouping cannot satisfy checkout/archive policy. Dedicated false worlds disable the entire job, hide both exact aggregate commands inside `if false`, and place the required archive self-test only in a comment or uncalled function. A true-world parser control retains one direct archive self-test while ignoring both decoys |
| Validator: historical-version adherence | The two context-free bare-version patterns were removed because they rejected legitimate history and were future-brittle. Context-bearing stale package/work/artifact markers and the field-aware self-certificate/plugin version equality check remain; explicit historical prose for both prior versions is a retained true world |
| Validator: cert-version check (kept) | Critical field-aware check that the active self-certificate `artifact.version` equals plugin.json's version (the real fix for the version-provenance issue); its false-world mutation is retained |
| CI: archive validation | The deterministic workflow creates a Git archive, unpacks it, runs the full validator `--self-test` with Markdown outside that Git-free tree, and only then runs the archive promotion aggregate. The exact workflow model and reachability checks require that order. Hosted execution is snapshot-bound external evidence recorded by GitHub checks; this source-level audit does not self-attest the status of a future merge snapshot |
| CI: immutable action identity | The allowlisted workflow pins `actions/checkout` to `34e114876b0b11c390a56381ad16ebd13914f8d5` and `actions/setup-python` to `a26af69be951a213d495a4c3e4e4022e16d87065`. The restricted workflow model requires those exact identities, and dedicated false worlds reject reverting either dependency to a mutable major-version tag |
| Semantic evidence contracts | Charter observed behavior uses citation-only prose rather than volatile digest echoes. Consistency records require unique canonical `affected_claim_ids`, unique `locations`/`edited_locations`, classification/resolution pairings, recommended edits, and resolution-conditional evidence; these remain parent/auditor-enforced and are not mechanically checked by `ntt_gate.py` or the formal runner (issue #5 deferred) |
| Runtime evidence provenance | New harness runs require zero-returning version/plugin preflight, fingerprint the resolved executable, and accept only one canonical successful SDK ResultMessage with nonempty `result` and fail-closed official controls. Provenance schema is `2.0`, carries `evidence_origin`, and identity explicitly says `observed-not-cryptographically-authenticated`; no official-binary proof is claimed. Legacy checked-in summaries retain unknown producing-run release/time/identity with null `carried_forward` and remain `UNVERIFIED_RUNTIME` |
| Boundary-aware display normalization | Validator, gate, regression, and live harness normalize an exact package root or rooted child path while preserving adjacent lookalikes such as `/tmp/root-old` |
| Reproducible manifest epoch / Issue #8 semantics | `STABLE_RELEASE_MANIFEST.json.generated_utc` is fixed at deterministic epoch `2026-05-26T00:00:00Z`; exact `generated_utc_kind=reproducible-build-epoch`, value, and non-wall-clock semantics are validated with no caller override. This resolves the v1.0.3 generated-time ambiguity for package semantics without claiming that the remote Issue #8 is closed |
| Slice F: exact executable identity | `shutil.which("claude")` is consumed once; its absolute regular target is fingerprinted and used for every version, plugin, and fixture subprocess. A relative-PATH/two-cwd false world proves the alternate fixture-cwd binary is never executed. Equal pre/post hashes and `fingerprint_stable=true` are required before PASS-SCOPED |
| Slice F: current transcript-backed live promotion | The certifier requires schema `2.0` current-run provenance with `evidence_origin`, exact current release, non-carried timestamped evidence, successful preflight, stable fingerprints, and the exact current `evals.json` fixture IDs once each. Every bundle-local transcript stdout is replayed through the canonical SDK ResultMessage checker and must exactly match self-reported checks |
| Promotion v2: fresh deterministic and official execution | `deterministic-capture-v2` records are non-authorizing and are compared through exact typed suite projections against fresh fixed-argv executions. Claude uses exact ordered strict argv and accepts the real ANSI-normalized `✔ Validation passed` form only when neither complete stream contradicts it. Full captured bytes determine decisions, hashes, and byte counts; public excerpts carry explicit truncation metadata. Text captures do not authorize; absent tools scope only through the explicit flag while both official-policy nodes and their dependencies remain present; installed failures fail |
| Promotion v2: typed evidence DAG | Exact-string `promotion_schema_version="2.0"` and exact required top-level field types are enforced. `evidence.schema_version=promotion-evidence-v2` replaces flat promotion refs. The fixed nine semantic roles bind distinct canonical regular non-symlink bundle files by exact bytes and SHA-256, carry one environment-independent bounded acyclic dependency graph, receive role-specific validation, and require explicit `downstream_review` |
| Promotion v2: canonical claims/downstream review | `claims` is nonempty; every entry has exact required types, nonempty scope, claim-contract `1.1`, complete modal world contracts, and a unique canonical ID; it is evaluated through the canonical strict gate at the bundle evidence root and must produce a nonempty all-PASS result set before the actual results enter promotion-v2 downstream non-closure evaluation. Empty downstream conclusions remain valid only with a real passing promotion claim, performed review, and substantive reason |
| Formal result 2.0 | Promotion follows only the typed `formal.result` locator. The result binds the standalone endpoint-checked target copy, exact report/gate/certificate/ledger/complete-transcript/prompt/target-copy manifest, package-tree identity, run identity, and target pre/post endpoint identity. Permission hardening is not temporal immutability, so that declared limitation caps an otherwise `PASS-TRACKED` formal result at `PASS-SCOPED`. Execution requires supported Linux child-subreaper plus process-group containment before `Popen`; same-group and detached-session descendants must be killed and reaped with no survivor and complete cleanup, while unavailable containment refuses execution. Complete transcript bytes are written, hashed, and authenticated; capture-limit excess fails closed and tail-only authentication is forbidden. No basename/glob-first selection is allowed; unrelated nonreserved files may remain |
| Structured promotion failures | Malformed, duplicate, invalid, or empty claims and other malformed bundle data return canonical `FAIL` plus `failure_kind` (`INVALID_INPUT`, `CHECK_FAILED`, or `INTERNAL_ERROR`) rather than an unhandled traceback |
| Held caller-output capabilities | Gate Markdown, certifier JSON/Markdown, formal output/compatibility JSON, live transcript/optional JSON, validator Markdown, deterministic wrapper JSON, and fixed behavior/stable-release manifest parents are acquired component-by-component before long-running work and held through descriptor-relative installation and fsync. Role/alias classification is frozen against held identities; ancestor substitution cannot redirect writes; validator Markdown remains external. These checks are not temporal isolation. Formal children additionally receive only authenticated runner-owned `/proc/<runner-pid>/fd/N` via `pass_fds`; child-FD close/rebind and invalid capability forms fail, while missing procfd support is `INVALID_INPUT` before requested formal output mutation |
| v1.0.3 promotion and formal caps | Every complete modeled result is `PASS-SCOPED` / `CAPPED`, `promotion_authorized=false`, `satisfied_profile=promotion-contract-v2-complete`, records both exact unresolved Issue #5 obligations, and exits nonzero. Generic `ntt_gate.py` `PASS-TRACKED` semantics remain unchanged. The formal runner independently caps an otherwise `PASS-TRACKED` result at `PASS-SCOPED` for the declared temporal-immutability limit; required process containment is a fail-before-execution prerequisite rather than another scope relaxation |
| Aggregate promotion contract | The dedicated synthetic suite expects 46/46 and invokes the production certifier CLI for the complete baseline and every negative. It covers exact strict-validator argv/real output, complete-stream early failures, fixed-DAG retention under explicit unavailable-validator scope, canonical positive downstream evaluation, malformed/empty claims, coordinator identity substitution, safe output paths, exact ordered Issue #5 obligations, and complete formal transcript binding. It is contract evidence, not real runtime authentication |
| Slice F: path boundaries | Validator, gate, regression, and live normalization retain `root@sibling`, `root old`, Unicode suffixes, and `root-old`, while still normalizing root and rooted child paths |
| Slice G: one-to-one live binding | Every live fixture records the exact canonical normalized-display prompt SHA-256 and exact written transcript JSON byte SHA-256. Promotion requires distinct canonical transcript paths, regular non-symlink files, exact transcript bytes, and transcript-command prompt text/hash binding to the exact current fixture ID plus expected artifact before independent stdout replay |
| Slice G: independent inventory policy | `package_tree_sha256` loads the current regular `validate_package.py`, executes `iter_release_inventory_files`, and requires manifest inventory paths plus volatile file/prefix exclusions to equal the current executable policy exactly. Manifest-authored exclusions cannot remove a behavior or stable file |
| Slice G: unconditional fresh validation | Every promotion attempt reruns the current basic package validator and treats failure as critical. `--run-fresh-package-validator` remains accepted only for compatibility and cannot disable or newly enable the check |
| Slice H: live bytes bind current package | `validate_package.compute_stable_release_tree` is the single `ntt-stable-release-tree-v2` implementation used by live capture and certification. Its canonical inventory binds path, byte count, content digest, and Git-compatible executable mode. Live results also hash exact `evals.json` and artifact bytes; certification recomputes each binding, so refreshed manifests cannot rescue stale live evidence after a package, fixture-spec, artifact, or non-artifact behavior-source change |
| Slice H: exact normalized argv | Live results record `run_config.max_turns`; certification requires exactly two ordered preflight argv arrays and each exact ordered fixture argv array with plugin directory, print mode, JSON output, recorded max turns, and canonical prompt. Prompt-only, missing, extra, reordered, wrong-format, wrong-turn, and wrong-preflight argv fail independently of prompt/report replay |
| Slice I: exact return-code type | Every certifier success check now requires exact integer zero (`type(value) is int and value == 0`), including official JSON validators, the unconditional fresh validator, live preflight commands and aggregate summary, fixture summaries, and transcript/result agreement. Focused false worlds reject `false`, `true`, `0.0`, `"0"`, and `null`; integer `0` remains valid |
| Slice I: contradictory text counts | Official text validation rejects anchored nonzero numeric `error`/`errors`/`failure`/`failures`/`failed` summaries before positive markers, case-insensitively and with punctuation. Focused controls reject pass-plus-nonzero contradictions, retain pass-plus-zero summaries, and preserve the `invalid`/`valid` boundary |
| Slice J: physical cruft and observational Git evidence | Every physical cruft entry is rejected from the initial snapshot before module activation in both Git and Git-free packages; only `.git` metadata is exempt. Sanitized bounded Git index/HEAD stage, mode, and cruft results are additive rejection evidence only: their absence never authorizes bytes or proves `HEAD`/archive equivalence. The exact historical `skills/nozickian-verify/scripts/__pycache__/ntt_gate.cpython-312.pyc` case remains a rejection, and ignored untracked bytecode is now rejected rather than retained. The required unpacked `git archive HEAD` full self-test is the committed-archive control. |
| Ultra-review: evidence substitution resistance | Every strict wrapper binds claim-contract `1.1`: the full local claim state plus certificate method, limitations/unknowns, thresholds, full downstream-policy object/records/review, and a digest inventory of every claim. Modal wrappers bind `outcome` and `observed_outcome` separately plus the complete schema-`1.1` world; authorization uses closed typed fields, never prose polarity. Under package-self, the certificate-wide modal ID multiset must equal all 80 immutable reviewed transitions exactly once, with pinned claim/kind assignment and complete payload. These identities are release declarations, not execution provenance |
| Ultra-review: strict result and method contracts | Live and formal envelopes require one canonical successful SDK ResultMessage with nonempty `result`; `content`/`output`, permission denials, non-null `api_error_status`, `deferred_tool_use`, or non-structured `structured_output`, non-completed `terminal_reason`, non-end-turn `stop_reason`, nested contradictory controls, and suffixed rejecting declarations fail closed. The one terminal record follows every lane and is final. Promotion cross-binds live provenance schema `2.0` and formal `evidence_origin`, reconstructs `promotion-method-m-v2`, rejects extra aliases, and preserves the independent nonauthorization cap |
| Ultra-review: bounded package capability snapshot | Validation authorizes from one immutable initial bounded no-follow snapshot containing captured regular-file bytes. Package reads and every self-test fixture consume or materialize only captured bytes, not a later lexical source/mirror path; finalization independently revalidates the held source and private mirror. Package traversal enforces separate path/metadata and aggregate-file budgets plus directory, entry, depth, and per-file ceilings and rejects non-private regular files. Git discovery/index capture is independently time-, byte-, and entry-bounded; transient import/frontmatter/fixture A→B→A substitution cannot influence a passing result |
| Ultra-review: bounded gate and trace inputs | Strict evidence reads, correction-locator excerpts, package walks and snapshots, JSON depth/node/string counts, trace records, node positions, public excerpts, subprocess output, and join time are all bounded. Package traversal has per-directory, total-entry, depth, per-file, and aggregate-byte ceilings; Git-compatible modes use owner-execute semantics. Trace order is total rather than line-local. Before execution, capture requires supported Linux child-subreaper setup plus original-process-group tracking; after normal leader exit, timeout, or overflow it kills and reaps adopted same-group and detached-session descendants to a bounded quiet state. Unavailable containment refuses execution, and any survivor or incomplete cleanup fails closed |
| Ultra-review: endpoint-checked execution identity | Formal and live runs preserve independent permission-hardened package/target copies and bind pre/post source, copy, and no-follow endpoint identity plus the exact resolved executable entrypoint identity. They explicitly record `temporal_immutability_enforced=false`: same-UID A→B→A mutation between observations is not mechanically excluded. This also does not attest the transitive interpreter, shared-library, kernel, or host closure |
| Ultra-review: held output capabilities | Gate Markdown, certifier JSON/Markdown, formal output/compatibility JSON, live transcript/optional JSON, validator Markdown, gate/formal/regression/promotion wrapper JSON, and fixed-manifest parents are acquired component-by-component before long-running work and retained through descriptor-relative installation. Formal canonical classification and cross-output alias decisions are frozen against held identities. Ancestor replacement cannot redirect writes; validator Markdown must remain external. Observed drift fails closed, but these checks are not temporal isolation |
| Ultra-review: literal release replay | Release idempotence now snapshots the complete no-follow package entry graph, including modes, empty directories, hardlinks, and timestamps, around the actual outer self-test and two literal deterministic CLI passes. Validator Markdown uses a held external parent and rechecks identity plus package ancestry around installation |
| Ultra-review: current evidence inventory | The active certificate contains seven proposition-bound claims and one closed-schema current release-declaration ledger. Its records are case-bound deduplication identities, not execution provenance, and no per-record suite reconciliation is claimed. Stale v1.0.1/v1.0.2 probe ledgers, redundant text mirrors, and orphaned wrapper inventories were removed; official validators remain explicitly `NOT_EXECUTED` in this environment |

### Consistency sweep for this release (dogfood record)

The final sweep covers assurance-bound claim-contract `1.1`, complete world-contract `1.1`, separate observed-outcome hashing, exact-once package-self registry membership, observation identity, downstream proposition binding, canonical SDK ResultMessage controls, provenance/evidence-origin `2.0`, promotion-method-m-v2, bounded parsing and capture, required Linux child-subreaper/process-group containment of same-group and detached-session descendants, fail-before-execution behavior when containment is unavailable, endpoint-checked permission-hardened package/target copies with temporal immutability explicitly unenforced, immutable captured-byte package authorization and fixture materialization, independent source/mirror finalization, executable-entrypoint identity, pre-acquired held output capabilities for every long-running release CLI, frozen formal/alias classification, live JSON/transcript non-aliasing, validator Markdown's external-parent check, runner-owned procfd output capabilities resilient to child-FD close/rebind and lexical ancestor substitution, literal release-command replay, current charter wording, single-document stdout, and regenerated release evidence. Every active correction locator in `self_validation/self_certificate.json` must be rechecked against its semantic target after the current regeneration. Historical counts above this addendum remain explicitly historical; they are not current-release evidence.

### Final v1.0.3 self-test and gate record

| Command | Result |
|---|---|
| checked-in `validate_package.py . --self-test` | PASS - 2017/2017 checks, 0 critical or noncritical failures, 83/83 false-world mutations rejected through ordinary completed failures, 12/12 true-world variants retained, and two literal release passes with zero changed files; raw stdout parses directly as one JSON document |
| checked-in basic `validate_package.py .` | PASS - 1827/1827 checks, 0 critical or noncritical failures; raw stdout parses directly as one JSON document |
| checked-in `ntt_gate.py self_validation/self_certificate.json --evidence-root . --strict-evidence --downstream-policy package-self` | PASS-SCOPED - 0 critical, 0 major, 7 claims, 3 derived/downstream non-closure records, strict local evidence and reviewed package transition registry verified |
| `run_gate_contract_tests.py` | 232/232 contract cases PASS |
| `run_formal_runner_contract_tests.py` | 231/231 contract cases PASS |
| `run_regression_evals.py .` | 166/166 checks PASS |
| optional official validators | `claude plugin validate . --strict` and `skills-ref validate skills/nozickian-verify` were not installed and were not executed; no official-validator pass is claimed |
| mode-aware package-surface checks | PASS - clean Git-free export retained; every physical cruft entry, including ignored untracked bytecode, is rejected before module activation; sanitized Git index/HEAD stage, mode, and cruft evidence is additive rejection evidence only. Exported/direct force-tracked/exact historical nested bytecode, untracked non-bytecode cruft, Git-evidence failure, tracked/Git-free/untracked symlinks, untracked/Git-free FIFOs, nonzero stages, and index-only gitlink mode 160000 are rejected before later reads. Absence of an observational Git finding does not prove `HEAD`/archive equivalence; the required unpacked archive self-test supplies that control. |
| safe manifest writes | PASS - symlinked MANIFEST update failed before write; external sentinel bytes and source checkout stayed unchanged; atomic fixed-path writer replaced the link without following its target |
| isolated checkout fixtures | PASS - disposable top level/index resolved inside the copy; source status and index hash remained unchanged; source status used `GIT_OPTIONAL_LOCKS=0` and before/after index hashes matched |
| allowlist and plugin-field parity | PASS - all declared unique-string sets exactly equal executable policy order-insensitively; omitted, contradictory, unknown-key, drift, and undeclared opaque `experimental` mutations rejected |
| context-bearing provenance hygiene | PASS - exact current-root leakage, active stale markers, and non-UTF-8 provenance rejected as named failures; full prior package/work-root text retained only behind the exact `Historical provenance reference:` line marker |
| mutation harness integrity | PASS - validator exceptions classify as `HARNESS_ERROR`; only completed FAIL/critical results count as false-world rejection, and true worlds require completed PASS |
| live harness contracts | PASS (offline controls) - valid structured report accepted; recursive metadata echo and non-object JSON rejected; fixed fake CLI plugin-preflight failure returned normal FAIL without fixture execution. No real Claude runtime was invoked |
| producer display normalization | PASS - validator, gate, regression, and live-harness serialized displays normalize exact roots/rooted children and preserve adjacent prefix lookalikes |
| exact live executable controls | PASS (offline controls) - relative-PATH candidates under distinct producer/fixture working directories executed only the fingerprinted absolute target for all five version/plugin/fixture calls; pre/post fingerprint remained stable; no resolved executable path was bundled |
| promotion aggregate contracts | PASS - 46/46 synthetic cases invoked the production certifier CLI for the complete baseline and all negatives; the complete modeled baseline passed 252/252 checks. Both coordinator result/argv identity substitutions returned the exact `INVALID_INPUT` oracle. The suite retained the fixed role DAG, evaluated a real promotion claim, recorded both ordered Issue #5 obligations, and returned the mandatory `PASS-SCOPED` / `CAPPED` non-authorizing result. JSON and stdout were byte-identical; a raw result digest is intentionally not presented as stable-tree evidence because valid runs retain elapsed-time telemetry. This remains synthetic contract evidence, not runtime authentication |
| shared package-tree implementation | PASS - live capture and certification both invoke `validate_package.compute_stable_release_tree`; no second `ntt-stable-release-tree-v2` algorithm body remains |
| promotion package/formal false worlds | PASS - missing/wrong-type promotion schema, wrong-tree deterministic capture, wrong strict-validator argv, realistic ANSI success plus complete-stream contradictions, decoy/swapped formal companions, an untyped existing DAG node, malformed/empty claim arrays, duplicate/invalid IDs, failed canonical claims, unsafe output targets/ancestors, a transcript with an early disallowed event before a large valid-looking tail, missing formal trace-authentication metadata, noncanonical paths, graph bounds, and target/package identity defects failed their exact named checks without unrelated failures |
| independent inventory derivation | PASS - 152 stable manifest paths exactly matched the current validator policy; volatile file/prefix arrays exactly matched current constants; every derived path was regular/non-symlink with matching hash and byte count |
| unconditional fresh package validation | PASS - omission of the compatibility flag still ran the current basic validator; the fixed stale-package false world returned FAIL with one critical failure |
| official-validator controls | PASS - allowlisted validators execute fresh; prewritten text cannot authorize; absent tools scope only through the explicit flag while both official policy nodes and the canonical DAG remain intact; installed failures fail. Exact integer zero is required and structured/plain/JSONL negative status on either stream dominates positive output |
| certifier no-follow controls | PASS - fixed symlink/FIFO inputs were recorded as critical failures, external sentinel content was not consumed, and plugin.json symlink/FIFO cases failed cleanly |
| reproducible manifest epoch | PASS - exact deterministic epoch, `generated_utc_kind`, and explicit non-wall-clock semantics validated |
| self-certificate artifact-version equality check | PASS - certificate=1.0.3 plugin=1.0.3 |
| unpacked Git archive workflow | CONFIGURED - CI archives, unpacks, and validates the Git-free package; hosted execution status is recorded by the per-snapshot GitHub check rather than embedded as a mutable current-status claim in this local record |
| consistency-sweep record contract | PASS - the final certificate records schema/DAG/formal-tree/provenance/obligation/Issue-8, CI reachability, documentation/template/cap-wording, stdout-containment, and regenerated-output corrections; an iterative post-serialization resolver verified every current locator against its semantic target |

Counts in this table come from the checked-in final release-evidence fixed point. `MANIFEST.sha256`, `STABLE_RELEASE_MANIFEST.json`, the current observation ledger, and structured evidence hashes were regenerated together and checked by literal release replay. The release remains **PASS-SCOPED**: no live official Claude Code fixture trace was captured, both optional official validators were unavailable, and the v1.0.3 certifier cannot discharge the two Issue #5 charter obligations. Live runtime stays `UNVERIFIED_RUNTIME`; the synthetic aggregate does not change that.


## Durable lessons ledger — PR #3 ultra-review (2026-07-15)

This is the canonical PR-visible mirror of the local orchestration ledger. It records reusable invariants separately from immutable release identifiers. Snapshot facts are superseded after any edit and must be re-proven before publication.

<!-- BEGIN PR3 DURABLE LESSONS v1 -->

## Ledger policy

- DATE records when the lesson was promoted.
- DURABILITY is PERMANENT for cross-project invariants, PROJECT for repository-specific policy, or RELEASE for immutable snapshot facts.
- A lesson is promoted only after at least two independent observations or an explicit DURABILITY decision. Every entry below is explicitly promoted by the user’s durability request and supported by implementation evidence plus independent review or hosted execution.
- ISSUE describes the demonstrated failure class; RESOLUTION states the invariant; RECURRENCE states when to reapply it; APPLIES TO limits scope; LAST VERIFIED and SOURCE identify evidence.
- COUNTEREXAMPLE names the nearby false world; RETENTION TEST names the adherence or fixed-point check; RESIDUAL prevents overclaiming; OWNER / FOLLOW-UP assigns continued custody.
- A newer record supersedes a snapshot identifier only by naming the prior identifier and proving the new immutable state. Historical identifiers and counts remain historical rather than silently becoming current.

### L-PR3-001 — Receive review findings as hypotheses

- DATE: 2026-07-15
- DURABILITY: PERMANENT
- ISSUE: Blind agreement, bulk speculative edits, or dismissing feedback without reproduction can add regressions or leave real defects unresolved.
- RESOLUTION: Read the whole finding, translate it into a concrete invariant, inspect current head, reproduce or falsify it, evaluate repository-wide consequences, repair one coherent lane, and run the focused regression before calling it resolved.
- RECURRENCE: Apply to every human, bot, or subagent review round.
- APPLIES TO: Pull-request review, audit remediation, and feedback integration.
- LAST VERIFIED: 2026-07-15; every accepted PR #3 finding received a focused test and independent cross-review.
- SOURCE: PR #3 remediation record; focused gate, formal, promotion, and validator suites.
- COUNTEREXAMPLE: A plausible review comment is implemented despite already being fixed or being false on current head.
- RETENTION TEST: Reproduce the alleged failure before editing and rerun the named regression after editing.
- RESIDUAL: A passing focused test does not establish global correctness.
- OWNER / FOLLOW-UP: Parent integrator; preserve the receiving-code-review sequence in future rounds.
- PROMOTION RATIONALE: Explicit user requirement plus repeated successful use across independent repair lanes.

### L-PR3-002 — Partition agents by trust and verification boundary

- DATE: 2026-07-15
- DURABILITY: PERMANENT
- ISSUE: One broad reviewer can conflate layers, miss correlated defects, or validate its own assumptions.
- RESOLUTION: Assign bounded lanes for gate/evidence semantics, formal/runtime handling, validator/release behavior, documentation/inventory, and adversarial review. The parent owns integration; independent read-only agents cross-review the integrated fixed point.
- RECURRENCE: Use specialized first-pass lanes and at least one cross-lane adversarial pass for high-assurance work.
- APPLIES TO: Ultra-reviews, formal-verification packages, and security-sensitive CI/certification.
- LAST VERIFIED: 2026-07-15; a final holistic audit plus lane-specific independent cross-reviews found no blocker within the reviewed scope.
- SOURCE: Conversation orchestration record; self-certificate human_review fields; final pushed-commit audit.
- COUNTEREXAMPLE: Sibling agents assume another lane checked an integration seam.
- RETENTION TEST: Final parent-owned diff audit plus an independent pushed-state audit.
- RESIDUAL: More agents do not create proof; correlated assumptions remain possible.
- OWNER / FOLLOW-UP: Parent integrator; explicitly record lane scope, handoffs, and unresolved seams.
- PROMOTION RATIONALE: Multiple independent observations and the user’s standing preference for layered orchestration.

### L-PR3-003 — Separate claim, method, oracle, neighborhood, execution, and runtime identity

- DATE: 2026-07-15
- DURABILITY: PERMANENT
- ISSUE: Byte identity or a passing run can be mistaken for truth, source authority, freshness, neighborhood adequacy, official provenance, or method-relative tracking.
- RESOLUTION: Record the exact proposition p; method M with versions, argv, configuration, parser, and approvals; truth-oracle assumptions; nearby false and true worlds; this execution; package/target snapshots; and runtime entrypoint identity as distinct objects.
- RECURRENCE: Reconstruct these dimensions whenever a claim, tool, oracle, prompt, parser, fixture neighborhood, or runtime changes.
- APPLIES TO: All Nozickian certificates and promotion claims.
- LAST VERIFIED: 2026-07-15; seven proposition-bound claims, explicit method/evidence records, modal bindings, and scoped runtime identity.
- SOURCE: skills/nozickian-verify/references/STANDARD.md; EVIDENCE_SCHEMA.md; self_validation/self_certificate.json.
- COUNTEREXAMPLE: “The file hash matched, therefore the claim is true and current.”
- RETENTION TEST: Require distinct fields and evidence for each dimension and preserve explicit residuals.
- RESIDUAL: No finite neighborhood proves global sensitivity or oracle adequacy.
- OWNER / FOLLOW-UP: Claim owner and parent adjudicator; revisit whenever M or the oracle changes.
- PROMOTION RATIONALE: Core method-relative truth-tracking invariant observed across the package’s entire evolution.

### L-PR3-004 — Bind evidence to the exact proposition

- DATE: 2026-07-15
- DURABILITY: PERMANENT
- ISSUE: Artifact hashes alone could remain byte-valid after the supported claim text was substituted.
- RESOLUTION: Canonicalize claim text, hash the canonical UTF-8 bytes, and require certificate proposition_sha256 plus every wrapper claim_proposition_sha256 to match.
- RECURRENCE: Recompute all proposition bindings after any claim wording change, including editorial-looking changes.
- APPLIES TO: Strict gates, promotion claims, self-certificates, and evidence migrations.
- LAST VERIFIED: 2026-07-18; gate contracts 232/232 and strict gate PASS-SCOPED.
- SOURCE: skills/nozickian-verify/references/EVIDENCE_SCHEMA.md; scripts/ntt_gate.py; run_gate_contract_tests.py.
- COUNTEREXAMPLE: Coordinated certificate-text substitution with unchanged evidence bytes.
- RETENTION TEST: Proposition-substitution false worlds.
- RESIDUAL: A proposition digest binds text, not truth.
- OWNER / FOLLOW-UP: Evidence producer and gate maintainer; version canonicalization deliberately.
- PROMOTION RATIONALE: Closes a demonstrated general substitution class.

### L-PR3-005 — Bind modal evidence to the exact nearby world and release declaration

- DATE: 2026-07-15
- DURABILITY: PERMANENT
- ISSUE: A wrapper could name one test while supporting another perturbation, outcome, or release declaration, and multiple wrappers over one aggregate artifact could masquerade as distinct threshold identities.
- RESOLUTION: Bind the canonical proposition, assurance-bound claim digest, kind, test ID, target claims, variation, complete world-contract `1.1`, expected and observed behavior, declared result text, separately hashed `outcome` and `observed_outcome`, and result in `modal_case_sha256`. Authorization uses the closed operator/target/outcome fields, never prose polarity. Under package-self, require the certificate-wide ID multiset to equal all 80 immutable reviewed transitions exactly once. Require an exact `observation_id` match in the versioned current ledger; otherwise deduplicate by underlying artifact bytes. The ledger does not authenticate execution or reconcile a suite result per record.
- RECURRENCE: Regenerate the digest and declaration record after any case edit; never count filenames as independent executions.
- APPLIES TO: False-world sensitivity, true-world adherence, and modal thresholds.
- LAST VERIFIED: 2026-07-18; 83/83 false worlds rejected through ordinary completed failures and 12/12 nearby true worlds retained.
- SOURCE: self_validation/current_observations.json; modal wrappers; gate contracts.
- COUNTEREXAMPLE: Reuse one declaration record for multiple different modal cases.
- RETENTION TEST: Modal-substitution and shared-ledger true-world cases.
- RESIDUAL: Passing chosen worlds does not prove neighborhood completeness.
- OWNER / FOLLOW-UP: Evidence producer and reviewer; justify neighborhood selection.
- PROMOTION RATIONALE: Core Nozickian case-to-observation identity rule.

### L-PR3-006 — Treat local evidence as bounded, no-follow, byte-backed input

- DATE: 2026-07-15
- DURABILITY: PERMANENT
- ISSUE: Traversal, schemes, symlinks, special files, inode swaps, oversized/deep JSON, hardlinks, aliases, and byte-identical copies could escape the root, exhaust resources, or inflate sufficiency.
- RESOLUTION: Require canonical relative POSIX paths; reject schemes, traversal, links, special files, aliases, and unsafe hardlinks; use bounded no-follow descriptor reads with pre/post identity checks; cap bytes, depth, nodes, records, fields, and strings; deduplicate wrapper and artifact bytes.
- RECURRENCE: Apply before every untrusted read and test both path aliases and byte-copy aliases.
- APPLIES TO: Gate evidence, observation ledgers, promotion bundles, formal companions, and validator fixtures.
- LAST VERIFIED: 2026-07-15; resource-bound, path-control, strict-root, and alias probes passed.
- SOURCE: scripts/ntt_gate.py; certify_pass_tracked_upgrade.py; gate and promotion contracts.
- COUNTEREXAMPLE: Strict evidence without a root, a path escape, a symlink, or two copied wrappers counted twice.
- RETENTION TEST: INVALID_INPUT for missing strict root and ordinary named failures for unsafe evidence.
- RESIDUAL: Bounds can reject unusually large legitimate inputs and must be documented.
- OWNER / FOLLOW-UP: Parser and filesystem-boundary maintainers; review limits when formats evolve.
- PROMOTION RATIONALE: Reusable security and availability invariant.

### L-PR3-007 — Never transmit epistemic status automatically downstream

- DATE: 2026-07-15
- DURABILITY: PERMANENT
- ISSUE: A passing source claim p could improperly promote an entailed, summarized, deployment, safety, compliance, or action-authorizing claim q.
- RESOLUTION: A passing downstream record must point to a distinct independently passing claim with its own proposition binding, method, evidence, nearby worlds, and residuals. Untested q remains reasoned UNKNOWN; p cannot verify itself downstream.
- RECURRENCE: Enumerate downstream conclusions after every source-claim pass.
- APPLIES TO: Generic gate, promotion certifier, reports, and deployment decisions.
- LAST VERIFIED: 2026-07-15; three downstream records and zero closure violations.
- SOURCE: EVIDENCE_SCHEMA.md; STANDARD.md; ntt_gate.py; promotion auto-closure contract.
- COUNTEREXAMPLE: Green CI or a passing package claim is reported as proof of safe deployment.
- RETENTION TEST: Downstream auto-closure false worlds and independent-claim checks.
- RESIDUAL: Explicit downstream records can still be semantically inadequate.
- OWNER / FOLLOW-UP: Parent adjudicator; require independent claim admission for q.
- PROMOTION RATIONALE: The project’s enduring no-automatic-epistemic-closure rule.

### L-PR3-008 — Authenticate structured runtime events, not tool-like text

- DATE: 2026-07-15
- DURABILITY: PERMANENT
- ISSUE: Nested tool-shaped payloads, text masquerades, role inversion, duplicate IDs, result-before-call order, malformed JSONL, and valid-looking tails could falsely authenticate execution.
- RESOLUTION: Parse only recognized event positions; treat tool nodes as hard boundaries; require assistant-origin tool use, a matching later user-origin substantive result, exact unique IDs and native selectors, no unexpected lanes, total line/node ordering, bounded per-record structure, and complete-transcript authentication.
- RECURRENCE: Add a false-world trace for every newly accepted event shape or parser relaxation.
- APPLIES TO: Formal runner, live trace authentication, and PASS-TRACKED evidence.
- LAST VERIFIED: 2026-07-18; formal contracts 231/231.
- SOURCE: docs/runtime-trace-auth/README.md; run_formal_artifact_verification.py; run_formal_runner_contract_tests.py.
- COUNTEREXAMPLE: An early disallowed event is hidden before a large valid-looking tail.
- RETENTION TEST: Malformed JSONL, descendant ordering, masquerade, mismatched-ID, and tail cases.
- RESIDUAL: Structural authentication does not prove semantic quality of a tool result.
- OWNER / FOLLOW-UP: Formal-runner maintainer; keep accepted event grammar explicit.
- PROMOTION RATIONALE: Prevents a broad demonstrated transcript-spoofing family.

### L-PR3-009 — Bound subprocess capture and state the process-containment boundary

- DATE: 2026-07-15
- DURABILITY: PERMANENT
- ISSUE: Sequential reads could deadlock, descendants could retain output pipes, capture could grow without bound, and tail-only handling could discard an early failure.
- RESOLUTION: Drain stdout and stderr concurrently under explicit ceilings; decide and hash from complete retained bytes. Before execution, require supported Linux `PR_SET_CHILD_SUBREAPER` plus process-group and bounded `/proc` adopted-child tracking. On normal leader exit, timeout, or overflow, kill and reap original-group and detached-session descendants to a bounded quiet state, close pipes, and use bounded joins. Refuse execution when containment cannot be established, and fail closed on any survivor or incomplete cleanup.
- RECURRENCE: Use this wrapper for every verifier or runtime subprocess.
- APPLIES TO: Live fixtures, formal runs, official validators, and promotion certification.
- LAST VERIFIED: 2026-07-15; current fixed-point evidence must include normal-exit closed-stdio survivor, detached-session adoption/kill/reap, and unavailable-containment fail-before-execution cases.
- SOURCE: run_live_skill_evals.py; run_formal_artifact_verification.py; certify_pass_tracked_upgrade.py.
- COUNTEREXAMPLE: A parent exits successfully after a child closes inherited stdio; without normal-exit cleanup the child survives and mutates state later. A child that calls `setsid()` escapes the original group unless a child subreaper adopts, enumerates, kills, and reaps it.
- RETENTION TEST: Inherited-pipe, closed-stdio normal-exit survivor, detached-session adoption/kill/reap, unavailable-containment, timeout, oversized-output, and early-failure/valid-tail probes.
- RESIDUAL: The containment mechanism depends on Linux `prctl` and `/proc`; unsupported platforms or runtimes refuse execution rather than claim a narrower successful run.
- OWNER / FOLLOW-UP: Runtime/process owner; specify platform behavior before porting.
- PROMOTION RATIONALE: General process-safety and evidence-integrity rule.

### L-PR3-010 — Use endpoint-checked copies and state runtime identity narrowly

- DATE: 2026-07-15
- DURABILITY: PERMANENT
- ISSUE: Mutable package/target bytes, same-UID A→B→A replacement, and ambient PATH resolution could let executed content differ from certified content.
- RESOLUTION: Materialize independent permission-hardened package and target copies, bind source/copy/no-follow endpoint identities, and verify pre/post endpoint stability without calling that temporal immutability. Record `temporal_immutability_enforced=false` and cap an otherwise `PASS-TRACKED` formal result at `PASS-SCOPED`. Resolve one absolute regular non-symlink executable entrypoint, fingerprint it before and after, and use that exact path for every invocation.
- RECURRENCE: Re-copy after behavior changes, fail on observed endpoint or entrypoint drift, and preserve the formal cap until a real isolation boundary prevents same-UID intermediate mutation.
- APPLIES TO: Live fixtures, formal artifact runs, and promotion bundles.
- LAST VERIFIED: 2026-07-15; current fixed-point evidence must include same-UID A→B→A and truthful-cap contracts.
- SOURCE: run_live_skill_evals.py; run_formal_artifact_verification.py; docs/release/README.md.
- COUNTEREXAMPLE: The coordinator chmods a `0400` copy, changes A→B→A, and restores its mode between the two endpoint observations.
- RETENTION TEST: Same-UID A→B→A, truthful temporal-cap, two-cwd PATH, and pre/post endpoint-identity checks.
- RESIDUAL: Endpoint equality does not prove temporal immutability; entrypoint fingerprinting does not attest the transitive interpreter, libraries, kernel, host, or official provenance.
- OWNER / FOLLOW-UP: Runtime evidence owner; expand the identity boundary only with explicit new evidence.
- PROMOTION RATIONALE: Binds what ran while keeping the assurance boundary honest.

### L-PR3-011 — Secure caller-controlled output destinations

- DATE: 2026-07-15
- DURABILITY: PERMANENT
- ISSUE: A caller-controlled output parent could be validated and then reopened after long-running work, allowing a same-UID ancestor substitution to redirect the eventual write; final entries could also traverse links, overwrite external sentinels, target special/hardlinked files, or alias another output or protected input.
- RESOLUTION: Acquire every long-running release CLI's output parent component-by-component with `O_DIRECTORY`/`O_NOFOLLOW` before work and retain the descriptor through descriptor-relative exclusive temporary/new-file creation, link/rename installation as applicable, and directory fsync. Freeze role/alias classification from lexical names plus held identities; never recompute the formal canonical-result decision after writes; reject certifier output aliases and live JSON/selected-transcript aliases. Enforce each output's declared fresh-versus-replaceable final-name policy. Validator Markdown additionally rechecks that its held parent remains outside the package tree.
- RECURRENCE: Apply to every new JSON, Markdown, transcript, manifest, or output-directory option.
- APPLIES TO: Gate, validator, live/formal runners, certifier, deterministic wrapper CLIs, and manifest writers.
- LAST VERIFIED: 2026-07-15; exact current gate/formal contracts and five validator Markdown checks cover early capability acquisition, private true controls, final-entry safety, alias rejection, symlink/real-directory parent substitution, and wrapper stdout/file equality.
- SOURCE: README.md; docs/release/README.md; relevant scripts and contract suites.
- COUNTEREXAMPLE: Validate `/safe/out`, run a long suite, rename `/safe/out` aside, replace it with a symlink or different real directory, and reopen the lexical path only when publishing the result.
- RETENTION TEST: Pre-execution capability-acquisition, direct/ancestor symlink, real-parent substitution, FIFO/hardlink, cross-output alias, frozen-classification, external-validator-Markdown, update-manifest CLI preflight substitution, both fixed-manifest writers, and ordinary true-control probes.
- RESIDUAL: Held capabilities and pre/post endpoint checks prevent redirection within the declared parent-write boundary and detect observed mismatch; they are not temporal isolation and cannot exclude every transient same-UID mutation between the last precheck and a descriptor-relative create/install.
- OWNER / FOLLOW-UP: Every CLI owner; keep structured bounded INVALID_INPUT behavior.
- PROMOTION RATIONALE: Cross-cutting filesystem safety invariant.

### L-PR3-012 — Release replay must observe the actual outer self-test and literal CLIs

- DATE: 2026-07-15
- DURABILITY: PERMANENT
- ISSUE: Semantic simulations and incomplete file snapshots could miss mutations caused by the real self-test, modes, empty directories, links, hardlinks, timestamps, or entry metadata.
- RESOLUTION: Capture one immutable bounded no-follow regular-file-byte snapshot before validation; make every authorization read and self-test fixture consume or materialize only those captured bytes; apply separate package path/metadata and aggregate-file budgets plus bounded Git time/output/index limits; and independently revalidate held source and private mirror at finalization. Then execute two literal deterministic CLI passes with external outputs and require zero drift.
- RECURRENCE: Preserve the reviewed literal command list and rerun after every release-affecting edit.
- APPLIES TO: validate_package.py --self-test, release lock, and release certification.
- LAST VERIFIED: 2026-07-18; full self-test 2017/2017 and two-pass replay succeeded with zero changed files.
- SOURCE: validate_package.py; RELEASE_LOCK.json; PACKAGE_SURFACE.json.
- COUNTEREXAMPLE: A simulated command passes while the actual CLI writes inside the package.
- RETENTION TEST: Actual outer invocation binding plus two literal passes.
- RESIDUAL: The replay covers declared deterministic commands, not arbitrary future commands.
- OWNER / FOLLOW-UP: Release maintainer; update policy and tests together when commands change.
- PROMOTION RATIONALE: Makes idempotence observational rather than merely modeled.

### L-PR3-013 — Executable policy, not a manifest, decides the stable tree

- DATE: 2026-07-15
- DURABILITY: PERMANENT
- ISSUE: A manifest author could hide behavior or stable files by editing inventory or volatile exclusions.
- RESOLUTION: Independently derive inventory and exclusions from the current validator; require exact manifest equality; verify the manifest self-hash and every path, type, byte count, and SHA before computing one canonical stable-tree digest.
- RECURRENCE: Refresh manifests after policy/content changes, then independently recompute and verify.
- APPLIES TO: Stable release identity, live results, promotion certificates, and archives.
- LAST VERIFIED: 2026-07-18; 152-file stable inventory and 153-file stable closure including `STABLE_RELEASE_MANIFEST.json` verified.
- SOURCE: validate_package.py; STABLE_RELEASE_MANIFEST.json; MANIFEST.sha256.
- COUNTEREXAMPLE: A behavior file is added to a manifest-authored volatile exclusion.
- RETENTION TEST: Exact policy parity and refreshed-manifest false worlds.
- RESIDUAL: The executable validator remains inside the team/internal threat model.
- OWNER / FOLLOW-UP: Validator and release maintainers; require independent review of policy changes.
- PROMOTION RATIONALE: Prevents self-authored exclusions from weakening certification.

### L-PR3-014 — Keep one current observation ledger and remove stale mirrors

- DATE: 2026-07-15
- DURABILITY: PROJECT
- ISSUE: Prior-version ledgers, redundant text artifacts, and checked-in generated outputs created stale provenance, orphan evidence, and divergent copies.
- RESOLUTION: Keep seven current claims, 94 current structured wrappers, and one closed-schema current_observations.json release-declaration ledger; reference every wrapper exactly once; remove stale v1.0.1/v1.0.2 ledgers, redundant text mirrors, and obsolete output ledgers. Its proposition/case-bound records are deduplication identities, not execution provenance; fresh suite outcomes are established separately and no per-record reconciliation is claimed.
- RECURRENCE: On regeneration, check wrapper-reference bijection, hashes, version, stale roots, and orphan/missing files.
- APPLIES TO: This repository’s self-validation evidence.
- LAST VERIFIED: 2026-07-18; 94/94 wrappers uniquely referenced with zero missing, orphaned, or stale hashes.
- SOURCE: self_validation/self_certificate.json; current_observations.json; self_validation/evidence/.
- COUNTEREXAMPLE: Two “current” ledgers disagree while both remain cited.
- RETENTION TEST: Inventory bijection and stale-provenance scans.
- RESIDUAL: Current records are scoped release declarations and deduplication identities, not execution or official-runtime evidence.
- OWNER / FOLLOW-UP: Release evidence owner; migrate atomically at the next release.
- PROMOTION RATIONALE: Repeated project-specific provenance failures justify a one-authoritative-ledger rule.

### L-PR3-015 — Promotion evidence is a typed graph and the production CLI must run fresh

- DATE: 2026-07-15
- DURABILITY: PERMANENT
- ISSUE: Flat refs, prewritten captures, first-glob selection, scoped-away policy nodes, or a substitute harness could fabricate a complete profile.
- RESOLUTION: Require the fixed nine-role promotion-evidence-v2 DAG with canonical bundle-local paths, exact bytes, hashes, dependencies, and role validation. Rerun deterministic suites and allowlisted tools with fixed argv. Invoke the production certifier CLI for the full baseline and every negative; sanitize and restore inherited control variables without mutating fake executable bytes.
- RECURRENCE: Version the graph when semantics change and prove every negative reached production.
- APPLIES TO: Modeled PASS-SCOPED to PASS-TRACKED certification.
- LAST VERIFIED: 2026-07-18; authoritative 46/46 cases and production baseline 252/252 passed.
- SOURCE: PASS_TRACKED_UPGRADE_AUDIT.md; certify_pass_tracked_upgrade.py; run_promotion_certifier_contract_tests.py.
- COUNTEREXAMPLE: The harness passes while bypassing production parsing or inherits NTT_CONTRACT_CLAUDE_OUTPUT_MODE.
- RETENTION TEST: Production-CLI invocation inventory, fixed-DAG negatives, and environment isolation.
- RESIDUAL: Synthetic contract coverage is not runtime authentication.
- OWNER / FOLLOW-UP: Promotion maintainer; preserve production parity and evidence-kind labels.
- PROMOTION RATIONALE: Guards against tests validating their own replacement implementation.

### L-PR3-016 — Machine results are one JSON document and full streams decide

- DATE: 2026-07-15
- DURABILITY: PERMANENT
- ISSUE: Import-time stdout, multiple JSON documents, tail extraction, permissive return-code coercion, or excerpts could corrupt parsing or hide contradictions.
- RESOLUTION: Require direct loading of exactly one JSON document. Parse complete bounded stdout and stderr; let any negative signal dominate; require exact integer zero for success; expose only sanitized bounded excerpts with truncation flags and full byte/hash metadata.
- RECURRENCE: Add single-document and early-failure/large-tail checks to every new machine CLI or external-output parser.
- APPLIES TO: Validator, gate, contract suites, regression, aggregate, formal, and official-validator captures.
- LAST VERIFIED: 2026-07-15; all release CLIs parsed as single documents and exact-return/contradiction controls passed.
- SOURCE: README.md; PACKAGE_SURFACE.json; validation and promotion scripts.
- COUNTEREXAMPLE: Boolean false or 0.0 is accepted as return code zero, or a late “pass” hides an early failure.
- RETENTION TEST: Exact-type return worlds, pass-plus-nonzero summaries, and single-document probes.
- RESIDUAL: Text semantics remain allowlist- and parser-relative.
- OWNER / FOLLOW-UP: Every CLI/parser owner; version accepted result grammar.
- PROMOTION RATIONALE: Foundational machine-evidence rule.

### L-PR3-017 — “Swept” is not “resolved,” and remote fetch specifications are untrusted

- DATE: 2026-07-15
- DURABILITY: PERMANENT
- ISSUE: A sweep could be declared complete despite unresolved echoes, a pinned mirror could be treated as fresh, or a parent could execute a subagent-authored fetch specification.
- RESOLUTION: Apply the canonical post-correction sweep predicate; record affected claims, locators, classification, resolution, and replacement evidence. For remote-only truth, emit the exact REMOTE_GROUND_TRUTH_REQUIRED base record; evaluate freshness relative to the claim; reconstruct and validate scheme, host, and method; require companion evidence before fetched-and-readjudicated.
- RECURRENCE: Run after every corrected/refuted claim and whenever authoritative evidence is remote-only.
- APPLIES TO: Skill orchestration, source verification, and gate-auditor review.
- LAST VERIFIED: 2026-07-15; charter false/true-world probes passed.
- SOURCE: skills/nozickian-verify/SKILL.md; SUBAGENT_PROTOCOLS.md; agents/ntt-gate-auditor.md.
- COUNTEREXAMPLE: A pinned historical mirror satisfies a current-state claim.
- RETENTION TEST: Remove sweep or remote fields and require charter-integrity failure; retain intact true world.
- RESIDUAL: Both charter mechanics remain parent/auditor-enforced under Issue #5.
- OWNER / FOLLOW-UP: Parent adjudicator and gate auditor; Issue #5 owns mechanical enforcement.
- PROMOTION RATIONALE: Essential charter behavior with an explicitly retained enforcement boundary.

### L-PR3-018 — CI policy must be reachable and validate both checkout and archive

- DATE: 2026-07-15
- DURABILITY: PERMANENT
- ISSUE: Required command text hidden in comments, false conditions, heredocs, functions, loops, or disabled jobs could satisfy superficial checks; checkout-only testing could miss shipped-archive defects.
- RESOLUTION: Validate a restricted exact workflow surface and count commands only as direct top-level commands in active named run blocks. Run the full package `--self-test` with external Markdown and then the promotion aggregate in both checkout and unpacked Git archive, with GitHub token permissions restricted to contents: read.
- RECURRENCE: Treat new triggers, permissions, jobs, steps, actions, environments, or shell structures as policy changes requiring nearby worlds.
- APPLIES TO: .github/workflows/nozickian-team-ci.yml and package-surface policy.
- LAST VERIFIED: 2026-07-20; the exact workflow model, archive full-self-test command, and nearby false/true worlds passed locally. As external predecessor-snapshot evidence, Actions run 19 attempt 3 / job 88250472119 executed the checkout and unpacked-archive sequence successfully on synthetic merge ece8371cb86f46af1483bf38f5ed1a037f9c3f73, which incorporated head a1c30b404f334f648ed422e53fa2d6d59cb435b1. Later revisions require their own GitHub check and do not inherit that result.
- SOURCE: Workflow file; PACKAGE_SURFACE.json; validate_package.py; current local workflow-policy results.
- COUNTEREXAMPLE: The archive runs only basic validation before promotion, or exact self-test text exists only inside `if false`, a comment, or an uncalled function.
- RETENTION TEST: Disabled-job/comment/conditional/function false worlds, a direct-command parser control, and a structurally equivalent YAML true world.
- RESIDUAL: Green CI is evidence for its exact merge snapshot, not semantic truth or future base states.
- OWNER / FOLLOW-UP: CI and validator maintainers; rerun after any base/head or workflow change.
- PROMOTION RATIONALE: Prevents presentation-only CI compliance and checkout-only assurance.

### L-PR3-019 — Treat publication transport as untrusted and prove the remote payload

- DATE: 2026-07-15
- DURABILITY: PROJECT
- ISSUE: The first connector publication silently truncated the 164,731-byte promotion certifier to 141,312 bytes while still returning a blob SHA; Actions run 13 caught the syntax and manifest failure.
- RESOLUTION: Re-fetch current head; enforce one path to one local Git blob to one returned remote blob; compare every path’s local Git-object SHA and byte count; chunk large base64 on three-byte boundaries when needed; compose the complete tree including deletions and modes; fast-forward with force false; re-fetch the ref, commit, tree, and critical files; then run hosted CI and an independent pushed-state audit.
- RECURRENCE: Apply to every connector Git-data publication and never treat batch success as payload-integrity evidence.
- APPLIES TO: PR #3 and similar connector-based repository writes.
- LAST VERIFIED: 2026-07-15; repaired certifier blob eace960d6b086f2a9c9b60039f50ee28857c8811, head c34fceb7b49617ed0aea007f1f6849e763c8c63b, and tree 8210b1e6ff5ac52467fc533f93e67ccaa8298de2 matched local; run 14 succeeded.
- SOURCE: Failed Actions run 29388787367; successful run 29388907116; commits 217e5cf and c34fceb.
- COUNTEREXAMPLE: A create-blob response is accepted without comparing the created blob to git hash-object.
- RETENTION TEST: Per-file SHA/cardinality audit, independent full-tree reconstruction, remote fetch, and hosted CI.
- RESIDUAL: Git-object equality proves bytes, not truth; each subsequent edit supersedes these snapshot identifiers.
- OWNER / FOLLOW-UP: Publishing parent; never reuse the current tree SHA after the durability commit.
- PROMOTION RATIONALE: Directly observed publication-layer corruption plus successful independent repair.

### L-PR3-020 — Finish at a reproducible fixed point, not the first green run

- DATE: 2026-07-15
- DURABILITY: PERMANENT
- ISSUE: Evidence, manifests, counts, documentation, and validators recursively affect one another; an earlier pass becomes stale after a later edit.
- RESOLUTION: Refresh only the integrity artifacts actually affected, rerun basic validation, strict gate, regression, gate/formal contracts, promotion aggregate, formal dry run, and full self-test; reconcile counts and status across all current records; repeat until commands and tree stop drifting; finish with JSON parsing, diff checks, orphan/stale evidence, and cache scans. Count a false-world rejection only when the intended named semantic check fails in an ordinary completed result; HARNESS_ERROR, INTERNAL_ERROR, an unrelated INVALID_INPUT, or a parser crash is not sensitivity evidence. Require true worlds to complete and pass so fail-closed does not become reject-all.
- RECURRENCE: Required after every release-affecting edit and again after publication.
- APPLIES TO: High-assurance release closure.
- LAST VERIFIED: 2026-07-18; local current-tree results recorded basic 1827/1827, full 2017/2017, gate 232/232, formal 231/231, regression 166/166, promotion 46/46 with a 252/252 baseline, 83/83 false and 12/12 true worlds.
- SOURCE: Current local machine results for the exact commands recorded in this addendum; per-snapshot GitHub checks and job logs are the external hosted-execution evidence. A hosted result for one immutable merge snapshot is not projected onto a later edit.
- COUNTEREXAMPLE: A count or manifest from an earlier green tree is presented as current after a documentation edit, or a crashed mutation harness is counted as a successful false-world rejection.
- RETENTION TEST: Two literal release passes, exact-tree comparison, causal named-check inspection for false worlds, completed PASS for true worlds, and new CI for every new head/base merge snapshot.
- RESIDUAL: A fixed point is relative to declared commands, policy, environment, and threat model.
- OWNER / FOLLOW-UP: Release parent; invalidate prior snapshot identifiers immediately on edit.
- PROMOTION RATIONALE: Prevents stale green evidence from becoming the verdict.

### L-PR3-021 — Preserve honest status vocabulary and residual scope

- DATE: 2026-07-15
- DURABILITY: PERMANENT
- ISSUE: Strong deterministic and synthetic results invite unsupported promotion or ambiguous status transmission across layers.
- RESOLUTION: Name the subject of every status. Untested claim q is UNKNOWN. Whole-artifact status may be PASS-TRACKED, PASS-SCOPED, LIMITED, FAIL, or UNVERIFIED. Missing live execution is UNVERIFIED_RUNTIME. Unavailable official validators are NOT_EXECUTED. The current modeled certifier result is status PASS-SCOPED, outcome CAPPED, promotion_authorized false, and nonzero exit while both Issue #5 obligations remain.
- RECURRENCE: Re-evaluate a limitation only with fresh direct evidence or mechanical implementation; never promote by confidence, interpretation, or synthetic coverage.
- APPLIES TO: Release verdicts, promotion reports, runtime identity, and threat-model claims.
- LAST VERIFIED: 2026-07-15; strict gate PASS-SCOPED with zero failed claims; official tools NOT_EXECUTED; runtime UNVERIFIED_RUNTIME.
- SOURCE: README.md; runtime-trace-auth docs; PASS_TRACKED_UPGRADE_AUDIT.md; PACKAGE_SURFACE.json; self-certificate.
- COUNTEREXAMPLE: “Promotion passed” is used to summarize a synthetic CAPPED result.
- RETENTION TEST: Exact status/type checks, unresolved Issue #5 obligations, and PR-body residual audit.
- RESIDUAL: Hostile maintainer control and semantic adequacy of future evidence remain outside mechanical closure.
- OWNER / FOLLOW-UP: Parent adjudicator and release maintainer; preserve scoped wording everywhere.
- PROMOTION RATIONALE: The durable outcome is calibrated assurance, not maximal status.

<!-- END PR3 DURABLE LESSONS v1 -->
