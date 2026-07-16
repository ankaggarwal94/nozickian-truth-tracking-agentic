# PASS-SCOPED to PASS-TRACKED upgrade audit

This README summarizes the package-level promotion protocol. The full normative reference is:

```text
skills/nozickian-verify/references/PASS_TRACKED_UPGRADE_AUDIT.md
```

## Promotion principle

A **PASS-SCOPED** package has deterministic evidence but retains one or more explicit limitations, usually live Claude Code runtime execution. A **PASS-TRACKED** package requires live runtime evidence showing that the method tracks the relevant claims in the actual Claude Code environment.

## Required bundle

A promotion bundle contains deterministic captures, official validator policy records, live fixture output, and a formal result selected through a typed promotion evidence graph. Promotion certificate v2 requires exact-string `promotion_schema_version: "2.0"`, exact required top-level JSON types, at least one well-formed promotion claim, and `evidence.schema_version: "promotion-evidence-v2"`. Its nine fixed semantic roles map to canonical bundle-local regular non-symlink files with exact bytes/SHA-256 and one environment-independent acyclic `depends_on` graph. Every claim is evaluated through the canonical strict gate using the correct bundle evidence root, and modeled completion requires a nonempty all-passing result set. It also contains an explicit `downstream_review`; a performed review may use an empty conclusions list only with a substantive `none_identified_reason`.

The certifier reruns deterministic suites and compares the captures through suite-specific semantic projections. It also executes allowlisted official validators fresh. Claude runs with the exact normalized argv `claude plugin validate <package-root> --strict`; after ANSI normalization, the real `✔ Validation passed` output is accepted only when neither complete output stream contains a failure or contradiction. Full captured bytes, not bounded excerpts or tails, determine semantics, hashes, and byte counts. Prewritten text captures never authorize; a missing official executable can be scoped only with the explicit exclusion flag, but both official-policy nodes and their canonical dependencies remain mandatory. A discovered executable that fails remains a failure.

Formal result `2.0` binds a standalone endpoint-checked target copy; the exact report, gate, certificate, ledger, complete stream-json transcript, prompt, and target-copy companion manifest; package-tree identity; run ID; target identity; and target pre/post endpoint stability. `temporal_immutability_enforced` is `false`, which caps an otherwise `PASS-TRACKED` formal result at `PASS-SCOPED`. Execution also requires supported Linux subreaper containment before `Popen`; same-group and detached-session descendants are killed/reaped to a bounded quiet state, while unavailable containment or incomplete cleanup fails closed. Transcript authentication and its SHA-256/byte count cover the complete bounded capture, never a tail-only view. Promotion follows only the typed `formal.result` locator. It does not substitute basenames or pick the first glob match, although unrelated nonreserved files may remain in the directory.

Gate Markdown, certifier JSON/Markdown, formal output plus compatibility JSON, live transcripts plus optional JSON, validator Markdown, deterministic wrapper JSON, and fixed behavior/stable-release manifest outputs retain component-wise no-follow directory descriptors from before long-running work through descriptor-relative exclusive creation, link/rename installation as applicable, and directory fsync. Role/alias classification is frozen against held identities. Ancestor-to-symlink or real-directory replacement cannot redirect writes, certifier aliases and live JSON/selected-transcript aliases fail, and validator Markdown remains external. Observed mismatch fails closed, but capability/endpoint checks are not temporal isolation.

Formal coordinator and gate children receive only the runner-owned `/proc/<runner-pid>/fd/N` alias through `pass_fds`; the procfs-visible runner `Pid:` must equal the gate child's procfs-visible direct-parent `PPid:`. Child-FD close/rebind, self/unrelated PIDs, noncanonical or nonpositive PID/FD tokens, extra components, closed descriptors, and file descriptors are rejected. Live formal execution requires POSIX no-follow directory descriptors and procfd inheritance; absence returns `INVALID_INPUT` before requested output creation.

## Certifier

Run the machine checker against the external bundle:

```bash
python3 skills/nozickian-verify/scripts/certify_pass_tracked_upgrade.py \
  . pass_tracked_audit_bundle \
  --json pass_tracked_audit_bundle/pass_tracked_certification_result.json \
  --markdown pass_tracked_audit_bundle/pass_tracked_certification_result.md
```

Malformed, duplicate, invalid, or empty claims and other contradictory data must return canonical `status: "FAIL"` plus `failure_kind` (`INVALID_INPUT`, `CHECK_FAILED`, or `INTERNAL_ERROR`) rather than an unhandled traceback.

For v1.0.3, satisfying every modeled check does not authorize promotion. The certifier returns `status: "PASS-SCOPED"`, `outcome: "CAPPED"`, `promotion_authorized: false`, `satisfied_profile: "promotion-contract-v2-complete"`, both exact unresolved Issue #5 obligations, and a nonzero exit. The obligations are:

- `Issue #5 consistency-sweep activation and resolution mechanics remain parent-enforced.`
- `Issue #5 REMOTE_GROUND_TRUTH_REQUIRED escalation mechanics remain parent-enforced.`

The modeled-promotion cap applies to the v1.0.3 certifier. Generic `ntt_gate.py` `PASS-TRACKED` semantics remain unchanged. The formal runner has a separate temporal-immutability cap; process containment is mandatory and fails before execution when unavailable.

Run the synthetic contract suite separately:

```bash
python3 skills/nozickian-verify/scripts/run_promotion_certifier_contract_tests.py .
```

Its expected `43/43` result invokes the production certifier CLI for the complete baseline and every negative case. It is synthetic contract evidence, not real runtime authentication.

## Non-closure reminder

PASS-TRACKED for an ordinary gate/formal trace does not automatically certify deployment safety, compliance, policy authorization, or final business action. Promotion v2 therefore requires actual canonical evaluation of the promotion claim set and a separate `downstream_review` even when no downstream claim was identified.

## Output-path safety

Certifier `--json`, formal `--output-dir`, and formal compatibility `--json` paths are validated component-by-component without resolving through caller-controlled links. Symlinked ancestors, direct links, special targets, and hardlink aliases fail with bounded structured invalid-input results and no external overwrite. Existing private regular `--json` files are intentionally regenerated via a same-directory exclusive temporary and atomic replacement. A formal output directory must be an existing real directory or a safely created new directory; an existing regular file is invalid.
