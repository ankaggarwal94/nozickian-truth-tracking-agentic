# Quickstart

This README gives a short path from a fresh checkout to deterministic validation. It assumes the package root is your current directory.

## Load the plugin for a Claude Code session

```bash
claude --plugin-dir .
```

Invoke the skill by its namespaced command:

```text
/nozickian-truth-tracking-agentic:nozickian-verify <artifact path or verification task>
```

## Run deterministic validation

```bash
python3 skills/nozickian-verify/scripts/validate_package.py . --self-test
python3 skills/nozickian-verify/scripts/ntt_gate.py self_validation/self_certificate.json --evidence-root . --strict-evidence --downstream-policy package-self
python3 skills/nozickian-verify/scripts/run_regression_evals.py .
python3 skills/nozickian-verify/scripts/run_gate_contract_tests.py .
python3 skills/nozickian-verify/scripts/run_formal_runner_contract_tests.py .
python3 skills/nozickian-verify/scripts/run_promotion_certifier_contract_tests.py .
```

## macOS portability caveats

The validators are Linux-first, and several fail-closed hardening checks intentionally reject conditions that are normal on macOS (observed on macOS Darwin 25.4.0, Python 3.14.6). These are the hardening boundaries working as designed on symlinked ancestry and missing Linux containment, not bugs.

- **`/tmp` and `/var` output paths are rejected.** Both are symlinks on macOS, and output-path hardening refuses any output whose ancestry crosses a symlink. A `--markdown` or `--json` path under `/tmp/...` fails with exit 2: the gate returns `status: INVALID_INPUT` with reason `unsafe --markdown output path was rejected`, and the certifier returns `failure_kind: INVALID_INPUT` with reason `unsafe --json output path was rejected`. Use `/private/tmp/...` or any directory with symlink-free ancestry, or omit the output flag.
- **`validate_package.py` needs a symlink-free `TMPDIR`.** The default macOS `TMPDIR` under `/var/folders` fails the snapshot mirror with `NotADirectoryError: [Errno 20] Not a directory: 'var'`. Point `TMPDIR` at a symlink-free directory first.
- **`validate_package.py` must run on a `.git`-free copy of the tree.** A Git checkout marker mandates bounded-Git observation, which requires Linux process containment; on macOS this fails with `OSError: bounded Git detached-session process containment is unavailable`. Validate a copy of the tree without `.git` — the shipped-package form.

With those three adjustments, basic mode reproduces the release count exactly on macOS:

```bash
cp -R . /private/tmp/ntt_pkg && rm -rf /private/tmp/ntt_pkg/.git
mkdir -p /private/tmp/ntt_tmp
TMPDIR=/private/tmp/ntt_tmp python3 /private/tmp/ntt_pkg/skills/nozickian-verify/scripts/validate_package.py /private/tmp/ntt_pkg
# expected: 1827/1827 checks passed, exit 0
```

Two boundaries remain Linux-only:

- **`--self-test` is unreachable on macOS by construction.** It aborts fail-closed at false-world mutation 76/83 (`rejects force-tracked checkout .pyc`), which requires Linux subprocess containment. The `2017/2017` and `83/83` counts require a Linux host.
- **Fresh promotion certification requires Linux.** On macOS `certify_pass_tracked_upgrade.py` is not a startup refusal: process containment degrades per execution lane, the full check battery runs, and every fresh-execution lane fails `rc=125` before `Popen`, yielding a deterministic structured `FAIL` and exit 2. Live formal execution is already documented as Linux/procfs-specific.

The ordinary certificate gate is portable: on macOS the self-certificate run returns `PASS-SCOPED` with exit 0 given a safe `--markdown` path. Note that gate exit code 0 means `PASS-TRACKED` **or** `PASS-SCOPED`; automation that must accept only `PASS-TRACKED` must parse the `status` field from the JSON output rather than keying on the exit code.

## Run live checks when Claude Code is available

```bash
python3 skills/nozickian-verify/scripts/run_live_skill_evals.py . --run-fixtures --require-claude
```

A machine without the `claude` executable cannot certify runtime tracking. In that environment the live harness should report `UNVERIFIED_RUNTIME` instead of promoting the package.

## Expected result language

Use **PASS-SCOPED** for deterministic/static assurance with explicitly retained runtime limitations. Use **PASS-TRACKED** only when the upgrade audit bundle proves live runtime tracking, formal trace authentication, strict gate success, and downstream non-closure discipline.

The aggregate command should report `46/46`. That result proves the synthetic promotion contract exercised the production certifier CLI, including nonempty canonical claim evaluation, coordinator identity binding, complete-stream failure detection, and safe output-path handling; it does not prove live runtime authentication. In v1.0.3, even its complete modeled baseline exits nonzero with `PASS-SCOPED`, `CAPPED`, and `promotion_authorized: false` because the two Issue #5 charter mechanics remain parent-enforced.
