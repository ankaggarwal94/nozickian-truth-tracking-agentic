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
python3 skills/nozickian-verify/scripts/ntt_gate.py self_validation/self_certificate.json --evidence-root . --strict-evidence
python3 skills/nozickian-verify/scripts/run_regression_evals.py .
python3 skills/nozickian-verify/scripts/run_gate_contract_tests.py .
python3 skills/nozickian-verify/scripts/run_formal_runner_contract_tests.py .
python3 skills/nozickian-verify/scripts/run_promotion_certifier_contract_tests.py .
```

## Run live checks when Claude Code is available

```bash
python3 skills/nozickian-verify/scripts/run_live_skill_evals.py . --run-fixtures --require-claude
```

A machine without the `claude` executable cannot certify runtime tracking. In that environment the live harness should report `UNVERIFIED_RUNTIME` instead of promoting the package.

## Expected result language

Use **PASS-SCOPED** for deterministic/static assurance with explicitly retained runtime limitations. Use **PASS-TRACKED** only when the upgrade audit bundle proves live runtime tracking, formal trace authentication, strict gate success, and downstream non-closure discipline.

The aggregate command should report `44/44`. That result proves the synthetic promotion contract exercised the production certifier CLI, including nonempty canonical claim evaluation, coordinator identity binding, complete-stream failure detection, and safe output-path handling; it does not prove live runtime authentication. In v1.0.3, even its complete modeled baseline exits nonzero with `PASS-SCOPED`, `CAPPED`, and `promotion_authorized: false` because the two Issue #5 charter mechanics remain parent-enforced.
