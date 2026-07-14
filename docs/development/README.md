# Development guide

Use this README when editing the package. The validator is intentionally strict; many seemingly harmless changes alter evidence hashes, manifests, or closed-surface guarantees.

## Change workflow

1. Edit the intended source files.
2. Run static syntax checks if scripts or JSON changed.
3. Refresh the behavior manifest when behavior-affecting files changed:

```bash
python3 skills/nozickian-verify/scripts/validate_package.py . --update-manifest
```

4. Refresh the stable release manifest after stable package-file changes.
5. Rerun the base validator and the full self-test.
6. Run the promotion aggregate contract suite:

```bash
python3 skills/nozickian-verify/scripts/run_promotion_certifier_contract_tests.py .
```

7. Rerun the strict evidence gate if certificate-bound artifacts changed.
8. Review stale-token and provenance hygiene output before packaging.

## Where to add documentation

Add GitHub-facing documentation under `docs/<topic>/README.md`. Do not add README files to `agents/`, `.claude-plugin/`, `skills/nozickian-verify/`, `skills/nozickian-verify/scripts/`, or `skills/nozickian-verify/references/` unless the validator and runtime-surface policy are deliberately redesigned.

## Editing evidence

If a file cited by structured evidence changes, update the evidence JSON hash and rerun `ntt_gate.py` in strict mode. A manifest update alone is not enough because strict local evidence separately checks artifact hashes.

## Editing validators

Validator changes require mutation thinking: identify the nearby false world that the new check should reject, add a mutation or contract test where practical, and make sure a benign true-world variant still passes.

The promotion aggregate must remain independent synthetic evidence: its 36 cases invoke the production certifier CLI for the complete baseline and all negatives. Do not treat `36/36` as real runtime authentication. Keep its generated result/stdout ledgers volatile and regenerate release manifests and final generated outputs only after source/schema/policy review reaches a fixed point.
