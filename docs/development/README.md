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

7. Rerun the package-self strict evidence gate if certificate-bound artifacts changed:

```bash
python3 skills/nozickian-verify/scripts/ntt_gate.py self_validation/self_certificate.json --evidence-root . --strict-evidence --downstream-policy package-self
```

8. Review stale-token and provenance hygiene output before packaging.

## Where to add documentation

Add GitHub-facing documentation under `docs/<topic>/README.md`. Do not add README files to `agents/`, `.claude-plugin/`, `skills/nozickian-verify/`, `skills/nozickian-verify/scripts/`, or `skills/nozickian-verify/references/` unless the validator and runtime-surface policy are deliberately redesigned.

## Editing evidence

If a file cited by structured evidence changes, update the evidence JSON hash and rerun `ntt_gate.py` in strict mode. A manifest update alone is not enough because strict local evidence separately checks artifact hashes.

Claim-contract `1.1` includes the full certificate-assurance object, including
the complete downstream-policy controls and the local digest inventory of every
claim. Modal-case digests independently bind `outcome` and
`observed_outcome`. Regenerate those digests after final claim/method/policy and
world-contract edits, not piecemeal. For this package, the package-self modal ID
multiset must still equal all 80 reviewed transitions exactly once; a deleted,
duplicated, reassigned, or unreviewed transition is not repaired by lowering a
per-claim minimum.

## Editing validators

Validator changes require mutation thinking: identify the nearby false world that the new check should reject, add a mutation or contract test where practical, and make sure a benign true-world variant still passes.

The validator's initial package snapshot captures immutable bytes under
independent entry, depth, per-file, aggregate-file, and path/metadata budgets;
Git discovery/index capture has separate timeout, output-byte, and entry
limits. Authorization reads and fixture materialization must consume those
captured bytes rather than reopen or copy the later lexical source/mirror path.
Keep the final independent source and mirror revalidation checks when changing
this boundary.

The promotion aggregate must remain independent synthetic evidence: its 46 cases invoke the production certifier CLI for the complete baseline and all negatives. Do not treat `46/46` as real runtime authentication. Keep its generated result/stdout ledgers volatile and regenerate release manifests and final generated outputs only after source/schema/policy review reaches a fixed point.
