# FAQ

## Is this a general Claude Code plugin validator?

No. It is a verifier for this package’s closed-surface method. It deliberately rejects several surfaces that Claude Code may otherwise support because this package’s threat model is team/internal and conservative.

## Why not put README files in every directory?

Some directories are runtime component locations. Adding Markdown files there can create ambiguity about whether a file is documentation or a plugin-loadable component. The GitHub README set is therefore centralized under `docs/` and summarized from the root README.

## Why is the status still PASS-SCOPED?

The deterministic checks can run without Claude Code, but PASS-TRACKED requires live runtime transcripts and trace authentication. A local pass without live runtime evidence does not track the runtime claim. Independently, v1.0.3 has a mandatory certifier-only Issue #5 cap: even a complete modeled promotion-v2 profile remains non-authorizing `PASS-SCOPED` / `CAPPED` until both parent-enforced charter obligations are mechanically implemented. Satisfying the live-evidence requirement does not discharge that separate cap.

## Can a passing trace prove the final answer is correct?

No. A trace can authenticate that the required method lanes executed. The correctness of an output, the safety of a deployment, and the authorization of an action are downstream claims requiring their own evidence.

## Why do the validators fail on macOS?

Because the fail-closed hardening is working as designed on symlinked ancestry and missing Linux containment, not because the package is broken. `/tmp` and `/var` are symlinks on macOS, so `/tmp/...` output paths are rejected; `validate_package.py` additionally needs a symlink-free `TMPDIR` and a `.git`-free copy of the tree. With those adjustments basic mode passes `1827/1827`. `--self-test` and fresh promotion certification require a Linux host. See the [macOS portability caveats](../quickstart/README.md#macos-portability-caveats).

## What should I do when a check fails?

Read the failed check name and details, identify whether the failure is a stale manifest, stale evidence hash, missing artifact, closed-surface expansion, or semantic regression, then fix the source of the failure rather than weakening the validator.
