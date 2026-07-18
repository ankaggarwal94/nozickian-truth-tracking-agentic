# Documentation hub

This directory is the GitHub-facing documentation set for the Nozickian verification team/internal package. The package remains a closed-surface Claude Code plugin: runtime components stay in `.claude-plugin/`, `skills/`, and `agents/`, while repository-oriented explanation lives here under `docs/`.

## What to read first

| Need | README |
|---|---|
| Install and run the package locally | [`quickstart/README.md`](quickstart/README.md) |
| Understand the Nozickian standard and CoVe flow | [`audit-model/README.md`](audit-model/README.md) |
| Interpret evidence files and certificates | [`evidence/README.md`](evidence/README.md) |
| Certify a future PASS-SCOPED to PASS-TRACKED upgrade | [`pass-tracked-upgrade/README.md`](pass-tracked-upgrade/README.md) |
| Understand formal runtime trace authentication | [`runtime-trace-auth/README.md`](runtime-trace-auth/README.md) |
| Review the threat model and closed-surface policy | [`security/README.md`](security/README.md) |
| Modify, test, and release the package | [`development/README.md`](development/README.md), [`release/README.md`](release/README.md) |
| Browse generated self-validation artifacts | [`../self_validation/README.md`](../self_validation/README.md) |

## Current assurance status

The package status is **PASS-SCOPED**. Deterministic package checks, strict local evidence binding, regression fixtures, gate-contract tests, formal-runner contract tests, stable release manifest checks, and release provenance hygiene checks are expected to pass from a clean checkout. Authenticated live fixture/formal traces are necessary for a future promotion, but they are not sufficient for the v1.0.3 certifier because its two Issue #5 obligations remain unresolved.

The v1.0.3 promotion path has a separate synthetic aggregate contract suite. It exercises production certification across 44 baseline/negative cases, including real strict-validator output, complete-stream early failures, canonical downstream claim evaluation, malformed/empty claims, coordinator identity substitution, and safe output paths, but does not authenticate a real runtime. Promotion certificates require at least one independently evaluated claim; an explicit performed review may still conclude that no downstream claims were identified when it records a substantive reason. Even a complete modeled certificate is capped by `certify_pass_tracked_upgrade.py` at `PASS-SCOPED` / `CAPPED` with `promotion_authorized: false` until the two Issue #5 charter mechanics are implemented. Generic `ntt_gate.py` `PASS-TRACKED` semantics remain unchanged; the formal runner separately caps an otherwise `PASS-TRACKED` result because `temporal_immutability_enforced` is `false`.

## Documentation boundary

These README files are intentionally documentation-only. They do not expand the plugin runtime surface, add tools, introduce hooks, add MCP servers, or create new plugin agents. The validator checks for this separation: README files belong under this non-runtime documentation tree and must not be placed in plugin-loadable component directories as a substitute for runtime components.
