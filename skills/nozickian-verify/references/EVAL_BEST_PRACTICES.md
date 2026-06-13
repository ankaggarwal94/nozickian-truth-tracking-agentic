# Eval best practices for this skill

The deterministic validator follows these practices:

- Prefer deterministic checks over vibes.
- Validate actual artifacts and evidence, not just final text.
- Include negative controls and nearby false worlds.
- Include nearby true-world benign variations so the verifier is not brittle.
- Run gate contract tests against deliberately malformed certificates.
- Treat missing live runtime execution as a scoped unknown, not a pass.
- Do not let the certificate under evaluation relax its own thresholds.
- Keep package validation separate from live skill/runtime validation.

Live evaluations should capture the full Claude Code run, transcripts, generated artifacts, commands, and gate outputs. The package includes a live-eval harness stub that records `UNVERIFIED_RUNTIME` when Claude Code is unavailable.
