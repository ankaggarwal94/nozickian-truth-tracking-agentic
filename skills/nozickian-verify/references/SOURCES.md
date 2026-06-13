# Source notes

This package was generated from the user's PDF, "Nozickian Truth-Tracking and the Verification of Agentic Factual Writing," especially the proposed standard requiring claim-level decomposition, real method M, paired nearby false-world and true-world tests, and a real gate condition.

Additional implementation assumptions are based on public Claude Code and Agent Skills documentation as of package generation:

- Claude Code plugins use a `.claude-plugin/plugin.json` manifest and can include root-level `skills/` and `agents/` directories.
- Claude Code skills use `SKILL.md` with YAML frontmatter and optional supporting files.
- Skill `allowed-tools` pre-approves tools and should not be broad by default.
- Claude Code subagents require `name` and `description`; tool access should be restricted to necessary tools.
- Agent Skills compatibility fields should remain concise and only be present for environment-specific needs.

The deterministic scripts encode these assumptions as validation checks. If upstream specs change, update the scripts and rerun the self-tests.

## PASS-TRACKED upgrade operational sources

- Claude Code CLI reference: print mode, `--output-format stream-json`, `--include-hook-events`, `--plugin-dir`, and permission flags are relevant to collecting runtime transcripts.
- Claude Code plugins reference: plugin packages can include skills and agents; plugin-shipped agents have specific supported frontmatter and restrictions.
- Claude Code tools reference: Agent tool behavior and subagent tool lists are relevant to trace authentication and native lane evidence.

These external sources are operational compatibility inputs, not substitutes for local evidence. A package-level pass does not certify current Claude Code runtime behavior unless the live audit bundle captures the actual commands, outputs, and traces.
