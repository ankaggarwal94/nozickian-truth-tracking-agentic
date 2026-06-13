# Security posture

This package deliberately avoids skill-level broad `allowed-tools`. Claude Code users should still inspect the package before trusting a workspace because skills and agents are operational text.

Subagents use read-only tools by default. Agents that need to execute tests or mutations use Bash only in scoped contexts and are instructed to operate in temporary copies or worktree-isolated sessions. The deterministic validator fails packages that introduce broad skill-level pre-approvals such as `Bash(*)`, `Write`, or `Edit`.

The deterministic gate does not execute untrusted artifact code. Code verification instructions require sandboxing, fresh worktrees, and explicit user consent for networked or destructive operations.


## Closed plugin surface

Do not add hooks, monitors, root settings, MCP/LSP configs, bin executables, extra commands, extra skills, or extra agents without treating the package as a new method M and rerunning full Nozickian validation. These components are plugin-loadable behavior, not inert documentation.
