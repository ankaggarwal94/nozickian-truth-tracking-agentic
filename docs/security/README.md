# Security and threat model

This package is a team/internal verifier, not a hostile-maintainer proof. Its security value comes from a deliberately closed runtime surface, strict local evidence binding, mutation tests, and refusal to overclaim runtime tracking without live traces.

## Closed surface

The validator rejects unexpected plugin-loadable surfaces such as root `commands/`, `hooks/`, `monitors/`, `bin/`, root `settings.json`, `.mcp.json`, `.lsp.json`, manifest component-path/runtime fields, broad skill tool grants, dynamic skill shell substitutions, extra plugin agents, and unsupported plugin-agent frontmatter.

## Documentation does not add runtime authority

GitHub README files are stored under `docs/` and `self_validation/`. They are not placed in `agents/`, `skills/nozickian-verify/`, or other component directories where Markdown could be confused with runtime components. The validator checks the documentation set without expanding the plugin runtime surface.

## Known limits

A malicious maintainer who rewrites validators, certificates, manifests, and evidence together can still create a deceptive package. Reviewers should use the release lock, stable manifest, independent reruns, official validators where available, and live runtime traces before promoting status.

## Safe handling

Do not add networked hooks, MCP servers, custom binaries, broad Bash permissions, or new agents unless you intentionally redesign the threat model and add new false-world tests. Treat any such change as a new package line rather than a small documentation edit.
