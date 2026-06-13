# Runtime trace authentication

Formal runtime claims require more than a transcript that says an agent was called. The package expects authenticated Claude Code stream events with native tool-use and tool-result boundaries for the required `ntt-*` lanes.

## Required lane idea

The formal coordinator is expected to invoke the method cartographer, claim extractor, source verifier, code verifier, false-world adversary, true-world adherence reviewer, and gate auditor as native structured subagent lanes. Each lane must have a real call and a corresponding successful result.

## Event-boundary rule

Tool-like objects embedded inside payload data do not authenticate execution. The formal runner treats nested `tool_use` or `tool_result` objects under message content, data, payload, delta, or arguments as payload data, not as runtime events. Direction also matters when role context is available: assistant-origin tool-use and user-origin tool-result events are expected.

## Status cap

When trace authentication is missing or incomplete, a generated certificate may still be useful, but runtime status must be capped. The package should retain **PASS-SCOPED** or `UNVERIFIED_RUNTIME` rather than claiming PASS-TRACKED.

## Reviewer checklist

Review `self_validation/formal_runner_contract_results.json` for cases covering fake traces, nested event smuggling, role inversion, duplicate tool-use IDs, missing results, generic results, text-only masquerades, and unexpected agent calls.
