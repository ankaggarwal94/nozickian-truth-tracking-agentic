# Runtime trace authentication

Formal runtime claims require more than a transcript that says an agent was called. The package expects authenticated Claude Code stream events with native tool-use and tool-result boundaries for the required `ntt-*` lanes.

Formal result `2.0` evaluates an immutable standalone target snapshot. It records that relative sibling context from the mutable source location is unavailable, binds the exact snapshot plus all required companions, and records package-tree, run, and target pre/post identities. The complete stream-json transcript is written before authentication and its full bytes determine parsing, byte count, and SHA-256; bounded public excerpts and truncation flags never replace the authenticated stream. A configured capture ceiling fails closed instead of discarding an early event or authenticating only a tail. Promotion finds this result only through its typed `formal.result` evidence role; basename substitution and glob-first selection are not trusted.

Runtime identity is deliberately narrower than a software-supply-chain attestation: it binds the resolved executable entrypoint bytes used for the run, but not the transitive interpreter, shared-library, kernel, or host dependency closure.

## Required lane idea

The formal coordinator is expected to invoke the method cartographer, claim extractor, source verifier, code verifier, false-world adversary, true-world adherence reviewer, and gate auditor as native structured subagent lanes. Each lane must have a real call and a corresponding successful result.

## Event-boundary rule

Tool-like objects embedded inside payload data do not authenticate execution. The formal runner treats nested `tool_use` or `tool_result` objects under message content, data, payload, delta, or arguments as payload data, not as runtime events. Direction also matters when role context is available: assistant-origin tool-use and user-origin tool-result events are expected.

## Status cap

When trace authentication is missing or incomplete, a generated certificate may still be useful, but runtime status must be capped. The package should retain **PASS-SCOPED** or `UNVERIFIED_RUNTIME` rather than claiming PASS-TRACKED.

Generic formal-runner semantics remain capable of `PASS-TRACKED` when their contract is satisfied. The v1.0.3 `certify_pass_tracked_upgrade.py` cap is separate: even a complete modeled promotion is `PASS-SCOPED` / `CAPPED` with a nonzero exit until both Issue #5 charter obligations are mechanically implemented.

## Reviewer checklist

Rerun `run_formal_runner_contract_tests.py` to an external JSON path and review its cases covering fake traces, nested event smuggling, role inversion, duplicate tool-use IDs, missing results, generic results, text-only masquerades, unexpected agent calls, an early general-purpose event followed by a large valid-looking tail, complete transcript binding, resource limits, process-group cleanup, and unsafe output destinations.
