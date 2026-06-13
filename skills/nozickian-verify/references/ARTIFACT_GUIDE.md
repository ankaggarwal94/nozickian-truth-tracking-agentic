# Artifact-specific perturbation guide

## Prose and research summaries

False worlds: wrong dates, swapped names, stale pages, unsupported causal claims, quotation drift, source laundering, contradictory primary sources, old roles/titles, and cherry-picked context.

True worlds: paraphrase, alternate authoritative source, equivalent date format, different but correct name variant, and added caveats that preserve the claim.

## Technical manuals

False worlds: wrong version, unsupported OS, changed flag semantics, missing prerequisite, different default install path, unavailable dependency, failed command hidden by a wrapper, and missing rollback step.

True worlds: equivalent shell, supported OS patch release, alternate mirror, reordered non-dependent steps, and version-compatible dependency.

## Code

False worlds: mutated implementation, boundary inputs, negative controls, dependency drift, test overfitting, skipped execution, flaky external services, invalid mocks, missing security preconditions.

True worlds: refactor preserving behavior, alternate correct algorithm, parameterized equivalent tests, compatible runtime version, and documentation wording changes that preserve semantics.

## RAG answers

False worlds: stale corpus, corrupted retrieval, answer grounded to wrong chunk, citation supports sibling claim only, contradictory chunk, answer faithful to false retrieved context.

True worlds: equivalent retrieved source, same claim in a different authoritative corpus, paraphrased question, or citation order changes.

## Agent traces and tool-use outputs

False worlds: tool unavailable, fabricated tool output, wrong tool arguments, wrong execution environment, hidden failures, invalid approvals, task succeeded only because of fixture leakage.

True worlds: alternate valid tool sequence, equivalent command, non-semantic trace reordering, or different but valid intermediate plan.
