# Audit model: Nozickian tracking, CoVe, and no automatic closure

The package verifies claims under a method-relative tracking model. It does not ask merely whether a claim has a citation or whether a script returned success. It asks whether a specified method **M** would reject nearby false worlds and retain nearby true worlds for the same claim.

## Claim-local tracking

Each important proposition is decomposed into an atomic claim. A claim record must identify the artifact, method, evidence, false-world tests, true-world tests, contradiction review, and residual risks. A passing upstream claim does not automatically verify downstream, summarized, deployment, compliance, safety, or action-authorizing conclusions.

## CoVe validation flow

The package implements a check-and-verify flow in which assertions are converted into claim records, evidence is bound to local artifacts, gate criteria are evaluated deterministically, and rival explanations are represented through false-world and true-world tests. The purpose is to make hallucination harder: a naked assertion, stale ledger, URI-like evidence reference, mismatched hash, missing modal test, or downstream pass inheritance should fail.

## No automatic epistemic closure

A verified claim `p` may entail another claim `q`, but this package does not let verification automatically transmit from `p` to `q`. The certificate field `derived_or_downstream_claims` records such conclusions explicitly. Untested downstream claims remain `UNKNOWN` unless they are promoted into their own full claim records with independent method and modal evidence; `UNVERIFIED` is reserved for a whole-artifact gate result.

## Practical interpretation

A trace-authenticated formal run can track the claim that the required subagent lanes executed. It does not by itself track the claim that the final operational decision is safe, authorized, complete, or production-ready. Those are separate downstream claims and must be audited separately.
