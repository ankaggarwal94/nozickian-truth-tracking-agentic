# Artifact-specific perturbation guide

Use this guide to specialize the general Nozickian verification contract to the artifact under review. The parent remains responsible for artifact identity, method `M`, evidence provenance, modal-test adequacy, downstream non-closure, and the final gate.

## Prose and research summaries

False worlds: wrong dates, swapped names, stale pages, unsupported causal claims, quotation drift, source laundering, contradictory primary sources, old roles/titles, and cherry-picked context.

True worlds: paraphrase, alternate authoritative source, equivalent date format, different but correct name variant, and added caveats that preserve the claim.

## Scientific papers and preprints

Activate this mode when the target is a paper, preprint, supplement, technical report, or a claim bundle whose support depends on mathematical arguments, experiments, simulations, datasets, or a model-to-hardware bridge. A paper is evidence of what its authors assert. It is not independent evidence that those assertions are true.

### 1. Lock the exact artifact

Before adjudicating claims, record:

- canonical identifier and exact version, such as an arXiv version rather than only an unversioned abstract URL;
- title, authors, publication or upload date, page count, and exact PDF SHA-256;
- every supplement, appendix, erratum, later version, code repository, data release, model checkpoint, and external result used in the audit;
- the retrieval time and provenance of remote artifacts;
- explicit exclusions, such as inaccessible code, unavailable hardware, or a later version outside scope.

Do not silently combine claims or corrections from different versions. A later revision may be relevant contradiction or correction evidence, but it is a distinct artifact. Peer-review status is context about the checking process, not evidence that every claim is true or false.

### 2. Build a claim graph, not a sentence list

Decompose the paper into atomic claims and link each claim to the assumptions, lemmas, measurements, citations, and downstream conclusions on which it depends. Use stable IDs and classify at least these claim families:

| Family | Typical claim | Required separation |
|---|---|---|
| `DEF` | Definition, notation, domain, or measurement convention | Separate mathematical definitions from physical or implementation conventions. |
| `THM` | Theorem, proposition, lemma, corollary, or necessity/sufficiency claim | Separate theorem statement, assumptions, proof obligations, and consequences. |
| `PRF` | Material proof step | Record the exact implication, equation, quantifier, limit, index, or external theorem used. |
| `MOD` | Mathematical, statistical, or physical model assumption | Separate idealized assumptions from observed facts. |
| `EMP` | Experimental or simulation result | Separate raw observation, metric computation, statistical estimate, and interpretation. |
| `REP` | Reproducibility or implementation claim | Track code, data, environment, seeds, preprocessing, and executable commands. |
| `PHY` | Hardware, realizability, noise, loss, latency, or energy claim | Separate proposed architecture, simulated architecture, built hardware, and measured system. |
| `QNT` | Arithmetic, scaling law, unit conversion, complexity, or resource estimate | Bind every number to units, denominator, time window, and assumptions. |
| `CIT` | Literature, novelty, priority, or comparison claim | Verify against the cited source and independent literature where material. |
| `DWN` | Generalization, deployment, safety, efficiency, or action-authorizing conclusion | Never inherit status automatically from an upstream theorem or experiment. |

Preserve qualifiers such as “almost all,” “in expectation,” “asymptotically,” “under assumption A,” “in simulation,” and “for the tested distribution.” Removing a qualifier creates a different claim.

### 3. Reconstruct the paper-specific method `M`

A scientific paper commonly contains several methods that must not be collapsed into one:

1. **Mathematical method**: definitions, theorem statement, assumptions, proof, cited lemmas, boundary cases, and any computer algebra or formal proof.
2. **Empirical method**: code commit, dependencies, hardware, dataset version and split, preprocessing, random seeds, optimizer, hyperparameter selection, stopping rule, metric implementation, aggregation, and statistical analysis.
3. **Physical-realization method**: component model, fabrication or optical/electronic assumptions, calibration, loss/noise/precision model, control and readout, latency, energy boundary, and whether the system was proposed, simulated, prototyped, or measured.
4. **Literature method**: search scope, comparison set, cited versions, and the basis for novelty or state-of-the-art claims.
5. **Editorial method**: author review, peer review, revision history, corrections, and release constraints. This can strengthen process evidence but cannot replace claim-level truth evidence.

Unknown components remain unknown. Do not reconstruct an ideal method and attribute it to the authors when the paper does not report it.

### 4. Mathematical claim protocol

For every critical or major theorem claim:

- restate the proposition with all quantifiers, domains, regularity conditions, measures, asymptotic limits, and exceptional sets;
- distinguish necessity, sufficiency, equivalence, genericity, density, full measure, and probability-one statements;
- inventory every proof dependency and identify where each assumption is used;
- check dimensions, indices, exponents, signs, conjugations, normalizations, boundary cases, and changes of variables;
- test whether a witness asserted to lie in a domain is actually guaranteed to lie there, or whether a translation parameter repairs the step;
- check convergence and interchange steps for the required pointwise, uniform, dominated, or distributional justification;
- test degenerate dimensions, empty-interior domains, singular parameters, zero coefficients, repeated functions, and limiting cases;
- distinguish a typographical inconsistency from a gap that changes the conclusion;
- seek a counterexample before treating a plausible proof as verified.

A theorem may be textually supported by its own proof while still remaining independently unverified. `PASS-TRACKED` normally requires an independently checked proof, formalization, or sufficiently strong counterexample-resistant audit of the exact statement. A proof sketch, numerical illustration, or citation to a related theorem is not a substitute for the missing proof obligation.

### 5. Empirical and simulation protocol

For every critical or major empirical claim:

- identify the population, sample, split, exclusions, preprocessing, and denominator;
- reproduce every reported arithmetic transformation and metric from raw or minimally processed outputs where available;
- distinguish training, validation, test, held-out, cross-validation, and post-selection results;
- record seeds, repeat count, variance or interval estimates, and whether the reported value is a single run, mean, median, maximum, or selected checkpoint;
- verify the hyperparameter-selection and model-selection procedure against the claimed evaluation split;
- compare baselines only under matched data, preprocessing, parameter or compute budgets, tuning effort, and metric definitions;
- require executable code and data provenance for independent reproduction claims;
- treat missing code, missing seeds, missing split definitions, and unreported selection procedures as method unknowns rather than filling them in charitably;
- separate finite-sample optimization and generalization evidence from asymptotic expressivity.

A universal-approximation theorem does not by itself predict monotonic finite-width test accuracy, successful optimization, sample efficiency, calibration, robustness, or energy efficiency. Training-set interpolation does not establish universality, and universality does not establish that a reported optimizer will find the approximant. Each bridge is a separate `DWN` claim with its own method and modal tests.

### 6. Physical-realization and efficiency protocol

For each physical or hardware claim, classify the evidence level:

- **proposed**: architecture described but not executed;
- **simulated**: numerical model executed under stated assumptions;
- **bench prototype**: partial hardware demonstrated;
- **integrated prototype**: end-to-end task executed on hardware;
- **measured deployment**: system-level performance measured under operational conditions.

Audit the model-to-hardware bridge explicitly:

- amplitude versus intensity conventions;
- phase, sign, and normalization conventions;
- reciprocity, unitarity, symmetry, passivity, and conservation constraints;
- loss, noise, detector precision, quantization, drift, crosstalk, bandwidth, and calibration;
- whether trainable parameters are physically addressable at the claimed scale;
- whether input loading, readout, memory, control, cooling, and conversion costs are included;
- whether a mathematical “almost all” parameter statement uses a declared measure that corresponds to the physical parameterization;
- whether the modeled component family covers manufacturable devices rather than only ideal matrices.

An energy-efficiency claim requires an explicit system boundary and measured or independently validated energy model. Optical propagation being passive or fast does not, by itself, establish end-to-end efficiency.

### 7. Citation and novelty protocol

For each material citation claim, verify that the cited source supports the exact proposition, not merely a neighboring topic. Check cited version, page or theorem, chronology, author identity, and whether later work contradicts or limits the claim. Novelty and priority claims require a search broad enough to expose plausible predecessors; the paper's own bibliography is orientation, not independent validation.

### 8. Quantitative and unit audit

Recompute all load-bearing arithmetic. Record formula, inputs, units, output, rounding, and sensitivity to omitted overhead. Probe at least:

- rates multiplied by durations;
- amplitude-to-intensity conversions;
- logarithmic units;
- sample counts and omitted partitions;
- parameter counts and rank or width conventions;
- asymptotic notation used as a finite numerical prediction;
- reported percentages, denominators, maxima, and averages;
- energy, latency, throughput, and bandwidth boundaries.

A numerically inconsistent estimate is not repaired by an unstated overhead factor. State the missing factor and leave the claim conditional or unknown until the authors' convention is established.

### 9. Paper-specific nearby false worlds

Construct false worlds that are close to the actual paper and targeted to each claim:

- remove or weaken one theorem assumption while retaining the conclusion;
- swap “dense” with “full measure,” or “almost every parameter” with a fixed parameter slice;
- alter one exponent, index bound, conjugation, sign, or normalization in a proof equation;
- preserve a plausible proof narrative while inserting a dimension or boundary-case failure;
- replace an independent source with the paper's own unsupported assertion;
- change a dataset split, seed, checkpoint-selection rule, or metric denominator while retaining headline accuracy;
- compare against an unmatched baseline or selected maximum;
- inject a unit conversion, amplitude/intensity, rate-duration, or order-of-magnitude error;
- remove loss, noise, precision, calibration, or control overhead from a hardware model;
- infer trainability, generalization, robustness, or efficiency directly from expressivity;
- treat a simulation as a hardware demonstration;
- treat a preprint upload or peer-review acceptance as claim-level truth evidence.

The method passes only if it rejects, revises, scopes, or flags the affected claim.

### 10. Paper-specific nearby true worlds

Test adherence under benign changes:

- equivalent theorem notation or a logically equivalent statement with explicit assumptions;
- an alternate valid proof or lemma chain;
- a corrected typographical exponent that leaves the intended derivation and theorem unchanged;
- a benign code refactor with identical outputs and environment;
- an equivalent authoritative dataset mirror with matching checksums;
- a different random seed whose result remains within the stated uncertainty claim;
- an alternate physically equivalent parameterization with the same conservation constraints;
- added caveats that narrow the claim without changing its supported core;
- a later paper version that corrects prose while preserving the verified proposition.

Do not overfit to the authors' exact notation, code path, or narrative order.

### 11. Required scientific-paper report additions

In addition to the standard report, include these tables:

#### Artifact and evidence ledger

| Artifact | Exact version or commit | SHA-256 | Retrieved at | Role | Freshness or access limits |
|---|---|---|---|---|---|

#### Claim graph

| Claim ID | Family | Exact claim and qualifier | Location | Depends on | Importance | Truth status | Gate impact |
|---|---|---|---|---|---|---|---|

#### Assumption and proof-obligation ledger

| Claim ID | Assumption or obligation | Where used | Evidence or derivation | Counterexample probe | Status | Residual risk |
|---|---|---|---|---|---|---|

#### Empirical reproducibility ledger

| Claim ID | Data and split | Code and environment | Seeds or repeats | Metric and selection rule | Independent rerun | Status |
|---|---|---|---|---|---|---|

#### Physical-realizability bridge

| Claim ID | Evidence level | Idealized assumption | Physical counterpart | Loss/noise/control treatment | Verified scope | Gap |
|---|---|---|---|---|---|---|

#### Arithmetic and units

| Claim ID | Reported quantity | Recomputed formula | Inputs and units | Recomputed value | Difference | Resolution |
|---|---|---|---|---|---|---|

#### Theory-to-conclusion bridges

| Downstream claim ID | Upstream claims | Additional bridge required | Independent evidence | Modal tests | Status |
|---|---|---|---|---|---|

### 12. Scientific-paper gate guidance

Use only the package's canonical whole-artifact gate statuses.

- `PASS-TRACKED`: the exact artifact and material supporting artifacts are identified; all critical and major claims have independently adequate truth evidence, complete methods, substantive false-world rejection, true-world adherence, and resolved contradictions.
- `PASS-SCOPED`: every claim inside a deliberately narrow scope passes, but an explicit boundary remains, such as textual theorem checking without formal proof or source-report verification without independent empirical reproduction. Do not describe this as verification of claims outside that scope.
- `LIMITED`: no identified critical claim is refuted, but one or more central theorem, empirical, physical, or reproducibility claims remain unknown or materially underdetermined.
- `FAIL`: a critical claim is refuted, a central proof or empirical result fails a decisive check, or the evaluation gate is bypassable.
- `UNVERIFIED`: the exact paper, version, supporting artifacts, or method cannot be identified well enough to evaluate.

Missing code or hardware does not automatically make the prose false. It prevents unsupported promotion from author-reported or simulated evidence to independently tracked empirical or physical truth.

## Target profile: arXiv:2509.05420v1

This profile adapts paper mode to **“Universality of physical neural networks with multivariate nonlinearity”** by Benjamin Savinson, David J. Norris, Siddhartha Mishra, and Samuel Lanthaler.

### Locked artifact

- Identifier: `arXiv:2509.05420v1`
- PDF pages: 31
- PDF SHA-256 for the audited copy: `4601799f97475e18aee6c70a06eb459e276c2a736698b121cdbab5fe5d2c33c0`
- Scope: the v1 PDF, including its supplement; later versions, author correspondence, code, and external reproductions are separate evidence and must be version-locked before use.
- Default posture: this is an audit plan, not a preassigned verdict.

### Seed claim inventory

| Claim ID | Family | Seed claim | Primary location | Required checks |
|---|---|---|---|---|
| `A2509-THM-01` | `THM` | The stated derivative nondegeneracy condition is necessary and sufficient for universal approximation by the fixed multivariate encoding architecture. | Main Theorem T1; Supplement S1 | Exact domain assumptions, necessity and sufficiency, witness location, translations, empty-interior cases, and all multi-index quantifiers. |
| `A2509-THM-02` | `THM` | Pairwise different nondegenerate encodings retain universality when the encoding function varies across terms. | Main Theorem T2; Supplement S2 | Meaning of the unbounded family, necessity of pairwise difference, Taylor/remainder control, and finite-to-infinite quantifiers. |
| `A2509-PHY-01` | `THM/PHY` | The scattering-based multivariate activation is nondegenerate for almost all symmetric unitary scattering matrices. | Main Theorem T3; Supplement S3 | Parameter-space measure, symmetric-unitary parameterization, fixed-slice versus almost-everywhere reasoning, degenerate dimensions, and proof indices. |
| `A2509-PHY-02` | `THM/PHY` | The phase-encoding/free-space optical construction satisfies the hypotheses needed for universal approximation. | Main Theorem T4 and Figure 2; Supplement S4-S5 | Exact optical-to-mathematical mapping, reference-wave and affine readout requirements, block independence, component constraints, and treatment of interaction between blocks. |
| `A2509-EMP-01` | `EMP` | The reported trained and random-scattering systems attain the stated MNIST and Fashion-MNIST accuracies. | Main numerical experiments; Supplement S6 | Dataset accounting, preprocessing, split, code, seeds, repeats, checkpoint selection, metric implementation, and independent rerun. |
| `A2509-DWN-01` | `DWN` | Increasing rank produces test-accuracy scaling predicted by the universality theorem. | Main numerical experiments and Figure 3 | Reject automatic closure from asymptotic approximation capacity to finite-r optimization and generalization; require an independent finite-sample bridge. |
| `A2509-QNT-01` | `QNT` | A 100 GHz switching rate over a 100 ms inference window supports an effective rank of order `10^7`. | Main scaling discussion | Recompute rate times duration, identify every multiplexing or overhead factor, and reconcile the stated order of magnitude. |
| `A2509-PHY-03` | `PHY` | The proposed architecture is physically realizable at the implied scale. | Figure 2, Remarks, and Conclusion | Distinguish proposal, simulation, prototype, and measurement; audit loss, noise, precision, crosstalk, control, readout, and trainable-addressability assumptions. |
| `A2509-DWN-02` | `DWN` | The results establish or substantively support energy-efficient physical neural networks. | Abstract and Conclusion | Require an explicit energy boundary and measured or independently validated system-level model, including encoding, control, detection, memory, and training costs. |
| `A2509-DWN-03` | `DWN` | The framework extends beyond optics or can address the most demanding machine-learning tasks. | Introduction and Conclusion | Require substrate-specific mappings and separate evidence for trainability, data efficiency, robustness, and task performance. |

### Mandatory disconfirmation probes

Treat the following as hypotheses to test, not conclusions to copy into the report:

1. **Theorem T1 witness and domain**: check whether the sufficiency proof unnecessarily places a nonzero derivative witness inside `Omega` even though the bias parameter may translate an arbitrary witness, and whether “compact domain” supplies the interior needed by the necessity argument.
2. **Theorem T2 quantifiers**: check what object is fixed as `r` grows, whether the family of pairwise different encoding functions is well-defined for all required widths, and whether the Taylor remainder is controlled strongly enough for the approximation claim.
3. **Supplement S3 exponent/index consistency**: inspect the derivative extraction around equations S39-S40. Test whether the power indexed as `2rd` is consistent with the degree of `T(x) S T(x)` and with the subsequent path sum of length `rd`, or is a typographical error that should be `rd`. Track the corresponding power of the mirror coefficient.
4. **Genericity and measure**: distinguish density from full measure. Verify which measure on real symmetric generators or symmetric unitaries supports “almost all,” and justify any passage from an almost-everywhere auxiliary scale parameter to the fixed physical value.
5. **Low-dimensional cases**: test `d = 1` and any proof step that selects an off-diagonal matrix entry or distinct indices.
6. **Optical coefficient conventions**: reconcile the main text's 50-percent-reflective mirror wording with supplementary amplitude coefficients, including phase and conservation constraints. Do not equate amplitude `1/2` with intensity `1/2` without an explicit convention.
7. **Dataset accounting**: reconcile the reported training and test counts with the canonical dataset partitions and identify any unreported validation subset.
8. **Run variability and selection**: locate code, seeds, repeated runs, uncertainty, and the rule by which a maximum or checkpoint was reported. If unavailable, keep independent reproducibility unknown.
9. **Controlled comparison**: require matched baselines before accepting “comparable to small ANNs” or an architectural advantage.
10. **Universality-to-accuracy bridge**: test a nearby world in which the theorem is true but optimization fails or generalization worsens as rank grows. The evaluation must reject the claim that the theorem alone predicts the plotted test-accuracy trend.
11. **Temporal-rank arithmetic**: directly calculate `100 GHz * 100 ms`. If the result differs from `10^7`, identify the missing duty-cycle, channel, or overhead assumption rather than inventing it.
12. **Readout scope**: verify whether universality after intensity detection requires an affine scale and offset or a reference wave, and whether the main claim includes those resources.
13. **Simulation-to-hardware bridge**: verify whether the reported results are simulations only and keep hardware realization, trainability at scale, and weakly interacting block assumptions separate.
14. **Energy boundary**: look for measurements or a complete model. Absence leaves the energy-efficiency conclusion independently unknown even if the mathematical theorem passes.

### Target-specific nearby true worlds

The evaluator should retain supported claims under these benign variants:

- a corrected S39-S40 exponent that restores internal degree/index consistency while leaving the intended theorem unchanged;
- an equivalent T1 statement that places the derivative witness anywhere in `R^d` and uses the bias to translate it;
- a mathematically equivalent parameterization of symmetric unitary scattering matrices with an explicit pushed-forward measure;
- independently reproduced accuracies within a prespecified uncertainty interval under the reported preprocessing;
- a narrower conclusion that claims simulated expressivity under idealized optics without asserting hardware or energy validation.

### Dispatch using the existing closed surface

Do not add a paper-specific agent. Use the existing lanes narrowly:

- `ntt-method-cartographer`: return separate mathematical, empirical, physical, literature, and editorial methods.
- `ntt-claim-extractor`: build the claim graph from the main paper and supplement, preserving qualifiers and derived claims.
- `ntt-source-verifier`: verify cited theorem, novelty, comparison, dataset, and hardware statements; escalate remote-only code, later versions, or external evidence.
- `ntt-code-verifier`: recompute arithmetic and units, inspect any released code and environment, and reproduce experiments only in an isolated worktree.
- `ntt-false-world-adversary`: run the mandatory disconfirmation probes and targeted theorem, metric, and hardware mutations.
- `ntt-true-world-adherence`: test equivalent theorem formulations, corrected typographical forms, benign implementation variation, and properly narrowed conclusions.
- `ntt-gate-auditor`: prevent theorem-to-empirics, simulation-to-hardware, and expressivity-to-efficiency status inheritance.

The target report must state separately whether the theorem claims, empirical results, physical-realizability claims, and downstream efficiency/generalization claims pass, fail, or remain unknown within scope. One successful lane cannot close the others.

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
