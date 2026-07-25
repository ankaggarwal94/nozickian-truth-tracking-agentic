#!/usr/bin/env python3
"""Deterministic Nozickian truth-tracking gate.

Rejects threshold manipulation, missing evidence, missing false/true-world tests,
fake pass labels, unresolved contradictions, unknown critical method fields, and
optionally missing or semantically unbound evidence artifacts when --evidence-root
is supplied.

This gate is intentionally conservative: it checks declared certificate structure,
local evidence-ref containment, hardlink-aware evidence identity, typed method-relative claim contracts, reviewer-classified structured nearby-world contracts, case-bound modal release declarations, proposition-bound downstream passes, structured evidence binding for every cited local ref, exact SHA-256 equality between artifact_path and hash_or_version, and URI-scheme rejection for both evidence refs and artifact_path. In strict local evidence mode, every cited evidence ref must be a valid in-root JSON evidence artifact; one good ref cannot mask a bad cited ref, duplicate or physically aliased refs count once for minimum evidence thresholds, and duplicate declaration identities count once for sensitivity/adherence thresholds. These declarations are not execution provenance. It is not a substitute
for expert judgment about whether every source semantically proves every claim, but
it prevents a bare README, LICENSE, or unrelated nonempty file from counting as
claim evidence for PASS-TRACKED.
"""
from __future__ import annotations
import argparse, hashlib, json, math, os, re, stat, unicodedata, uuid
from collections import Counter
from urllib.parse import urlparse
from dataclasses import dataclass, asdict
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

PASS_TRUTH = {"confirmed", "executed_confirmed", "formal_confirmed", "independently_confirmed"}
MINOR_TRUTH = PASS_TRUTH | {"supported"}
IMPORTANCE = {"critical", "major", "minor"}
REQ_METHOD = ("producer", "checker", "artifacts", "environment", "tools", "evidence_process", "graders_or_tests", "trace_or_logs")
METHOD_NARRATIVE_FIELDS = frozenset({"producer", "checker", "evidence_process"})
METHOD_COLLECTION_FIELDS = frozenset(set(REQ_METHOD) - METHOD_NARRATIVE_FIELDS)
DEFAULT_THRESHOLDS: Dict[str, Dict[str, float]] = {
    "critical": {"method_completeness": 0.875, "sensitivity": 0.95, "adherence": 0.90},
    "major": {"method_completeness": 0.750, "sensitivity": 0.80, "adherence": 0.75},
    "minor": {"method_completeness": 0.500, "sensitivity": 0.50, "adherence": 0.50},
}
MIN_REQ = {
    "critical": {"evidence": 2, "false_tests": 2, "true_tests": 1, "structured_evidence": 1},
    "major": {"evidence": 1, "false_tests": 1, "true_tests": 1, "structured_evidence": 1},
    # Even a minor strict claim needs one externalized contract binding. Without
    # it, a certificate could downgrade critical -> minor, rewrite its own
    # digest, and delete every evidence/modal reference.
    "minor": {"evidence": 1, "false_tests": 0, "true_tests": 0, "structured_evidence": 1},
}
FALSE_OUTCOMES = {"rejected_false_claim", "withheld", "flagged", "failed_as_expected", "downgraded", "corrected", "blocked", "not_certified"}
TRUE_OUTCOMES = {"retained_true_claim", "accepted_equivalent", "passed_benign_variant", "correctly_updated", "preserved", "recovered", "not_overfit"}
NEG_FALSE = ("accepted false", "certified false", "passed false", "ignored contradiction", "hallucinated", "misrepresented", "failed to flag", "did not reject")
NEG_TRUE = ("rejected equivalent", "overfit", "failed benign", "did not retain", "lost true", "penalized alternate")
UNKNOWN = {"", "unknown", "inferred_unknown", "n/a", "none"}
STRUCTURED_EVIDENCE_FIELDS = (
    "evidence_schema_version",
    "claim_id",
    "claim_proposition_sha256",
    "claim_contract_schema_version",
    "claim_contract_sha256",
    "artifact_path",
    "command_or_source",
    "observed_result",
    "support_summary",
    "timestamp_utc",
    "hash_or_version",
)
STRUCTURED_EVIDENCE_OPTIONAL_FIELDS = frozenset({"applies_to_claims"})
STRUCTURED_TEST_OPTIONAL_FIELDS = frozenset({
    "applies_to_tests",
    "modal_case_sha256",
    "observation_id",
    "test_id",
})
EVIDENCE_SCHEMA_VERSION = "1.1"
OBSERVATION_SCHEMA_VERSION = "1.2"
CLAIM_CONTRACT_SCHEMA_VERSION = "1.1"
CERTIFICATE_ASSURANCE_SCHEMA_VERSION = "1.0"
WORLD_CONTRACT_SCHEMA_VERSION = "1.1"
WORLD_CONTRACT_FIELDS = frozenset({
    "schema_version",
    "semantic_equivalence_class",
    "operator",
    "target",
    "precondition",
    "state_delta",
    "oracle",
    "expected_outcome",
})
# These values are machine identities, not reviewer prose.  Free-form details
# remain useful explanations in precondition/state_delta/oracle, but cannot
# manufacture an additional nearby world by punctuation or paraphrase alone.
WORLD_MUTATION_OPERATORS = frozenset({
    "mutate",
    "preserve",
    "remove",
    "replace",
})
WORLD_MUTATION_TARGETS = frozenset({
    "artifact.digest",
    "artifact.identity",
    "artifact.path",
    "certificate.assurance",
    "certificate.claim_contract",
    "certificate.evidence_refs",
    "certificate.modal_tests",
    "certificate.thresholds",
    "claim.presentation",
    "documentation.claim",
    "evidence_wrapper.artifact_digest",
    "evidence_wrapper.identity",
    "evidence_wrapper.path",
    "filesystem.entry",
    "filesystem.parent",
    "fixture.contract",
    "manifest.entry",
    "markdown.output",
    "process.containment",
    "process.output",
    "release.archive",
    "runtime.envelope",
    "runtime.trace",
    "workflow.command",
    "workflow.step",
})
# One-time deterministic migration for the package's schema-1.0 release
# declarations.  The values are semantic typed operands, not mechanically
# derived slugs: each old test was adjudicated to an operator and closed target.
LEGACY_WORLD_IDENTITY_BY_TEST_ID: Dict[str, Tuple[str, str]] = {
    "FW-structure-missing-manifest": ("remove", "manifest.entry"),
    "FW-structure-dynamic-shell": ("replace", "workflow.command"),
    "TW-structure-unused-asset": ("preserve", "manifest.entry"),
    "FW-gate-strict-root": ("remove", "certificate.assurance"),
    "FW-gate-proposition-substitution": ("replace", "certificate.claim_contract"),
    "FW-gate-modal-substitution": ("replace", "certificate.modal_tests"),
    "FW-gate-resource-bounds": ("mutate", "certificate.assurance"),
    "FW-gate-path-control": ("mutate", "artifact.path"),
    "FW-gate-markdown-linked-target": ("replace", "markdown.output"),
    "FW-gate-markdown-symlinked-ancestor": ("mutate", "markdown.output"),
    "FW-gate-markdown-parent-substitution": ("replace", "filesystem.parent"),
    "TW-gate-shared-ledger": ("preserve", "runtime.trace"),
    "TW-gate-private-markdown-output": ("preserve", "markdown.output"),
    "FW-validator-extra-ci-action": ("mutate", "workflow.step"),
    "FW-validator-unsafe-fixture-id": ("replace", "artifact.path"),
    "FW-validator-extra-release-command": ("mutate", "workflow.command"),
    "FW-validator-mutable-checkout-action": ("replace", "workflow.step"),
    "FW-validator-mutable-setup-python-action": ("replace", "workflow.step"),
    "FW-validator-archive-self-test-comment": ("mutate", "workflow.command"),
    "FW-validator-archive-self-test-function": ("replace", "workflow.command"),
    "FW-validator-formal-output-invariant": ("remove", "certificate.assurance"),
    "FW-validator-held-output-capability-invariant": ("remove", "process.output"),
    "FW-validator-markdown-parent-substitution": ("replace", "filesystem.parent"),
    "FW-validator-markdown-moved-into-package": ("mutate", "filesystem.parent"),
    "FW-validator-fixed-manifest-symlink": ("replace", "manifest.entry"),
    "FW-validator-fixed-manifest-hardlink": ("mutate", "manifest.entry"),
    "FW-validator-fixed-manifest-special": ("replace", "filesystem.entry"),
    "FW-validator-fixed-manifest-linked-ancestor": ("mutate", "filesystem.entry"),
    "FW-validator-fixed-manifest-real-substitution": ("replace", "filesystem.parent"),
    "FW-validator-update-manifest-cli-preflight-substitution": ("mutate", "workflow.step"),
    "TW-validator-ci-presentation": ("preserve", "workflow.step"),
    "TW-validator-direct-archive-command": ("preserve", "workflow.command"),
    "TW-validator-held-markdown": ("preserve", "markdown.output"),
    "TW-validator-fixed-manifest-normal": ("preserve", "manifest.entry"),
    "FW-formal-malformed-jsonl": ("mutate", "runtime.trace"),
    "FW-formal-large-reordered-result": ("replace", "runtime.trace"),
    "FW-formal-descendant-pipe": ("mutate", "process.containment"),
    "FW-formal-closed-stdio-descendant": ("replace", "process.containment"),
    "FW-formal-containment-unavailable": ("remove", "process.containment"),
    "FW-formal-detached-session": ("mutate", "process.output"),
    "FW-formal-deep-detached-chain": ("replace", "process.output"),
    "FW-formal-companion-substitution": ("replace", "artifact.identity"),
    "FW-formal-self-attested-output-check": ("mutate", "certificate.assurance"),
    "FW-formal-empty-report-gate": ("remove", "artifact.identity"),
    "FW-formal-held-dirfd-symlink-swap": ("replace", "filesystem.parent"),
    "FW-formal-child-fd-rebind": ("mutate", "process.output"),
    "FW-formal-procfd-unavailable": ("remove", "process.output"),
    "FW-formal-canonical-json-classification": ("replace", "artifact.path"),
    "FW-live-transcript-symlink-substitution": ("replace", "artifact.path"),
    "FW-live-transcript-real-substitution": ("mutate", "filesystem.parent"),
    "FW-live-json-real-substitution": ("replace", "filesystem.parent"),
    "FW-live-json-transcript-alias": ("mutate", "artifact.identity"),
    "FW-live-output-direct-symlink": ("replace", "filesystem.entry"),
    "FW-live-output-ancestor-symlink": ("mutate", "filesystem.entry"),
    "FW-live-explicit-output-a-b-a": ("mutate", "filesystem.parent"),
    "FW-live-explicit-output-persistent-substitution": ("replace", "process.output"),
    "FW-wrapper-json-unsafe-targets": ("replace", "artifact.path"),
    "FW-wrapper-json-parent-substitution": ("replace", "filesystem.parent"),
    "FW-formal-temporal-cap": ("mutate", "certificate.assurance"),
    "TW-formal-valid-role-direction": ("preserve", "runtime.trace"),
    "TW-formal-held-dirfd-ordinary-output": ("preserve", "filesystem.parent"),
    "TW-live-explicit-output-early-capability": ("preserve", "process.output"),
    "TW-wrapper-json-held-output": ("preserve", "artifact.path"),
    "TW-wrapper-json-early-capability": ("preserve", "filesystem.parent"),
    "FW-promotion-auto-closure": ("mutate", "certificate.assurance"),
    "FW-promotion-missing-trace": ("remove", "runtime.trace"),
    "FW-promotion-unsafe-output": ("replace", "artifact.path"),
    "FW-promotion-self-attested-output-check": ("mutate", "certificate.assurance"),
    "FW-promotion-empty-formal-output": ("remove", "artifact.identity"),
    "FW-promotion-coordinator-result-identity": ("replace", "artifact.identity"),
    "FW-promotion-coordinator-argv-identity": ("replace", "workflow.command"),
    "FW-certifier-json-markdown-alias": ("mutate", "artifact.identity"),
    "FW-certifier-parent-substitution": ("replace", "filesystem.parent"),
    "TW-promotion-capped-baseline": ("preserve", "certificate.assurance"),
    "TW-certifier-distinct-outputs": ("preserve", "artifact.path"),
    "FW-github-readmes-degraded": ("remove", "documentation.claim"),
    "TW-github-readmes-benign-note": ("preserve", "documentation.claim"),
    "FW-charter-sweep-removed": ("remove", "documentation.claim"),
    "FW-charter-remote-fields-removed": ("remove", "certificate.assurance"),
    "TW-charter-intact": ("preserve", "documentation.claim"),
}
PACKAGE_WORLD_REGISTRY_VERSION = "1.0"
# Package-self modal declarations use a closed transition envelope. Evidence
# references remain authenticated by the surrounding claim contract; every
# field that can change the transition's semantics is pinned here.  The sole
# optional mechanics field is a canonical fixture SHA-256.
PACKAGE_WORLD_REQUIRED_TEST_FIELDS = frozenset({
    "id",
    "kind",
    "target_claim_ids",
    "expected_behavior",
    "observed_behavior",
    "outcome",
    "result",
    "evidence_refs",
    "world_contract",
})
PACKAGE_WORLD_OPTIONAL_TEST_FIELDS = frozenset({
    "observed_outcome",
    "fixture_sha256",
})
# Immutable reviewed transition pins for the package-self certificate.  These
# digests cover the complete canonical transition declaration, including its
# explanatory prose. They cannot be extended by a certificate declaration.
REVIEWED_PACKAGE_WORLD_TRANSITION_SHA256: Dict[str, str] = {
    "FW-structure-missing-manifest": "49f31ec839f5bd436dacab9d49d23233b453fb4ab2889ca0b1db7d33c259577a",
    "FW-structure-dynamic-shell": "2a316b8f68ac5c5a887cabaa3071781fb6df15353fa966bc70d4a6961a0cdbda",
    "TW-structure-unused-asset": "d8b583e8f2e35a69818c2984f430216c1811da322b5e96a6c33d3588bb5e976a",
    "FW-gate-strict-root": "d4c6e6d4255f87a8c800c45a7e5a3d672f4101cf160b5e14dd34cdb11c1eee64",
    "FW-gate-proposition-substitution": "c22daa535b85b93154271fb5f9a9a978fc40c080eaddf8decbf32d06d6b3e2a7",
    "FW-gate-modal-substitution": "c01e24853c93239f6a09f869a0b820e692e9c80e6c638966c619ee2db96d7891",
    "FW-gate-resource-bounds": "5c93ad2c9a958cbb4d6963b27e1f8e2f222048e92ea43fd51627a40f5746e5b6",
    "FW-gate-path-control": "bd92b0575533d796de252d60d04f180c940c51f26325f06e59deb3049696681f",
    "FW-gate-markdown-linked-target": "bb75eaa863f7f17ecfbc1e999c5f7f5cd3bcf593ee4fb1afa3e7dc759ae568e8",
    "FW-gate-markdown-symlinked-ancestor": "7fe34d6b923eb3c41a774b6b35619557021c39766794a14292a7ce7c74b03969",
    "FW-gate-markdown-parent-substitution": "a13c5b9a1f7ad60a047803b9d5f9ec74e26e4e054089368e5029b2f0cadd2568",
    "TW-gate-shared-ledger": "ecfa1a2c3cc71fd81c63b4b1a21a6769f1d47df67e835b93a2e46b04ab301d23",
    "TW-gate-private-markdown-output": "99617cc03822858b3f5280a73c3b365b0c64d38a48d8bc5c91ccc72023fded68",
    "FW-validator-extra-ci-action": "b3a2c4c69b918cd672d8f1e6a05e5a2c64d3f92089c4f409c734d720cd7c49c1",
    "FW-validator-unsafe-fixture-id": "a97961b7b6dd1cf2e61ec32e4342a596b23d867eaea965e9234429866ef349f0",
    "FW-validator-extra-release-command": "3389d0b5a8593a7c272b683741e03526fdf3d4aa8b42c40973f81dcd28dfdbf8",
    "FW-validator-mutable-checkout-action": "4aa103e5f4466f8e1397caff2fed355e3e84c6cf8272e1ee641433bda0e66ed1",
    "FW-validator-mutable-setup-python-action": "434a4815dfa14d9987a7f138f7aa67959ac5e8c3496e87c91bda8a8ef98a6940",
    "FW-validator-archive-self-test-comment": "aa1038467af7417dc070450c3b6d9caf501293cfd90d28c90cbb3ec5370ff19d",
    "FW-validator-archive-self-test-function": "b0a379f905322f7973d20e9effafee672d4a496179c5c11ef9b007172aef7955",
    "FW-validator-formal-output-invariant": "ba35ce695bc7d561dddeaf5b852aa69237e5c1bd62a8f893d92f9b9189e297c4",
    "FW-validator-held-output-capability-invariant": "4a10c44129cfe34107e1110986eba394c4b9bedab031e2241febb96ba51243a7",
    "FW-validator-markdown-parent-substitution": "d88452af9d74b0d6489fbaf6ff0ebd908d85fb35108c1d5fb5333932a1ab3165",
    "FW-validator-markdown-moved-into-package": "75382e43fd917792876ef98abb16a4fcf877e2783a70490c946719175dd5d15f",
    "FW-validator-fixed-manifest-symlink": "2e3a092c66ce05b8302f3e76ce4fbfa9559d0d37d1e109f893137773dabb8a7e",
    "FW-validator-fixed-manifest-hardlink": "3a9787e6869d9905b423ae99c4554f14422a187329a7998be19a52719c890c8d",
    "FW-validator-fixed-manifest-special": "741641058277911edefdbdf870a3a389c5d904567d609c9b74e8a3a0c0b15cea",
    "FW-validator-fixed-manifest-linked-ancestor": "e932490dd95490c0eeb900694dc4f886b16a1e839dde20c155713748686a5f5e",
    "FW-validator-fixed-manifest-real-substitution": "35666b18d5dcb676ac2b110bb019ee565a485098a1d98ecb49417144eae6bb2b",
    "FW-validator-update-manifest-cli-preflight-substitution": "34136fce46ec20b5bd4bf8fcf185a139d7e128c462864d01f34358d753399312",
    "TW-validator-ci-presentation": "45c3bd626c1c9cea947c71f2de3f9e1d238d273ddb40c21de829d806fc1dffe6",
    "TW-validator-direct-archive-command": "b20862092ba55b813ce5a08ca0a34f67ba6e5148f8ba64245f312d85c024b67d",
    "TW-validator-held-markdown": "745b038e13ec8891604e2d9747bbb815912e4d61971b66cdc175e95294af1e65",
    "TW-validator-fixed-manifest-normal": "60897f5bf8328044ad77e20335e703390c6e68da5ef01a4087509b20a196c516",
    "FW-formal-malformed-jsonl": "5f2f315873f68b6640fcc224a395c087ea5c769f125d98abaafc409e245fab7e",
    "FW-formal-large-reordered-result": "062419c3480817b3137d77922e6d3171f42cf7871b94c28d71ea507d4d4221b2",
    "FW-formal-descendant-pipe": "eb75e5e37343d9693745f290c0741f2f90a5ec921ffd0975c24812c3cf5b7715",
    "FW-formal-closed-stdio-descendant": "ecae58386dbc6502ce304f6df6f33baaf5090341aa265ddf07e0151582f8536a",
    "FW-formal-containment-unavailable": "599a2ee2738c8bbd8af366b7f06c34963c2e526c7603948d2310d68dca26bb7a",
    "FW-formal-detached-session": "0d3fd73a5443a0c53c6fd93b690999e203dffd8f44706f390e1ed7903915b676",
    "FW-formal-deep-detached-chain": "296819b2de828685ed3f0c29d7b172e80da8e17a124cbc6c418f71fcba4fe482",
    "FW-formal-companion-substitution": "1828e76c0e9d35e961643afa6f154de6a74dfdb7e7bcd84925408f4e635c5f19",
    "FW-formal-self-attested-output-check": "39cf5fec57a6de11f5f9a13db5ff290a85ffbec85424baa86c0fd17117e4c951",
    "FW-formal-empty-report-gate": "a2eda41f6bc22e98ae9ad463dd818c20dc63c39c1a3b588333438663eb8fc970",
    "FW-formal-held-dirfd-symlink-swap": "f4daaf6849f75a5c664d6bce8616de5ed4782b4ea124bcdf9888c35ec8fb39f7",
    "FW-formal-child-fd-rebind": "015d16d66a5ba08e2ef9ec03b9d5d7b7d8328819c047c161a47565f7b40e6115",
    "FW-formal-procfd-unavailable": "8c550d82e19cead1bc80865de63999d48ca54de2f8c2a09036fefc949f18e729",
    "FW-formal-canonical-json-classification": "a7c5cd330d5f6f2d15ce8bd77ea68c6fa52b77852949c962ec427781ac668dee",
    "FW-live-transcript-symlink-substitution": "924e561a3e9322be27f6494d811c5e415161cc259c039dde539bc3dbd12b09e1",
    "FW-live-transcript-real-substitution": "2ea040663735f9424be9caa3bd8606520a02b3b91d06e2b824555b1085159410",
    "FW-live-json-real-substitution": "5781669dc6bdcc8aee7ff0678562f306a54e07bcf03abbfb8bb20961431f2117",
    "FW-live-json-transcript-alias": "2d8b602b38da379000db29744e0fb2166610fd48b9fcc67089a68a6d9f8a0fea",
    "FW-live-output-direct-symlink": "02ab4da1526722d20c9bf2e562c503ca0343b3274e87577abaa0dcdab3e298c3",
    "FW-live-output-ancestor-symlink": "99b90523befffb894d35c214d384fcf8ab3538fceb58ce48897ddd99b07f6da6",
    "FW-live-explicit-output-a-b-a": "c855298f69ddbae6300f747fa9cd9ecc7e99dee48c641f6c7ebcf5a9076cd7e3",
    "FW-live-explicit-output-persistent-substitution": "391f52fcd77efc701d3c57d368d472dc5f102234574d2460f3276852fffa6545",
    "FW-wrapper-json-unsafe-targets": "d9302ad40390b92312328fa55f9cd10d3bdddac8392cadfe76d662e82c408eb7",
    "FW-wrapper-json-parent-substitution": "d2a7a8ab99d33356bc7a8b1e077d010171081c7accb32af51a1e009656c47b50",
    "FW-formal-temporal-cap": "064a3d551e56979f44517336d3b4c1e62a1e82f7079ac9887003c840b0c93178",
    "TW-formal-valid-role-direction": "950fae052f3528695ed2ecb6a422510db7e4ce2439a986f2be6f2faea8ada2dd",
    "TW-formal-held-dirfd-ordinary-output": "d63c0014ce53a7b207dd37479ae99365e4aa109166ecb1dcf09c7b9e1837f669",
    "TW-live-explicit-output-early-capability": "d80874747bdb2a3254be2d2df055f87b09cc67b2572db76efe71c07d707a450f",
    "TW-wrapper-json-held-output": "785a1dabf1d14d3f397a08f48a3f3d0ce377756b84b87cb2785361e02b9236a8",
    "TW-wrapper-json-early-capability": "86d7a4954a33e38e70b444041826e62581c5b93f61714d8b7c97d5e53ee75b91",
    "FW-promotion-auto-closure": "9cf69fd3dd172d167834dd2c688320291ffc7d01d3d14ea1dcd90b2b098c556b",
    "FW-promotion-missing-trace": "a67ffc90ff5c3e9b65382dc422a39ffba2efdaa6b94676c5fa43658c89f2a18b",
    "FW-promotion-unsafe-output": "b02b8552996b6ca50af3aa89854c20b2acc45f0399c01fe3bc459934b35943b9",
    "FW-promotion-self-attested-output-check": "7d7a225d39b5daa9fa1163d02d6df2c829315f77a5be6c80890651217416b214",
    "FW-promotion-empty-formal-output": "4d33b9b11768290e652730988f35e88c4a82e657801d0d44f7e023ce117c7429",
    "FW-promotion-coordinator-result-identity": "1d215c25ba7558f3d35eb45b82ab68c7ef1644780dbc92fc33876a3d10f22ea9",
    "FW-promotion-coordinator-argv-identity": "18fdec7c2f1e3cd8cfca14e5d5b559a531b86660e8a7f8efbdc8bdbea562bd0b",
    "FW-certifier-json-markdown-alias": "6584eb861f92638a0f7a07ae11b82667f3ede80efd8a6d33a984ace037f58a80",
    "FW-certifier-parent-substitution": "9e81155384dc3d4d4a18d5c09ad408085acddf09bbf7c893a2a65b3cd3621036",
    "TW-promotion-capped-baseline": "79f2b9bd21edd25b9363a50df19c0e46c51c864d2241dd09630e691ec2745176",
    "TW-certifier-distinct-outputs": "a8687b111cdb80a34358384542f0bec9eb39650cda4d50a62a6d3bdca919f63c",
    "FW-github-readmes-degraded": "00eed35d0430228514dbb88a09217f4e3ef7f91e4ba27ab4c9aad18356591d79",
    "TW-github-readmes-benign-note": "11256f4dc9f457a53f85307faa5af7d7e54fb8d05c611757cc22f174dcd299f8",
    "FW-charter-sweep-removed": "9aa6efa23770499d8a83a9783111910d2bd88579f89dc3b6cc3ecc9e2f22b8cf",
    "FW-charter-remote-fields-removed": "2b97a840cb6ca97ecb7f737f547427197a7c07d01150b49998c825aaaa337ebc",
    "TW-charter-intact": "3545392d01961c4cec1ad9278959853c829073f76784a78999ecde29632cbe55",
}
OBSERVATION_LEDGER_FIELDS = frozenset({
    "observation_schema_version",
    "observations",
})
OBSERVATION_RECORD_FIELDS = frozenset({
    "claim_id",
    "test_id",
    "kind",
    "claim_proposition_sha256",
    "claim_contract_sha256",
    "modal_case_sha256",
    "result",
    "outcome",
    "observed_result",
})
PROPOSITION_BINDING_SCHEMA_VERSION = "1.0"
MAX_CERTIFICATE_DEPTH = 128
MAX_CERTIFICATE_NODES = 100_000
MAX_CERTIFICATE_FIELDS = 100_000
MAX_CERTIFICATE_BYTES = 8_388_608
MAX_EVIDENCE_WRAPPER_BYTES = 1_048_576
MAX_OBSERVATION_LEDGER_BYTES = 8_388_608
MAX_EVIDENCE_ARTIFACT_BYTES = 67_108_864
MAX_EVIDENCE_JSON_DEPTH = 64
MAX_EVIDENCE_JSON_NODES = 100_000
MAX_EVIDENCE_JSON_FIELDS = 100_000
DOWNSTREAM_PASS_STATUSES = {"pass", "passed", "verified", "confirmed", "pass-tracked", "pass-scoped", "pass_tracked", "pass_scoped"}
DOWNSTREAM_NONPASS_STATUSES = {
    "unverified",
    "unknown",
    "fail",
    "failed",
    "rejected",
    "limited",
    "blocked",
    "withheld",
    "not-certified",
    "not_certified",
}
DOWNSTREAM_STATUSES = DOWNSTREAM_PASS_STATUSES | DOWNSTREAM_NONPASS_STATUSES


@dataclass(frozen=True)
class DownstreamPolicy:
    """Policy controls for the shared non-closure evaluator."""

    name: str = "generic"
    require_records: bool = False
    require_review: bool = False
    require_own_claim_field: bool = False


DOWNSTREAM_POLICIES = {
    "generic": DownstreamPolicy(),
    "package-self": DownstreamPolicy(
        name="package-self",
        require_records=True,
    ),
    "promotion-v2": DownstreamPolicy(
        name="promotion-v2",
        require_review=True,
        require_own_claim_field=True,
    ),
}


class InvalidInputError(ValueError):
    """Expected malformed-input error safe to expose without a traceback."""

@dataclass
class EvidenceCheck:
    ref: str
    exists: bool
    structured: bool
    reasons: List[str]
    canonical_ref: Optional[str] = None
    artifact_identity: str = ""
    artifact_path_resolved: Optional[str] = None
    artifact_sha256: Optional[str] = None
    observation_id: str = ""
    wrapper_sha256: str = ""
    modal_case_sha256: str = ""


@dataclass(frozen=True)
class BoundedJsonResult:
    data: Any = None
    sha256: str = ""
    reason: str = ""


@dataclass
class EvidenceRootCapability:
    """A held directory descriptor defining the evidence-root boundary."""

    path: Path
    descriptor: int

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


@dataclass(frozen=True)
class ResolvedEvidenceFile:
    """A canonical relative file addressed through a held root capability."""

    root: EvidenceRootCapability
    relative: str

    @property
    def display_path(self) -> Path:
        return self.root.path / PurePosixPath(self.relative)

    def __str__(self) -> str:
        return str(self.display_path)


JsonCacheKey = Tuple[str, int, str, int, int, int]


class DuplicateJsonKeyError(ValueError):
    """A JSON object repeats a key and is therefore semantically ambiguous."""


def _strict_json_object(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    value: Dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateJsonKeyError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def strict_json_loads(text: str) -> Any:
    def reject_nonfinite(value: str) -> Any:
        raise ValueError(f"non-finite JSON number is not allowed: {value}")

    def parse_finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            reject_nonfinite(value)
        return parsed

    return json.loads(
        text,
        object_pairs_hook=_strict_json_object,
        parse_constant=reject_nonfinite,
        parse_float=parse_finite_float,
    )

@dataclass
class TestResult:
    test_id: str
    kind: str
    status: str
    reasons: List[str]
    evidence_checks: List[EvidenceCheck]

@dataclass
class ClaimResult:
    claim_id: str
    importance: str
    status: str
    reasons: List[str]
    sensitivity_rate: float
    adherence_rate: float
    method_completeness: float
    evidence_count: int
    structured_evidence_count: int
    false_world_tests: int
    true_world_tests: int
    test_results: List[TestResult]
    unique_evidence_count: int = 0
    unique_structured_evidence_count: int = 0
    unique_artifact_count: int = 0


def _nonempty(v: Any) -> bool:
    if v is None: return False
    if isinstance(v, str): return bool(v.strip()) and v.strip().lower() not in UNKNOWN
    if isinstance(v, (list, tuple, set, dict)): return bool(v)
    return True


def _as_list(v: Any) -> List[Any]:
    if v is None: return []
    return v if isinstance(v, list) else [v]


def _lower(v: Any) -> str:
    return str(v or "").strip().lower()


def normalize_cli_display(value: Any, package_root: Optional[Path]) -> Any:
    """Normalize only serialized CLI/report values, not gate evaluation state."""
    if package_root is None:
        return value
    try:
        root_text = str(package_root.resolve())
    except (OSError, RuntimeError, ValueError):
        root_text = str(package_root)
    if isinstance(value, str):
        return re.sub(
            re.escape(root_text) + r"(?=$|[\\/])",
            lambda _match: "<package-root>",
            value,
        )
    if isinstance(value, list):
        return [normalize_cli_display(item, package_root) for item in value]
    if isinstance(value, tuple):
        return [normalize_cli_display(item, package_root) for item in value]
    if isinstance(value, Mapping):
        return {
            key: normalize_cli_display(item, package_root)
            for key, item in value.items()
        }
    return value


def _unknown_item(v: Any) -> bool:
    """Return whether an unknown-bearing field declares a real limitation.

    Sentinel-looking text is still an unknown when it occurs inside an
    ``unknowns``/``method_unknowns``/``scope_limitations`` collection. The
    canonical representation for "no unknowns" is an empty collection, not a
    magic word such as ``unknown``, ``none``, or ``n/a``.
    """
    # Once an item is present in an unknown-bearing collection it declares a
    # limitation, even when its shape is malformed or its text resembles a
    # placeholder. The only canonical representation for no limitations is an
    # empty list.
    del v
    return True


def _unknown_collection_shape_error(cert: Mapping[str, Any]) -> Optional[str]:
    """Require unknown-bearing fields to use the canonical list container."""
    for field in ("scope_limitations", "unknowns", "method_unknowns"):
        if field in cert and type(cert.get(field)) is not list:
            return f"certificate {field} is not a list"
    method_roots: List[Tuple[str, Any]] = [
        ("method_manifest", cert.get("method_manifest"))
    ]
    claims = cert.get("claims")
    if isinstance(claims, list):
        for index, claim in enumerate(claims):
            if isinstance(claim, Mapping):
                method_roots.append(
                    (
                        f"claims[{index}].method",
                        claim.get("method_m", claim.get("method")),
                    )
                )
    for root_name, root in method_roots:
        stack: List[Tuple[str, Any]] = [(root_name, root)]
        while stack:
            path, node = stack.pop()
            if isinstance(node, Mapping):
                for key, value in node.items():
                    child_path = f"{path}.{key}"
                    if key in {"unknowns", "method_unknowns"}:
                        if type(value) is not list:
                            return f"{child_path} is not a list"
                    else:
                        stack.append((child_path, value))
            elif isinstance(node, list):
                stack.extend((f"{path}[]", value) for value in node)
    return None


def _validate_json_bounds(
    root: Any,
    *,
    max_depth: int = MAX_CERTIFICATE_DEPTH,
    max_nodes: int = MAX_CERTIFICATE_NODES,
    max_fields: int = MAX_CERTIFICATE_FIELDS,
    label: str = "certificate",
) -> Optional[str]:
    """Reject non-JSON, cyclic, over-deep, or oversized input.

    Once this succeeds, security-sensitive walks can be exhaustive without a
    caller-controlled recursion limit or unbounded resource consumption.
    Reused object identities are permitted when they are not on the active
    traversal path; each occurrence still consumes the node/field budget.
    """
    stack: List[Tuple[Any, int, bool]] = [(root, 0, False)]
    active_containers: set[int] = set()
    nodes = 0
    fields = 0
    while stack:
        node, depth, exiting = stack.pop()
        if exiting:
            active_containers.discard(id(node))
            continue
        nodes += 1
        if nodes > max_nodes:
            return (
                f"{label} exceeds maximum JSON node count "
                f"{max_nodes}"
            )
        if depth > max_depth:
            return (
                f"{label} exceeds maximum JSON depth "
                f"{max_depth}"
            )
        if isinstance(node, Mapping):
            identity = id(node)
            if identity in active_containers:
                return f"{label} contains a cyclic JSON object"
            active_containers.add(identity)
            if any(type(key) is not str for key in node):
                return f"{label} JSON object contains a non-string key"
            fields += len(node)
            if fields > max_fields:
                return (
                    f"{label} exceeds maximum JSON field count "
                    f"{max_fields}"
                )
            stack.append((node, depth, True))
            stack.extend(
                (value, depth + 1, False) for value in node.values()
            )
        elif isinstance(node, list):
            identity = id(node)
            if identity in active_containers:
                return f"{label} contains a cyclic JSON array"
            active_containers.add(identity)
            stack.append((node, depth, True))
            stack.extend((value, depth + 1, False) for value in node)
        elif node is None or type(node) in {str, bool, int}:
            continue
        elif type(node) is float:
            if not math.isfinite(node):
                return f"{label} contains a non-finite JSON number"
        else:
            return (
                f"{label} contains a non-JSON value of type "
                f"{type(node).__name__}"
            )
    return None


def _collect_unknowns_in_method(root: Any) -> List[Any]:
    found: List[Any] = []
    stack: List[Any] = [root]
    while stack:
        node = stack.pop()
        if isinstance(node, Mapping):
            for key, value in node.items():
                if key in ("unknowns", "method_unknowns"):
                    found.extend(
                        item for item in _as_list(value) if _unknown_item(item)
                    )
                else:
                    stack.append(value)
        elif isinstance(node, list):
            stack.extend(node)
    return found


def _collect_method_unknowns(cert: Mapping[str, Any]) -> List[Any]:
    """Exhaustively collect unknowns from every declared method scope."""
    found = _collect_unknowns_in_method(cert.get("method_manifest"))
    raw_claims = cert.get("claims")
    if isinstance(raw_claims, list):
        for claim in raw_claims:
            if isinstance(claim, Mapping):
                found.extend(
                    _collect_unknowns_in_method(
                        claim.get("method_m", claim.get("method"))
                    )
                )
    for key in ("unknowns", "method_unknowns"):
        found.extend(
            item for item in _as_list(cert.get(key)) if _unknown_item(item)
        )
    return found


def load_json(path: Path) -> Any:
    result = _bounded_json_read(
        path,
        max_bytes=MAX_CERTIFICATE_BYTES,
        label="certificate",
        max_depth=MAX_CERTIFICATE_DEPTH,
        max_nodes=MAX_CERTIFICATE_NODES,
        max_fields=MAX_CERTIFICATE_FIELDS,
    )
    if result.reason:
        raise InvalidInputError(result.reason)
    return result.data


def _open_evidence_root_capability(path: Path) -> EvidenceRootCapability:
    """Open one stable no-follow evidence-root endpoint and hold it."""
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise OSError("platform lacks no-follow directory traversal")
    before = os.lstat(path)
    if stat.S_ISLNK(before.st_mode):
        raise OSError("evidence_root must not be a symlink")
    if not stat.S_ISDIR(before.st_mode):
        raise OSError("evidence_root is not an existing directory")
    flags = os.O_RDONLY | nofollow | directory
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISDIR(opened.st_mode):
            raise OSError("evidence_root is not a directory")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise OSError("evidence_root changed before open")
        return EvidenceRootCapability(Path(os.path.abspath(path)), descriptor)
    except BaseException:
        os.close(descriptor)
        raise


def _open_resolved_evidence_file(path: ResolvedEvidenceFile) -> int:
    """Open every relative component beneath the held root with O_NOFOLLOW."""
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise OSError("platform lacks no-follow directory traversal")
    if path.root.descriptor < 0:
        raise OSError("evidence_root capability is closed")
    common = os.O_RDONLY | nofollow
    if hasattr(os, "O_CLOEXEC"):
        common |= os.O_CLOEXEC
    descriptor = os.dup(path.root.descriptor)
    try:
        parts = PurePosixPath(path.relative).parts
        for part in parts[:-1]:
            child = os.open(
                part,
                common | directory,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        final_descriptor = os.open(
            parts[-1],
            common,
            dir_fd=descriptor,
        )
        os.close(descriptor)
        descriptor = -1
        metadata = os.fstat(final_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            os.close(final_descriptor)
            raise OSError("resolved evidence path is not a regular file")
        return final_descriptor
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _resolved_evidence_stat(path: ResolvedEvidenceFile) -> os.stat_result:
    descriptor = _open_resolved_evidence_file(path)
    try:
        return os.fstat(descriptor)
    finally:
        os.close(descriptor)


def sha256_path(
    path: Path | ResolvedEvidenceFile,
    *,
    max_bytes: Optional[int] = None,
) -> str:
    """Hash one stable regular file without following a swapped-in symlink."""
    if max_bytes is not None and (
        type(max_bytes) is not int or max_bytes < 0
    ):
        raise ValueError("max_bytes must be a nonnegative integer")
    descriptor: Optional[int] = None
    try:
        before: Optional[os.stat_result] = None
        if isinstance(path, ResolvedEvidenceFile):
            descriptor = _open_resolved_evidence_file(path)
        else:
            before = os.lstat(path)
            if not stat.S_ISREG(before.st_mode):
                raise OSError("path is not a regular file")
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise OSError("opened path is not a regular file")
        if max_bytes is not None and opened.st_size > max_bytes:
            raise ValueError(f"file exceeds byte limit {max_bytes}")
        if before is not None and (
            (opened.st_dev, opened.st_ino)
            != (before.st_dev, before.st_ino)
        ):
            raise OSError("path changed before hash read")
        digest = hashlib.sha256()
        observed_bytes = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            observed_bytes += len(chunk)
            if max_bytes is not None and observed_bytes > max_bytes:
                raise ValueError(f"file exceeds byte limit {max_bytes}")
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        ):
            raise OSError("path changed during hash read")
        return digest.hexdigest()
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _bounded_json_read(
    path: Path | ResolvedEvidenceFile,
    *,
    max_bytes: int,
    label: str,
    max_depth: int = MAX_EVIDENCE_JSON_DEPTH,
    max_nodes: int = MAX_EVIDENCE_JSON_NODES,
    max_fields: int = MAX_EVIDENCE_JSON_FIELDS,
    cache: Optional[Dict[JsonCacheKey, BoundedJsonResult]] = None,
) -> BoundedJsonResult:
    """Read one regular non-symlink JSON file once under explicit bounds."""
    cache_key = (
        str(path),
        max_bytes,
        label,
        max_depth,
        max_nodes,
        max_fields,
    )
    if cache is not None and cache_key in cache:
        return cache[cache_key]

    def finish(result: BoundedJsonResult) -> BoundedJsonResult:
        if cache is not None:
            cache[cache_key] = result
        return result

    descriptor: Optional[int] = None
    try:
        before: Optional[os.stat_result] = None
        if isinstance(path, ResolvedEvidenceFile):
            descriptor = _open_resolved_evidence_file(path)
        else:
            before = os.lstat(path)
            if not stat.S_ISREG(before.st_mode):
                return finish(BoundedJsonResult(reason=f"{label} is not a regular file"))
            if before.st_size > max_bytes:
                return finish(
                    BoundedJsonResult(
                        reason=f"{label} exceeds byte limit {max_bytes}"
                    )
                )
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            return finish(BoundedJsonResult(reason=f"{label} is not a regular file"))
        if before is not None and (
            (opened.st_dev, opened.st_ino)
            != (before.st_dev, before.st_ino)
        ):
            return finish(BoundedJsonResult(reason=f"{label} changed before read"))
        if opened.st_size > max_bytes:
            return finish(
                BoundedJsonResult(
                    reason=f"{label} exceeds byte limit {max_bytes}"
                )
            )
        raw = bytearray()
        while len(raw) <= max_bytes:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, max_bytes + 1 - len(raw)),
            )
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        if len(raw) > max_bytes:
            return finish(
                BoundedJsonResult(
                    reason=f"{label} exceeds byte limit {max_bytes}"
                )
            )
        if (
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        ):
            return finish(BoundedJsonResult(reason=f"{label} changed during read"))
        raw_bytes = bytes(raw)
        try:
            text = raw_bytes.decode("utf-8")
            data = strict_json_loads(text)
        except (
            UnicodeError,
            ValueError,
            RecursionError,
            MemoryError,
            OverflowError,
        ) as exc:
            return finish(
                BoundedJsonResult(
                    reason=f"{label} JSON parse failed: {type(exc).__name__}"
                )
            )
        bounds_error = _validate_json_bounds(
            data,
            max_depth=max_depth,
            max_nodes=max_nodes,
            max_fields=max_fields,
            label=label,
        )
        if bounds_error is not None:
            return finish(BoundedJsonResult(reason=bounds_error))
        return finish(
            BoundedJsonResult(
                data=data,
                sha256=hashlib.sha256(raw_bytes).hexdigest(),
            )
        )
    except (
        OSError,
        RuntimeError,
        ValueError,
        RecursionError,
        MemoryError,
        OverflowError,
    ) as exc:
        return finish(
            BoundedJsonResult(
                reason=f"{label} read failed: {type(exc).__name__}"
            )
        )
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _canonical_claimed_sha256(value: Any) -> Optional[str]:
    if type(value) is not str:
        return None
    raw = value.strip()
    if raw.startswith("sha256:"):
        raw = raw.split(":", 1)[1].strip()
    elif raw.startswith("sha256="):
        raw = raw.split("=", 1)[1].strip()
    if re.fullmatch(r"[0-9a-fA-F]{64}", raw):
        return raw.lower()
    return None


def _artifact_under_root(
    artifact_path: Any,
    evidence_root: Optional[Path | EvidenceRootCapability],
) -> Tuple[Optional[Path | ResolvedEvidenceFile], Optional[str]]:
    if evidence_root is None:
        return None, "evidence_root unavailable for artifact hash verification"
    rel, canonical_error = _canonical_relative_path(
        artifact_path,
        "artifact_path",
    )
    if canonical_error is not None or rel is None:
        return None, canonical_error
    scheme = (urlparse(rel).scheme or "").strip()
    if scheme:
        return None, "artifact_path URI schemes are not allowed in strict local evidence mode"
    return _resolve_regular_under_root(
        rel,
        evidence_root,
        "artifact_path",
    )


def _verify_artifact_sha256(
    data: Mapping[str, Any],
    evidence_root: Optional[Path | EvidenceRootCapability],
) -> Tuple[List[str], Optional[ResolvedEvidenceFile | Path], Optional[str]]:
    """Verify structured evidence provenance and return artifact identity.

    For PASS-TRACKED evidence, hash_or_version must be an actual SHA-256 digest
    of artifact_path under evidence_root. The resolved artifact path and actual
    digest are returned so strict evidence thresholds can count unique underlying
    artifacts rather than repeated wrappers or aliases.
    """
    reasons: List[str] = []
    artifact, err = _artifact_under_root(data.get("artifact_path"), evidence_root)
    if err:
        reasons.append(err)
        return reasons, None, None
    claimed = _canonical_claimed_sha256(data.get("hash_or_version"))
    if claimed is None:
        reasons.append("hash_or_version must be a SHA-256 digest, optionally prefixed by sha256:")
        return reasons, artifact, None
    try:
        artifact_limit = (
            MAX_OBSERVATION_LEDGER_BYTES
            if data.get("observation_id") is not None
            else MAX_EVIDENCE_ARTIFACT_BYTES
        )
        actual = sha256_path(artifact, max_bytes=artifact_limit)
    except (OSError, RuntimeError, ValueError) as exc:
        reasons.append(
            "artifact_path SHA-256 read failed: "
            f"{type(exc).__name__}: {exc}"
        )
        return reasons, artifact, None
    if actual != claimed:
        reasons.append(f"hash_or_version does not match artifact_path SHA-256: claimed={claimed} actual={actual}")
    return reasons, artifact, actual


def _verify_observation_binding(
    data: Mapping[str, Any],
    artifact_path_resolved: Optional[ResolvedEvidenceFile | Path],
    artifact_sha256: Optional[str],
    claim_id: Optional[str],
    test_id: Optional[str],
    test_kind: Optional[str],
    claim_proposition_sha256: Optional[str],
    claim_contract_sha256: Optional[str],
    modal_case_sha256: Optional[str],
    expected_outcome: Optional[str],
    json_cache: Optional[
        Dict[JsonCacheKey, BoundedJsonResult]
    ] = None,
) -> Tuple[List[str], str]:
    """Verify an optional case-level observation inside a hashed JSON ledger.

    Distinct evidence wrappers over one aggregate file are not independent by
    themselves. A wrapper may name a declaration only when the hashed artifact
    contains an exact claim/test/kind-bound release record. The record is a
    deduplication identity, not execution provenance or a claim that a named
    suite result was reconciled to this modal case.
    """
    raw_observation_id = data.get("observation_id")
    if raw_observation_id is None:
        return [], ""
    if (
        type(raw_observation_id) is not str
        or raw_observation_id != raw_observation_id.strip()
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", raw_observation_id)
    ):
        return ["observation_id is not a canonical bounded identifier"], ""
    observation_id = raw_observation_id
    if not artifact_path_resolved:
        return ["observation_id cannot be verified without artifact_path"], ""
    ledger_result = _bounded_json_read(
        artifact_path_resolved,
        max_bytes=MAX_OBSERVATION_LEDGER_BYTES,
        label="observation ledger",
        cache=json_cache,
    )
    if ledger_result.reason:
        raise InvalidInputError(ledger_result.reason)
    if artifact_sha256 and ledger_result.sha256 != artifact_sha256:
        return [
            "observation ledger changed between artifact hashing and JSON read"
        ], ""
    ledger = ledger_result.data
    if not isinstance(ledger, Mapping):
        return ["observation ledger JSON is not an object"], ""
    if ledger.get("observation_schema_version") != OBSERVATION_SCHEMA_VERSION:
        return [
            "observation ledger schema is not "
            f"{OBSERVATION_SCHEMA_VERSION}"
        ], ""
    ledger_fields = set(ledger)
    if ledger_fields != OBSERVATION_LEDGER_FIELDS:
        missing = sorted(OBSERVATION_LEDGER_FIELDS - ledger_fields)
        extra = sorted(ledger_fields - OBSERVATION_LEDGER_FIELDS)
        return [
            "observation ledger fields are not exact for schema "
            f"{OBSERVATION_SCHEMA_VERSION}: missing={missing}; extra={extra}"
        ], ""
    observations = ledger.get("observations")
    if not isinstance(observations, Mapping):
        return ["observation ledger lacks an observations object"], ""
    # The schema is closed for the complete ledger, not merely the selected
    # record. Otherwise unsupported provenance claims can be hidden in an
    # unreferenced sibling while one valid record authenticates the artifact.
    for candidate_id in sorted(observations):
        if (
            type(candidate_id) is not str
            or candidate_id != candidate_id.strip()
            or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",
                candidate_id,
            )
        ):
            return [
                "observation ledger contains a noncanonical record identifier"
            ], ""
        candidate = observations.get(candidate_id)
        if not isinstance(candidate, Mapping):
            return [
                f"observation {candidate_id} is not an object"
            ], ""
        candidate_fields = set(candidate)
        if candidate_fields != OBSERVATION_RECORD_FIELDS:
            missing = sorted(
                OBSERVATION_RECORD_FIELDS - candidate_fields
            )
            extra = sorted(
                candidate_fields - OBSERVATION_RECORD_FIELDS
            )
            return [
                f"observation {candidate_id} fields are not exact for schema "
                f"{OBSERVATION_SCHEMA_VERSION}: missing={missing}; "
                f"extra={extra}"
            ], ""
        non_string_fields = sorted(
            field
            for field in OBSERVATION_RECORD_FIELDS
            if type(candidate.get(field)) is not str
        )
        if non_string_fields:
            return [
                f"observation {candidate_id} fields must all be strings: "
                f"{non_string_fields}"
            ], ""
        for identity_field in ("claim_id", "test_id"):
            identity_value = candidate.get(identity_field)
            if (
                not identity_value
                or identity_value != identity_value.strip()
                or len(identity_value) > 256
            ):
                return [
                    f"observation {candidate_id} {identity_field} is not a "
                    "canonical bounded identifier"
                ], ""
        candidate_kind = _lower(candidate.get("kind"))
        if candidate_kind not in {"false_world", "true_world"}:
            return [
                f"observation {candidate_id} kind is not recognized"
            ], ""
        for digest_field in (
            "claim_proposition_sha256",
            "claim_contract_sha256",
            "modal_case_sha256",
        ):
            if _canonical_claimed_sha256(
                candidate.get(digest_field)
            ) is None:
                return [
                    f"observation {candidate_id} {digest_field} is not a "
                    "canonical SHA-256"
                ], ""
        if _lower(candidate.get("result")) != "pass":
            return [
                f"observation {candidate_id} result is not pass"
            ], ""
        candidate_outcome = _lower(candidate.get("outcome"))
        candidate_outcomes = (
            FALSE_OUTCOMES
            if candidate_kind == "false_world"
            else TRUE_OUTCOMES
        )
        if candidate_outcome not in candidate_outcomes:
            return [
                f"observation {candidate_id} outcome is not accepted for "
                f"{candidate_kind}"
            ], ""
        if len(str(candidate.get("observed_result") or "").strip()) < 10:
            return [
                f"observation {candidate_id} observed_result is too short"
            ], ""
    record = observations.get(observation_id)
    if not isinstance(record, Mapping):
        return [
            f"observation ledger lacks record {observation_id}"
        ], ""
    reasons: List[str] = []
    expected_bindings = {
        "claim_id": claim_id,
        "test_id": test_id,
        "kind": test_kind,
    }
    for field, expected in expected_bindings.items():
        if expected is not None and record.get(field) != expected:
            reasons.append(
                f"observation {observation_id} {field} does not match {expected}"
            )
    for field, expected in (
        ("claim_proposition_sha256", claim_proposition_sha256),
        ("claim_contract_sha256", claim_contract_sha256),
        ("modal_case_sha256", modal_case_sha256),
    ):
        if expected is not None and _canonical_claimed_sha256(
            record.get(field)
        ) != expected:
            reasons.append(
                f"observation {observation_id} {field} does not match"
            )
    if _lower(record.get("result")) != "pass":
        reasons.append(f"observation {observation_id} result is not pass")
    outcome = _lower(record.get("outcome"))
    accepted_outcomes = (
        FALSE_OUTCOMES if test_kind == "false_world" else TRUE_OUTCOMES
    )
    if outcome not in accepted_outcomes:
        reasons.append(
            f"observation {observation_id} outcome is not accepted for {test_kind}"
        )
    if expected_outcome is not None and outcome != expected_outcome:
        reasons.append(
            f"observation {observation_id} outcome does not match "
            "world_contract expected_outcome"
        )
    ledger_observed = str(record.get("observed_result") or "").strip()
    wrapper_observed = str(data.get("observed_result") or "").strip()
    if len(ledger_observed) < 10:
        reasons.append(
            f"observation {observation_id} observed_result is too short"
        )
    elif ledger_observed != wrapper_observed:
        reasons.append(
            f"observation {observation_id} observed_result does not match evidence wrapper"
        )
    return reasons, observation_id if not reasons else ""

def _canonical_relative_path(
    value: Any,
    field: str,
) -> Tuple[Optional[str], Optional[str]]:
    """Require an already-canonical relative POSIX path before resolution."""
    if type(value) is not str or not value:
        return None, f"{field} is empty or not a string"
    if value != value.strip():
        return None, f"{field} has surrounding whitespace"
    if any(
        ord(character) < 32
        or ord(character) == 127
        or unicodedata.category(character) == "Cc"
        for character in value
    ):
        return None, f"{field} contains a NUL or control character"
    if "\\" in value:
        return None, f"{field} uses a non-canonical separator"
    if "::" in value:
        return None, f"{field} uses an unsupported alias suffix"
    if _is_remote_ref(value):
        return None, (
            f"{field} URI schemes are not allowed in strict local evidence mode"
        )
    posix = PurePosixPath(value)
    if posix.is_absolute():
        return None, f"{field} must be relative to evidence_root"
    if (
        not posix.parts
        or any(part in {"", ".", ".."} for part in posix.parts)
        or posix.as_posix() != value
    ):
        return None, f"{field} is not a canonical relative POSIX path"
    return value, None


def _resolve_regular_under_root(
    relative: str,
    evidence_root: Path | EvidenceRootCapability,
    field: str,
) -> Tuple[Optional[Path | ResolvedEvidenceFile], Optional[str]]:
    """Resolve a canonical relative path without following in-root symlinks."""
    if isinstance(evidence_root, EvidenceRootCapability):
        resolved = ResolvedEvidenceFile(evidence_root, relative)
        descriptor: Optional[int] = None
        try:
            descriptor = _open_resolved_evidence_file(resolved)
            return resolved, None
        except FileNotFoundError:
            return None, f"{field} is not an existing local file"
        except (OSError, RuntimeError, ValueError) as exc:
            return None, f"{field} resolution failed: {type(exc).__name__}"
        finally:
            if descriptor is not None:
                os.close(descriptor)
    try:
        root = evidence_root.resolve(strict=True)
        root_stat = os.stat(root, follow_symlinks=False)
        if not stat.S_ISDIR(root_stat.st_mode):
            return None, "evidence_root is not a directory"
        current = root
        parts = PurePosixPath(relative).parts
        for index, part in enumerate(parts):
            current = current / part
            entry = os.lstat(current)
            if stat.S_ISLNK(entry.st_mode):
                return None, f"{field} traverses a symlink"
            if index < len(parts) - 1 and not stat.S_ISDIR(entry.st_mode):
                return None, f"{field} parent is not a directory"
        final = os.lstat(current)
        if not stat.S_ISREG(final.st_mode):
            return None, f"{field} does not identify a regular file"
        current.relative_to(root)
        return current, None
    except FileNotFoundError:
        return None, f"{field} is not an existing local file"
    except (OSError, RuntimeError, ValueError) as exc:
        return None, f"{field} resolution failed: {type(exc).__name__}"


def _raw_ref(ref: Any) -> str:
    return ref if type(ref) is str else ""


def _is_remote_ref(raw: str) -> bool:
    """Return True for any URI-scheme evidence ref in strict local mode.

    URI schemes are case-insensitive, so HTTPS://, hTtPs://, DOI:, and URN:
    must be treated the same as their lowercase forms. For strict local
    evidence, reject any non-empty URI scheme rather than maintaining an
    allowlist that can be bypassed by case or obscure schemes.
    """
    parsed = urlparse(str(raw or ""))
    scheme = (parsed.scheme or "").strip().lower()
    if scheme:
        return True
    return False


def _ref_to_path(ref: Any, evidence_root: Optional[Path]) -> Optional[Path]:
    """Backward-compatible unchecked resolver for non-strict callers.

    Strict local-evidence mode must use _ref_to_path_checked so path traversal,
    absolute paths, remote refs, and missing files become explicit failures.
    """
    if evidence_root is None:
        return None
    raw = _raw_ref(ref)
    if not raw or _is_remote_ref(raw):
        return None
    p = Path(raw)
    return p if p.is_absolute() else evidence_root / p


def _ref_to_path_checked(
    ref: Any,
    evidence_root: Path | EvidenceRootCapability,
) -> Tuple[Optional[Path | ResolvedEvidenceFile], Optional[str]]:
    """Resolve a cited evidence JSON path under evidence_root.

    This is deliberately stricter than merely checking artifact_path inside an
    evidence JSON. The evidence JSON file itself is part of the provenance
    boundary; strict local evidence rejects remote refs, absolute paths, path
    traversal, directories, and missing/empty files.
    """
    raw, canonical_error = _canonical_relative_path(ref, "evidence ref")
    if canonical_error is not None or raw is None:
        return None, canonical_error
    resolved, resolution_error = _resolve_regular_under_root(
        raw,
        evidence_root,
        "evidence ref",
    )
    if resolution_error is not None or resolved is None:
        return None, resolution_error
    try:
        metadata = (
            _resolved_evidence_stat(resolved)
            if isinstance(resolved, ResolvedEvidenceFile)
            else os.stat(resolved, follow_symlinks=False)
        )
        if metadata.st_size <= 0:
            return None, "evidence ref is empty"
    except (OSError, ValueError) as exc:
        return None, f"evidence ref stat failed: {type(exc).__name__}"
    return resolved, None


def _canonical_evidence_key(ref: Any, evidence_root: Optional[Path]) -> str:
    """Canonicalize raw refs, including :: aliases, to resolved evidence-file identity.

    Strict evidence sufficiency must count unique local provenance files, not
    repeated raw strings or alias-decorated refs that resolve to the same JSON.
    Invalid refs remain unique invalid sentinels so separate invalid-ref reasons
    are still reported while thresholds cannot be satisfied by duplicates.
    """
    if evidence_root is None:
        return str(ref or "")
    path, err = _ref_to_path_checked(ref, evidence_root)
    if err or path is None:
        return f"<invalid:{str(ref or '')}>"
    return str(path)


def _evidence_exists(ref: Any, evidence_root: Optional[Path]) -> bool:
    if evidence_root is None:
        return True
    path, err = _ref_to_path_checked(ref, evidence_root)
    return err is None and bool(path)


def _matches_claim(data: Mapping[str, Any], claim_id: Optional[str]) -> bool:
    if not claim_id:
        return True
    cid = str(data.get("claim_id") or "")
    if cid == claim_id:
        return True
    applies = [str(x) for x in _as_list(data.get("applies_to_claims"))]
    return "*" in applies or claim_id in applies


def _matches_test(data: Mapping[str, Any], test_id: Optional[str]) -> bool:
    if not test_id:
        return True
    tid = str(data.get("test_id") or "")
    if tid == test_id:
        return True
    applies = [str(x) for x in _as_list(data.get("applies_to_tests"))]
    return "*" in applies or test_id in applies


def _load_structured_evidence(
    ref: Any,
    evidence_root: Optional[Path],
    claim_id: Optional[str] = None,
    claim_proposition: Any = None,
    claim_contract_sha256: Optional[str] = None,
    test_id: Optional[str] = None,
    test_kind: Optional[str] = None,
    modal_test: Optional[Mapping[str, Any]] = None,
    json_cache: Optional[
        Dict[JsonCacheKey, BoundedJsonResult]
    ] = None,
) -> EvidenceCheck:
    ref_s = str(ref or "")
    reasons: List[str] = []
    if evidence_root is None:
        # Without a local evidence root, the deterministic gate can only check
        # declared certificate structure. Do not report existence or structured
        # verification for an unchecked string.
        return EvidenceCheck(
            ref_s,
            False,
            False,
            ["local evidence was not checked without evidence_root"],
        )
    path, err = _ref_to_path_checked(ref, evidence_root)
    if err:
        return EvidenceCheck(ref_s, False, False, [err])
    assert path is not None
    canonical_ref = str(path)
    wrapper_result = _bounded_json_read(
        path,
        max_bytes=MAX_EVIDENCE_WRAPPER_BYTES,
        label="structured evidence wrapper",
        cache=json_cache,
    )
    if wrapper_result.reason:
        raise InvalidInputError(wrapper_result.reason)
    data = wrapper_result.data
    if not isinstance(data, Mapping):
        return EvidenceCheck(ref_s, True, False, ["structured evidence JSON is not an object"], canonical_ref=canonical_ref)
    required_wrapper_fields = set(STRUCTURED_EVIDENCE_FIELDS)
    allowed_wrapper_fields = (
        required_wrapper_fields
        | set(STRUCTURED_EVIDENCE_OPTIONAL_FIELDS)
        | set(STRUCTURED_TEST_OPTIONAL_FIELDS)
    )
    wrapper_fields = set(data)
    missing_wrapper_fields = sorted(
        required_wrapper_fields - wrapper_fields
    )
    extra_wrapper_fields = sorted(
        wrapper_fields - allowed_wrapper_fields
    )
    if missing_wrapper_fields or extra_wrapper_fields:
        reasons.append(
            "structured evidence fields are not closed for schema "
            f"{EVIDENCE_SCHEMA_VERSION}: missing={missing_wrapper_fields}; "
            f"extra={extra_wrapper_fields}"
        )
    for field in STRUCTURED_EVIDENCE_FIELDS:
        if field not in data:
            continue
        raw_value = data.get(field)
        canonical_value = _canonical_proposition_text(raw_value)
        if canonical_value is None:
            reasons.append(
                f"structured evidence {field} must be a nonempty string"
            )
        elif raw_value != canonical_value:
            reasons.append(
                f"structured evidence {field} is not canonical"
            )
    for field in ("applies_to_claims", "applies_to_tests"):
        if field not in data:
            continue
        raw_values = data.get(field)
        if (
            type(raw_values) is not list
            or not raw_values
            or any(
                type(value) is not str
                or _canonical_proposition_text(value) != value
                for value in raw_values
            )
            or len(set(raw_values)) != len(raw_values)
        ):
            reasons.append(
                f"structured evidence {field} must be a nonempty, "
                "duplicate-free list of canonical strings"
            )
    if "test_id" in data:
        raw_wrapper_test_id = data.get("test_id")
        if (
            type(raw_wrapper_test_id) is not str
            or _canonical_proposition_text(raw_wrapper_test_id)
            != raw_wrapper_test_id
        ):
            reasons.append(
                "structured evidence test_id must be a canonical "
                "nonempty string"
            )
    if (
        "modal_case_sha256" in data
        and _canonical_claimed_sha256(data.get("modal_case_sha256")) is None
    ):
        reasons.append(
            "structured evidence modal_case_sha256 must be a string-typed "
            "SHA-256 identity"
        )
    if data.get("evidence_schema_version") != EVIDENCE_SCHEMA_VERSION:
        reasons.append(
            "structured evidence schema is not "
            f"{EVIDENCE_SCHEMA_VERSION}"
        )
    if data.get("claim_contract_schema_version") != CLAIM_CONTRACT_SCHEMA_VERSION:
        reasons.append(
            "structured evidence claim_contract_schema_version is not "
            f"{CLAIM_CONTRACT_SCHEMA_VERSION}"
        )
    if (
        test_id is not None
        and "test_id" not in data
        and "applies_to_tests" not in data
    ):
        reasons.append("test evidence missing test_id or applies_to_tests")
    if not _matches_claim(data, claim_id):
        reasons.append(f"evidence claim binding does not match {claim_id}")
    if not _matches_test(data, test_id):
        reasons.append(f"evidence test binding does not match {test_id}")
    # Avoid obviously useless generic non-evidence files that happen to be JSON.
    summary = (
        data.get("support_summary")
        if type(data.get("support_summary")) is str
        else ""
    )
    observed = (
        data.get("observed_result")
        if type(data.get("observed_result")) is str
        else ""
    )
    if len(summary.strip()) < 20:
        reasons.append("support_summary too short to evidence semantic support")
    if len(observed.strip()) < 10:
        reasons.append("observed_result too short to evidence an observation")
    expected_claim_digest = _proposition_sha256(claim_proposition)
    wrapper_claim_digest = _canonical_claimed_sha256(
        data.get("claim_proposition_sha256")
    )
    if expected_claim_digest is None:
        reasons.append("claim proposition cannot be canonicalized")
    elif wrapper_claim_digest != expected_claim_digest:
        reasons.append(
            "claim_proposition_sha256 does not match certificate claim text"
        )
    wrapper_contract_digest = _canonical_claimed_sha256(
        data.get("claim_contract_sha256")
    )
    if claim_contract_sha256 is None:
        reasons.append("certificate claim contract cannot be canonicalized")
    elif wrapper_contract_digest != claim_contract_sha256:
        reasons.append(
            "claim_contract_sha256 does not match certificate claim contract"
        )
    expected_modal_digest: Optional[str] = None
    expected_modal_outcome: Optional[str] = None
    if test_id is not None:
        if modal_test is None:
            reasons.append("modal test binding is unavailable")
        else:
            world_contract = modal_test.get("world_contract")
            if isinstance(world_contract, Mapping):
                candidate_outcome = _lower(
                    world_contract.get("expected_outcome")
                )
                if candidate_outcome in FALSE_OUTCOMES | TRUE_OUTCOMES:
                    expected_modal_outcome = candidate_outcome
            expected_modal_digest = _modal_case_sha256(
                modal_test,
                claim_proposition,
                test_kind or "",
                data.get("observed_result"),
                claim_contract_sha256=claim_contract_sha256,
            )
            wrapper_modal_digest = _canonical_claimed_sha256(
                data.get("modal_case_sha256")
            )
            if expected_modal_digest is None:
                reasons.append("modal case cannot be canonicalized")
            elif wrapper_modal_digest != expected_modal_digest:
                reasons.append(
                    "modal_case_sha256 does not match certificate modal test"
                )
    artifact_reasons, artifact_path_resolved, artifact_sha256 = _verify_artifact_sha256(data, evidence_root)
    reasons.extend(artifact_reasons)
    observation_reasons, observation_id = _verify_observation_binding(
        data,
        artifact_path_resolved,
        artifact_sha256,
        claim_id,
        test_id,
        test_kind,
        expected_claim_digest,
        claim_contract_sha256,
        expected_modal_digest,
        expected_modal_outcome,
        json_cache,
    )
    reasons.extend(observation_reasons)
    return EvidenceCheck(
        ref_s,
        True,
        not reasons,
        reasons,
        canonical_ref=canonical_ref,
        artifact_path_resolved=(
            str(artifact_path_resolved)
            if artifact_path_resolved is not None
            else None
        ),
        artifact_sha256=artifact_sha256,
        observation_id=observation_id,
        wrapper_sha256=wrapper_result.sha256,
        modal_case_sha256=expected_modal_digest or "",
    )


def _unique_valid_evidence_refs(checks: Sequence[EvidenceCheck]) -> List[str]:
    representatives: Dict[str, str] = {}
    for check in checks:
        if check.structured and check.canonical_ref and check.wrapper_sha256:
            representatives.setdefault(
                check.wrapper_sha256,
                str(check.canonical_ref),
            )
    return list(representatives.values())


def _unique_valid_artifacts(checks: Sequence[EvidenceCheck]) -> List[str]:
    valid = [
        check
        for check in checks
        if check.structured
        and check.artifact_path_resolved
        and check.artifact_sha256
    ]
    representatives: Dict[str, str] = {}
    for check in valid:
        representatives.setdefault(
            str(check.artifact_sha256),
            str(check.artifact_path_resolved),
        )
    return [
        f"{path}#sha256:{digest}"
        for digest, path in representatives.items()
    ]


def merge_thresholds(supplied: Mapping[str, Any] | None) -> Tuple[Dict[str, Dict[str, float]], List[str]]:
    merged = {k: dict(v) for k, v in DEFAULT_THRESHOLDS.items()}
    notes: List[str] = []
    if supplied is not None and not isinstance(supplied, Mapping):
        return merged, ["gate_thresholds is not an object"]
    for imp_raw, vals in (supplied or {}).items():
        imp = _lower(imp_raw)
        if imp not in DEFAULT_THRESHOLDS or not isinstance(vals, Mapping):
            notes.append(f"ignored invalid threshold group {imp_raw!r}"); continue
        for key, raw in vals.items():
            if key not in DEFAULT_THRESHOLDS[imp]:
                notes.append(f"ignored invalid threshold key {imp}.{key}"); continue
            try: val = float(raw)
            except (TypeError, ValueError, OverflowError):
                notes.append(f"ignored non-numeric threshold {imp}.{key}={raw!r}"); continue
            if not math.isfinite(val) or not (0 <= val <= 1):
                notes.append(f"ignored out-of-range threshold {imp}.{key}={raw!r}"); continue
            if val < DEFAULT_THRESHOLDS[imp][key]:
                notes.append(f"threshold relaxation attempt ignored: {imp}.{key} {val:.3f} < default {DEFAULT_THRESHOLDS[imp][key]:.3f}"); continue
            merged[imp][key] = val
    return merged, notes


METHOD_PLACEHOLDERS = frozenset({
    "dummy",
    "example",
    "fill me",
    "fixme",
    "placeholder",
    "tbd",
    "todo",
    "unknown",
})
MAX_METHOD_ANCHOR_TEXT_LENGTH = 2_048
MAX_METHOD_LOCATOR_LENGTH = 512
MIN_DISTINCT_METHOD_COLLECTION_ANCHORS = 2
METHOD_COMMAND_NAMES = frozenset({
    "bash",
    "git",
    "make",
    "node",
    "npm",
    "python",
    "python3",
    "pytest",
    "rg",
    "sh",
})


def _method_tokens(value: str) -> List[str]:
    return [
        token.casefold()
        for token in re.findall(
            r"[A-Za-z0-9][A-Za-z0-9_+.-]*",
            value,
        )
    ]


def _method_tokens_are_periodic(tokens: Sequence[str]) -> bool:
    """Detect an exact repeated lexical period, independent of punctuation."""
    count = len(tokens)
    for period in range(1, count // 2 + 1):
        if count % period:
            continue
        if all(tokens[index] == tokens[index % period] for index in range(count)):
            return True
    return False


def _method_string_is_substantive(
    value: Any,
    *,
    narrative: bool = False,
) -> bool:
    if type(value) is not str:
        return False
    normalized = value.strip()
    if not normalized or normalized.lower() in UNKNOWN:
        return False
    lowered = normalized.lower()
    if lowered in METHOD_PLACEHOLDERS:
        return False
    # C and R are conventional one-letter language locators. They are valid
    # only as collection members; the collection must still provide qualifying
    # anchors and cross-field anchor diversity.
    if not narrative and normalized in {"C", "R"}:
        return True
    alphanumeric = "".join(character for character in lowered if character.isalnum())
    if not alphanumeric or len(set(alphanumeric)) == 1:
        return False
    if narrative:
        # Producer/checker/process are explanations rather than identifiers.
        # Four lexical tokens and a modest byte floor reject marker strings,
        # filenames, and terse labels while retaining concise real methods.
        tokens = _method_tokens(normalized)
        distinct_tokens = set(tokens)
        return (
            len(normalized) >= 24
            and len(tokens) >= 4
            and len(distinct_tokens) >= 4
            and len(distinct_tokens) / len(tokens) >= 0.6
            and not _method_tokens_are_periodic(tokens)
        )
    # Collection components may legitimately be short identifiers (Git, Bash,
    # paths, version strings).  Single-letter language names remain usable in
    # an otherwise substantive method object, while arbitrary one-character
    # markers and repeated-character placeholders do not count.
    return len(normalized) >= 3


def _method_anchor_identity(value: str) -> Optional[str]:
    """Return a canonical collection anchor or None for a short identifier."""
    normalized = re.sub(
        r"\s+",
        " ",
        unicodedata.normalize("NFC", value),
    ).strip()
    if (
        not normalized
        or len(normalized) > MAX_METHOD_ANCHOR_TEXT_LENGTH
        or any(ord(character) < 32 or ord(character) == 127 for character in normalized)
    ):
        return None
    lowered = normalized.casefold()
    digest = lowered.removeprefix("sha256:")
    if re.fullmatch(r"[0-9a-f]{64}", digest):
        return f"digest:{digest}"
    if re.search(
        r"(?:^|\s)(?:[A-Za-z][A-Za-z0-9+.-]*\s+)?v?\d+(?:\.\d+)+(?:[-+][A-Za-z0-9.-]+)?(?:$|\s)",
        normalized,
    ):
        return f"version:{lowered}"
    if (
        len(normalized) <= MAX_METHOD_LOCATOR_LENGTH
        and not any(character.isspace() for character in normalized)
    ):
        candidate = PurePosixPath(normalized)
        if (
            not candidate.is_absolute()
            and ".." not in candidate.parts
            and str(candidate) == normalized
            and ("/" in normalized or bool(candidate.suffix))
        ):
            return f"path:{lowered}"
    command_parts = normalized.split()
    if (
        2 <= len(command_parts) <= 32
        and command_parts[0].casefold() in METHOD_COMMAND_NAMES
        and all(len(part) <= 256 for part in command_parts)
    ):
        return f"command:{lowered}"
    tokens = _method_tokens(normalized)
    distinct_tokens = set(tokens)
    if (
        12 <= len(normalized) <= MAX_METHOD_ANCHOR_TEXT_LENGTH
        and len(tokens) >= 2
        and len(distinct_tokens) >= 2
        and len(distinct_tokens) / len(tokens) >= 0.6
        and not _method_tokens_are_periodic(tokens)
    ):
        return f"description:{lowered}"
    return None


def _collection_method_anchors(value: Any) -> Tuple[bool, set[str]]:
    """Validate one collection and collect non-scalar substantive anchors."""
    if not (type(value) is list or isinstance(value, Mapping)) or not value:
        return False, set()
    valid = True
    anchors: set[str] = set()
    stack: List[Tuple[Any, int]] = [(value, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > 16:
            valid = False
            continue
        if type(node) is str:
            if not _method_string_is_substantive(node):
                valid = False
                continue
            anchor = _method_anchor_identity(node)
            if anchor is not None:
                anchors.add(anchor)
        elif type(node) is list:
            if not node:
                valid = False
            stack.extend((item, depth + 1) for item in node)
        elif isinstance(node, Mapping):
            if not node or any(
                type(key) is not str or not key.strip() for key in node
            ):
                valid = False
            stack.extend((item, depth + 1) for item in node.values())
        elif type(node) in {bool, int, float}:
            if type(node) is float and not math.isfinite(node):
                valid = False
            # Numeric and boolean metadata is supported but never an anchor.
        else:
            valid = False
    return valid, anchors


def _distinct_collection_anchor_fields(
    anchors_by_field: Mapping[str, set[str]],
) -> set[str]:
    """Find fields that can each be assigned a distinct substantive anchor."""
    anchor_owner: Dict[str, str] = {}

    def assign(field: str, seen: set[str]) -> bool:
        for anchor in sorted(anchors_by_field.get(field, set())):
            if anchor in seen:
                continue
            seen.add(anchor)
            owner = anchor_owner.get(anchor)
            if owner is None or assign(owner, seen):
                anchor_owner[anchor] = field
                return True
        return False

    for field in REQ_METHOD:
        if field in METHOD_COLLECTION_FIELDS:
            assign(field, set())
    return set(anchor_owner.values())


def _structured_method_value_is_substantive(
    value: Any,
    *,
    depth: int = 0,
) -> bool:
    """Accept JSON method structure only when it contains real text.

    Booleans and numbers may describe a structured method below a named field,
    but cannot by themselves constitute method M. Requiring at least one
    substantive string prevents objects such as ``{"synthetic": true}`` from
    being counted as an actual producer, checker, artifact set, or trace.
    """
    if depth > 16:
        return False
    if _method_string_is_substantive(value):
        return True
    if type(value) is list:
        return bool(value) and all(
            _structured_method_value_is_substantive(item, depth=depth + 1)
            for item in value
        )
    if isinstance(value, Mapping):
        if not value:
            return False
        if any(
            type(key) is not str or not key.strip()
            for key in value
        ):
            return False
        supported = True
        contains_text = False
        for item in value.values():
            if type(item) in {bool, int, float} or item is None:
                if type(item) is float and not math.isfinite(item):
                    supported = False
                continue
            if not _structured_method_value_is_substantive(
                item,
                depth=depth + 1,
            ):
                supported = False
                continue
            contains_text = True
        return supported and contains_text
    return False


def _narrative_method_value_is_substantive(value: Any) -> bool:
    """Require substantive aggregate prose even inside typed structures."""
    if _method_string_is_substantive(value, narrative=True):
        return True
    if not (
        isinstance(value, Mapping) or type(value) is list
    ) or not _structured_method_value_is_substantive(value):
        return False
    fragments: List[str] = []
    stack: List[Any] = [value]
    while stack:
        node = stack.pop()
        if type(node) is str:
            fragments.append(node.strip())
        elif isinstance(node, Mapping):
            stack.extend(node.values())
        elif type(node) is list:
            stack.extend(node)
    return _method_string_is_substantive(
        " ".join(reversed(fragments)),
        narrative=True,
    )


def _method_component_is_substantive(field: str, value: Any) -> bool:
    if field in METHOD_NARRATIVE_FIELDS:
        return _narrative_method_value_is_substantive(value)
    if field in METHOD_COLLECTION_FIELDS:
        valid, anchors = _collection_method_anchors(value)
        return valid and bool(anchors)
    return False


def method_completeness(method: Mapping[str, Any] | None) -> Tuple[float, List[str]]:
    if not isinstance(method, Mapping):
        return 0.0, list(REQ_METHOD)
    anchors_by_field: Dict[str, set[str]] = {}
    individually_valid: set[str] = set()
    for field in REQ_METHOD:
        if field in METHOD_NARRATIVE_FIELDS:
            if _method_component_is_substantive(field, method.get(field)):
                individually_valid.add(field)
            continue
        valid, anchors = _collection_method_anchors(method.get(field))
        if valid and anchors:
            anchors_by_field[field] = anchors
    matched_collection_fields = _distinct_collection_anchor_fields(
        anchors_by_field
    )
    # Even the minor threshold must not be reachable by repeating one marker
    # across every collection field alongside three narrative components.
    if len(matched_collection_fields) >= MIN_DISTINCT_METHOD_COLLECTION_ANCHORS:
        individually_valid.update(matched_collection_fields)
    missing = [field for field in REQ_METHOD if field not in individually_valid]
    return (len(REQ_METHOD) - len(missing)) / len(REQ_METHOD), missing


def _test_evidence_checks(
    t: Mapping[str, Any],
    evidence_root: Optional[Path],
    claim_id: Optional[str],
    test_id: str,
    test_kind: str,
    claim_proposition: Any,
    claim_contract_sha256: Optional[str],
    json_cache: Optional[
        Dict[JsonCacheKey, BoundedJsonResult]
    ] = None,
) -> Tuple[bool, List[str], List[EvidenceCheck]]:
    reasons: List[str] = []
    raw_refs = t.get("evidence_refs")
    if (
        type(raw_refs) is not list
        or any(
            type(ref) is not str
            or _canonical_proposition_text(ref) != ref
            for ref in (raw_refs if type(raw_refs) is list else [])
        )
        or (
            type(raw_refs) is list
            and len(set(raw_refs)) != len(raw_refs)
        )
    ):
        reasons.append(
            "test evidence_refs must be a duplicate-free list of "
            "canonical nonempty strings"
        )
    refs = list(raw_refs) if type(raw_refs) is list else []
    checks = [
        _load_structured_evidence(
            ref,
            evidence_root,
            claim_id=claim_id,
            claim_proposition=claim_proposition,
            claim_contract_sha256=claim_contract_sha256,
            test_id=test_id,
            test_kind=test_kind,
            modal_test=t,
            json_cache=json_cache,
        )
        for ref in refs
    ]
    if evidence_root is not None:
        invalid = [c for c in checks if c.reasons]
        if invalid:
            reasons.append("invalid evidence refs: " + "; ".join(f"{c.ref}: {', '.join(c.reasons)}" for c in invalid))
        unique_refs = _unique_valid_evidence_refs(checks)
        if refs and len(unique_refs) < len(refs):
            reasons.append(f"unique test evidence refs {len(unique_refs)} < cited refs {len(refs)}")
        if not any(c.structured for c in checks): reasons.append("missing structured test evidence bound to claim/test")
    if not (refs or _nonempty(t.get("observed_behavior")) or _nonempty(t.get("evidence"))):
        reasons.append("missing test evidence or observed behavior")
    return not reasons, reasons, checks


def _canonical_world_contract(
    value: Any,
) -> Tuple[Optional[Dict[str, str]], List[str]]:
    """Validate and canonicalize a closed nearby-world identity."""
    if not isinstance(value, Mapping):
        return None, ["world_contract is not an object"]
    fields = set(value)
    if fields != WORLD_CONTRACT_FIELDS:
        return None, [
            "world_contract fields are not exact for schema "
            f"{WORLD_CONTRACT_SCHEMA_VERSION}: "
            f"missing={sorted(WORLD_CONTRACT_FIELDS - fields)}; "
            f"extra={sorted(fields - WORLD_CONTRACT_FIELDS)}"
        ]
    if value.get("schema_version") != WORLD_CONTRACT_SCHEMA_VERSION:
        return None, [
            "world_contract schema_version is not "
            f"{WORLD_CONTRACT_SCHEMA_VERSION}"
        ]
    canonical: Dict[str, str] = {
        "schema_version": WORLD_CONTRACT_SCHEMA_VERSION,
    }
    reasons: List[str] = []
    equivalence_class = value.get("semantic_equivalence_class")
    if (
        type(equivalence_class) is not str
        or not re.fullmatch(
            r"[a-z0-9]+(?:[._:-][a-z0-9]+){0,31}",
            equivalence_class,
        )
        or len(equivalence_class) > 128
    ):
        reasons.append(
            "world_contract semantic_equivalence_class must be a canonical "
            "lowercase ASCII slug"
        )
    else:
        canonical["semantic_equivalence_class"] = equivalence_class
    operator = value.get("operator")
    if type(operator) is not str or operator not in WORLD_MUTATION_OPERATORS:
        reasons.append(
            "world_contract operator must be one of the closed canonical "
            f"mutation operators: {sorted(WORLD_MUTATION_OPERATORS)}"
        )
    else:
        canonical["operator"] = operator
    target = value.get("target")
    if type(target) is not str or target not in WORLD_MUTATION_TARGETS:
        reasons.append(
            "world_contract target must be one of the closed canonical "
            f"mutation targets: {sorted(WORLD_MUTATION_TARGETS)}"
        )
    else:
        canonical["target"] = target
    for field in sorted({"precondition", "state_delta", "oracle"}):
        normalized = _canonical_proposition_text(value.get(field))
        if normalized is None:
            reasons.append(
                f"world_contract {field} must be a nonempty string"
            )
        else:
            canonical[field] = normalized
    expected_outcome = _lower(value.get("expected_outcome"))
    if expected_outcome not in FALSE_OUTCOMES | TRUE_OUTCOMES:
        reasons.append(
            "world_contract expected_outcome is not a canonical modal outcome"
        )
    else:
        canonical["expected_outcome"] = expected_outcome
    return (canonical if not reasons else None), reasons


def migrate_legacy_world_contract(test: Mapping[str, Any]) -> Dict[str, Any]:
    """Migrate one known package schema-1.0 world without semantic guessing.

    This pure helper is intentionally closed over the 80 reviewed release
    declarations. Unknown IDs fail rather than receiving a generic target.
    Callers remain responsible for regenerating modal digests, observation
    ledgers, claim contracts, and manifests after applying the returned value.
    """
    if not isinstance(test, Mapping):
        raise InvalidInputError("legacy modal test is not an object")
    test_id = _test_id(test)
    identity = LEGACY_WORLD_IDENTITY_BY_TEST_ID.get(test_id)
    if identity is None:
        raise InvalidInputError(
            f"no reviewed world-contract migration identity for {test_id!r}"
        )
    world = test.get("world_contract")
    if not isinstance(world, Mapping):
        raise InvalidInputError("legacy world_contract is not an object")
    if set(world) != WORLD_CONTRACT_FIELDS:
        raise InvalidInputError("legacy world_contract fields are not exact")
    if world.get("schema_version") != "1.0":
        raise InvalidInputError(
            "legacy world_contract schema_version is not 1.0"
        )
    migrated = dict(world)
    migrated["schema_version"] = WORLD_CONTRACT_SCHEMA_VERSION
    migrated["operator"], migrated["target"] = identity
    _, reasons = _canonical_world_contract(migrated)
    if reasons:
        raise InvalidInputError(
            "migrated world_contract is invalid: " + "; ".join(reasons)
        )
    return migrated


def _behavior_integrity_reasons(value: Any, field: str) -> List[str]:
    """Treat behavior prose as bound explanation, never as a classifier.

    Natural-language polarity is not a deterministic oracle: negation,
    quotation, reported speech, and domain vocabulary make unrestricted prose
    inference unsound.  Authorization therefore comes only from the closed
    typed outcome fields below.  Prose must merely be present and remains bound
    by the claim/modal digests for human review.
    """
    if _canonical_proposition_text(value) is None:
        return [f"{field} must be a nonempty string"]
    return []


def evaluate_test(
    t: Mapping[str, Any],
    expected_kind: str,
    evidence_root: Optional[Path] = None,
    claim_id: Optional[str] = None,
    claim_proposition: Any = None,
    claim_contract_sha256: Optional[str] = None,
    json_cache: Optional[
        Dict[JsonCacheKey, BoundedJsonResult]
    ] = None,
) -> TestResult:
    raw_tid, test_id_reason = _canonical_modal_test_id(t)
    tid = raw_tid or "<invalid-test-id>"
    kind = _lower(t.get("kind") or expected_kind)
    reasons: List[str] = []
    if test_id_reason is not None:
        reasons.append(test_id_reason)
    if kind != expected_kind: reasons.append(f"test kind {kind!r} does not match expected {expected_kind!r}")
    targets, target_reasons = _canonical_target_claim_values(t)
    reasons.extend(target_reasons)
    if not targets:
        reasons.append("missing target_claim")
    elif claim_id is not None and not _target_claim_matches(t, claim_id):
        reasons.append(f"test target_claim does not match evaluated claim {claim_id}")
    variation_fields = [
        field for field in ("perturbation", "variant") if field in t
    ]
    if len(variation_fields) != 1:
        reasons.append(
            "modal test must contain exactly one perturbation/variant field"
        )
    elif _canonical_proposition_text(t.get(variation_fields[0])) is None:
        reasons.append(
            f"{variation_fields[0]} must be a nonempty string"
        )
    world_contract, world_reasons = _canonical_world_contract(
        t.get("world_contract")
    )
    reasons.extend(world_reasons)
    _, ev_reasons, evidence_checks = _test_evidence_checks(
        t,
        evidence_root,
        claim_id=claim_id,
        test_id=tid,
        test_kind=expected_kind,
        claim_proposition=claim_proposition,
        claim_contract_sha256=claim_contract_sha256,
        json_cache=json_cache,
    )
    reasons.extend(ev_reasons)
    result = _lower(t.get("result"))
    outcome_present = "outcome" in t
    observed_outcome_present = "observed_outcome" in t
    outcome = _lower(t.get("outcome")) if outcome_present else ""
    observed_outcome = (
        _lower(t.get("observed_outcome"))
        if observed_outcome_present
        else ""
    )
    if result != "pass": reasons.append(f"result is {result!r}, not 'pass'")
    if outcome_present and observed_outcome_present and outcome != observed_outcome:
        reasons.append("outcome and observed_outcome do not match")
    typed_outcomes = [
        (field, value)
        for field, present, value in (
            ("outcome", outcome_present, outcome),
            ("observed_outcome", observed_outcome_present, observed_outcome),
        )
        if present
    ]
    if not typed_outcomes:
        reasons.append("modal test lacks a canonical typed outcome")
    if expected_kind == "false_world":
        for field, value in typed_outcomes:
            if value not in FALSE_OUTCOMES:
                reasons.append(
                    f"false-world {field} {value!r} is not accepted"
                )
    else:
        for field, value in typed_outcomes:
            if value not in TRUE_OUTCOMES:
                reasons.append(
                    f"true-world {field} {value!r} is not accepted"
                )
    if world_contract is not None:
        world_outcome = world_contract.get("expected_outcome")
        for field, value in typed_outcomes:
            if value != world_outcome:
                reasons.append(
                    f"{field} does not match world_contract expected_outcome"
                )
    reasons.extend(
        _behavior_integrity_reasons(
            t.get("expected_behavior"),
            "expected_behavior",
        )
    )
    reasons.extend(
        _behavior_integrity_reasons(
            t.get("observed_behavior"),
            "observed_behavior",
        )
    )
    if world_contract is not None:
        reasons.extend(
            _behavior_integrity_reasons(
                world_contract.get("oracle"),
                "world_contract oracle",
            )
        )
    return TestResult(tid, expected_kind, "PASS" if not reasons else "FAIL", reasons, evidence_checks)


def evaluate_tests(
    tests: Sequence[Mapping[str, Any]],
    expected_kind: str,
    evidence_root: Optional[Path] = None,
    claim_id: Optional[str] = None,
    claim_proposition: Any = None,
    claim_contract_sha256: Optional[str] = None,
    json_cache: Optional[
        Dict[JsonCacheKey, BoundedJsonResult]
    ] = None,
) -> Tuple[float, List[TestResult]]:
    if not tests: return 0.0, []
    results = [
        evaluate_test(
            test,
            expected_kind,
            evidence_root=evidence_root,
            claim_id=claim_id,
            claim_proposition=claim_proposition,
            claim_contract_sha256=claim_contract_sha256,
            json_cache=json_cache,
        )
        for test in tests
    ]
    return sum(r.status == "PASS" for r in results) / len(results), results


def _test_id(t: Mapping[str, Any]) -> str:
    test_id, _reason = _canonical_modal_test_id(t)
    return test_id or ""


def _canonical_modal_test_id(
    test: Mapping[str, Any],
) -> Tuple[Optional[str], Optional[str]]:
    """Return one exact generic modal identity without scalar coercion."""
    id_present = "id" in test
    alias_present = "test_id" in test
    if not id_present and not alias_present:
        return None, "missing modal test id"
    raw_id = test.get("id") if id_present else test.get("test_id")
    if id_present and alias_present and test.get("id") != test.get("test_id"):
        return None, "modal test id and test_id aliases conflict"
    if type(raw_id) is not str:
        return None, "modal test id must be a string"
    canonical_id = _canonical_proposition_text(raw_id)
    if canonical_id is None:
        return None, "modal test id must be nonempty"
    if raw_id != canonical_id:
        return None, "modal test id is not canonical"
    return raw_id, None


def _package_modal_test_id(
    test: Mapping[str, Any],
) -> Tuple[Optional[str], Optional[str]]:
    """Return an exact package-registry ID without lossy coercion.

    Generic certificates retain the historical ``id``/``test_id`` label
    compatibility implemented by :func:`_test_id`.  The package-self policy is
    different: it authenticates a closed reviewed registry, so an integer,
    boolean, empty label, or whitespace/Unicode-normalized alias must never be
    converted into a registry key.
    """
    raw_test_id = test.get("id")
    if type(raw_test_id) is not str:
        return None, "package-self modal test id is not a string"
    canonical_test_id = _canonical_proposition_text(raw_test_id)
    if canonical_test_id is None:
        return None, "package-self modal test id is empty"
    if raw_test_id != canonical_test_id:
        return None, "package-self modal test id is not canonical"
    return raw_test_id, None

def _canonical_target_claim_values(
    test: Mapping[str, Any],
) -> Tuple[List[str], List[str]]:
    """Return exact target IDs from one unambiguous generic field shape."""
    fields = [
        field
        for field in ("target_claim_ids", "target_claim")
        if field in test
    ]
    if len(fields) != 1:
        return [], [
            "modal test must contain exactly one target_claim_ids/"
            "target_claim field"
        ]
    field = fields[0]
    raw_targets = test.get(field)
    if field == "target_claim":
        values = [raw_targets]
    elif type(raw_targets) is list and raw_targets:
        values = list(raw_targets)
    else:
        return [], [
            "target_claim_ids must be a nonempty list of canonical strings"
        ]
    targets: List[str] = []
    reasons: List[str] = []
    for index, raw_target in enumerate(values):
        if type(raw_target) is not str:
            reasons.append(
                f"modal target member {index} must be a string"
            )
            continue
        canonical_target = _canonical_proposition_text(raw_target)
        if canonical_target is None or canonical_target != raw_target:
            reasons.append(
                f"modal target member {index} is not canonical"
            )
            continue
        targets.append(raw_target)
    if len(set(targets)) != len(targets):
        reasons.append("modal target IDs contain duplicates")
    return targets, reasons


def _target_claim_values(t: Mapping[str, Any]) -> List[str]:
    values, _reasons = _canonical_target_claim_values(t)
    return values


def _target_claim_matches(t: Mapping[str, Any], claim_id: Optional[str]) -> bool:
    if claim_id is None:
        return True
    return str(claim_id).strip() in set(_target_claim_values(t))


def _canonical_test_evidence_keys(t: Mapping[str, Any], evidence_root: Optional[Path]) -> Tuple[str, ...]:
    raw_refs = t.get("evidence_refs")
    refs = list(raw_refs) if type(raw_refs) is list else []
    if evidence_root is None:
        return tuple(sorted(str(r or "") for r in refs))
    return tuple(sorted(_canonical_evidence_key(r, evidence_root) for r in refs))


def _modal_test_key(
    t: Mapping[str, Any],
    expected_kind: str,
    evidence_root: Optional[Path],
    evaluated_claim_id: str,
) -> Tuple[str, str, str, str]:
    """Return independent reviewer and structural nearby-world identities.

    Test IDs, result prose, and evidence filenames are labels or observations;
    changing them does not construct a second nearby world. The versioned,
    closed ``world_contract`` binds the mutation/operator, target, precondition,
    state delta, oracle, and expected outcome. Coverage deduplicates on its
    reviewer-assigned ``semantic_equivalence_class`` and independently on the
    closed typed mutation identity: operator, canonical target, and typed
    expected outcome. Explanatory prose remains evidence-bound but is not a
    diversity identity, so punctuation, paraphrase, or a simultaneous class
    relabel cannot turn one typed mutation into two nearby worlds.
    """
    del evidence_root  # Kept in the signature for compatibility with callers.
    kind = _lower(t.get("kind") or expected_kind)
    world_contract, _ = _canonical_world_contract(t.get("world_contract"))
    equivalence_class = (
        world_contract.get("semantic_equivalence_class", "")
        if world_contract is not None
        else ""
    )
    structural_payload = (
        {
            "operator": world_contract["operator"],
            "target": world_contract["target"],
            "expected_outcome": world_contract["expected_outcome"],
        }
        if world_contract is not None
        else None
    )
    structural_fingerprint = (
        hashlib.sha256(
            json.dumps(
                structural_payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        if structural_payload is not None
        else ""
    )
    return (
        kind,
        evaluated_claim_id,
        equivalence_class,
        structural_fingerprint,
    )


def _package_world_transition_payload(
    test: Mapping[str, Any],
    expected_kind: str,
    evaluated_claim_id: str,
) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """Build the complete closed package-self transition identity."""
    reasons: List[str] = []
    test_id, test_id_reason = _package_modal_test_id(test)
    if test_id_reason is not None:
        reasons.append(test_id_reason)
    variation_fields = [
        field for field in ("perturbation", "variant") if field in test
    ]
    if len(variation_fields) != 1:
        reasons.append(
            "package-self modal transition must contain exactly one "
            "perturbation/variant field"
        )
        variation_field = ""
        variation = None
    else:
        variation_field = variation_fields[0]
        variation = _canonical_proposition_text(test.get(variation_field))
        if variation is None:
            reasons.append(
                f"package-self modal transition {variation_field} is empty"
            )
    allowed_fields = (
        PACKAGE_WORLD_REQUIRED_TEST_FIELDS
        | PACKAGE_WORLD_OPTIONAL_TEST_FIELDS
        | {"perturbation", "variant"}
    )
    fields = set(test)
    missing = sorted(PACKAGE_WORLD_REQUIRED_TEST_FIELDS - fields)
    extra = sorted(fields - allowed_fields)
    if missing or extra:
        reasons.append(
            "package-self modal transition fields are not closed: "
            f"missing={missing}; extra={extra}"
        )
    kind = _lower(test.get("kind"))
    if kind != expected_kind:
        reasons.append(
            f"package-self modal transition kind {kind!r} does not match "
            f"{expected_kind!r}"
        )
    raw_targets = test.get("target_claim_ids")
    target_claim_ids: List[str] = []
    if type(raw_targets) is not list or not raw_targets:
        reasons.append(
            "package-self modal transition target_claim_ids is not a "
            "nonempty list"
        )
    else:
        for target_index, raw_target in enumerate(raw_targets):
            if type(raw_target) is not str:
                reasons.append(
                    "package-self modal transition target_claim_ids member "
                    f"{target_index} is not a string"
                )
                continue
            target = _canonical_proposition_text(raw_target)
            if target is None or target != raw_target:
                reasons.append(
                    "package-self modal transition target_claim_ids contains "
                    "a noncanonical id"
                )
            else:
                target_claim_ids.append(target)
        if len(set(target_claim_ids)) != len(target_claim_ids):
            reasons.append(
                "package-self modal transition target_claim_ids contains "
                "duplicates"
            )
    target_claim_ids = sorted(set(target_claim_ids))
    if evaluated_claim_id not in target_claim_ids:
        reasons.append(
            "package-self modal transition does not target the evaluated claim"
        )
    world_contract, world_reasons = _canonical_world_contract(
        test.get("world_contract")
    )
    if world_contract is None:
        reasons.append(
            "package-self modal transition world_contract is not canonical: "
            + "; ".join(world_reasons)
        )
    expected_behavior = _canonical_proposition_text(
        test.get("expected_behavior")
    )
    observed_behavior = _canonical_proposition_text(
        test.get("observed_behavior")
    )
    if expected_behavior is None:
        reasons.append(
            "package-self modal transition expected_behavior is empty"
        )
    if observed_behavior is None:
        reasons.append(
            "package-self modal transition observed_behavior is empty"
        )
    outcome = _lower(test.get("outcome"))
    observed_outcome = _lower(test.get("observed_outcome"))
    result = _lower(test.get("result"))
    fixture_sha256 = ""
    if "fixture_sha256" in test:
        candidate_fixture_digest = _canonical_claimed_sha256(
            test.get("fixture_sha256")
        )
        if candidate_fixture_digest is None:
            reasons.append(
                "package-self modal transition fixture_sha256 is not canonical"
            )
        else:
            fixture_sha256 = candidate_fixture_digest
    evidence_refs = test.get("evidence_refs")
    if type(evidence_refs) is not list or any(
        _canonical_proposition_text(ref) is None for ref in evidence_refs
    ):
        reasons.append(
            "package-self modal transition evidence_refs is not a canonical list"
        )
    if reasons:
        return None, reasons
    assert test_id is not None
    assert variation is not None
    assert world_contract is not None
    assert expected_behavior is not None
    assert observed_behavior is not None
    payload = {
        "registry_version": PACKAGE_WORLD_REGISTRY_VERSION,
        "claim_id": _canonical_proposition_text(evaluated_claim_id) or "",
        "test_id": test_id,
        "kind": kind,
        "target_claim_ids": target_claim_ids,
        "variation_field": variation_field,
        "variation": variation,
        "world_contract": world_contract,
        "expected_behavior": expected_behavior,
        "observed_behavior": observed_behavior,
        "outcome": outcome,
        "observed_outcome": observed_outcome,
        "result": result,
        "fixture_sha256": fixture_sha256,
    }
    return payload, []


def _reviewed_package_world_transition_digest(
    test: Mapping[str, Any],
    expected_kind: str,
    evaluated_claim_id: str,
) -> Tuple[str, Optional[str]]:
    """Authenticate one package-self transition against the reviewed pins."""
    test_id, test_id_reason = _package_modal_test_id(test)
    if test_id_reason is not None:
        return "", test_id_reason
    assert test_id is not None
    expected_digest = REVIEWED_PACKAGE_WORLD_TRANSITION_SHA256.get(test_id)
    if expected_digest is None:
        return "", f"unreviewed package-self modal transition {test_id!r}"
    payload, payload_reasons = _package_world_transition_payload(
        test,
        expected_kind,
        evaluated_claim_id,
    )
    if payload is None:
        return "", (
            f"package-self modal transition {test_id!r} is not canonical: "
            + "; ".join(payload_reasons)
        )
    observed_digest = hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    if observed_digest != expected_digest:
        return "", (
            f"package-self modal transition {test_id!r} does not match "
            "the reviewed registry"
        )
    return observed_digest, None


def _package_world_registry_inventory_reasons(
    claims: Sequence[Mapping[str, Any]],
) -> List[str]:
    """Require every reviewed package transition exactly once certificate-wide."""
    expected = Counter({
        test_id: 1
        for test_id in REVIEWED_PACKAGE_WORLD_TRANSITION_SHA256
    })
    actual: Counter[str] = Counter()
    identity_reasons: List[str] = []
    for claim_index, claim in enumerate(claims):
        for field in ("false_world_tests", "true_world_tests"):
            raw_tests = claim.get(field)
            tests = raw_tests if type(raw_tests) is list else _as_list(raw_tests)
            for test_index, test in enumerate(tests):
                if isinstance(test, Mapping):
                    test_id, test_id_reason = _package_modal_test_id(test)
                    if test_id_reason is not None:
                        identity_reasons.append(
                            f"{test_id_reason} at claims[{claim_index}]."
                            f"{field}[{test_index}]"
                        )
                        continue
                    assert test_id is not None
                else:
                    identity_reasons.append(
                        "package-self modal test is not an object at "
                        f"claims[{claim_index}].{field}[{test_index}]"
                    )
                    continue
                actual[test_id] += 1
    if actual == expected and not identity_reasons:
        return []
    reasons: List[str] = list(identity_reasons)
    missing = sorted(
        test_id
        for test_id in expected
        if actual.get(test_id, 0) == 0
    )
    unreviewed = sorted(
        (test_id, count)
        for test_id, count in actual.items()
        if test_id not in expected
    )
    duplicates = sorted(
        (test_id, count)
        for test_id, count in actual.items()
        if count > 1
    )
    if missing:
        reasons.append(
            "package-self reviewed registry missing modal test IDs: "
            + ", ".join(missing)
        )
    if unreviewed:
        reasons.append(
            "package-self unreviewed modal test IDs: "
            + ", ".join(
                f"{test_id} x{count}" for test_id, count in unreviewed
            )
        )
    if duplicates:
        reasons.append(
            "package-self duplicate modal test IDs: "
            + ", ".join(
                f"{test_id} x{count}" for test_id, count in duplicates
            )
        )
    return reasons


def _distinct_observation_capacity(
    observation_sets: Sequence[set[Tuple[Any, ...]]],
    required: int,
) -> int:
    """Return threshold-capped one-to-one capacity in linear work.

    The fixed policy requires at most two false-world and one true-world
    observations. For thresholds 0..2, Hall's condition reduces to enough
    nonempty tests and enough distinct observations across them.
    """
    if required not in {0, 1, 2}:
        raise InvalidInputError(
            "modal observation threshold exceeds supported bound 2"
        )
    if required == 0:
        return 0
    nonempty_tests = 0
    observations: set[Tuple[Any, ...]] = set()
    for identities in observation_sets:
        if identities:
            nonempty_tests = min(required, nonempty_tests + 1)
        if len(observations) < required:
            for identity in identities:
                observations.add(identity)
                if len(observations) >= required:
                    break
    return min(required, nonempty_tests, len(observations))


def _modal_observation_sets(
    results: Sequence[TestResult],
) -> List[set[Tuple[Any, ...]]]:
    """Map test evidence to physical artifact plus verified case identity."""
    output: List[set[Tuple[Any, ...]]] = []
    for result in results:
        identities: set[Tuple[Any, ...]] = set()
        for check in result.evidence_checks:
            if not check.structured or not check.artifact_path_resolved:
                continue
            if check.observation_id:
                identities.add(("observation", check.observation_id))
            elif check.artifact_sha256:
                identities.add(
                    ("artifact-sha256", check.artifact_sha256)
                )
        output.append(identities)
    return output


def _modal_test_uniqueness_reasons(
    tests: Sequence[Mapping[str, Any]],
    results: Sequence[TestResult],
    expected_kind: str,
    required: int,
    evidence_root: Optional[Path],
    evaluated_claim_id: str,
    downstream_policy: DownstreamPolicy = DOWNSTREAM_POLICIES["generic"],
) -> List[str]:
    reasons: List[str] = []
    label = "false-world" if expected_kind == "false_world" else "true-world"
    if not tests:
        return reasons
    ids = [_test_id(t) for t in tests]
    nonempty_ids = [i for i in ids if i]
    id_counts: Dict[str, int] = {}
    for identifier in nonempty_ids:
        id_counts[identifier] = id_counts.get(identifier, 0) + 1
    duplicate_ids = sorted(
        identifier
        for identifier, count in id_counts.items()
        if count > 1
    )
    missing_count = len(ids) - len(nonempty_ids)
    if missing_count:
        reasons.append(f"missing {label} test IDs present: {missing_count}")
    if duplicate_ids:
        reasons.append(f"duplicate {label} test IDs present: {', '.join(duplicate_ids)}")
    keys = [
        _modal_test_key(
            test,
            expected_kind,
            evidence_root,
            evaluated_claim_id,
        )
        for test in tests
    ]
    reviewer_keys = {
        (kind, claim_id, equivalence_class)
        for kind, claim_id, equivalence_class, _ in keys
    }
    structural_keys = {
        (kind, claim_id, structural_fingerprint)
        for kind, claim_id, _, structural_fingerprint in keys
    }
    if len(reviewer_keys) < required:
        reasons.append(
            f"reviewer-classified distinct {label} cases "
            f"{len(reviewer_keys)} "
            f"< required {required}"
        )
    if len(structural_keys) < required:
        reasons.append(
            f"structurally distinct {label} cases {len(structural_keys)} "
            f"< required {required}"
        )
    if downstream_policy.name == "package-self":
        reviewed_keys: set[str] = set()
        for test in tests:
            reviewed_digest, reviewed_reason = (
                _reviewed_package_world_transition_digest(
                    test,
                    expected_kind,
                    evaluated_claim_id,
                )
            )
            if reviewed_reason is not None:
                reasons.append(reviewed_reason)
            elif reviewed_digest:
                reviewed_keys.add(reviewed_digest)
        if len(reviewed_keys) < required:
            reasons.append(
                f"reviewed-registry distinct {label} cases "
                f"{len(reviewed_keys)} < required {required}"
            )
    elif any(
        test_id in REVIEWED_PACKAGE_WORLD_TRANSITION_SHA256
        for test_id in nonempty_ids
    ):
        # A package integration must opt into package-self explicitly. Merely
        # presenting a known registry ID under the generic evaluator is not an
        # authorization path and must never yield a silent generic pass.
        reasons.append(
            "registered package-self modal transitions require the "
            "package-self downstream policy"
        )
    if evidence_root is not None:
        observation_sets = _modal_observation_sets(results)
        distinct_observations = _distinct_observation_capacity(
            observation_sets,
            required,
        )
        if distinct_observations < required:
            reasons.append(
                f"distinct {label} case-bound declaration identities "
                f"{distinct_observations} "
                f"< required {required}"
            )
    else:
        evidence_sets = [
            _canonical_test_evidence_keys(test, evidence_root)
            for test in tests
            if _canonical_test_evidence_keys(test, evidence_root)
        ]
        if evidence_sets:
            unique_evidence_sets = set(evidence_sets)
            expected_evidence_sets = min(required, len(evidence_sets))
            if len(unique_evidence_sets) < expected_evidence_sets:
                reasons.append(
                    f"unique {label} test evidence sets "
                    f"{len(unique_evidence_sets)} < required "
                    f"{expected_evidence_sets}"
                )
    return reasons


def evaluate_claim(
    claim: Mapping[str, Any],
    thresholds: Mapping[str, Mapping[str, float]],
    evidence_root: Optional[Path] = None,
    certificate_assurance: Optional[Mapping[str, Any]] = None,
    downstream_policy: DownstreamPolicy = DOWNSTREAM_POLICIES["generic"],
    json_cache: Optional[
        Dict[JsonCacheKey, BoundedJsonResult]
    ] = None,
) -> ClaimResult:
    raw_claim_id = claim.get("id")
    canonical_claim_id = _canonical_proposition_text(raw_claim_id)
    cid = (
        raw_claim_id
        if type(raw_claim_id) is str and raw_claim_id
        else "<invalid-id>"
    )
    raw_importance = claim.get("importance")
    imp = _lower(raw_importance or "critical")
    if imp not in IMPORTANCE: imp = "critical"
    reasons: List[str] = []
    if canonical_claim_id is None:
        reasons.append("claim id must be a nonempty string")
    elif raw_claim_id != canonical_claim_id:
        reasons.append("claim id is not canonical")
    claim_text = claim.get("text")
    if _canonical_proposition_text(claim_text) is None:
        reasons.append("claim text must be a nonempty string")
    if type(raw_importance) is not str or raw_importance not in IMPORTANCE:
        reasons.append(
            "importance must be exactly critical, major, or minor"
        )
    reasons.extend(_claim_collection_shape_reasons(claim, context="claim"))
    expected_claim_digest = _proposition_sha256(claim_text)
    declared_claim_digest = _canonical_claimed_sha256(
        claim.get("proposition_sha256")
    )
    if (
        evidence_root is not None
        or _nonempty(claim.get("proposition_sha256"))
    ) and declared_claim_digest != expected_claim_digest:
        reasons.append(
            "proposition_sha256 does not match canonical claim text"
        )
    expected_contract_digest = _claim_contract_sha256(
        claim,
        certificate_assurance,
    )
    if evidence_root is not None:
        if claim.get("claim_contract_schema_version") != CLAIM_CONTRACT_SCHEMA_VERSION:
            reasons.append(
                "claim_contract_schema_version is not "
                f"{CLAIM_CONTRACT_SCHEMA_VERSION}"
            )
        _, contract_reasons = _claim_contract_payload(
            claim,
            certificate_assurance,
        )
        reasons.extend(contract_reasons)
        declared_contract_digest = _canonical_claimed_sha256(
            claim.get("claim_contract_sha256")
        )
        if declared_contract_digest != expected_contract_digest:
            reasons.append(
                "claim_contract_sha256 does not match canonical "
                "method-relative claim contract"
            )
    if _canonical_proposition_text(claim.get("artifact_location")) is None:
        reasons.append("artifact_location must be a nonempty string")
    truth = _lower(claim.get("truth_status"))
    if imp in {"critical", "major"} and truth not in PASS_TRUTH: reasons.append(f"{imp} truth_status is {truth!r}; required confirmed")
    if imp == "minor" and truth not in MINOR_TRUTH: reasons.append(f"minor truth_status is {truth!r}; required supported or confirmed")
    method = (
        claim.get("method_m")
        if "method_m" in claim
        else claim.get("method")
    )
    computed_method, missing_method = method_completeness(method if isinstance(method, Mapping) else None)
    method_score = computed_method
    if claim.get("method_completeness") is not None:
        try: method_score = min(computed_method, max(0.0, min(1.0, float(claim.get("method_completeness")))))
        except (TypeError, ValueError, OverflowError): reasons.append(f"non-numeric method_completeness {claim.get('method_completeness')!r}")
    if missing_method and imp in {"critical", "major"}: reasons.append(f"missing method components: {missing_method}")
    th = thresholds[imp]
    if method_score < th["method_completeness"]: reasons.append(f"method completeness {method_score:.3f} < threshold {th['method_completeness']:.3f}")

    raw_evidence_refs = claim.get("evidence_refs")
    if (
        type(raw_evidence_refs) is not list
        or any(
            type(ref) is not str
            or _canonical_proposition_text(ref) != ref
            for ref in (
                raw_evidence_refs
                if type(raw_evidence_refs) is list
                else []
            )
        )
        or (
            type(raw_evidence_refs) is list
            and len(set(raw_evidence_refs)) != len(raw_evidence_refs)
        )
    ):
        reasons.append(
            "claim evidence_refs must be a duplicate-free list of "
            "canonical nonempty strings"
        )
    ev_refs = (
        list(raw_evidence_refs)
        if type(raw_evidence_refs) is list
        else []
    )
    req = MIN_REQ[imp]
    structured_checks = [
        _load_structured_evidence(
            evidence,
            evidence_root,
            claim_id=cid,
            claim_proposition=claim_text,
            claim_contract_sha256=expected_contract_digest,
            json_cache=json_cache,
        )
        for evidence in ev_refs
    ]
    if evidence_root is not None:
        invalid_refs = [c for c in structured_checks if c.reasons]
        if invalid_refs:
            reasons.append("invalid evidence refs: " + "; ".join(f"{c.ref}: {', '.join(c.reasons)}" for c in invalid_refs))

        valid_ref_digests = [
            check.wrapper_sha256
            for check in structured_checks
            if check.canonical_ref and check.wrapper_sha256
        ]
        unique_ref_digests = set(valid_ref_digests)
        duplicate_count = len(valid_ref_digests) - len(unique_ref_digests)
        ev_count = len(unique_ref_digests)
        if ev_count < req["evidence"]:
            reasons.append(f"unique evidence refs {ev_count} < required {req['evidence']}")
        if duplicate_count > 0 and imp in {"critical", "major"}:
            reasons.append(f"duplicate or aliased evidence refs present: {duplicate_count}")

        unique_structured_refs = _unique_valid_evidence_refs(structured_checks)
        structured_count = len(unique_structured_refs)
        if structured_count < req["structured_evidence"]:
            reasons.append(f"unique structured evidence refs {structured_count} < required {req['structured_evidence']}")

        unique_artifacts = _unique_valid_artifacts(structured_checks)
        unique_artifact_count = len(unique_artifacts)
        if req["evidence"] > 1 and structured_count >= req["structured_evidence"] and unique_artifact_count < min(req["evidence"], structured_count):
            reasons.append(f"unique structured evidence artifacts {unique_artifact_count} < unique structured evidence refs {structured_count}")
    else:
        ev_count = len(ev_refs)
        structured_count = sum(c.structured for c in structured_checks)
        unique_artifact_count = 0
        if ev_count < req["evidence"]:
            reasons.append(f"evidence refs {ev_count} < required {req['evidence']}")
    raw_false_tests = claim.get("false_world_tests")
    raw_true_tests = claim.get("true_world_tests")
    false_entries = (
        list(raw_false_tests) if type(raw_false_tests) is list else []
    )
    true_entries = (
        list(raw_true_tests) if type(raw_true_tests) is list else []
    )
    false_nonobjects = sum(
        not isinstance(test, Mapping) for test in false_entries
    )
    true_nonobjects = sum(
        not isinstance(test, Mapping) for test in true_entries
    )
    if false_nonobjects:
        reasons.append(
            "false_world_tests contains non-object entries: "
            f"{false_nonobjects}"
        )
    if true_nonobjects:
        reasons.append(
            "true_world_tests contains non-object entries: "
            f"{true_nonobjects}"
        )
    ftests = [t for t in false_entries if isinstance(t, Mapping)]
    ttests = [t for t in true_entries if isinstance(t, Mapping)]
    if len(ftests) < req["false_tests"]: reasons.append(f"false-world tests {len(ftests)} < required {req['false_tests']}")
    if len(ttests) < req["true_tests"]: reasons.append(f"true-world tests {len(ttests)} < required {req['true_tests']}")
    sens, fr = evaluate_tests(
        ftests,
        "false_world",
        evidence_root=evidence_root,
        claim_id=cid,
        claim_proposition=claim_text,
        claim_contract_sha256=expected_contract_digest,
        json_cache=json_cache,
    )
    adh, tr = evaluate_tests(
        ttests,
        "true_world",
        evidence_root=evidence_root,
        claim_id=cid,
        claim_proposition=claim_text,
        claim_contract_sha256=expected_contract_digest,
        json_cache=json_cache,
    )
    reasons.extend(
        _modal_test_uniqueness_reasons(
            ftests,
            fr,
            "false_world",
            req["false_tests"],
            evidence_root,
            cid,
            downstream_policy,
        )
    )
    reasons.extend(
        _modal_test_uniqueness_reasons(
            ttests,
            tr,
            "true_world",
            req["true_tests"],
            evidence_root,
            cid,
            downstream_policy,
        )
    )
    fails = [r for r in fr + tr if r.status != "PASS"]
    if fails: reasons.append(f"{len(fails)} test(s) failed deterministic checks")
    if ftests and sens < th["sensitivity"]: reasons.append(f"sensitivity pass rate {sens:.3f} < threshold {th['sensitivity']:.3f}")
    if ttests and adh < th["adherence"]: reasons.append(f"adherence pass rate {adh:.3f} < threshold {th['adherence']:.3f}")
    unresolved = [
        contradiction
        for contradiction in _claim_contradictions(claim)
        if _nonempty(contradiction)
    ]
    if unresolved: reasons.append(f"unresolved contradictions present: {len(unresolved)}")
    if isinstance(method, Mapping):
        mus = _collect_unknowns_in_method(method)
        if mus and imp in {"critical", "major"}: reasons.append(f"{imp} method unknowns present: {len(mus)}")
    status = "PASS" if not reasons else "FAIL"
    return ClaimResult(cid, imp, status, reasons, sens, adh, method_score, ev_count, structured_count, len(ftests), len(ttests), fr + tr, ev_count, structured_count, unique_artifact_count)



def _resolve_downstream_policy(
    policy: str | DownstreamPolicy,
) -> DownstreamPolicy:
    if isinstance(policy, DownstreamPolicy):
        canonical = DOWNSTREAM_POLICIES.get(policy.name)
        if canonical is None or policy != canonical:
            raise InvalidInputError(
                "downstream policy object is not an exact registered policy"
            )
        return canonical
    if type(policy) is not str or policy not in DOWNSTREAM_POLICIES:
        raise InvalidInputError(f"unknown downstream policy: {policy!r}")
    return DOWNSTREAM_POLICIES[policy]


def _canonical_proposition_text(value: Any) -> Optional[str]:
    if type(value) is not str or not value.strip():
        return None
    normalized = unicodedata.normalize("NFC", value)
    return re.sub(r"\s+", " ", normalized).strip()


def _proposition_sha256(value: Any) -> Optional[str]:
    canonical = _canonical_proposition_text(value)
    if canonical is None:
        return None
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_identity_json(value: Any, *, depth: int = 0) -> Any:
    """Return a deterministic JSON value for integrity identities.

    Strings use the same NFC/whitespace canonicalization as propositions.
    Arrays retain order because argv, grader, and trace order may be part of
    method M. Object keys are sorted by the serializer.
    """
    if depth > 64:
        raise ValueError("identity JSON exceeds maximum depth 64")
    if type(value) is str:
        normalized = unicodedata.normalize("NFC", value)
        return re.sub(r"\s+", " ", normalized).strip()
    if value is None or type(value) in {bool, int}:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("identity JSON contains a non-finite number")
        return value
    if type(value) is list:
        return [
            _canonical_identity_json(item, depth=depth + 1)
            for item in value
        ]
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise ValueError("identity JSON object keys must be strings")
        return {
            key: _canonical_identity_json(item, depth=depth + 1)
            for key, item in value.items()
        }
    raise ValueError(
        f"identity value has unsupported type {type(value).__name__}"
    )


def _certificate_assurance_payload(
    cert: Mapping[str, Any],
    downstream_policy: DownstreamPolicy,
) -> Dict[str, Any]:
    """Return every certificate-level input that can weaken gate status.

    Each strict claim wrapper authenticates this same payload through its claim
    contract.  Consequently, deleting a scope limitation or method unknown,
    relaxing a threshold, or changing downstream non-closure state invalidates
    the wrappers instead of silently promoting the certificate.
    """
    payload = {
        "schema_version": CERTIFICATE_ASSURANCE_SCHEMA_VERSION,
        "downstream_policy": {
            "name": downstream_policy.name,
            "require_records": downstream_policy.require_records,
            "require_review": downstream_policy.require_review,
            "require_own_claim_field": (
                downstream_policy.require_own_claim_field
            ),
        },
        "method_manifest": cert.get("method_manifest"),
        "scope_limitations": cert.get("scope_limitations", []),
        "unknowns": cert.get("unknowns", []),
        "method_unknowns": cert.get("method_unknowns", []),
        "gate_thresholds": cert.get("gate_thresholds"),
        "derived_or_downstream_claims": cert.get(
            "derived_or_downstream_claims", []
        ),
        "downstream_review": cert.get("downstream_review"),
        "claim_inventory": [
            {
                "id": _canonical_proposition_text(claim.get("id")) or "",
                "local_claim_contract_sha256": _claim_contract_sha256(claim),
            }
            for claim in cert.get("claims", [])
            if isinstance(claim, Mapping)
        ],
    }
    canonical = _canonical_identity_json(payload)
    assert isinstance(canonical, dict)
    return canonical


def _claim_collection_shape_reasons(
    claim: Mapping[str, Any],
    *,
    context: str,
) -> List[str]:
    """Require every strict claim collection to retain its JSON-array shape."""
    reasons: List[str] = []
    contradiction_fields = [
        field
        for field in ("unresolved_contradictions", "contradictions")
        if field in claim
    ]
    if not contradiction_fields:
        reasons.append(
            f"{context} must include unresolved_contradictions or "
            "contradictions as a list"
        )
    for field in contradiction_fields:
        if type(claim.get(field)) is not list:
            reasons.append(f"{context} {field} must be a list")
    for field in (
        "residual_risks",
        "false_world_tests",
        "true_world_tests",
    ):
        if field not in claim or type(claim.get(field)) is not list:
            reasons.append(f"{context} {field} must be a list")
    return reasons


def _claim_contradictions(claim: Mapping[str, Any]) -> List[Any]:
    """Collect the documented field and its pre-1.0 short alias.

    Treating the names as additive prevents a certificate from hiding an open
    contradiction in the alias merely because an empty documented field is
    also present.  Empty/missing variants canonicalize to the same list.
    """
    combined: List[Any] = []
    for field in ("unresolved_contradictions", "contradictions"):
        values = claim.get(field)
        if type(values) is list:
            combined.extend(values)
    return combined


def _claim_contract_payload(
    claim: Mapping[str, Any],
    certificate_assurance: Optional[Mapping[str, Any]] = None,
) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """Build the versioned method-relative identity for a claim."""
    reasons: List[str] = []
    raw_claim_id = claim.get("id")
    claim_id = _canonical_proposition_text(raw_claim_id)
    if claim_id is None:
        reasons.append("claim contract id must be a nonempty string")
    elif raw_claim_id != claim_id:
        reasons.append("claim contract id is not canonical")
    text = _canonical_proposition_text(claim.get("text"))
    if text is None:
        reasons.append("claim contract text must be a nonempty string")
    scope = _canonical_proposition_text(claim.get("scope"))
    if scope is None:
        reasons.append("claim contract scope must be a nonempty string")
    artifact_location = _canonical_proposition_text(
        claim.get("artifact_location")
    )
    if artifact_location is None:
        reasons.append(
            "claim contract artifact_location must be a nonempty string"
        )
    importance = claim.get("importance")
    if type(importance) is not str or importance not in IMPORTANCE:
        reasons.append(
            "claim contract importance must be exactly critical, major, or minor"
        )
    reasons.extend(
        _claim_collection_shape_reasons(claim, context="claim contract")
    )
    raw_evidence_refs = claim.get("evidence_refs")
    if (
        type(raw_evidence_refs) is not list
        or any(
            type(ref) is not str
            or _canonical_proposition_text(ref) != ref
            for ref in (
                raw_evidence_refs
                if type(raw_evidence_refs) is list
                else []
            )
        )
        or (
            type(raw_evidence_refs) is list
            and len(set(raw_evidence_refs)) != len(raw_evidence_refs)
        )
    ):
        reasons.append(
            "claim contract evidence_refs must be a duplicate-free list "
            "of canonical nonempty strings"
        )
    method = claim.get("method_m")
    if not isinstance(method, Mapping):
        reasons.append("claim contract method_m must be an object")
        canonical_method = None
    else:
        try:
            canonical_method = _canonical_identity_json(method)
        except ValueError as exc:
            reasons.append(f"claim contract method_m is invalid: {exc}")
            canonical_method = None
    try:
        canonical_contradictions = _canonical_identity_json(
            _claim_contradictions(claim)
        )
        canonical_residual_risks = _canonical_identity_json(
            claim.get("residual_risks", [])
        )
        canonical_assurance = _canonical_identity_json(
            certificate_assurance
        )
        canonical_evidence_refs = _canonical_identity_json(
            claim.get("evidence_refs", [])
        )
        canonical_false_tests = _canonical_identity_json(
            claim.get("false_world_tests", [])
        )
        canonical_true_tests = _canonical_identity_json(
            claim.get("true_world_tests", [])
        )
    except ValueError as exc:
        reasons.append(f"claim assurance fields are invalid: {exc}")
        canonical_contradictions = None
        canonical_residual_risks = None
        canonical_assurance = None
        canonical_evidence_refs = None
        canonical_false_tests = None
        canonical_true_tests = None
    if reasons:
        return None, reasons
    assert text is not None
    assert scope is not None
    assert artifact_location is not None
    assert type(importance) is str
    assert canonical_method is not None
    return {
        "schema_version": CLAIM_CONTRACT_SCHEMA_VERSION,
        "id": claim_id,
        "text": text,
        "scope": scope,
        "artifact_location": artifact_location,
        "importance": importance,
        "method_m": canonical_method,
        "truth_status": _lower(claim.get("truth_status")),
        "method_completeness": claim.get("method_completeness"),
        "unresolved_contradictions": canonical_contradictions,
        "residual_risks": canonical_residual_risks,
        "evidence_refs": canonical_evidence_refs,
        "false_world_tests": canonical_false_tests,
        "true_world_tests": canonical_true_tests,
        "certificate_assurance": canonical_assurance,
    }, []


def _claim_contract_sha256(
    claim: Mapping[str, Any],
    certificate_assurance: Optional[Mapping[str, Any]] = None,
) -> Optional[str]:
    payload, _ = _claim_contract_payload(claim, certificate_assurance)
    if payload is None:
        return None
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _modal_case_sha256(
    test: Mapping[str, Any],
    claim_proposition: Any,
    expected_kind: str,
    evidence_observed_result: Any = None,
    *,
    claim_contract_sha256: Any = None,
) -> Optional[str]:
    claim_text = _canonical_proposition_text(claim_proposition)
    if claim_text is None:
        return None
    contract_digest = _canonical_claimed_sha256(claim_contract_sha256)
    if contract_digest is None:
        return None
    world_contract, _ = _canonical_world_contract(test.get("world_contract"))
    if world_contract is None:
        return None
    if _nonempty(test.get("perturbation")):
        variation_field = "perturbation"
        variation = test.get("perturbation")
    else:
        variation_field = "variant"
        variation = test.get("variant")
    payload = {
        "claim_proposition": claim_text,
        "claim_contract_sha256": contract_digest,
        "kind": _lower(test.get("kind") or expected_kind),
        "test_id": _test_id(test),
        "target_claim_ids": sorted(set(_target_claim_values(test))),
        "variation_field": variation_field,
        "variation": _canonical_proposition_text(variation) or "",
        "world_contract": world_contract,
        "expected_behavior": (
            _canonical_proposition_text(test.get("expected_behavior")) or ""
        ),
        "observed_behavior": (
            _canonical_proposition_text(test.get("observed_behavior")) or ""
        ),
        "observed_result": (
            _canonical_proposition_text(
                evidence_observed_result
                if evidence_observed_result is not None
                else test.get("observed_result")
            ) or ""
        ),
        "outcome": _lower(test.get("outcome")),
        "observed_outcome": _lower(test.get("observed_outcome")),
        "result": _lower(test.get("result")),
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _downstream_proposition_binding_reasons(
    downstream_id: str,
    derived_claim: Any,
    own_claim: Mapping[str, Any],
    binding: Any,
) -> List[str]:
    """Require an explicit versioned textual proposition identity.

    Semantic equivalence is not guessed. The downstream proposition and the
    independently evaluated claim must canonicalize to the same text and digest.
    """
    prefix = f"downstream claim {downstream_id} proposition binding"
    if not isinstance(binding, Mapping):
        return [f"{prefix} is not an object"]
    reasons: List[str] = []
    if binding.get("schema_version") != PROPOSITION_BINDING_SCHEMA_VERSION:
        reasons.append(
            f"{prefix} schema_version is not "
            f"{PROPOSITION_BINDING_SCHEMA_VERSION}"
        )
    raw_digest = binding.get("canonical_text_sha256")
    claimed_digest = _canonical_claimed_sha256(raw_digest)
    if claimed_digest is None:
        reasons.append(
            f"{prefix} canonical_text_sha256 is not a SHA-256 digest"
        )
    downstream_digest = _proposition_sha256(derived_claim)
    own_digest = _proposition_sha256(own_claim.get("text"))
    if downstream_digest is None or own_digest is None:
        reasons.append(
            f"{prefix} requires nonempty downstream and own-claim text"
        )
    elif downstream_digest != own_digest:
        reasons.append(
            f"{prefix} does not identify the independent claim proposition"
        )
    if (
        claimed_digest is not None
        and downstream_digest is not None
        and claimed_digest != downstream_digest
    ):
        reasons.append(
            f"{prefix} digest does not match the downstream proposition"
        )
    if (
        claimed_digest is not None
        and own_digest is not None
        and claimed_digest != own_digest
    ):
        reasons.append(
            f"{prefix} digest does not match the independent claim"
        )
    return reasons


def evaluate_downstream_nonclosure(
    cert: Mapping[str, Any],
    claim_results: Optional[Mapping[str, Any] | set[str]] = None,
    policy: str | DownstreamPolicy = "generic",
) -> Tuple[List[str], int]:
    """Apply the shared policy-aware downstream non-closure contract."""
    selected_policy = _resolve_downstream_policy(policy)
    reasons: List[str] = []
    raw_claims = cert.get("claims")
    claims = (
        [claim for claim in raw_claims if isinstance(claim, Mapping)]
        if isinstance(raw_claims, list)
        else []
    )
    claim_records: Dict[str, Mapping[str, Any]] = {}
    for claim in claims:
        raw_id = claim.get("id")
        if type(raw_id) is not str or not raw_id.strip():
            continue
        claim_id = raw_id.strip()
        if claim_id in claim_records:
            reasons.append(
                f"duplicate claim id used by downstream policy: {claim_id}"
            )
        else:
            claim_records[claim_id] = claim

    evaluated_status: Dict[str, Optional[str]] = {}
    if isinstance(claim_results, Mapping):
        for claim_id, result in claim_results.items():
            if isinstance(result, ClaimResult):
                evaluated_status[str(claim_id)] = result.status
            elif isinstance(result, Mapping):
                status = result.get("status")
                evaluated_status[str(claim_id)] = (
                    status if isinstance(status, str) else None
                )
    elif isinstance(claim_results, set):
        evaluated_status = {str(claim_id): None for claim_id in claim_results}

    raw_records = cert.get("derived_or_downstream_claims")
    if raw_records is None:
        records: List[Any] = []
    elif isinstance(raw_records, list):
        records = list(raw_records)
    else:
        records = []
        reasons.append("derived_or_downstream_claims is not a list")
    if selected_policy.require_records and not records:
        reasons.append(
            "certificate lacks derived_or_downstream_claims non-closure records"
        )

    record_ids: List[str] = []
    for idx, record in enumerate(records, start=1):
        if not isinstance(record, Mapping):
            reasons.append(
                f"derived_or_downstream_claims[{idx}] is not an object"
            )
            continue
        raw_did = record.get("id")
        if type(raw_did) is not str or not raw_did.strip():
            did = f"derived-{idx}"
            reasons.append(
                f"downstream claim {did} has a non-string or empty id"
            )
        else:
            did = raw_did.strip()
            if did in record_ids:
                reasons.append(f"duplicate downstream claim id: {did}")
            record_ids.append(did)

        derived_claim = record.get("derived_claim", record.get("claim"))
        if type(derived_claim) is not str or not derived_claim.strip():
            reasons.append(f"downstream claim {did} lacks derived_claim text")

        raw_from_ids = record.get("from_claim_ids")
        if not isinstance(raw_from_ids, list) or not raw_from_ids:
            from_ids: List[str] = []
            reasons.append(f"downstream claim {did} lacks from_claim_ids")
        elif not all(
            type(item) is str and item.strip() for item in raw_from_ids
        ):
            from_ids = []
            reasons.append(
                f"downstream claim {did} has non-string or empty from_claim_ids"
            )
        else:
            from_ids = [item.strip() for item in raw_from_ids]
            unknown_sources = sorted(set(from_ids) - set(claim_records))
            if unknown_sources:
                reasons.append(
                    f"downstream claim {did} cites unknown source claim ids: "
                    f"{unknown_sources}"
                )

        raw_status = record.get("status")
        if type(raw_status) is not str:
            status = ""
            reasons.append(f"downstream claim {did} has a non-string status")
        else:
            status = raw_status.strip().lower()
        if status not in DOWNSTREAM_STATUSES:
            reasons.append(
                f"downstream claim {did} uses unsupported status: "
                f"{raw_status!r}"
            )

        own_field_present = "own_claim_id" in record
        raw_own_claim_id = (
            record.get("own_claim_id")
            if own_field_present
            else record.get("claim_id")
        )
        if raw_own_claim_id is not None and (
            type(raw_own_claim_id) is not str
            or not raw_own_claim_id.strip()
        ):
            reasons.append(
                f"downstream claim {did} has a non-string or empty own_claim_id"
            )
            own_claim_id = ""
        else:
            own_claim_id = (
                raw_own_claim_id.strip()
                if isinstance(raw_own_claim_id, str)
                else ""
            )

        if status in DOWNSTREAM_PASS_STATUSES:
            if selected_policy.require_own_claim_field and not own_field_present:
                reasons.append(
                    f"downstream claim {did} pass status requires own_claim_id"
                )
            if not own_claim_id:
                reasons.append(
                    f"downstream claim {did} attempts automatic closure/status "
                    "inheritance without an independent claim record"
                )
            elif own_claim_id in from_ids:
                reasons.append(
                    f"downstream claim {did} aliases source claim "
                    f"{own_claim_id} instead of a distinct independent claim"
                )
            elif own_claim_id not in claim_records:
                reasons.append(
                    f"downstream claim {did} cites missing independent claim "
                    f"{own_claim_id}"
                )
            else:
                reasons.extend(
                    _downstream_proposition_binding_reasons(
                        did,
                        derived_claim,
                        claim_records[own_claim_id],
                        record.get("proposition_binding"),
                    )
                )
                if evaluated_status.get(own_claim_id) != "PASS":
                    reasons.append(
                        f"downstream claim {did} independent claim "
                        f"{own_claim_id} did not evaluate PASS"
                    )
        if status in DOWNSTREAM_NONPASS_STATUSES:
            reason = record.get("reason")
            if type(reason) is not str or not reason.strip():
                reasons.append(
                    f"downstream claim {did} is non-passing but lacks a reason"
                )

    if selected_policy.require_review:
        review = cert.get("downstream_review")
        if not isinstance(review, Mapping):
            reasons.append("promotion downstream_review is not an object")
        else:
            if review.get("performed") is not True:
                reasons.append(
                    "promotion downstream_review.performed is not true"
                )
            identified = review.get("claims_identified")
            if not isinstance(identified, list) or not all(
                type(item) is str and item.strip() for item in identified
            ):
                reasons.append(
                    "promotion downstream_review.claims_identified is not a "
                    "list of nonempty strings"
                )
            else:
                normalized = [item.strip() for item in identified]
                if len(set(normalized)) != len(normalized):
                    reasons.append(
                        "promotion downstream_review.claims_identified "
                        "contains duplicates"
                    )
                if set(normalized) != set(record_ids):
                    reasons.append(
                        "promotion downstream_review.claims_identified does "
                        "not match downstream records"
                    )
                if not normalized:
                    none_reason = review.get("none_identified_reason")
                    if (
                        type(none_reason) is not str
                        or not none_reason.strip()
                    ):
                        reasons.append(
                            "promotion downstream_review."
                            "none_identified_reason is required when no "
                            "claims are identified"
                        )
    return reasons, len(records)

def _invalid_certificate_result(
    reason: str,
    summary_updates: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    summary: Dict[str, Any] = {
        "claims": 0,
        "failed_claims": 0,
        "critical_failed": 0,
        "major_failed": 0,
        "downstream_nonclosure_violations": 0,
    }
    summary.update(summary_updates or {})
    return {
        "status": "INVALID_INPUT",
        "failure_kind": "invalid_input",
        "summary": summary,
        "reasons": [reason],
        "claim_results": [],
    }


def evaluate_certificate(
    cert: Any,
    evidence_root: Optional[Path] = None,
    strict_evidence: bool = False,
    downstream_policy: str | DownstreamPolicy = "generic",
) -> Dict[str, Any]:
    try:
        selected_downstream_policy = _resolve_downstream_policy(
            downstream_policy
        )
    except InvalidInputError as exc:
        return _invalid_certificate_result(str(exc))
    if not isinstance(cert, Mapping):
        return _invalid_certificate_result(
            "certificate JSON root is not an object"
        )
    bounds_error = _validate_json_bounds(cert)
    if bounds_error is not None:
        return _invalid_certificate_result(bounds_error)
    if strict_evidence and evidence_root is None:
        return _invalid_certificate_result(
            "strict_evidence requires evidence_root",
            {
                "evidence_root_checked": False,
                "strict_evidence": True,
                "structured_evidence_required": True,
                "structured_evidence_checked": False,
            },
        )
    raw_claims = cert.get("claims")
    if raw_claims is not None and not isinstance(raw_claims, list):
        return _invalid_certificate_result("certificate claims is not a list")
    if isinstance(raw_claims, list) and any(
        not isinstance(claim, Mapping) for claim in raw_claims
    ):
        return _invalid_certificate_result(
            "certificate claims contains a non-object entry"
        )
    unknown_shape_error = _unknown_collection_shape_error(cert)
    if unknown_shape_error is not None:
        return _invalid_certificate_result(unknown_shape_error)
    evidence_root_error: Optional[str] = None
    evidence_root_capability: Optional[EvidenceRootCapability] = None
    if evidence_root is not None:
        if not isinstance(evidence_root, Path):
            evidence_root_error = "evidence_root is not a pathlib Path"
        else:
            try:
                evidence_root_capability = (
                    _open_evidence_root_capability(evidence_root)
                )
            except (OSError, RuntimeError, ValueError) as exc:
                evidence_root_error = (
                    "evidence_root stat failed: "
                    f"{type(exc).__name__}"
                )
    if evidence_root_error is not None:
        return _invalid_certificate_result(
            evidence_root_error,
            {
                "evidence_root_checked": False,
                "strict_evidence": bool(strict_evidence),
                "structured_evidence_required": True,
                "structured_evidence_checked": False,
            },
        )
    thresholds, notes = merge_thresholds(cert.get("gate_thresholds"))
    reasons: List[str] = list(notes)
    claims = list(raw_claims or [])
    if not claims: reasons.append("no claims in certificate")
    package_registry_inventory_reasons: List[str] = []
    if selected_downstream_policy.name == "package-self":
        package_registry_inventory_reasons = (
            _package_world_registry_inventory_reasons(claims)
        )
        reasons.extend(package_registry_inventory_reasons)
    try:
        certificate_assurance = _certificate_assurance_payload(
            cert,
            selected_downstream_policy,
        )
    except ValueError as exc:
        return _invalid_certificate_result(
            f"certificate assurance contract is invalid: {exc}"
        )
    method_score, method_missing = method_completeness(cert.get("method_manifest") if isinstance(cert.get("method_manifest"), Mapping) else None)
    if method_score < DEFAULT_THRESHOLDS["major"]["method_completeness"]: reasons.append(f"certificate-level method_manifest incomplete: missing {method_missing}")
    effective_evidence_root = evidence_root_capability
    json_cache: Dict[JsonCacheKey, BoundedJsonResult] = {}
    try:
        try:
            results = [
                evaluate_claim(
                    claim,
                    thresholds,
                    evidence_root=effective_evidence_root,
                    certificate_assurance=certificate_assurance,
                    downstream_policy=selected_downstream_policy,
                    json_cache=json_cache,
                )
                for claim in claims
            ]
        except InvalidInputError as exc:
            return _invalid_certificate_result(
                str(exc),
                {
                    "evidence_root_checked": bool(evidence_root),
                    "strict_evidence": bool(
                        strict_evidence or evidence_root is not None
                    ),
                    "structured_evidence_required": bool(
                        strict_evidence or evidence_root is not None
                    ),
                    "structured_evidence_checked": bool(evidence_root),
                },
            )
    finally:
        if evidence_root_capability is not None:
            evidence_root_capability.close()
    result_by_id = {
        result.claim_id: result
        for result in results
        if result.claim_id != "<missing-id>"
    }
    downstream_reasons, downstream_count = evaluate_downstream_nonclosure(
        cert,
        result_by_id,
        policy=selected_downstream_policy,
    )
    reasons.extend(downstream_reasons)
    if evidence_root is None:
        reasons.append(
            "local evidence was not checked; PASS-TRACKED requires evidence_root"
        )
    fail_count = sum(r.status == "FAIL" for r in results)
    critical_fail = sum(r.status == "FAIL" and r.importance == "critical" for r in results)
    major_fail = sum(r.status == "FAIL" and r.importance == "major" for r in results)
    scope_unknowns = [
        x
        for x in _as_list(cert.get("scope_limitations"))
        if _unknown_item(x)
    ]
    cert_method_unknowns = _collect_method_unknowns(cert)
    claim_residual_risks = [
        risk
        for claim in claims
        for risk in (
            claim.get("residual_risks")
            if type(claim.get("residual_risks")) is list
            else []
        )
        if _unknown_item(risk)
    ]
    if (
        critical_fail
        or major_fail
        or not claims
        or downstream_reasons
        or package_registry_inventory_reasons
    ):
        status = "FAIL"
    elif fail_count or reasons:
        status = "LIMITED"
    elif scope_unknowns or cert_method_unknowns or claim_residual_risks:
        status = "PASS-SCOPED"
    else:
        status = "PASS-TRACKED"
    return {
        "status": status,
        "summary": {
            "claims": len(claims),
            "failed_claims": fail_count,
            "critical_failed": critical_fail,
            "major_failed": major_fail,
            "scope_limitations": len(scope_unknowns),
            "certificate_method_unknowns": len(cert_method_unknowns),
            "claim_residual_risks": len(claim_residual_risks),
            "certificate_method_completeness": round(method_score, 4),
            "evidence_root_checked": bool(evidence_root),
            "strict_evidence": bool(
                strict_evidence or evidence_root is not None
            ),
            "structured_evidence_required": bool(
                strict_evidence or evidence_root is not None
            ),
            "structured_evidence_checked": bool(evidence_root),
            "derived_or_downstream_claims": downstream_count,
            "downstream_nonclosure_violations": len(downstream_reasons),
            "downstream_policy": selected_downstream_policy.name,
            "package_registry_inventory_violations": len(
                package_registry_inventory_reasons
            ),
        },
        "reasons": reasons,
        "claim_results": [{"claim_id": r.claim_id, "importance": r.importance, "status": r.status, "reasons": r.reasons, "evidence_count": r.evidence_count, "structured_evidence_count": r.structured_evidence_count, "unique_evidence_count": r.unique_evidence_count, "unique_structured_evidence_count": r.unique_structured_evidence_count, "unique_artifact_count": r.unique_artifact_count, "false_world_tests": r.false_world_tests, "true_world_tests": r.true_world_tests, "sensitivity_rate": round(r.sensitivity_rate,4), "adherence_rate": round(r.adherence_rate,4), "method_completeness": round(r.method_completeness,4), "test_results": [asdict(t) for t in r.test_results]} for r in results]
    }


def to_markdown(result: Mapping[str, Any], cert_path: Path) -> str:
    lines = ["# Nozickian Gate Result", "", f"Certificate: `{cert_path}`", f"Status: **{result.get('status')}**", "", "## Summary", "", "| Metric | Value |", "|---|---:|"]
    for k,v in (result.get("summary") or {}).items(): lines.append(f"| {k} | {v} |")
    if result.get("reasons"):
        lines += ["", "## Gate notes", ""] + [f"- {r}" for r in result["reasons"]]
    lines += ["", "## Claim results", "", "| Claim | Importance | Status | Sensitivity | Adherence | Method | Evidence | Structured evidence | False tests | True tests | Reasons |", "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---|"]
    for r in result.get("claim_results", []):
        reasons = "; ".join(r.get("reasons") or []) or "—"
        lines.append(f"| {r['claim_id']} | {r['importance']} | {r['status']} | {r['sensitivity_rate']:.2f} | {r['adherence_rate']:.2f} | {r['method_completeness']:.2f} | {r['evidence_count']} | {r.get('structured_evidence_count', 0)} | {r['false_world_tests']} | {r['true_world_tests']} | {reasons} |")
    lines.append("\nThis deterministic result checks declared fields, thresholds, tests, outcomes, field-typed method completeness, versioned method-relative claim contracts, independent reviewer-assigned nearby-world equivalence-class and structural-fingerprint thresholds, local evidence-ref containment, hardlink-aware evidence and artifact identity, case-bound modal release-declaration identity deduplication, proposition-bound downstream passes, structured evidence binding for every cited local ref, exact SHA-256 equality between artifact_path and hash_or_version, and URI-scheme rejection for both evidence refs and artifact_path. It does not independently prove expert-level semantic adequacy of every evidence artifact, method, or nearby-world classification.")
    return "\n".join(lines) + "\n"


def _proc_status_pid(field: str) -> Optional[int]:
    """Return one canonical procfs-visible Pid/PPid field."""
    if field not in {"Pid", "PPid"}:
        raise ValueError("unsupported proc status identity field")
    try:
        with Path("/proc/self/status").open(
            "r", encoding="utf-8", errors="replace"
        ) as stream:
            payload = stream.read(64 * 1024)
    except OSError:
        return None
    matches: List[int] = []
    prefix = f"{field}:"
    for line in payload.splitlines():
        if not line.startswith(prefix):
            continue
        fields = line.split()
        if len(fields) != 2 or not fields[1].isdigit():
            return None
        value = int(fields[1])
        if value <= 0 or str(value) != fields[1]:
            return None
        matches.append(value)
    if len(matches) != 1:
        return None
    return matches[0]


def _open_output_parent(path: Path) -> Tuple[int, str]:
    """Open/create an output parent by dirfd without following symlinks."""
    raw = str(path)
    if (
        not raw
        or any(
            ord(character) < 32
            or ord(character) == 127
            or unicodedata.category(character) == "Cc"
            for character in raw
        )
    ):
        raise ValueError("output path contains a control character")
    if path.name in {"", ".", ".."} or ".." in path.parts:
        raise ValueError("output path is not canonical")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise OSError("platform lacks no-follow directory traversal")
    # The formal runner addresses its already-held output directory as
    # /proc/<direct-parent-pid>/fd/N. Opening that exact kernel capability keeps
    # the target bound to the runner even if this child closes/rebinds its own
    # descriptor N. Self, unrelated-PID, malformed, closed-fd, and nested
    # procfd spellings are rejected rather than traversed.
    parent_parts = path.parent.parts
    procfd_shape = (
        os.name == "posix"
        and len(parent_parts) == 5
        and parent_parts[0:2] == ("/", "proc")
        and parent_parts[3] == "fd"
    )
    if procfd_shape:
        pid_token = parent_parts[2]
        fd_token = parent_parts[4]
        if not (
            pid_token.isascii()
            and pid_token.isdecimal()
            and fd_token.isascii()
            and fd_token.isdecimal()
        ):
            raise ValueError("procfd output capability is not canonical")
        pid_value = int(pid_token)
        fd_value = int(fd_token)
        if (
            pid_value <= 0
            or fd_value <= 0
            or str(pid_value) != pid_token
            or str(fd_value) != fd_token
        ):
            raise ValueError("procfd output capability is not canonical")
        proc_parent_pid = _proc_status_pid("PPid")
        if (
            proc_parent_pid is None
            or pid_token != str(proc_parent_pid)
        ):
            raise ValueError(
                "procfd output capability is not owned by the direct parent"
            )
        descriptor = os.open(
            str(path.parent),
            os.O_RDONLY | directory,
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            os.close(descriptor)
            raise ValueError("parent output capability is not a directory")
        return descriptor, path.name
    if path.is_absolute():
        descriptor = os.open(path.anchor, os.O_RDONLY | directory)
        parts = path.parent.parts[1:]
    else:
        descriptor = os.open(".", os.O_RDONLY | directory)
        parts = path.parent.parts
    try:
        for part in parts:
            if part in {"", "."}:
                continue
            try:
                child = os.open(
                    part,
                    os.O_RDONLY | directory | nofollow,
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                os.mkdir(part, mode=0o700, dir_fd=descriptor)
                child = os.open(
                    part,
                    os.O_RDONLY | directory | nofollow,
                    dir_fd=descriptor,
                )
            os.close(descriptor)
            descriptor = child
        return descriptor, path.name
    except BaseException:
        os.close(descriptor)
        raise


def _canonical_output_path(path: Path) -> Path:
    raw = str(path)
    absolute = Path(os.path.abspath(path))
    if (
        not raw
        or any(
            ord(character) < 32
            or ord(character) == 127
            or unicodedata.category(character) == "Cc"
            for character in raw
        )
        or absolute.name in {"", ".", ".."}
        or ".." in absolute.parts
    ):
        raise ValueError("output path is not canonical")
    return absolute


def _directory_path_matches_fd(path: Path, descriptor: int) -> bool:
    observed: Optional[int] = None
    try:
        parent_parts = path.parts
        procfd_shape = (
            os.name == "posix"
            and len(parent_parts) == 5
            and parent_parts[0:2] == ("/", "proc")
            and parent_parts[3] == "fd"
        )
        if procfd_shape:
            observed, _name = _open_output_parent(
                path / "identity-probe"
            )
        else:
            nofollow = getattr(os, "O_NOFOLLOW", 0)
            directory = getattr(os, "O_DIRECTORY", 0)
            if not nofollow or not directory:
                return False
            flags = os.O_RDONLY | nofollow | directory
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            absolute = Path(os.path.abspath(path))
            observed = os.open(os.path.sep, flags)
            for component in absolute.parts[1:]:
                child = os.open(component, flags, dir_fd=observed)
                os.close(observed)
                observed = child
        expected_metadata = os.fstat(descriptor)
        observed_metadata = os.fstat(observed)
        return (
            expected_metadata.st_dev,
            expected_metadata.st_ino,
        ) == (
            observed_metadata.st_dev,
            observed_metadata.st_ino,
        )
    except (OSError, ValueError):
        return False
    finally:
        if observed is not None:
            os.close(observed)


def _require_new_markdown_target(directory_fd: int, name: str) -> None:
    try:
        os.stat(
            name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    raise ValueError("Markdown output target already exists")


def _acquire_markdown_output_capability(path: Path) -> Tuple[Path, int]:
    absolute = _canonical_output_path(path)
    descriptor, _name = _open_output_parent(absolute)
    try:
        _require_new_markdown_target(descriptor, absolute.name)
        if not _directory_path_matches_fd(absolute.parent, descriptor):
            raise ValueError("Markdown output parent identity is unstable")
        return absolute, descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _atomic_write_new_text(
    path: Path,
    text: str,
    *,
    directory_fd: Optional[int] = None,
) -> None:
    # SECURITY-REVIEW: Traverse the caller-selected report parent by dirfd so
    # no ancestor symlink is followed, then install only to an absent final
    # name. Existing symlinks, special files, regular files, and hardlink
    # sentinels are never opened or overwritten.
    if directory_fd is None:
        absolute, parent_fd = _acquire_markdown_output_capability(path)
    else:
        absolute = _canonical_output_path(path)
        parent_fd = os.dup(directory_fd)
    target_name = absolute.name
    temporary_name = f".{target_name}.{uuid.uuid4().hex}.tmp"
    temporary_created = False
    try:
        _require_new_markdown_target(parent_fd, target_name)
        if not _directory_path_matches_fd(absolute.parent, parent_fd):
            raise ValueError("Markdown output parent changed before write")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        descriptor = os.open(
            temporary_name,
            flags,
            0o600,
            dir_fd=parent_fd,
        )
        temporary_created = True
        try:
            payload = text.encode("utf-8")
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise OSError("short write while creating Markdown report")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _require_new_markdown_target(parent_fd, target_name)
        if not _directory_path_matches_fd(absolute.parent, parent_fd):
            raise ValueError("Markdown output parent changed before install")
        os.link(
            temporary_name,
            target_name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
        os.unlink(temporary_name, dir_fd=parent_fd)
        temporary_created = False
        installed = os.stat(
            target_name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if not stat.S_ISREG(installed.st_mode) or installed.st_nlink != 1:
            raise OSError("installed Markdown report is not a private regular file")
        os.fsync(parent_fd)
        if not _directory_path_matches_fd(absolute.parent, parent_fd):
            raise ValueError("Markdown output parent changed during install")
    finally:
        if temporary_created:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Evaluate a Nozickian truth-tracking certificate JSON")
    ap.add_argument("certificate", type=Path); ap.add_argument("--markdown", type=Path); ap.add_argument("--evidence-root", type=Path); ap.add_argument("--strict-evidence", "--require-structured-evidence", dest="strict_evidence", action="store_true", help="Require structured local evidence binding; --evidence-root is mandatory")
    ap.add_argument(
        "--downstream-policy",
        choices=sorted(DOWNSTREAM_POLICIES),
        default="generic",
    )
    args = ap.parse_args(argv)
    markdown_path: Optional[Path] = None
    markdown_directory_fd: Optional[int] = None
    if args.markdown is not None:
        try:
            markdown_path, markdown_directory_fd = (
                _acquire_markdown_output_capability(args.markdown)
            )
        except (OSError, RuntimeError, ValueError):
            invalid = _invalid_certificate_result(
                "unsafe --markdown output path was rejected"
            )
            print(json.dumps(invalid, indent=2, sort_keys=True))
            return 2
    evidence_root = args.evidence_root
    try:
        result = evaluate_certificate(
            load_json(args.certificate),
            evidence_root=evidence_root,
            strict_evidence=(args.strict_evidence or evidence_root is not None),
            downstream_policy=args.downstream_policy,
        )
    except InvalidInputError as exc:
        result = _invalid_certificate_result(str(exc))
    except Exception:  # pylint: disable=broad-exception-caught
        result = {
            "status": "INTERNAL_ERROR",
            "failure_kind": "internal_error",
            "summary": {},
            "reasons": [
                "unexpected gate implementation failure; internal details omitted"
            ],
            "claim_results": [],
        }
    display_result = normalize_cli_display(result, evidence_root)
    if markdown_path is not None and markdown_directory_fd is not None:
        report = to_markdown(display_result, args.certificate)
        report = normalize_cli_display(report, evidence_root)
        try:
            _atomic_write_new_text(
                markdown_path,
                report,
                directory_fd=markdown_directory_fd,
            )
        except (OSError, ValueError):
            failed_result = dict(display_result)
            failed_result.update({
                "status": "INVALID_INPUT",
                "failure_kind": "invalid_input",
                "reasons": [
                    "held --markdown output path changed or became unsafe"
                ],
            })
            print(json.dumps(failed_result, indent=2, sort_keys=True))
            os.close(markdown_directory_fd)
            return 2
        os.close(markdown_directory_fd)
    print(json.dumps(display_result, indent=2, sort_keys=True))
    return 0 if result["status"] in {"PASS-TRACKED", "PASS-SCOPED"} else 2

if __name__ == "__main__":
    raise SystemExit(main())
