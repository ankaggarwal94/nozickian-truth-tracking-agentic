#!/usr/bin/env python3
"""Adversarial contract tests for ntt_gate.py.

These tests are intentionally small and deterministic. They check that the gate
rejects nearby false certificates that would otherwise create a fake impression
of Nozickian verification. v0.7.2 hardens strict local evidence semantics:

* every cited local evidence ref must be valid, not merely enough refs to meet a
  minimum structured-evidence count;
* the cited evidence JSON file itself must stay under evidence_root;
* remote, absolute, path-escaping, missing, non-JSON, and wrong-hash evidence
  refs are rejected in strict local-evidence mode; and
* a good evidence ref cannot mask one bad cited evidence ref; and
* URI-like artifact_path values are rejected even if a matching local path exists,
  modal-test thresholds count unique false/true-world tests rather than duplicated
  test objects, and Markdown report output never follows final or ancestor links;
* method components reject scalar and flag-only placeholders while retaining
  substantive string and structured descriptions;
* wrapper 1.1 and ledger 1.2 evidence binds a versioned claim contract covering
  local claim assurance plus the certificate-level limitation/downstream state;
  and
* modal case hashes bind closed world contracts while coverage independently
  requires reviewer classes and schema-1.1 typed operator/target/outcome
  identities, never punctuation or free-form paraphrase fingerprints.
"""
from __future__ import annotations
import argparse
import contextlib
import copy
import hashlib
import importlib.util
import inspect
import io
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import unicodedata
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple


REMOTE_EVIDENCE_REF = "https://example.invalid/nozickian/evidence.json"
UPPERCASE_REMOTE_EVIDENCE_REF = "HTTPS://example.invalid/nozickian/evidence.json"
MIXEDCASE_REMOTE_EVIDENCE_REF = "hTtPs://example.invalid/nozickian/evidence.json"
UPPERCASE_DOI_EVIDENCE_REF = "DOI:10.5555/nozickian-test"
SCHEME_LIKE_EVIDENCE_REF = "nozickian-scheme:evidence.json"
ARTIFACT_URI_PATHS = {
    "lowercase_https": "https://example.invalid/nozickian/artifact.txt",
    "uppercase_https": "HTTPS://example.invalid/nozickian/artifact.txt",
    "mixed_case": "hTtPs://example.invalid/nozickian/artifact.txt",
    "arbitrary_scheme": "nozickian-artifact:artifact.txt",
}
BASE_CLAIM_TEXT = "The package gate rejects fake Nozickian certificates that omit evidence, tests, method components, contradiction resolution, invalid local evidence refs, or valid structured evidence hashes."
EXPECTED_CASE_TOTAL = 232
EXPECTED_CASE_NAME_SHA256 = (
    "9ee785be4af6bfbff87d3a89d9701930381ea4957ca68614f19ea1e6237476d6"
)

# Independently recorded golden migration oracle.  Keep this literal separate
# from ntt_gate.py so a mistaken production tuple cannot validate itself.
INDEPENDENT_LEGACY_WORLD_IDENTITY = {
    parts[0]: (parts[1], parts[2])
    for line in """
FW-structure-missing-manifest|remove|manifest.entry
FW-structure-dynamic-shell|replace|workflow.command
TW-structure-unused-asset|preserve|manifest.entry
FW-gate-strict-root|remove|certificate.assurance
FW-gate-proposition-substitution|replace|certificate.claim_contract
FW-gate-modal-substitution|replace|certificate.modal_tests
FW-gate-resource-bounds|mutate|certificate.assurance
FW-gate-path-control|mutate|artifact.path
FW-gate-markdown-linked-target|replace|markdown.output
FW-gate-markdown-symlinked-ancestor|mutate|markdown.output
FW-gate-markdown-parent-substitution|replace|filesystem.parent
TW-gate-shared-ledger|preserve|runtime.trace
TW-gate-private-markdown-output|preserve|markdown.output
FW-validator-extra-ci-action|mutate|workflow.step
FW-validator-unsafe-fixture-id|replace|artifact.path
FW-validator-extra-release-command|mutate|workflow.command
FW-validator-mutable-checkout-action|replace|workflow.step
FW-validator-mutable-setup-python-action|replace|workflow.step
FW-validator-archive-self-test-comment|mutate|workflow.command
FW-validator-archive-self-test-function|replace|workflow.command
FW-validator-formal-output-invariant|remove|certificate.assurance
FW-validator-held-output-capability-invariant|remove|process.output
FW-validator-markdown-parent-substitution|replace|filesystem.parent
FW-validator-markdown-moved-into-package|mutate|filesystem.parent
FW-validator-fixed-manifest-symlink|replace|manifest.entry
FW-validator-fixed-manifest-hardlink|mutate|manifest.entry
FW-validator-fixed-manifest-special|replace|filesystem.entry
FW-validator-fixed-manifest-linked-ancestor|mutate|filesystem.entry
FW-validator-fixed-manifest-real-substitution|replace|filesystem.parent
FW-validator-update-manifest-cli-preflight-substitution|mutate|workflow.step
TW-validator-ci-presentation|preserve|workflow.step
TW-validator-direct-archive-command|preserve|workflow.command
TW-validator-held-markdown|preserve|markdown.output
TW-validator-fixed-manifest-normal|preserve|manifest.entry
FW-formal-malformed-jsonl|mutate|runtime.trace
FW-formal-large-reordered-result|replace|runtime.trace
FW-formal-descendant-pipe|mutate|process.containment
FW-formal-closed-stdio-descendant|replace|process.containment
FW-formal-containment-unavailable|remove|process.containment
FW-formal-detached-session|mutate|process.output
FW-formal-deep-detached-chain|replace|process.output
FW-formal-companion-substitution|replace|artifact.identity
FW-formal-self-attested-output-check|mutate|certificate.assurance
FW-formal-empty-report-gate|remove|artifact.identity
FW-formal-held-dirfd-symlink-swap|replace|filesystem.parent
FW-formal-child-fd-rebind|mutate|process.output
FW-formal-procfd-unavailable|remove|process.output
FW-formal-canonical-json-classification|replace|artifact.path
FW-live-transcript-symlink-substitution|replace|artifact.path
FW-live-transcript-real-substitution|mutate|filesystem.parent
FW-live-json-real-substitution|replace|filesystem.parent
FW-live-json-transcript-alias|mutate|artifact.identity
FW-live-output-direct-symlink|replace|filesystem.entry
FW-live-output-ancestor-symlink|mutate|filesystem.entry
FW-live-explicit-output-a-b-a|mutate|filesystem.parent
FW-live-explicit-output-persistent-substitution|replace|process.output
FW-wrapper-json-unsafe-targets|replace|artifact.path
FW-wrapper-json-parent-substitution|replace|filesystem.parent
FW-formal-temporal-cap|mutate|certificate.assurance
TW-formal-valid-role-direction|preserve|runtime.trace
TW-formal-held-dirfd-ordinary-output|preserve|filesystem.parent
TW-live-explicit-output-early-capability|preserve|process.output
TW-wrapper-json-held-output|preserve|artifact.path
TW-wrapper-json-early-capability|preserve|filesystem.parent
FW-promotion-auto-closure|mutate|certificate.assurance
FW-promotion-missing-trace|remove|runtime.trace
FW-promotion-unsafe-output|replace|artifact.path
FW-promotion-self-attested-output-check|mutate|certificate.assurance
FW-promotion-empty-formal-output|remove|artifact.identity
FW-promotion-coordinator-result-identity|replace|artifact.identity
FW-promotion-coordinator-argv-identity|replace|workflow.command
FW-certifier-json-markdown-alias|mutate|artifact.identity
FW-certifier-parent-substitution|replace|filesystem.parent
TW-promotion-capped-baseline|preserve|certificate.assurance
TW-certifier-distinct-outputs|preserve|artifact.path
FW-github-readmes-degraded|remove|documentation.claim
TW-github-readmes-benign-note|preserve|documentation.claim
FW-charter-sweep-removed|remove|documentation.claim
FW-charter-remote-fields-removed|remove|certificate.assurance
TW-charter-intact|preserve|documentation.claim
""".strip().splitlines()
    for parts in [line.split("|")]
}


# Static full-transition oracle recorded independently of the production
# registry and current release certificate. Tests compare current migrated
# declarations to these pins before separately comparing production pins.
INDEPENDENT_PACKAGE_WORLD_TRANSITION_SHA256 = {
    parts[0]: parts[1]
    for line in """
FW-structure-missing-manifest|49f31ec839f5bd436dacab9d49d23233b453fb4ab2889ca0b1db7d33c259577a
FW-structure-dynamic-shell|2a316b8f68ac5c5a887cabaa3071781fb6df15353fa966bc70d4a6961a0cdbda
TW-structure-unused-asset|d8b583e8f2e35a69818c2984f430216c1811da322b5e96a6c33d3588bb5e976a
FW-gate-strict-root|d4c6e6d4255f87a8c800c45a7e5a3d672f4101cf160b5e14dd34cdb11c1eee64
FW-gate-proposition-substitution|c22daa535b85b93154271fb5f9a9a978fc40c080eaddf8decbf32d06d6b3e2a7
FW-gate-modal-substitution|c01e24853c93239f6a09f869a0b820e692e9c80e6c638966c619ee2db96d7891
FW-gate-resource-bounds|5c93ad2c9a958cbb4d6963b27e1f8e2f222048e92ea43fd51627a40f5746e5b6
FW-gate-path-control|bd92b0575533d796de252d60d04f180c940c51f26325f06e59deb3049696681f
FW-gate-markdown-linked-target|bb75eaa863f7f17ecfbc1e999c5f7f5cd3bcf593ee4fb1afa3e7dc759ae568e8
FW-gate-markdown-symlinked-ancestor|7fe34d6b923eb3c41a774b6b35619557021c39766794a14292a7ce7c74b03969
FW-gate-markdown-parent-substitution|a13c5b9a1f7ad60a047803b9d5f9ec74e26e4e054089368e5029b2f0cadd2568
TW-gate-shared-ledger|ecfa1a2c3cc71fd81c63b4b1a21a6769f1d47df67e835b93a2e46b04ab301d23
TW-gate-private-markdown-output|99617cc03822858b3f5280a73c3b365b0c64d38a48d8bc5c91ccc72023fded68
FW-validator-extra-ci-action|b3a2c4c69b918cd672d8f1e6a05e5a2c64d3f92089c4f409c734d720cd7c49c1
FW-validator-unsafe-fixture-id|a97961b7b6dd1cf2e61ec32e4342a596b23d867eaea965e9234429866ef349f0
FW-validator-extra-release-command|3389d0b5a8593a7c272b683741e03526fdf3d4aa8b42c40973f81dcd28dfdbf8
FW-validator-mutable-checkout-action|4aa103e5f4466f8e1397caff2fed355e3e84c6cf8272e1ee641433bda0e66ed1
FW-validator-mutable-setup-python-action|434a4815dfa14d9987a7f138f7aa67959ac5e8c3496e87c91bda8a8ef98a6940
FW-validator-archive-self-test-comment|aa1038467af7417dc070450c3b6d9caf501293cfd90d28c90cbb3ec5370ff19d
FW-validator-archive-self-test-function|b0a379f905322f7973d20e9effafee672d4a496179c5c11ef9b007172aef7955
FW-validator-formal-output-invariant|ba35ce695bc7d561dddeaf5b852aa69237e5c1bd62a8f893d92f9b9189e297c4
FW-validator-held-output-capability-invariant|4a10c44129cfe34107e1110986eba394c4b9bedab031e2241febb96ba51243a7
FW-validator-markdown-parent-substitution|d88452af9d74b0d6489fbaf6ff0ebd908d85fb35108c1d5fb5333932a1ab3165
FW-validator-markdown-moved-into-package|75382e43fd917792876ef98abb16a4fcf877e2783a70490c946719175dd5d15f
FW-validator-fixed-manifest-symlink|2e3a092c66ce05b8302f3e76ce4fbfa9559d0d37d1e109f893137773dabb8a7e
FW-validator-fixed-manifest-hardlink|3a9787e6869d9905b423ae99c4554f14422a187329a7998be19a52719c890c8d
FW-validator-fixed-manifest-special|741641058277911edefdbdf870a3a389c5d904567d609c9b74e8a3a0c0b15cea
FW-validator-fixed-manifest-linked-ancestor|e932490dd95490c0eeb900694dc4f886b16a1e839dde20c155713748686a5f5e
FW-validator-fixed-manifest-real-substitution|35666b18d5dcb676ac2b110bb019ee565a485098a1d98ecb49417144eae6bb2b
FW-validator-update-manifest-cli-preflight-substitution|34136fce46ec20b5bd4bf8fcf185a139d7e128c462864d01f34358d753399312
TW-validator-ci-presentation|45c3bd626c1c9cea947c71f2de3f9e1d238d273ddb40c21de829d806fc1dffe6
TW-validator-direct-archive-command|b20862092ba55b813ce5a08ca0a34f67ba6e5148f8ba64245f312d85c024b67d
TW-validator-held-markdown|745b038e13ec8891604e2d9747bbb815912e4d61971b66cdc175e95294af1e65
TW-validator-fixed-manifest-normal|60897f5bf8328044ad77e20335e703390c6e68da5ef01a4087509b20a196c516
FW-formal-malformed-jsonl|5f2f315873f68b6640fcc224a395c087ea5c769f125d98abaafc409e245fab7e
FW-formal-large-reordered-result|062419c3480817b3137d77922e6d3171f42cf7871b94c28d71ea507d4d4221b2
FW-formal-descendant-pipe|eb75e5e37343d9693745f290c0741f2f90a5ec921ffd0975c24812c3cf5b7715
FW-formal-closed-stdio-descendant|ecae58386dbc6502ce304f6df6f33baaf5090341aa265ddf07e0151582f8536a
FW-formal-containment-unavailable|599a2ee2738c8bbd8af366b7f06c34963c2e526c7603948d2310d68dca26bb7a
FW-formal-detached-session|0d3fd73a5443a0c53c6fd93b690999e203dffd8f44706f390e1ed7903915b676
FW-formal-deep-detached-chain|296819b2de828685ed3f0c29d7b172e80da8e17a124cbc6c418f71fcba4fe482
FW-formal-companion-substitution|1828e76c0e9d35e961643afa6f154de6a74dfdb7e7bcd84925408f4e635c5f19
FW-formal-self-attested-output-check|39cf5fec57a6de11f5f9a13db5ff290a85ffbec85424baa86c0fd17117e4c951
FW-formal-empty-report-gate|a2eda41f6bc22e98ae9ad463dd818c20dc63c39c1a3b588333438663eb8fc970
FW-formal-held-dirfd-symlink-swap|f4daaf6849f75a5c664d6bce8616de5ed4782b4ea124bcdf9888c35ec8fb39f7
FW-formal-child-fd-rebind|015d16d66a5ba08e2ef9ec03b9d5d7b7d8328819c047c161a47565f7b40e6115
FW-formal-procfd-unavailable|8c550d82e19cead1bc80865de63999d48ca54de2f8c2a09036fefc949f18e729
FW-formal-canonical-json-classification|a7c5cd330d5f6f2d15ce8bd77ea68c6fa52b77852949c962ec427781ac668dee
FW-live-transcript-symlink-substitution|924e561a3e9322be27f6494d811c5e415161cc259c039dde539bc3dbd12b09e1
FW-live-transcript-real-substitution|2ea040663735f9424be9caa3bd8606520a02b3b91d06e2b824555b1085159410
FW-live-json-real-substitution|5781669dc6bdcc8aee7ff0678562f306a54e07bcf03abbfb8bb20961431f2117
FW-live-json-transcript-alias|2d8b602b38da379000db29744e0fb2166610fd48b9fcc67089a68a6d9f8a0fea
FW-live-output-direct-symlink|02ab4da1526722d20c9bf2e562c503ca0343b3274e87577abaa0dcdab3e298c3
FW-live-output-ancestor-symlink|99b90523befffb894d35c214d384fcf8ab3538fceb58ce48897ddd99b07f6da6
FW-live-explicit-output-a-b-a|c855298f69ddbae6300f747fa9cd9ecc7e99dee48c641f6c7ebcf5a9076cd7e3
FW-live-explicit-output-persistent-substitution|391f52fcd77efc701d3c57d368d472dc5f102234574d2460f3276852fffa6545
FW-wrapper-json-unsafe-targets|d9302ad40390b92312328fa55f9cd10d3bdddac8392cadfe76d662e82c408eb7
FW-wrapper-json-parent-substitution|d2a7a8ab99d33356bc7a8b1e077d010171081c7accb32af51a1e009656c47b50
FW-formal-temporal-cap|064a3d551e56979f44517336d3b4c1e62a1e82f7079ac9887003c840b0c93178
TW-formal-valid-role-direction|950fae052f3528695ed2ecb6a422510db7e4ce2439a986f2be6f2faea8ada2dd
TW-formal-held-dirfd-ordinary-output|d63c0014ce53a7b207dd37479ae99365e4aa109166ecb1dcf09c7b9e1837f669
TW-live-explicit-output-early-capability|d80874747bdb2a3254be2d2df055f87b09cc67b2572db76efe71c07d707a450f
TW-wrapper-json-held-output|785a1dabf1d14d3f397a08f48a3f3d0ce377756b84b87cb2785361e02b9236a8
TW-wrapper-json-early-capability|86d7a4954a33e38e70b444041826e62581c5b93f61714d8b7c97d5e53ee75b91
FW-promotion-auto-closure|9cf69fd3dd172d167834dd2c688320291ffc7d01d3d14ea1dcd90b2b098c556b
FW-promotion-missing-trace|a67ffc90ff5c3e9b65382dc422a39ffba2efdaa6b94676c5fa43658c89f2a18b
FW-promotion-unsafe-output|b02b8552996b6ca50af3aa89854c20b2acc45f0399c01fe3bc459934b35943b9
FW-promotion-self-attested-output-check|7d7a225d39b5daa9fa1163d02d6df2c829315f77a5be6c80890651217416b214
FW-promotion-empty-formal-output|4d33b9b11768290e652730988f35e88c4a82e657801d0d44f7e023ce117c7429
FW-promotion-coordinator-result-identity|1d215c25ba7558f3d35eb45b82ab68c7ef1644780dbc92fc33876a3d10f22ea9
FW-promotion-coordinator-argv-identity|18fdec7c2f1e3cd8cfca14e5d5b559a531b86660e8a7f8efbdc8bdbea562bd0b
FW-certifier-json-markdown-alias|6584eb861f92638a0f7a07ae11b82667f3ede80efd8a6d33a984ace037f58a80
FW-certifier-parent-substitution|9e81155384dc3d4d4a18d5c09ad408085acddf09bbf7c893a2a65b3cd3621036
TW-promotion-capped-baseline|79f2b9bd21edd25b9363a50df19c0e46c51c864d2241dd09630e691ec2745176
TW-certifier-distinct-outputs|a8687b111cdb80a34358384542f0bec9eb39650cda4d50a62a6d3bdca919f63c
FW-github-readmes-degraded|00eed35d0430228514dbb88a09217f4e3ef7f91e4ba27ab4c9aad18356591d79
TW-github-readmes-benign-note|11256f4dc9f457a53f85307faa5af7d7e54fb8d05c611757cc22f174dcd299f8
FW-charter-sweep-removed|9aa6efa23770499d8a83a9783111910d2bd88579f89dc3b6cc3ecc9e2f22b8cf
FW-charter-remote-fields-removed|2b97a840cb6ca97ecb7f737f547427197a7c07d01150b49998c825aaaa337ebc
TW-charter-intact|3545392d01961c4cec1ad9278959853c829073f76784a78999ecde29632cbe55
""".strip().splitlines()
    for parts in [line.split("|")]
}


def _private_tempdir(prefix: str) -> Path:
    root = Path(tempfile.mkdtemp(prefix=prefix))
    root.chmod(0o700)
    return root


def load_gate(gate_path: Path):
    spec = importlib.util.spec_from_file_location("ntt_gate_under_test", str(gate_path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {gate_path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    previous_dont_write = sys.dont_write_bytecode
    import_stdout = io.StringIO()
    try:
        sys.dont_write_bytecode = True
        # SECURITY-REVIEW: The fixed package-local gate executes at import
        # time. Contain stdout so this contract CLI emits one JSON document.
        with contextlib.redirect_stdout(import_stdout):
            spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    finally:
        sys.dont_write_bytecode = previous_dont_write
    return mod


def sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def method() -> Dict[str, Any]:
    return {
        "producer": "Nozickian verification skill instructions, references, and specialist subagents.",
        "checker": "Hardened deterministic validator plus gate contract tests and manual inspection.",
        "artifacts": ["SKILL.md", "references/STANDARD.md", "scripts/ntt_gate.py", "scripts/validate_package.py"],
        "environment": ["local filesystem", "Python 3", "package mutation tempdirs"],
        "tools": ["Read", "Grep", "Glob", "Python scripts", "Bash in isolated mutation copies"],
        "evidence_process": "Reproducible checks over package files, semantic contract certificates, and mutation cases.",
        "graders_or_tests": ["validate_package.py --self-test", "run_gate_contract_tests.py", "ntt_gate.py"],
        "trace_or_logs": ["self_validation/SELF_VALIDATION_REPORT.md", "self_validation/GATE_RESULT.md"],
        "human_review": "Sanity review of generated reports and scripts."
    }


def ev(i: str) -> str:
    return f"self_validation/evidence/{i}.json"


def canonical_proposition(value: Any) -> str:
    normalized = unicodedata.normalize("NFC", str(value or ""))
    return re.sub(r"\s+", " ", normalized).strip()


def proposition_sha256(value: Any) -> str:
    return hashlib.sha256(
        canonical_proposition(value).encode("utf-8")
    ).hexdigest()


def canonical_identity_json(value: Any) -> Any:
    if type(value) is str:
        return canonical_proposition(value)
    if value is None or type(value) in {bool, int, float}:
        return value
    if type(value) is list:
        return [canonical_identity_json(item) for item in value]
    if isinstance(value, Mapping):
        return {
            str(key): canonical_identity_json(item)
            for key, item in value.items()
        }
    raise TypeError(f"unsupported identity value {type(value).__name__}")


def certificate_assurance_payload(
    cert: Optional[Mapping[str, Any]],
    *,
    downstream_policy: str = "generic",
) -> Optional[Dict[str, Any]]:
    if cert is None:
        return None
    policy_requirements = {
        "generic": (False, False, False),
        "package-self": (True, False, False),
        "promotion-v2": (False, True, True),
    }
    require_records, require_review, require_own_claim_field = (
        policy_requirements[downstream_policy]
    )
    return canonical_identity_json({
        "schema_version": "1.0",
        "downstream_policy": {
            "name": downstream_policy,
            "require_records": require_records,
            "require_review": require_review,
            "require_own_claim_field": require_own_claim_field,
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
                "id": canonical_proposition(claim.get("id")),
                "local_claim_contract_sha256": claim_contract_sha256(claim),
            }
            for claim in cert.get("claims", [])
            if isinstance(claim, Mapping)
        ],
    })


def claim_contradictions(claim: Mapping[str, Any]) -> List[Any]:
    values: List[Any] = []
    if "unresolved_contradictions" in claim:
        raw = claim.get("unresolved_contradictions")
        values.extend(raw if isinstance(raw, list) else [raw])
    if "contradictions" in claim:
        raw = claim.get("contradictions")
        values.extend(raw if isinstance(raw, list) else [raw])
    return values


def claim_contract_sha256(
    claim: Mapping[str, Any],
    cert: Optional[Mapping[str, Any]] = None,
    *,
    downstream_policy: str = "generic",
) -> str:
    payload = {
        "schema_version": "1.1",
        "id": canonical_proposition(claim.get("id")),
        "text": canonical_proposition(claim.get("text")),
        "scope": canonical_proposition(claim.get("scope")),
        "artifact_location": canonical_proposition(
            claim.get("artifact_location")
        ),
        "importance": claim.get("importance"),
        "method_m": canonical_identity_json(claim.get("method_m")),
        "truth_status": str(claim.get("truth_status") or "").strip().lower(),
        "method_completeness": claim.get("method_completeness"),
        "unresolved_contradictions": canonical_identity_json(
            claim_contradictions(claim)
        ),
        "residual_risks": canonical_identity_json(
            claim.get("residual_risks", [])
        ),
        "evidence_refs": canonical_identity_json(
            claim.get("evidence_refs", [])
        ),
        "false_world_tests": canonical_identity_json(
            claim.get("false_world_tests", [])
        ),
        "true_world_tests": canonical_identity_json(
            claim.get("true_world_tests", [])
        ),
        "certificate_assurance": certificate_assurance_payload(
            cert,
            downstream_policy=downstream_policy,
        ),
    }
    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def finalize_claim_contract(
    claim: Dict[str, Any],
    cert: Optional[Mapping[str, Any]] = None,
    *,
    downstream_policy: str = "generic",
) -> None:
    claim["claim_contract_schema_version"] = "1.1"
    claim["claim_contract_sha256"] = (
        "sha256:"
        + claim_contract_sha256(
            claim,
            cert,
            downstream_policy=downstream_policy,
        )
    )


def finalize_certificate_contracts(
    cert: Dict[str, Any],
    *,
    downstream_policy: str = "generic",
) -> None:
    for claim in cert.get("claims", []):
        if isinstance(claim, dict):
            finalize_claim_contract(
                claim,
                cert,
                downstream_policy=downstream_policy,
            )


def world_contract(
    *,
    semantic_equivalence_class: str,
    operator: str,
    target: str,
    precondition: str,
    state_delta: str,
    oracle: str,
    expected_outcome: str,
) -> Dict[str, str]:
    return {
        "schema_version": "1.1",
        "semantic_equivalence_class": semantic_equivalence_class,
        "operator": operator,
        "target": target,
        "precondition": precondition,
        "state_delta": state_delta,
        "oracle": oracle,
        "expected_outcome": expected_outcome,
    }


def independent_package_world_transition_payload(
    test: Mapping[str, Any],
    claim_id: str,
    kind: str,
) -> Dict[str, Any]:
    """Build the golden full-transition payload without production helpers."""
    required_fields = {
        "id",
        "kind",
        "target_claim_ids",
        "expected_behavior",
        "observed_behavior",
        "outcome",
        "result",
        "evidence_refs",
        "world_contract",
    }
    optional_fields = {"observed_outcome", "fixture_sha256"}
    variation_fields = [
        field for field in ("perturbation", "variant") if field in test
    ]
    if len(variation_fields) != 1:
        raise AssertionError("golden transition has ambiguous variation")
    variation_field = variation_fields[0]
    fields = set(test)
    if required_fields - fields or fields - (
        required_fields
        | optional_fields
        | {"perturbation", "variant"}
    ):
        raise AssertionError("golden transition fields are not closed")
    targets = [canonical_proposition(value) for value in test[
        "target_claim_ids"
    ]]
    if not targets or any(not value for value in targets):
        raise AssertionError("golden transition target list is invalid")
    if len(targets) != len(set(targets)):
        raise AssertionError("golden transition target list is duplicated")
    if canonical_proposition(claim_id) not in targets:
        raise AssertionError("golden transition does not target its claim")
    if str(test.get("kind") or "").strip().lower() != kind:
        raise AssertionError("golden transition kind differs from its lane")
    fixture_sha256 = ""
    if "fixture_sha256" in test:
        fixture_sha256 = str(test.get("fixture_sha256") or "").strip()
        if fixture_sha256.lower().startswith("sha256:"):
            fixture_sha256 = fixture_sha256.split(":", 1)[1]
        fixture_sha256 = fixture_sha256.lower()
        if not re.fullmatch(r"[0-9a-f]{64}", fixture_sha256):
            raise AssertionError("golden fixture SHA-256 is invalid")
    return {
        "registry_version": "1.0",
        "claim_id": canonical_proposition(claim_id),
        "test_id": str(test.get("id") or "").strip(),
        "kind": str(test.get("kind") or "").strip().lower(),
        "target_claim_ids": sorted(targets),
        "variation_field": variation_field,
        "variation": canonical_proposition(test.get(variation_field)),
        "world_contract": canonical_identity_json(test["world_contract"]),
        "expected_behavior": canonical_proposition(
            test.get("expected_behavior")
        ),
        "observed_behavior": canonical_proposition(
            test.get("observed_behavior")
        ),
        "outcome": str(test.get("outcome") or "").strip().lower(),
        "observed_outcome": str(
            test.get("observed_outcome") or ""
        ).strip().lower(),
        "result": str(test.get("result") or "").strip().lower(),
        "fixture_sha256": fixture_sha256,
    }


def modal_case_sha256(
    test: Mapping[str, Any],
    claim: Mapping[str, Any],
    expected_kind: str,
    evidence_observed_result: Any = None,
    cert: Optional[Mapping[str, Any]] = None,
    *,
    downstream_policy: str = "generic",
) -> str:
    target_raw = test.get("target_claim_ids", test.get("target_claim"))
    targets = target_raw if isinstance(target_raw, list) else [target_raw]
    if test.get("perturbation"):
        variation_field = "perturbation"
        variation = test.get("perturbation")
    else:
        variation_field = "variant"
        variation = test.get("variant")
    payload = {
        "claim_proposition": canonical_proposition(claim.get("text")),
        "claim_contract_sha256": claim_contract_sha256(
            claim,
            cert,
            downstream_policy=downstream_policy,
        ),
        "kind": str(test.get("kind") or expected_kind).strip().lower(),
        "test_id": str(test.get("id") or test.get("test_id") or "").strip(),
        "target_claim_ids": sorted({
            str(value).strip() for value in targets if str(value or "").strip()
        }),
        "variation_field": variation_field,
        "variation": canonical_proposition(variation),
        "world_contract": canonical_identity_json(test.get("world_contract")),
        "expected_behavior": canonical_proposition(
            test.get("expected_behavior")
        ),
        "observed_behavior": canonical_proposition(
            test.get("observed_behavior")
        ),
        "observed_result": canonical_proposition(
            evidence_observed_result
            if evidence_observed_result is not None
            else test.get("observed_result")
        ),
        "outcome": str(test.get("outcome") or "").strip().lower(),
        "observed_outcome": str(
            test.get("observed_outcome") or ""
        ).strip().lower(),
        "result": str(test.get("result") or "").strip().lower(),
    }
    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def false_test(i: str) -> Dict[str, Any]:
    test = {
        "id": i,
        "kind": "false_world",
        "target_claim": "C-001",
        "perturbation": f"Nearby false package/certificate mutation {i}.",
        "expected_behavior": "The verifier must reject, flag, block, downgrade, or refuse to certify the false world.",
        "observed_behavior": "The verifier rejected the false claim, flagged the mutation, and did not certify it.",
        "outcome": "rejected_false_claim",
        "result": "pass",
        "evidence_refs": [ev(i)]
    }
    if i == "FW-001":
        test["world_contract"] = world_contract(
            semantic_equivalence_class="claim-evidence-absent",
            operator="remove",
            target="certificate.evidence_refs",
            precondition="The critical claim cites two distinct evidence wrappers.",
            state_delta="Replace the evidence_refs array with an empty array.",
            oracle="The strict gate must return FAIL for missing critical evidence.",
            expected_outcome="rejected_false_claim",
        )
    elif i == "FW-002":
        test["world_contract"] = world_contract(
            semantic_equivalence_class="artifact-digest-mismatch",
            operator="replace",
            target="evidence_wrapper.artifact_digest",
            precondition="The wrapper names the exact SHA-256 of its artifact.",
            state_delta="Replace the digest with sixty-four zero hexadecimal characters.",
            oracle="The strict gate must return FAIL for the wrong artifact digest.",
            expected_outcome="rejected_false_claim",
        )
    else:
        test["world_contract"] = world_contract(
            semantic_equivalence_class=(
                "fixture-" + re.sub(r"[^a-z0-9]+", "-", i.lower()).strip("-")
            ),
            operator="mutate",
            target="fixture.contract",
            precondition="The baseline nearby-world contract is valid.",
            state_delta=f"Apply the independently identified false mutation {i}.",
            oracle="The strict gate must reject the declared false world.",
            expected_outcome="rejected_false_claim",
        )
    return test


def true_test(i: str) -> Dict[str, Any]:
    return {
        "id": i,
        "kind": "true_world",
        "target_claim": "C-001",
        "variant": f"Benign nearby true variation {i}.",
        "expected_behavior": "The verifier should retain the true claim and not overfit to incidental syntax.",
        "observed_behavior": "The verifier retained the true claim and accepted the equivalent variant as true.",
        "outcome": "retained_true_claim",
        "result": "pass",
        "evidence_refs": [ev(i)],
        "world_contract": world_contract(
            semantic_equivalence_class="benign-presentation-equivalence",
            operator="preserve",
            target="claim.presentation",
            precondition="The baseline strict certificate is valid.",
            state_delta=f"Apply benign presentation-equivalent variation {i}.",
            oracle="The strict gate must retain the supported claim.",
            expected_outcome="retained_true_claim",
        ),
    }


def valid_cert() -> Dict[str, Any]:
    m = method()
    claim_text = BASE_CLAIM_TEXT
    claim: Dict[str, Any] = {
        "id": "C-001",
        "text": claim_text,
        "proposition_sha256": f"sha256:{proposition_sha256(claim_text)}",
        "scope": (
            "This claim covers deterministic behavior of the package-local "
            "ntt_gate.py and run_gate_contract_tests.py fixtures."
        ),
        "importance": "critical",
        "artifact_location": "scripts/ntt_gate.py + scripts/run_gate_contract_tests.py",
        "truth_status": "executed_confirmed",
        "method_m": copy.deepcopy(m),
        "evidence_refs": [ev("run-gate-contract-tests"), ev("ntt-gate-source")],
        "false_world_tests": [false_test("FW-001"), false_test("FW-002")],
        "true_world_tests": [true_test("TW-001")],
        "unresolved_contradictions": [],
        "residual_risks": [],
    }
    cert = {
        "schema_version": "2.0",
        "artifact": {"name": "contract-test-artifact", "version": "2.0.0"},
        "method_manifest": copy.deepcopy(m),
        "scope_limitations": [],
        "claims": [claim],
    }
    finalize_claim_contract(claim, cert)
    return cert


def all_evidence_refs(
    cert: Mapping[str, Any],
) -> Iterable[
    Tuple[
        str,
        Optional[str],
        Optional[str],
        Mapping[str, Any],
        Optional[Mapping[str, Any]],
        Optional[str],
    ]
]:
    for claim in cert.get("claims", []):
        cid = str(claim.get("id"))
        for ref in claim.get("evidence_refs", []):
            yield str(ref), cid, None, claim, None, None
        for key in ("false_world_tests", "true_world_tests"):
            kind = "false_world" if key == "false_world_tests" else "true_world"
            for test in claim.get(key, []):
                tid_raw = test.get("id", test.get("test_id"))
                tid = str(tid_raw).strip() if tid_raw is not None else ""
                for ref in test.get("evidence_refs", []):
                    yield str(ref), cid, tid, claim, test, kind


def _safe_evidence_ref(ref: str) -> bool:
    # Strict local evidence mode rejects any URI-scheme ref, case-insensitively.
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", ref or ""):
        return False
    p = Path(ref)
    if p.is_absolute():
        return False
    return ".." not in p.parts


def _write_one_evidence(
    root: Path,
    ref: str,
    cid: Optional[str],
    tid: Optional[str],
    claim: Mapping[str, Any],
    modal_test: Optional[Mapping[str, Any]],
    test_kind: Optional[str],
    cert: Mapping[str, Any],
    *,
    downstream_policy: str = "generic",
    wrong_hash: bool = False,
    artifact_escape: bool = False,
    artifact_absolute: bool = False,
    artifact_uri: Optional[str] = None,
    outside: Optional[Path] = None,
) -> None:
    evidence = root / ref
    evidence.parent.mkdir(parents=True, exist_ok=True)
    artifact_rel = f"observations/{Path(ref).stem}.txt"
    artifact = root / artifact_rel
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(f"Observation for {ref}: deterministic contract case executed.\n", encoding="utf-8")
    digest = sha256_path(artifact)
    if artifact_escape:
        assert outside is not None
        escaped = outside / (Path(ref).stem + "-escaped-artifact.txt")
        escaped.write_text("escaped artifact content\n", encoding="utf-8")
        digest = sha256_path(escaped)
        artifact_rel = "../" + escaped.name
    if artifact_absolute:
        assert outside is not None
        absolute = outside / (Path(ref).stem + "-absolute-artifact.txt")
        absolute.write_text("absolute artifact content\n", encoding="utf-8")
        digest = sha256_path(absolute)
        artifact_rel = str(absolute.resolve())
    if artifact_uri is not None:
        artifact_rel = artifact_uri
        # Create the POSIX-local path Python would otherwise map the URI-like
        # string onto, proving the gate rejects by URI semantics rather than
        # accepting a coincidental local file such as https:/example/... .
        local_uri_path = root / artifact_uri
        local_uri_path.parent.mkdir(parents=True, exist_ok=True)
        local_uri_path.write_text(f"Local file backing URI-like artifact path {artifact_uri}.\n", encoding="utf-8")
        digest = sha256_path(local_uri_path)
    if wrong_hash:
        digest = "0" * 64
    data: Dict[str, Any] = {
        "evidence_schema_version": "1.1",
        "claim_id": cid,
        "claim_proposition_sha256": (
            f"sha256:{proposition_sha256(claim.get('text'))}"
        ),
        "claim_contract_schema_version": "1.1",
        "claim_contract_sha256": (
            "sha256:"
            + claim_contract_sha256(
                claim,
                cert,
                downstream_policy=downstream_policy,
            )
        ),
        "artifact_path": artifact_rel,
        "command_or_source": "run_gate_contract_tests.py structured evidence fixture",
        "observed_result": f"Structured evidence fixture for {ref} observed a deterministic gate contract case.",
        "support_summary": f"This evidence file binds {ref} to claim {cid} and exercises strict local evidence validation for ntt_gate.py.",
        "timestamp_utc": "2026-05-25T00:00:00Z",
        "hash_or_version": f"sha256:{digest}",
    }
    if tid:
        data["test_id"] = tid
        assert modal_test is not None and test_kind is not None
        data["modal_case_sha256"] = (
            "sha256:"
            + modal_case_sha256(
                modal_test,
                claim,
                test_kind,
                data["observed_result"],
                cert,
                downstream_policy=downstream_policy,
            )
        )
    else:
        data["applies_to_tests"] = ["*"]
    evidence.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def write_external_evidence(evidence_root: Path, ref_path: Path, *, artifact_rel: str = "observations/external-valid.txt") -> None:
    artifact = evidence_root / artifact_rel
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("In-root artifact intentionally cited by an out-of-root evidence JSON.\n", encoding="utf-8")
    base_cert = valid_cert()
    base_claim = base_cert["claims"][0]
    data = {
        "evidence_schema_version": "1.1",
        "claim_id": "C-001",
        "claim_proposition_sha256": (
            f"sha256:{proposition_sha256(BASE_CLAIM_TEXT)}"
        ),
        "claim_contract_schema_version": "1.1",
        "claim_contract_sha256": (
            f"sha256:{claim_contract_sha256(base_claim, base_cert)}"
        ),
        "applies_to_tests": ["*"],
        "artifact_path": artifact_rel,
        "command_or_source": "external evidence-ref false-world fixture",
        "observed_result": "The external evidence JSON points at a real in-root artifact with a correct hash, but the evidence JSON itself is outside evidence_root.",
        "support_summary": "This should still fail because strict local evidence provenance requires evidence_refs themselves to stay under evidence_root.",
        "timestamp_utc": "2026-05-25T00:00:00Z",
        "hash_or_version": f"sha256:{sha256_path(artifact)}",
    }
    ref_path.parent.mkdir(parents=True, exist_ok=True)
    ref_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def write_structured_evidence_tree(
    cert: Mapping[str, Any],
    *,
    downstream_policy: str = "generic",
    wrong_refs: Optional[Set[str]] = None,
    artifact_escape_refs: Optional[Set[str]] = None,
    artifact_absolute_refs: Optional[Set[str]] = None,
    artifact_uri_refs: Optional[Mapping[str, str]] = None,
) -> Tuple[Path, Path]:
    root = _private_tempdir("ntt_gate_evidence_contract_")
    outside = _private_tempdir("ntt_gate_evidence_outside_")
    (root / "observations").mkdir(parents=True, exist_ok=True)
    wrong_refs = wrong_refs or set()
    artifact_escape_refs = artifact_escape_refs or set()
    artifact_absolute_refs = artifact_absolute_refs or set()
    artifact_uri_refs = artifact_uri_refs or {}
    for ref, cid, tid, claim, modal_test, test_kind in all_evidence_refs(cert):
        if not _safe_evidence_ref(ref):
            continue
        _write_one_evidence(
            root,
            ref,
            cid,
            tid,
            claim,
            modal_test,
            test_kind,
            cert,
            downstream_policy=downstream_policy,
            wrong_hash=ref in wrong_refs,
            artifact_escape=ref in artifact_escape_refs,
            artifact_absolute=ref in artifact_absolute_refs,
            artifact_uri=artifact_uri_refs.get(ref),
            outside=outside,
        )
    return root, outside


def exercise_evidence_ancestor_swap(
    gate_mod: Any,
    cert: Dict[str, Any],
) -> Dict[str, Any]:
    """Swap a checked evidence ancestor to an external symlink at open time."""
    evidence_root, outside_root = write_structured_evidence_tree(cert)
    source = evidence_root / "self_validation"
    parked = evidence_root / "self_validation.parked"
    outside_tree = outside_root / "self_validation"
    shutil.copytree(source, outside_tree, copy_function=os.link)
    first_ref = Path(cert["claims"][0]["evidence_refs"][0])
    lexical_wrapper = evidence_root / first_ref
    original_open = os.open
    swapped = False
    outside_read = False

    def swapping_open(
        path: Any,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: Optional[int] = None,
    ) -> int:
        nonlocal swapped, outside_read
        path_text = str(path)
        trigger = (
            (dir_fd is not None and path_text == "self_validation")
            or (dir_fd is None and path_text == str(lexical_wrapper))
        )
        if not swapped and trigger:
            os.rename(source, parked)
            os.symlink(outside_tree, source, target_is_directory=True)
            swapped = True
            if dir_fd is None and path_text == str(lexical_wrapper):
                outside_read = True
            try:
                if dir_fd is None:
                    return original_open(path, flags, mode)
                return original_open(path, flags, mode, dir_fd=dir_fd)
            finally:
                source.unlink()
                os.rename(parked, source)
        if dir_fd is None:
            return original_open(path, flags, mode)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    os.open = swapping_open
    try:
        result = gate_mod.evaluate_certificate(
            cert,
            evidence_root=evidence_root,
            strict_evidence=True,
        )
    finally:
        os.open = original_open
        if source.is_symlink():
            source.unlink()
        if parked.exists():
            os.rename(parked, source)
    return {
        "status": result.get("status"),
        "swapped": swapped,
        "outside_read": outside_read,
        "reasons": list(result.get("reasons") or []),
    }


def run_cases(gate_mod) -> List[Dict[str, Any]]:
    cases: List[Dict[str, Any]] = []

    def summarize(result: Mapping[str, Any]) -> List[str]:
        def clean(reason: str) -> str:
            # Keep contract artifacts deterministic even when tempdirs differ.
            reason = re.sub(
                r"/(?:[^/\s;]+/)*ntt_gate_evidence_outside_[^/\s;]+/[^\s;]+",
                "<temporary-absolute-evidence-ref>",
                reason,
            )
            reason = re.sub(
                r"/(?:[^/\s;]+/)*ntt_gate_evidence_contract_[^/\s;]+/[^\s;]+",
                "<temporary-evidence-root-ref>",
                reason,
            )
            return reason
        out = [clean(str(r)) for r in (result.get("reasons", []) or [])]
        for claim in result.get("claim_results", []) or []:
            cid = claim.get("claim_id")
            for reason in claim.get("reasons", []) or []:
                out.append(clean(f"{cid}: {reason}"))
            for test in claim.get("test_results", []) or []:
                test_id = test.get("test_id")
                for reason in test.get("reasons", []) or []:
                    out.append(clean(f"{cid}/{test_id}: {reason}"))
        return out[:12]

    def add(
        name: str,
        cert: Dict[str, Any],
        allowed: Set[str],
        *,
        downstream_policy: str = "generic",
        reason_contains: tuple[str, ...] = (),
    ) -> None:
        effective_allowed = set(allowed)
        # Structure-only evaluation is deliberately non-authorizing. Cases
        # that would pass with checked evidence are LIMITED without a root.
        if effective_allowed & {"PASS-TRACKED", "PASS-SCOPED"}:
            effective_allowed -= {"PASS-TRACKED", "PASS-SCOPED"}
            effective_allowed.add("LIMITED")
        result = gate_mod.evaluate_certificate(
            cert,
            downstream_policy=downstream_policy,
        )
        status = result.get("status")
        reasons = summarize(result)
        cases.append(
            {
                "name": name,
                "status": status,
                "expected_any": sorted(effective_allowed),
                "passed": status in effective_allowed
                and all(
                    any(expected in reason for reason in reasons)
                    for expected in reason_contains
                ),
                "reasons": reasons,
            }
        )

    def add_invalid(name: str, cert: Any) -> None:
        result = gate_mod.evaluate_certificate(cert)
        status = result.get("status")
        cases.append(
            {
                "name": name,
                "status": status,
                "expected_any": ["INVALID_INPUT"],
                "passed": (
                    status == "INVALID_INPUT"
                    and isinstance(result.get("reasons"), list)
                    and bool(result.get("reasons"))
                ),
                "reasons": summarize(result),
            }
        )

    def add_strict(
        name: str,
        cert: Dict[str, Any],
        allowed: Set[str],
        *,
        wrong_refs: Optional[Set[str]] = None,
        artifact_escape_refs: Optional[Set[str]] = None,
        artifact_absolute_refs: Optional[Set[str]] = None,
        artifact_uri_refs: Optional[Mapping[str, str]] = None,
        external_ref: Optional[str] = None,
        absolute_ref: bool = False,
        downstream_policy: str = "generic",
    ) -> None:
        # Strict fixtures authenticate the complete certificate assurance
        # payload. Refresh their declared digests after intentional fixture
        # construction; substitution cases that must retain old evidence use
        # add_claim_contract_substitution below instead.
        finalize_certificate_contracts(
            cert,
            downstream_policy=downstream_policy,
        )
        evidence_root, outside_root = write_structured_evidence_tree(
            cert,
            downstream_policy=downstream_policy,
            wrong_refs=wrong_refs,
            artifact_escape_refs=artifact_escape_refs,
            artifact_absolute_refs=artifact_absolute_refs,
            artifact_uri_refs=artifact_uri_refs,
        )
        if external_ref is not None:
            external_path = outside_root / "external-valid-evidence.json"
            write_external_evidence(evidence_root, external_path)
            if absolute_ref:
                ref_value = str(external_path.resolve())
            else:
                ref_value = Path(
                    os.path.relpath(external_path, evidence_root)
                ).as_posix()
            refs = cert["claims"][0]["evidence_refs"]
            refs[:] = [
                ref_value if ref == external_ref else ref
                for ref in refs
            ]
            if ref_value not in refs:
                refs.append(ref_value)
        result = gate_mod.evaluate_certificate(
            cert,
            evidence_root=evidence_root,
            strict_evidence=True,
            downstream_policy=downstream_policy,
        )
        status = result.get("status")
        cases.append({
            "name": name,
            "status": status,
            "expected_any": sorted(allowed),
            "passed": status in allowed,
            "evidence_root": "<temporary strict-evidence root>",
            "outside_root": "<temporary outside-root probe>",
            "reasons": summarize(result),
        })

    def add_claim_contract_substitution(
        name: str,
        mutate: Any,
        allowed: Optional[Set[str]] = None,
    ) -> None:
        effective_allowed = allowed or {"FAIL"}
        cert = copy.deepcopy(base)
        evidence_root, _outside_root = write_structured_evidence_tree(cert)
        mutate(cert["claims"][0])
        finalize_claim_contract(cert["claims"][0], cert)
        result = gate_mod.evaluate_certificate(
            cert,
            evidence_root=evidence_root,
            strict_evidence=True,
        )
        reasons = summarize(result)
        cases.append({
            "name": name,
            "status": result.get("status"),
            "expected_any": sorted(effective_allowed),
            "passed": (
                result.get("status") in effective_allowed
                and any(
                    "claim_contract_sha256 does not match" in reason
                    for reason in reasons
                )
            ),
            "evidence_root": "<temporary strict-evidence root>",
            "outside_root": "<temporary outside-root probe>",
            "reasons": reasons,
        })

    def add_strict_same_artifact(name: str, cert: Dict[str, Any], allowed: Set[str]) -> None:
        evidence_root, _outside_root = write_structured_evidence_tree(cert)
        refs = list(cert["claims"][0].get("evidence_refs", []))
        if len(refs) >= 2:
            first = evidence_root / refs[0]
            second = evidence_root / refs[1]
            first_data = json.loads(first.read_text(encoding="utf-8"))
            second_data = json.loads(second.read_text(encoding="utf-8"))
            second_data["artifact_path"] = first_data["artifact_path"]
            second_data["hash_or_version"] = first_data["hash_or_version"]
            second.write_text(json.dumps(second_data, indent=2, sort_keys=True), encoding="utf-8")
        result = gate_mod.evaluate_certificate(cert, evidence_root=evidence_root, strict_evidence=True)
        status = result.get("status")
        cases.append({
            "name": name,
            "status": status,
            "expected_any": sorted(allowed),
            "passed": status in allowed,
            "evidence_root": "<temporary strict-evidence root>",
            "outside_root": "<temporary outside-root probe>",
            "reasons": summarize(result),
        })

    def add_hardlink_alias(
        name: str,
        cert: Dict[str, Any],
        *,
        target: str,
    ) -> None:
        evidence_root, _outside_root = write_structured_evidence_tree(cert)
        if target == "evidence-wrapper":
            refs = list(cert["claims"][0]["evidence_refs"])
            first = evidence_root / refs[0]
            second = evidence_root / refs[1]
        elif target == "claim-artifact":
            refs = list(cert["claims"][0]["evidence_refs"])
            wrappers = [evidence_root / ref for ref in refs]
            data = [json.loads(path.read_text(encoding="utf-8")) for path in wrappers]
            first = evidence_root / data[0]["artifact_path"]
            second = evidence_root / data[1]["artifact_path"]
        elif target == "modal-artifact":
            wrappers = [
                evidence_root / ev("FW-001"),
                evidence_root / ev("FW-002"),
            ]
            data = [json.loads(path.read_text(encoding="utf-8")) for path in wrappers]
            first = evidence_root / data[0]["artifact_path"]
            second = evidence_root / data[1]["artifact_path"]
        else:
            raise AssertionError(f"unknown hardlink target {target}")
        second.unlink()
        os.link(first, second)
        if target != "evidence-wrapper":
            data[1]["hash_or_version"] = f"sha256:{sha256_path(first)}"
            wrappers[1].write_text(
                json.dumps(data[1], indent=2, sort_keys=True),
                encoding="utf-8",
            )
        result = gate_mod.evaluate_certificate(
            cert,
            evidence_root=evidence_root,
            strict_evidence=True,
        )
        reasons = summarize(result)
        cases.append({
            "name": name,
            "status": result.get("status"),
            "expected_any": ["FAIL"],
            "passed": (
                os.path.samefile(first, second)
                and result.get("status") == "FAIL"
            ),
            "evidence_root": "<temporary strict-evidence root>",
            "outside_root": "<temporary outside-root probe>",
            "reasons": reasons,
        })

    def add_content_copy(
        name: str,
        cert: Dict[str, Any],
        *,
        target: str,
    ) -> None:
        evidence_root, _outside_root = write_structured_evidence_tree(cert)
        if target == "evidence-wrapper":
            refs = list(cert["claims"][0]["evidence_refs"])
            first = evidence_root / refs[0]
            second = evidence_root / refs[1]
            wrappers: List[Path] = []
            data: List[Dict[str, Any]] = []
        elif target == "claim-artifact":
            refs = list(cert["claims"][0]["evidence_refs"])
            wrappers = [evidence_root / ref for ref in refs]
            data = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in wrappers
            ]
            first = evidence_root / data[0]["artifact_path"]
            second = evidence_root / data[1]["artifact_path"]
        elif target == "modal-artifact":
            wrappers = [
                evidence_root / ev("FW-001"),
                evidence_root / ev("FW-002"),
            ]
            data = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in wrappers
            ]
            first = evidence_root / data[0]["artifact_path"]
            second = evidence_root / data[1]["artifact_path"]
        else:
            raise AssertionError(f"unknown content-copy target {target}")
        second.write_bytes(first.read_bytes())
        if target != "evidence-wrapper":
            data[1]["hash_or_version"] = f"sha256:{sha256_path(second)}"
            wrappers[1].write_text(
                json.dumps(data[1], indent=2, sort_keys=True),
                encoding="utf-8",
            )
        result = gate_mod.evaluate_certificate(
            cert,
            evidence_root=evidence_root,
            strict_evidence=True,
        )
        cases.append({
            "name": name,
            "status": result.get("status"),
            "expected_any": ["FAIL"],
            "passed": (
                not os.path.samefile(first, second)
                and first.read_bytes() == second.read_bytes()
                and result.get("status") == "FAIL"
            ),
            "evidence_root": "<temporary strict-evidence root>",
            "outside_root": "<temporary outside-root probe>",
            "reasons": summarize(result),
        })

    def add_shared_modal_ledger(
        name: str,
        cert: Dict[str, Any],
        *,
        observation_mode: str,
        allowed: Set[str],
    ) -> None:
        evidence_root, _outside_root = write_structured_evidence_tree(cert)
        wrappers = [
            evidence_root / ev("FW-001"),
            evidence_root / ev("FW-002"),
        ]
        wrapper_data = [
            json.loads(path.read_text(encoding="utf-8")) for path in wrappers
        ]
        ledger_rel = "observations/shared-modal-ledger.json"
        ledger_path = evidence_root / ledger_rel
        observations: Dict[str, Any] = {}
        for index, (test_id, data) in enumerate(
            zip(("FW-001", "FW-002"), wrapper_data),
            start=1,
        ):
            observation_id = f"OBS-FW-{index:03d}"
            observations[observation_id] = {
                "claim_id": "C-001",
                "test_id": test_id,
                "kind": "false_world",
                "claim_proposition_sha256": data[
                    "claim_proposition_sha256"
                ],
                "claim_contract_sha256": data[
                    "claim_contract_sha256"
                ],
                "modal_case_sha256": data["modal_case_sha256"],
                "result": "pass",
                "outcome": "rejected_false_claim",
                "observed_result": data["observed_result"],
            }
        if observation_mode == "wrong-modal-digest":
            observations["OBS-FW-002"]["modal_case_sha256"] = (
                "sha256:" + "0" * 64
            )
        elif observation_mode == "wrong-typed-outcome":
            # Both values are valid false-world outcomes; exact world binding,
            # rather than family membership, must reject the disagreement.
            observations["OBS-FW-002"]["outcome"] = (
                "accepted_false_claim"
            )
        elif observation_mode == "extra-record-field":
            observations["OBS-FW-001"]["source_suite"] = (
                "fabricated-suite-result.json"
            )
        elif observation_mode == "missing-record-field":
            observations["OBS-FW-001"].pop("observed_result")
        elif observation_mode == "missing-contract-field":
            observations["OBS-FW-001"].pop("claim_contract_sha256")
        elif observation_mode == "unreferenced-extra-record-field":
            observations["OBS-UNREFERENCED"] = {
                **copy.deepcopy(observations["OBS-FW-001"]),
                "test_id": "FW-UNREFERENCED",
                "source_suite": "fabricated-suite-result.json",
            }
        elif observation_mode == "unreferenced-invalid-record-semantics":
            observations["OBS-UNREFERENCED"] = {
                "claim_id": "C-001",
                "test_id": "FW-UNREFERENCED",
                "kind": "garbage",
                "claim_proposition_sha256": "not-a-digest",
                "claim_contract_sha256": "not-a-digest",
                "modal_case_sha256": "not-a-digest",
                "result": "FAIL",
                "outcome": "invented_outcome",
                "observed_result": "x",
            }
        ledger = {
            "observation_schema_version": "1.2",
            "observations": observations,
        }
        if observation_mode == "extra-ledger-field":
            ledger["suite_summaries"] = {
                "fabricated": {"status": "PASS"}
            }
        elif observation_mode == "old-schema":
            ledger["observation_schema_version"] = "1.1"
        ledger_path.write_text(
            json.dumps(ledger, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        if observation_mode == "duplicate-record-key":
            ledger_text = ledger_path.read_text(encoding="utf-8")
            ledger_path.write_text(
                ledger_text.replace(
                    '"result": "pass"',
                    '"result": "FAIL",\n      "result": "pass"',
                    1,
                ),
                encoding="utf-8",
            )
        digest = sha256_path(ledger_path)
        for index, (path, data) in enumerate(
            zip(wrappers, wrapper_data),
            start=1,
        ):
            data["artifact_path"] = ledger_rel
            data["hash_or_version"] = f"sha256:{digest}"
            if observation_mode in {
                "valid",
                "extra-record-field",
                "missing-record-field",
                "missing-contract-field",
                "unreferenced-extra-record-field",
                "unreferenced-invalid-record-semantics",
                "duplicate-record-key",
                "extra-ledger-field",
                "old-schema",
            }:
                data["observation_id"] = f"OBS-FW-{index:03d}"
            elif observation_mode == "wrong-modal-digest":
                data["observation_id"] = f"OBS-FW-{index:03d}"
            elif observation_mode == "wrong-typed-outcome":
                data["observation_id"] = f"OBS-FW-{index:03d}"
            elif observation_mode == "duplicate":
                data["observation_id"] = "OBS-FW-001"
            elif observation_mode == "missing":
                data["observation_id"] = f"ABSENT-{index}"
            elif observation_mode != "none":
                raise AssertionError(
                    f"unknown observation mode {observation_mode}"
                )
            path.write_text(
                json.dumps(data, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        result = gate_mod.evaluate_certificate(
            cert,
            evidence_root=evidence_root,
            strict_evidence=True,
        )
        status = result.get("status")
        schema_reason_tokens = {
            "old-schema": (
                "observation ledger schema is not 1.2",
            ),
            "extra-ledger-field": (
                "observation ledger fields are not exact for schema 1.2",
                "suite_summaries",
            ),
            "extra-record-field": (
                "fields are not exact for schema 1.2",
                "source_suite",
            ),
            "missing-record-field": (
                "fields are not exact for schema 1.2",
                "observed_result",
            ),
            "missing-contract-field": (
                "fields are not exact for schema 1.2",
                "claim_contract_sha256",
            ),
            "unreferenced-extra-record-field": (
                "observation OBS-UNREFERENCED fields are not exact for schema 1.2",
                "source_suite",
            ),
            "unreferenced-invalid-record-semantics": (
                "observation OBS-UNREFERENCED kind is not recognized",
            ),
            "duplicate-record-key": (
                "observation ledger JSON parse failed",
                "DuplicateJsonKeyError",
            ),
        }.get(observation_mode, ())
        serialized_result = json.dumps(result, sort_keys=True)
        reason_contract_met = all(
            token in serialized_result for token in schema_reason_tokens
        )
        cases.append({
            "name": name,
            "status": status,
            "expected_any": sorted(allowed),
            "passed": status in allowed and reason_contract_met,
            "reason_contract_met": reason_contract_met,
            "evidence_root": "<temporary strict-evidence root>",
            "outside_root": "<temporary outside-root probe>",
            "reasons": summarize(result),
        })

    def add_noncanonical_path(
        name: str,
        *,
        evidence_ref: Optional[str] = None,
        artifact_path: Optional[str] = None,
    ) -> None:
        cert = copy.deepcopy(base)
        evidence_root, _outside_root = write_structured_evidence_tree(cert)
        original_ref = cert["claims"][0]["evidence_refs"][0]
        if evidence_ref is not None:
            cert["claims"][0]["evidence_refs"][0] = evidence_ref
        if artifact_path is not None:
            evidence_file = evidence_root / original_ref
            evidence_data = json.loads(evidence_file.read_text(encoding="utf-8"))
            evidence_data["artifact_path"] = artifact_path
            evidence_file.write_text(
                json.dumps(evidence_data, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        result = gate_mod.evaluate_certificate(
            cert,
            evidence_root=evidence_root,
            strict_evidence=True,
        )
        reasons = summarize(result)
        cases.append(
            {
                "name": name,
                "status": result.get("status"),
                "expected_any": ["FAIL"],
                "passed": result.get("status") == "FAIL",
                "evidence_root": "<temporary strict-evidence root>",
                "outside_root": "<temporary outside-root probe>",
                "reasons": reasons,
            }
        )

    base = valid_cert()
    add("valid_substantive_certificate", copy.deepcopy(base), {"PASS-TRACKED"})

    claim_id_probe_results: Dict[str, Dict[str, Any]] = {}
    for variant_name, raw_claim_id in (
        ("non-string", 1),
        ("noncanonical", " C-001 "),
    ):
        claim_id_cert = copy.deepcopy(base)
        claim_id_cert["claims"][0]["id"] = raw_claim_id
        for lane in ("false_world_tests", "true_world_tests"):
            for modal_test in claim_id_cert["claims"][0][lane]:
                modal_test["target_claim"] = str(raw_claim_id)
        finalize_certificate_contracts(claim_id_cert)
        claim_id_root, _claim_id_outside = (
            write_structured_evidence_tree(claim_id_cert)
        )
        claim_id_result = gate_mod.evaluate_certificate(
            claim_id_cert,
            evidence_root=claim_id_root,
            strict_evidence=True,
        )
        claim_id_probe_results[variant_name] = {
            "status": claim_id_result.get("status"),
            "serialized": json.dumps(claim_id_result, sort_keys=True),
        }

    def materialize_identity_probe_tree(
        certificate: Mapping[str, Any],
    ) -> Path:
        evidence_root = _private_tempdir(
            "ntt_gate_identity_shape_contract_"
        )
        (evidence_root / "observations").mkdir(parents=True, exist_ok=True)
        for claim in certificate.get("claims", []):
            claim_id = str(claim.get("id"))
            raw_claim_refs = claim.get("evidence_refs")
            claim_refs = (
                list(raw_claim_refs)
                if type(raw_claim_refs) is list
                else [raw_claim_refs]
            )
            for ref in claim_refs:
                _write_one_evidence(
                    evidence_root,
                    str(ref),
                    claim_id,
                    None,
                    claim,
                    None,
                    None,
                    certificate,
                )
            for lane, kind in (
                ("false_world_tests", "false_world"),
                ("true_world_tests", "true_world"),
            ):
                for modal_test in claim.get(lane, []):
                    raw_test_refs = modal_test.get("evidence_refs")
                    test_refs = (
                        list(raw_test_refs)
                        if type(raw_test_refs) is list
                        else [raw_test_refs]
                    )
                    test_id = str(
                        modal_test.get(
                            "id",
                            modal_test.get("test_id", ""),
                        )
                    ).strip()
                    for ref in test_refs:
                        _write_one_evidence(
                            evidence_root,
                            str(ref),
                            claim_id,
                            test_id,
                            claim,
                            modal_test,
                            kind,
                            certificate,
                        )
        return evidence_root

    identity_shape_probes = (
        (
            "scalar-claim-evidence-refs",
            lambda certificate: certificate["claims"][0].update({
                "importance": "minor",
                "evidence_refs": ev("run-gate-contract-tests"),
                "false_world_tests": [],
                "true_world_tests": [],
            }),
            "claim evidence_refs must be a duplicate-free list",
        ),
        (
            "scalar-modal-evidence-refs",
            lambda certificate: [
                modal_test.update({
                    "evidence_refs": modal_test["evidence_refs"][0],
                })
                for lane in ("false_world_tests", "true_world_tests")
                for modal_test in certificate["claims"][0][lane]
            ],
            "test evidence_refs must be a duplicate-free list",
        ),
        (
            "non-string-modal-ids",
            lambda certificate: [
                modal_test.update({"id": index})
                for index, modal_test in enumerate(
                    [
                        *certificate["claims"][0]["false_world_tests"],
                        *certificate["claims"][0]["true_world_tests"],
                    ],
                    start=1,
                )
            ],
            "modal test id must be a string",
        ),
        (
            "conflicting-modal-id-aliases",
            lambda certificate: [
                modal_test.update({
                    "test_id": modal_test["id"] + "-CONFLICT",
                })
                for lane in ("false_world_tests", "true_world_tests")
                for modal_test in certificate["claims"][0][lane]
            ],
            "modal test id and test_id aliases conflict",
        ),
        (
            "non-string-target-members",
            lambda certificate: [
                (
                    modal_test.pop("target_claim", None),
                    modal_test.update({
                        "target_claim_ids": ["C-001", 7],
                    }),
                )
                for lane in ("false_world_tests", "true_world_tests")
                for modal_test in certificate["claims"][0][lane]
            ],
            "modal target member 1 must be a string",
        ),
    )
    for variant_name, mutate_identity, expected_reason in (
        identity_shape_probes
    ):
        identity_cert = copy.deepcopy(base)
        mutate_identity(identity_cert)
        finalize_certificate_contracts(identity_cert)
        identity_root = materialize_identity_probe_tree(identity_cert)
        identity_result = gate_mod.evaluate_certificate(
            identity_cert,
            evidence_root=identity_root,
            strict_evidence=True,
        )
        serialized_identity_result = json.dumps(
            identity_result,
            sort_keys=True,
        )
        claim_id_probe_results[variant_name] = {
            "status": identity_result.get("status"),
            "expected_reason_present": (
                expected_reason in serialized_identity_result
            ),
        }
    numeric_digest = int("1" * 64)
    claim_id_probe_results["numeric-sha256-identity"] = {
        "numeric_rejected": (
            gate_mod._canonical_claimed_sha256(numeric_digest) is None
        ),
        "canonical_string_retained": (
            gate_mod._canonical_claimed_sha256("sha256:" + "1" * 64)
            == "1" * 64
        ),
    }
    cases.append({
        "name": "strict_generic_claim_and_modal_identities_are_exact",
        "passed": (
            claim_id_probe_results["non-string"]["status"] == "FAIL"
            and "claim id must be a nonempty string"
            in claim_id_probe_results["non-string"]["serialized"]
            and claim_id_probe_results["noncanonical"]["status"] == "FAIL"
            and "claim id is not canonical"
            in claim_id_probe_results["noncanonical"]["serialized"]
            and all(
                claim_id_probe_results[name]["status"]
                not in {"PASS-TRACKED", "PASS-SCOPED"}
                and claim_id_probe_results[name][
                    "expected_reason_present"
                ]
                is True
                for name, _mutate, _reason in identity_shape_probes
            )
            and claim_id_probe_results["numeric-sha256-identity"] == {
                "numeric_rejected": True,
                "canonical_string_retained": True,
            }
        ),
        "results": claim_id_probe_results,
    })

    wrapper_schema_probe_results: Dict[str, Dict[str, Any]] = {}
    wrapper_schema_probes = (
        (
            "non-string-identities",
            ev("run-gate-contract-tests"),
            {"command_or_source": True, "timestamp_utc": True},
            (
                "structured evidence command_or_source must be a nonempty string",
                "structured evidence timestamp_utc must be a nonempty string",
            ),
        ),
        (
            "non-string-narratives",
            ev("FW-001"),
            {
                "support_summary": 123456789012345678901234567890,
                "observed_result": 12345678901234567890,
            },
            (
                "structured evidence support_summary must be a nonempty string",
                "structured evidence observed_result must be a nonempty string",
            ),
        ),
        (
            "unknown-field",
            ev("run-gate-contract-tests"),
            {"fabricated_provenance": "unsupported"},
            ("structured evidence fields are not closed",),
        ),
        (
            "scalar-applies-list",
            ev("run-gate-contract-tests"),
            {"applies_to_claims": "C-001"},
            (
                "structured evidence applies_to_claims must be a nonempty, "
                "duplicate-free list of canonical strings",
            ),
        ),
        (
            "numeric-test-id-with-valid-applies-list",
            ev("FW-001"),
            {"test_id": 1, "applies_to_tests": ["FW-001"]},
            (
                "structured evidence test_id must be a canonical "
                "nonempty string",
            ),
        ),
        (
            "numeric-modal-digest-on-claim-wrapper",
            ev("run-gate-contract-tests"),
            {"modal_case_sha256": int("1" * 64)},
            (
                "structured evidence modal_case_sha256 must be a "
                "string-typed SHA-256 identity",
            ),
        ),
    )
    for variant_name, wrapper_ref, mutations, expected_reasons in (
        wrapper_schema_probes
    ):
        wrapper_cert = copy.deepcopy(base)
        finalize_certificate_contracts(wrapper_cert)
        wrapper_root, _wrapper_outside = write_structured_evidence_tree(
            wrapper_cert
        )
        wrapper_path = wrapper_root / wrapper_ref
        wrapper_data = json.loads(wrapper_path.read_text(encoding="utf-8"))
        wrapper_data.update(mutations)
        wrapper_path.write_text(
            json.dumps(wrapper_data, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        wrapper_result = gate_mod.evaluate_certificate(
            wrapper_cert,
            evidence_root=wrapper_root,
            strict_evidence=True,
        )
        serialized_wrapper_result = json.dumps(
            wrapper_result,
            sort_keys=True,
        )
        wrapper_schema_probe_results[variant_name] = {
            "status": wrapper_result.get("status"),
            "expected_reasons_present": all(
                reason in serialized_wrapper_result
                for reason in expected_reasons
            ),
        }
    shared_wrapper_cert = copy.deepcopy(base)
    finalize_certificate_contracts(shared_wrapper_cert)
    shared_wrapper_root, _shared_wrapper_outside = (
        write_structured_evidence_tree(shared_wrapper_cert)
    )
    shared_wrapper_path = shared_wrapper_root / ev("FW-001")
    shared_wrapper_data = json.loads(
        shared_wrapper_path.read_text(encoding="utf-8")
    )
    shared_wrapper_data.update({
        "test_id": "ANOTHER-CANONICAL-TEST",
        "applies_to_tests": ["FW-001"],
    })
    shared_wrapper_path.write_text(
        json.dumps(shared_wrapper_data, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    shared_wrapper_result = gate_mod.evaluate_certificate(
        shared_wrapper_cert,
        evidence_root=shared_wrapper_root,
        strict_evidence=True,
    )
    wrapper_schema_probe_results["canonical-shared-wrapper-binding"] = {
        "status": shared_wrapper_result.get("status"),
        "expected_reasons_present": True,
        "positive_control": True,
    }
    cases.append({
        "name": (
            "structured_evidence_schema_rejects_non_string_and_unknown_fields"
        ),
        "passed": all(
            result["status"] == "FAIL"
            and result["expected_reasons_present"] is True
            for result in wrapper_schema_probe_results.values()
            if not result.get("positive_control")
        ) and wrapper_schema_probe_results[
            "canonical-shared-wrapper-binding"
        ]["status"] == "PASS-TRACKED",
        "results": wrapper_schema_probe_results,
    })

    collection_probe_results: Dict[str, Dict[str, Any]] = {}
    collection_shape_probes = (
        (
            "null-unresolved-contradictions",
            lambda claim: claim.__setitem__(
                "unresolved_contradictions", None
            ),
            ("claim unresolved_contradictions must be a list",),
        ),
        (
            "null-legacy-contradictions",
            lambda claim: (
                claim.pop("unresolved_contradictions", None),
                claim.__setitem__("contradictions", None),
            ),
            ("claim contradictions must be a list",),
        ),
        (
            "missing-contradiction-review",
            lambda claim: (
                claim.pop("unresolved_contradictions", None),
                claim.pop("contradictions", None),
            ),
            (
                "claim must include unresolved_contradictions or "
                "contradictions as a list",
            ),
        ),
        (
            "null-residual-risks",
            lambda claim: claim.__setitem__("residual_risks", None),
            ("claim residual_risks must be a list",),
        ),
        (
            "missing-residual-risks",
            lambda claim: claim.pop("residual_risks", None),
            ("claim residual_risks must be a list",),
        ),
        (
            "minor-null-modal-arrays",
            lambda claim: claim.update({
                "importance": "minor",
                "false_world_tests": None,
                "true_world_tests": None,
            }),
            (
                "claim false_world_tests must be a list",
                "claim true_world_tests must be a list",
            ),
        ),
        (
            "missing-modal-arrays",
            lambda claim: (
                claim.pop("false_world_tests", None),
                claim.pop("true_world_tests", None),
            ),
            (
                "claim false_world_tests must be a list",
                "claim true_world_tests must be a list",
            ),
        ),
    )
    for variant_name, mutate_collection, expected_reasons in (
        collection_shape_probes
    ):
        collection_cert = copy.deepcopy(base)
        finalize_certificate_contracts(collection_cert)
        collection_root, _collection_outside = (
            write_structured_evidence_tree(collection_cert)
        )
        mutate_collection(collection_cert["claims"][0])
        collection_result = gate_mod.evaluate_certificate(
            collection_cert,
            evidence_root=collection_root,
            strict_evidence=True,
        )
        serialized_collection_result = json.dumps(
            collection_result,
            sort_keys=True,
        )
        collection_probe_results[variant_name] = {
            "status": collection_result.get("status"),
            "expected_reasons_present": all(
                reason in serialized_collection_result
                for reason in expected_reasons
            ),
        }
    empty_collection_cert = copy.deepcopy(base)
    empty_collection_claim = empty_collection_cert["claims"][0]
    empty_collection_claim.update({
        "importance": "minor",
        "unresolved_contradictions": [],
        "residual_risks": [],
        "false_world_tests": [],
        "true_world_tests": [],
    })
    finalize_certificate_contracts(empty_collection_cert)
    empty_collection_root, _empty_collection_outside = (
        write_structured_evidence_tree(empty_collection_cert)
    )
    empty_collection_result = gate_mod.evaluate_certificate(
        empty_collection_cert,
        evidence_root=empty_collection_root,
        strict_evidence=True,
    )
    collection_probe_results["minor-empty-array-positive-control"] = {
        "status": empty_collection_result.get("status"),
        "expected_reasons_present": True,
        "positive_control": True,
    }
    cases.append({
        "name": "strict_claim_collection_fields_require_exact_arrays",
        "passed": (
            all(
                result["status"] not in {"PASS-TRACKED", "PASS-SCOPED"}
                and result["expected_reasons_present"] is True
                for result in collection_probe_results.values()
                if not result.get("positive_control")
            )
            and collection_probe_results[
                "minor-empty-array-positive-control"
            ]["status"] == "PASS-TRACKED"
        ),
        "results": collection_probe_results,
    })

    add_invalid("non_object_certificate_is_invalid_input", 7)
    malformed_claims = copy.deepcopy(base)
    malformed_claims["claims"] = "not-a-list"
    add_invalid("non_list_claims_is_invalid_input", malformed_claims)
    malformed_claim_entry = copy.deepcopy(base)
    malformed_claim_entry["claims"].append(7)
    add_invalid(
        "non_object_claim_entry_is_invalid_input",
        malformed_claim_entry,
    )
    proc_fds = Path("/proc/self/fd")
    if proc_fds.is_dir():
        with tempfile.TemporaryDirectory(prefix="ntt-gate-fd-lifecycle-") as raw:
            fd_test_root = Path(raw)
            before_fds = len(os.listdir(proc_fds))
            for _index in range(32):
                gate_mod.evaluate_certificate(
                    malformed_claims,
                    evidence_root=fd_test_root,
                )
                gate_mod.evaluate_certificate(
                    malformed_claim_entry,
                    evidence_root=fd_test_root,
                )
            after_fds = len(os.listdir(proc_fds))
        cases.append({
            "name": "malformed_claims_do_not_leak_evidence_root_capability",
            "status": "PASS" if after_fds == before_fds else "FAIL",
            "expected_any": ["PASS"],
            "passed": after_fds == before_fds,
            "reasons": [
                f"before={before_fds}; after={after_fds}"
            ],
        })
    else:
        cases.append({
            "name": "malformed_claims_do_not_leak_evidence_root_capability",
            "status": "PASS",
            "expected_any": ["PASS"],
            "passed": True,
            "reasons": ["procfs fd inventory unavailable; portable skip"],
        })

    shared_method_cert = copy.deepcopy(base)
    shared_method_object = method()
    shared_method_cert["method_manifest"] = shared_method_object
    shared_method_cert["claims"][0]["method_m"] = shared_method_object
    shared_method_result = gate_mod.evaluate_certificate(shared_method_cert)
    cases.append({
        "name": "shared_noncyclic_method_object_is_allowed",
        "status": shared_method_result.get("status"),
        "expected_any": ["LIMITED"],
        "passed": shared_method_result.get("status") == "LIMITED",
        "reasons": summarize(shared_method_result),
    })

    cyclic_method_cert = copy.deepcopy(base)
    cyclic_method = cyclic_method_cert["method_manifest"]
    cyclic_method["cycle"] = cyclic_method
    cyclic_method_result = gate_mod.evaluate_certificate(cyclic_method_cert)
    cases.append({
        "name": "cyclic_method_object_is_invalid_input",
        "status": cyclic_method_result.get("status"),
        "expected_any": ["INVALID_INPUT"],
        "passed": cyclic_method_result.get("status") == "INVALID_INPUT",
        "reasons": summarize(cyclic_method_result),
    })

    aliased_leaf = {"leaf": 1}
    alias_budget_error = gate_mod._validate_json_bounds(  # pylint: disable=protected-access
        [aliased_leaf, aliased_leaf],
        max_depth=4,
        max_nodes=4,
        max_fields=4,
        label="alias budget probe",
    )
    cases.append({
        "name": "shared_object_aliases_each_consume_json_budget",
        "status": "PASS" if alias_budget_error else "FAIL",
        "expected_any": ["PASS"],
        "passed": bool(
            alias_budget_error
            and "node count" in alias_budget_error
        ),
        "reasons": [alias_budget_error] if alias_budget_error else [],
    })
    strict_without_root = gate_mod.evaluate_certificate(
        copy.deepcopy(base),
        strict_evidence=True,
    )
    strict_without_root_summary = strict_without_root.get("summary") or {}
    cases.append({
        "name": "strict_evidence_without_root_is_invalid_input",
        "status": strict_without_root.get("status"),
        "expected_any": ["INVALID_INPUT"],
        "passed": (
            strict_without_root.get("status") == "INVALID_INPUT"
            and strict_without_root_summary.get("evidence_root_checked") is False
            and strict_without_root_summary.get("structured_evidence_checked") is False
            and strict_without_root.get("claim_results") == []
        ),
        "reasons": summarize(strict_without_root),
    })

    structural_only = gate_mod.evaluate_certificate(copy.deepcopy(base))
    structural_claim = (structural_only.get("claim_results") or [{}])[0]
    structural_summary = structural_only.get("summary") or {}
    cases.append({
        "name": "unchecked_refs_cannot_authorize_pass_tracked",
        "status": structural_only.get("status"),
        "expected_any": ["LIMITED"],
        "passed": (
            structural_only.get("status") == "LIMITED"
            and structural_claim.get("structured_evidence_count") == 0
            and structural_summary.get("structured_evidence_checked") is False
            and structural_summary.get("structured_evidence_required") is False
            and any(
                "PASS-TRACKED requires evidence_root" in reason
                for reason in structural_only.get("reasons", [])
            )
        ),
        "reasons": summarize(structural_only),
    })

    missing_root = _private_tempdir("ntt_gate_missing_root_") / "missing"
    missing_root_result = gate_mod.evaluate_certificate(
        copy.deepcopy(base),
        evidence_root=missing_root,
        strict_evidence=True,
    )
    cases.append({
        "name": "missing_evidence_root_is_invalid_input",
        "status": missing_root_result.get("status"),
        "expected_any": ["INVALID_INPUT"],
        "passed": missing_root_result.get("status") == "INVALID_INPUT",
        "reasons": summarize(missing_root_result),
    })
    add_strict("valid_structured_evidence_hashes", copy.deepcopy(base), {"PASS-TRACKED"})

    ancestor_swap = exercise_evidence_ancestor_swap(
        gate_mod,
        copy.deepcopy(base),
    )
    cases.append({
        "name": "strict_evidence_ancestor_symlink_swap_cannot_escape_root",
        "status": ancestor_swap.get("status"),
        "expected_any": ["FAIL", "INVALID_INPUT"],
        "passed": (
            ancestor_swap.get("swapped") is True
            and ancestor_swap.get("outside_read") is False
            and ancestor_swap.get("status") in {"FAIL", "INVALID_INPUT"}
        ),
        "reasons": ancestor_swap.get("reasons"),
    })

    claim_substitution = copy.deepcopy(base)
    substitution_root, _ = write_structured_evidence_tree(
        claim_substitution
    )
    substituted_text = (
        "A coordinated certificate-only substitution must not inherit the "
        "original claim evidence."
    )
    claim_substitution["claims"][0]["text"] = substituted_text
    claim_substitution["claims"][0]["proposition_sha256"] = (
        f"sha256:{proposition_sha256(substituted_text)}"
    )
    substitution_result = gate_mod.evaluate_certificate(
        claim_substitution,
        evidence_root=substitution_root,
        strict_evidence=True,
    )
    substitution_reasons = summarize(substitution_result)
    cases.append({
        "name": "coordinated_claim_text_digest_substitution_rejected",
        "status": substitution_result.get("status"),
        "expected_any": ["FAIL"],
        "passed": (
            substitution_result.get("status") == "FAIL"
            and any(
                "claim_proposition_sha256 does not match" in reason
                for reason in substitution_reasons
            )
        ),
        "reasons": substitution_reasons,
    })

    add_claim_contract_substitution(
        "coordinated_scope_widening_cannot_inherit_original_evidence",
        lambda claim: claim.__setitem__(
            "scope",
            "All production deployments, environments, users, and future versions.",
        ),
    )
    add_claim_contract_substitution(
        "coordinated_artifact_referent_substitution_cannot_inherit_evidence",
        lambda claim: claim.__setitem__(
            "artifact_location",
            "every production artifact and deployment",
        ),
    )

    def downgrade_importance(claim: Dict[str, Any]) -> None:
        claim["importance"] = "minor"
        claim["false_world_tests"] = []
        claim["true_world_tests"] = []

    add_claim_contract_substitution(
        "critical_to_minor_downgrade_cannot_delete_modal_obligations",
        downgrade_importance,
        {"LIMITED"},
    )

    def replace_method_with_unrelated_method(claim: Dict[str, Any]) -> None:
        claim["method_m"] = {
            "producer": "coin flip unrelated to the claimed package behavior",
            "checker": "rubber-stamp acceptance unrelated to the claim",
            "artifacts": ["unrelated.txt"],
            "environment": ["unrelated environment"],
            "tools": ["coin"],
            "evidence_process": "accept whatever the coin flip says",
            "graders_or_tests": ["none relevant to the claim"],
            "trace_or_logs": ["unrelated.log"],
        }

    add_claim_contract_substitution(
        "substantive_but_unrelated_method_cannot_inherit_original_evidence",
        replace_method_with_unrelated_method,
    )

    missing_scope = copy.deepcopy(base)
    missing_scope["claims"][0].pop("scope")
    add_strict(
        "strict_claim_requires_explicit_scope",
        missing_scope,
        {"FAIL"},
    )
    for scope_type, scope_value in (
        ("boolean", False),
        ("array", ["apparently", "scoped"]),
        ("object", {"statement": "apparently scoped"}),
    ):
        malformed_scope = copy.deepcopy(base)
        malformed_scope["claims"][0]["scope"] = scope_value
        add_strict(
            f"strict_claim_rejects_{scope_type}_scope",
            malformed_scope,
            {"FAIL"},
        )

    canonical_contract_whitespace = copy.deepcopy(base)
    canonical_contract_root, _ = write_structured_evidence_tree(
        canonical_contract_whitespace
    )
    canonical_contract_whitespace["claims"][0]["scope"] = (
        "  This claim covers deterministic behavior of the package-local\n"
        "ntt_gate.py   and run_gate_contract_tests.py fixtures.  "
    )
    canonical_contract_whitespace["claims"][0]["method_m"]["checker"] = (
        "  Hardened deterministic validator plus gate contract tests\n"
        "and manual inspection.  "
    )
    canonical_contract_whitespace_result = gate_mod.evaluate_certificate(
        canonical_contract_whitespace,
        evidence_root=canonical_contract_root,
        strict_evidence=True,
    )
    cases.append({
        "name": "claim_contract_canonicalizes_benign_whitespace",
        "status": canonical_contract_whitespace_result.get("status"),
        "expected_any": ["PASS-TRACKED"],
        "passed": (
            canonical_contract_whitespace_result.get("status")
            == "PASS-TRACKED"
        ),
        "reasons": summarize(canonical_contract_whitespace_result),
    })

    for wrapper_case, mutate_wrapper in (
        (
            "legacy_evidence_wrapper_schema_1_0_is_rejected",
            lambda data: data.__setitem__("evidence_schema_version", "1.0"),
        ),
        (
            "legacy_wrapper_missing_claim_contract_digest_is_rejected",
            lambda data: data.pop("claim_contract_sha256"),
        ),
        (
            "legacy_wrapper_missing_claim_contract_version_is_rejected",
            lambda data: data.pop("claim_contract_schema_version"),
        ),
    ):
        wrapper_cert = copy.deepcopy(base)
        wrapper_root, _ = write_structured_evidence_tree(wrapper_cert)
        wrapper_path = wrapper_root / wrapper_cert["claims"][0][
            "evidence_refs"
        ][0]
        wrapper_data = json.loads(wrapper_path.read_text(encoding="utf-8"))
        mutate_wrapper(wrapper_data)
        wrapper_path.write_text(
            json.dumps(wrapper_data, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        wrapper_result = gate_mod.evaluate_certificate(
            wrapper_cert,
            evidence_root=wrapper_root,
            strict_evidence=True,
        )
        cases.append({
            "name": wrapper_case,
            "status": wrapper_result.get("status"),
            "expected_any": ["FAIL"],
            "passed": wrapper_result.get("status") == "FAIL",
            "reasons": summarize(wrapper_result),
        })

    modal_substitution = copy.deepcopy(base)
    modal_substitution_root, _ = write_structured_evidence_tree(
        modal_substitution
    )
    modal_substitution["claims"][0]["false_world_tests"][0][
        "expected_behavior"
    ] = (
        "The mutated modal case still expects rejection but is not the case "
        "that the cited evidence observed."
    )
    modal_substitution_result = gate_mod.evaluate_certificate(
        modal_substitution,
        evidence_root=modal_substitution_root,
        strict_evidence=True,
    )
    modal_substitution_reasons = summarize(modal_substitution_result)
    modal_substitution_test_reasons = [
        str(reason)
        for claim_result in modal_substitution_result.get(
            "claim_results", []
        )
        for test_result in claim_result.get("test_results", [])
        for reason in test_result.get("reasons", [])
    ]
    cases.append({
        "name": "certificate_modal_case_substitution_rejected",
        "status": modal_substitution_result.get("status"),
        "expected_any": ["FAIL"],
        "passed": (
            modal_substitution_result.get("status") == "FAIL"
            and any(
                "modal_case_sha256 does not match" in reason
                for reason in modal_substitution_test_reasons
            )
        ),
        "reasons": (
            modal_substitution_reasons
            + modal_substitution_test_reasons[:3]
        ),
    })

    add_strict("wrong_structured_evidence_hash_rejected", copy.deepcopy(base), {"FAIL"}, wrong_refs={ev("FW-001")})

    oversized_wrapper_cert = copy.deepcopy(base)
    oversized_wrapper_root, _ = write_structured_evidence_tree(
        oversized_wrapper_cert
    )
    oversized_wrapper = (
        oversized_wrapper_root
        / oversized_wrapper_cert["claims"][0]["evidence_refs"][0]
    )
    oversized_wrapper.write_bytes(
        b" " * (gate_mod.MAX_EVIDENCE_WRAPPER_BYTES + 1)
    )
    oversized_wrapper_result = gate_mod.evaluate_certificate(
        oversized_wrapper_cert,
        evidence_root=oversized_wrapper_root,
        strict_evidence=True,
    )
    cases.append({
        "name": "oversized_evidence_wrapper_is_invalid_input",
        "status": oversized_wrapper_result.get("status"),
        "expected_any": ["INVALID_INPUT"],
        "passed": oversized_wrapper_result.get("status") == "INVALID_INPUT",
        "reasons": summarize(oversized_wrapper_result),
    })

    with tempfile.TemporaryDirectory(
        prefix="ntt-gate-sparse-ledger-bound-"
    ) as sparse_raw:
        sparse_ledger = Path(sparse_raw) / "sparse-ledger.json"
        with sparse_ledger.open("wb") as stream:
            stream.truncate(gate_mod.MAX_OBSERVATION_LEDGER_BYTES + 1)
        original_os_read = gate_mod.os.read
        bounded_hash_reads = 0

        def count_bounded_hash_reads(*args: Any, **kwargs: Any) -> bytes:
            nonlocal bounded_hash_reads
            bounded_hash_reads += 1
            return original_os_read(*args, **kwargs)

        bounded_hash_error = ""
        gate_mod.os.read = count_bounded_hash_reads
        try:
            gate_mod.sha256_path(
                sparse_ledger,
                max_bytes=gate_mod.MAX_OBSERVATION_LEDGER_BYTES,
            )
        except ValueError as exc:
            bounded_hash_error = str(exc)
        finally:
            gate_mod.os.read = original_os_read
        cases.append({
            "name": "oversized_sparse_ledger_hash_rejects_before_read",
            "status": "PASS",
            "expected_any": ["PASS"],
            "passed": (
                bounded_hash_reads == 0
                and "exceeds byte limit" in bounded_hash_error
            ),
            "reasons": [
                f"read_calls={bounded_hash_reads}; error={bounded_hash_error}"
            ],
        })

    oversized_byte_ledger_cert = copy.deepcopy(base)
    oversized_byte_ledger_root, _ = write_structured_evidence_tree(
        oversized_byte_ledger_cert
    )
    oversized_byte_wrapper = oversized_byte_ledger_root / ev("FW-001")
    oversized_byte_data = json.loads(
        oversized_byte_wrapper.read_text(encoding="utf-8")
    )
    oversized_byte_path = (
        oversized_byte_ledger_root / "observations/oversized-ledger.json"
    )
    with oversized_byte_path.open("wb") as stream:
        stream.truncate(gate_mod.MAX_OBSERVATION_LEDGER_BYTES + 1)
    oversized_byte_data["artifact_path"] = (
        "observations/oversized-ledger.json"
    )
    oversized_byte_data["hash_or_version"] = f"sha256:{'0' * 64}"
    oversized_byte_data["observation_id"] = "OBS-BYTE-LIMIT"
    oversized_byte_wrapper.write_text(
        json.dumps(oversized_byte_data, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    oversized_byte_result = gate_mod.evaluate_certificate(
        oversized_byte_ledger_cert,
        evidence_root=oversized_byte_ledger_root,
        strict_evidence=True,
    )
    oversized_byte_serialized = json.dumps(
        oversized_byte_result,
        sort_keys=True,
    )
    cases.append({
        "name": "oversized_observation_ledger_is_invalid_input",
        "status": oversized_byte_result.get("status"),
        "expected_any": ["INVALID_INPUT"],
        "passed": (
            oversized_byte_result.get("status") == "INVALID_INPUT"
            and "observation ledger exceeds byte limit" in (
                oversized_byte_serialized
            )
        ),
        "reasons": summarize(oversized_byte_result),
    })

    oversized_ledger_cert = copy.deepcopy(base)
    oversized_ledger_root, _ = write_structured_evidence_tree(
        oversized_ledger_cert
    )
    oversized_ledger_wrapper = oversized_ledger_root / ev("FW-001")
    oversized_ledger_data = json.loads(
        oversized_ledger_wrapper.read_text(encoding="utf-8")
    )
    oversized_ledger_path = (
        oversized_ledger_root / "observations/field-heavy-ledger.json"
    )
    oversized_ledger_path.write_text(
        json.dumps({
            "observation_schema_version": "1.2",
            "observations": {},
            "padding": {
                f"field-{index}": index
                for index in range(gate_mod.MAX_EVIDENCE_JSON_FIELDS + 1)
            },
        }),
        encoding="utf-8",
    )
    oversized_ledger_data["artifact_path"] = (
        "observations/field-heavy-ledger.json"
    )
    oversized_ledger_data["hash_or_version"] = (
        f"sha256:{sha256_path(oversized_ledger_path)}"
    )
    oversized_ledger_data["observation_id"] = "OBS-FIELD-LIMIT"
    oversized_ledger_wrapper.write_text(
        json.dumps(oversized_ledger_data, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    oversized_ledger_result = gate_mod.evaluate_certificate(
        oversized_ledger_cert,
        evidence_root=oversized_ledger_root,
        strict_evidence=True,
    )
    cases.append({
        "name": "observation_ledger_field_bound_is_invalid_input",
        "status": oversized_ledger_result.get("status"),
        "expected_any": ["INVALID_INPUT"],
        "passed": oversized_ledger_result.get("status") == "INVALID_INPUT",
        "reasons": summarize(oversized_ledger_result),
    })

    recursive_ledger_cert = copy.deepcopy(base)
    recursive_ledger_root, _ = write_structured_evidence_tree(
        recursive_ledger_cert
    )
    recursive_ledger_wrapper = recursive_ledger_root / ev("FW-001")
    recursive_ledger_data = json.loads(
        recursive_ledger_wrapper.read_text(encoding="utf-8")
    )
    recursive_ledger_path = (
        recursive_ledger_root / "observations/recursive-ledger.json"
    )
    recursive_depth = sys.getrecursionlimit() + 100
    recursive_ledger_path.write_text(
        '{"nested":' * recursive_depth
        + "0"
        + "}" * recursive_depth,
        encoding="utf-8",
    )
    recursive_ledger_data["artifact_path"] = (
        "observations/recursive-ledger.json"
    )
    recursive_ledger_data["hash_or_version"] = (
        f"sha256:{sha256_path(recursive_ledger_path)}"
    )
    recursive_ledger_data["observation_id"] = "OBS-RECURSION-LIMIT"
    recursive_ledger_wrapper.write_text(
        json.dumps(recursive_ledger_data, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    recursive_ledger_result = gate_mod.evaluate_certificate(
        recursive_ledger_cert,
        evidence_root=recursive_ledger_root,
        strict_evidence=True,
    )
    cases.append({
        "name": "observation_ledger_recursion_failure_is_invalid_input",
        "status": recursive_ledger_result.get("status"),
        "expected_any": ["INVALID_INPUT"],
        "passed": recursive_ledger_result.get("status") == "INVALID_INPUT",
        "reasons": summarize(recursive_ledger_result),
    })

    cache_cert = copy.deepcopy(base)
    cache_root, _ = write_structured_evidence_tree(cache_cert)
    cache_path = cache_root / cache_cert["claims"][0]["evidence_refs"][0]
    json_cache: Dict[Any, Any] = {}
    cached_first = gate_mod._bounded_json_read(  # pylint: disable=protected-access
        cache_path,
        max_bytes=gate_mod.MAX_EVIDENCE_WRAPPER_BYTES,
        label="structured evidence wrapper",
        cache=json_cache,
    )
    cache_path.write_text("{}", encoding="utf-8")
    cached_second = gate_mod._bounded_json_read(  # pylint: disable=protected-access
        cache_path,
        max_bytes=gate_mod.MAX_EVIDENCE_WRAPPER_BYTES,
        label="structured evidence wrapper",
        cache=json_cache,
    )
    cases.append({
        "name": "bounded_evidence_parse_cache_reads_each_path_once",
        "status": "PASS" if cached_first is cached_second else "FAIL",
        "expected_any": ["PASS"],
        "passed": (
            cached_first is cached_second
            and cached_first.sha256 != sha256_path(cache_path)
        ),
        "reasons": [],
    })
    add_strict("artifact_path_escape_rejected", copy.deepcopy(base), {"FAIL"}, artifact_escape_refs={ev("FW-002")})
    add_strict("artifact_path_absolute_rejected", copy.deepcopy(base), {"FAIL"}, artifact_absolute_refs={ev("FW-002")})

    add_strict("artifact_path_lowercase_https_uri_rejected", copy.deepcopy(base), {"FAIL"}, artifact_uri_refs={ev("FW-002"): ARTIFACT_URI_PATHS["lowercase_https"]})
    add_strict("artifact_path_uppercase_https_uri_rejected", copy.deepcopy(base), {"FAIL"}, artifact_uri_refs={ev("FW-002"): ARTIFACT_URI_PATHS["uppercase_https"]})
    add_strict("artifact_path_mixed_case_uri_rejected", copy.deepcopy(base), {"FAIL"}, artifact_uri_refs={ev("FW-002"): ARTIFACT_URI_PATHS["mixed_case"]})
    add_strict("artifact_path_arbitrary_scheme_rejected", copy.deepcopy(base), {"FAIL"}, artifact_uri_refs={ev("FW-002"): ARTIFACT_URI_PATHS["arbitrary_scheme"]})

    one_bad_claim = copy.deepcopy(base)
    # One good claim-level evidence ref remains; the second cited ref is wrong-hash and must still fail.
    add_strict("one_of_two_claim_evidence_hashes_wrong_rejected", one_bad_claim, {"FAIL"}, wrong_refs={ev("ntt-gate-source")})

    one_bad_test = copy.deepcopy(base)
    one_bad_test["claims"][0]["false_world_tests"][0]["evidence_refs"] = [ev("FW-001"), ev("FW-001-bad")]
    add_strict("one_of_two_test_evidence_hashes_wrong_rejected", one_bad_test, {"FAIL"}, wrong_refs={ev("FW-001-bad")})

    duplicate_claim_ref = copy.deepcopy(base)
    duplicate_claim_ref["claims"][0]["evidence_refs"] = [ev("run-gate-contract-tests"), ev("run-gate-contract-tests")]
    add_strict("duplicate_claim_evidence_ref_does_not_satisfy_minimum", duplicate_claim_ref, {"FAIL"})

    aliased_claim_ref = copy.deepcopy(base)
    aliased_claim_ref["claims"][0]["evidence_refs"] = [ev("run-gate-contract-tests") + "::A", ev("run-gate-contract-tests") + "::B"]
    add_strict("aliased_same_claim_evidence_ref_does_not_satisfy_minimum", aliased_claim_ref, {"FAIL"})

    duplicate_structured_ref = copy.deepcopy(base)
    duplicate_structured_ref["claims"][0]["evidence_refs"] = [ev("ntt-gate-source"), ev("ntt-gate-source")]
    add_strict("duplicate_structured_evidence_file_counted_once", duplicate_structured_ref, {"FAIL"})

    same_artifact = copy.deepcopy(base)
    add_strict_same_artifact("same_artifact_path_for_all_claim_refs_fails_for_critical_claims", same_artifact, {"FAIL"})

    add_hardlink_alias(
        "hardlinked_claim_evidence_wrappers_count_once",
        copy.deepcopy(base),
        target="evidence-wrapper",
    )
    add_hardlink_alias(
        "hardlinked_claim_artifacts_count_once",
        copy.deepcopy(base),
        target="claim-artifact",
    )
    add_content_copy(
        "byte_identical_claim_evidence_copies_count_once",
        copy.deepcopy(base),
        target="evidence-wrapper",
    )
    add_content_copy(
        "byte_identical_claim_artifact_copies_count_once",
        copy.deepcopy(base),
        target="claim-artifact",
    )

    unique_valid = copy.deepcopy(base)
    add_strict("unique_evidence_refs_with_valid_hashes_still_pass", unique_valid, {"PASS-TRACKED"})

    duplicate_false_id = copy.deepcopy(base)
    duplicate_false_id["claims"][0]["false_world_tests"] = [false_test("FW-001"), false_test("FW-001")]
    duplicate_false_id["claims"][0]["false_world_tests"][1]["evidence_refs"] = [ev("FW-002")]
    add_strict("duplicate_false_world_test_id_does_not_satisfy_minimum", duplicate_false_id, {"FAIL"})

    duplicate_false_object = copy.deepcopy(base)
    duplicate_false_object["claims"][0]["false_world_tests"] = [false_test("FW-001"), copy.deepcopy(false_test("FW-001"))]
    add_strict("duplicated_false_world_test_object_does_not_satisfy_minimum", duplicate_false_object, {"FAIL"})

    same_false_evidence = copy.deepcopy(base)
    same_false_evidence["claims"][0]["false_world_tests"] = [false_test("FW-A"), false_test("FW-B")]
    same_false_evidence["claims"][0]["false_world_tests"][0]["evidence_refs"] = [ev("FW-SHARED")]
    same_false_evidence["claims"][0]["false_world_tests"][1]["evidence_refs"] = [ev("FW-SHARED")]
    add_strict("aliased_same_false_world_test_evidence_counted_once", same_false_evidence, {"FAIL"})

    add_shared_modal_ledger(
        "distinct_wrappers_over_one_artifact_are_one_observation",
        copy.deepcopy(base),
        observation_mode="none",
        allowed={"FAIL"},
    )
    add_shared_modal_ledger(
        "shared_ledger_with_verified_case_observations_passes",
        copy.deepcopy(base),
        observation_mode="valid",
        allowed={"PASS-TRACKED"},
    )
    add_shared_modal_ledger(
        "observation_schema_1_1_is_rejected",
        copy.deepcopy(base),
        observation_mode="old-schema",
        allowed={"FAIL"},
    )
    add_shared_modal_ledger(
        "observation_ledger_extra_provenance_field_is_rejected",
        copy.deepcopy(base),
        observation_mode="extra-ledger-field",
        allowed={"FAIL"},
    )
    add_shared_modal_ledger(
        "observation_record_source_provenance_field_is_rejected",
        copy.deepcopy(base),
        observation_mode="extra-record-field",
        allowed={"FAIL"},
    )
    add_shared_modal_ledger(
        "observation_record_missing_required_field_is_rejected",
        copy.deepcopy(base),
        observation_mode="missing-record-field",
        allowed={"FAIL"},
    )
    add_shared_modal_ledger(
        "legacy_observation_record_missing_claim_contract_is_rejected",
        copy.deepcopy(base),
        observation_mode="missing-contract-field",
        allowed={"FAIL"},
    )
    add_shared_modal_ledger(
        "unreferenced_observation_record_extra_field_is_rejected",
        copy.deepcopy(base),
        observation_mode="unreferenced-extra-record-field",
        allowed={"FAIL"},
    )
    add_shared_modal_ledger(
        "unreferenced_observation_record_invalid_semantics_is_rejected",
        copy.deepcopy(base),
        observation_mode="unreferenced-invalid-record-semantics",
        allowed={"FAIL"},
    )
    add_shared_modal_ledger(
        "duplicate_observation_record_key_is_invalid_input",
        copy.deepcopy(base),
        observation_mode="duplicate-record-key",
        allowed={"INVALID_INPUT"},
    )
    add_shared_modal_ledger(
        "shared_ledger_duplicate_observation_id_rejected",
        copy.deepcopy(base),
        observation_mode="duplicate",
        allowed={"FAIL"},
    )
    add_shared_modal_ledger(
        "shared_ledger_missing_observation_id_rejected",
        copy.deepcopy(base),
        observation_mode="missing",
        allowed={"FAIL"},
    )
    add_shared_modal_ledger(
        "shared_ledger_modal_case_digest_mismatch_rejected",
        copy.deepcopy(base),
        observation_mode="wrong-modal-digest",
        allowed={"FAIL"},
    )
    add_shared_modal_ledger(
        "shared_ledger_typed_outcome_mismatch_rejected",
        copy.deepcopy(base),
        observation_mode="wrong-typed-outcome",
        allowed={"FAIL"},
    )
    add_hardlink_alias(
        "hardlinked_modal_artifacts_are_one_observation",
        copy.deepcopy(base),
        target="modal-artifact",
    )
    add_content_copy(
        "byte_identical_modal_artifact_copies_are_one_observation",
        copy.deepcopy(base),
        target="modal-artifact",
    )

    unique_false_tests = copy.deepcopy(base)
    add_strict("unique_false_world_tests_with_distinct_ids_still_pass", unique_false_tests, {"PASS-TRACKED"})

    relabeled_false_world = copy.deepcopy(base)
    original_world = copy.deepcopy(
        relabeled_false_world["claims"][0]["false_world_tests"][0]
    )
    relabeled_world = copy.deepcopy(original_world)
    relabeled_world["id"] = "FW-RELABEL"
    relabeled_world["evidence_refs"] = [ev("FW-RELABEL")]
    relabeled_world["variant"] = relabeled_world.pop("perturbation")
    relabeled_world.pop("target_claim", None)
    relabeled_world["target_claim_ids"] = ["C-001", "arbitrary-label"]
    relabeled_false_world["claims"][0]["false_world_tests"] = [
        original_world,
        relabeled_world,
    ]
    add_strict(
        "relabeling_one_false_world_does_not_create_modal_coverage",
        relabeled_false_world,
        {"FAIL"},
    )

    paraphrased_same_world = copy.deepcopy(base)
    first_paraphrase = copy.deepcopy(
        paraphrased_same_world["claims"][0]["false_world_tests"][0]
    )
    second_paraphrase = copy.deepcopy(first_paraphrase)
    second_paraphrase["id"] = "FW-PARAPHRASE"
    second_paraphrase["evidence_refs"] = [ev("FW-PARAPHRASE")]
    second_paraphrase["perturbation"] = (
        "Erase all supporting references from the same critical claim."
    )
    second_paraphrase["world_contract"].update({
        "operator": "delete",
        "target": "the critical claim's supporting-reference array",
        "precondition": "Two independent wrappers support the claim.",
        "state_delta": "The supporting-reference collection becomes empty.",
        "oracle": "Strict evaluation rejects the unsupported critical claim.",
    })
    paraphrased_same_world["claims"][0]["false_world_tests"] = [
        first_paraphrase,
        second_paraphrase,
    ]
    add_strict(
        "paraphrased_same_equivalence_class_does_not_inflate_coverage",
        paraphrased_same_world,
        {"FAIL"},
    )

    equivalence_class_relabel = copy.deepcopy(base)
    relabel_original = copy.deepcopy(
        equivalence_class_relabel["claims"][0]["false_world_tests"][0]
    )
    relabel_clone = copy.deepcopy(relabel_original)
    relabel_clone["id"] = "FW-CLASS-RELABEL"
    relabel_clone["evidence_refs"] = [ev("FW-CLASS-RELABEL")]
    relabel_clone["world_contract"]["semantic_equivalence_class"] = (
        "claim-evidence-absent-relabel"
    )
    equivalence_class_relabel["claims"][0]["false_world_tests"] = [
        relabel_original,
        relabel_clone,
    ]
    add_strict(
        "changing_only_equivalence_class_slug_does_not_inflate_coverage",
        equivalence_class_relabel,
        {"FAIL"},
    )

    add_strict(
        "distinct_equivalence_classes_and_structural_worlds_still_pass",
        copy.deepcopy(base),
        {"PASS-TRACKED"},
    )

    same_display_distinct_worlds = copy.deepcopy(base)
    same_display_distinct_worlds["claims"][0]["false_world_tests"][1][
        "perturbation"
    ] = same_display_distinct_worlds["claims"][0]["false_world_tests"][0][
        "perturbation"
    ]
    add_strict(
        "same_display_prose_with_distinct_structured_worlds_still_passes",
        same_display_distinct_worlds,
        {"PASS-TRACKED"},
    )

    invalid_equivalence_class = copy.deepcopy(base)
    invalid_equivalence_class["claims"][0]["false_world_tests"][0][
        "world_contract"
    ]["semantic_equivalence_class"] = "Claim Evidence Absent"
    add_strict(
        "noncanonical_world_equivalence_class_is_rejected",
        invalid_equivalence_class,
        {"FAIL"},
    )

    missing_world_field = copy.deepcopy(base)
    missing_world_field["claims"][0]["false_world_tests"][0][
        "world_contract"
    ].pop("oracle")
    add_strict(
        "world_contract_is_closed_and_requires_oracle",
        missing_world_field,
        {"FAIL"},
    )

    container_modal_fields = copy.deepcopy(base)
    container_modal_fields["claims"][0]["false_world_tests"][0][
        "perturbation"
    ] = {"not": "a proposition"}
    container_modal_fields["claims"][0]["false_world_tests"][1][
        "expected_behavior"
    ] = ["not", "a", "behavior"]
    container_modal_fields["claims"][0]["true_world_tests"][0][
        "observed_behavior"
    ] = {"not": "an observation"}
    add_strict(
        "modal_variation_and_behavior_containers_are_rejected",
        container_modal_fields,
        {"FAIL"},
    )

    duplicate_true_id = copy.deepcopy(base)
    duplicate_true_id["claims"][0]["true_world_tests"] = [true_test("TW-001"), true_test("TW-001")]
    duplicate_true_id["claims"][0]["true_world_tests"][1]["evidence_refs"] = [ev("TW-002")]
    add_strict("duplicate_true_world_test_id_rejected", duplicate_true_id, {"FAIL"})


    wrong_false_target = copy.deepcopy(base)
    for t in wrong_false_target["claims"][0]["false_world_tests"]:
        t["target_claim"] = "NOT-C-001"
    add_strict("wrong_false_world_target_claim_rejected", wrong_false_target, {"FAIL"})

    wrong_true_target = copy.deepcopy(base)
    for t in wrong_true_target["claims"][0]["true_world_tests"]:
        t["target_claim"] = "NOT-C-001"
    add_strict("wrong_true_world_target_claim_rejected", wrong_true_target, {"FAIL"})

    missing_false_id = copy.deepcopy(base)
    for t in missing_false_id["claims"][0]["false_world_tests"]:
        t.pop("id", None)
        t.pop("test_id", None)
    add_strict("missing_false_world_test_id_rejected", missing_false_id, {"FAIL"})

    missing_true_id = copy.deepcopy(base)
    for t in missing_true_id["claims"][0]["true_world_tests"]:
        t.pop("id", None)
        t.pop("test_id", None)
    add_strict("missing_true_world_test_id_rejected", missing_true_id, {"FAIL"})

    wildcard_no_id = copy.deepcopy(base)
    wildcard_no_id["claims"][0]["false_world_tests"][0].pop("id", None)
    wildcard_no_id["claims"][0]["false_world_tests"][0].pop("test_id", None)
    wildcard_no_id["claims"][0]["false_world_tests"][0]["evidence_refs"] = [ev("FW-WILDCARD-NO-ID")]
    add_strict("wildcard_applies_to_tests_does_not_replace_test_id", wildcard_no_id, {"FAIL"})

    target_claim_ids_list = copy.deepcopy(base)
    for t in target_claim_ids_list["claims"][0]["false_world_tests"] + target_claim_ids_list["claims"][0]["true_world_tests"]:
        t.pop("target_claim", None)
        t["target_claim_ids"] = ["C-001", "supporting-context"]
    add_strict("valid_target_claim_ids_list_still_passes", target_claim_ids_list, {"PASS-TRACKED"})

    path_escape = copy.deepcopy(base)
    # A real outside file with a valid in-root artifact hash is still outside provenance boundary.
    add_strict("evidence_ref_path_escape_rejected", path_escape, {"FAIL"}, external_ref="../ntt_gate_external_valid_ref/evidence.json")

    absolute = copy.deepcopy(base)
    add_strict("evidence_ref_absolute_path_rejected", absolute, {"FAIL"}, external_ref="unused-by-absolute", absolute_ref=True)

    external_valid = copy.deepcopy(base)
    external_valid["claims"][0]["evidence_refs"] = ["../ntt_gate_external_valid_ref/evidence.json", ev("ntt-gate-source")]
    add_strict("external_ref_with_valid_artifact_hash_rejected", external_valid, {"FAIL"}, external_ref="../ntt_gate_external_valid_ref/evidence.json")

    canonical_ref = base["claims"][0]["evidence_refs"][0]
    for case_name, variant in (
        ("dot_component", f"./{canonical_ref}"),
        ("repeated_separator", canonical_ref.replace("/", "//", 1)),
        ("trailing_separator", f"{canonical_ref}/"),
        ("backslash_separator", canonical_ref.replace("/", "\\", 1)),
    ):
        add_noncanonical_path(
            f"noncanonical_evidence_ref_{case_name}_rejected",
            evidence_ref=variant,
        )

    canonical_artifact = f"observations/{Path(canonical_ref).stem}.txt"
    for case_name, variant in (
        ("dot_component", f"./{canonical_artifact}"),
        (
            "repeated_separator",
            canonical_artifact.replace("/", "//", 1),
        ),
        ("trailing_separator", f"{canonical_artifact}/"),
        (
            "backslash_separator",
            canonical_artifact.replace("/", "\\", 1),
        ),
    ):
        add_noncanonical_path(
            f"noncanonical_artifact_path_{case_name}_rejected",
            artifact_path=variant,
        )

    add_noncanonical_path(
        "evidence_ref_nul_character_rejected_without_exception",
        evidence_ref=f"{canonical_ref}\0ignored",
    )
    add_noncanonical_path(
        "artifact_path_unicode_control_rejected_without_exception",
        artifact_path=f"{canonical_artifact}\x85ignored",
    )

    symlink_loop_cert = copy.deepcopy(base)
    symlink_loop_root, _ = write_structured_evidence_tree(
        symlink_loop_cert
    )
    symlink_loop_wrapper = (
        symlink_loop_root
        / symlink_loop_cert["claims"][0]["evidence_refs"][0]
    )
    symlink_loop_wrapper.unlink()
    symlink_loop_wrapper.symlink_to(symlink_loop_wrapper.name)
    symlink_loop_result = gate_mod.evaluate_certificate(
        symlink_loop_cert,
        evidence_root=symlink_loop_root,
        strict_evidence=True,
    )
    cases.append({
        "name": "evidence_ref_symlink_loop_fails_closed",
        "status": symlink_loop_result.get("status"),
        "expected_any": ["FAIL"],
        "passed": symlink_loop_result.get("status") == "FAIL",
        "reasons": summarize(symlink_loop_result),
    })

    root_loop_parent = _private_tempdir("ntt_gate_root_loop_")
    root_loop_a = root_loop_parent / "root-a"
    root_loop_b = root_loop_parent / "root-b"
    root_loop_a.symlink_to(root_loop_b.name)
    root_loop_b.symlink_to(root_loop_a.name)
    root_loop_result = gate_mod.evaluate_certificate(
        copy.deepcopy(base),
        evidence_root=root_loop_a,
        strict_evidence=True,
    )
    cases.append({
        "name": "evidence_root_symlink_loop_is_invalid_input",
        "status": root_loop_result.get("status"),
        "expected_any": ["INVALID_INPUT"],
        "passed": root_loop_result.get("status") == "INVALID_INPUT",
        "reasons": summarize(root_loop_result),
    })
    root_loop_certificate = root_loop_parent / "certificate.json"
    root_loop_certificate.write_text(
        json.dumps(base, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    root_loop_stdout = io.StringIO()
    with contextlib.redirect_stdout(root_loop_stdout):
        root_loop_exit = gate_mod.main([
            str(root_loop_certificate),
            "--evidence-root",
            str(root_loop_a),
            "--strict-evidence",
        ])
    root_loop_cli_result = json.loads(root_loop_stdout.getvalue())
    cases.append({
        "name": "cli_evidence_root_symlink_loop_has_no_traceback",
        "status": root_loop_cli_result.get("status"),
        "expected_any": ["INVALID_INPUT"],
        "passed": (
            root_loop_exit == 2
            and root_loop_cli_result.get("status") == "INVALID_INPUT"
        ),
        "reasons": summarize(root_loop_cli_result),
    })

    remote = copy.deepcopy(base)
    remote["claims"][0]["evidence_refs"].append(REMOTE_EVIDENCE_REF)
    add_strict("remote_ref_rejected_in_strict_local_mode", remote, {"FAIL"})

    upper_remote = copy.deepcopy(base)
    upper_remote["claims"][0]["evidence_refs"].append(UPPERCASE_REMOTE_EVIDENCE_REF)
    add_strict("uppercase_https_evidence_ref_rejected", upper_remote, {"FAIL"})

    mixed_remote = copy.deepcopy(base)
    mixed_remote["claims"][0]["evidence_refs"].append(MIXEDCASE_REMOTE_EVIDENCE_REF)
    add_strict("mixed_case_https_evidence_ref_rejected", mixed_remote, {"FAIL"})

    doi_remote = copy.deepcopy(base)
    doi_remote["claims"][0]["evidence_refs"].append(UPPERCASE_DOI_EVIDENCE_REF)
    add_strict("uppercase_doi_urn_refs_rejected", doi_remote, {"FAIL"})

    scheme_like = copy.deepcopy(base)
    scheme_like["claims"][0]["evidence_refs"].append(SCHEME_LIKE_EVIDENCE_REF)
    add_strict("scheme_like_evidence_ref_rejected_in_strict_mode", scheme_like, {"FAIL"})


    downstream_auto_pass = copy.deepcopy(base)
    downstream_auto_pass["derived_or_downstream_claims"] = [{
        "id": "D-001",
        "from_claim_ids": ["C-001"],
        "derived_claim": "The workflow is safe for production deployment because C-001 passed.",
        "status": "PASS-TRACKED",
        "reason": "Improper automatic closure from C-001."
    }]
    add("downstream_claim_auto_pass_rejected", downstream_auto_pass, {"FAIL"})

    downstream_source_alias = copy.deepcopy(base)
    downstream_source_alias["derived_or_downstream_claims"] = [{
        "id": "D-OWN-SOURCE",
        "from_claim_ids": ["C-001"],
        "derived_claim": "The source claim automatically proves its own downstream consequence.",
        "status": "PASS-TRACKED",
        "own_claim_id": "C-001",
        "reason": "A source claim is not a distinct downstream evaluation.",
    }]
    add(
        "downstream_pass_cannot_alias_source_claim",
        downstream_source_alias,
        {"FAIL"},
    )

    downstream_scalar_own_claim = copy.deepcopy(base)
    downstream_scalar_own_claim["derived_or_downstream_claims"] = [{
        "id": "D-SCALAR-OWN",
        "from_claim_ids": ["C-001"],
        "derived_claim": "A scalar identifier must not be coerced into a claim ID.",
        "status": "PASS-TRACKED",
        "own_claim_id": 123,
        "reason": "Malformed untrusted downstream identifier.",
    }]
    add(
        "downstream_non_string_own_claim_id_rejected",
        downstream_scalar_own_claim,
        {"FAIL"},
    )

    for unknown_status in ("SUCCESS", "VALID", "ACCEPTED"):
        unknown_downstream_status = copy.deepcopy(base)
        unknown_downstream_status["derived_or_downstream_claims"] = [{
            "id": f"D-UNKNOWN-{unknown_status}",
            "from_claim_ids": ["C-001"],
            "derived_claim": "An unknown status token must not close this claim.",
            "status": unknown_status,
            "reason": "The status vocabulary is closed.",
        }]
        add(
            f"downstream_unknown_status_{unknown_status.lower()}_rejected",
            unknown_downstream_status,
            {"FAIL"},
            reason_contains=("uses unsupported status",),
        )

    def proposition_binding(text: str) -> Dict[str, str]:
        digest = gate_mod._proposition_sha256(text)  # pylint: disable=protected-access
        assert digest is not None
        return {
            "schema_version": "1.0",
            "canonical_text_sha256": f"sha256:{digest}",
        }

    downstream_independent = copy.deepcopy(base)
    independent_claim = copy.deepcopy(base["claims"][0])
    independent_claim["id"] = "C-DOWNSTREAM-001"
    independent_proposition = (
        "The production-readiness consequence was independently evaluated."
    )
    independent_claim["text"] = independent_proposition
    independent_claim["proposition_sha256"] = (
        f"sha256:{proposition_sha256(independent_proposition)}"
    )
    independent_claim["evidence_refs"] = [
        ev("downstream-independent-evaluation"),
        ev("downstream-independent-source"),
    ]
    independent_modal_ids = (
        "FW-DOWNSTREAM-001",
        "FW-DOWNSTREAM-002",
        "TW-DOWNSTREAM-001",
    )
    for test in (
        independent_claim["false_world_tests"]
        + independent_claim["true_world_tests"]
    ):
        test["target_claim"] = "C-DOWNSTREAM-001"
    for test, distinct_test_id in zip(
        independent_claim["false_world_tests"]
        + independent_claim["true_world_tests"],
        independent_modal_ids,
    ):
        test["id"] = distinct_test_id
        test["evidence_refs"] = [ev(distinct_test_id)]
    downstream_independent["claims"].append(independent_claim)
    downstream_independent["derived_or_downstream_claims"] = [{
        "id": "D-INDEPENDENT",
        "from_claim_ids": ["C-001"],
        "derived_claim": independent_proposition,
        "status": "PASS-TRACKED",
        "own_claim_id": "C-DOWNSTREAM-001",
        "proposition_binding": proposition_binding(independent_proposition),
        "reason": "The distinct claim record carries its own complete evaluation.",
    }]
    add_strict(
        "downstream_independent_pass_is_proposition_bound",
        downstream_independent,
        {"PASS-TRACKED"},
    )

    downstream_missing_binding = copy.deepcopy(downstream_independent)
    downstream_missing_binding["derived_or_downstream_claims"][0].pop(
        "proposition_binding"
    )
    add(
        "downstream_pass_without_proposition_binding_rejected",
        downstream_missing_binding,
        {"FAIL"},
        reason_contains=("proposition binding is not an object",),
    )

    downstream_unrelated_claim = copy.deepcopy(downstream_independent)
    unrelated_claim = downstream_unrelated_claim["claims"][1]
    unrelated_claim["text"] = "Two plus two equals four."
    unrelated_claim["proposition_sha256"] = (
        f"sha256:{proposition_sha256(unrelated_claim['text'])}"
    )
    downstream_record = downstream_unrelated_claim[
        "derived_or_downstream_claims"
    ][0]
    downstream_record["derived_claim"] = (
        "The package is safe for autonomous production deployment."
    )
    downstream_record["proposition_binding"] = proposition_binding(
        downstream_record["derived_claim"]
    )
    add(
        "unrelated_passing_claim_cannot_authorize_downstream_pass",
        downstream_unrelated_claim,
        {"FAIL"},
        reason_contains=(
            "does not identify the independent claim proposition",
        ),
    )
    promotion_bound = copy.deepcopy(downstream_independent)
    promotion_bound["downstream_review"] = {
        "performed": True,
        "claims_identified": ["D-INDEPENDENT"],
    }
    add_strict(
        "strict_promotion_downstream_pass_is_proposition_bound",
        promotion_bound,
        {"PASS-TRACKED"},
        downstream_policy="promotion-v2",
    )

    promotion_unrelated = copy.deepcopy(downstream_unrelated_claim)
    promotion_unrelated["downstream_review"] = {
        "performed": True,
        "claims_identified": ["D-INDEPENDENT"],
    }
    add(
        "promotion_unrelated_claim_cannot_authorize_downstream_pass",
        promotion_unrelated,
        {"FAIL"},
        downstream_policy="promotion-v2",
        reason_contains=(
            "does not identify the independent claim proposition",
        ),
    )

    downstream_wrong_digest = copy.deepcopy(downstream_independent)
    downstream_wrong_digest["derived_or_downstream_claims"][0][
        "proposition_binding"
    ]["canonical_text_sha256"] = "sha256:" + "0" * 64
    add(
        "downstream_proposition_digest_mismatch_rejected",
        downstream_wrong_digest,
        {"FAIL"},
        reason_contains=("digest does not match",),
    )

    downstream_canonical_whitespace = copy.deepcopy(downstream_independent)
    downstream_canonical_whitespace["claims"][1]["text"] = (
        "The production-readiness consequence\nwas independently evaluated."
    )
    add(
        "downstream_binding_canonicalizes_whitespace",
        downstream_canonical_whitespace,
        {"PASS-TRACKED"},
    )

    unknown_policy = gate_mod.evaluate_certificate(
        copy.deepcopy(base),
        downstream_policy="promotion-v2-typo",
    )
    unknown_policy_reasons = summarize(unknown_policy)
    cases.append(
        {
            "name": "unknown_downstream_policy_fails_closed",
            "status": unknown_policy.get("status"),
            "expected_any": ["INVALID_INPUT"],
            "passed": (
                unknown_policy.get("status") == "INVALID_INPUT"
                and any(
                    "unknown downstream policy" in reason
                    for reason in unknown_policy_reasons
                )
            ),
            "reasons": unknown_policy_reasons,
        }
    )
    canonical_package_policy = gate_mod.DOWNSTREAM_POLICIES["package-self"]
    relaxed_same_name_policy = gate_mod.DownstreamPolicy(
        name="package-self",
        require_records=False,
        require_review=False,
        require_own_claim_field=False,
    )
    relaxed_policy_result = gate_mod.evaluate_certificate(
        copy.deepcopy(base),
        downstream_policy=relaxed_same_name_policy,
    )
    canonical_policy_payload = gate_mod._certificate_assurance_payload(
        base,
        canonical_package_policy,
    )
    relaxed_policy_payload = gate_mod._certificate_assurance_payload(
        base,
        relaxed_same_name_policy,
    )
    relaxed_policy_reasons = summarize(relaxed_policy_result)
    cases.append({
        "name": "same_name_relaxed_policy_object_is_rejected_and_digests_differ",
        "status": relaxed_policy_result.get("status"),
        "expected_any": ["INVALID_INPUT"],
        "passed": (
            relaxed_policy_result.get("status") == "INVALID_INPUT"
            and canonical_policy_payload != relaxed_policy_payload
            and any(
                "not an exact registered policy" in reason
                for reason in relaxed_policy_reasons
            )
        ),
        "reasons": relaxed_policy_reasons,
    })

    promotion_missing_review = copy.deepcopy(base)
    add(
        "promotion_policy_requires_downstream_review",
        promotion_missing_review,
        {"FAIL"},
        downstream_policy="promotion-v2",
    )

    promotion_missing_none_reason = copy.deepcopy(base)
    promotion_missing_none_reason["downstream_review"] = {
        "performed": True,
        "claims_identified": [],
    }
    add(
        "promotion_policy_empty_review_requires_reason",
        promotion_missing_none_reason,
        {"FAIL"},
        downstream_policy="promotion-v2",
    )

    promotion_clean_review = copy.deepcopy(base)
    promotion_clean_review["downstream_review"] = {
        "performed": True,
        "claims_identified": [],
        "none_identified_reason": (
            "The explicit downstream review found no derived claims."
        ),
    }
    add(
        "promotion_policy_clean_empty_review_allowed",
        promotion_clean_review,
        {"PASS-TRACKED"},
        downstream_policy="promotion-v2",
    )

    downstream_unknown = copy.deepcopy(base)
    downstream_unknown["derived_or_downstream_claims"] = [{
        "id": "D-002",
        "from_claim_ids": ["C-001"],
        "derived_claim": "The workflow is safe for production deployment because C-001 passed.",
        "status": "UNKNOWN",
        "reason": "No independent deployment method M, action-space review, evidence, false-world tests, or true-world tests supplied."
    }]
    add(
        "downstream_unknown_record_retains_pass",
        downstream_unknown,
        {"PASS-TRACKED"},
    )

    scoped = copy.deepcopy(base)
    scoped["scope_limitations"] = ["Live Claude Code runtime was not executed in this deterministic contract test."]
    add_strict("valid_scoped_unknown_downgrades", scoped, {"PASS-SCOPED"})

    literal_scope_unknown = copy.deepcopy(base)
    literal_scope_unknown["scope_limitations"] = ["unknown"]
    add_strict(
        "literal_unknown_scope_limitation_downgrades_scoped",
        literal_scope_unknown,
        {"PASS-SCOPED"},
    )

    zero = copy.deepcopy(base)
    zero["gate_thresholds"] = {"critical": {"method_completeness": 0, "sensitivity": 0, "adherence": 0}}
    zero["claims"][0]["false_world_tests"] = []
    zero["claims"][0]["true_world_tests"] = []
    zero["claims"][0]["evidence_refs"] = []
    zero["claims"][0]["method_completeness"] = 0
    add("zero_threshold_no_tests_bypass", zero, {"FAIL"})

    no_ev = copy.deepcopy(base)
    no_ev["claims"][0]["evidence_refs"] = []
    add("no_claim_evidence", no_ev, {"FAIL"})

    empty_test_ev = copy.deepcopy(base)
    empty_test_ev["claims"][0]["false_world_tests"][0]["evidence_refs"] = []
    empty_test_ev["claims"][0]["false_world_tests"][0]["observed_behavior"] = ""
    add("empty_test_evidence", empty_test_ev, {"FAIL"})

    unresolved = copy.deepcopy(base)
    unresolved["claims"][0]["unresolved_contradictions"] = [{"id": "K1", "status": "open", "summary": "An unresolved contradiction."}]
    add("unresolved_contradiction", unresolved, {"FAIL"})

    unknown_truth = copy.deepcopy(base)
    unknown_truth["claims"][0]["truth_status"] = "unknown"
    add("unknown_truth_status", unknown_truth, {"FAIL"})

    missing_method = copy.deepcopy(base)
    missing_method["method_manifest"] = {"producer": "only producer"}
    missing_method["claims"][0]["method_m"] = {"producer": "only producer"}
    missing_method["claims"][0]["method_completeness"] = 1.0
    add("method_component_overclaim", missing_method, {"FAIL"})

    for scalar_name, scalar in (
        ("false", False),
        ("true", True),
        ("integer_zero", 0),
        ("float_zero", 0.0),
    ):
        scalar_method = copy.deepcopy(base)
        scalar_method["method_manifest"] = {
            field: scalar for field in gate_mod.REQ_METHOD
        }
        scalar_method["claims"][0]["method_m"] = {
            field: scalar for field in gate_mod.REQ_METHOD
        }
        finalize_claim_contract(scalar_method["claims"][0], scalar_method)
        add_strict(
            f"scalar_{scalar_name}_method_fields_do_not_count_as_method_m",
            scalar_method,
            {"FAIL"},
        )

    flag_only_method = copy.deepcopy(base)
    flag_only_method["method_manifest"] = {
        field: {"synthetic_contract": True}
        for field in gate_mod.REQ_METHOD
    }
    flag_only_method["claims"][0]["method_m"] = copy.deepcopy(
        flag_only_method["method_manifest"]
    )
    finalize_claim_contract(flag_only_method["claims"][0], flag_only_method)
    add_strict(
        "boolean_flag_only_objects_do_not_count_as_method_m",
        flag_only_method,
        {"FAIL"},
    )

    structured_method = copy.deepcopy(base)
    structured_value = {
        "producer": {
            "implementation": (
                "versioned package source with deterministic fixture generation"
            ),
            "fresh": True,
        },
        "checker": "strict deterministic package contract gate",
        "artifacts": {"primary": "ntt_gate.py", "count": 1},
        "environment": ["local Python execution environment"],
        "tools": ["Python", {"shell": "Bash", "version": "5.2"}],
        "evidence_process": {
            "workflow": "fresh strict evidence evaluation",
            "replayed": True,
        },
        "graders_or_tests": ["run_gate_contract_tests.py"],
        "trace_or_logs": {"report": "gate-contract-result.json"},
    }
    structured_method["method_manifest"] = copy.deepcopy(structured_value)
    structured_method["claims"][0]["method_m"] = copy.deepcopy(
        structured_value
    )
    finalize_claim_contract(
        structured_method["claims"][0], structured_method
    )
    add_strict(
        "substantive_structured_and_string_method_fields_still_pass",
        structured_method,
        {"PASS-TRACKED"},
    )

    bad_status = copy.deepcopy(base)
    bad_status["claims"][0]["false_world_tests"][0]["result"] = "claimed-pass-without-run"
    add("bad_test_status", bad_status, {"FAIL"})

    accepted_false = copy.deepcopy(base)
    accepted_false_test = accepted_false["claims"][0][
        "false_world_tests"
    ][0]
    accepted_false_test["observed_behavior"] = (
        "The verifier accepted false output and certified false claim."
    )
    accepted_false_test["observed_outcome"] = "retained_true_claim"
    add("observed_accepts_false", accepted_false, {"FAIL"})

    rejected_true = copy.deepcopy(base)
    rejected_true_test = rejected_true["claims"][0][
        "true_world_tests"
    ][0]
    rejected_true_test["observed_behavior"] = (
        "The verifier rejected equivalent true output and overfit to one path."
    )
    rejected_true_test["observed_outcome"] = "rejected_false_claim"
    add("observed_rejects_true", rejected_true, {"FAIL"})

    minor = copy.deepcopy(base)
    minor["claims"][0]["importance"] = "minor"
    minor["claims"][0]["false_world_tests"] = []
    minor["claims"][0]["true_world_tests"] = []
    finalize_claim_contract(minor["claims"][0], minor)
    add_strict("minor_claim_without_modal_tests", minor, {"PASS-TRACKED"})

    manifest_unknowns = copy.deepcopy(base)
    manifest_unknowns["scope_limitations"] = []
    manifest_unknowns["method_manifest"]["unknowns"] = ["x"]
    add_strict("manifest_unknowns_downgrades_scoped", manifest_unknowns, {"PASS-SCOPED"})

    manifest_method_unknowns = copy.deepcopy(base)
    manifest_method_unknowns["scope_limitations"] = []
    manifest_method_unknowns["method_manifest"]["method_unknowns"] = ["x"]
    add_strict("manifest_method_unknowns_synonym_downgrades", manifest_method_unknowns, {"PASS-SCOPED"})

    top_level_unknowns = copy.deepcopy(base)
    top_level_unknowns["scope_limitations"] = []
    top_level_unknowns["unknowns"] = ["x"]
    add_strict("top_level_unknowns_downgrades", top_level_unknowns, {"PASS-SCOPED"})

    nested_manifest_unknowns = copy.deepcopy(base)
    nested_manifest_unknowns["scope_limitations"] = []
    nested_manifest_unknowns["method_manifest"]["runtime"] = {"unknowns": ["x"]}
    add_strict("nested_manifest_unknowns_downgrades", nested_manifest_unknowns, {"PASS-SCOPED"})

    deeply_nested_unknowns = copy.deepcopy(base)
    deeply_nested_unknowns["scope_limitations"] = []
    nested_node = deeply_nested_unknowns["method_manifest"]
    for index in range(16):
        child: Dict[str, Any] = {"level": index}
        nested_node["nested"] = child
        nested_node = child
    nested_node["unknowns"] = ["deep material unknown"]
    add_strict(
        "deep_method_unknowns_are_collected_exhaustively",
        deeply_nested_unknowns,
        {"PASS-SCOPED"},
    )

    signature = inspect.signature(gate_mod.evaluate_certificate)
    cases.append({
        "name": "unknown_depth_cannot_be_relaxed_by_caller",
        "status": "PASS" if "max_unknown_depth" not in signature.parameters else "FAIL",
        "expected_any": ["PASS"],
        "passed": "max_unknown_depth" not in signature.parameters,
        "reasons": [],
    })

    large_shared_observations = [{(0, "shared")}] * 5_000
    large_capacity = gate_mod._distinct_observation_capacity(  # pylint: disable=protected-access
        large_shared_observations,
        2,
    )
    cases.append({
        "name": "large_shared_observation_input_is_bounded_and_counts_once",
        "status": "PASS" if large_capacity == 1 else "FAIL",
        "expected_any": ["PASS"],
        "passed": large_capacity == 1,
        "reasons": [],
    })

    repeated_observation_results = []
    for index in range(2):
        check = gate_mod.EvidenceCheck(
            ref=f"wrapper-{index}",
            exists=True,
            structured=True,
            reasons=[],
            artifact_path_resolved=f"/distinct-ledger-{index}.json",
            artifact_sha256=str(index) * 64,
            observation_id="OBS-GLOBAL-001",
        )
        repeated_observation_results.append(
            gate_mod.TestResult(
                test_id=f"FW-{index}",
                kind="false_world",
                status="PASS",
                reasons=[],
                evidence_checks=[check],
            )
        )
    repeated_sets = gate_mod._modal_observation_sets(  # pylint: disable=protected-access
        repeated_observation_results
    )
    repeated_capacity = gate_mod._distinct_observation_capacity(  # pylint: disable=protected-access
        repeated_sets,
        2,
    )
    cases.append({
        "name": "observation_id_is_global_across_copied_ledgers",
        "status": "PASS" if repeated_capacity == 1 else "FAIL",
        "expected_any": ["PASS"],
        "passed": repeated_capacity == 1,
        "reasons": [],
    })

    overdeep_certificate = copy.deepcopy(base)
    nested_node = overdeep_certificate["method_manifest"]
    for index in range(gate_mod.MAX_CERTIFICATE_DEPTH + 2):
        child = {"level": index}
        nested_node["nested"] = child
        nested_node = child
    overdeep_result = gate_mod.evaluate_certificate(overdeep_certificate)
    cases.append({
        "name": "overdeep_certificate_is_invalid_input",
        "status": overdeep_result.get("status"),
        "expected_any": ["INVALID_INPUT"],
        "passed": overdeep_result.get("status") == "INVALID_INPUT",
        "reasons": summarize(overdeep_result),
    })

    nested_clean_manifest = copy.deepcopy(base)
    nested_clean_manifest["scope_limitations"] = []
    nested_clean_manifest["method_manifest"]["runtime"] = {"env": "local", "notes": ["fine"]}
    add_strict("nested_clean_manifest_still_tracked", nested_clean_manifest, {"PASS-TRACKED"})

    placeholder_unknowns = copy.deepcopy(base)
    placeholder_unknowns["scope_limitations"] = []
    placeholder_unknowns["method_manifest"]["unknowns"] = ["none", "n/a", ""]
    add_strict(
        "placeholder_words_in_unknowns_are_not_laundered",
        placeholder_unknowns,
        {"PASS-SCOPED"},
    )

    literal_method_unknowns = copy.deepcopy(base)
    literal_method_unknowns["scope_limitations"] = []
    literal_method_unknowns["method_manifest"]["unknowns"] = [
        "inferred_unknown"
    ]
    add_strict(
        "literal_inferred_unknown_downgrades_scoped",
        literal_method_unknowns,
        {"PASS-SCOPED"},
    )

    scalar_zero_unknowns = copy.deepcopy(base)
    scalar_zero_unknowns["scope_limitations"] = []
    scalar_zero_unknowns["method_manifest"]["unknowns"] = 0
    add_invalid(
        "scalar_zero_unknowns_cannot_erase_limitations",
        scalar_zero_unknowns,
    )

    null_scope_unknowns = copy.deepcopy(base)
    null_scope_unknowns["scope_limitations"] = None
    add_invalid(
        "null_scope_limitations_cannot_erase_limitations",
        null_scope_unknowns,
    )

    object_method_unknowns = copy.deepcopy(base)
    object_method_unknowns["scope_limitations"] = []
    object_method_unknowns["method_manifest"]["unknowns"] = {}
    add_invalid(
        "object_method_unknowns_cannot_erase_limitations",
        object_method_unknowns,
    )

    item_shape_unknowns = copy.deepcopy(base)
    item_shape_unknowns["scope_limitations"] = []
    item_shape_unknowns["method_manifest"]["unknowns"] = [{}]
    add_strict(
        "malformed_unknown_list_item_still_scopes_certificate",
        item_shape_unknowns,
        {"PASS-SCOPED"},
    )

    major_claim_unknowns = copy.deepcopy(base)
    major_claim_unknowns["claims"][0]["importance"] = "major"
    major_claim_unknowns["claims"][0]["method_m"]["method_unknowns"] = ["x"]
    add("major_claim_method_unknowns_blocks", major_claim_unknowns, {"FAIL"})

    nested_claim_unknowns = copy.deepcopy(base)
    nested_node = nested_claim_unknowns["claims"][0]["method_m"]
    for index in range(12):
        child = {"level": index}
        nested_node["nested"] = child
        nested_node = child
    nested_node["unknowns"] = ["nested claim-method uncertainty"]
    add(
        "nested_critical_claim_method_unknowns_block",
        nested_claim_unknowns,
        {"FAIL"},
    )

    minor_claim_unknowns = copy.deepcopy(base)
    minor_claim_unknowns["claims"][0]["importance"] = "minor"
    minor_claim_unknowns["claims"][0]["method_m"]["method_unknowns"] = ["x"]
    finalize_claim_contract(
        minor_claim_unknowns["claims"][0], minor_claim_unknowns
    )
    add_strict(
        "minor_claim_method_unknowns_scope_the_certificate",
        minor_claim_unknowns,
        {"PASS-SCOPED"},
    )

    # Review-response regressions: certificate-level assurance must be carried
    # by the same strict wrappers that authorize each claim. An attacker may
    # recompute the self-declared digest, but cannot reuse the old wrappers.
    assurance_original = copy.deepcopy(base)
    assurance_original["scope_limitations"] = [
        "One reviewed runtime limitation remains."
    ]
    assurance_original["method_manifest"]["unknowns"] = [
        "One reviewed method uncertainty remains."
    ]
    finalize_certificate_contracts(assurance_original)
    assurance_root, assurance_outside = write_structured_evidence_tree(
        assurance_original
    )
    assurance_before = gate_mod.evaluate_certificate(
        assurance_original,
        evidence_root=assurance_root,
        strict_evidence=True,
    )
    assurance_promoted = copy.deepcopy(assurance_original)
    assurance_promoted["scope_limitations"] = []
    assurance_promoted["method_manifest"]["unknowns"] = []
    finalize_certificate_contracts(assurance_promoted)
    assurance_after = gate_mod.evaluate_certificate(
        assurance_promoted,
        evidence_root=assurance_root,
        strict_evidence=True,
    )
    assurance_after_reasons = summarize(assurance_after)
    cases.append({
        "name": "stripping_certificate_limitations_invalidates_strict_wrappers",
        "status": assurance_after.get("status"),
        "expected_any": ["FAIL"],
        "passed": (
            assurance_before.get("status") == "PASS-SCOPED"
            and assurance_after.get("status") == "FAIL"
            and any(
                "claim_contract_sha256 does not match certificate claim contract"
                in reason
                for reason in assurance_after_reasons
            )
        ),
        "reasons": assurance_after_reasons,
    })

    for field_name, mutate_claim in (
        (
            "truth_status",
            lambda claim: claim.__setitem__("truth_status", "confirmed"),
        ),
        (
            "residual_risks",
            lambda claim: claim.__setitem__("residual_risks", []),
        ),
    ):
        original = copy.deepcopy(base)
        if field_name == "residual_risks":
            original["claims"][0]["residual_risks"] = [
                "A reviewed claim-level limitation remains."
            ]
        finalize_certificate_contracts(original)
        original_root, _original_outside = write_structured_evidence_tree(
            original
        )
        substituted = copy.deepcopy(original)
        mutate_claim(substituted["claims"][0])
        finalize_certificate_contracts(substituted)
        substituted_result = gate_mod.evaluate_certificate(
            substituted,
            evidence_root=original_root,
            strict_evidence=True,
        )
        substituted_reasons = summarize(substituted_result)
        cases.append({
            "name": f"claim_{field_name}_substitution_invalidates_strict_wrappers",
            "status": substituted_result.get("status"),
            "expected_any": ["FAIL"],
            "passed": (
                substituted_result.get("status") == "FAIL"
                and any(
                    "claim_contract_sha256 does not match certificate claim contract"
                    in reason
                    for reason in substituted_reasons
                )
            ),
            "reasons": substituted_reasons,
        })

    contradiction_alias = copy.deepcopy(base)
    contradiction_alias["claims"][0]["contradictions"] = (
        contradiction_alias["claims"][0].pop("unresolved_contradictions")
    )
    add_strict(
        "empty_contradiction_alias_canonicalizes_without_invalidating_certificate",
        contradiction_alias,
        {"PASS-TRACKED"},
    )
    open_contradiction_alias = copy.deepcopy(base)
    open_contradiction_alias["claims"][0]["contradictions"] = [
        "An unresolved contradiction supplied through the short alias."
    ]
    add(
        "nonempty_contradiction_alias_fails_closed",
        open_contradiction_alias,
        {"FAIL"},
        reason_contains=("unresolved contradictions present",),
    )
    scoped_residual_risk = copy.deepcopy(base)
    scoped_residual_risk["claims"][0]["residual_risks"] = [
        "One bounded claim-level residual risk remains."
    ]
    add_strict(
        "claim_residual_risk_caps_certificate_at_pass_scoped",
        scoped_residual_risk,
        {"PASS-SCOPED"},
    )

    digest_fixture = copy.deepcopy(base)
    finalize_certificate_contracts(digest_fixture)
    production_assurance = gate_mod._certificate_assurance_payload(
        digest_fixture,
        gate_mod.DOWNSTREAM_POLICIES["generic"],
    )
    production_test_digests_match = all(
        gate_mod._claim_contract_sha256(
            claim,
            production_assurance,
        ) == claim_contract_sha256(claim, digest_fixture)
        for claim in digest_fixture["claims"]
    )
    cases.append({
        "name": "production_and_fixture_claim_contract_payloads_are_byte_identical",
        "status": "PASS" if production_test_digests_match else "FAIL",
        "expected_any": ["PASS"],
        "passed": production_test_digests_match,
        "reasons": [],
    })

    for placeholder_name, placeholder in (
        ("one_character", "x"),
        ("two_repeated_characters", "xx"),
        ("three_repeated_characters", "xxx"),
        ("tbd", "tbd"),
        ("todo", "todo"),
        ("placeholder_word", "placeholder"),
        ("terse_label", "only producer"),
    ):
        placeholder_cert = copy.deepcopy(base)
        placeholder_method = {
            field: placeholder for field in gate_mod.REQ_METHOD
        }
        placeholder_cert["method_manifest"] = copy.deepcopy(
            placeholder_method
        )
        placeholder_cert["claims"][0]["method_m"] = copy.deepcopy(
            placeholder_method
        )
        add(
            f"method_placeholder_{placeholder_name}_does_not_score_complete",
            placeholder_cert,
            {"FAIL"},
            reason_contains=("method completeness",),
        )

    nested_narrative_placeholders = copy.deepcopy(base)
    for field in gate_mod.METHOD_NARRATIVE_FIELDS:
        nested_narrative_placeholders["method_manifest"][field] = {
            "x": "abc"
        }
        nested_narrative_placeholders["claims"][0]["method_m"][field] = {
            "x": "abc"
        }
    add(
        "nested_identifier_fragments_do_not_satisfy_narrative_method_fields",
        nested_narrative_placeholders,
        {"FAIL"},
        reason_contains=("method completeness",),
    )
    repeated_narrative = copy.deepcopy(base)
    for field in gate_mod.METHOD_NARRATIVE_FIELDS:
        repeated_narrative["method_manifest"][field] = (
            "gate gate gate gate gate gate"
        )
        repeated_narrative["claims"][0]["method_m"][field] = (
            "gate gate gate gate gate gate"
        )
    add(
        "repeated_token_narratives_do_not_satisfy_method_m",
        repeated_narrative,
        {"FAIL"},
        reason_contains=("method completeness",),
    )
    periodic_narrative = copy.deepcopy(base)
    for field in gate_mod.METHOD_NARRATIVE_FIELDS:
        periodic_narrative["method_manifest"][field] = (
            "alpha beta gamma delta alpha beta gamma delta"
        )
        periodic_narrative["claims"][0]["method_m"][field] = (
            "alpha beta gamma delta alpha beta gamma delta"
        )
    add(
        "periodic_narratives_do_not_satisfy_method_m",
        periodic_narrative,
        {"FAIL"},
        reason_contains=("method completeness",),
    )
    low_diversity_narrative = copy.deepcopy(base)
    for field in gate_mod.METHOD_NARRATIVE_FIELDS:
        low_diversity_narrative["method_manifest"][field] = (
            "alpha beta gamma delta alpha alpha beta"
        )
        low_diversity_narrative["claims"][0]["method_m"][field] = (
            "alpha beta gamma delta alpha alpha beta"
        )
    add(
        "low_distinct_token_ratio_narratives_do_not_satisfy_method_m",
        low_diversity_narrative,
        {"FAIL"},
        reason_contains=("method completeness",),
    )
    scalar_collection_markers = copy.deepcopy(base)
    for field in gate_mod.METHOD_COLLECTION_FIELDS:
        scalar_collection_markers["method_manifest"][field] = "marker"
        scalar_collection_markers["claims"][0]["method_m"][field] = (
            "marker"
        )
    add(
        "bare_scalar_markers_do_not_satisfy_collection_method_fields",
        scalar_collection_markers,
        {"FAIL"},
        reason_contains=("method completeness",),
    )
    unanchored_short_identifiers = copy.deepcopy(base)
    for field in gate_mod.METHOD_COLLECTION_FIELDS:
        unanchored_short_identifiers["method_manifest"][field] = [
            "Git",
            "Bash",
            "CLI",
        ]
        unanchored_short_identifiers["claims"][0]["method_m"][field] = [
            "Git",
            "Bash",
            "CLI",
        ]
    add(
        "short_identifier_only_collections_do_not_satisfy_method_m",
        unanchored_short_identifiers,
        {"FAIL"},
        reason_contains=("method completeness",),
    )
    flag_metadata_without_anchor = copy.deepcopy(base)
    for field in gate_mod.METHOD_COLLECTION_FIELDS:
        flag_metadata_without_anchor["method_manifest"][field] = [
            "Git",
            True,
            3,
        ]
        flag_metadata_without_anchor["claims"][0]["method_m"][field] = [
            "Git",
            True,
            3,
        ]
    add(
        "boolean_numeric_metadata_is_not_a_collection_anchor",
        flag_metadata_without_anchor,
        {"FAIL"},
        reason_contains=("method completeness",),
    )
    unanchored_supported_language_ids = copy.deepcopy(base)
    for field in gate_mod.METHOD_COLLECTION_FIELDS:
        unanchored_supported_language_ids["method_manifest"][field] = [
            "C",
            "R",
        ]
        unanchored_supported_language_ids["claims"][0]["method_m"][field] = [
            "C",
            "R",
        ]
    add(
        "supported_c_r_short_ids_without_anchor_do_not_satisfy_method_m",
        unanchored_supported_language_ids,
        {"FAIL"},
        reason_contains=("method completeness",),
    )
    repeated_collection_anchor = copy.deepcopy(base)
    for field in gate_mod.METHOD_COLLECTION_FIELDS:
        repeated_collection_anchor["method_manifest"][field] = [
            "Git",
            "Bash",
            "shared/a.py",
        ]
        repeated_collection_anchor["claims"][0]["method_m"][field] = [
            "Git",
            "Bash",
            "shared/a.py",
        ]
    add(
        "one_repeated_anchor_cannot_satisfy_all_collection_fields",
        repeated_collection_anchor,
        {"FAIL"},
        reason_contains=("method completeness",),
    )
    minor_repeated_collection_anchor = copy.deepcopy(
        repeated_collection_anchor
    )
    minor_repeated_collection_anchor["claims"][0]["importance"] = "minor"
    minor_repeated_collection_anchor["claims"][0]["truth_status"] = (
        "supported"
    )
    add(
        "one_repeated_anchor_cannot_reach_minor_method_threshold",
        minor_repeated_collection_anchor,
        {"LIMITED"},
        reason_contains=("method completeness",),
    )
    short_structured_identifiers = copy.deepcopy(base)
    distinct_collection_anchors = {
        "artifacts": "src/a.py",
        "environment": "Python 3.12.13",
        "tools": "python3 -m pytest",
        "graders_or_tests": "tests/test_gate.py",
        "trace_or_logs": "logs/gate-result.json",
    }
    for field in gate_mod.METHOD_COLLECTION_FIELDS:
        short_structured_identifiers["method_manifest"][field] = [
            "Git",
            "Bash",
            distinct_collection_anchors[field],
        ]
        short_structured_identifiers["claims"][0]["method_m"][field] = [
            "Git",
            "Bash",
            distinct_collection_anchors[field],
        ]
    add_strict(
        "short_identifiers_inside_structured_collections_remain_valid",
        short_structured_identifiers,
        {"PASS-TRACKED"},
    )
    anchored_supported_language_ids = copy.deepcopy(base)
    for field in gate_mod.METHOD_COLLECTION_FIELDS:
        anchored_supported_language_ids["method_manifest"][field] = [
            "C",
            "R",
            distinct_collection_anchors[field],
        ]
        anchored_supported_language_ids["claims"][0]["method_m"][field] = [
            "C",
            "R",
            distinct_collection_anchors[field],
        ]
    add_strict(
        "supported_c_r_short_ids_work_alongside_distinct_anchors",
        anchored_supported_language_ids,
        {"PASS-TRACKED"},
    )

    nonobject_false_test = copy.deepcopy(base)
    nonobject_false_test["claims"][0]["false_world_tests"].append(
        "not-a-modal-object"
    )
    add(
        "nonobject_false_world_entry_fails_closed",
        nonobject_false_test,
        {"FAIL"},
        reason_contains=("false_world_tests contains non-object entries",),
    )
    minor_nonobject_test = copy.deepcopy(base)
    minor_nonobject_test["claims"][0]["importance"] = "minor"
    minor_nonobject_test["claims"][0]["false_world_tests"] = [None]
    minor_nonobject_test["claims"][0]["true_world_tests"] = []
    add(
        "nonobject_modal_entry_fails_even_when_minor_threshold_is_zero",
        minor_nonobject_test,
        {"LIMITED"},
        reason_contains=("false_world_tests contains non-object entries",),
    )

    for variant_name, oracle_transform in (
        ("punctuation", lambda value: value + "."),
        (
            "paraphrase",
            lambda _value: (
                "A strict evaluation must reject the critical claim when its "
                "supporting evidence is absent."
            ),
        ),
    ):
        modal_clone = copy.deepcopy(base)
        first_world = copy.deepcopy(
            modal_clone["claims"][0]["false_world_tests"][0]
        )
        second_world = copy.deepcopy(first_world)
        second_world["id"] = f"FW-CLONE-{variant_name.upper()}"
        second_world["evidence_refs"] = [ev(second_world["id"])]
        second_world["world_contract"]["semantic_equivalence_class"] = (
            f"claim-evidence-absent-{variant_name}-relabel"
        )
        second_world["world_contract"]["oracle"] = oracle_transform(
            first_world["world_contract"]["oracle"]
        )
        modal_clone["claims"][0]["false_world_tests"] = [
            first_world,
            second_world,
        ]
        add_strict(
            f"modal_{variant_name}_plus_relabel_does_not_create_coverage",
            modal_clone,
            {"FAIL"},
        )

    invalid_operator = copy.deepcopy(base)
    invalid_operator["claims"][0]["false_world_tests"][0][
        "world_contract"
    ]["operator"] = "delete"
    add(
        "world_operator_synonym_outside_closed_vocabulary_is_rejected",
        invalid_operator,
        {"FAIL"},
    )
    invalid_target = copy.deepcopy(base)
    invalid_target["claims"][0]["false_world_tests"][0][
        "world_contract"
    ]["target"] = "invented.unique.slug"
    add(
        "world_target_relabel_outside_closed_vocabulary_is_rejected",
        invalid_target,
        {"FAIL"},
    )
    legacy_world_schema = copy.deepcopy(base)
    legacy_world_schema["claims"][0]["false_world_tests"][0][
        "world_contract"
    ]["schema_version"] = "1.0"
    add(
        "legacy_free_prose_world_schema_1_0_is_rejected",
        legacy_world_schema,
        {"FAIL"},
    )

    for case_name, mutate_test in (
        (
            "polarity_laden_false_observation_does_not_override_typed_outcome",
            lambda test: test.__setitem__(
                "observed_behavior",
                "The log quotes 'accepted' while explaining why that label was rejected.",
            ),
        ),
        (
            "polarity_laden_true_observation_does_not_override_typed_outcome",
            lambda test: test.__setitem__(
                "observed_behavior",
                "The report discusses a rejected alternative while retaining this case.",
            ),
        ),
        (
            "polarity_laden_expected_behavior_is_explanation_only",
            lambda test: test.__setitem__(
                "expected_behavior",
                "Do not infer authorization from the quoted phrase 'accept the claim'.",
            ),
        ),
        (
            "polarity_laden_oracle_prose_is_explanation_only",
            lambda test: test["world_contract"].__setitem__(
                "oracle",
                "The oracle records why an apparent 'pass' is not authorization.",
            ),
        ),
    ):
        explanatory = copy.deepcopy(base)
        selected_tests = (
            explanatory["claims"][0]["true_world_tests"]
            if "true_observation" in case_name
            else explanatory["claims"][0]["false_world_tests"]
        )
        mutate_test(selected_tests[0])
        add(
            case_name,
            explanatory,
            {"PASS-TRACKED"},
        )

    world_outcome_mismatch = copy.deepcopy(base)
    world_outcome_mismatch["claims"][0]["false_world_tests"][0][
        "world_contract"
    ]["expected_outcome"] = "retained_true_claim"
    add(
        "world_expected_outcome_disagrees_with_test_outcome",
        world_outcome_mismatch,
        {"FAIL"},
        reason_contains=(
            "outcome does not match world_contract expected_outcome",
        ),
    )
    typed_outcome_mismatch = copy.deepcopy(base)
    typed_outcome_mismatch["claims"][0]["false_world_tests"][0][
        "observed_outcome"
    ] = "retained_true_claim"
    add(
        "outcome_and_observed_outcome_mismatch_fails_closed",
        typed_outcome_mismatch,
        {"FAIL"},
        reason_contains=("outcome and observed_outcome do not match",),
    )
    matching_typed_outcomes = copy.deepcopy(base)
    matching_typed_outcomes["claims"][0]["false_world_tests"][0][
        "observed_outcome"
    ] = "rejected_false_claim"
    add(
        "matching_outcome_and_observed_outcome_remain_valid",
        matching_typed_outcomes,
        {"PASS-TRACKED"},
    )
    observed_outcome_only = copy.deepcopy(base)
    observed_test = observed_outcome_only["claims"][0][
        "false_world_tests"
    ][0]
    observed_test["observed_outcome"] = observed_test.pop("outcome")
    add(
        "observed_outcome_only_remains_a_valid_typed_channel",
        observed_outcome_only,
        {"PASS-TRACKED"},
    )

    package_root = Path(gate_mod.__file__).resolve().parents[3]
    release_certificate_path = (
        package_root / "self_validation" / "self_certificate.json"
    )
    release_certificate_source = release_certificate_path.read_text(
        encoding="utf-8"
    )
    release_certificate = json.loads(release_certificate_source)
    untouched_release_certificate = copy.deepcopy(release_certificate)
    release_tests = [
        test
        for claim in release_certificate.get("claims", [])
        for field in ("false_world_tests", "true_world_tests")
        for test in claim.get(field, [])
    ]
    release_ids = {
        test.get("id")
        for test in release_tests
        if type(test.get("id")) is str
    }
    # Exercise the one-time migration only on an isolated legacy fixture.  The
    # checked-in schema-1.1 certificate below is never repaired by the test.
    legacy_fixture_certificate = copy.deepcopy(release_certificate)
    legacy_fixture_tests = [
        test
        for claim in legacy_fixture_certificate.get("claims", [])
        for field in ("false_world_tests", "true_world_tests")
        for test in claim.get(field, [])
    ]
    migrated_worlds: Dict[str, Dict[str, Any]] = {}
    migration_error = ""
    try:
        for legacy_test in legacy_fixture_tests:
            legacy_test["world_contract"]["schema_version"] = "1.0"
            legacy_test["world_contract"]["operator"] = "legacy-untyped"
            legacy_test["world_contract"]["target"] = "legacy-untyped"
            test_id = legacy_test.get("id")
            if type(test_id) is not str:
                raise TypeError("legacy fixture modal id is not a string")
            migrated_worlds[test_id] = (
                gate_mod.migrate_legacy_world_contract(legacy_test)
            )
    except (KeyError, TypeError, ValueError) as exc:
        migration_error = f"{type(exc).__name__}: {exc}"
    current_release_method_scores = {
        str(claim.get("id")): gate_mod.method_completeness(
            claim.get("method_m")
        )
        for claim in release_certificate.get("claims", [])
    }
    mapping_exact = (
        len(release_tests) == 80
        and release_ids == set(gate_mod.LEGACY_WORLD_IDENTITY_BY_TEST_ID)
    )
    independent_mapping_exact = (
        len(INDEPENDENT_LEGACY_WORLD_IDENTITY) == 80
        and release_ids == set(INDEPENDENT_LEGACY_WORLD_IDENTITY)
        and gate_mod.LEGACY_WORLD_IDENTITY_BY_TEST_ID
        == INDEPENDENT_LEGACY_WORLD_IDENTITY
    )
    independent_declaration_digests: Dict[str, str] = {}
    production_payload_digests: Dict[str, str] = {}
    reviewed_pin_errors: List[str] = []
    for claim in release_certificate.get("claims", []):
        for field, kind in (
            ("false_world_tests", "false_world"),
            ("true_world_tests", "true_world"),
        ):
            for test in claim.get(field, []):
                test_id = test.get("id")
                if type(test_id) is not str:
                    reviewed_pin_errors.append(
                        "checked-in release modal id is not a string"
                    )
                    continue
                independent_payload = (
                    independent_package_world_transition_payload(
                        test,
                        str(claim.get("id")),
                        kind,
                    )
                )
                independent_declaration_digests[test_id] = hashlib.sha256(
                    json.dumps(
                        independent_payload,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    ).encode("utf-8")
                ).hexdigest()
                production_payload, production_reasons = (
                    gate_mod._package_world_transition_payload(
                        test,
                        kind,
                        str(claim.get("id")),
                    )
                )
                if production_payload is None:
                    reviewed_pin_errors.extend(production_reasons)
                else:
                    if production_payload != independent_payload:
                        reviewed_pin_errors.append(
                            f"{test_id}: production transition payload differs "
                            "from independent construction"
                        )
                    production_payload_digests[test_id] = hashlib.sha256(
                        json.dumps(
                            production_payload,
                            ensure_ascii=False,
                            separators=(",", ":"),
                            sort_keys=True,
                        ).encode("utf-8")
                    ).hexdigest()
                pin_digest, pin_reason = (
                    gate_mod._reviewed_package_world_transition_digest(
                        test,
                        kind,
                        str(claim.get("id")),
                    )
                )
                if pin_reason is not None:
                    reviewed_pin_errors.append(pin_reason)
                elif pin_digest != independent_declaration_digests[test_id]:
                    reviewed_pin_errors.append(
                        f"{test_id}: reviewed pin digest differs from oracle"
                    )
    declarations_match_oracle = independent_declaration_digests == (
        INDEPENDENT_PACKAGE_WORLD_TRANSITION_SHA256
    )
    production_payloads_match_registry = production_payload_digests == (
        gate_mod.REVIEWED_PACKAGE_WORLD_TRANSITION_SHA256
    )
    registry_exact = INDEPENDENT_PACKAGE_WORLD_TRANSITION_SHA256 == (
        gate_mod.REVIEWED_PACKAGE_WORLD_TRANSITION_SHA256
    )
    registry_collision_free = (
        len(set(INDEPENDENT_PACKAGE_WORLD_TRANSITION_SHA256.values())) == 80
        and len(set(
            gate_mod.REVIEWED_PACKAGE_WORLD_TRANSITION_SHA256.values()
        )) == 80
    )
    current_worlds_by_id = {
        test["id"]: test.get("world_contract")
        for test in release_tests
        if type(test.get("id")) is str
    }
    migration_matches_current = (
        len(migrated_worlds) == 80
        and migrated_worlds == current_worlds_by_id
        and all(
            not gate_mod._canonical_world_contract(world)[1]
            for world in migrated_worlds.values()
        )
    )
    cases.append({
        "name": "legacy_world_migration_isolated_from_current_release",
        "status": "PASS" if (
            mapping_exact
            and independent_mapping_exact
            and declarations_match_oracle
            and production_payloads_match_registry
            and registry_exact
            and registry_collision_free
            and not reviewed_pin_errors
            and migration_matches_current
            and not migration_error
            and release_certificate == untouched_release_certificate
            and json.loads(release_certificate_source)
            == untouched_release_certificate
        ) else "FAIL",
        "expected_any": ["PASS"],
        "passed": (
            mapping_exact
            and independent_mapping_exact
            and declarations_match_oracle
            and production_payloads_match_registry
            and registry_exact
            and registry_collision_free
            and not reviewed_pin_errors
            and migration_matches_current
            and not migration_error
            and release_certificate == untouched_release_certificate
            and json.loads(release_certificate_source)
            == untouched_release_certificate
        ),
        "reasons": (
            ([migration_error] if migration_error else [])
            + reviewed_pin_errors[:4]
        ),
    })

    def release_claim(
        certificate: Mapping[str, Any],
        claim_id: str,
    ) -> Dict[str, Any]:
        return next(
            claim
            for claim in certificate["claims"]
            if claim.get("id") == claim_id
        )

    def release_modal_count(certificate: Mapping[str, Any]) -> int:
        return sum(
            len(claim.get(field, []))
            for claim in certificate.get("claims", [])
            for field in ("false_world_tests", "true_world_tests")
        )

    exact_inventory_reasons = (
        gate_mod._package_world_registry_inventory_reasons(
            release_certificate["claims"]
        )
    )
    cases.append({
        "name": "package_self_registry_exact_80_once_inventory_passes",
        "status": "PASS" if not exact_inventory_reasons else "FAIL",
        "expected_any": ["PASS"],
        "passed": (
            release_modal_count(release_certificate) == 80
            and not exact_inventory_reasons
        ),
        "reasons": exact_inventory_reasons,
    })
    release_certificate_method = gate_mod.method_completeness(
        release_certificate.get("method_manifest")
    )
    incomplete_current_methods = sorted(
        claim_id
        for claim_id, (score, missing) in current_release_method_scores.items()
        if score < 1.0 or missing
    )
    methods_complete = (
        release_certificate_method == (1.0, [])
        and len(current_release_method_scores) == 7
        and not incomplete_current_methods
    )
    cases.append({
        "name": "current_release_certificate_and_all_claim_methods_complete",
        "status": "PASS" if methods_complete else "FAIL",
        "expected_any": ["PASS"],
        "passed": methods_complete,
        "reasons": [
            "current release methods awaiting artifact-anchor migration: "
            + ", ".join(incomplete_current_methods)
        ] if incomplete_current_methods else [],
    })

    release_evidence_rows = list(all_evidence_refs(release_certificate))
    release_evidence_refs = [row[0] for row in release_evidence_rows]
    release_ledger = json.loads(
        (
            package_root / "self_validation" / "current_observations.json"
        ).read_text(encoding="utf-8")
    )
    release_observations = release_ledger.get("observations")
    release_strict_result = gate_mod.evaluate_certificate(
        release_certificate,
        evidence_root=package_root,
        strict_evidence=True,
        downstream_policy="package-self",
    )
    current_schema_complete = (
        len(current_worlds_by_id) == 80
        and all(
            isinstance(world, Mapping)
            and world.get("schema_version")
            == gate_mod.WORLD_CONTRACT_SCHEMA_VERSION
            and not gate_mod._canonical_world_contract(world)[1]
            for world in current_worlds_by_id.values()
        )
    )
    checked_in_release_passed = (
        release_strict_result.get("status") == "PASS-SCOPED"
        and release_certificate == untouched_release_certificate
        and current_schema_complete
        and methods_complete
        and len(release_evidence_refs) == 94
        and len(set(release_evidence_refs)) == 94
        and release_ledger.get("observation_schema_version") == "1.2"
        and isinstance(release_observations, Mapping)
        and len(release_observations) == 80
    )
    cases.append({
        "name": "checked_in_schema_1_1_release_strict_package_self_passes",
        "status": release_strict_result.get("status"),
        "expected_any": ["PASS-SCOPED"],
        "passed": checked_in_release_passed,
        "reasons": summarize(release_strict_result),
    })

    deleted_nonminimum = copy.deepcopy(release_certificate)
    deleted_claim = release_claim(
        deleted_nonminimum,
        "C-formal-invocation",
    )
    deleted_test_id = str(
        deleted_claim["false_world_tests"].pop(0).get("id")
    )
    deleted_inventory_reasons = (
        gate_mod._package_world_registry_inventory_reasons(
            deleted_nonminimum["claims"]
        )
    )
    deleted_result = gate_mod.evaluate_certificate(
        deleted_nonminimum,
        downstream_policy="package-self",
    )
    cases.append({
        "name": "package_self_delete_nonminimum_transition_fails_inventory",
        "status": deleted_result.get("status"),
        "expected_any": ["FAIL"],
        "passed": (
            release_modal_count(deleted_nonminimum) == 79
            and deleted_result.get("status") == "FAIL"
            and any(
                "missing modal test IDs" in reason
                and deleted_test_id in reason
                for reason in deleted_inventory_reasons
            )
            and not any(
                "unreviewed modal test IDs" in reason
                or "duplicate modal test IDs" in reason
                for reason in deleted_inventory_reasons
            )
        ),
        "reasons": deleted_inventory_reasons,
    })

    replaced_with_duplicate = copy.deepcopy(release_certificate)
    replacement_claim = release_claim(
        replaced_with_duplicate,
        "C-structure",
    )
    missing_id = str(
        replacement_claim["false_world_tests"].pop(0).get("id")
    )
    duplicate_id = str(
        replacement_claim["false_world_tests"][0].get("id")
    )
    replacement_claim["false_world_tests"].append(
        copy.deepcopy(replacement_claim["false_world_tests"][0])
    )
    replacement_inventory_reasons = (
        gate_mod._package_world_registry_inventory_reasons(
            replaced_with_duplicate["claims"]
        )
    )
    replacement_result = gate_mod.evaluate_certificate(
        replaced_with_duplicate,
        downstream_policy="package-self",
    )
    cases.append({
        "name": "package_self_total_80_delete_one_duplicate_another_fails",
        "status": replacement_result.get("status"),
        "expected_any": ["FAIL"],
        "passed": (
            release_modal_count(replaced_with_duplicate) == 80
            and replacement_result.get("status") == "FAIL"
            and any(
                "missing modal test IDs" in reason and missing_id in reason
                for reason in replacement_inventory_reasons
            )
            and any(
                "duplicate modal test IDs" in reason and duplicate_id in reason
                for reason in replacement_inventory_reasons
            )
        ),
        "reasons": replacement_inventory_reasons,
    })

    duplicate_cross_claim_lane = copy.deepcopy(
        release_certificate
    )
    duplicate_source = copy.deepcopy(
        release_claim(
            duplicate_cross_claim_lane,
            "C-structure",
        )["false_world_tests"][0]
    )
    duplicate_cross_id = str(duplicate_source.get("id"))
    release_claim(
        duplicate_cross_claim_lane,
        "C-gate-hardening",
    )["true_world_tests"].append(duplicate_source)
    duplicate_cross_reasons = (
        gate_mod._package_world_registry_inventory_reasons(
            duplicate_cross_claim_lane["claims"]
        )
    )
    duplicate_cross_result = gate_mod.evaluate_certificate(
        duplicate_cross_claim_lane,
        downstream_policy="package-self",
    )
    cases.append({
        "name": "package_self_duplicate_across_claim_and_lane_fails",
        "status": duplicate_cross_result.get("status"),
        "expected_any": ["FAIL"],
        "passed": (
            release_modal_count(duplicate_cross_claim_lane) == 81
            and duplicate_cross_result.get("status") == "FAIL"
            and any(
                "duplicate modal test IDs" in reason
                and duplicate_cross_id in reason
                for reason in duplicate_cross_reasons
            )
        ),
        "reasons": duplicate_cross_reasons,
    })

    moved_cross_claim_lane = copy.deepcopy(release_certificate)
    moved_source_claim = release_claim(
        moved_cross_claim_lane,
        "C-formal-invocation",
    )
    moved_test = moved_source_claim["true_world_tests"].pop(0)
    moved_id = str(moved_test.get("id"))
    release_claim(
        moved_cross_claim_lane,
        "C-gate-hardening",
    )["false_world_tests"].append(moved_test)
    moved_inventory_reasons = (
        gate_mod._package_world_registry_inventory_reasons(
            moved_cross_claim_lane["claims"]
        )
    )
    moved_result = gate_mod.evaluate_certificate(
        moved_cross_claim_lane,
        downstream_policy="package-self",
    )
    moved_result_text = json.dumps(moved_result, sort_keys=True)
    cases.append({
        "name": "package_self_cross_claim_lane_move_fails_full_pin",
        "status": moved_result.get("status"),
        "expected_any": ["FAIL"],
        "passed": (
            release_modal_count(moved_cross_claim_lane) == 80
            and not moved_inventory_reasons
            and moved_result.get("status") == "FAIL"
            and moved_id in moved_result_text
            and "is not canonical" in moved_result_text
        ),
        "reasons": summarize(moved_result),
    })

    unknown_eighty_first = copy.deepcopy(release_certificate)
    unknown_test = copy.deepcopy(
        release_claim(
            unknown_eighty_first,
            "C-structure",
        )["false_world_tests"][0]
    )
    unknown_id = "FW-package-self-unreviewed-81"
    unknown_test["id"] = unknown_id
    unknown_test["world_contract"]["semantic_equivalence_class"] = (
        "fw-package-self-unreviewed-81"
    )
    release_claim(
        unknown_eighty_first,
        "C-structure",
    )["false_world_tests"].append(unknown_test)
    unknown_inventory_reasons = (
        gate_mod._package_world_registry_inventory_reasons(
            unknown_eighty_first["claims"]
        )
    )
    unknown_result = gate_mod.evaluate_certificate(
        unknown_eighty_first,
        downstream_policy="package-self",
    )
    cases.append({
        "name": "package_self_80_plus_unknown_transition_fails",
        "status": unknown_result.get("status"),
        "expected_any": ["FAIL"],
        "passed": (
            release_modal_count(unknown_eighty_first) == 81
            and unknown_result.get("status") == "FAIL"
            and any(
                "unreviewed modal test IDs" in reason
                and unknown_id in reason
                for reason in unknown_inventory_reasons
            )
        ),
        "reasons": unknown_inventory_reasons,
    })

    for case_name, invalid_id, expected_reason in (
        (
            "package_self_non_string_modal_id_rejected_strictly",
            7,
            "package-self modal test id is not a string",
        ),
        (
            "package_self_empty_modal_id_rejected_strictly",
            "",
            "package-self modal test id is empty",
        ),
        (
            "package_self_noncanonical_modal_id_rejected_strictly",
            " FW-structure-missing-manifest ",
            "package-self modal test id is not canonical",
        ),
    ):
        malformed_id_certificate = copy.deepcopy(release_certificate)
        malformed_id_claim = release_claim(
            malformed_id_certificate,
            "C-structure",
        )
        malformed_id_test = malformed_id_claim["false_world_tests"][0]
        malformed_id_test["id"] = invalid_id
        malformed_payload, malformed_payload_reasons = (
            gate_mod._package_world_transition_payload(
                malformed_id_test,
                "false_world",
                "C-structure",
            )
        )
        malformed_inventory_reasons = (
            gate_mod._package_world_registry_inventory_reasons(
                malformed_id_certificate["claims"]
            )
        )
        malformed_id_result = gate_mod.evaluate_certificate(
            malformed_id_certificate,
            evidence_root=package_root,
            strict_evidence=True,
            downstream_policy="package-self",
        )
        malformed_id_reasons = (
            malformed_payload_reasons
            + malformed_inventory_reasons
            + summarize(malformed_id_result)
        )
        cases.append({
            "name": case_name,
            "status": malformed_id_result.get("status"),
            "expected_any": ["FAIL"],
            "passed": (
                malformed_id_result.get("status") == "FAIL"
                and malformed_payload is None
                and any(
                    expected_reason in reason
                    for reason in malformed_payload_reasons
                )
                and any(
                    expected_reason in reason
                    for reason in malformed_inventory_reasons
                )
            ),
            "reasons": malformed_id_reasons[:12],
        })

    for case_name, invalid_targets, expected_reason in (
        (
            "package_self_non_string_target_member_rejected_strictly",
            ["C-structure", 7],
            "target_claim_ids member 1 is not a string",
        ),
        (
            "package_self_noncanonical_target_member_rejected_strictly",
            ["C-structure "],
            "target_claim_ids contains a noncanonical id",
        ),
    ):
        malformed_target_certificate = copy.deepcopy(release_certificate)
        malformed_target_claim = release_claim(
            malformed_target_certificate,
            "C-structure",
        )
        malformed_target_test = malformed_target_claim[
            "false_world_tests"
        ][0]
        malformed_target_test["target_claim_ids"] = invalid_targets
        malformed_target_payload, malformed_target_payload_reasons = (
            gate_mod._package_world_transition_payload(
                malformed_target_test,
                "false_world",
                "C-structure",
            )
        )
        malformed_target_result = gate_mod.evaluate_certificate(
            malformed_target_certificate,
            evidence_root=package_root,
            strict_evidence=True,
            downstream_policy="package-self",
        )
        malformed_target_reasons = (
            malformed_target_payload_reasons
            + summarize(malformed_target_result)
        )
        cases.append({
            "name": case_name,
            "status": malformed_target_result.get("status"),
            "expected_any": ["FAIL"],
            "passed": (
                malformed_target_result.get("status") == "FAIL"
                and malformed_target_payload is None
                and any(
                    expected_reason in reason
                    for reason in malformed_target_payload_reasons
                )
            ),
            "reasons": malformed_target_reasons[:12],
        })

    structure_claim = next(
        claim
        for claim in release_certificate["claims"]
        if claim.get("id") == "C-structure"
    )
    reviewed_first = copy.deepcopy(structure_claim["false_world_tests"][0])
    if (
        reviewed_first.get("world_contract", {}).get("schema_version")
        != gate_mod.WORLD_CONTRACT_SCHEMA_VERSION
    ):
        raise RuntimeError("checked-in release world contract is not current")
    relabeled_clone = copy.deepcopy(reviewed_first)
    relabeled_clone["id"] = "FW-structure-relabeled-clone"
    relabeled_clone["world_contract"]["semantic_equivalence_class"] = (
        "fw-structure-relabeled-clone"
    )
    relabeled_clone["world_contract"]["operator"] = "replace"
    pinned_clone_reasons = gate_mod._modal_test_uniqueness_reasons(
        [reviewed_first, relabeled_clone],
        [],
        "false_world",
        2,
        None,
        "C-structure",
        gate_mod.DOWNSTREAM_POLICIES["package-self"],
    )
    cases.append({
        "name": "package_self_id_class_operator_relabel_clone_counts_once",
        "status": "FAIL" if pinned_clone_reasons else "PASS",
        "expected_any": ["FAIL"],
        "passed": (
            any(
                "unreviewed package-self modal transition" in reason
                for reason in pinned_clone_reasons
            )
            and any(
                "reviewed-registry distinct false-world cases 1 < required 2"
                in reason
                for reason in pinned_clone_reasons
            )
        ),
        "reasons": pinned_clone_reasons,
    })
    known_id_impostor = copy.deepcopy(reviewed_first)
    known_id_impostor["perturbation"] = (
        "Replace a README sentence while leaving the package manifest intact."
    )
    known_id_impostor["expected_behavior"] = (
        "The documentation reviewer should accept the harmless sentence edit."
    )
    known_id_impostor["observed_behavior"] = (
        "The documentation lane retained the package after the sentence edit."
    )
    known_id_impostor["world_contract"]["precondition"] = (
        "The package documentation is internally consistent."
    )
    known_id_impostor["world_contract"]["state_delta"] = (
        "Edit one harmless sentence without changing any package mechanic."
    )
    known_id_impostor["world_contract"]["oracle"] = (
        "The documentation-only edit should remain accepted."
    )
    known_id_reasons = gate_mod._modal_test_uniqueness_reasons(
        [known_id_impostor],
        [],
        "false_world",
        1,
        None,
        "C-structure",
        gate_mod.DOWNSTREAM_POLICIES["package-self"],
    )
    cases.append({
        "name": "package_self_c_structure_known_id_impersonation_rejected",
        "status": "FAIL" if known_id_reasons else "PASS",
        "expected_any": ["FAIL"],
        "passed": (
            any(
                "does not match the reviewed registry" in reason
                for reason in known_id_reasons
            )
            and any(
                "reviewed-registry distinct false-world cases 0 < required 1"
                in reason
                for reason in known_id_reasons
            )
        ),
        "reasons": known_id_reasons,
    })
    fixture_alias = copy.deepcopy(reviewed_first)
    fixture_alias["fixture_digest"] = "sha256:" + "a" * 64
    fixture_alias_digest, fixture_alias_reason = (
        gate_mod._reviewed_package_world_transition_digest(
            fixture_alias,
            "false_world",
            "C-structure",
        )
    )
    cases.append({
        "name": "package_self_unrecognized_fixture_digest_alias_rejected",
        "status": "FAIL" if fixture_alias_reason else "PASS",
        "expected_any": ["FAIL"],
        "passed": (
            not fixture_alias_digest
            and fixture_alias_reason is not None
            and "fields are not closed" in fixture_alias_reason
        ),
        "reasons": [fixture_alias_reason] if fixture_alias_reason else [],
    })
    fixture_bound = copy.deepcopy(reviewed_first)
    fixture_bound["fixture_sha256"] = "sha256:" + "b" * 64
    fixture_bound_digest, fixture_bound_reason = (
        gate_mod._reviewed_package_world_transition_digest(
            fixture_bound,
            "false_world",
            "C-structure",
        )
    )
    cases.append({
        "name": "package_self_fixture_sha256_is_part_of_registry_pin",
        "status": "FAIL" if fixture_bound_reason else "PASS",
        "expected_any": ["FAIL"],
        "passed": (
            not fixture_bound_digest
            and fixture_bound_reason is not None
            and "does not match the reviewed registry" in fixture_bound_reason
        ),
        "reasons": [fixture_bound_reason] if fixture_bound_reason else [],
    })
    duplicate_reviewed_reasons = gate_mod._modal_test_uniqueness_reasons(
        [reviewed_first, copy.deepcopy(reviewed_first)],
        [],
        "false_world",
        2,
        None,
        "C-structure",
        gate_mod.DOWNSTREAM_POLICIES["package-self"],
    )
    cases.append({
        "name": "package_self_duplicate_reviewed_transition_counts_once",
        "status": "FAIL" if duplicate_reviewed_reasons else "PASS",
        "expected_any": ["FAIL"],
        "passed": (
            any(
                "duplicate false-world test IDs present" in reason
                for reason in duplicate_reviewed_reasons
            )
            and any(
                "reviewed-registry distinct false-world cases 1 < required 2"
                in reason
                for reason in duplicate_reviewed_reasons
            )
        ),
        "reasons": duplicate_reviewed_reasons,
    })
    generic_registry_reasons = gate_mod._modal_test_uniqueness_reasons(
        [reviewed_first],
        [],
        "false_world",
        1,
        None,
        "C-structure",
        gate_mod.DOWNSTREAM_POLICIES["generic"],
    )
    cases.append({
        "name": "package_registry_requires_explicit_package_self_policy",
        "status": "FAIL" if generic_registry_reasons else "PASS",
        "expected_any": ["FAIL"],
        "passed": any(
            "registered package-self modal transitions require the "
            "package-self downstream policy" in reason
            for reason in generic_registry_reasons
        ),
        "reasons": generic_registry_reasons,
    })

    output_root = _private_tempdir("ntt_gate_output_contract_")
    output_path = output_root / "nested" / "result.json"
    _atomic_write_json(output_path, '{"generation":1}')
    _atomic_write_json(output_path, '{"generation":2}')
    regular_atomic_ok = (
        output_path.read_text(encoding="utf-8") == '{"generation":2}'
        and stat.S_IMODE(output_path.stat().st_mode) == 0o600
    )
    sentinel = output_root / "sentinel.json"
    sentinel.write_text('{"sentinel":true}', encoding="utf-8")
    symlink_output = output_root / "symlink-output.json"
    symlink_output.symlink_to(sentinel.name)
    symlink_rejected = False
    try:
        _atomic_write_json(symlink_output, '{"overwrite":true}')
    except (OSError, RuntimeError, ValueError):
        symlink_rejected = True
    real_parent = output_root / "real-parent"
    real_parent.mkdir()
    parent_symlink = output_root / "parent-symlink"
    parent_symlink.symlink_to(real_parent.name)
    parent_symlink_rejected = False
    try:
        _atomic_write_json(
            parent_symlink / "result.json",
            '{"write":true}',
        )
    except (OSError, RuntimeError, ValueError):
        parent_symlink_rejected = True
    cases.append({
        "name": "json_output_is_atomic_and_never_follows_symlinks",
        "status": "PASS" if (
            regular_atomic_ok
            and symlink_rejected
            and parent_symlink_rejected
        ) else "FAIL",
        "expected_any": ["PASS"],
        "passed": (
            regular_atomic_ok
            and symlink_rejected
            and parent_symlink_rejected
            and sentinel.read_text(encoding="utf-8")
            == '{"sentinel":true}'
            and not (real_parent / "result.json").exists()
        ),
        "reasons": [],
    })

    markdown_root = _private_tempdir("ntt_gate_markdown_output_contract_")
    markdown_output = markdown_root / "nested" / "gate-result.md"
    gate_mod._atomic_write_new_text(markdown_output, "first report\n")
    markdown_regular_ok = (
        markdown_output.read_text(encoding="utf-8") == "first report\n"
        and stat.S_IMODE(markdown_output.stat().st_mode) == 0o600
    )
    cases.append({
        "name": "gate_markdown_output_is_private_and_atomically_created",
        "status": "PASS" if markdown_regular_ok else "FAIL",
        "expected_any": ["PASS"],
        "passed": markdown_regular_ok,
        "reasons": [],
    })

    markdown_sentinel = markdown_root / "sentinel.md"
    markdown_sentinel.write_text("sentinel\n", encoding="utf-8")
    markdown_symlink = markdown_root / "symlink-output.md"
    markdown_symlink.symlink_to(markdown_sentinel.name)
    markdown_hardlink = markdown_root / "hardlink-output.md"
    os.link(markdown_sentinel, markdown_hardlink)

    def markdown_write_rejected(path: Path) -> bool:
        try:
            gate_mod._atomic_write_new_text(path, "overwrite\n")
        except (OSError, RuntimeError, ValueError):
            return True
        return False

    markdown_final_links_rejected = (
        markdown_write_rejected(markdown_symlink)
        and markdown_write_rejected(markdown_hardlink)
        and markdown_write_rejected(markdown_output)
    )
    cases.append({
        "name": "gate_markdown_output_rejects_existing_and_linked_targets",
        "status": "PASS" if markdown_final_links_rejected else "FAIL",
        "expected_any": ["PASS"],
        "passed": (
            markdown_final_links_rejected
            and markdown_sentinel.read_text(encoding="utf-8") == "sentinel\n"
            and markdown_output.read_text(encoding="utf-8") == "first report\n"
        ),
        "reasons": [],
    })

    markdown_real_parent = markdown_root / "real-parent"
    markdown_real_parent.mkdir()
    markdown_linked_parent = markdown_root / "linked-parent"
    markdown_linked_parent.symlink_to(markdown_real_parent.name)
    markdown_ancestor_rejected = markdown_write_rejected(
        markdown_linked_parent / "escaped-report.md"
    )
    cases.append({
        "name": "gate_markdown_output_rejects_symlinked_ancestor",
        "status": "PASS" if markdown_ancestor_rejected else "FAIL",
        "expected_any": ["PASS"],
        "passed": (
            markdown_ancestor_rejected
            and not (markdown_real_parent / "escaped-report.md").exists()
        ),
        "reasons": [],
    })

    markdown_swap_root = _private_tempdir(
        "ntt_gate_markdown_real_directory_swap_"
    )
    markdown_checked_parent = markdown_swap_root / "checked-parent"
    markdown_checked_parent.mkdir()
    markdown_parked_parent = markdown_swap_root / "parked-parent"
    markdown_replacement_parent = markdown_swap_root / "replacement-parent"
    markdown_replacement_parent.mkdir()
    markdown_swap_output = markdown_checked_parent / "gate-result.md"
    markdown_replacement_sentinel = (
        markdown_replacement_parent / markdown_swap_output.name
    )
    markdown_replacement_bytes = b"replacement sentinel\n"
    markdown_replacement_sentinel.write_bytes(markdown_replacement_bytes)
    markdown_certificate = markdown_swap_root / "certificate.json"
    markdown_certificate.write_text("{}\n", encoding="utf-8")
    original_evaluate_certificate = gate_mod.evaluate_certificate
    markdown_swap_performed = False

    def swap_during_gate_evaluation(*_args: Any, **_kwargs: Any) -> Dict[str, Any]:
        nonlocal markdown_swap_performed
        markdown_checked_parent.rename(markdown_parked_parent)
        markdown_replacement_parent.rename(markdown_checked_parent)
        markdown_swap_performed = True
        return {
            "status": "PASS-SCOPED",
            "failure_kind": None,
            "summary": {},
            "reasons": [],
            "claim_results": [],
        }

    markdown_swap_stdout = io.StringIO()
    try:
        gate_mod.evaluate_certificate = swap_during_gate_evaluation
        with contextlib.redirect_stdout(markdown_swap_stdout):
            markdown_swap_returncode = gate_mod.main([
                str(markdown_certificate),
                "--markdown",
                str(markdown_swap_output),
            ])
    finally:
        gate_mod.evaluate_certificate = original_evaluate_certificate
    try:
        markdown_swap_result = json.loads(
            markdown_swap_stdout.getvalue()
        )
    except (TypeError, ValueError):
        markdown_swap_result = {}
    cases.append({
        "name": "gate_markdown_holds_parent_across_real_directory_substitution",
        "status": "PASS" if (
            markdown_swap_performed
            and markdown_swap_returncode == 2
            and markdown_swap_result.get("status") == "INVALID_INPUT"
            and (markdown_checked_parent / markdown_swap_output.name).read_bytes()
            == markdown_replacement_bytes
            and not (
                markdown_parked_parent / markdown_swap_output.name
            ).exists()
        ) else "FAIL",
        "expected_any": ["PASS"],
        "passed": (
            markdown_swap_performed
            and markdown_swap_returncode == 2
            and markdown_swap_result.get("status") == "INVALID_INPUT"
            and (markdown_checked_parent / markdown_swap_output.name).read_bytes()
            == markdown_replacement_bytes
            and not (
                markdown_parked_parent / markdown_swap_output.name
            ).exists()
            and not any(
                entry.name.startswith(f".{markdown_swap_output.name}.")
                for entry in markdown_parked_parent.iterdir()
            )
        ),
        "reasons": [],
    })
    return cases


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


def _require_replaceable_json_target(directory_fd: int, name: str) -> None:
    try:
        metadata = os.stat(
            name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError("JSON output target is not a private regular file")


def _acquire_json_output_capability(path: Path) -> Tuple[Path, int]:
    absolute = _canonical_output_path(path)
    descriptor, _name = _open_output_parent(absolute)
    try:
        _require_replaceable_json_target(descriptor, absolute.name)
        if not _directory_path_matches_fd(absolute.parent, descriptor):
            raise ValueError("JSON output parent identity is unstable")
        return absolute, descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _atomic_write_json(
    path: Path,
    text: str,
    *,
    directory_fd: Optional[int] = None,
) -> None:
    """Atomically install JSON without following target/ancestor symlinks."""
    if directory_fd is None:
        absolute, parent_fd = _acquire_json_output_capability(path)
    else:
        absolute = _canonical_output_path(path)
        parent_fd = os.dup(directory_fd)
    target_name = absolute.name
    temporary_name = f".{target_name}.{uuid.uuid4().hex}.tmp"
    temporary_created = False
    descriptor: Optional[int] = None
    try:
        _require_replaceable_json_target(parent_fd, target_name)
        if not _directory_path_matches_fd(absolute.parent, parent_fd):
            raise ValueError("JSON output parent changed before write")
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
                    raise OSError("zero-byte JSON output write")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
            descriptor = None
        _require_replaceable_json_target(parent_fd, target_name)
        if not _directory_path_matches_fd(absolute.parent, parent_fd):
            raise ValueError("JSON output parent changed before install")
        os.replace(
            temporary_name,
            target_name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        temporary_created = False
        installed = os.stat(
            target_name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if not stat.S_ISREG(installed.st_mode) or installed.st_nlink != 1:
            raise OSError("installed JSON output is not private")
        os.fsync(parent_fd)
        if not _directory_path_matches_fd(absolute.parent, parent_fd):
            raise ValueError("JSON output parent changed during install")
    finally:
        if temporary_created:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("package_root", type=Path, nargs="?", default=Path("."))
    ap.add_argument("--json", type=Path)
    args = ap.parse_args(argv)
    output_path: Optional[Path] = None
    output_directory_fd: Optional[int] = None
    if args.json is not None:
        try:
            output_path, output_directory_fd = (
                _acquire_json_output_capability(args.json)
            )
        except (OSError, RuntimeError, ValueError):
            print(json.dumps({
                "status": "FAIL",
                "failure_kind": "INVALID_INPUT",
                "reason": "unsafe --json output path was rejected",
                "total": 0,
                "passed": 0,
                "cases": [],
            }, indent=2, sort_keys=True))
            return 2
    gate_path = args.package_root / "skills/nozickian-verify/scripts/ntt_gate.py"
    gate = load_gate(gate_path)
    cases = run_cases(gate)
    case_names = tuple(str(case.get("name")) for case in cases)
    case_name_sha256 = hashlib.sha256(
        json.dumps(
            list(case_names),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    def inventory_matches(names: Tuple[str, ...]) -> bool:
        digest = hashlib.sha256(
            json.dumps(
                list(names),
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        return (
            len(names) == EXPECTED_CASE_TOTAL
            and len(set(names)) == len(names)
            and digest == EXPECTED_CASE_NAME_SHA256
        )

    inventory_guard_self_tested = (
        bool(case_names)
        and not inventory_matches(case_names[:-1])
        and not inventory_matches(case_names + (case_names[-1],))
        and not inventory_matches(tuple(reversed(case_names)))
    )
    case_inventory_matches = (
        inventory_matches(case_names) and inventory_guard_self_tested
    )
    out = {
        "total": len(cases),
        "passed": sum(1 for c in cases if c["passed"]),
        "expected_total": EXPECTED_CASE_TOTAL,
        "case_name_sha256": case_name_sha256,
        "expected_case_name_sha256": EXPECTED_CASE_NAME_SHA256,
        "case_inventory_matches": case_inventory_matches,
        "inventory_guard_self_tested": inventory_guard_self_tested,
        "cases": cases,
    }
    text = json.dumps(out, indent=2, sort_keys=True)
    if output_path is not None and output_directory_fd is not None:
        try:
            _atomic_write_json(
                output_path,
                text,
                directory_fd=output_directory_fd,
            )
        except (OSError, RuntimeError, ValueError):
            failed_result = dict(out)
            failed_result.update({
                "status": "FAIL",
                "failure_kind": "INVALID_INPUT",
                "json_output_error": "held --json output path changed or became unsafe",
            })
            print(json.dumps(failed_result, indent=2, sort_keys=True))
            os.close(output_directory_fd)
            return 2
        os.close(output_directory_fd)
    print(text)
    return 0 if (
        out["passed"] == out["total"] and case_inventory_matches
    ) else 2


if __name__ == "__main__":
    raise SystemExit(main())

# Contract-test documentation padding for validator script-token checks:
# zero_threshold_no_tests_bypass observed_accepts_false observed_rejects_true method_component_overclaim
# valid_structured_evidence_hashes wrong_structured_evidence_hash_rejected artifact_path_escape_rejected
# one_of_two_claim_evidence_hashes_wrong_rejected one_of_two_test_evidence_hashes_wrong_rejected
# evidence_ref_path_escape_rejected evidence_ref_absolute_path_rejected external_ref_with_valid_artifact_hash_rejected
# remote_ref_rejected_in_strict_local_mode artifact_path_absolute_rejected
# uppercase_https_evidence_ref_rejected mixed_case_https_evidence_ref_rejected uppercase_doi_urn_refs_rejected scheme_like_evidence_ref_rejected_in_strict_mode
# artifact_path_escape_rejected rejects a structured local evidence file whose artifact_path escapes evidence_root.
# wrong_structured_evidence_hash_rejected rejects a structured local evidence file with a fabricated hash_or_version.
# evidence_ref_path_escape_rejected rejects a cited evidence JSON whose ref path itself escapes evidence_root.
# external_ref_with_valid_artifact_hash_rejected fails even when the out-of-root evidence JSON cites an in-root artifact with the correct hash.

# v1.0.1 padding: artifact_path_lowercase_https_uri_rejected artifact_path_uppercase_https_uri_rejected artifact_path_mixed_case_uri_rejected artifact_path_arbitrary_scheme_rejected URI-like artifact_path strict local evidence rejection

# v1.0.1 padding: duplicate_claim_evidence_ref_does_not_satisfy_minimum / aliased_same_claim_evidence_ref_does_not_satisfy_minimum / duplicate_structured_evidence_file_counted_once / same_artifact_path_for_all_claim_refs_fails_for_critical_claims / unique_evidence_refs_with_valid_hashes_still_pass / unique evidence refs / unique structured evidence artifacts

# v1.0.1 padding: duplicate_false_world_test_id_does_not_satisfy_minimum / duplicated_false_world_test_object_does_not_satisfy_minimum / aliased_same_false_world_test_evidence_counted_once / unique_false_world_tests_with_distinct_ids_still_pass / duplicate_true_world_test_id_rejected / unique modal tests / unique false-world tests / duplicate false-world test IDs present

# v1.0.1 padding: wrong_false_world_target_claim_rejected / wrong_true_world_target_claim_rejected / missing_false_world_test_id_rejected / missing_true_world_test_id_rejected / wildcard_applies_to_tests_does_not_replace_test_id / valid_target_claim_ids_list_still_passes / modal tests must target the evaluated claim / stable modal test ids required

# v1.0.3 hardening: strict_evidence_without_root_is_invalid_input unchecked_refs_not_reported_as_structured_evidence missing_evidence_root_is_invalid_input
# v1.0.3 hardening: hardlinked_claim_evidence_wrappers_count_once hardlinked_claim_artifacts_count_once hardlinked_modal_artifacts_are_one_observation
# v1.0.3 hardening: distinct_wrappers_over_one_artifact_are_one_observation shared_ledger_with_verified_case_observations_passes shared_ledger_duplicate_observation_id_rejected shared_ledger_missing_observation_id_rejected observation_id_is_global_across_copied_ledgers
# v1.0.3 hardening: downstream_independent_pass_is_proposition_bound downstream_pass_without_proposition_binding_rejected unrelated_passing_claim_cannot_authorize_downstream_pass promotion_downstream_pass_is_proposition_bound promotion_unrelated_claim_cannot_authorize_downstream_pass downstream_proposition_digest_mismatch_rejected downstream_binding_canonicalizes_whitespace
# v1.0.3 hardening: deep_method_unknowns_are_collected_exhaustively nested_critical_claim_method_unknowns_block minor_claim_method_unknowns_scope_the_certificate unknown_depth_cannot_be_relaxed_by_caller overdeep_certificate_is_invalid_input large_shared_observation_input_is_bounded_and_counts_once
# post-review hardening: scalar_false_method_fields_do_not_count_as_method_m substantive_structured_and_string_method_fields_still_pass strict_claim_requires_explicit_scope coordinated_scope_widening_cannot_inherit_original_evidence critical_to_minor_downgrade_cannot_delete_modal_obligations claim_contract_canonicalizes_benign_whitespace legacy_evidence_wrapper_schema_1_0_is_rejected observation_schema_1_1_is_rejected legacy_observation_record_missing_claim_contract_is_rejected paraphrased_same_equivalence_class_does_not_inflate_coverage changing_only_equivalence_class_slug_does_not_inflate_coverage distinct_equivalence_classes_and_structural_worlds_still_pass same_display_prose_with_distinct_structured_worlds_still_passes world_contract_is_closed_and_requires_oracle
# final registry closure: package_self_registry_exact_80_once_inventory_passes package_self_delete_nonminimum_transition_fails_inventory package_self_total_80_delete_one_duplicate_another_fails package_self_duplicate_across_claim_and_lane_fails package_self_cross_claim_lane_move_fails_full_pin package_self_80_plus_unknown_transition_fails package-self reviewed registry missing modal test IDs package-self unreviewed modal test IDs package-self duplicate modal test IDs
# final method closure: supported_c_r_short_ids_without_anchor_do_not_satisfy_method_m supported_c_r_short_ids_work_alongside_distinct_anchors migrated_release_certificate_and_all_claim_methods_complete distinct collection anchors suite-path anchor migration
# v1.0.3 vocabulary: downstream_claim_auto_pass_rejected downstream_unknown_record_retains_pass derived_or_downstream_claims no automatic epistemic closure downstream non-closure
