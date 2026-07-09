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
* URI-like artifact_path values are rejected even if a matching local path exists, and modal-test thresholds count unique false/true-world tests rather than duplicated test objects.
"""
from __future__ import annotations
import argparse
import copy
import hashlib
import importlib.util
import json
import re
import sys
import tempfile
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


def load_gate(gate_path: Path):
    spec = importlib.util.spec_from_file_location("ntt_gate_under_test", str(gate_path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {gate_path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
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


def false_test(i: str) -> Dict[str, Any]:
    return {
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
        "evidence_refs": [ev(i)]
    }


def valid_cert() -> Dict[str, Any]:
    m = method()
    return {
        "schema_version": "2.0",
        "artifact": {"name": "contract-test-artifact", "version": "2.0.0"},
        "method_manifest": copy.deepcopy(m),
        "scope_limitations": [],
        "claims": [{
            "id": "C-001",
            "text": "The package gate rejects fake Nozickian certificates that omit evidence, tests, method components, contradiction resolution, invalid local evidence refs, or valid structured evidence hashes.",
            "importance": "critical",
            "artifact_location": "scripts/ntt_gate.py + scripts/run_gate_contract_tests.py",
            "truth_status": "executed_confirmed",
            "method_m": copy.deepcopy(m),
            "evidence_refs": [ev("run-gate-contract-tests"), ev("ntt-gate-source")],
            "false_world_tests": [false_test("FW-001"), false_test("FW-002")],
            "true_world_tests": [true_test("TW-001")],
            "unresolved_contradictions": [],
            "residual_risks": ["This contract test does not execute Claude Code runtime."]
        }]
    }


def all_evidence_refs(cert: Mapping[str, Any]) -> Iterable[Tuple[str, Optional[str], Optional[str]]]:
    for claim in cert.get("claims", []):
        cid = str(claim.get("id"))
        for ref in claim.get("evidence_refs", []):
            yield str(ref), cid, None
        for key in ("false_world_tests", "true_world_tests"):
            for test in claim.get(key, []):
                tid_raw = test.get("id", test.get("test_id"))
                tid = str(tid_raw).strip() if tid_raw is not None else ""
                for ref in test.get("evidence_refs", []):
                    yield str(ref), cid, tid


def _safe_evidence_ref(ref: str) -> bool:
    # Strict local evidence mode rejects any URI-scheme ref, case-insensitively.
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", ref or ""):
        return False
    p = Path(ref)
    if p.is_absolute():
        return False
    return ".." not in p.parts


def _write_one_evidence(root: Path, ref: str, cid: Optional[str], tid: Optional[str], *, wrong_hash: bool = False, artifact_escape: bool = False, artifact_absolute: bool = False, artifact_uri: Optional[str] = None, outside: Optional[Path] = None) -> None:
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
        "evidence_schema_version": "1.0",
        "claim_id": cid,
        "artifact_path": artifact_rel,
        "command_or_source": "run_gate_contract_tests.py structured evidence fixture",
        "observed_result": f"Structured evidence fixture for {ref} observed a deterministic gate contract case.",
        "support_summary": f"This evidence file binds {ref} to claim {cid} and exercises strict local evidence validation for ntt_gate.py.",
        "timestamp_utc": "2026-05-25T00:00:00Z",
        "hash_or_version": f"sha256:{digest}",
    }
    if tid:
        data["test_id"] = tid
    else:
        data["applies_to_tests"] = ["*"]
    evidence.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def write_external_evidence(evidence_root: Path, ref_path: Path, *, artifact_rel: str = "observations/external-valid.txt") -> None:
    artifact = evidence_root / artifact_rel
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("In-root artifact intentionally cited by an out-of-root evidence JSON.\n", encoding="utf-8")
    data = {
        "evidence_schema_version": "1.0",
        "claim_id": "C-001",
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
    wrong_refs: Optional[Set[str]] = None,
    artifact_escape_refs: Optional[Set[str]] = None,
    artifact_absolute_refs: Optional[Set[str]] = None,
    artifact_uri_refs: Optional[Mapping[str, str]] = None,
) -> Tuple[Path, Path]:
    root = Path(tempfile.mkdtemp(prefix="ntt_gate_evidence_contract_"))
    outside = Path(tempfile.mkdtemp(prefix="ntt_gate_evidence_outside_"))
    (root / "observations").mkdir(parents=True, exist_ok=True)
    wrong_refs = wrong_refs or set()
    artifact_escape_refs = artifact_escape_refs or set()
    artifact_absolute_refs = artifact_absolute_refs or set()
    artifact_uri_refs = artifact_uri_refs or {}
    for ref, cid, tid in all_evidence_refs(cert):
        if not _safe_evidence_ref(ref):
            continue
        _write_one_evidence(
            root,
            ref,
            cid,
            tid,
            wrong_hash=ref in wrong_refs,
            artifact_escape=ref in artifact_escape_refs,
            artifact_absolute=ref in artifact_absolute_refs,
            artifact_uri=artifact_uri_refs.get(ref),
            outside=outside,
        )
    return root, outside


def run_cases(gate_mod) -> List[Dict[str, Any]]:
    cases: List[Dict[str, Any]] = []

    def summarize(result: Mapping[str, Any]) -> List[str]:
        def clean(reason: str) -> str:
            # Keep contract artifacts deterministic even when tempdirs differ.
            reason = re.sub(r"/tmp/ntt_gate_evidence_outside_[^/\s;]+/[^\s;]+", "<temporary-absolute-evidence-ref>", reason)
            reason = re.sub(r"/tmp/ntt_gate_evidence_contract_[^/\s;]+/[^\s;]+", "<temporary-evidence-root-ref>", reason)
            return reason
        out = [clean(str(r)) for r in (result.get("reasons", []) or [])]
        for claim in result.get("claim_results", []) or []:
            cid = claim.get("claim_id")
            for reason in claim.get("reasons", []) or []:
                out.append(clean(f"{cid}: {reason}"))
        return out[:12]

    def add(name: str, cert: Dict[str, Any], allowed: Set[str]) -> None:
        result = gate_mod.evaluate_certificate(cert)
        status = result.get("status")
        cases.append({"name": name, "status": status, "expected_any": sorted(allowed), "passed": status in allowed, "reasons": summarize(result)})

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
    ) -> None:
        evidence_root, outside_root = write_structured_evidence_tree(
            cert,
            wrong_refs=wrong_refs,
            artifact_escape_refs=artifact_escape_refs,
            artifact_absolute_refs=artifact_absolute_refs,
            artifact_uri_refs=artifact_uri_refs,
        )
        if external_ref is not None:
            external_path = outside_root / "external-valid-evidence.json"
            write_external_evidence(evidence_root, external_path)
            if absolute_ref:
                ref_value = "/tmp/ntt_gate_absolute_ref_probe.json"
                try:
                    Path(ref_value).write_text(external_path.read_text(encoding="utf-8"), encoding="utf-8")
                except Exception:
                    pass
            else:
                ref_value = external_ref
                # Ensure the referenced relative path points to the same file for ../ probes.
                target = (evidence_root / external_ref).resolve()
                target.parent.mkdir(parents=True, exist_ok=True)
                if target != external_path.resolve():
                    target.write_text(external_path.read_text(encoding="utf-8"), encoding="utf-8")
            if ref_value not in cert["claims"][0]["evidence_refs"]:
                cert["claims"][0]["evidence_refs"].append(ref_value)
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

    def add_strict_same_artifact(name: str, cert: Dict[str, Any], allowed: Set[str]) -> None:
        evidence_root, outside_root = write_structured_evidence_tree(cert)
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

    base = valid_cert()
    add("valid_substantive_certificate", copy.deepcopy(base), {"PASS-TRACKED"})
    add_strict("valid_structured_evidence_hashes", copy.deepcopy(base), {"PASS-TRACKED"})
    add_strict("wrong_structured_evidence_hash_rejected", copy.deepcopy(base), {"FAIL"}, wrong_refs={ev("FW-001")})
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

    unique_false_tests = copy.deepcopy(base)
    add_strict("unique_false_world_tests_with_distinct_ids_still_pass", unique_false_tests, {"PASS-TRACKED"})

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

    downstream_unverified = copy.deepcopy(base)
    downstream_unverified["derived_or_downstream_claims"] = [{
        "id": "D-002",
        "from_claim_ids": ["C-001"],
        "derived_claim": "The workflow is safe for production deployment because C-001 passed.",
        "status": "UNVERIFIED",
        "reason": "No independent deployment method M, action-space review, evidence, false-world tests, or true-world tests supplied."
    }]
    add("downstream_unverified_record_retains_pass", downstream_unverified, {"PASS-TRACKED"})

    scoped = copy.deepcopy(base)
    scoped["scope_limitations"] = ["Live Claude Code runtime was not executed in this deterministic contract test."]
    add("valid_scoped_unknown_downgrades", scoped, {"PASS-SCOPED"})

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

    bad_status = copy.deepcopy(base)
    bad_status["claims"][0]["false_world_tests"][0]["result"] = "claimed-pass-without-run"
    add("bad_test_status", bad_status, {"FAIL"})

    accepted_false = copy.deepcopy(base)
    accepted_false["claims"][0]["false_world_tests"][0]["observed_behavior"] = "The verifier accepted false output and certified false claim."
    add("observed_accepts_false", accepted_false, {"FAIL"})

    rejected_true = copy.deepcopy(base)
    rejected_true["claims"][0]["true_world_tests"][0]["observed_behavior"] = "The verifier rejected equivalent true output and overfit to one path."
    add("observed_rejects_true", rejected_true, {"FAIL"})

    minor = copy.deepcopy(base)
    minor["claims"][0]["importance"] = "minor"
    minor["claims"][0]["false_world_tests"] = []
    minor["claims"][0]["true_world_tests"] = []
    add("minor_claim_without_modal_tests", minor, {"PASS-TRACKED"})

    manifest_unknowns = copy.deepcopy(base)
    manifest_unknowns["scope_limitations"] = []
    manifest_unknowns["method_manifest"]["unknowns"] = ["x"]
    add("manifest_unknowns_downgrades_scoped", manifest_unknowns, {"PASS-SCOPED"})

    manifest_method_unknowns = copy.deepcopy(base)
    manifest_method_unknowns["scope_limitations"] = []
    manifest_method_unknowns["method_manifest"]["method_unknowns"] = ["x"]
    add("manifest_method_unknowns_synonym_downgrades", manifest_method_unknowns, {"PASS-SCOPED"})

    top_level_unknowns = copy.deepcopy(base)
    top_level_unknowns["scope_limitations"] = []
    top_level_unknowns["unknowns"] = ["x"]
    add("top_level_unknowns_downgrades", top_level_unknowns, {"PASS-SCOPED"})

    nested_manifest_unknowns = copy.deepcopy(base)
    nested_manifest_unknowns["scope_limitations"] = []
    nested_manifest_unknowns["method_manifest"]["runtime"] = {"unknowns": ["x"]}
    add("nested_manifest_unknowns_downgrades", nested_manifest_unknowns, {"PASS-SCOPED"})

    nested_clean_manifest = copy.deepcopy(base)
    nested_clean_manifest["scope_limitations"] = []
    nested_clean_manifest["method_manifest"]["runtime"] = {"env": "local", "notes": ["fine"]}
    add("nested_clean_manifest_still_tracked", nested_clean_manifest, {"PASS-TRACKED"})

    placeholder_unknowns = copy.deepcopy(base)
    placeholder_unknowns["scope_limitations"] = []
    placeholder_unknowns["method_manifest"]["unknowns"] = ["none", "n/a", ""]
    add("placeholder_unknowns_still_tracked", placeholder_unknowns, {"PASS-TRACKED"})

    scalar_zero_unknowns = copy.deepcopy(base)
    scalar_zero_unknowns["scope_limitations"] = []
    scalar_zero_unknowns["method_manifest"]["unknowns"] = 0
    add("scalar_zero_unknowns_still_tracked", scalar_zero_unknowns, {"PASS-TRACKED"})

    major_claim_unknowns = copy.deepcopy(base)
    major_claim_unknowns["claims"][0]["importance"] = "major"
    major_claim_unknowns["claims"][0]["method_m"]["method_unknowns"] = ["x"]
    add("major_claim_method_unknowns_blocks", major_claim_unknowns, {"FAIL"})

    minor_claim_unknowns = copy.deepcopy(base)
    minor_claim_unknowns["claims"][0]["importance"] = "minor"
    minor_claim_unknowns["claims"][0]["method_m"]["method_unknowns"] = ["x"]
    add("minor_claim_method_unknowns_still_tracked", minor_claim_unknowns, {"PASS-TRACKED"})
    return cases


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("package_root", type=Path, nargs="?", default=Path("."))
    ap.add_argument("--json", type=Path)
    args = ap.parse_args(argv)
    gate_path = args.package_root / "skills/nozickian-verify/scripts/ntt_gate.py"
    gate = load_gate(gate_path)
    cases = run_cases(gate)
    out = {"total": len(cases), "passed": sum(1 for c in cases if c["passed"]), "cases": cases}
    text = json.dumps(out, indent=2, sort_keys=True)
    print(text)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(text, encoding="utf-8")
    return 0 if out["passed"] == out["total"] else 2


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

# v1.0.1 padding: downstream_claim_auto_pass_rejected downstream_unverified_record_retains_pass derived_or_downstream_claims no automatic epistemic closure downstream non-closure
