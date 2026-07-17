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
  test objects, and Markdown report output never follows final or ancestor links.
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


def modal_case_sha256(
    test: Mapping[str, Any],
    claim_text: str,
    expected_kind: str,
    evidence_observed_result: Any = None,
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
        "claim_proposition": canonical_proposition(claim_text),
        "kind": str(test.get("kind") or expected_kind).strip().lower(),
        "test_id": str(test.get("id") or test.get("test_id") or "").strip(),
        "target_claim_ids": sorted({
            str(value).strip() for value in targets if str(value or "").strip()
        }),
        "variation_field": variation_field,
        "variation": canonical_proposition(variation),
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
        "outcome": str(
            test.get("outcome") or test.get("observed_outcome") or ""
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
    claim_text = BASE_CLAIM_TEXT
    return {
        "schema_version": "2.0",
        "artifact": {"name": "contract-test-artifact", "version": "2.0.0"},
        "method_manifest": copy.deepcopy(m),
        "scope_limitations": [],
        "claims": [{
            "id": "C-001",
            "text": claim_text,
            "proposition_sha256": f"sha256:{proposition_sha256(claim_text)}",
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


def all_evidence_refs(
    cert: Mapping[str, Any],
) -> Iterable[
    Tuple[
        str,
        Optional[str],
        Optional[str],
        str,
        Optional[Mapping[str, Any]],
        Optional[str],
    ]
]:
    for claim in cert.get("claims", []):
        cid = str(claim.get("id"))
        claim_text = str(claim.get("text") or "")
        for ref in claim.get("evidence_refs", []):
            yield str(ref), cid, None, claim_text, None, None
        for key in ("false_world_tests", "true_world_tests"):
            kind = "false_world" if key == "false_world_tests" else "true_world"
            for test in claim.get(key, []):
                tid_raw = test.get("id", test.get("test_id"))
                tid = str(tid_raw).strip() if tid_raw is not None else ""
                for ref in test.get("evidence_refs", []):
                    yield str(ref), cid, tid, claim_text, test, kind


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
    claim_text: str,
    modal_test: Optional[Mapping[str, Any]],
    test_kind: Optional[str],
    *,
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
        "evidence_schema_version": "1.0",
        "claim_id": cid,
        "claim_proposition_sha256": (
            f"sha256:{proposition_sha256(claim_text)}"
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
                claim_text,
                test_kind,
                data["observed_result"],
            )
        )
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
        "claim_proposition_sha256": (
            f"sha256:{proposition_sha256(BASE_CLAIM_TEXT)}"
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
    for ref, cid, tid, claim_text, modal_test, test_kind in all_evidence_refs(cert):
        if not _safe_evidence_ref(ref):
            continue
        _write_one_evidence(
            root,
            ref,
            cid,
            tid,
            claim_text,
            modal_test,
            test_kind,
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
                "modal_case_sha256": data["modal_case_sha256"],
                "result": "pass",
                "outcome": "rejected_false_claim",
                "observed_result": data["observed_result"],
            }
        if observation_mode == "wrong-modal-digest":
            observations["OBS-FW-002"]["modal_case_sha256"] = (
                "sha256:" + "0" * 64
            )
        elif observation_mode == "extra-record-field":
            observations["OBS-FW-001"]["source_suite"] = (
                "fabricated-suite-result.json"
            )
        elif observation_mode == "missing-record-field":
            observations["OBS-FW-001"].pop("observed_result")
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
                "modal_case_sha256": "not-a-digest",
                "result": "FAIL",
                "outcome": "invented_outcome",
                "observed_result": "x",
            }
        ledger = {
            "observation_schema_version": "1.1",
            "observations": observations,
        }
        if observation_mode == "extra-ledger-field":
            ledger["suite_summaries"] = {
                "fabricated": {"status": "PASS"}
            }
        elif observation_mode == "old-schema":
            ledger["observation_schema_version"] = "1.0"
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
                "unreferenced-extra-record-field",
                "unreferenced-invalid-record-semantics",
                "duplicate-record-key",
                "extra-ledger-field",
                "old-schema",
            }:
                data["observation_id"] = f"OBS-FW-{index:03d}"
            elif observation_mode == "wrong-modal-digest":
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
                "observation ledger schema is not 1.1",
            ),
            "extra-ledger-field": (
                "observation ledger fields are not exact for schema 1.1",
                "suite_summaries",
            ),
            "extra-record-field": (
                "fields are not exact for schema 1.1",
                "source_suite",
            ),
            "missing-record-field": (
                "fields are not exact for schema 1.1",
                "observed_result",
            ),
            "unreferenced-extra-record-field": (
                "observation OBS-UNREFERENCED fields are not exact for schema 1.1",
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
            "observation_schema_version": "1.1",
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
        "observation_schema_1_0_is_rejected",
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
    for test in (
        independent_claim["false_world_tests"]
        + independent_claim["true_world_tests"]
    ):
        test["target_claim"] = "C-DOWNSTREAM-001"
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
    add(
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
    add(
        "promotion_downstream_pass_is_proposition_bound",
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
    add_strict(
        "minor_claim_method_unknowns_scope_the_certificate",
        minor_claim_unknowns,
        {"PASS-SCOPED"},
    )

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
    out = {"total": len(cases), "passed": sum(1 for c in cases if c["passed"]), "cases": cases}
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

# v1.0.3 hardening: strict_evidence_without_root_is_invalid_input unchecked_refs_not_reported_as_structured_evidence missing_evidence_root_is_invalid_input
# v1.0.3 hardening: hardlinked_claim_evidence_wrappers_count_once hardlinked_claim_artifacts_count_once hardlinked_modal_artifacts_are_one_observation
# v1.0.3 hardening: distinct_wrappers_over_one_artifact_are_one_observation shared_ledger_with_verified_case_observations_passes shared_ledger_duplicate_observation_id_rejected shared_ledger_missing_observation_id_rejected observation_id_is_global_across_copied_ledgers
# v1.0.3 hardening: downstream_independent_pass_is_proposition_bound downstream_pass_without_proposition_binding_rejected unrelated_passing_claim_cannot_authorize_downstream_pass promotion_downstream_pass_is_proposition_bound promotion_unrelated_claim_cannot_authorize_downstream_pass downstream_proposition_digest_mismatch_rejected downstream_binding_canonicalizes_whitespace
# v1.0.3 hardening: deep_method_unknowns_are_collected_exhaustively nested_critical_claim_method_unknowns_block minor_claim_method_unknowns_scope_the_certificate unknown_depth_cannot_be_relaxed_by_caller overdeep_certificate_is_invalid_input large_shared_observation_input_is_bounded_and_counts_once
# v1.0.3 vocabulary: downstream_claim_auto_pass_rejected downstream_unknown_record_retains_pass derived_or_downstream_claims no automatic epistemic closure downstream non-closure
