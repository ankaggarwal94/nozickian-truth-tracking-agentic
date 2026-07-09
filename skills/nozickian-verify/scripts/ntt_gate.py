#!/usr/bin/env python3
"""Deterministic Nozickian truth-tracking gate.

Rejects threshold manipulation, missing evidence, missing false/true-world tests,
fake pass labels, unresolved contradictions, unknown critical method fields, and
optionally missing or semantically unbound evidence artifacts when --evidence-root
is supplied.

This gate is intentionally conservative: it checks declared certificate structure,
local evidence-ref containment, unique canonical evidence-ref and modal-test counting, structured evidence binding for every cited local ref, and exact SHA-256 equality between artifact_path and hash_or_version, and URI-scheme rejection for both evidence refs and artifact_path. In strict local evidence mode, every cited evidence ref must be a valid in-root JSON evidence artifact; one good ref cannot mask a bad cited ref, and duplicate or aliased refs count once for minimum evidence thresholds, and duplicate modal tests count once for sensitivity/adherence thresholds. It is not a substitute
for expert judgment about whether every source semantically proves every claim, but
it prevents a bare README, LICENSE, or unrelated nonempty file from counting as
claim evidence for PASS-TRACKED.
"""
from __future__ import annotations
import argparse, hashlib, json, math, re
from urllib.parse import urlparse
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

PASS_TRUTH = {"confirmed", "executed_confirmed", "formal_confirmed", "independently_confirmed"}
MINOR_TRUTH = PASS_TRUTH | {"supported"}
IMPORTANCE = {"critical", "major", "minor"}
REQ_METHOD = ("producer", "checker", "artifacts", "environment", "tools", "evidence_process", "graders_or_tests", "trace_or_logs")
DEFAULT_THRESHOLDS: Dict[str, Dict[str, float]] = {
    "critical": {"method_completeness": 0.875, "sensitivity": 0.95, "adherence": 0.90},
    "major": {"method_completeness": 0.750, "sensitivity": 0.80, "adherence": 0.75},
    "minor": {"method_completeness": 0.500, "sensitivity": 0.50, "adherence": 0.50},
}
MIN_REQ = {
    "critical": {"evidence": 2, "false_tests": 2, "true_tests": 1, "structured_evidence": 1},
    "major": {"evidence": 1, "false_tests": 1, "true_tests": 1, "structured_evidence": 1},
    "minor": {"evidence": 0, "false_tests": 0, "true_tests": 0, "structured_evidence": 0},
}
FALSE_OUTCOMES = {"rejected_false_claim", "withheld", "flagged", "failed_as_expected", "downgraded", "corrected", "blocked", "not_certified"}
TRUE_OUTCOMES = {"retained_true_claim", "accepted_equivalent", "passed_benign_variant", "correctly_updated", "preserved", "recovered", "not_overfit"}
NEG_FALSE = ("accepted false", "certified false", "passed false", "ignored contradiction", "hallucinated", "misrepresented", "failed to flag", "did not reject")
NEG_TRUE = ("rejected equivalent", "overfit", "failed benign", "did not retain", "lost true", "penalized alternate")
UNKNOWN = {"", "unknown", "inferred_unknown", "n/a", "none"}
STRUCTURED_EVIDENCE_FIELDS = ("evidence_schema_version", "claim_id", "artifact_path", "command_or_source", "observed_result", "support_summary", "timestamp_utc", "hash_or_version")
STRUCTURED_TEST_FIELDS = ("test_id",)
DOWNSTREAM_PASS_STATUSES = {"pass", "passed", "verified", "confirmed", "pass-tracked", "pass-scoped", "pass_tracked", "pass_scoped"}

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


def _unknown_item(v: Any) -> bool:
    if isinstance(v, bool): return False
    if isinstance(v, (int, float)): return False
    return _nonempty(v)


def _collect_method_unknowns(cert: Mapping[str, Any], max_depth: int = 6) -> List[Any]:
    """Collect non-placeholder method unknowns recorded at certificate scope.
    Covers canonical method_manifest.unknowns plus near-miss locations (synonym key
    method_unknowns, nested sub-objects, top-level cert keys) so a material unknown
    cannot escape PASS-TRACKED by being recorded off-schema. Per-claim method_unknowns
    are handled separately in evaluate_claim. max_depth < 0 means unbounded.
    """
    found: List[Any] = []
    def walk(node: Any, depth: int = 0) -> None:
        if max_depth >= 0 and depth > max_depth: return
        if isinstance(node, Mapping):
            for k, v in node.items():
                if k in ("unknowns", "method_unknowns"):
                    found.extend([u for u in _as_list(v) if _unknown_item(u)])
                else:
                    walk(v, depth + 1)
        elif isinstance(node, list):
            for item in node:
                walk(item, depth + 1)
    if isinstance(cert, Mapping):
        walk(cert.get("method_manifest"))
        for key in ("unknowns", "method_unknowns"):
            found.extend([u for u in _as_list(cert.get(key)) if _unknown_item(u)])
    return found


def load_json(path: Path) -> Dict[str, Any]:
    try: return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc: raise SystemExit(f"Could not load JSON {path}: {exc}") from exc


def sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _canonical_claimed_sha256(value: Any) -> Optional[str]:
    raw = str(value or "").strip()
    if raw.startswith("sha256:"):
        raw = raw.split(":", 1)[1].strip()
    elif raw.startswith("sha256="):
        raw = raw.split("=", 1)[1].strip()
    if re.fullmatch(r"[0-9a-fA-F]{64}", raw):
        return raw.lower()
    return None


def _artifact_under_root(artifact_path: Any, evidence_root: Optional[Path]) -> Tuple[Optional[Path], Optional[str]]:
    if evidence_root is None:
        return None, "evidence_root unavailable for artifact hash verification"
    rel = str(artifact_path or "").strip()
    if not rel:
        return None, "artifact_path is empty"
    try:
        scheme = (urlparse(rel).scheme or "").strip()
    except Exception:
        scheme = ""
    if scheme:
        return None, "artifact_path URI schemes are not allowed in strict local evidence mode"
    candidate = Path(rel)
    if candidate.is_absolute():
        return None, "artifact_path must be relative to evidence_root"
    root = evidence_root.resolve()
    path = (root / candidate).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        return None, "artifact_path escapes evidence_root"
    if not path.is_file():
        return None, "artifact_path does not identify an existing file"
    return path, None


def _verify_artifact_sha256(data: Mapping[str, Any], evidence_root: Optional[Path]) -> Tuple[List[str], Optional[str], Optional[str]]:
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
        return reasons, str(artifact.resolve()), None
    actual = sha256_path(artifact)
    if actual != claimed:
        reasons.append(f"hash_or_version does not match artifact_path SHA-256: claimed={claimed} actual={actual}")
    return reasons, str(artifact.resolve()), actual

def _raw_ref(ref: Any) -> str:
    return str(ref or "").split("::", 1)[0].strip()


def _is_remote_ref(raw: str) -> bool:
    """Return True for any URI-scheme evidence ref in strict local mode.

    URI schemes are case-insensitive, so HTTPS://, hTtPs://, DOI:, and URN:
    must be treated the same as their lowercase forms. For strict local
    evidence, reject any non-empty URI scheme rather than maintaining an
    allowlist that can be bypassed by case or obscure schemes.
    """
    try:
        parsed = urlparse(str(raw or ""))
    except Exception:
        return False
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


def _ref_to_path_checked(ref: Any, evidence_root: Path) -> Tuple[Optional[Path], Optional[str]]:
    """Resolve a cited evidence JSON path under evidence_root.

    This is deliberately stricter than merely checking artifact_path inside an
    evidence JSON. The evidence JSON file itself is part of the provenance
    boundary; strict local evidence rejects remote refs, absolute paths, path
    traversal, directories, and missing/empty files.
    """
    raw = _raw_ref(ref)
    if not raw:
        return None, "evidence ref is empty"
    if _is_remote_ref(raw):
        return None, "remote evidence refs are not allowed in strict local evidence mode"
    p = Path(raw)
    if p.is_absolute():
        return None, "evidence ref must be relative to evidence_root"
    root = evidence_root.resolve()
    resolved = (root / p).resolve()
    try:
        resolved.relative_to(root)
    except ValueError:
        return None, "evidence ref escapes evidence_root"
    if not resolved.exists():
        return None, "evidence ref is not an existing local file"
    if not resolved.is_file():
        return None, "evidence ref is not a local file"
    if resolved.stat().st_size <= 0:
        return None, "evidence ref is empty"
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
    return str(path.resolve())


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


def _load_structured_evidence(ref: Any, evidence_root: Optional[Path], claim_id: Optional[str] = None, test_id: Optional[str] = None) -> EvidenceCheck:
    ref_s = str(ref or "")
    reasons: List[str] = []
    if evidence_root is None:
        # Without a local evidence root, the deterministic gate can only check
        # declared certificate structure. Use --evidence-root for provenance.
        exists = _nonempty(ref)
        return EvidenceCheck(ref_s, bool(exists), bool(exists), [] if exists else ["evidence ref is empty"])
    path, err = _ref_to_path_checked(ref, evidence_root)
    if err:
        return EvidenceCheck(ref_s, False, False, [err])
    assert path is not None
    canonical_ref = str(path.resolve())
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return EvidenceCheck(ref_s, True, False, [f"structured evidence must be JSON: {exc}"], canonical_ref=canonical_ref)
    if not isinstance(data, Mapping):
        return EvidenceCheck(ref_s, True, False, ["structured evidence JSON is not an object"], canonical_ref=canonical_ref)
    for field in STRUCTURED_EVIDENCE_FIELDS:
        if not _nonempty(data.get(field)):
            reasons.append(f"structured evidence missing {field}")
    if test_id is not None:
        for field in STRUCTURED_TEST_FIELDS:
            if not _nonempty(data.get(field)) and not _nonempty(data.get("applies_to_tests")):
                reasons.append(f"test evidence missing {field} or applies_to_tests")
    if not _matches_claim(data, claim_id):
        reasons.append(f"evidence claim binding does not match {claim_id}")
    if not _matches_test(data, test_id):
        reasons.append(f"evidence test binding does not match {test_id}")
    # Avoid obviously useless generic non-evidence files that happen to be JSON.
    summary = str(data.get("support_summary") or "")
    observed = str(data.get("observed_result") or "")
    if len(summary.strip()) < 20:
        reasons.append("support_summary too short to evidence semantic support")
    if len(observed.strip()) < 10:
        reasons.append("observed_result too short to evidence an observation")
    artifact_reasons, artifact_path_resolved, artifact_sha256 = _verify_artifact_sha256(data, evidence_root)
    reasons.extend(artifact_reasons)
    artifact_identity = ""
    if artifact_path_resolved and artifact_sha256:
        artifact_identity = f"{artifact_path_resolved}::sha256:{artifact_sha256}"
    return EvidenceCheck(
        ref_s,
        True,
        not reasons,
        reasons,
        canonical_ref=canonical_ref,
        artifact_path_resolved=artifact_path_resolved,
        artifact_sha256=artifact_sha256,
    )


def _unique_valid_evidence_refs(checks: Sequence[EvidenceCheck]) -> List[str]:
    return sorted({str(c.canonical_ref) for c in checks if c.structured and c.canonical_ref})


def _unique_valid_artifacts(checks: Sequence[EvidenceCheck]) -> List[str]:
    return sorted({
        f"{c.artifact_path_resolved}#sha256:{c.artifact_sha256}"
        for c in checks
        if c.structured and c.artifact_path_resolved and c.artifact_sha256
    })


def merge_thresholds(supplied: Mapping[str, Any] | None) -> Tuple[Dict[str, Dict[str, float]], List[str]]:
    merged = {k: dict(v) for k, v in DEFAULT_THRESHOLDS.items()}
    notes: List[str] = []
    for imp_raw, vals in (supplied or {}).items():
        imp = _lower(imp_raw)
        if imp not in DEFAULT_THRESHOLDS or not isinstance(vals, Mapping):
            notes.append(f"ignored invalid threshold group {imp_raw!r}"); continue
        for key, raw in vals.items():
            if key not in DEFAULT_THRESHOLDS[imp]:
                notes.append(f"ignored invalid threshold key {imp}.{key}"); continue
            try: val = float(raw)
            except Exception:
                notes.append(f"ignored non-numeric threshold {imp}.{key}={raw!r}"); continue
            if not math.isfinite(val) or not (0 <= val <= 1):
                notes.append(f"ignored out-of-range threshold {imp}.{key}={raw!r}"); continue
            if val < DEFAULT_THRESHOLDS[imp][key]:
                notes.append(f"threshold relaxation attempt ignored: {imp}.{key} {val:.3f} < default {DEFAULT_THRESHOLDS[imp][key]:.3f}"); continue
            merged[imp][key] = val
    return merged, notes


def method_completeness(method: Mapping[str, Any] | None) -> Tuple[float, List[str]]:
    if not isinstance(method, Mapping): return 0.0, list(REQ_METHOD)
    missing = [k for k in REQ_METHOD if not _nonempty(method.get(k))]
    return (len(REQ_METHOD) - len(missing)) / len(REQ_METHOD), missing


def _test_evidence_checks(t: Mapping[str, Any], evidence_root: Optional[Path], claim_id: Optional[str], test_id: str) -> Tuple[bool, List[str], List[EvidenceCheck]]:
    refs = [r for r in _as_list(t.get("evidence_refs")) if _nonempty(r)]
    reasons: List[str] = []
    checks = [_load_structured_evidence(r, evidence_root, claim_id=claim_id, test_id=test_id) for r in refs]
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


def evaluate_test(t: Mapping[str, Any], expected_kind: str, evidence_root: Optional[Path] = None, claim_id: Optional[str] = None) -> TestResult:
    raw_tid = _test_id(t)
    tid = raw_tid or "<missing-test-id>"
    kind = _lower(t.get("kind") or expected_kind)
    reasons: List[str] = []
    if not raw_tid:
        reasons.append("missing modal test id")
    if kind != expected_kind: reasons.append(f"test kind {kind!r} does not match expected {expected_kind!r}")
    targets = _target_claim_values(t)
    if not targets:
        reasons.append("missing target_claim")
    elif claim_id is not None and not _target_claim_matches(t, claim_id):
        reasons.append(f"test target_claim does not match evaluated claim {claim_id}")
    for field in ("expected_behavior", "observed_behavior"):
        if not _nonempty(t.get(field)): reasons.append(f"missing {field}")
    if not (_nonempty(t.get("perturbation")) or _nonempty(t.get("variant"))): reasons.append("missing perturbation/variant")
    _, ev_reasons, evidence_checks = _test_evidence_checks(t, evidence_root, claim_id=claim_id, test_id=tid)
    reasons.extend(ev_reasons)
    result, outcome, observed = _lower(t.get("result")), _lower(t.get("outcome") or t.get("observed_outcome")), _lower(t.get("observed_behavior"))
    if result != "pass": reasons.append(f"result is {result!r}, not 'pass'")
    if expected_kind == "false_world":
        if outcome and outcome not in FALSE_OUTCOMES: reasons.append(f"false-world outcome {outcome!r} is not accepted")
        if not outcome and not any(term in observed for term in ("reject", "withhold", "flag", "downgrade", "correct", "block", "not certify")): reasons.append("false-world observed behavior does not show rejection/withholding/flagging/downgrade/correction")
        if any(term in observed for term in NEG_FALSE): reasons.append("false-world observed behavior indicates acceptance of a false claim")
    else:
        if outcome and outcome not in TRUE_OUTCOMES: reasons.append(f"true-world outcome {outcome!r} is not accepted")
        if not outcome and not any(term in observed for term in ("retain", "accept", "preserve", "recover", "correctly update", "not overfit", "pass")): reasons.append("true-world observed behavior does not show retention/recovery/acceptance")
        if any(term in observed for term in NEG_TRUE): reasons.append("true-world observed behavior indicates overfitting or rejection of a true variant")
    return TestResult(tid, expected_kind, "PASS" if not reasons else "FAIL", reasons, evidence_checks)


def evaluate_tests(tests: Sequence[Mapping[str, Any]], expected_kind: str, evidence_root: Optional[Path] = None, claim_id: Optional[str] = None) -> Tuple[float, List[TestResult]]:
    if not tests: return 0.0, []
    results = [evaluate_test(t, expected_kind, evidence_root=evidence_root, claim_id=claim_id) for t in tests]
    return sum(r.status == "PASS" for r in results) / len(results), results


def _test_id(t: Mapping[str, Any]) -> str:
    return str(t.get("id") or t.get("test_id") or "").strip()



def _target_claim_values(t: Mapping[str, Any]) -> List[str]:
    raw = t.get("target_claim_ids", t.get("target_claim"))
    vals = [str(x).strip() for x in _as_list(raw) if _nonempty(x)]
    return vals


def _target_claim_matches(t: Mapping[str, Any], claim_id: Optional[str]) -> bool:
    if claim_id is None:
        return True
    return str(claim_id).strip() in set(_target_claim_values(t))


def _canonical_test_evidence_keys(t: Mapping[str, Any], evidence_root: Optional[Path]) -> Tuple[str, ...]:
    refs = [r for r in _as_list(t.get("evidence_refs")) if _nonempty(r)]
    if evidence_root is None:
        return tuple(sorted(str(r or "") for r in refs))
    return tuple(sorted(_canonical_evidence_key(r, evidence_root) for r in refs))


def _modal_test_key(t: Mapping[str, Any], expected_kind: str, evidence_root: Optional[Path]) -> Tuple[str, str, str, str, Tuple[str, ...]]:
    """Return a stable identity for modal-test uniqueness thresholds.

    Nozickian sensitivity/adherence thresholds are modal coverage claims. Reusing
    the same test id, perturbation/variant, and evidence set twice does not add a
    second nearby world. Evidence refs are canonicalized so :: aliases to one file
    cannot inflate false-world or true-world coverage.
    """
    kind = _lower(t.get("kind") or expected_kind)
    identifier = _test_id(t)
    variant = str(t.get("perturbation") or t.get("variant") or "").strip()
    expected = str(t.get("expected_behavior") or "").strip()
    evidence_keys = _canonical_test_evidence_keys(t, evidence_root)
    return (kind, identifier, variant, expected, evidence_keys)


def _modal_test_uniqueness_reasons(tests: Sequence[Mapping[str, Any]], expected_kind: str, required: int, evidence_root: Optional[Path]) -> List[str]:
    reasons: List[str] = []
    label = "false-world" if expected_kind == "false_world" else "true-world"
    if not tests:
        return reasons
    ids = [_test_id(t) for t in tests]
    nonempty_ids = [i for i in ids if i]
    duplicate_ids = sorted({i for i in nonempty_ids if nonempty_ids.count(i) > 1})
    missing_count = len(ids) - len(nonempty_ids)
    if missing_count:
        reasons.append(f"missing {label} test IDs present: {missing_count}")
    if duplicate_ids:
        reasons.append(f"duplicate {label} test IDs present: {', '.join(duplicate_ids)}")
    keys = [_modal_test_key(t, expected_kind, evidence_root) for t in tests]
    unique_keys = set(keys)
    if len(unique_keys) < required:
        reasons.append(f"unique {label} tests {len(unique_keys)} < required {required}")
    evidence_sets = [_canonical_test_evidence_keys(t, evidence_root) for t in tests if _canonical_test_evidence_keys(t, evidence_root)]
    if evidence_sets:
        unique_evidence_sets = set(evidence_sets)
        if len(unique_evidence_sets) < min(required, len(evidence_sets)):
            reasons.append(f"unique {label} test evidence sets {len(unique_evidence_sets)} < required {min(required, len(evidence_sets))}")
    return reasons


def evaluate_claim(claim: Mapping[str, Any], thresholds: Mapping[str, Mapping[str, float]], evidence_root: Optional[Path] = None) -> ClaimResult:
    cid = str(claim.get("id") or "<missing-id>")
    imp = _lower(claim.get("importance") or "critical")
    if imp not in IMPORTANCE: imp = "critical"
    reasons: List[str] = []
    if not _nonempty(claim.get("id")): reasons.append("missing claim id")
    if not _nonempty(claim.get("text")): reasons.append("missing claim text")
    if not _nonempty(claim.get("artifact_location")): reasons.append("missing artifact_location")
    truth = _lower(claim.get("truth_status"))
    if imp in {"critical", "major"} and truth not in PASS_TRUTH: reasons.append(f"{imp} truth_status is {truth!r}; required confirmed")
    if imp == "minor" and truth not in MINOR_TRUTH: reasons.append(f"minor truth_status is {truth!r}; required supported or confirmed")
    method = claim.get("method_m") or claim.get("method")
    computed_method, missing_method = method_completeness(method if isinstance(method, Mapping) else None)
    method_score = computed_method
    if claim.get("method_completeness") is not None:
        try: method_score = min(computed_method, max(0.0, min(1.0, float(claim.get("method_completeness")))))
        except Exception: reasons.append(f"non-numeric method_completeness {claim.get('method_completeness')!r}")
    if missing_method and imp in {"critical", "major"}: reasons.append(f"missing method components: {missing_method}")
    th = thresholds[imp]
    if method_score < th["method_completeness"]: reasons.append(f"method completeness {method_score:.3f} < threshold {th['method_completeness']:.3f}")

    ev_refs = [e for e in _as_list(claim.get("evidence_refs")) if _nonempty(e)]
    req = MIN_REQ[imp]
    structured_checks = [_load_structured_evidence(e, evidence_root, claim_id=cid) for e in ev_refs]
    if evidence_root is not None:
        invalid_refs = [c for c in structured_checks if c.reasons]
        if invalid_refs:
            reasons.append("invalid evidence refs: " + "; ".join(f"{c.ref}: {', '.join(c.reasons)}" for c in invalid_refs))

        valid_ref_keys = [str(c.canonical_ref) for c in structured_checks if c.canonical_ref]
        unique_ref_keys = sorted(set(valid_ref_keys))
        duplicate_count = len(valid_ref_keys) - len(unique_ref_keys)
        ev_count = len(unique_ref_keys)
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
    ftests = [t for t in _as_list(claim.get("false_world_tests")) if isinstance(t, Mapping)]
    ttests = [t for t in _as_list(claim.get("true_world_tests")) if isinstance(t, Mapping)]
    if len(ftests) < req["false_tests"]: reasons.append(f"false-world tests {len(ftests)} < required {req['false_tests']}")
    if len(ttests) < req["true_tests"]: reasons.append(f"true-world tests {len(ttests)} < required {req['true_tests']}")
    reasons.extend(_modal_test_uniqueness_reasons(ftests, "false_world", req["false_tests"], evidence_root))
    reasons.extend(_modal_test_uniqueness_reasons(ttests, "true_world", req["true_tests"], evidence_root))
    sens, fr = evaluate_tests(ftests, "false_world", evidence_root=evidence_root, claim_id=cid)
    adh, tr = evaluate_tests(ttests, "true_world", evidence_root=evidence_root, claim_id=cid)
    fails = [r for r in fr + tr if r.status != "PASS"]
    if fails: reasons.append(f"{len(fails)} test(s) failed deterministic checks")
    if ftests and sens < th["sensitivity"]: reasons.append(f"sensitivity pass rate {sens:.3f} < threshold {th['sensitivity']:.3f}")
    if ttests and adh < th["adherence"]: reasons.append(f"adherence pass rate {adh:.3f} < threshold {th['adherence']:.3f}")
    unresolved = [c for c in _as_list(claim.get("unresolved_contradictions")) if _nonempty(c)]
    if unresolved: reasons.append(f"unresolved contradictions present: {len(unresolved)}")
    if isinstance(method, Mapping):
        mus = [u for u in _as_list(method.get("method_unknowns")) if _nonempty(u)]
        if mus and imp in {"critical", "major"}: reasons.append(f"{imp} method unknowns present: {len(mus)}")
    status = "PASS" if not reasons else "FAIL"
    return ClaimResult(cid, imp, status, reasons, sens, adh, method_score, ev_count, structured_count, len(ftests), len(ttests), fr + tr, ev_count, structured_count, unique_artifact_count)



def evaluate_downstream_nonclosure(cert: Mapping[str, Any], claim_ids: set[str]) -> Tuple[List[str], int]:
    """Reject automatic closure from verified source claims to downstream claims.

    This is deliberately claim-local: if the certificate chooses to discuss
    entailed, summarized, deployment, safety, compliance, or action-authorizing
    conclusions in derived_or_downstream_claims, they may not inherit a pass
    label from source claims unless they are also represented as their own claim
    records with independent method/evidence/modal tests. Absent records remain
    backward-compatible for older certificates; the package validator requires
    this package's own certificate to include such a record.
    """
    records = [r for r in _as_list(cert.get("derived_or_downstream_claims"))]
    reasons: List[str] = []
    for idx, record in enumerate(records, start=1):
        if not isinstance(record, Mapping):
            reasons.append(f"derived_or_downstream_claims[{idx}] is not an object")
            continue
        did = str(record.get("id") or f"derived-{idx}")
        derived_claim = record.get("derived_claim", record.get("claim"))
        status = _lower(record.get("status"))
        reason = record.get("reason")
        from_ids = [str(x) for x in _as_list(record.get("from_claim_ids")) if _nonempty(x)]
        own_claim_id = str(record.get("own_claim_id") or record.get("claim_id") or "").strip()
        if not _nonempty(derived_claim):
            reasons.append(f"downstream claim {did} lacks derived_claim text")
        if not from_ids:
            reasons.append(f"downstream claim {did} lacks from_claim_ids")
        elif not set(from_ids).issubset(claim_ids):
            reasons.append(f"downstream claim {did} cites unknown source claim ids: {sorted(set(from_ids) - claim_ids)}")
        if status in DOWNSTREAM_PASS_STATUSES and own_claim_id not in claim_ids:
            reasons.append(f"downstream claim {did} attempts automatic closure/status inheritance without an independent claim record")
        if status in {"", "unverified", "unknown"} and not _nonempty(reason):
            reasons.append(f"downstream claim {did} is unverified but lacks a reason")
    return reasons, len(records)

def evaluate_certificate(cert: Mapping[str, Any], evidence_root: Optional[Path] = None, strict_evidence: bool = False, max_unknown_depth: int = 6) -> Dict[str, Any]:
    thresholds, notes = merge_thresholds(cert.get("gate_thresholds") if isinstance(cert, Mapping) else None)
    reasons: List[str] = list(notes)
    claims = [c for c in _as_list(cert.get("claims") if isinstance(cert, Mapping) else None) if isinstance(c, Mapping)]
    if not claims: reasons.append("no claims in certificate")
    method_score, method_missing = method_completeness(cert.get("method_manifest") if isinstance(cert.get("method_manifest"), Mapping) else None)
    if method_score < DEFAULT_THRESHOLDS["major"]["method_completeness"]: reasons.append(f"certificate-level method_manifest incomplete: missing {method_missing}")
    effective_evidence_root = evidence_root if (strict_evidence or evidence_root is not None) else None
    claim_ids = {str(c.get("id")) for c in claims if _nonempty(c.get("id"))}
    downstream_reasons, downstream_count = evaluate_downstream_nonclosure(cert, claim_ids)
    reasons.extend(downstream_reasons)
    results = [evaluate_claim(c, thresholds, evidence_root=effective_evidence_root) for c in claims]
    fail_count = sum(r.status == "FAIL" for r in results)
    critical_fail = sum(r.status == "FAIL" and r.importance == "critical" for r in results)
    major_fail = sum(r.status == "FAIL" and r.importance == "major" for r in results)
    scope_unknowns = [x for x in _as_list(cert.get("scope_limitations")) if _nonempty(x)]
    cert_method_unknowns = _collect_method_unknowns(cert, max_depth=max_unknown_depth)
    if critical_fail or major_fail or not claims or downstream_reasons:
        status = "FAIL"
    elif fail_count or reasons:
        status = "LIMITED"
    elif scope_unknowns or cert_method_unknowns:
        status = "PASS-SCOPED"
    else:
        status = "PASS-TRACKED"
    return {
        "status": status,
        "summary": {"claims": len(claims), "failed_claims": fail_count, "critical_failed": critical_fail, "major_failed": major_fail, "scope_limitations": len(scope_unknowns), "certificate_method_unknowns": len(cert_method_unknowns), "certificate_method_completeness": round(method_score,4), "evidence_root_checked": bool(evidence_root), "strict_evidence": bool(strict_evidence or evidence_root is not None), "structured_evidence_required": bool(strict_evidence or evidence_root is not None), "derived_or_downstream_claims": downstream_count, "downstream_nonclosure_violations": len(downstream_reasons)},
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
    lines.append("\nThis deterministic result checks declared fields, thresholds, tests, outcomes, local evidence-ref containment, unique canonical evidence-ref and modal-test counting, structured evidence binding for every cited local ref, and exact SHA-256 equality between artifact_path and hash_or_version, and URI-scheme rejection for both evidence refs and artifact_path. It does not independently prove expert-level semantic adequacy of every evidence artifact or perturbation.")
    return "\n".join(lines) + "\n"


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Evaluate a Nozickian truth-tracking certificate JSON")
    ap.add_argument("certificate", type=Path); ap.add_argument("--markdown", type=Path); ap.add_argument("--evidence-root", type=Path); ap.add_argument("--strict-evidence", "--require-structured-evidence", dest="strict_evidence", action="store_true", help="Require structured local evidence binding when --evidence-root is supplied")
    ap.add_argument("--max-unknown-depth", type=int, default=6, help="Max recursion depth for collecting certificate-scope method unknowns; negative means unbounded (default: 6).")
    args = ap.parse_args(argv)
    evidence_root = args.evidence_root.resolve() if args.evidence_root else None
    result = evaluate_certificate(load_json(args.certificate), evidence_root=evidence_root, strict_evidence=(args.strict_evidence or evidence_root is not None), max_unknown_depth=args.max_unknown_depth)
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True); args.markdown.write_text(to_markdown(result, args.certificate), encoding="utf-8")
    return 0 if result["status"] in {"PASS-TRACKED", "PASS-SCOPED"} else 2

if __name__ == "__main__":
    raise SystemExit(main())
