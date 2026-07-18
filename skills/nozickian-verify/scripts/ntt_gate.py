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
STRUCTURED_TEST_FIELDS = ("test_id",)
EVIDENCE_SCHEMA_VERSION = "1.1"
OBSERVATION_SCHEMA_VERSION = "1.2"
CLAIM_CONTRACT_SCHEMA_VERSION = "1.0"
WORLD_CONTRACT_SCHEMA_VERSION = "1.0"
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
    raw = str(value or "").strip()
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
    # Schema 1.1 is closed for the complete ledger, not merely the selected
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
    for field in STRUCTURED_EVIDENCE_FIELDS:
        if not _nonempty(data.get(field)):
            reasons.append(f"structured evidence missing {field}")
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
    if test_id is not None:
        if modal_test is None:
            reasons.append("modal test binding is unavailable")
        else:
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


def _method_string_is_substantive(value: Any) -> bool:
    return (
        type(value) is str
        and bool(value.strip())
        and value.strip().lower() not in UNKNOWN
    )


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


def _method_component_is_substantive(field: str, value: Any) -> bool:
    if field in METHOD_NARRATIVE_FIELDS:
        return _method_string_is_substantive(value) or (
            isinstance(value, Mapping)
            and _structured_method_value_is_substantive(value)
        )
    if field in METHOD_COLLECTION_FIELDS:
        return (
            _method_string_is_substantive(value)
            or (
                type(value) is list
                and _structured_method_value_is_substantive(value)
            )
            or (
                isinstance(value, Mapping)
                and _structured_method_value_is_substantive(value)
            )
        )
    return False


def method_completeness(method: Mapping[str, Any] | None) -> Tuple[float, List[str]]:
    if not isinstance(method, Mapping):
        return 0.0, list(REQ_METHOD)
    missing = [
        field
        for field in REQ_METHOD
        if not _method_component_is_substantive(field, method.get(field))
    ]
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
    refs = [r for r in _as_list(t.get("evidence_refs")) if _nonempty(r)]
    reasons: List[str] = []
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
    for field in sorted(
        WORLD_CONTRACT_FIELDS
        - {"schema_version", "semantic_equivalence_class"}
    ):
        normalized = _canonical_proposition_text(value.get(field))
        if normalized is None:
            reasons.append(
                f"world_contract {field} must be a nonempty string"
            )
        else:
            canonical[field] = normalized
    return (canonical if not reasons else None), reasons


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
        if _canonical_proposition_text(t.get(field)) is None:
            reasons.append(f"{field} must be a nonempty string")
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
    _, world_reasons = _canonical_world_contract(t.get("world_contract"))
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
    reviewer-assigned ``semantic_equivalence_class`` and independently on a
    fingerprint of every other structured world field. Changing only the class
    label or only the display/structural prose cannot manufacture extra
    coverage.
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
            field: value
            for field, value in world_contract.items()
            if field != "semantic_equivalence_class"
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
    json_cache: Optional[
        Dict[JsonCacheKey, BoundedJsonResult]
    ] = None,
) -> ClaimResult:
    cid = str(claim.get("id") or "<missing-id>")
    raw_importance = claim.get("importance")
    imp = _lower(raw_importance or "critical")
    if imp not in IMPORTANCE: imp = "critical"
    reasons: List[str] = []
    if not _nonempty(claim.get("id")): reasons.append("missing claim id")
    claim_text = claim.get("text")
    if _canonical_proposition_text(claim_text) is None:
        reasons.append("claim text must be a nonempty string")
    if type(raw_importance) is not str or raw_importance not in IMPORTANCE:
        reasons.append(
            "importance must be exactly critical, major, or minor"
        )
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
    expected_contract_digest = _claim_contract_sha256(claim)
    if evidence_root is not None:
        if claim.get("claim_contract_schema_version") != CLAIM_CONTRACT_SCHEMA_VERSION:
            reasons.append(
                "claim_contract_schema_version is not "
                f"{CLAIM_CONTRACT_SCHEMA_VERSION}"
            )
        _, contract_reasons = _claim_contract_payload(claim)
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

    ev_refs = [e for e in _as_list(claim.get("evidence_refs")) if _nonempty(e)]
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
    ftests = [t for t in _as_list(claim.get("false_world_tests")) if isinstance(t, Mapping)]
    ttests = [t for t in _as_list(claim.get("true_world_tests")) if isinstance(t, Mapping)]
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
        )
    )
    fails = [r for r in fr + tr if r.status != "PASS"]
    if fails: reasons.append(f"{len(fails)} test(s) failed deterministic checks")
    if ftests and sens < th["sensitivity"]: reasons.append(f"sensitivity pass rate {sens:.3f} < threshold {th['sensitivity']:.3f}")
    if ttests and adh < th["adherence"]: reasons.append(f"adherence pass rate {adh:.3f} < threshold {th['adherence']:.3f}")
    unresolved = [c for c in _as_list(claim.get("unresolved_contradictions")) if _nonempty(c)]
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
        return policy
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


def _claim_contract_payload(
    claim: Mapping[str, Any],
) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """Build the versioned method-relative identity for a claim."""
    reasons: List[str] = []
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
    if reasons:
        return None, reasons
    assert text is not None
    assert scope is not None
    assert artifact_location is not None
    assert type(importance) is str
    assert canonical_method is not None
    return {
        "schema_version": CLAIM_CONTRACT_SCHEMA_VERSION,
        "text": text,
        "scope": scope,
        "artifact_location": artifact_location,
        "importance": importance,
        "method_m": canonical_method,
    }, []


def _claim_contract_sha256(claim: Mapping[str, Any]) -> Optional[str]:
    payload, _ = _claim_contract_payload(claim)
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
        "outcome": _lower(
            test.get("outcome") or test.get("observed_outcome")
        ),
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
        "summary": {
            "claims": len(claims),
            "failed_claims": fail_count,
            "critical_failed": critical_fail,
            "major_failed": major_fail,
            "scope_limitations": len(scope_unknowns),
            "certificate_method_unknowns": len(cert_method_unknowns),
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
