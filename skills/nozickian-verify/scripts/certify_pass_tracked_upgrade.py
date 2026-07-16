#!/usr/bin/env python3
"""Evaluate a promotion-v2 modeled-profile audit bundle.

This script is deliberately conservative. It does not run Claude Code itself; it
checks an external audit bundle produced by the documented upgrade workflow. It
rejects dry-runs, missing official validators, missing live fixture evidence,
missing formal artifact evidence, missing strict-gate PASS-TRACKED status,
missing native stream-json trace authentication, and downstream automatic
closure. For every complete modeled profile, v1.0.3 always emits a non-authorizing PASS-SCOPED/CAPPED result
with promotion_authorized false and exit status 2 while the two Issue #5 charter
obligations remain unresolved. It does not enable a human or CI system to
record PASS-TRACKED.
"""
from __future__ import annotations

import argparse
import contextlib
import ctypes
import hashlib
import importlib.util
import io
import json
import os
import re
import signal
import shutil
import stat
import subprocess
import sys
import threading
import time
import uuid
from collections import Counter
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

PASS_TRACKED = "PASS-TRACKED"
PASS_SCOPED = "PASS-SCOPED"
UNVERIFIED_RUNTIME = "UNVERIFIED_RUNTIME"
FAIL_STATUSES = {"FAIL", "LIMITED", "UNVERIFIED", UNVERIFIED_RUNTIME}
PASSISH = {PASS_TRACKED, PASS_SCOPED, "PASS"}
PROMOTION_PROFILE = "promotion-contract-v2-complete"
PROMOTION_CERTIFICATE_SCHEMA = "2.0"
PROMOTION_EVIDENCE_SCHEMA = "promotion-evidence-v2"
DETERMINISTIC_CAPTURE_SCHEMA = "deterministic-capture-v2"
OFFICIAL_POLICY_SCHEMA = "official-validator-policy-v1"
FORMAL_RESULT_SCHEMA = "2.0"
MAX_EVIDENCE_NODES = 16
MAX_EVIDENCE_DEPENDENCIES = 8
MAX_EVIDENCE_GRAPH_DEPTH = 8
MAX_CAPTURE_BYTES = 64 * 1024 * 1024
PUBLIC_STREAM_BOUND_BYTES = 2048
MAX_STALE_SCAN_ENTRIES = 20_000
MAX_STALE_SCAN_FILE_BYTES = 8 * 1024 * 1024
MAX_STALE_SCAN_TOTAL_BYTES = 128 * 1024 * 1024
PIPE_CLOSE_GRACE_SEC = 0.5
READER_JOIN_GRACE_SEC = 1.0
PROCESS_CONTAINMENT_SCOPE = {
    "mechanism": (
        "initial-posix-process-group"
        if os.name == "posix"
        else "leader-process-only"
    ),
    "cleanup_after_leader_exit": os.name == "posix",
    "detached_session_descendants_contained": False,
}
DETACHED_CLEANUP_TIMEOUT_SEC = 1.0
DETACHED_CLEANUP_QUIET_SEC = 0.05
MAX_PROC_SCAN_ENTRIES = 100_000
PR_SET_CHILD_SUBREAPER = 36
ISSUE_5_UNRESOLVED_OBLIGATIONS = [
    "Issue #5 consistency-sweep activation and resolution mechanics remain parent-enforced.",
    "Issue #5 REMOTE_GROUND_TRUTH_REQUIRED escalation mechanics remain parent-enforced.",
]
PROMOTION_CERTIFICATE_REQUIRED_FIELD_TYPES = {
    "upgrade_from_status": str,
    "requested_status": str,
    "package_version": str,
    "package_tree_sha256": str,
    "method_m_upgrade": dict,
    "live_result_bindings": dict,
    "evidence": dict,
    "claims": list,
    "derived_or_downstream_claims": list,
    "downstream_review": dict,
}
PROMOTION_CERTIFICATE_OPTIONAL_FIELD_TYPES = {
    "origin": str,
    "scope_limitations": list,
}
PROMOTION_CLAIM_REQUIRED_FIELD_TYPES = {
    "id": str,
    "text": str,
    "importance": str,
    "artifact_location": str,
    "truth_status": str,
    "method_m": dict,
    "evidence_refs": list,
    "false_world_tests": list,
    "true_world_tests": list,
    "unresolved_contradictions": list,
    "residual_risks": list,
}
PROMOTION_CLAIM_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
LIVE_PROVENANCE_SCHEMA_VERSION = "1.0"
CLAUDE_VERSION_RE = re.compile(r"\b\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?\b")
REQUIRED_NATIVE_AGENTS = [
    "ntt-method-cartographer",
    "ntt-claim-extractor",
    "ntt-source-verifier",
    "ntt-code-verifier",
    "ntt-false-world-adversary",
    "ntt-true-world-adherence",
    "ntt-gate-auditor",
]
PROMOTION_EVIDENCE_SPECS: Dict[str, Dict[str, Any]] = {
    "deterministic.package_validation": {
        "kind": "deterministic",
        "suite": "package_validation",
        "path": "deterministic/package_validation.json",
        "depends_on": (),
    },
    "deterministic.gate_result": {
        "kind": "deterministic",
        "suite": "gate_result",
        "path": "deterministic/gate_result.json",
        "depends_on": ("deterministic.package_validation",),
    },
    "deterministic.regression": {
        "kind": "deterministic",
        "suite": "regression",
        "path": "deterministic/regression_eval_result.json",
        "depends_on": ("deterministic.package_validation",),
    },
    "deterministic.gate_contract": {
        "kind": "deterministic",
        "suite": "gate_contract",
        "path": "deterministic/gate_contract_results.json",
        "depends_on": ("deterministic.gate_result",),
    },
    "deterministic.formal_contract": {
        "kind": "deterministic",
        "suite": "formal_contract",
        "path": "deterministic/formal_runner_contract_results.json",
        "depends_on": ("deterministic.gate_contract",),
    },
    "official.claude_plugin_validate": {
        "kind": "official-policy",
        "validator_id": "claude_plugin_validate",
        "executable": "claude",
        "executable_label": "<claude-cli>",
        "path": "official_validators/claude_plugin_validate.policy.json",
        "depends_on": ("deterministic.package_validation",),
    },
    "official.skills_ref_validate": {
        "kind": "official-policy",
        "validator_id": "skills_ref_validate",
        "executable": "skills-ref",
        "executable_label": "<skills-ref-cli>",
        "path": "official_validators/skills_ref_validate.policy.json",
        "depends_on": ("deterministic.package_validation",),
    },
    "live.runtime": {
        "kind": "live",
        "path": "live_fixtures/live_runtime_eval_result.json",
        "depends_on": (
            "deterministic.package_validation",
            "official.claude_plugin_validate",
        ),
    },
    "formal.result": {
        "kind": "formal",
        "path": None,
        "depends_on": ("live.runtime", "deterministic.gate_result"),
    },
}
DETERMINISTIC_FILES = {
    str(spec["suite"]): str(spec["path"])
    for spec in PROMOTION_EVIDENCE_SPECS.values()
    if spec["kind"] == "deterministic"
}


@dataclass
class Check:
    name: str
    passed: bool
    severity: str = "critical"
    details: Any = None
    failure_kind: str = "CHECK_FAILED"


def sha256_path(path: Path) -> str:
    error = regular_file_error(path)
    if error:
        raise ValueError(error)
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def regular_file_error(path: Path) -> Optional[str]:
    """Describe why a path is not a regular final entry without following it."""
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        return f"{type(exc).__name__} while inspecting {path.name}"
    if stat.S_ISLNK(mode):
        return f"{path.name} is a symbolic link"
    if not stat.S_ISREG(mode):
        return f"{path.name} is not a regular file"
    return None


def directory_error(path: Path) -> Optional[str]:
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        return f"{type(exc).__name__} while inspecting {path.name}"
    if stat.S_ISLNK(mode):
        return f"{path.name} is a symbolic link"
    if not stat.S_ISDIR(mode):
        return f"{path.name} is not a directory"
    return None


def lexical_directory_ancestor_error(path: Path) -> Optional[str]:
    """Reject existing non-directory or symlink ancestors without resolving."""
    absolute = Path(os.path.abspath(path))
    for ancestor in reversed(absolute.parents):
        try:
            mode = ancestor.lstat().st_mode
        except FileNotFoundError:
            break
        except OSError as exc:
            return f"{type(exc).__name__} while inspecting output ancestors"
        if stat.S_ISLNK(mode):
            return "output path has a symbolic link ancestor"
        if not stat.S_ISDIR(mode):
            return "output path has a non-directory ancestor"
    return None


def _directory_open_flags() -> int:
    """Return flags for a held, no-follow directory capability."""
    if not all(
        hasattr(os, name)
        for name in ("O_DIRECTORY", "O_NOFOLLOW")
    ):
        raise OSError("no-follow directory descriptors are unavailable")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _open_directory_no_follow(path: Path) -> int:
    """Open every component beneath a held parent without following links."""
    absolute = Path(os.path.abspath(path))
    flags = _directory_open_flags()
    descriptor = os.open(os.path.sep, flags)
    try:
        for component in absolute.parts[1:]:
            if component in ("", ".", ".."):
                raise ValueError("unsafe output directory component")
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _safe_output_name(path: Path) -> str:
    name = path.name
    if name in ("", ".", "..") or os.path.sep in name:
        raise ValueError("unsafe output file name")
    if os.path.altsep and os.path.altsep in name:
        raise ValueError("unsafe output file name")
    return name


def _directory_path_matches_fd(path: Path, descriptor: int) -> bool:
    """Confirm the lexical directory still denotes the held directory."""
    reopened: Optional[int] = None
    try:
        reopened = _open_directory_no_follow(path)
        expected = os.fstat(descriptor)
        observed = os.fstat(reopened)
        return (expected.st_dev, expected.st_ino) == (
            observed.st_dev,
            observed.st_ino,
        )
    except (OSError, ValueError):
        return False
    finally:
        if reopened is not None:
            os.close(reopened)


def _paths_alias(first: Path, second: Path) -> bool:
    if first == second:
        return True
    try:
        return os.path.samefile(first, second)
    except OSError:
        return False


def _acquire_output_parent(
    path: Path,
    *,
    directory_fd: Optional[int],
    lexical_parent: Optional[Path],
) -> Tuple[str, int, Path]:
    name = _safe_output_name(path)
    if directory_fd is None:
        parent = path.parent
        descriptor = _open_directory_no_follow(parent)
    else:
        parent = lexical_parent if lexical_parent is not None else path.parent
        descriptor = os.dup(directory_fd)
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            os.close(descriptor)
            raise ValueError("held output parent is not a directory")
    return name, descriptor, parent


def _replaceable_regular_at(
    directory_fd: int,
    name: str,
) -> None:
    try:
        metadata = os.stat(
            name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError("unsafe output target is a symbolic link")
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("unsafe output target is not a regular file")
    if metadata.st_nlink != 1:
        raise ValueError("unsafe output target is a hardlink alias")


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("short write while creating output")
        remaining = remaining[written:]


def atomic_replace_regular_text(
    path: Path,
    text: str,
    *,
    directory_fd: Optional[int] = None,
    lexical_parent: Optional[Path] = None,
) -> None:
    """Atomically create or replace one private regular output."""
    # SECURITY-REVIEW: CLI output paths are caller-controlled. Hold the exact
    # parent directory while validating, creating, and installing the output;
    # every filesystem operation below is relative to that descriptor. An
    # attacker can rename the lexical ancestor, but cannot redirect these
    # operations through a replacement symlink or directory.
    name, parent_fd, parent = _acquire_output_parent(
        path,
        directory_fd=directory_fd,
        lexical_parent=lexical_parent,
    )
    temporary = f".{name}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor: Optional[int] = None
    try:
        _replaceable_regular_at(parent_fd, name)
        if not _directory_path_matches_fd(parent, parent_fd):
            raise ValueError("output parent changed before write")
        descriptor = os.open(
            temporary,
            flags,
            0o600,
            dir_fd=parent_fd,
        )
        _write_all(descriptor, text.encode("utf-8"))
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        # Recheck both the final entry and the lexical parent at the commit
        # boundary. os.replace uses the held parent for both names.
        _replaceable_regular_at(parent_fd, name)
        if not _directory_path_matches_fd(parent, parent_fd):
            raise ValueError("output parent changed before install")
        os.replace(
            temporary,
            name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        metadata = os.stat(
            name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("installed output is not a private regular file")
        os.fsync(parent_fd)
        if not _directory_path_matches_fd(parent, parent_fd):
            raise ValueError("output parent changed during install")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        finally:
            os.close(parent_fd)


def read_regular_text(
    path: Path,
    *,
    encoding: str = "utf-8",
    errors: str = "strict",
) -> str:
    # SECURITY-REVIEW: Audit-bundle paths are untrusted. The final entry is
    # lstat-checked before opening and symlink/special files are never read.
    file_error = regular_file_error(path)
    if file_error:
        raise ValueError(file_error)
    return path.read_text(encoding=encoding, errors=errors)


def load_json(path: Path) -> Any:
    return json.loads(read_regular_text(path))


def try_load_json(path: Path) -> Tuple[Optional[Any], Optional[str]]:
    try:
        return load_json(path), None
    except Exception as exc:
        return None, f"{type(exc).__name__}: invalid or unreadable JSON"


def relpath(root: Path, path: Path) -> str:
    return os.path.relpath(path, root).replace(os.sep, "/")


def walk_tree_no_follow(
    root: Path,
    *,
    skip_dir_names: Sequence[str] = (),
) -> Iterable[Tuple[Path, str, Optional[str]]]:
    """Walk a tree without following links and classify every entry."""
    root_error = directory_error(root)
    if root_error:
        yield root, "invalid", root_error
        return
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as scan:
                entries = sorted(scan, key=lambda entry: entry.name)
        except OSError as exc:
            yield (
                current,
                "unreadable-directory",
                f"{type(exc).__name__}: directory unreadable",
            )
            continue
        child_dirs: List[Path] = []
        for entry in entries:
            path = Path(entry.path)
            try:
                mode = entry.stat(follow_symlinks=False).st_mode
            except OSError as exc:
                yield (
                    path,
                    "unreadable",
                    f"{type(exc).__name__}: entry unreadable",
                )
                continue
            if stat.S_ISLNK(mode):
                yield path, "symlink", "symbolic link"
            elif stat.S_ISREG(mode):
                yield path, "regular", None
            elif stat.S_ISDIR(mode):
                yield path, "directory", None
                if path.name not in skip_dir_names:
                    child_dirs.append(path)
            else:
                yield path, "special", f"unsupported mode {stat.S_IFMT(mode):#o}"
        stack.extend(reversed(child_dirs))


class ResourceBoundError(ValueError):
    pass


def walk_tree_no_follow_bounded(
    root: Path,
    *,
    skip_dir_names: Sequence[str] = (),
    max_entries: int,
) -> Iterable[Tuple[Path, str, Optional[str]]]:
    """Stream a no-follow walk and fail before retaining an unbounded tree."""
    root_error = directory_error(root)
    if root_error:
        yield root, "invalid", root_error
        return
    stack = [root]
    observed = 0
    while stack:
        current = stack.pop()
        child_dirs: List[Path] = []
        try:
            with os.scandir(current) as scan:
                for entry in scan:
                    observed += 1
                    if observed > max_entries:
                        raise ResourceBoundError(
                            f"tree exceeds {max_entries} entries"
                        )
                    path = Path(entry.path)
                    try:
                        mode = entry.stat(follow_symlinks=False).st_mode
                    except OSError as exc:
                        yield path, "unreadable", f"{type(exc).__name__}: entry unreadable"
                        continue
                    if stat.S_ISLNK(mode):
                        yield path, "symlink", "symbolic link"
                    elif stat.S_ISREG(mode):
                        yield path, "regular", None
                    elif stat.S_ISDIR(mode):
                        yield path, "directory", None
                        if path.name not in skip_dir_names:
                            child_dirs.append(path)
                    else:
                        yield path, "special", f"unsupported mode {stat.S_IFMT(mode):#o}"
        except ResourceBoundError:
            raise
        except OSError as exc:
            yield current, "unreadable-directory", f"{type(exc).__name__}: directory unreadable"
        stack.extend(reversed(child_dirs))


def read_regular_text_bounded(
    path: Path,
    *,
    max_bytes: int,
) -> Tuple[str, int]:
    error = regular_file_error(path)
    if error is not None:
        raise ValueError(error)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        with os.fdopen(descriptor, "rb") as stream:
            payload = stream.read(max_bytes + 1)
            descriptor = -1
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(payload) > max_bytes:
        raise ResourceBoundError(f"file exceeds {max_bytes} bytes")
    return payload.decode("utf-8", errors="replace"), len(payload)


def valid_utc_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(parsed)


JSON_POSITIVE_STATUS_RE = re.compile(r"^(?:pass|passed|valid|success)$", re.I)
JSON_NEGATIVE_STATUS_RE = re.compile(
    r"^(?:fail|failed|failure|invalid|error|not[- ]?ok)\b",
    re.I,
)
TEXT_NEGATIVE_STATUS_RE = re.compile(
    r"^\s*(?:(?:validation|validator|status|result)\s*[:=\-]?\s*)?"
    r"(?:fail|failed|failure|invalid|error|not[\s-]?ok)\b",
    re.I,
)
TEXT_POSITIVE_STATUS_RE = re.compile(
    r"^\s*(?:(?:validation|validator|status|result)\s*[:=\-]?\s*)?"
    r"(?:pass|passed|valid|success|ok)\s*[.!]?\s*$",
    re.I,
)
TEXT_NONZERO_FAILURE_SUMMARY_RE = re.compile(
    r"^\s*(?=[0-9]*[1-9])[0-9]+\s+(?:errors?|failures?|failed)\b",
    re.I,
)
TEXT_ZERO_FAILED_RE = re.compile(r"^\s*0\s+failed(?:\s|$)", re.I)
ANSI_ESCAPE_RE = re.compile(
    r"(?:\x1B[@-_][0-?]*[ -/]*[@-~]|\x1B\][^\x07]*(?:\x07|\x1B\\))"
)
CLAUDE_PLUGIN_SUCCESS_RE = re.compile(r"^\s*✔\s+Validation passed\s*$")


def returncode_is_integer_zero(value: Any) -> bool:
    """Accept only JSON/Python integer zero, never bool or coercible scalars."""
    return type(value) is int and value == 0


def json_validator_status(data: Any) -> Tuple[bool, str, Dict[str, Any]]:
    if not isinstance(data, Mapping):
        return False, "validator JSON is not an object", {}
    returncode = data.get("returncode")
    status_values = [
        str(data.get(field) or "").strip()
        for field in ("status", "result")
        if field in data
    ]
    negative = [value for value in status_values if JSON_NEGATIVE_STATUS_RE.match(value)]
    positive = [value for value in status_values if JSON_POSITIVE_STATUS_RE.fullmatch(value)]
    details = {
        "returncode": returncode,
        "status_values": status_values,
        "negative_statuses": negative,
        "positive_statuses": positive,
    }
    if negative:
        return False, "explicit negative JSON status", details
    if not returncode_is_integer_zero(returncode):
        return False, "validator JSON returncode is not integer zero", details
    if not positive:
        return False, "validator JSON lacks an anchored positive status", details
    return True, "returncode zero and anchored positive JSON status", details


def _linux_status_process_identity(
    path: Path,
    namespace_index: int,
    expected_host_pid: Optional[int] = None,
) -> Optional[Tuple[int, int]]:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            payload = stream.read(64 * 1024)
    except OSError:
        return None
    parent_host_pid: Optional[int] = None
    namespace_pid: Optional[int] = None
    host_pid_matches = expected_host_pid is None
    for line in payload.splitlines():
        if line.startswith("PPid:"):
            fields = line.split()
            if len(fields) == 2 and fields[1].isdigit():
                parent_host_pid = int(fields[1])
        elif line.startswith("NSpid:"):
            fields = line.split()[1:]
            if (
                len(fields) > namespace_index
                and all(field.isdigit() for field in fields)
            ):
                namespace_pid = int(fields[namespace_index])
                host_pid_matches = (
                    expected_host_pid is None
                    or int(fields[0]) == expected_host_pid
                )
    if (
        parent_host_pid is None
        or namespace_pid is None
        or not host_pid_matches
    ):
        return None
    return parent_host_pid, namespace_pid


def _linux_self_host_pid() -> Optional[int]:
    fallback: Optional[int] = None
    try:
        with Path("/proc/self/status").open(
            "r", encoding="utf-8", errors="replace"
        ) as stream:
            payload = stream.read(64 * 1024)
    except OSError:
        return None
    for line in payload.splitlines():
        if line.startswith("NSpid:"):
            fields = line.split()[1:]
            if fields and all(field.isdigit() for field in fields):
                return int(fields[0])
        elif line.startswith("Pid:"):
            fields = line.split()
            if len(fields) == 2 and fields[1].isdigit():
                fallback = int(fields[1])
    return fallback


def _linux_self_namespace_index() -> Optional[int]:
    try:
        with Path("/proc/self/status").open(
            "r", encoding="utf-8", errors="replace"
        ) as stream:
            payload = stream.read(64 * 1024)
    except OSError:
        return None
    for line in payload.splitlines():
        if line.startswith("NSpid:"):
            fields = line.split()[1:]
            if fields and all(field.isdigit() for field in fields):
                return len(fields) - 1
    return None


def _linux_process_graph(
    namespace_index: int,
) -> Optional[Dict[int, Tuple[int, int]]]:
    graph: Dict[int, Tuple[int, int]] = {}
    scanned = 0
    try:
        with os.scandir("/proc") as entries:
            for entry in entries:
                if not entry.name.isdigit():
                    continue
                scanned += 1
                if scanned > MAX_PROC_SCAN_ENTRIES:
                    return None
                identity = _linux_status_process_identity(
                    Path(entry.path) / "status",
                    namespace_index,
                    int(entry.name),
                )
                if identity is None:
                    continue
                graph[int(entry.name)] = identity
    except OSError:
        return None
    return graph


def _host_descendant_closure(
    graph: Mapping[int, Tuple[int, int]],
    roots: set[int],
) -> set[int]:
    children: Dict[int, List[int]] = {}
    for host_pid, (parent_host_pid, _namespace_pid) in graph.items():
        children.setdefault(parent_host_pid, []).append(host_pid)
    closure: set[int] = set()
    pending = list(roots)
    while pending:
        host_pid = pending.pop()
        if host_pid in closure:
            continue
        closure.add(host_pid)
        pending.extend(children.get(host_pid, ()))
    return closure


def prepare_process_containment() -> Dict[str, Any]:
    unavailable = {
        "enabled": False,
        "parent_host_pid": None,
        "baseline_host_pids": set(),
        "scope": dict(PROCESS_CONTAINMENT_SCOPE),
    }
    if not sys.platform.startswith("linux") or not Path("/proc").is_dir():
        return unavailable
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
        prctl.argtypes = [
            ctypes.c_int,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
        ]
        prctl.restype = ctypes.c_int
        if prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
            return unavailable
    except (AttributeError, OSError):
        return unavailable
    parent_host_pid = _linux_self_host_pid()
    namespace_index = _linux_self_namespace_index()
    if parent_host_pid is None or namespace_index is None:
        return unavailable
    baseline_graph = _linux_process_graph(namespace_index)
    if baseline_graph is None:
        return unavailable
    baseline_direct = {
        host_pid
        for host_pid, (parent_pid, _namespace_pid) in baseline_graph.items()
        if parent_pid == parent_host_pid
    }
    return {
        "enabled": True,
        "parent_host_pid": parent_host_pid,
        "namespace_index": namespace_index,
        "baseline_host_pids": baseline_direct,
        "scope": {
            "mechanism": "linux-child-subreaper-plus-process-group",
            "cleanup_after_leader_exit": True,
            "detached_session_descendants_contained": True,
        },
    }


def cleanup_detached_descendants(
    containment: Mapping[str, Any],
) -> Tuple[bool, bool]:
    """Kill/reap the complete new transitive closure to a quiet state."""
    if containment.get("enabled") is not True:
        # The capture caller fails before Popen when this capability is absent.
        return False, True
    parent_host_pid = containment.get("parent_host_pid")
    namespace_index = containment.get("namespace_index")
    baseline = containment.get("baseline_host_pids")
    if (
        type(parent_host_pid) is not int
        or type(namespace_index) is not int
        or not isinstance(baseline, set)
    ):
        return False, False
    deadline = time.monotonic() + DETACHED_CLEANUP_TIMEOUT_SEC
    quiet_since: Optional[float] = None
    survivor_seen = False
    while time.monotonic() < deadline:
        graph = _linux_process_graph(namespace_index)
        if graph is None:
            return survivor_seen, False
        runner_closure = _host_descendant_closure(
            graph,
            {parent_host_pid},
        ) - {parent_host_pid}
        excluded = _host_descendant_closure(graph, set(baseline))
        candidate_host_pids = runner_closure - excluded
        candidates = {
            host_pid: graph[host_pid][1]
            for host_pid in candidate_host_pids
            if host_pid in graph
        }
        if candidates:
            survivor_seen = True
            quiet_since = None
            for namespace_pid in candidates.values():
                try:
                    os.kill(namespace_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError:
                    return survivor_seen, False
            for namespace_pid in candidates.values():
                try:
                    os.waitpid(namespace_pid, os.WNOHANG)
                except (ChildProcessError, ProcessLookupError):
                    pass
                except OSError:
                    return survivor_seen, False
        else:
            now = time.monotonic()
            if quiet_since is None:
                quiet_since = now
            elif now - quiet_since >= DETACHED_CLEANUP_QUIET_SEC:
                return survivor_seen, True
        time.sleep(0.01)
    # Make a final best-effort full-closure kill/reap pass at the deadline.
    # Success still requires a fresh scan proving that the closure is empty;
    # merely sending the signals is not completion evidence.
    graph = _linux_process_graph(namespace_index)
    if graph is None:
        return survivor_seen, False
    runner_closure = _host_descendant_closure(
        graph,
        {parent_host_pid},
    ) - {parent_host_pid}
    excluded = _host_descendant_closure(graph, set(baseline))
    final_host_pids = runner_closure - excluded
    if final_host_pids:
        survivor_seen = True
    for host_pid in final_host_pids:
        namespace_pid = graph[host_pid][1]
        try:
            os.kill(namespace_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            return survivor_seen, False
    for host_pid in final_host_pids:
        namespace_pid = graph[host_pid][1]
        try:
            os.waitpid(namespace_pid, os.WNOHANG)
        except (ChildProcessError, ProcessLookupError):
            pass
        except OSError:
            return survivor_seen, False
    time.sleep(0.005)
    fresh_graph = _linux_process_graph(namespace_index)
    if fresh_graph is None:
        return survivor_seen, False
    fresh_closure = _host_descendant_closure(
        fresh_graph,
        {parent_host_pid},
    ) - {parent_host_pid}
    fresh_excluded = _host_descendant_closure(
        fresh_graph,
        set(baseline),
    )
    return survivor_seen, not (fresh_closure - fresh_excluded)


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    previous_dont_write = sys.dont_write_bytecode
    import_stdout = io.StringIO()
    try:
        # Package verification must not mutate the tree it is measuring.
        sys.dont_write_bytecode = True
        # SECURITY-REVIEW: Fixed package-local validators execute at import
        # time. Contain stdout so certification emits one JSON document.
        with contextlib.redirect_stdout(import_stdout):
            spec.loader.exec_module(module)  # type: ignore[union-attr]
    finally:
        sys.dont_write_bytecode = previous_dont_write
    return module


def _captured_stream_fields(raw: bytes, name: str) -> Dict[str, Any]:
    return {
        name: raw.decode("utf-8", errors="replace"),
        f"_{name}_bytes": raw,
        f"{name}_bytes": len(raw),
        f"{name}_sha256": f"sha256:{hashlib.sha256(raw).hexdigest()}",
        f"{name}_truncated": len(raw) > PUBLIC_STREAM_BOUND_BYTES,
    }


def run_cmd(cmd: Sequence[str], cwd: Optional[Path] = None, timeout: int = 900) -> Dict[str, Any]:
    try:
        # SECURITY-REVIEW: The certifier constructs fixed argv for the
        # package-local validator and never invokes a shell. Full raw streams
        # remain in-memory for decisions and exact hashes; no untrusted stream
        # content is copied into the final machine result. Pipe readers enforce
        # the declared bound while the child is running.
        process_env = os.environ.copy()
        process_env["PYTHONDONTWRITEBYTECODE"] = "1"
        containment = prepare_process_containment()
        if containment.get("enabled") is not True:
            raise OSError(
                "detached-session process containment is unavailable"
            )
        proc = subprocess.Popen(
            list(cmd),
            cwd=str(cwd) if cwd else None,
            env=process_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=(os.name == "posix"),
        )
        stop = threading.Event()
        states: Dict[str, Dict[str, Any]] = {}

        def drain(name: str, stream: Any) -> None:
            retained = bytearray()
            digest = hashlib.sha256()
            observed = 0
            exceeded = False
            try:
                while True:
                    chunk = stream.read(64 * 1024)
                    if not chunk:
                        break
                    raw_chunk = bytes(chunk)
                    observed += len(raw_chunk)
                    digest.update(raw_chunk)
                    remaining = max(0, MAX_CAPTURE_BYTES - len(retained))
                    if remaining:
                        retained.extend(raw_chunk[:remaining])
                    if observed > MAX_CAPTURE_BYTES:
                        exceeded = True
                        stop.set()
            except (OSError, ValueError):
                pass
            finally:
                try:
                    stream.close()
                except Exception:
                    pass
                states[name] = {
                    "raw": bytes(retained),
                    "observed": observed,
                    "sha256": f"sha256:{digest.hexdigest()}",
                    "exceeded": exceeded,
                }

        assert proc.stdout is not None and proc.stderr is not None
        readers = [
            threading.Thread(target=drain, args=("stdout", proc.stdout), daemon=True),
            threading.Thread(target=drain, args=("stderr", proc.stderr), daemon=True),
        ]
        for reader in readers:
            reader.start()
        deadline = time.monotonic() + timeout
        timed_out = False
        descendant_pipe_leak = False
        normal_exit_group_survivor = False
        process_group_terminated = False
        process_group_cleanup_attempted = False

        def terminate_group() -> bool:
            nonlocal process_group_cleanup_attempted, process_group_terminated
            process_group_cleanup_attempted = True
            try:
                if os.name == "posix":
                    os.killpg(proc.pid, signal.SIGKILL)
                    process_group_terminated = True
                else:
                    proc.kill()
                    process_group_terminated = True
            except ProcessLookupError:
                pass
            except OSError:
                try:
                    proc.kill()
                    process_group_terminated = True
                except OSError:
                    pass
            return process_group_terminated

        while True:
            if stop.is_set():
                terminate_group()
                break
            if proc.poll() is not None:
                # Pipe state is not a containment oracle. Kill/probe the
                # original group immediately, then sweep the complete
                # transitive /proc closure before joining readers.
                if terminate_group():
                    normal_exit_group_survivor = True
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                terminate_group()
                break
            time.sleep(min(0.01, remaining))
        try:
            proc.wait(timeout=READER_JOIN_GRACE_SEC)
        except subprocess.TimeoutExpired:
            terminate_group()
            try:
                proc.wait(timeout=READER_JOIN_GRACE_SEC)
            except subprocess.TimeoutExpired:
                pass
        (
            detached_descendant_survivor,
            process_containment_cleanup_complete,
        ) = cleanup_detached_descendants(containment)
        join_deadline = time.monotonic() + READER_JOIN_GRACE_SEC
        for reader in readers:
            reader.join(timeout=max(0.0, join_deadline - time.monotonic()))
        if any(reader.is_alive() for reader in readers):
            for stream in (proc.stdout, proc.stderr):
                try:
                    os.close(stream.fileno())
                except OSError:
                    pass
            for reader in readers:
                reader.join(timeout=max(0.0, join_deadline - time.monotonic()))
        reader_join_timed_out = any(reader.is_alive() for reader in readers)
        empty_sha = f"sha256:{hashlib.sha256(b'').hexdigest()}"
        stdout_state = states.get("stdout", {"raw": b"", "observed": 0, "sha256": empty_sha, "exceeded": False})
        stderr_state = states.get("stderr", {"raw": b"", "observed": 0, "sha256": empty_sha, "exceeded": False})
        stdout_raw = bytes(stdout_state["raw"])
        stderr_raw = bytes(stderr_state["raw"])
        capture_limit_exceeded = bool(stdout_state["exceeded"] or stderr_state["exceeded"])
        result = {
            "cmd": list(cmd),
            "returncode": (
                124
                if timed_out
                else 126
                if capture_limit_exceeded
                else 125
                if (
                    descendant_pipe_leak
                    or normal_exit_group_survivor
                    or detached_descendant_survivor
                    or not process_containment_cleanup_complete
                    or reader_join_timed_out
                )
                else proc.returncode
            ),
            "stdout": stdout_raw.decode("utf-8", errors="replace"),
            "_stdout_bytes": stdout_raw,
            "stdout_bytes": stdout_state["observed"],
            "stdout_sha256": stdout_state["sha256"],
            "stdout_truncated": stdout_state["observed"] > PUBLIC_STREAM_BOUND_BYTES,
            "stderr": stderr_raw.decode("utf-8", errors="replace"),
            "_stderr_bytes": stderr_raw,
            "stderr_bytes": stderr_state["observed"],
            "stderr_sha256": stderr_state["sha256"],
            "stderr_truncated": stderr_state["observed"] > PUBLIC_STREAM_BOUND_BYTES,
            "capture_limit_exceeded": capture_limit_exceeded,
            "timed_out": timed_out,
            "descendant_pipe_leak": descendant_pipe_leak,
            "normal_exit_group_survivor": normal_exit_group_survivor,
            "detached_descendant_survivor": (
                detached_descendant_survivor
            ),
            "process_containment_cleanup_complete": (
                process_containment_cleanup_complete
            ),
            "reader_join_timed_out": reader_join_timed_out,
            "process_group_cleanup_attempted": (
                process_group_cleanup_attempted
            ),
            "process_group_terminated": process_group_terminated,
            "process_containment": dict(containment["scope"]),
        }
        return result
    except Exception as exc:
        stderr_raw = (
            f"{type(exc).__name__}: command execution failed"
        ).encode("utf-8")
        return {
            "cmd": list(cmd),
            "returncode": 125,
            **_captured_stream_fields(b"", "stdout"),
            **_captured_stream_fields(stderr_raw, "stderr"),
            "capture_limit_exceeded": False,
            "timed_out": False,
            "descendant_pipe_leak": False,
            "reader_join_timed_out": False,
            "normal_exit_group_survivor": False,
            "detached_descendant_survivor": False,
            "process_containment_cleanup_complete": False,
            "process_group_cleanup_attempted": False,
            "process_group_terminated": False,
            "process_containment": dict(PROCESS_CONTAINMENT_SCOPE),
        }


def canonical_json_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def exact_json_equal(left: Any, right: Any) -> bool:
    """Compare JSON values without Python bool/int equality aliases."""
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return (
            set(left) == set(right)
            and all(exact_json_equal(left[key], right[key]) for key in left)
        )
    if type(left) is list:
        return len(left) == len(right) and all(
            exact_json_equal(left_item, right_item)
            for left_item, right_item in zip(left, right)
        )
    return left == right


def _string_list(value: Any) -> bool:
    return type(value) is list and all(type(item) is str for item in value)


def trace_authentication_schema_valid(
    value: Any,
    expected_fields: Sequence[str],
) -> bool:
    if type(value) is not dict or set(value) != set(expected_fields):
        return False
    string_list_fields = (
        "agent_calls_authenticated",
        "agent_results_authenticated",
        "missing_agents",
        "missing_result_agents",
        "reasons",
    )
    event_list_fields = (
        "unexpected_native_tool_calls",
        "role_violations",
        "evidence_events",
        "invalid_result_bindings",
        "malformed_stream_records",
        "trace_bound_violations",
    )
    return (
        type(value.get("authenticated")) is bool
        and type(value.get("events_seen")) is int
        and value.get("events_seen") >= 0
        and type(value.get("saw_general_purpose")) is bool
        and all(_string_list(value.get(field)) for field in string_list_fields)
        and all(
            type(value.get(field)) is list
            and all(type(item) is dict for item in value.get(field))
            for field in event_list_fields
        )
        and type(value.get("duplicate_tool_use_ids")) is dict
        and all(
            type(tool_id) is str and _string_list(agents)
            for tool_id, agents in value.get("duplicate_tool_use_ids").items()
        )
        and type(value.get("result_before_call_ids")) is dict
        and all(
            type(tool_id) is str and type(record) is dict
            for tool_id, record in value.get("result_before_call_ids").items()
        )
        and type(value.get("duplicate_agent_calls")) is dict
        and all(
            type(agent) is str and type(count) is int and count > 1
            for agent, count in value.get("duplicate_agent_calls").items()
        )
        and type(value.get("duplicate_tool_result_ids")) is dict
        and all(
            type(tool_id) is str and type(count) is int and count > 1
            for tool_id, count in value.get("duplicate_tool_result_ids").items()
        )
    )


def _process_containment_scope_typed(value: Any) -> bool:
    return (
        type(value) is dict
        and set(value)
        == {
            "mechanism",
            "cleanup_after_leader_exit",
            "detached_session_descendants_contained",
        }
        and value.get("mechanism")
        == "linux-child-subreaper-plus-process-group"
        and value.get("cleanup_after_leader_exit") is True
        and value.get("detached_session_descendants_contained") is True
    )


def _endpoint_metadata_identity_typed(value: Any) -> bool:
    return (
        type(value) is dict
        and set(value) == {"algorithm", "sha256", "entries", "valid"}
        and value.get("algorithm") == "no-follow-endpoint-metadata-v1"
        and type(value.get("sha256")) is str
        and bool(re.fullmatch(r"sha256:[0-9a-f]{64}", value["sha256"]))
        and type(value.get("entries")) is int
        and value.get("entries") > 0
        and value.get("valid") is True
    )


def _execution_copy_identity_typed(
    value: Any,
    expected_tree: Mapping[str, Any],
) -> bool:
    return (
        type(value) is dict
        and set(value)
        == {
            "mode",
            "source_pre",
            "source_post",
            "snapshot_pre",
            "snapshot_post",
            "snapshot_endpoint_pre",
            "snapshot_endpoint_post",
            "endpoint_stable",
            "stability_scope",
            "temporal_immutability_enforced",
            "process_containment",
            "stable",
        }
        and value.get("mode")
        == "private-permission-hardened-endpoint-checked-release-copy"
        and all(
            exact_json_equal(value.get(field), expected_tree)
            for field in (
                "source_pre",
                "source_post",
                "snapshot_pre",
                "snapshot_post",
            )
        )
        and _endpoint_metadata_identity_typed(
            value.get("snapshot_endpoint_pre")
        )
        and exact_json_equal(
            value.get("snapshot_endpoint_pre"),
            value.get("snapshot_endpoint_post"),
        )
        and value.get("endpoint_stable") is True
        and value.get("stability_scope") == "pre-post-endpoint"
        and value.get("temporal_immutability_enforced") is False
        and _process_containment_scope_typed(value.get("process_containment"))
        and value.get("stable") is True
    )


LIVE_COMMAND_CAPTURE_FIELDS = (
    "returncode",
    "capture_limit_exceeded",
    "timed_out",
    "descendant_pipe_leak",
    "reader_join_timed_out",
    "normal_exit_group_survivor",
    "detached_descendant_survivor",
    "process_group_cleanup_attempted",
    "process_group_terminated",
    "process_containment_cleanup_complete",
    "process_containment",
)


def _live_command_capture_projection(value: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(value, Mapping):
        return None
    return {field: value.get(field) for field in LIVE_COMMAND_CAPTURE_FIELDS}


def _live_command_capture_typed(value: Any) -> bool:
    return (
        type(value) is dict
        and set(value) == set(LIVE_COMMAND_CAPTURE_FIELDS)
        and type(value.get("returncode")) is int
        and all(
            type(value.get(field)) is bool
            for field in LIVE_COMMAND_CAPTURE_FIELDS
            if field not in {"returncode", "process_containment"}
        )
        and value.get("returncode") == 0
        and value.get("capture_limit_exceeded") is False
        and value.get("timed_out") is False
        and value.get("descendant_pipe_leak") is False
        and value.get("reader_join_timed_out") is False
        and value.get("normal_exit_group_survivor") is False
        and value.get("detached_descendant_survivor") is False
        and value.get("process_group_cleanup_attempted") is True
        and value.get("process_group_terminated") is False
        and value.get("process_containment_cleanup_complete") is True
        and _process_containment_scope_typed(value.get("process_containment"))
    )


def _formal_command_record_typed(value: Any) -> bool:
    return (
        type(value) is dict
        and set(value)
        == {
            "argv",
            "returncode",
            "stdout_sha256",
            "stderr_sha256",
            "stdout_bytes",
            "stderr_bytes",
            "stdout_truncated",
            "stderr_truncated",
            "capture_limit_exceeded",
            "timed_out",
            "descendant_pipe_leak",
            "reader_join_timed_out",
            "normal_exit_group_survivor",
            "detached_descendant_survivor",
            "process_containment_cleanup_complete",
            "process_group_cleanup_attempted",
            "process_group_terminated",
            "process_containment",
        }
        and _string_list(value.get("argv"))
        and type(value.get("returncode")) is int
        and type(value.get("stdout_bytes")) is int
        and value.get("stdout_bytes") >= 0
        and type(value.get("stderr_bytes")) is int
        and value.get("stderr_bytes") >= 0
        and type(value.get("stdout_truncated")) is bool
        and type(value.get("stderr_truncated")) is bool
        and type(value.get("capture_limit_exceeded")) is bool
        and type(value.get("timed_out")) is bool
        and type(value.get("descendant_pipe_leak")) is bool
        and type(value.get("reader_join_timed_out")) is bool
        and type(value.get("normal_exit_group_survivor")) is bool
        and type(value.get("detached_descendant_survivor")) is bool
        and type(value.get("process_containment_cleanup_complete")) is bool
        and type(value.get("process_group_cleanup_attempted")) is bool
        and type(value.get("process_group_terminated")) is bool
        and _process_containment_scope_typed(
            value.get("process_containment")
        )
        and value.get("returncode") == 0
        and value.get("capture_limit_exceeded") is False
        and value.get("timed_out") is False
        and value.get("descendant_pipe_leak") is False
        and value.get("reader_join_timed_out") is False
        and value.get("normal_exit_group_survivor") is False
        and value.get("detached_descendant_survivor") is False
        and value.get("process_containment_cleanup_complete") is True
        and value.get("process_group_cleanup_attempted") is True
        and value.get("process_group_terminated") is False
        and all(
            type(value.get(field)) is str
            and bool(re.fullmatch(r"sha256:[0-9a-f]{64}", value.get(field)))
            for field in ("stdout_sha256", "stderr_sha256")
        )
    )


def _formal_file_identity_typed(value: Any) -> bool:
    return (
        type(value) is dict
        and set(value)
        == {"sha256", "device", "inode", "bytes", "mtime_ns", "ctime_ns"}
        and type(value.get("sha256")) is str
        and bool(re.fullmatch(r"sha256:[0-9a-f]{64}", value.get("sha256")))
        and all(
            type(value.get(field)) is int and value.get(field) >= 0
            for field in ("device", "inode", "bytes", "mtime_ns", "ctime_ns")
        )
    )


def formal_runtime_identity_typed(value: Any) -> bool:
    return (
        type(value) is dict
        and set(value)
        == {
            "resolved_executable_path",
            "version_output",
            "version_pattern",
            "version_pattern_match",
            "executable_sha256_pre",
            "executable_sha256_post",
            "executable_identity_pre",
            "executable_identity_post",
            "fingerprint_stable",
            "error",
        }
        and type(value.get("resolved_executable_path")) is str
        and Path(value["resolved_executable_path"]).is_absolute()
        and type(value.get("version_output")) is str
        and bool(CLAUDE_VERSION_RE.search(value.get("version_output")))
        and type(value.get("version_pattern")) is str
        and type(value.get("version_pattern_match")) is bool
        and value.get("version_pattern_match") is True
        and all(
            type(value.get(field)) is str
            and bool(re.fullmatch(r"[0-9a-f]{64}", value.get(field)))
            for field in ("executable_sha256_pre", "executable_sha256_post")
        )
        and value.get("executable_sha256_pre")
        == value.get("executable_sha256_post")
        and _formal_file_identity_typed(value.get("executable_identity_pre"))
        and exact_json_equal(
            value.get("executable_identity_pre"),
            value.get("executable_identity_post"),
        )
        and value.get("fingerprint_stable") is True
        and value.get("error") in (None, "")
    )


def _formal_record_argv(record: Any) -> Optional[List[str]]:
    if not isinstance(record, Mapping):
        return None
    argv = record.get("argv")
    if not _string_list(argv):
        return None
    return list(argv)


def _formal_precheck_inventory_typed(
    records: Any,
    runtime_executable: Any,
) -> bool:
    """Bind a passing formal result to the production precheck inventory."""
    if type(records) is not list or len(records) != 4:
        return False
    if not all(_formal_command_record_typed(record) for record in records):
        return False
    argvs = [_formal_record_argv(record) for record in records]
    if any(argv is None for argv in argvs):
        return False
    validate, regression, gate, plugin = argvs
    assert validate is not None
    assert regression is not None
    assert gate is not None
    assert plugin is not None
    scripts = "<execution-package-root>/skills/nozickian-verify/scripts"
    return (
        type(runtime_executable) is str
        and Path(runtime_executable).is_absolute()
        and len(validate) in {3, 4}
        and validate[:3]
        == [
            "<python>",
            f"{scripts}/validate_package.py",
            "<execution-package-root>",
        ]
        and validate[2] == "<execution-package-root>"
        and validate[3:] in ([], ["--self-test"])
        and regression
        == [
            "<python>",
            f"{scripts}/run_regression_evals.py",
            "<execution-package-root>",
        ]
        and gate
        == [
            "<python>",
            f"{scripts}/ntt_gate.py",
            "<execution-package-root>/self_validation/self_certificate.json",
            "--evidence-root",
            "<execution-package-root>",
            "--strict-evidence",
        ]
        and plugin
        == [
            runtime_executable,
            "plugin",
            "validate",
            "<execution-package-root>",
            "--strict",
        ]
    )


def _formal_execution_inventory_typed(
    records: Any,
    runtime_executable: Any,
    formal_coordinator: str,
) -> bool:
    """Bind formal evidence to version, coordinator, and strict-gate calls."""
    if type(records) is not list or len(records) != 3:
        return False
    if not all(_formal_command_record_typed(record) for record in records):
        return False
    argvs = [_formal_record_argv(record) for record in records]
    if any(argv is None for argv in argvs):
        return False
    version, coordinator, gate = argvs
    assert version is not None
    assert coordinator is not None
    assert gate is not None
    if type(runtime_executable) is not str or not Path(
        runtime_executable
    ).is_absolute():
        return False
    optional = coordinator[11:-1] if len(coordinator) >= 12 else []
    optional_valid = (
        optional == []
        or (
            len(optional) == 2
            and optional[0] in {"--model", "--effort"}
            and bool(optional[1])
        )
        or (
            len(optional) == 4
            and optional[0] == "--model"
            and bool(optional[1])
            and optional[2] == "--effort"
            and bool(optional[3])
        )
    )
    coordinator_shape = (
        len(coordinator) >= 12
        and type(formal_coordinator) is str
        and bool(formal_coordinator)
        and coordinator[:10]
        == [
            runtime_executable,
            "--plugin-dir",
            "<execution-package-root>",
            "--agent",
            formal_coordinator,
            "-p",
            "--output-format",
            "stream-json",
            "--include-hook-events",
            "--max-turns",
        ]
        and bool(re.fullmatch(r"[1-9][0-9]*", coordinator[10]))
        and optional_valid
        and bool(re.fullmatch(r"sha256:[0-9a-f]{64}", coordinator[-1]))
    )
    gate_certificate = gate[2] if len(gate) == 8 else ""
    gate_markdown = gate[7] if len(gate) == 8 else ""
    certificate_prefix = (
        gate_certificate[: -len("_NOZICKIAN_certificate.json")]
        if gate_certificate.endswith("_NOZICKIAN_certificate.json")
        else None
    )
    return (
        version == [runtime_executable, "--version"]
        and coordinator_shape
        and gate[:2]
        == [
            "<python>",
            "<execution-package-root>/skills/nozickian-verify/scripts/ntt_gate.py",
        ]
        and gate[3:7]
        == [
            "--evidence-root",
            "<output-dir>",
            "--strict-evidence",
            "--markdown",
        ]
        and certificate_prefix is not None
        and certificate_prefix.startswith("<output-dir>/")
        and gate_markdown
        == certificate_prefix + "_NOZICKIAN_GATE.md"
    )


def _formal_execution_companions_bound(
    data: Mapping[str, Any],
    companions: Mapping[str, Any],
) -> Dict[str, bool]:
    commands = data.get("commands")
    if type(commands) is not list or len(commands) != 3:
        return {"prompt": False, "transcript": False, "gate": False}
    coordinator = commands[1]
    gate = commands[2]
    coordinator_argv = (
        coordinator.get("argv") if isinstance(coordinator, Mapping) else None
    )
    gate_argv = gate.get("argv") if isinstance(gate, Mapping) else None
    prompt = companions.get("prompt")
    transcript = companions.get("transcript")
    certificate = companions.get("certificate")
    gate_companion = companions.get("gate")
    prompt_sha256 = (
        prompt.get("sha256") if isinstance(prompt, Mapping) else None
    )
    transcript_sha256 = (
        transcript.get("sha256")
        if isinstance(transcript, Mapping)
        else None
    )
    transcript_bytes = (
        transcript.get("bytes") if isinstance(transcript, Mapping) else None
    )
    certificate_path = (
        certificate.get("path")
        if isinstance(certificate, Mapping)
        else None
    )
    gate_path = (
        gate_companion.get("path")
        if isinstance(gate_companion, Mapping)
        else None
    )
    return {
        "prompt": (
            isinstance(coordinator_argv, list)
            and bool(coordinator_argv)
            and coordinator_argv[-1] == prompt_sha256
        ),
        "transcript": (
            isinstance(coordinator, Mapping)
            and coordinator.get("stdout_sha256") == transcript_sha256
            and coordinator.get("stdout_bytes") == transcript_bytes
        ),
        "gate": (
            isinstance(gate_argv, list)
            and len(gate_argv) == 8
            and type(certificate_path) is str
            and type(gate_path) is str
            and gate_argv[2] == f"<output-dir>/{certificate_path}"
            and gate_argv[7] == f"<output-dir>/{gate_path}"
        ),
    }


def _formal_output_checks_recomputed(
    runner: Any,
    resolved_companions: Mapping[str, Path],
    recorded_checks: Any,
) -> Tuple[bool, List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Recompute the runner's output checks and bind their exact projection."""
    recorded_projection = (
        [
            {"name": check.get("name"), "passed": check.get("passed")}
            for check in recorded_checks
        ]
        if type(recorded_checks) is list
        and all(isinstance(check, Mapping) for check in recorded_checks)
        else []
    )
    required_roles = {"report", "certificate", "ledger", "gate"}
    if not required_roles.issubset(resolved_companions):
        return False, recorded_projection, []
    try:
        recomputed = runner.check_required_outputs(
            dict(resolved_companions),
            include_gate=True,
        )
    except Exception:
        return False, recorded_projection, []
    recomputed_projection = (
        [
            {"name": check.get("name"), "passed": check.get("passed")}
            for check in recomputed
        ]
        if type(recomputed) is list
        and all(isinstance(check, Mapping) for check in recomputed)
        else []
    )
    matched = (
        bool(recomputed_projection)
        and all(check.get("passed") is True for check in recomputed_projection)
        and exact_json_equal(recorded_projection, recomputed_projection)
    )
    return matched, recorded_projection, recomputed_projection


def formal_projected_fields_typed(
    data: Mapping[str, Any],
    required_agents: Sequence[str],
    formal_coordinator: str,
) -> bool:
    expected_keys = {
        "formal_result_schema_version",
        "run_id",
        "status",
        "reason",
        "formal_coordinator",
        "required_native_agents",
        "package_tree_identity",
        "execution_package_snapshot_identity",
        "runtime_identity",
        "target_snapshot_identity",
        "verification_context",
        "evidence_root",
        "companions",
        "prechecks",
        "precheck_summary",
        "commands",
        "output_checks",
        "gate_status",
        "trace_authentication",
        "output_dir",
        "plugin_root",
        "target_artifact",
    }
    summary = data.get("precheck_summary")
    output_checks = data.get("output_checks")
    runtime_identity = data.get("runtime_identity")
    runtime_executable = (
        runtime_identity.get("resolved_executable_path")
        if isinstance(runtime_identity, Mapping)
        else None
    )
    return (
        set(data) == expected_keys
        and all(
            type(data.get(field)) is str
            for field in (
                "formal_result_schema_version",
                "run_id",
                "status",
                "reason",
                "formal_coordinator",
                "evidence_root",
                "gate_status",
                "output_dir",
                "plugin_root",
                "target_artifact",
            )
        )
        and _string_list(data.get("required_native_agents"))
        and exact_json_equal(
            data.get("required_native_agents"),
            list(required_agents),
        )
        and type(formal_coordinator) is str
        and bool(formal_coordinator)
        and data.get("formal_coordinator") == formal_coordinator
        and _formal_precheck_inventory_typed(
            data.get("prechecks"),
            runtime_executable,
        )
        and _formal_execution_inventory_typed(
            data.get("commands"),
            runtime_executable,
            formal_coordinator,
        )
        and type(summary) is dict
        and set(summary) == {"total", "failed", "passed", "failed_commands"}
        and all(
            type(summary.get(field)) is int
            for field in ("total", "failed", "passed")
        )
        and summary.get("total") == len(data.get("prechecks"))
        and summary.get("failed") == 0
        and summary.get("passed") == summary.get("total")
        and summary.get("failed_commands") == []
        and type(output_checks) is list
        and bool(output_checks)
        and all(
            type(check) is dict
            and type(check.get("name")) is str
            and type(check.get("passed")) is bool
            and check.get("passed") is True
            for check in output_checks
        )
        and len(
            {
                check.get("name")
                for check in output_checks
                if isinstance(check, Mapping)
            }
        )
        == len(output_checks)
    )


def normalized_argv(
    cmd: Sequence[str],
    package_root: Path,
    executable_label: str = "<python>",
) -> List[str]:
    root_text = str(package_root.resolve())
    normalized: List[str] = []
    for index, value in enumerate(cmd):
        item = str(value)
        if index == 0:
            normalized.append(executable_label)
            continue
        normalized.append(
            re.sub(
                re.escape(root_text) + r"(?=$|[\\/])",
                lambda _match: "<package-root>",
                item,
            )
        )
    return normalized


def command_evidence(
    result: Mapping[str, Any],
    package_root: Path,
    *,
    executable_label: str = "<python>",
) -> Dict[str, Any]:
    stdout = result.get("stdout")
    stderr = result.get("stderr")
    cmd = result.get("cmd")
    stdout_raw = result.get("_stdout_bytes")
    stderr_raw = result.get("_stderr_bytes")
    stdout_bytes = (
        bytes(stdout_raw)
        if isinstance(stdout_raw, (bytes, bytearray))
        else stdout.encode("utf-8")
        if isinstance(stdout, str)
        else b""
    )
    stderr_bytes = (
        bytes(stderr_raw)
        if isinstance(stderr_raw, (bytes, bytearray))
        else stderr.encode("utf-8")
        if isinstance(stderr, str)
        else b""
    )
    return {
        "argv": normalized_argv(
            cmd if isinstance(cmd, list) else [],
            package_root,
            executable_label=executable_label,
        ),
        "returncode": (
            result.get("returncode")
            if type(result.get("returncode")) is int
            else None
        ),
        "stdout_sha256": f"sha256:{hashlib.sha256(stdout_bytes).hexdigest()}",
        "stderr_sha256": f"sha256:{hashlib.sha256(stderr_bytes).hexdigest()}",
        "stdout_bytes": len(stdout_bytes),
        "stderr_bytes": len(stderr_bytes),
        "stdout_truncated": len(stdout_bytes) > PUBLIC_STREAM_BOUND_BYTES,
        "stderr_truncated": len(stderr_bytes) > PUBLIC_STREAM_BOUND_BYTES,
        "capture_limit_exceeded": (
            result.get("capture_limit_exceeded") is True
        ),
    }


def _strict_int(
    data: Mapping[str, Any],
    field: str,
    *,
    minimum: int = 0,
) -> int:
    value = data.get(field)
    if type(value) is not int or value < minimum:
        raise ValueError(f"{field} is not an integer >= {minimum}")
    return value


def _check_projection(data: Mapping[str, Any]) -> List[Dict[str, Any]]:
    checks = data.get("checks")
    if not isinstance(checks, list):
        raise ValueError("checks is not a list")
    projection: List[Dict[str, Any]] = []
    for index, check in enumerate(checks, start=1):
        if not isinstance(check, Mapping):
            raise ValueError(f"checks[{index}] is not an object")
        name = check.get("name")
        passed = check.get("passed")
        if type(name) is not str or type(passed) is not bool:
            raise ValueError(
                f"checks[{index}] name/passed has an invalid JSON type"
            )
        row = {"name": name, "passed": passed}
        severity = check.get("severity")
        if severity is not None:
            if type(severity) is not str:
                raise ValueError(
                    f"checks[{index}].severity is not a string"
                )
            row["severity"] = severity
        projection.append(row)
    return projection


CHECK_SUITE_PROJECTION_SPECS = {
    "package_validation": {
        "count_fields": (
            "checks_total",
            "checks_passed",
            "critical_failed",
        ),
        "failure_count": "critical_failed",
        "critical_only": True,
    },
    "regression": {
        "count_fields": (
            "checks_total",
            "checks_passed",
            "checks_failed",
        ),
        "failure_count": "checks_failed",
        "critical_only": False,
    },
}


def deterministic_semantic_projection(
    suite: str,
    data: Any,
) -> Dict[str, Any]:
    if not isinstance(data, Mapping):
        raise ValueError(f"{suite} result is not an object")
    if suite in CHECK_SUITE_PROJECTION_SPECS:
        spec = CHECK_SUITE_PROJECTION_SPECS[suite]
        status = data.get("status")
        if type(status) is not str:
            raise ValueError(f"{suite}.status is not a string")
        checks = _check_projection(data)
        counts = {
            field: _strict_int(data, field)
            for field in spec["count_fields"]
        }
        if counts["checks_total"] != len(checks):
            raise ValueError(f"{suite}.checks_total does not match checks")
        if counts["checks_passed"] != sum(
            1 for check in checks if check["passed"]
        ):
            raise ValueError(f"{suite}.checks_passed does not match checks")
        expected_failures = sum(
            1
            for check in checks
            if not check["passed"]
            and (
                not spec["critical_only"]
                or check.get("severity") == "critical"
            )
        )
        failure_field = spec["failure_count"]
        if counts[failure_field] != expected_failures:
            raise ValueError(
                f"{suite}.{failure_field} does not match checks"
            )
        return {
            "status": status,
            "counts": counts,
            "checks": checks,
        }
    if suite == "gate_result":
        status = data.get("status")
        summary = data.get("summary")
        claims = data.get("claim_results")
        if type(status) is not str or not isinstance(summary, Mapping):
            raise ValueError("gate result status/summary has invalid type")
        if not isinstance(claims, list):
            raise ValueError("gate result claim_results is not a list")
        summary_fields = {}
        for field in (
            "claims",
            "failed_claims",
            "critical_failed",
            "major_failed",
            "scope_limitations",
            "certificate_method_unknowns",
            "derived_or_downstream_claims",
            "downstream_nonclosure_violations",
        ):
            summary_fields[field] = _strict_int(summary, field)
        claim_projection: List[Dict[str, Any]] = []
        for index, claim in enumerate(claims, start=1):
            if not isinstance(claim, Mapping):
                raise ValueError(
                    f"gate claim_results[{index}] is not an object"
                )
            claim_id = claim.get("claim_id")
            claim_status = claim.get("status")
            if type(claim_id) is not str or type(claim_status) is not str:
                raise ValueError(
                    f"gate claim_results[{index}] id/status has invalid type"
                )
            count_fields = {}
            for field in (
                "evidence_count",
                "structured_evidence_count",
                "unique_evidence_count",
                "unique_structured_evidence_count",
                "unique_artifact_count",
                "false_world_tests",
                "true_world_tests",
            ):
                count_fields[field] = _strict_int(claim, field)
            rate_fields: Dict[str, float | int] = {}
            for field in (
                "sensitivity_rate",
                "adherence_rate",
                "method_completeness",
            ):
                value = claim.get(field)
                if type(value) not in {int, float}:
                    raise ValueError(
                        f"gate claim_results[{index}].{field} is not numeric"
                    )
                rate_fields[field] = value
            raw_tests = claim.get("test_results")
            if not isinstance(raw_tests, list):
                raise ValueError(
                    f"gate claim_results[{index}].test_results is not a list"
                )
            test_projection: List[Dict[str, Any]] = []
            for test_index, test in enumerate(raw_tests, start=1):
                if not isinstance(test, Mapping):
                    raise ValueError(
                        "gate claim_results"
                        f"[{index}].test_results[{test_index}] is not an object"
                    )
                test_id = test.get("test_id")
                kind = test.get("kind")
                test_status = test.get("status")
                if not all(
                    type(value) is str
                    for value in (test_id, kind, test_status)
                ):
                    raise ValueError(
                        "gate test result id/kind/status has invalid type"
                    )
                raw_evidence = test.get("evidence_checks")
                if not isinstance(raw_evidence, list):
                    raise ValueError(
                        "gate test result evidence_checks is not a list"
                    )
                evidence_projection: List[Dict[str, Any]] = []
                for evidence_index, evidence in enumerate(
                    raw_evidence,
                    start=1,
                ):
                    if not isinstance(evidence, Mapping):
                        raise ValueError(
                            "gate evidence check "
                            f"{index}.{test_index}.{evidence_index} "
                            "is not an object"
                        )
                    ref = evidence.get("ref")
                    exists = evidence.get("exists")
                    structured = evidence.get("structured")
                    artifact_sha = evidence.get("artifact_sha256")
                    if (
                        type(ref) is not str
                        or type(exists) is not bool
                        or type(structured) is not bool
                        or (
                            artifact_sha is not None
                            and (
                                type(artifact_sha) is not str
                                or not re.fullmatch(
                                    r"[0-9a-f]{64}",
                                    artifact_sha,
                                )
                            )
                        )
                    ):
                        raise ValueError(
                            "gate evidence check fields have invalid types"
                        )
                    evidence_projection.append(
                        {
                            "ref": ref,
                            "exists": exists,
                            "structured": structured,
                            "artifact_sha256": artifact_sha,
                        }
                    )
                test_projection.append(
                    {
                        "test_id": test_id,
                        "kind": kind,
                        "status": test_status,
                        "evidence": evidence_projection,
                    }
                )
            claim_projection.append(
                {
                    "claim_id": claim_id,
                    "status": claim_status,
                    "counts": count_fields,
                    "rates": rate_fields,
                    "tests": test_projection,
                }
            )
        if summary_fields["claims"] != len(claim_projection):
            raise ValueError("gate summary claims does not match claim_results")
        if summary_fields["failed_claims"] != sum(
            1 for claim in claim_projection if claim["status"] == "FAIL"
        ):
            raise ValueError(
                "gate summary failed_claims does not match claim_results"
            )
        return {
            "status": status,
            "summary": summary_fields,
            "claims": claim_projection,
        }
    if suite in {"gate_contract", "formal_contract"}:
        total = _strict_int(data, "total", minimum=1)
        passed = _strict_int(data, "passed")
        cases = data.get("cases")
        if not isinstance(cases, list):
            raise ValueError(f"{suite}.cases is not a list")
        projected_cases: List[Dict[str, Any]] = []
        for index, case in enumerate(cases, start=1):
            if not isinstance(case, Mapping):
                raise ValueError(f"{suite}.cases[{index}] is not an object")
            name = case.get("name")
            case_passed = case.get("passed")
            if type(name) is not str or type(case_passed) is not bool:
                raise ValueError(
                    f"{suite}.cases[{index}] name/passed has invalid type"
                )
            projected = {"name": name, "passed": case_passed}
            if "status" in case:
                if type(case.get("status")) is not str:
                    raise ValueError(
                        f"{suite}.cases[{index}].status is not a string"
                    )
                projected["status"] = case.get("status")
            projected_cases.append(projected)
        if total != len(projected_cases):
            raise ValueError(f"{suite}.total does not match cases")
        if passed != sum(1 for case in projected_cases if case["passed"]):
            raise ValueError(f"{suite}.passed does not match cases")
        return {
            "total": total,
            "passed": passed,
            "cases": projected_cases,
        }
    raise ValueError(f"unknown deterministic suite {suite}")


def text_validator_status(text: str) -> Tuple[bool, str]:
    lines = text.splitlines()
    if any(TEXT_NEGATIVE_STATUS_RE.match(line) for line in lines):
        return False, "text contains an anchored negative status"
    if any(TEXT_NONZERO_FAILURE_SUMMARY_RE.match(line) for line in lines):
        return False, "text contains an anchored nonzero failure summary"
    if any(TEXT_POSITIVE_STATUS_RE.fullmatch(line) for line in lines):
        return True, "text contains an anchored standalone positive status"
    if any(TEXT_ZERO_FAILED_RE.match(line) for line in lines):
        return True, "text contains an explicit 0 failed line"
    return False, "no anchored positive status or explicit 0 failed line"


def deterministic_suite_commands(
    package_root: Path,
) -> Dict[str, List[str]]:
    scripts = package_root / "skills/nozickian-verify/scripts"
    validator_cmd = [
        sys.executable,
        str(scripts / "validate_package.py"),
        str(package_root),
        "--skip-release-idempotence",
    ]
    return {
        "package_validation": validator_cmd,
        "gate_result": [
            sys.executable,
            str(scripts / "ntt_gate.py"),
            str(package_root / "self_validation/self_certificate.json"),
            "--evidence-root",
            str(package_root),
            "--strict-evidence",
        ],
        "regression": [
            sys.executable,
            str(scripts / "run_regression_evals.py"),
            str(package_root),
        ],
        "gate_contract": [
            sys.executable,
            str(scripts / "run_gate_contract_tests.py"),
            str(package_root),
        ],
        "formal_contract": [
            sys.executable,
            str(scripts / "run_formal_runner_contract_tests.py"),
            str(package_root),
        ],
    }


def deterministic_checks(
    package_root: Path,
    bundle: Path,
    _run_fresh_compat: bool,
    execution_evidence: Optional[Dict[str, Any]] = None,
) -> List[Check]:
    """Freshly execute every deterministic lane and compare typed captures."""
    checks: List[Check] = []
    commands = deterministic_suite_commands(package_root)
    tree = package_tree_sha256(package_root)
    tree_identity = {
        "algorithm": tree.get("algorithm"),
        "sha256": (
            f"sha256:{tree.get('sha256')}"
            if isinstance(tree.get("sha256"), str)
            else None
        ),
    }
    checks.append(
        Check(
            "fresh deterministic package tree is valid",
            tree.get("valid") is True,
            details=tree_identity,
        )
    )
    run_cache: Dict[Tuple[str, ...], Dict[str, Any]] = {}
    fresh_package_passed = False
    fresh_package_details: Dict[str, Any] = {
        "compatibility_flag_requested": bool(_run_fresh_compat),
        "fresh_validation_unconditional": True,
    }
    for name, rel in DETERMINISTIC_FILES.items():
        path = bundle / rel
        file_error = regular_file_error(path)
        checks.append(
            Check(
                f"deterministic artifact present as regular file: {name}",
                file_error is None,
                details=rel if file_error is None else file_error,
            )
        )
        if file_error is not None:
            capture: Any = None
            capture_error = file_error
        else:
            capture, capture_error = try_load_json(path)
        checks.append(
            Check(
                f"deterministic capture parses as object: {name}",
                capture_error is None and isinstance(capture, Mapping),
                details=capture_error,
                failure_kind="INVALID_INPUT",
            )
        )

        cmd = commands[name]
        key = tuple(cmd)
        if key not in run_cache:
            run_cache[key] = run_cmd(cmd, cwd=package_root)
        fresh_run = run_cache[key]
        public_run = command_evidence(fresh_run, package_root)
        if execution_evidence is not None:
            execution_evidence[name] = {
                **public_run,
                "package_tree_identity": tree_identity,
            }
        fresh_parsed: Any = None
        fresh_parse_error: Optional[str] = None
        try:
            stdout = fresh_run.get("stdout")
            if not isinstance(stdout, str):
                raise ValueError("fresh stdout is not text")
            fresh_parsed = json.loads(stdout)
            fresh_projection = deterministic_semantic_projection(
                name,
                fresh_parsed,
            )
        except Exception as exc:
            fresh_projection = None
            fresh_parse_error = f"{type(exc).__name__}: invalid fresh result"
        fresh_ok = (
            returncode_is_integer_zero(fresh_run.get("returncode"))
            and fresh_run.get("capture_limit_exceeded") is False
            and fresh_projection is not None
        )
        if name == "package_validation":
            fresh_ok = (
                fresh_ok
                and fresh_projection.get("status") == "PASS"
                and fresh_projection.get("counts", {}).get(
                    "critical_failed"
                )
                == 0
            )
        elif name == "gate_result":
            fresh_ok = fresh_ok and fresh_projection.get("status") in {
                PASS_TRACKED,
                PASS_SCOPED,
            }
        elif name == "regression":
            fresh_ok = (
                fresh_ok
                and fresh_projection.get("status") == "PASS"
                and fresh_projection.get("counts", {}).get("checks_failed")
                == 0
            )
        else:
            fresh_ok = (
                fresh_ok
                and fresh_projection.get("total")
                == fresh_projection.get("passed")
            )
        checks.append(
            Check(
                f"fresh deterministic suite passes: {name}",
                bool(fresh_ok),
                details={
                    **public_run,
                    "projection_error": fresh_parse_error,
                },
            )
        )
        if name == "package_validation":
            fresh_package_passed = bool(fresh_ok)
            fresh_package_details.update(
                {
                    "returncode": public_run.get("returncode"),
                    "status": (
                        fresh_projection.get("status")
                        if isinstance(fresh_projection, Mapping)
                        else None
                    ),
                    "critical_failed": (
                        fresh_projection.get("counts", {}).get(
                            "critical_failed"
                        )
                        if isinstance(fresh_projection, Mapping)
                        else None
                    ),
                }
            )

        if not isinstance(capture, Mapping):
            continue
        capture_keys = {
            "capture_schema_version",
            "suite",
            "argv",
            "returncode",
            "package_tree_identity",
            "stdout_sha256",
            "result_sha256",
            "result",
        }
        captured_tree = capture.get("package_tree_identity")
        capture_shape_ok = (
            set(capture) == capture_keys
            and capture.get("capture_schema_version")
            == DETERMINISTIC_CAPTURE_SCHEMA
            and capture.get("suite") == name
            and isinstance(capture.get("argv"), list)
            and all(
                type(item) is str for item in capture.get("argv", [])
            )
            and capture.get("argv")
            == normalized_argv(cmd, package_root)
            and returncode_is_integer_zero(capture.get("returncode"))
            and isinstance(captured_tree, Mapping)
            and set(captured_tree) == {"algorithm", "sha256"}
            and type(captured_tree.get("algorithm")) is str
            and type(captured_tree.get("sha256")) is str
            and capture.get("package_tree_identity") == tree_identity
            and isinstance(capture.get("result"), Mapping)
            and isinstance(capture.get("result_sha256"), str)
            and capture.get("result_sha256")
            == f"sha256:{canonical_json_sha256(capture.get('result'))}"
            and isinstance(capture.get("stdout_sha256"), str)
            and bool(
                re.fullmatch(
                    r"sha256:[0-9a-f]{64}",
                    capture.get("stdout_sha256"),
                )
            )
        )
        checks.append(
            Check(
                f"deterministic capture v2 metadata valid: {name}",
                capture_shape_ok,
                details={
                    "schema": capture.get("capture_schema_version"),
                    "suite": capture.get("suite"),
                    "argv": capture.get("argv"),
                    "package_tree_identity": capture.get(
                        "package_tree_identity"
                    ),
                },
                failure_kind="INVALID_INPUT",
            )
        )
        if not capture_shape_ok:
            continue
        try:
            capture_projection = deterministic_semantic_projection(
                name,
                capture.get("result"),
            )
            projection_error = None
        except Exception as exc:
            capture_projection = None
            projection_error = f"{type(exc).__name__}: invalid capture result"
        checks.append(
            Check(
                f"deterministic capture semantic projection matches fresh: {name}",
                capture_shape_ok
                and fresh_projection is not None
                and capture_projection == fresh_projection,
                details={
                    "projection_error": projection_error,
                    "captured_projection_sha256": (
                        f"sha256:{canonical_json_sha256(capture_projection)}"
                        if capture_projection is not None
                        else None
                    ),
                    "fresh_projection_sha256": (
                        f"sha256:{canonical_json_sha256(fresh_projection)}"
                        if fresh_projection is not None
                        else None
                    ),
                },
            )
        )
    checks.append(
        Check(
            "fresh deterministic package validator still passes",
            fresh_package_passed,
            details=fresh_package_details,
        )
    )
    return checks


def validator_contradiction(text: str) -> Optional[str]:
    lines = text.splitlines()
    if any(TEXT_NEGATIVE_STATUS_RE.match(line) for line in lines):
        return "contains an anchored negative status"
    if any(TEXT_NONZERO_FAILURE_SUMMARY_RE.match(line) for line in lines):
        return "contains an anchored nonzero failure summary"
    return None


def json_line_validator_semantics(data: Any) -> Tuple[str, str]:
    """Classify one top-level JSONL event without trusting nested statuses."""
    if not isinstance(data, Mapping):
        return "neutral", "JSON line is not an object"
    status_values = [
        value.strip()
        for field in ("status", "result")
        for value in [data.get(field)]
        if type(value) is str
    ]
    if any(JSON_NEGATIVE_STATUS_RE.match(value) for value in status_values):
        return "contradiction", "explicit negative JSON status"
    if "returncode" in data and not returncode_is_integer_zero(
        data.get("returncode")
    ):
        return "contradiction", "validator JSON returncode is not integer zero"
    if (
        any(JSON_POSITIVE_STATUS_RE.fullmatch(value) for value in status_values)
        and returncode_is_integer_zero(data.get("returncode"))
    ):
        return "positive", "returncode zero and anchored positive JSON status"
    return "neutral", "JSON line has no strict positive or negative result"


def normalize_validator_stream(text: str) -> str:
    """Remove terminal control sequences before strict line classification."""
    return ANSI_ESCAPE_RE.sub("", text)


def validator_stream_semantics(
    text: str,
    *,
    validator_id: Optional[str] = None,
) -> Tuple[str, str]:
    """Classify one validator stream through shared strict semantics."""
    text = normalize_validator_stream(text)
    if not text.strip():
        return "neutral", "stream is empty"
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None
    else:
        positive, reason, _details = json_validator_status(parsed)
        return ("positive" if positive else "contradiction"), reason

    positive_reasons: List[str] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            line_json = json.loads(line)
        except json.JSONDecodeError:
            contradiction = validator_contradiction(line)
            if contradiction is not None:
                return (
                    "contradiction",
                    f"line {line_number} {contradiction}",
                )
            positive, reason = text_validator_status(line)
            if (
                not positive
                and validator_id == "claude_plugin_validate"
                and CLAUDE_PLUGIN_SUCCESS_RE.fullmatch(line)
            ):
                positive = True
                reason = "exact Claude plugin validation success line"
            if positive:
                positive_reasons.append(f"line {line_number} {reason}")
            continue
        line_kind, line_reason = json_line_validator_semantics(line_json)
        if line_kind == "contradiction":
            return (
                "contradiction",
                f"line {line_number} {line_reason}",
            )
        if line_kind == "positive":
            positive_reasons.append(f"line {line_number} {line_reason}")
    if positive_reasons:
        return "positive", "; ".join(positive_reasons)
    return "neutral", "stream has no strict positive or negative result"


def official_validator_status(
    stdout: str,
    stderr: str,
    *,
    validator_id: str,
) -> Tuple[bool, str]:
    stdout_kind, stdout_reason = validator_stream_semantics(
        stdout,
        validator_id=validator_id,
    )
    stderr_kind, stderr_reason = validator_stream_semantics(
        stderr,
        validator_id=validator_id,
    )
    if stderr_kind == "contradiction":
        return False, f"stderr contradiction: {stderr_reason}"
    if stdout_kind == "contradiction":
        return False, f"stdout contradiction: {stdout_reason}"
    if stdout_kind != "positive":
        return False, f"stdout is not a strict positive result: {stdout_reason}"
    return True, "stdout is positive and stderr has no contradiction"


def _resolved_executable(name: str) -> Tuple[Optional[Path], Optional[str]]:
    found = shutil.which(name)
    if not found:
        return None, None
    try:
        resolved = Path(found).resolve(strict=True)
    except OSError as exc:
        return None, f"{type(exc).__name__}: executable resolution failed"
    error = regular_file_error(resolved)
    if error:
        return None, error
    return resolved, None


def official_validator_checks(
    package_root: Path,
    _bundle: Path,
    allow_scope_exclusion: bool,
    execution_evidence: Optional[Dict[str, Any]] = None,
) -> List[Check]:
    checks: List[Check] = []
    tree = package_tree_sha256(package_root)
    tree_identity = {
        "algorithm": tree.get("algorithm"),
        "sha256": (
            f"sha256:{tree.get('sha256')}"
            if isinstance(tree.get("sha256"), str)
            else None
        ),
    }
    specs = {
        str(spec["validator_id"]): spec
        for spec in PROMOTION_EVIDENCE_SPECS.values()
        if spec.get("kind") == "official-policy"
    }
    for name, spec in sorted(specs.items()):
        if name == "claude_plugin_validate":
            args = [
                "plugin",
                "validate",
                str(package_root),
                "--strict",
            ]
        elif name == "skills_ref_validate":
            args = [
                "validate",
                str(package_root / "skills/nozickian-verify"),
            ]
        else:
            checks.append(
                Check(
                    f"official validator specification recognized: {name}",
                    False,
                    failure_kind="INTERNAL_ERROR",
                )
            )
            continue
        executable, executable_error = _resolved_executable(
            spec["executable"]
        )
        if executable is None and executable_error is None:
            if execution_evidence is not None:
                execution_evidence[name] = {
                    "available": False,
                    "scope_excluded": bool(allow_scope_exclusion),
                    "package_tree_identity": tree_identity,
                }
            checks.append(
                Check(
                    f"official validator executable available: {name}",
                    allow_scope_exclusion,
                    severity=(
                        "major" if allow_scope_exclusion else "critical"
                    ),
                    details=(
                        "tool absent and explicitly scope-excluded"
                        if allow_scope_exclusion
                        else "tool absent without scope exclusion"
                    ),
                )
            )
            continue
        if executable is None:
            checks.append(
                Check(
                    f"official validator executable valid: {name}",
                    False,
                    details=executable_error,
                    failure_kind="INVALID_INPUT",
                )
            )
            continue
        try:
            fingerprint_pre = sha256_path(executable)
        except (OSError, ValueError) as exc:
            checks.append(
                Check(
                    f"official validator executable fingerprinted: {name}",
                    False,
                    details=f"{type(exc).__name__}: fingerprint failed",
                )
            )
            continue
        cmd = [str(executable), *args]
        # SECURITY-REVIEW: Only allowlisted validator names and fixed argv are
        # executed. The resolved regular executable is invoked directly with
        # no shell, and untrusted bundle values never influence argv.
        fresh = run_cmd(cmd, cwd=package_root)
        try:
            fingerprint_post = sha256_path(executable)
        except (OSError, ValueError):
            fingerprint_post = None
        public = command_evidence(
            fresh,
            package_root,
            executable_label=spec["executable_label"],
        )
        stdout = fresh.get("stdout")
        stderr = fresh.get("stderr")
        status_ok, status_reason = (
            official_validator_status(stdout, stderr, validator_id=name)
            if isinstance(stdout, str) and isinstance(stderr, str)
            else (False, "validator stdout/stderr is not text")
        )
        fresh_ok = (
            returncode_is_integer_zero(fresh.get("returncode"))
            and fresh.get("capture_limit_exceeded") is False
            and fingerprint_pre == fingerprint_post
            and status_ok
        )
        fresh_record = {
            "available": True,
            **public,
            "executable_sha256": f"sha256:{fingerprint_pre}",
            "fingerprint_stable": fingerprint_pre == fingerprint_post,
            "package_tree_identity": tree_identity,
            "status_reason": status_reason,
        }
        if execution_evidence is not None:
            execution_evidence[name] = fresh_record
        checks.append(
            Check(
                f"fresh official validator passes: {name}",
                fresh_ok,
                details=fresh_record,
            )
        )
    return checks


def live_fixture_checks(package_root: Path, bundle: Path) -> List[Check]:
    checks: List[Check] = []
    plugin_path = package_root / ".claude-plugin/plugin.json"
    evals_path = package_root / "skills/nozickian-verify/evals/evals.json"
    live_script = package_root / "skills/nozickian-verify/scripts/run_live_skill_evals.py"
    package_tree = package_tree_sha256(package_root)
    plugin, plugin_err = try_load_json(plugin_path)
    evals, evals_err = try_load_json(evals_path)
    checks.append(
        Check(
            "current plugin metadata is a regular parseable JSON file",
            plugin_err is None and isinstance(plugin, Mapping),
            details=plugin_err,
        )
    )
    checks.append(
        Check(
            "current live fixture specification is a regular parseable JSON file",
            evals_err is None and isinstance(evals, Mapping),
            details=evals_err,
        )
    )
    live_script_error = regular_file_error(live_script)
    checks.append(
        Check(
            "current live transcript checker is a regular file",
            live_script_error is None,
            details=live_script_error,
        )
    )
    if (
        plugin_err is not None
        or evals_err is not None
        or not isinstance(plugin, Mapping)
        or not isinstance(evals, Mapping)
        or live_script_error is not None
    ):
        return checks
    current_version = str(plugin.get("version") or "")
    fixture_specs = evals.get("fixtures")
    expected_by_id: Dict[str, str] = {}
    fixture_spec_error = None
    if not isinstance(fixture_specs, list) or not fixture_specs:
        fixture_spec_error = "fixtures is not a nonempty list"
    else:
        for item in fixture_specs:
            if (
                not isinstance(item, Mapping)
                or not isinstance(item.get("id"), str)
                or not item.get("id")
                or not isinstance(item.get("artifact"), str)
                or not item.get("artifact")
                or item["id"] in expected_by_id
            ):
                fixture_spec_error = "fixture IDs/artifacts are missing or duplicated"
                break
            expected_by_id[item["id"]] = item["artifact"]
    checks.append(
        Check(
            "current live fixture IDs are unique and complete",
            fixture_spec_error is None,
            details=fixture_spec_error or sorted(expected_by_id),
        )
    )
    if fixture_spec_error is not None:
        return checks
    live_module = load_module("ntt_live_checker_for_promotion", live_script)
    plugin_name = str(
        plugin.get("name") or "nozickian-truth-tracking-agentic"
    )
    path = bundle / PROMOTION_EVIDENCE_SPECS["live.runtime"]["path"]
    result_file_error = regular_file_error(path)
    checks.append(
        Check(
            "live runtime eval result present as regular file",
            result_file_error is None,
            details=relpath(bundle, path) if result_file_error is None else result_file_error,
        )
    )
    if result_file_error is not None:
        return checks
    data, err = try_load_json(path)
    checks.append(Check("live runtime eval result parses", err is None, details=err))
    if not isinstance(data, Mapping):
        return checks
    checks.append(
        Check(
            "current package tree verifies through shared validator helper",
            package_tree.get("valid") is True
            and package_tree.get("algorithm")
            == "ntt-stable-release-tree-v1"
            and bool(
                re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(package_tree.get("sha256") or ""),
                )
            ),
            details=package_tree,
        )
    )
    artifact_paths_by_id: Dict[str, Path] = {}
    current_artifact_sha256_by_id: Dict[str, str] = {}
    for fixture_id, artifact in sorted(expected_by_id.items()):
        try:
            artifact_path = live_module.fixture_artifact_path(
                package_root,
                artifact,
            )
            artifact_error = regular_file_error(artifact_path)
            if artifact_error is None:
                artifact_paths_by_id[fixture_id] = artifact_path
                current_artifact_sha256_by_id[fixture_id] = sha256_path(
                    artifact_path
                )
        except Exception as exc:
            artifact_error = (
                f"{type(exc).__name__}: fixture artifact resolution failed"
            )
        checks.append(
            Check(
                f"current live fixture artifact is regular and hashable: {fixture_id}",
                artifact_error is None,
                details={
                    "fixture_id": fixture_id,
                    "artifact": artifact,
                    "error": artifact_error,
                    "sha256": current_artifact_sha256_by_id.get(
                        fixture_id
                    ),
                },
            )
        )
    recorded_tree_algorithm = data.get("package_tree_algorithm")
    recorded_tree_sha256 = data.get("package_tree_sha256")
    expected_tree_sha256 = (
        package_tree.get("sha256")
        if package_tree.get("valid") is True
        else None
    )
    checks.append(
        Check(
            "live package-tree algorithm exactly matches current shared algorithm",
            recorded_tree_algorithm == "ntt-stable-release-tree-v1"
            and recorded_tree_algorithm == package_tree.get("algorithm"),
            details={
                "recorded": recorded_tree_algorithm,
                "current": package_tree.get("algorithm"),
            },
        )
    )
    checks.append(
        Check(
            "live package-tree SHA-256 matches current package bytes",
            isinstance(recorded_tree_sha256, str)
            and bool(
                re.fullmatch(r"[0-9a-f]{64}", recorded_tree_sha256)
            )
            and recorded_tree_sha256 == expected_tree_sha256,
            details={
                "recorded": recorded_tree_sha256,
                "current": expected_tree_sha256,
            },
        )
    )
    execution_snapshot = data.get("execution_package_snapshot_identity")
    expected_live_tree_identity = {
        "algorithm": package_tree.get("algorithm"),
        "sha256": expected_tree_sha256,
        "valid": package_tree.get("valid") is True,
    }
    checks.append(
        Check(
            "live execution used one endpoint-checked package copy with explicit limits",
            _execution_copy_identity_typed(
                execution_snapshot,
                expected_live_tree_identity,
            ),
            details=execution_snapshot,
        )
    )
    try:
        current_fixture_spec_sha256 = (
            sha256_path(evals_path) if evals_err is None else None
        )
    except (OSError, ValueError):
        current_fixture_spec_sha256 = None
    recorded_fixture_spec_sha256 = data.get("fixture_spec_sha256")
    checks.append(
        Check(
            "live fixture specification SHA-256 matches current evals bytes",
            isinstance(recorded_fixture_spec_sha256, str)
            and bool(
                re.fullmatch(
                    r"[0-9a-f]{64}",
                    recorded_fixture_spec_sha256,
                )
            )
            and recorded_fixture_spec_sha256
            == current_fixture_spec_sha256,
            details={
                "recorded": recorded_fixture_spec_sha256,
                "current": current_fixture_spec_sha256,
            },
        )
    )
    status = data.get("status")
    runtime_status_valid = type(status) is str
    checks.append(
        Check(
            "live runtime status has an exact string type",
            runtime_status_valid,
            details=type(status).__name__,
            failure_kind="INVALID_INPUT",
        )
    )
    checks.append(
        Check(
            "live runtime was executed",
            runtime_status_valid
            and status
            not in {
                "",
                UNVERIFIED_RUNTIME,
                "UNVERIFIED",
                "FAIL",
                "LIMITED",
            },
            details={"status": status, "reason": data.get("reason")},
        )
    )
    checks.append(Check("live runtime status is PASS-SCOPED", status == PASS_SCOPED, details=status))
    provenance = data.get("provenance")
    checks.append(
        Check(
            "live provenance schema is 1.0",
            isinstance(provenance, Mapping)
            and provenance.get("provenance_schema_version") == LIVE_PROVENANCE_SCHEMA_VERSION,
            details=provenance,
        )
    )
    checks.append(
        Check(
            "live provenance records the current observed run",
            isinstance(provenance, Mapping)
            and provenance.get("status") == "observed-current-run"
            and provenance.get("source_release") == current_version
            and provenance.get("carried_forward") is False
            and valid_utc_timestamp(provenance.get("observed_at_utc")),
            details={
                "status": provenance.get("status") if isinstance(provenance, Mapping) else None,
                "source_release": provenance.get("source_release") if isinstance(provenance, Mapping) else None,
                "current_version": current_version,
                "carried_forward": provenance.get("carried_forward") if isinstance(provenance, Mapping) else None,
                "observed_at_utc": provenance.get("observed_at_utc") if isinstance(provenance, Mapping) else None,
            },
        )
    )
    identity = data.get("runtime_identity")
    identity_mapping = identity if isinstance(identity, Mapping) else {}
    executable_sha256 = str(identity_mapping.get("executable_sha256") or "")
    executable_sha256_pre = str(identity_mapping.get("executable_sha256_pre") or "")
    executable_sha256_post = str(identity_mapping.get("executable_sha256_post") or "")
    version_output = str(identity_mapping.get("version_output") or "")
    checks.append(
        Check(
            "live runtime executable fingerprints are valid and stable",
            bool(re.fullmatch(r"[0-9a-f]{64}", executable_sha256))
            and bool(re.fullmatch(r"[0-9a-f]{64}", executable_sha256_pre))
            and bool(re.fullmatch(r"[0-9a-f]{64}", executable_sha256_post))
            and executable_sha256 == executable_sha256_pre == executable_sha256_post
            and identity_mapping.get("fingerprint_stable") is True
            and (
                identity_mapping.get("executable_fingerprint_error") is None
                or identity_mapping.get("executable_fingerprint_error") == ""
            ),
            details={
                "executable_sha256": executable_sha256,
                "executable_sha256_pre": executable_sha256_pre,
                "executable_sha256_post": executable_sha256_post,
                "fingerprint_stable": identity_mapping.get("fingerprint_stable"),
                "executable_fingerprint_error": identity_mapping.get("executable_fingerprint_error"),
            },
        )
    )
    checks.append(
        Check(
            "live runtime version output matches expected pattern",
            identity_mapping.get("version_pattern_match") is True
            and bool(CLAUDE_VERSION_RE.search(version_output)),
            details={
                "version_output": version_output,
                "version_pattern_match": identity_mapping.get("version_pattern_match"),
            },
        )
    )
    checks.append(
        Check(
            "live runtime identity records observational authentication limit",
            identity_mapping.get("authentication_status")
            == "observed-not-cryptographically-authenticated"
            and identity_mapping.get("resolved_executable_path_recorded") is False,
            details={
                "authentication_status": identity_mapping.get("authentication_status"),
                "resolved_executable_path_recorded": identity_mapping.get("resolved_executable_path_recorded"),
            },
        )
    )
    run_config = data.get("run_config")
    run_config_mapping = (
        run_config if isinstance(run_config, Mapping) else {}
    )
    recorded_max_turns = run_config_mapping.get("max_turns")
    checks.append(
        Check(
            "live run config records exact normalized fixture settings",
            isinstance(run_config, Mapping)
            and type(recorded_max_turns) is int
            and recorded_max_turns > 0
            and type(run_config_mapping.get("max_fixtures")) is int
            and run_config_mapping.get("max_fixtures") >= 0
            and type(run_config_mapping.get("timeout_sec")) is int
            and run_config_mapping.get("timeout_sec") > 0
            and run_config_mapping.get("output_format") == "json"
            and run_config_mapping.get("print_mode") is True
            and run_config_mapping.get("plugin_dir") == "<package-root>"
            and run_config_mapping.get("working_directory")
            == "<package-root>",
            details=run_config,
        )
    )
    commands = data.get("commands")
    version_command = (
        commands[0]
        if isinstance(commands, list)
        and len(commands) == 2
        and isinstance(commands[0], Mapping)
        else {}
    )
    plugin_command = (
        commands[1]
        if isinstance(commands, list)
        and len(commands) == 2
        and isinstance(commands[1], Mapping)
        else {}
    )
    expected_version_argv = ["<claude-cli>", "--version"]
    expected_plugin_argv = [
        "<claude-cli>",
        "plugin",
        "validate",
        "<package-root>",
    ]
    version_preflight_ok = (
        version_command.get("cmd") == expected_version_argv
        and returncode_is_integer_zero(version_command.get("returncode"))
        and _live_command_capture_typed(
            _live_command_capture_projection(version_command)
        )
    )
    plugin_preflight_ok = (
        plugin_command.get("cmd") == expected_plugin_argv
        and returncode_is_integer_zero(plugin_command.get("returncode"))
        and _live_command_capture_typed(
            _live_command_capture_projection(plugin_command)
        )
    )
    checks.append(
        Check(
            "live Claude version preflight exact normalized argv succeeded",
            version_preflight_ok,
            details={
                "commands_count": (
                    len(commands) if isinstance(commands, list) else "n/a"
                ),
                "recorded": version_command.get("cmd"),
                "expected": expected_version_argv,
            },
        )
    )
    checks.append(
        Check(
            "live plugin validation preflight exact normalized argv succeeded",
            plugin_preflight_ok,
            details={
                "commands_count": (
                    len(commands) if isinstance(commands, list) else "n/a"
                ),
                "recorded": plugin_command.get("cmd"),
                "expected": expected_plugin_argv,
            },
        )
    )
    preflight = data.get("preflight")
    checks.append(
        Check(
            "live harness records successful aggregate preflight",
            isinstance(preflight, Mapping)
            and preflight.get("successful") is True
            and returncode_is_integer_zero(
                preflight.get("version_returncode")
            )
            and returncode_is_integer_zero(
                preflight.get("plugin_validate_returncode")
            ),
            details=preflight,
        )
    )
    fixtures = data.get("fixture_results")
    recorded_artifact_sha256_by_id = {
        str(item.get("id")): item.get("artifact_sha256")
        for item in fixtures
        if isinstance(item, Mapping)
        and isinstance(item.get("id"), str)
        and isinstance(item.get("artifact_sha256"), str)
    } if isinstance(fixtures, list) else {}
    checks.append(
        Check(
            "live artifact SHA-256 bindings exactly match every current fixture",
            len(current_artifact_sha256_by_id) == len(expected_by_id)
            and recorded_artifact_sha256_by_id
            == current_artifact_sha256_by_id,
            details={
                "recorded": dict(
                    sorted(recorded_artifact_sha256_by_id.items())
                ),
                "current": dict(
                    sorted(current_artifact_sha256_by_id.items())
                ),
            },
        )
    )
    actual_ids = [
        item.get("id")
        for item in fixtures
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    ] if isinstance(fixtures, list) else []
    expected_counts = Counter({fixture_id: 1 for fixture_id in expected_by_id})
    actual_counts = Counter(actual_ids)
    checks.append(
        Check(
            "live fixture IDs exactly match the current package once each",
            isinstance(fixtures, list)
            and len(fixtures) == len(expected_by_id)
            and actual_counts == expected_counts,
            details={
                "expected": dict(sorted(expected_counts.items())),
                "actual": dict(sorted(actual_counts.items())),
                "fixture_objects": len(fixtures) if isinstance(fixtures, list) else "n/a",
            },
        )
    )
    transcript_paths_by_index: Dict[int, Tuple[str, Path]] = {}
    if isinstance(fixtures, list):
        for idx, item in enumerate(fixtures, start=1):
            transcript_file = (
                item.get("transcript_file")
                if isinstance(item, Mapping)
                else None
            )
            transcript_name = (
                PurePosixPath(str(transcript_file).replace("\\", "/")).name
                if isinstance(transcript_file, str)
                and transcript_file.strip()
                else ""
            )
            if transcript_name:
                transcript_paths_by_index[idx] = (
                    transcript_name,
                    bundle / "live_fixtures/transcripts" / transcript_name,
                )
    canonical_transcript_paths = [
        relpath(bundle, path_value)
        for _name, path_value in transcript_paths_by_index.values()
    ]
    canonical_transcript_counts = Counter(canonical_transcript_paths)
    checks.append(
        Check(
            "live fixture bundle-local transcript paths are unique and complete",
            isinstance(fixtures, list)
            and len(transcript_paths_by_index) == len(fixtures)
            and all(
                count == 1
                for count in canonical_transcript_counts.values()
            ),
            details={
                "paths": canonical_transcript_paths,
                "duplicates": sorted(
                    path_value
                    for path_value, count in canonical_transcript_counts.items()
                    if count > 1
                ),
            },
        )
    )
    if isinstance(fixtures, list):
        for idx, item in enumerate(fixtures, start=1):
            if not isinstance(item, Mapping):
                checks.append(Check(f"live fixture {idx} object", False, details=item)); continue
            fixture_id = str(item.get("id") or "")
            artifact = expected_by_id.get(fixture_id)
            fixture_capture = item.get("command_capture")
            checks.append(Check(
                f"live fixture {idx} command returned zero",
                returncode_is_integer_zero(item.get("returncode"))
                and _live_command_capture_typed(fixture_capture)
                and fixture_capture.get("returncode")
                == item.get("returncode"),
                details={
                    "id": fixture_id,
                    "returncode": item.get("returncode"),
                    "command_capture": fixture_capture,
                },
            ))
            checks.append(
                Check(
                    f"live fixture {idx} ID names a current fixture",
                    artifact is not None,
                    details=fixture_id,
                )
            )
            c = item.get("checks")
            transcript_name, transcript_path = transcript_paths_by_index.get(
                idx,
                ("", bundle / "live_fixtures/transcripts"),
            )
            transcript_error = (
                regular_file_error(transcript_path)
                if transcript_name
                else "fixture does not name a transcript"
            )
            checks.append(
                Check(
                    f"live fixture {idx} transcript is a bundle-local regular file",
                    transcript_error is None,
                    details={
                        "id": fixture_id,
                        "bundle_copy": relpath(bundle, transcript_path) if transcript_name else None,
                        "error": transcript_error,
                    },
                )
            )
            if artifact is None:
                continue
            try:
                artifact_path = live_module.fixture_artifact_path(
                    package_root,
                    artifact,
                )
                artifact_error = regular_file_error(artifact_path)
            except Exception as exc:
                artifact_path = (
                    package_root / "skills/nozickian-verify/evals"
                )
                artifact_error = (
                    f"{type(exc).__name__}: fixture artifact resolution failed"
                )
            checks.append(
                Check(
                    f"live fixture {idx} current artifact is a regular file",
                    artifact_error is None,
                    details={
                        "id": fixture_id,
                        "artifact": artifact,
                        "error": artifact_error,
                    },
                )
            )
            if artifact_error is not None:
                continue
            canonical_artifact = live_module.normalize_display(
                str(artifact_path),
                ((str(package_root), "<package-root>"),),
            )
            checks.append(
                Check(
                    f"live fixture {idx} recorded artifact matches current fixture",
                    item.get("artifact") == canonical_artifact,
                    details={
                        "id": fixture_id,
                        "recorded": item.get("artifact"),
                        "expected": canonical_artifact,
                    },
                )
            )
            actual_artifact_sha256 = sha256_path(artifact_path)
            recorded_artifact_sha256 = item.get("artifact_sha256")
            checks.append(
                Check(
                    f"live fixture {idx} artifact SHA-256 matches current exact bytes",
                    isinstance(recorded_artifact_sha256, str)
                    and bool(
                        re.fullmatch(
                            r"[0-9a-f]{64}",
                            recorded_artifact_sha256,
                        )
                    )
                    and recorded_artifact_sha256
                    == actual_artifact_sha256,
                    details={
                        "id": fixture_id,
                        "recorded": recorded_artifact_sha256,
                        "current": actual_artifact_sha256,
                    },
                )
            )
            if transcript_error is not None:
                continue
            actual_transcript_sha256 = sha256_path(transcript_path)
            recorded_transcript_sha256 = item.get("transcript_sha256")
            checks.append(
                Check(
                    f"live fixture {idx} transcript SHA-256 matches fixture record",
                    isinstance(recorded_transcript_sha256, str)
                    and bool(
                        re.fullmatch(
                            r"[0-9a-f]{64}",
                            recorded_transcript_sha256,
                        )
                    )
                    and recorded_transcript_sha256
                    == actual_transcript_sha256,
                    details={
                        "id": fixture_id,
                        "recorded": recorded_transcript_sha256,
                        "actual": actual_transcript_sha256,
                    },
                )
            )
            transcript_data, transcript_json_error = try_load_json(transcript_path)
            checks.append(
                Check(
                    f"live fixture {idx} transcript parses",
                    transcript_json_error is None and isinstance(transcript_data, Mapping),
                    details=transcript_json_error,
                )
            )
            if not isinstance(transcript_data, Mapping):
                continue
            literal_expected_prompt = live_module.build_fixture_prompt(
                plugin_name,
                fixture_id,
                artifact_path,
            )
            canonical_expected_prompt = live_module.normalize_display(
                literal_expected_prompt,
                ((str(package_root), "<package-root>"),),
            )
            expected_prompt_sha256 = hashlib.sha256(
                canonical_expected_prompt.encode("utf-8")
            ).hexdigest()
            recorded_prompt_sha256 = item.get("prompt_sha256")
            checks.append(
                Check(
                    f"live fixture {idx} recorded prompt SHA-256 matches current canonical prompt",
                    isinstance(recorded_prompt_sha256, str)
                    and bool(
                        re.fullmatch(
                            r"[0-9a-f]{64}",
                            recorded_prompt_sha256,
                        )
                    )
                    and recorded_prompt_sha256
                    == expected_prompt_sha256,
                    details={
                        "id": fixture_id,
                        "recorded": recorded_prompt_sha256,
                        "expected": expected_prompt_sha256,
                    },
                )
            )
            argv = transcript_data.get("cmd")
            expected_fixture_argv = [
                "<claude-cli>",
                "--plugin-dir",
                "<package-root>",
                "-p",
                "--output-format",
                "json",
                "--max-turns",
                (
                    str(recorded_max_turns)
                    if type(recorded_max_turns) is int
                    and recorded_max_turns > 0
                    else "<invalid-max-turns>"
                ),
                canonical_expected_prompt,
            ]
            checks.append(
                Check(
                    f"live fixture {idx} transcript command exactly matches normalized argv",
                    isinstance(argv, list)
                    and all(isinstance(arg, str) for arg in argv)
                    and argv == expected_fixture_argv,
                    details={
                        "id": fixture_id,
                        "recorded": argv,
                        "expected": expected_fixture_argv,
                    },
                )
            )
            transcript_prompt = (
                argv[-1]
                if isinstance(argv, list)
                and argv
                and all(isinstance(arg, str) for arg in argv)
                else None
            )
            checks.append(
                Check(
                    f"live fixture {idx} transcript command prompt binds exact fixture and artifact",
                    item.get("prompt") == canonical_expected_prompt
                    and transcript_prompt == canonical_expected_prompt,
                    details={
                        "id": fixture_id,
                        "recorded_prompt": item.get("prompt"),
                        "transcript_prompt": transcript_prompt,
                        "expected_prompt": canonical_expected_prompt,
                    },
                )
            )
            transcript_prompt_sha256 = (
                hashlib.sha256(transcript_prompt.encode("utf-8")).hexdigest()
                if isinstance(transcript_prompt, str)
                else None
            )
            checks.append(
                Check(
                    f"live fixture {idx} transcript command prompt SHA-256 matches fixture record",
                    transcript_prompt_sha256 == expected_prompt_sha256
                    and transcript_prompt_sha256
                    == recorded_prompt_sha256,
                    details={
                        "id": fixture_id,
                        "transcript": transcript_prompt_sha256,
                        "recorded": recorded_prompt_sha256,
                        "expected": expected_prompt_sha256,
                    },
                )
            )
            stdout = transcript_data.get("stdout")
            checks.append(
                Check(
                    f"live fixture {idx} transcript records stdout",
                    isinstance(stdout, str),
                    details={"id": fixture_id, "stdout_type": type(stdout).__name__},
                )
            )
            if not isinstance(stdout, str):
                continue
            recomputed = live_module.transcript_checks(stdout, artifact)
            checks.append(
                Check(
                    f"live fixture {idx} self-reported checks match transcript replay",
                    isinstance(c, Mapping) and dict(c) == recomputed,
                    details={
                        "id": fixture_id,
                        "self_reported": c,
                        "recomputed": recomputed,
                    },
                )
            )
            checks.append(
                Check(
                    f"live fixture {idx} transcript returncode matches result",
                    _live_command_capture_typed(fixture_capture)
                    and _live_command_capture_typed(
                        _live_command_capture_projection(transcript_data)
                    )
                    and exact_json_equal(
                        fixture_capture,
                        _live_command_capture_projection(transcript_data),
                    )
                    and returncode_is_integer_zero(item.get("returncode")),
                    details={
                        "id": fixture_id,
                        "result_returncode": item.get("returncode"),
                        "transcript_returncode": transcript_data.get("returncode"),
                        "result_capture": fixture_capture,
                        "transcript_capture": (
                            _live_command_capture_projection(transcript_data)
                        ),
                    },
                )
            )
            checks.append(
                Check(
                    f"live fixture {idx} replay has structured JSON envelope, substantive report, and artifact identity",
                    recomputed.get("structured_json_envelope") is True
                    and recomputed.get("envelope_is_error") is False
                    and recomputed.get("report_field") in {"result", "content"}
                    and recomputed.get("report_substantive") is True
                    and recomputed.get("artifact_seen") is True
                    and recomputed.get("passed") is True,
                    details={"id": fixture_id, "recomputed": recomputed},
                )
            )
    return checks


def formal_result_locator(
    bundle: Path,
) -> Tuple[Optional[Path], Optional[str]]:
    certificate = bundle / "promotion_certificate.json"
    data, error = try_load_json(certificate)
    if error is not None or not isinstance(data, Mapping):
        return None, "promotion certificate is not a parseable object"
    node = promotion_evidence_nodes(data).get("formal.result")
    if not isinstance(node, Mapping):
        return None, "typed promotion locator formal.result is missing"
    path, path_error, _identity = bundle_regular_file(
        bundle,
        node.get("path"),
    )
    if path_error is not None:
        return None, path_error
    return path, None


def _reserved_formal_role(
    name: str,
    companion_specs: Mapping[str, str],
) -> Optional[str]:
    if name == "formal_result.json":
        return "formal_result"
    for role, suffix in companion_specs.items():
        if len(name) > len(suffix) and name.endswith(suffix):
            return role
    return None


def _expected_formal_companion_name(
    source_name: Any,
    role: str,
    companion_specs: Mapping[str, str],
) -> Optional[str]:
    if (
        type(source_name) is not str
        or not source_name
        or Path(source_name).name != source_name
    ):
        return None
    stem = Path(source_name).stem
    if not stem:
        return None
    suffix = companion_specs.get(role)
    return f"{stem}{suffix}" if suffix is not None else None


def formal_artifact_checks(
    package_root: Path,
    bundle: Path,
) -> List[Check]:
    """Validate exactly one formal-result v2 selected by its typed locator."""
    checks: List[Check] = []
    result_path, locator_error = formal_result_locator(bundle)
    checks.append(
        Check(
            "typed promotion locator selects one formal_result.json",
            locator_error is None and result_path is not None,
            details=locator_error,
            failure_kind="INVALID_INPUT",
        )
    )
    if result_path is None:
        return checks
    data, parse_error = try_load_json(result_path)
    checks.append(
        Check(
            "typed formal result parses as object",
            parse_error is None and isinstance(data, Mapping),
            details=parse_error,
            failure_kind="INVALID_INPUT",
        )
    )
    if not isinstance(data, Mapping):
        return checks
    result_dir = result_path.parent
    checks.append(
        Check(
            "formal result schema is v2",
            data.get("formal_result_schema_version")
            == FORMAL_RESULT_SCHEMA,
            details=data.get("formal_result_schema_version"),
            failure_kind="INVALID_INPUT",
        )
    )
    run_id = data.get("run_id")
    checks.append(
        Check(
            "formal result has typed run_id",
            type(run_id) is str
            and bool(re.fullmatch(r"[A-Za-z0-9._-]{8,128}", run_id)),
            details=run_id,
            failure_kind="INVALID_INPUT",
        )
    )
    checks.append(
        Check(
            "formal result status is capped to PASS-SCOPED by execution-boundary limits",
            data.get("status") == PASS_SCOPED,
            details=data.get("status"),
        )
    )
    checks.append(
        Check(
            "formal result gate_status PASS-TRACKED",
            data.get("gate_status") == PASS_TRACKED,
            details=data.get("gate_status"),
        )
    )
    checks.append(
        Check(
            "formal result uses one bundle-local evidence root",
            data.get("evidence_root") == ".",
            details=data.get("evidence_root"),
            failure_kind="INVALID_INPUT",
        )
    )

    current_tree = package_tree_sha256(package_root)
    expected_tree = {
        "algorithm": current_tree.get("algorithm"),
        "sha256": (
            f"sha256:{current_tree.get('sha256')}"
            if isinstance(current_tree.get("sha256"), str)
            else None
        ),
        "valid": current_tree.get("valid") is True,
    }
    recorded_tree = data.get("package_tree_identity")
    tree_schema_ok = (
        isinstance(recorded_tree, Mapping)
        and set(recorded_tree) == {"algorithm", "sha256", "valid"}
        and type(recorded_tree.get("algorithm")) is str
        and bool(recorded_tree.get("algorithm"))
        and type(recorded_tree.get("sha256")) is str
        and bool(
            re.fullmatch(
                r"sha256:[0-9a-f]{64}",
                recorded_tree.get("sha256"),
            )
        )
        and type(recorded_tree.get("valid")) is bool
    )
    checks.append(
        Check(
            "formal result package-tree identity has exact JSON schema",
            tree_schema_ok,
            details=recorded_tree,
            failure_kind="INVALID_INPUT",
        )
    )
    checks.append(
        Check(
            "formal result package-tree identity matches current package",
            tree_schema_ok and exact_json_equal(recorded_tree, expected_tree),
            details={
                "recorded": recorded_tree,
                "expected": expected_tree,
            },
        )
    )
    execution_snapshot = data.get("execution_package_snapshot_identity")
    execution_snapshot_ok = _execution_copy_identity_typed(
        execution_snapshot,
        expected_tree,
    )
    checks.append(
        Check(
            "formal execution package copy is endpoint-stable, current, and explicitly scoped",
            execution_snapshot_ok,
            details=execution_snapshot,
        )
    )
    formal_runtime_identity = data.get("runtime_identity")
    formal_runtime_ok = formal_runtime_identity_typed(
        formal_runtime_identity
    )
    checks.append(
        Check(
            "formal Claude executable path, version, and pre/post identity are bound",
            formal_runtime_ok,
            details=formal_runtime_identity,
            failure_kind="INVALID_INPUT",
        )
    )
    live_result_path = (
        bundle / PROMOTION_EVIDENCE_SPECS["live.runtime"]["path"]
    )
    live_result, live_result_error = try_load_json(live_result_path)
    live_runtime = (
        live_result.get("runtime_identity")
        if isinstance(live_result, Mapping)
        else None
    )
    checks.append(
        Check(
            "formal and live evidence bind the same Claude runtime",
            formal_runtime_ok
            and isinstance(live_runtime, Mapping)
            and formal_runtime_identity.get("executable_sha256_pre")
            == live_runtime.get("executable_sha256_pre")
            and formal_runtime_identity.get("executable_sha256_post")
            == live_runtime.get("executable_sha256_post")
            and formal_runtime_identity.get("version_output")
            == live_runtime.get("version_output"),
            details={
                "formal_sha256": (
                    formal_runtime_identity.get("executable_sha256_pre")
                    if isinstance(formal_runtime_identity, Mapping)
                    else None
                ),
                "live_sha256": (
                    live_runtime.get("executable_sha256_pre")
                    if isinstance(live_runtime, Mapping)
                    else None
                ),
                "live_result_error": live_result_error,
            },
        )
    )

    runner_path = (
        package_root
        / "skills/nozickian-verify/scripts/run_formal_artifact_verification.py"
    )
    runner_error = regular_file_error(runner_path)
    checks.append(
        Check(
            "current formal runner is a regular file",
            runner_error is None,
            details=runner_error,
        )
    )
    if runner_error is not None:
        return checks
    try:
        runner = load_module(
            "ntt_formal_runner_for_promotion_v2",
            runner_path,
        )
        companion_specs = getattr(runner, "FORMAL_COMPANION_SPECS", None)
        verification_context_spec = getattr(
            runner,
            "FORMAL_VERIFICATION_CONTEXT",
            None,
        )
        trace_authentication_fields = getattr(
            runner,
            "TRACE_AUTHENTICATION_FIELDS",
            None,
        )
        runner_required_agents = getattr(
            runner,
            "REQUIRED_NATIVE_AGENTS",
            None,
        )
        runner_formal_coordinator = getattr(
            runner,
            "FORMAL_COORDINATOR",
            None,
        )
    except Exception:
        companion_specs = None
        verification_context_spec = None
        trace_authentication_fields = None
        runner_required_agents = None
        runner_formal_coordinator = None
    specs_typed = (
        isinstance(companion_specs, Mapping)
        and bool(companion_specs)
        and all(
            type(role) is str
            and type(suffix) is str
            and role
            and suffix
            for role, suffix in companion_specs.items()
        )
    )
    checks.append(
        Check(
            "formal companion specifications load from current runner",
            specs_typed,
            details=(
                sorted(companion_specs)
                if isinstance(companion_specs, Mapping)
                else None
            ),
            failure_kind="INTERNAL_ERROR",
        )
    )
    if not specs_typed or not isinstance(companion_specs, Mapping):
        return checks
    runner_schema_specs_typed = (
        type(verification_context_spec) is dict
        and all(
            type(key) is str
            and (
                (
                    key == "temporal_immutability_enforced"
                    and value is False
                )
                or (
                    key != "temporal_immutability_enforced"
                    and type(value) is str
                )
            )
            for key, value in verification_context_spec.items()
        )
        and type(trace_authentication_fields) in {tuple, list}
        and all(
            type(field) is str and field
            for field in trace_authentication_fields
        )
        and len(set(trace_authentication_fields))
        == len(trace_authentication_fields)
        and _string_list(runner_required_agents)
        and type(runner_formal_coordinator) is str
        and bool(runner_formal_coordinator)
    )
    checks.append(
        Check(
            "formal runner exports exact result schema specifications",
            runner_schema_specs_typed,
            details={
                "verification_context": verification_context_spec,
                "trace_authentication_fields": trace_authentication_fields,
                "required_native_agents": runner_required_agents,
                "formal_coordinator": runner_formal_coordinator,
            },
            failure_kind="INTERNAL_ERROR",
        )
    )
    if not runner_schema_specs_typed:
        return checks
    formal_commands = data.get("commands")
    coordinator_argv = (
        formal_commands[1].get("argv")
        if type(formal_commands) is list
        and len(formal_commands) > 1
        and isinstance(formal_commands[1], Mapping)
        else None
    )
    coordinator_argv_agent = (
        coordinator_argv[4]
        if type(coordinator_argv) is list and len(coordinator_argv) > 4
        else None
    )
    checks.append(
        Check(
            "formal result projected fields have exact JSON types",
            formal_projected_fields_typed(
                data,
                runner_required_agents,
                runner_formal_coordinator,
            ),
            details={
                "keys": sorted(str(key) for key in data),
                "trace_authentication_present": (
                    "trace_authentication" in data
                ),
                "formal_coordinator": data.get("formal_coordinator"),
                "coordinator_argv_agent": coordinator_argv_agent,
                "expected_formal_coordinator": runner_formal_coordinator,
            },
            failure_kind="INVALID_INPUT",
        )
    )
    checks.append(
        Check(
            "formal result declares standalone endpoint-checked copy context",
            type(data.get("verification_context")) is dict
            and exact_json_equal(
                data.get("verification_context"),
                verification_context_spec,
            ),
            details=data.get("verification_context"),
            failure_kind="INVALID_INPUT",
        )
    )

    target_identity = data.get("target_snapshot_identity")
    target_source_name = (
        target_identity.get("source_name")
        if isinstance(target_identity, Mapping)
        else None
    )
    companions = data.get("companions")
    required_roles = set(companion_specs)
    companions_typed = (
        isinstance(companions, Mapping)
        and set(companions) == required_roles
        and "formal_result" not in companions
    )
    checks.append(
        Check(
            "formal result declares exact required typed companions",
            companions_typed,
            details={
                "roles": (
                    sorted(companions) if isinstance(companions, Mapping) else []
                )
            },
            failure_kind="INVALID_INPUT",
        )
    )
    if not isinstance(companions, Mapping):
        return checks

    declared_paths: Dict[str, str] = {}
    resolved_by_role: Dict[str, Path] = {}
    identities: Dict[Tuple[int, int], str] = {}
    for role in sorted(required_roles):
        record = companions.get(role)
        if not isinstance(record, Mapping):
            checks.append(
                Check(
                    f"formal companion record is typed: {role}",
                    False,
                    details="companion is not an object",
                    failure_kind="INVALID_INPUT",
                )
            )
            continue
        path_value = record.get("path")
        claimed_sha = record.get("sha256")
        claimed_bytes = record.get("bytes")
        fields_typed = (
            set(record) == {"path", "sha256", "bytes", "present"}
            and type(path_value) is str
            and type(claimed_sha) is str
            and bool(re.fullmatch(r"sha256:[0-9a-f]{64}", claimed_sha))
            and type(claimed_bytes) is int
            and claimed_bytes >= 0
            and record.get("present") is True
        )
        checks.append(
            Check(
                f"formal companion fields are typed and present: {role}",
                fields_typed,
                details={
                    "path": path_value,
                    "sha256": claimed_sha,
                    "bytes": claimed_bytes,
                    "present": record.get("present"),
                    "keys": sorted(str(key) for key in record),
                },
                failure_kind="INVALID_INPUT",
            )
        )
        if type(path_value) is not str:
            continue
        expected_name = _expected_formal_companion_name(
            target_source_name,
            role,
            companion_specs,
        )
        checks.append(
            Check(
                f"formal companion path is canonical for role: {role}",
                expected_name is not None and path_value == expected_name,
                details={
                    "recorded": path_value,
                    "expected": expected_name,
                },
                failure_kind="INVALID_INPUT",
            )
        )
        path, path_error, identity = bundle_regular_file(
            result_dir,
            path_value,
        )
        checks.append(
            Check(
                f"formal companion is bundle-local regular file: {role}",
                path_error is None and path is not None,
                details=path_error or path_value,
                failure_kind="INVALID_INPUT",
            )
        )
        if path is None:
            continue
        if path == result_path:
            checks.append(
                Check(
                    f"formal companion does not hash formal_result itself: {role}",
                    False,
                    details=path_value,
                    failure_kind="INVALID_INPUT",
                )
            )
            continue
        resolved_by_role[role] = path
        declared_paths[relpath(result_dir, path)] = role
        identity_alias = identities.get(identity) if identity else None
        checks.append(
            Check(
                f"formal companion has distinct path/file identity: {role}",
                identity_alias is None,
                details=(
                    f"aliases {identity_alias}"
                    if identity_alias is not None
                    else path_value
                ),
                failure_kind="INVALID_INPUT",
            )
        )
        if identity is not None:
            identities[identity] = role
        actual_sha = f"sha256:{sha256_path(path)}"
        actual_bytes = path.stat().st_size
        checks.append(
            Check(
                f"formal companion exact bytes and sha256 match: {role}",
                claimed_sha == actual_sha
                and claimed_bytes == actual_bytes,
                details={
                    "claimed_sha256": claimed_sha,
                    "actual_sha256": actual_sha,
                    "claimed_bytes": claimed_bytes,
                    "actual_bytes": actual_bytes,
                },
            )
        )

    formal_commands = data.get("commands")
    coordinator_record = (
        formal_commands[1]
        if isinstance(formal_commands, list)
        and len(formal_commands) == 3
        and isinstance(formal_commands[1], Mapping)
        else {}
    )
    gate_record = (
        formal_commands[2]
        if isinstance(formal_commands, list)
        and len(formal_commands) == 3
        and isinstance(formal_commands[2], Mapping)
        else {}
    )
    coordinator_argv = coordinator_record.get("argv")
    gate_argv = gate_record.get("argv")
    prompt_record = companions.get("prompt")
    transcript_record = companions.get("transcript")
    certificate_record = companions.get("certificate")
    gate_companion_record = companions.get("gate")
    execution_bindings = _formal_execution_companions_bound(
        data,
        companions,
    )
    prompt_sha256 = (
        prompt_record.get("sha256")
        if isinstance(prompt_record, Mapping)
        else None
    )
    checks.append(
        Check(
            "formal coordinator prompt digest matches declared prompt companion",
            execution_bindings["prompt"],
            details={
                "command_prompt_sha256": (
                    coordinator_argv[-1]
                    if isinstance(coordinator_argv, list)
                    and coordinator_argv
                    else None
                ),
                "companion_prompt_sha256": prompt_sha256,
            },
        )
    )
    transcript_sha256 = (
        transcript_record.get("sha256")
        if isinstance(transcript_record, Mapping)
        else None
    )
    transcript_bytes = (
        transcript_record.get("bytes")
        if isinstance(transcript_record, Mapping)
        else None
    )
    checks.append(
        Check(
            "formal coordinator stdout matches complete transcript companion",
            execution_bindings["transcript"],
            details={
                "command_stdout_sha256": coordinator_record.get(
                    "stdout_sha256"
                ),
                "command_stdout_bytes": coordinator_record.get(
                    "stdout_bytes"
                ),
                "companion_transcript_sha256": transcript_sha256,
                "companion_transcript_bytes": transcript_bytes,
            },
        )
    )
    certificate_path = (
        certificate_record.get("path")
        if isinstance(certificate_record, Mapping)
        else None
    )
    gate_companion_path = (
        gate_companion_record.get("path")
        if isinstance(gate_companion_record, Mapping)
        else None
    )
    checks.append(
        Check(
            "formal strict-gate argv binds declared certificate and gate companions",
            execution_bindings["gate"],
            details={
                "command_certificate": (
                    gate_argv[2]
                    if isinstance(gate_argv, list) and len(gate_argv) > 2
                    else None
                ),
                "declared_certificate": certificate_path,
                "command_gate": (
                    gate_argv[7]
                    if isinstance(gate_argv, list) and len(gate_argv) > 7
                    else None
                ),
                "declared_gate": gate_companion_path,
            },
        )
    )
    (
        output_checks_match,
        recorded_output_projection,
        recomputed_output_projection,
    ) = _formal_output_checks_recomputed(
        runner,
        resolved_by_role,
        data.get("output_checks"),
    )
    checks.append(
        Check(
            "formal output checks recompute exactly from declared companions",
            output_checks_match,
            details={
                "recorded": recorded_output_projection,
                "recomputed": recomputed_output_projection,
            },
        )
    )

    reserved_undeclared: List[str] = []
    for entry, kind, entry_error in walk_tree_no_follow(
        result_dir,
        skip_dir_names=("__pycache__",),
    ):
        if kind == "directory":
            continue
        entry_relative = relpath(result_dir, entry)
        reserved_role = _reserved_formal_role(
            entry.name,
            companion_specs,
        )
        if reserved_role is None or entry == result_path:
            continue
        if (
            kind != "regular"
            or entry_error is not None
            or declared_paths.get(entry_relative) != reserved_role
        ):
            reserved_undeclared.append(entry_relative)
    checks.append(
        Check(
            "formal result directory has no undeclared reserved companions",
            not reserved_undeclared,
            details=sorted(reserved_undeclared),
            failure_kind="INVALID_INPUT",
        )
    )

    target_record = companions.get("target_snapshot")
    target_sha = (
        target_record.get("sha256")
        if isinstance(target_record, Mapping)
        else None
    )
    target_ok = (
        isinstance(target_identity, Mapping)
        and set(target_identity)
        == {
            "source_name",
            "companion_role",
            "snapshot_sha256",
            "pre_sha256",
            "post_sha256",
            "stable",
            "endpoint_stable",
            "stability_scope",
            "temporal_immutability_enforced",
            "digest_stable",
            "source_metadata_stable",
            "snapshot_metadata_stable",
        }
        and type(target_identity.get("source_name")) is str
        and bool(target_identity.get("source_name"))
        and Path(target_identity["source_name"]).name
        == target_identity["source_name"]
        and type(target_identity.get("companion_role")) is str
        and target_identity.get("companion_role") == "target_snapshot"
        and all(
            type(target_identity.get(field)) is str
            and bool(
                re.fullmatch(
                    r"sha256:[0-9a-f]{64}",
                    target_identity.get(field),
                )
            )
            for field in (
                "snapshot_sha256",
                "pre_sha256",
                "post_sha256",
            )
        )
        and target_identity.get("snapshot_sha256") == target_sha
        and target_identity.get("pre_sha256") == target_sha
        and target_identity.get("post_sha256") == target_sha
        and target_identity.get("stability_scope")
        == "pre-post-endpoint"
        and target_identity.get("temporal_immutability_enforced") is False
        and all(
            type(target_identity.get(field)) is bool
            and target_identity.get(field) is True
            for field in (
                "stable",
                "endpoint_stable",
                "digest_stable",
                "source_metadata_stable",
                "snapshot_metadata_stable",
            )
        )
    )
    checks.append(
        Check(
            "formal target copy binds stable pre/post endpoints without claiming temporal immutability",
            target_ok,
            details=target_identity,
        )
    )

    gate_path = package_root / "skills/nozickian-verify/scripts/ntt_gate.py"
    gate_error = regular_file_error(gate_path)
    checks.append(
        Check(
            "current formal gate is a regular file",
            gate_error is None,
            details=gate_error,
        )
    )
    if gate_error is not None:
        return checks
    gate = load_module("ntt_gate_for_promotion_v2", gate_path)
    transcript = resolved_by_role.get("transcript")
    if transcript is not None:
        parsed_auth = runner.authenticate_trace(transcript)
        recorded_auth = data.get("trace_authentication")
        recorded_auth_schema_ok = trace_authentication_schema_valid(
            recorded_auth,
            trace_authentication_fields,
        )
        parsed_auth_schema_ok = trace_authentication_schema_valid(
            parsed_auth,
            trace_authentication_fields,
        )
        checks.append(
            Check(
                "formal trace authentication has exact JSON schema",
                recorded_auth_schema_ok,
                details={
                    "keys": (
                        sorted(str(key) for key in recorded_auth)
                        if isinstance(recorded_auth, Mapping)
                        else []
                    ),
                    "authenticated": (
                        recorded_auth.get("authenticated")
                        if isinstance(recorded_auth, Mapping)
                        else None
                    ),
                    "authenticated_type": (
                        type(recorded_auth.get("authenticated")).__name__
                        if isinstance(recorded_auth, Mapping)
                        else None
                    ),
                },
                failure_kind="INVALID_INPUT",
            )
        )
        checks.append(
            Check(
                "formal transcript re-authenticates and matches recorded semantics",
                recorded_auth_schema_ok
                and parsed_auth_schema_ok
                and parsed_auth.get("authenticated") is True
                and exact_json_equal(recorded_auth, parsed_auth),
                details={
                    "parsed_authenticated": parsed_auth.get("authenticated"),
                    "recorded_authenticated": (
                        recorded_auth.get("authenticated")
                        if isinstance(recorded_auth, Mapping)
                        else None
                    ),
                },
            )
        )
    certificate = resolved_by_role.get("certificate")
    if certificate is not None:
        certificate_data, certificate_error = try_load_json(certificate)
        if isinstance(certificate_data, Mapping):
            gate_result = gate.evaluate_certificate(
                certificate_data,
                evidence_root=result_dir,
                strict_evidence=True,
            )
        else:
            gate_result = {
                "status": "INVALID_INPUT",
                "reasons": [certificate_error],
            }
        checks.append(
            Check(
                "formal generated certificate strict gate PASS-TRACKED",
                gate_result.get("status") == PASS_TRACKED,
                details={
                    "status": gate_result.get("status"),
                    "reasons": gate_result.get("reasons"),
                },
            )
        )
    ledger = resolved_by_role.get("ledger")
    if ledger is not None:
        text = read_regular_text(ledger, errors="replace").lower()
        checks.append(
            Check(
                "formal ledger says no substitution",
                "substitution used: none" in text
                and "formal_subagent_failure" not in text,
                details=ledger.name,
            )
        )
    return checks


URI_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:")


def safe_relative_posix_path(value: Any) -> Tuple[Optional[PurePosixPath], Optional[str]]:
    if type(value) is not str or not value:
        return None, "path is not a nonempty string"
    if value != value.strip():
        return None, "path has surrounding whitespace"
    if "\\" in value:
        return None, "path uses a non-canonical separator"
    if URI_SCHEME_RE.match(value):
        return None, "path has a URI scheme"
    posix = PurePosixPath(value)
    if posix.is_absolute():
        return None, "path is absolute"
    if (
        not posix.parts
        or any(part in {"", ".", ".."} for part in posix.parts)
        or posix.as_posix() != value
    ):
        return None, "path is empty, dotted, or traverses"
    return posix, None


def bundle_regular_file(
    bundle: Path,
    value: Any,
) -> Tuple[Optional[Path], Optional[str], Optional[Tuple[int, int]]]:
    posix, path_error = safe_relative_posix_path(value)
    if path_error is not None or posix is None:
        return None, path_error, None
    current = bundle
    for index, part in enumerate(posix.parts):
        current = current / part
        try:
            mode = current.lstat().st_mode
        except OSError as exc:
            return (
                None,
                f"{type(exc).__name__} while inspecting bundle path",
                None,
            )
        final = index == len(posix.parts) - 1
        if stat.S_ISLNK(mode):
            return None, "bundle path contains a symbolic link", None
        if final:
            if not stat.S_ISREG(mode):
                return None, "bundle path is not a regular file", None
        elif not stat.S_ISDIR(mode):
            return None, "bundle path parent is not a directory", None
    try:
        stat_result = current.stat(follow_symlinks=False)
    except OSError as exc:
        return None, f"{type(exc).__name__} while inspecting bundle file", None
    return current, None, (stat_result.st_dev, stat_result.st_ino)


def required_promotion_roles(
    _allow_official_scope_exclusion: bool,
) -> set[str]:
    """Return the fixed promotion-v2 semantic role set.

    Official executable availability changes only fresh execution evidence. It
    never changes the certificate's evidence schema, role inventory, or DAG.
    """
    return set(PROMOTION_EVIDENCE_SPECS)


def required_promotion_dependencies(
    _allow_official_scope_exclusion: bool,
) -> Dict[str, List[str]]:
    """Return the fixed canonical dependency DAG for promotion certificate v2."""
    roles = set(PROMOTION_EVIDENCE_SPECS)
    return {
        role: list(PROMOTION_EVIDENCE_SPECS[role]["depends_on"])
        for role in sorted(roles)
    }


def promotion_evidence_nodes(
    data: Mapping[str, Any],
) -> Mapping[str, Any]:
    evidence = data.get("evidence")
    if type(evidence) is not dict:
        return {}
    nodes = evidence.get("nodes")
    return nodes if isinstance(nodes, Mapping) else {}


def iterative_evidence_graph_analysis(
    dependency_map: Mapping[str, Sequence[str]],
) -> Tuple[List[str], int]:
    """Return cyclic roles and maximum depth without recursive traversal."""
    indegree = {
        role: sum(
            1 for dependency in dependencies if dependency in dependency_map
        )
        for role, dependencies in dependency_map.items()
    }
    dependents: Dict[str, List[str]] = {
        role: [] for role in dependency_map
    }
    for role, dependencies in dependency_map.items():
        for dependency in dependencies:
            if dependency in dependents:
                dependents[dependency].append(role)
    queue = sorted(role for role, degree in indegree.items() if degree == 0)
    depths = {role: 1 for role in queue}
    visited: List[str] = []
    while queue:
        role = queue.pop(0)
        visited.append(role)
        for dependent in sorted(dependents[role]):
            depths[dependent] = max(
                depths.get(dependent, 1),
                depths[role] + 1,
            )
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                queue.append(dependent)
                queue.sort()
    cyclic = sorted(set(dependency_map) - set(visited))
    return cyclic, max(depths.values(), default=0)


def promotion_evidence_checks(
    bundle: Path,
    data: Mapping[str, Any],
    allow_official_scope_exclusion: bool,
) -> List[Check]:
    checks: List[Check] = []
    checks.append(
        Check(
            "legacy flat evidence_refs are rejected by promotion v2",
            "evidence_refs" not in data,
            details=(
                "remove evidence_refs and use evidence.nodes typed by semantic role"
                if "evidence_refs" in data
                else None
            ),
            failure_kind="INVALID_INPUT",
        )
    )
    evidence = data.get("evidence")
    if not isinstance(evidence, Mapping):
        checks.append(
            Check(
                "promotion certificate has typed evidence map",
                False,
                details="evidence is not an object",
                failure_kind="INVALID_INPUT",
            )
        )
        return checks
    checks.append(
        Check(
            "promotion evidence schema is v2",
            type(evidence.get("schema_version")) is str
            and evidence.get("schema_version") == PROMOTION_EVIDENCE_SCHEMA,
            details=evidence.get("schema_version"),
            failure_kind="INVALID_INPUT",
        )
    )
    checks.append(
        Check(
            "promotion evidence map has only schema_version and nodes",
            set(evidence) == {"schema_version", "nodes"},
            details=sorted(str(key) for key in evidence),
            failure_kind="INVALID_INPUT",
        )
    )
    nodes = evidence.get("nodes")
    if type(nodes) is not dict:
        checks.append(
            Check(
                "promotion evidence nodes is a typed map",
                False,
                details="nodes is not an object",
                failure_kind="INVALID_INPUT",
            )
        )
        return checks
    node_count_ok = len(nodes) <= MAX_EVIDENCE_NODES
    checks.append(
        Check(
            "promotion evidence node count is bounded",
            node_count_ok,
            details={"count": len(nodes), "maximum": MAX_EVIDENCE_NODES},
            failure_kind="INVALID_INPUT",
        )
    )
    if not node_count_ok:
        return checks

    required_roles = required_promotion_roles(
        allow_official_scope_exclusion
    )
    actual_roles = set(nodes) if all(type(key) is str for key in nodes) else set()
    checks.append(
        Check(
            "promotion evidence roles exactly match required semantic roles",
            actual_roles == required_roles,
            details={
                "missing": sorted(required_roles - actual_roles),
                "unexpected": sorted(actual_roles - required_roles),
            },
            failure_kind="INVALID_INPUT",
        )
    )
    if actual_roles != required_roles:
        return checks

    nodes_typed = True
    for role in sorted(required_roles):
        node_typed = type(nodes.get(role)) is dict
        checks.append(
            Check(
                f"promotion evidence node is typed: {role}",
                node_typed,
                details=(
                    None if node_typed else "node is not an object"
                ),
                failure_kind="INVALID_INPUT",
            )
        )
        nodes_typed = nodes_typed and node_typed
    if not nodes_typed:
        return checks

    canonical_paths: Dict[str, str] = {}
    file_identities: Dict[Tuple[int, int], str] = {}
    dependency_map: Dict[str, List[str]] = {}
    for role, node in nodes.items():
        path_value = node.get("path")
        claimed_sha = node.get("sha256")
        depends_on = node.get("depends_on")
        dependencies_valid = (
            isinstance(depends_on, list)
            and len(depends_on) <= MAX_EVIDENCE_DEPENDENCIES
            and all(type(item) is str and item for item in depends_on)
            and len(set(depends_on)) == len(depends_on)
        )
        node_keys_valid = set(node) == {
            "path",
            "sha256",
            "depends_on",
        }
        dependency_map[role] = list(depends_on) if dependencies_valid else []
        checks.append(
            Check(
                f"promotion evidence node fields are typed: {role}",
                node_keys_valid
                and type(path_value) is str
                and type(claimed_sha) is str
                and bool(re.fullmatch(r"sha256:[0-9a-f]{64}", claimed_sha))
                and dependencies_valid,
                details={
                    "path": path_value,
                    "sha256": claimed_sha,
                    "depends_on": depends_on,
                    "keys": sorted(str(key) for key in node),
                },
                failure_kind="INVALID_INPUT",
            )
        )
        if type(path_value) is not str:
            continue
        path, path_error, file_identity = bundle_regular_file(
            bundle,
            path_value,
        )
        checks.append(
            Check(
                f"promotion evidence role resolves to bundle-local regular file: {role}",
                path_error is None and path is not None,
                details=path_error or path_value,
                failure_kind="INVALID_INPUT",
            )
        )
        if path is None:
            continue
        canonical = relpath(bundle, path)
        alias_role = canonical_paths.get(canonical)
        identity_role = (
            file_identities.get(file_identity)
            if file_identity is not None
            else None
        )
        alias_error = (
            f"path aliases role {alias_role}"
            if alias_role is not None
            else (
                f"file identity aliases role {identity_role}"
                if identity_role is not None
                else None
            )
        )
        checks.append(
            Check(
                f"promotion evidence role has distinct path/file identity: {role}",
                alias_error is None,
                details=alias_error or canonical,
                failure_kind="INVALID_INPUT",
            )
        )
        canonical_paths[canonical] = role
        if file_identity is not None:
            file_identities[file_identity] = role
        try:
            actual_sha = f"sha256:{sha256_path(path)}"
        except (OSError, ValueError):
            actual_sha = None
        checks.append(
            Check(
                f"promotion evidence role exact bytes match sha256: {role}",
                actual_sha is not None and claimed_sha == actual_sha,
                details={"claimed": claimed_sha, "actual": actual_sha},
            )
        )

        expected_path = PROMOTION_EVIDENCE_SPECS[role].get("path")
        if expected_path is not None:
            lane_path_ok = canonical == expected_path
        elif role == "formal.result":
            parts = PurePosixPath(canonical).parts
            lane_path_ok = (
                len(parts) == 3
                and parts[0] == "formal_artifacts"
                and parts[1] not in {"", ".", ".."}
                and parts[2] == "formal_result.json"
            )
        else:
            lane_path_ok = False
        checks.append(
            Check(
                f"promotion evidence role points to canonical lane: {role}",
                lane_path_ok,
                details=canonical,
                failure_kind="INVALID_INPUT",
            )
        )
        spec = PROMOTION_EVIDENCE_SPECS[role]
        if spec.get("kind") == "official-policy":
            policy, policy_error = try_load_json(path)
            expected_validator = spec.get("validator_id")
            policy_ok = (
                policy_error is None
                and isinstance(policy, Mapping)
                and set(policy) == {
                    "policy_schema_version",
                    "required_validator_id",
                }
                and type(policy.get("policy_schema_version")) is str
                and policy.get("policy_schema_version")
                == OFFICIAL_POLICY_SCHEMA
                and type(policy.get("required_validator_id")) is str
                and policy.get("required_validator_id")
                == expected_validator
            )
            checks.append(
                Check(
                    f"official validator policy declares required id: {expected_validator}",
                    policy_ok,
                    details=policy_error or policy,
                    failure_kind="INVALID_INPUT",
                )
            )

    unknown_dependencies = sorted(
        {
            dependency
            for dependencies in dependency_map.values()
            for dependency in dependencies
            if dependency not in nodes
        }
    )
    checks.append(
        Check(
            "promotion evidence dependencies name declared roles",
            not unknown_dependencies,
            details=unknown_dependencies,
            failure_kind="INVALID_INPUT",
        )
    )
    expected_dependencies = required_promotion_dependencies(
        allow_official_scope_exclusion
    )
    dependency_contract_ok = (
        actual_roles == required_roles
        and dependency_map == expected_dependencies
    )
    checks.append(
        Check(
            "promotion evidence dependencies match canonical role DAG",
            dependency_contract_ok,
            details={
                "recorded": dependency_map,
                "expected": expected_dependencies,
            },
            failure_kind="INVALID_INPUT",
        )
    )
    cycle, graph_depth = iterative_evidence_graph_analysis(dependency_map)
    checks.append(
        Check(
            "promotion evidence dependency graph is acyclic",
            not cycle,
            details=cycle,
            failure_kind="INVALID_INPUT",
        )
    )
    checks.append(
        Check(
            "promotion evidence dependency depth is bounded",
            not cycle and graph_depth <= MAX_EVIDENCE_GRAPH_DEPTH,
            details={
                "depth": graph_depth,
                "maximum": MAX_EVIDENCE_GRAPH_DEPTH,
            },
            failure_kind="INVALID_INPUT",
        )
    )
    return checks


def package_tree_sha256(package_root: Path) -> Dict[str, Any]:
    """Delegate stable-tree verification to the current package validator."""
    validator_path = (
        package_root
        / "skills/nozickian-verify/scripts/validate_package.py"
    )
    validator_error = regular_file_error(validator_path)
    if validator_error is not None:
        return {
            "algorithm": None,
            "valid": False,
            "sha256": None,
            "errors": [
                "current package validator is not a regular file: "
                + validator_error
            ],
        }
    try:
        validator_module = load_module(
            "ntt_current_validator_for_package_tree",
            validator_path,
        )
        shared_tree = getattr(
            validator_module,
            "compute_stable_release_tree",
            None,
        )
        if not callable(shared_tree):
            raise AttributeError(
                "compute_stable_release_tree is not callable"
            )
        result = shared_tree(package_root)
        if not isinstance(result, Mapping):
            raise TypeError(
                "compute_stable_release_tree did not return an object"
            )
        return dict(result)
    except Exception as exc:
        return {
            "algorithm": None,
            "valid": False,
            "sha256": None,
            "errors": [
                "shared package-tree computation failed: "
                f"{type(exc).__name__}"
            ],
        }


def promotion_claim_validation_errors(data: Mapping[str, Any]) -> List[str]:
    """Validate every promotion claim before invoking the shared gate."""
    claims = data.get("claims")
    if type(claims) is not list:
        return ["claims is not an array"]
    errors: List[str] = []
    if not claims:
        errors.append("claims must contain at least one promotion claim")
    claim_ids: set[str] = set()
    for index, claim in enumerate(claims):
        label = f"claims[{index}]"
        if type(claim) is not dict:
            json_type = (
                "null"
                if claim is None
                else "boolean"
                if type(claim) is bool
                else "number"
                if type(claim) in {int, float}
                else type(claim).__name__
            )
            errors.append(f"{label} is not an object ({json_type})")
            continue
        missing = sorted(
            field
            for field in PROMOTION_CLAIM_REQUIRED_FIELD_TYPES
            if field not in claim
        )
        if missing:
            errors.append(f"{label} missing required fields: {missing}")
        wrong_types = sorted(
            field
            for field, expected_type in PROMOTION_CLAIM_REQUIRED_FIELD_TYPES.items()
            if field in claim and type(claim.get(field)) is not expected_type
        )
        if wrong_types:
            errors.append(f"{label} fields have invalid exact types: {wrong_types}")
        claim_id = claim.get("id")
        if type(claim_id) is not str or not PROMOTION_CLAIM_ID_RE.fullmatch(
            claim_id
        ):
            errors.append(f"{label}.id is not a canonical claim identifier")
        elif claim_id in claim_ids:
            errors.append(f"duplicate promotion claim id: {claim_id}")
        else:
            claim_ids.add(claim_id)
        for field in ("evidence_refs",):
            value = claim.get(field)
            if type(value) is list and not all(
                type(item) is str and bool(item) for item in value
            ):
                errors.append(f"{label}.{field} contains a non-string/empty entry")
        if "method_completeness" in claim and type(
            claim.get("method_completeness")
        ) not in {int, float}:
            errors.append(
                f"{label}.method_completeness is not an exact JSON number"
            )
    return errors


def promotion_certificate_checks(
    package_root: Path,
    bundle: Path,
    allow_official_scope_exclusion: bool = False,
) -> List[Check]:
    checks: List[Check] = []
    path = bundle / "promotion_certificate.json"
    certificate_error = regular_file_error(path)
    checks.append(
        Check(
            "promotion certificate present as regular file",
            certificate_error is None,
            details=certificate_error or relpath(bundle, path),
        )
    )
    if certificate_error is not None:
        return checks
    data, err = try_load_json(path)
    checks.append(Check("promotion certificate parses", err is None, details=err))
    if not isinstance(data, Mapping):
        return checks
    schema_value = data.get("promotion_schema_version")
    checks.append(
        Check(
            "promotion certificate schema version is exact string 2.0",
            type(schema_value) is str
            and schema_value == PROMOTION_CERTIFICATE_SCHEMA,
            details={
                "recorded": schema_value,
                "recorded_type": type(schema_value).__name__,
                "expected": PROMOTION_CERTIFICATE_SCHEMA,
            },
            failure_kind="INVALID_INPUT",
        )
    )
    missing_required_fields = sorted(
        field
        for field in PROMOTION_CERTIFICATE_REQUIRED_FIELD_TYPES
        if field not in data
    )
    wrong_required_field_types = {
        field: {
            "recorded": type(data.get(field)).__name__,
            "expected": expected_type.__name__,
        }
        for field, expected_type
        in PROMOTION_CERTIFICATE_REQUIRED_FIELD_TYPES.items()
        if field in data and type(data.get(field)) is not expected_type
    }
    wrong_optional_field_types = {
        field: {
            "recorded": type(data.get(field)).__name__,
            "expected": expected_type.__name__,
        }
        for field, expected_type
        in PROMOTION_CERTIFICATE_OPTIONAL_FIELD_TYPES.items()
        if field in data and type(data.get(field)) is not expected_type
    }
    checks.append(
        Check(
            "promotion certificate required top-level fields have exact JSON types",
            not missing_required_fields
            and not wrong_required_field_types
            and not wrong_optional_field_types,
            details={
                "missing": missing_required_fields,
                "wrong_required_types": wrong_required_field_types,
                "wrong_optional_types": wrong_optional_field_types,
            },
            failure_kind="INVALID_INPUT",
        )
    )
    claim_errors = promotion_claim_validation_errors(data)
    claims_shape_valid = not claim_errors
    checks.append(
        Check(
            "promotion claims have required exact types and unique canonical ids",
            claims_shape_valid,
            details=claim_errors,
            failure_kind="INVALID_INPUT",
        )
    )
    checks.append(Check("promotion certificate records upgrade_from_status PASS-SCOPED", type(data.get("upgrade_from_status")) is str and data.get("upgrade_from_status") == PASS_SCOPED, details=data.get("upgrade_from_status"), failure_kind="INVALID_INPUT"))
    checks.append(Check("promotion certificate requests PASS-TRACKED", type(data.get("requested_status")) is str and data.get("requested_status") == PASS_TRACKED, details=data.get("requested_status"), failure_kind="INVALID_INPUT"))
    plugin = try_load_json(package_root / ".claude-plugin/plugin.json")[0] or {}
    current_version = str(plugin.get("version") or "")
    checks.append(Check("promotion certificate package version matches plugin", type(data.get("package_version")) is str and data.get("package_version") == current_version, details={"certificate": data.get("package_version"), "plugin": current_version, "plugin_version_alias_ignored": data.get("plugin_version")}, failure_kind="INVALID_INPUT"))
    tree = package_tree_sha256(package_root)
    checks.append(
        Check(
            "current package tree verifies against stable release manifest",
            tree.get("valid") is True,
            details=tree,
        )
    )
    expected_tree_digest = (
        f"sha256:{tree['sha256']}" if tree.get("valid") is True else None
    )
    digest = data.get("package_tree_sha256")
    checks.append(
        Check(
            "promotion certificate package_tree_sha256 matches current package tree",
            isinstance(digest, str)
            and digest == expected_tree_digest
            and bool(re.fullmatch(r"sha256:[0-9a-f]{64}", digest)),
            details={
                "certificate": digest,
                "expected": expected_tree_digest,
                "package_sha256_alias_ignored": data.get("package_sha256"),
            },
        )
    )
    checks.extend(
        promotion_evidence_checks(
            bundle,
            data,
            allow_official_scope_exclusion,
        )
    )
    gate_path = (
        package_root / "skills/nozickian-verify/scripts/ntt_gate.py"
    )
    downstream_reasons: List[str] = []
    downstream_count = 0
    try:
        gate = load_module(
            "ntt_gate_for_promotion_downstream_policy",
            gate_path,
        )
        if claims_shape_valid:
            gate_result = gate.evaluate_certificate(
                data,
                evidence_root=bundle,
                strict_evidence=True,
                downstream_policy="promotion-v2",
            )
            raw_claim_results = gate_result.get("claim_results")
            claim_results = (
                {
                    result["claim_id"]: result
                    for result in raw_claim_results
                    if type(result) is dict
                    and type(result.get("claim_id")) is str
                }
                if type(raw_claim_results) is list
                else {}
            )
            claims = data.get("claims")
            claims_pass = (
                type(raw_claim_results) is list
                and bool(raw_claim_results)
                and type(claims) is list
                and len(raw_claim_results) == len(claims)
                and all(
                    type(result) is dict
                    and result.get("status") == "PASS"
                    for result in raw_claim_results
                )
            )
            checks.append(
                Check(
                    "promotion claims pass canonical strict gate evaluation",
                    claims_pass,
                    details={
                        "gate_status": gate_result.get("status"),
                        "claim_statuses": {
                            claim_id: result.get("status")
                            for claim_id, result in claim_results.items()
                        },
                        "evidence_root": ".",
                        "downstream_policy": "promotion-v2",
                    },
                )
            )
            downstream_reasons, downstream_count = (
                gate.evaluate_downstream_nonclosure(
                    data,
                    claim_results,
                    policy="promotion-v2",
                )
            )
        else:
            downstream_reasons = [
                "promotion claims failed pre-evaluation schema validation"
            ]
    except Exception as exc:
        downstream_reasons = [
            "shared downstream evaluator unavailable: "
            f"{type(exc).__name__}"
        ]
        downstream_count = 0
    if claims_shape_valid:
        checks.append(
            Check(
                "promotion v2 downstream review prevents automatic closure",
                not downstream_reasons,
                details={
                    "records": downstream_count,
                    "reasons": downstream_reasons,
                },
                failure_kind="INVALID_INPUT",
            )
        )
    return checks


def stale_token_checks(package_root: Path, bundle: Path) -> List[Check]:
    checks: List[Check] = []
    plugin = try_load_json(package_root / ".claude-plugin/plugin.json")[0] or {}
    current = str(plugin.get("version") or "")
    # Compose stale-token patterns so this certifier does not fail by matching
    # its own guard literals while still rejecting the actual stale strings in
    # package or audit-bundle evidence.
    local_data = "/" + "mnt" + "/" + "data"
    local_home = "/" + "home" + "/" + "oai"
    prior_patch = "0\\.7\\." + "13"
    prior_label = "v" + prior_patch
    prior_probe = "v07" + "13"
    prior_root = "nozickian-truth-tracking-agentic-v" + prior_patch
    stale_patterns = [re.escape(local_data), re.escape(local_home), prior_label, prior_patch, prior_probe, prior_root]
    hits: List[Dict[str, Any]] = []
    unsafe: List[Dict[str, Any]] = []
    total_bytes = 0
    for root_label, root in (("package", package_root), ("bundle", bundle)):
        if directory_error(root) is not None:
            unsafe.append(
                {
                    "root": root_label,
                    "path": ".",
                    "kind": "invalid-root",
                    "error": directory_error(root),
                }
            )
            continue
        try:
            for p, kind, entry_error in walk_tree_no_follow_bounded(
                root,
                skip_dir_names=(".git", "__pycache__"),
                max_entries=MAX_STALE_SCAN_ENTRIES,
            ):
                rel = relpath(root, p)
                if kind == "directory":
                    continue
                if kind != "regular":
                    unsafe.append(
                        {
                            "root": root_label,
                            "path": rel,
                            "kind": kind,
                            "error": entry_error,
                        }
                    )
                    continue
                if p.suffix == ".pyc":
                    continue
                try:
                    text, read_bytes = read_regular_text_bounded(
                        p,
                        max_bytes=MAX_STALE_SCAN_FILE_BYTES,
                    )
                    total_bytes += read_bytes
                    if total_bytes > MAX_STALE_SCAN_TOTAL_BYTES:
                        raise ResourceBoundError(
                            "aggregate stale-token scan byte limit exceeded"
                        )
                except Exception as exc:
                    unsafe.append(
                        {
                            "root": root_label,
                            "path": rel,
                            "kind": "unreadable-or-over-limit",
                            "error": (
                                f"{type(exc).__name__}: regular file unreadable or over limit"
                            ),
                        }
                    )
                    if isinstance(exc, ResourceBoundError):
                        break
                    continue
                for pat in stale_patterns:
                    m = re.search(pat, text)
                    if m:
                        hits.append(
                            {
                                "root": root_label,
                                "path": rel,
                                "pattern": pat,
                            }
                        )
                        break
        except ResourceBoundError as exc:
            unsafe.append(
                {
                    "root": root_label,
                    "path": ".",
                    "kind": "resource-limit",
                    "error": str(exc),
                }
            )
    for item in unsafe:
        checks.append(
            Check(
                f"stale-token input is readable regular file: {item['root']}:{item['path']}",
                False,
                details=item,
            )
        )
    checks.append(Check("no stale local path or prior-version tokens in package/bundle evidence", not hits, details=hits[:20]))
    checks.append(Check("current plugin version is semver", bool(re.fullmatch(r"\d+\.\d+\.\d+", current)), details=current))
    return checks


def summarize(checks: List[Check]) -> Dict[str, Any]:
    critical_failed = [c for c in checks if c.severity == "critical" and not c.passed]
    major_failed = [c for c in checks if c.severity == "major" and not c.passed]
    return {
        "checks_total": len(checks),
        "checks_passed": sum(1 for c in checks if c.passed),
        "critical_failed": len(critical_failed),
        "major_failed": len(major_failed),
        "checks": [asdict(c) for c in checks],
        "failed_checks": [asdict(c) for c in checks if not c.passed],
    }


def finalize_promotion_result(
    checks: List[Check],
    *,
    allow_official_scope_exclusion: bool,
    execution_evidence: Mapping[str, Any],
    synthetic_origin: bool,
) -> Dict[str, Any]:
    base = summarize(checks)
    failed = [check for check in checks if not check.passed]
    invalid = [
        check for check in failed if check.failure_kind == "INVALID_INPUT"
    ]
    internal = [
        check for check in failed if check.failure_kind == "INTERNAL_ERROR"
    ]
    modeled_passed = not failed
    result = {
        **base,
        "status": PASS_SCOPED if modeled_passed else "FAIL",
        "modeled_promotion_checks_passed": modeled_passed,
        "promotion_authorized": False,
        "synthetic_origin": synthetic_origin,
        "official_validator_scope_exclusion_requested": bool(
            allow_official_scope_exclusion
        ),
        "execution_evidence": dict(execution_evidence),
    }
    if modeled_passed:
        # v1.0.3 cannot satisfy the still-unimplemented Issue #5 charter
        # mechanics. The certifier alone is capped; generic gate/formal PASS
        # semantics remain unchanged.
        result.update({
            "outcome": "CAPPED",
            "satisfied_profile": PROMOTION_PROFILE,
            "unresolved_charter_obligations": list(
                ISSUE_5_UNRESOLVED_OBLIGATIONS
            ),
            "scope_cap_reason": (
                "v1.0.3 Issue #5 charter mechanics are not implemented"
            ),
        })
    else:
        result.update({
            "outcome": "FAILED",
            "failure_kind": (
                "INTERNAL_ERROR"
                if internal
                else "INVALID_INPUT"
                if invalid
                else "CHECK_FAILED"
            ),
        })
    return result


def normalize_result_paths(
    value: Any,
    replacements: Sequence[Tuple[str, str]],
) -> Any:
    if isinstance(value, str):
        normalized = value
        for raw, display in sorted(
            replacements,
            key=lambda item: len(item[0]),
            reverse=True,
        ):
            if raw:
                normalized = re.sub(
                    re.escape(raw) + r"(?=$|[\\/])",
                    lambda _match, replacement=display: replacement,
                    normalized,
                )
        return normalized
    if isinstance(value, list):
        return [normalize_result_paths(item, replacements) for item in value]
    if isinstance(value, tuple):
        return [normalize_result_paths(item, replacements) for item in value]
    if isinstance(value, Mapping):
        return {
            key: normalize_result_paths(item, replacements)
            for key, item in value.items()
        }
    return value


def to_markdown(result: Mapping[str, Any]) -> str:
    lines = ["# PASS-TRACKED upgrade certification", "", f"Status: **{result.get('status')}**", "", "| Check | Severity | Result | Details |", "|---|---|---:|---|"]
    for c in result.get("checks", []):
        details = json.dumps(c.get("details"), sort_keys=True)[:600] if c.get("details") is not None else ""
        lines.append(f"| {c.get('name')} | {c.get('severity')} | {'PASS' if c.get('passed') else 'FAIL'} | {details} |")
    return "\n".join(lines) + "\n"


def certify_bundle(
    package_root: Path,
    bundle: Path,
    *,
    run_fresh_compat: bool = False,
    allow_official_scope_exclusion: bool = False,
) -> Dict[str, Any]:
    checks: List[Check] = []
    execution_evidence: Dict[str, Any] = {
        "deterministic": {},
        "official_validators": {},
    }
    synthetic_origin = False
    package_root_error = directory_error(package_root)
    bundle_error = directory_error(bundle)
    checks.append(
        Check(
            "package root exists as regular directory",
            package_root_error is None,
            details=package_root_error or str(package_root),
            failure_kind="INVALID_INPUT",
        )
    )
    checks.append(
        Check(
            "audit bundle exists as regular directory",
            bundle_error is None,
            details=bundle_error or str(bundle),
            failure_kind="INVALID_INPUT",
        )
    )
    try:
        if package_root_error is None and bundle_error is None:
            plugin_data, plugin_error = try_load_json(
                package_root / ".claude-plugin/plugin.json"
            )
            plugin_version = (
                plugin_data.get("version")
                if isinstance(plugin_data, Mapping)
                else None
            )
            checks.append(
                Check(
                    "promotion certifier profile applies to package v1.0.3",
                    plugin_error is None and plugin_version == "1.0.3",
                    details=plugin_version,
                    failure_kind="INVALID_INPUT",
                )
            )
            certificate_data, _certificate_error = try_load_json(
                bundle / "promotion_certificate.json"
            )
            synthetic_origin = (
                isinstance(certificate_data, Mapping)
                and certificate_data.get("origin") == "synthetic-contract"
            )
            checks.extend(
                deterministic_checks(
                    package_root,
                    bundle,
                    run_fresh_compat,
                    execution_evidence["deterministic"],
                )
            )
            checks.extend(
                official_validator_checks(
                    package_root,
                    bundle,
                    allow_official_scope_exclusion,
                    execution_evidence["official_validators"],
                )
            )
            checks.extend(live_fixture_checks(package_root, bundle))
            promotion_checks = promotion_certificate_checks(
                package_root,
                bundle,
                allow_official_scope_exclusion,
            )
            checks.extend(promotion_checks)
            formal_locator_blocked = any(
                not check.passed
                and (
                    check.name
                    == (
                        "promotion evidence roles exactly match required "
                        "semantic roles"
                    )
                    or check.name.startswith(
                        "promotion evidence node is typed:"
                    )
                )
                for check in promotion_checks
            )
            if not formal_locator_blocked:
                checks.extend(formal_artifact_checks(package_root, bundle))
            checks.extend(stale_token_checks(package_root, bundle))
        return finalize_promotion_result(
            checks,
            allow_official_scope_exclusion=(
                allow_official_scope_exclusion
            ),
            execution_evidence=execution_evidence,
            synthetic_origin=synthetic_origin,
        )
    except Exception:
        return {
            "status": "FAIL",
            "outcome": "FAILED",
            "failure_kind": "INTERNAL_ERROR",
            "promotion_authorized": False,
            "reason": (
                "unexpected certifier implementation failure; "
                "internal details omitted"
            ),
            "checks": [asdict(check) for check in checks],
            "failed_checks": [
                asdict(check) for check in checks if not check.passed
            ],
        }




def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Certify a PASS-SCOPED to PASS-TRACKED Nozickian upgrade audit bundle")
    parser.add_argument("package_root", type=Path)
    parser.add_argument("audit_bundle", type=Path)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--markdown", type=Path)
    parser.add_argument(
        "--run-fresh-package-validator",
        action="store_true",
        help=(
            "compatibility flag; the current basic validate_package.py run is "
            "now unconditional for every promotion attempt"
        ),
    )
    parser.add_argument("--allow-official-validator-scope-exclusion", action="store_true", help="do not fail when official Claude Code validators are missing; the result remains PASS-SCOPED rather than PASS-TRACKED")
    args = parser.parse_args(argv)

    package_root = Path(os.path.abspath(args.package_root))
    bundle = Path(os.path.abspath(args.audit_bundle))
    json_path = Path(os.path.abspath(args.json)) if args.json else None
    markdown_path = (
        Path(os.path.abspath(args.markdown)) if args.markdown else None
    )
    if (
        json_path is not None
        and markdown_path is not None
        and _paths_alias(json_path, markdown_path)
    ):
        invalid = {
            "status": "FAIL",
            "outcome": "FAILED",
            "failure_kind": "INVALID_INPUT",
            "promotion_authorized": False,
            "reason": (
                "unsafe output paths: --json and --markdown destinations alias"
            ),
        }
        print(json.dumps(invalid, indent=2, sort_keys=True))
        return 2
    output_capabilities: Dict[str, Tuple[Path, int]] = {}
    for label, path in (("json", json_path), ("markdown", markdown_path)):
        if path is None:
            continue
        descriptor: Optional[int] = None
        try:
            descriptor = _open_directory_no_follow(path.parent)
            if not _directory_path_matches_fd(path.parent, descriptor):
                raise ValueError("output parent identity is unstable")
            _replaceable_regular_at(descriptor, _safe_output_name(path))
            output_capabilities[label] = (path, descriptor)
        except (OSError, ValueError):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            for _path, held_fd in output_capabilities.values():
                os.close(held_fd)
            invalid = {
                "status": "FAIL",
                "outcome": "FAILED",
                "failure_kind": "INVALID_INPUT",
                "promotion_authorized": False,
                "reason": f"unsafe --{label} output path was rejected",
            }
            print(json.dumps(invalid, indent=2, sort_keys=True))
            return 2
    result = certify_bundle(
        package_root,
        bundle,
        run_fresh_compat=args.run_fresh_package_validator,
        allow_official_scope_exclusion=(
            args.allow_official_validator_scope_exclusion
        ),
    )
    display_result = normalize_result_paths(
        result,
        (
            (str(package_root), "<package-root>"),
            (str(bundle), "<audit-bundle>"),
        ),
    )
    if json_path is not None:
        try:
            atomic_replace_regular_text(
                json_path,
                json.dumps(display_result, indent=2, sort_keys=True) + "\n",
                directory_fd=output_capabilities["json"][1],
                lexical_parent=json_path.parent,
            )
        except (OSError, ValueError):
            invalid = {
                "status": "FAIL",
                "outcome": "FAILED",
                "failure_kind": "INVALID_INPUT",
                "promotion_authorized": False,
                "reason": "unsafe --json output path was rejected",
            }
            print(json.dumps(invalid, indent=2, sort_keys=True))
            for _path, held_fd in output_capabilities.values():
                os.close(held_fd)
            return 2
    if markdown_path is not None:
        try:
            atomic_replace_regular_text(
                markdown_path,
                to_markdown(display_result),
                directory_fd=output_capabilities["markdown"][1],
                lexical_parent=markdown_path.parent,
            )
        except (OSError, ValueError):
            invalid = {
                "status": "FAIL",
                "outcome": "FAILED",
                "failure_kind": "INVALID_INPUT",
                "promotion_authorized": False,
                "reason": "unsafe --markdown output path was rejected",
            }
            print(json.dumps(invalid, indent=2, sort_keys=True))
            for _path, held_fd in output_capabilities.values():
                os.close(held_fd)
            return 2
    print(json.dumps(display_result, indent=2, sort_keys=True))
    for _path, held_fd in output_capabilities.values():
        os.close(held_fd)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
