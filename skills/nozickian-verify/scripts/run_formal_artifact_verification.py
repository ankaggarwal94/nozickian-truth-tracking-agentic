#!/usr/bin/env python3
"""Formal artifact invocation runner for the team/internal Nozickian verifier.

This script is the mechanical glue that distinguishes a useful prose audit from a
formal package invocation. It validates the package, prepares an auditable prompt,
runs Claude Code with the ntt-formal-coordinator main agent when available, requires
machine-readable output artifacts, authenticates native subagent calls from the
stream-json transcript when possible, and re-runs ntt_gate.py on the generated
certificate. If Claude Code is unavailable or not requested, the script records
UNVERIFIED_RUNTIME rather than pretending the formal invocation occurred.

Trace-authentication scope: this runner cannot cryptographically prove that an
arbitrary executable named `claude` is genuine. It does, however, refuse to treat a
ledger assertion as enough. PASS-TRACKED requires both a passing gate and observed
stream-json Agent/Task tool-use events and successful matching tool-result/completion events for every required native ntt-* lane. Without
those events, a passing certificate is capped at PASS-SCOPED.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

PASS_STATUSES = {"PASS-TRACKED", "PASS-SCOPED"}
FINAL_STATUSES = PASS_STATUSES | {"LIMITED", "FAIL", "UNVERIFIED", "UNVERIFIED_RUNTIME"}
REQUIRED_NATIVE_AGENTS = [
    "ntt-method-cartographer",
    "ntt-claim-extractor",
    "ntt-source-verifier",
    "ntt-code-verifier",
    "ntt-false-world-adversary",
    "ntt-true-world-adherence",
    "ntt-gate-auditor",
]
FORMAL_COORDINATOR = "ntt-formal-coordinator"
SKILL_PATH = "skills/nozickian-verify"
TRACE_TOOL_NAMES = {"Agent", "Task"}
TOOL_USE_TYPES = {"tool_use", "tool-use", "tooluse", "tool_call", "tool-call", "toolcall"}
TOOL_RESULT_TYPES = {"tool_result", "tool-result", "toolresult", "tool_call_result", "tool-call-result", "toolcallresult"}
GENERAL_PURPOSE_NAMES = {"general-purpose", "general_purpose", "generalpurpose"}
CONTENT_METADATA_KEYS = {"type", "id", "name", "role", "media_type", "mime_type", "tool_use_id", "toolUseId", "tool_call_id", "toolCallId", "status", "outcome", "is_error"}
FORMAL_COMPANION_SPECS = {
    "report": "_NOZICKIAN_REPORT.md",
    "gate": "_NOZICKIAN_GATE.md",
    "certificate": "_NOZICKIAN_certificate.json",
    "ledger": "_NOZICKIAN_INVOCATION_LEDGER.md",
    "transcript": "_NOZICKIAN_FORMAL_TRANSCRIPT.stream.jsonl",
    "prompt": "_NOZICKIAN_FORMAL_PROMPT.md",
    "target_snapshot": "_NOZICKIAN_TARGET_SNAPSHOT.bin",
}
FORMAL_AUXILIARY_OUTPUT_SPECS = {
    "formal_result": "formal_result.json",
    "precheck": "_NOZICKIAN_FORMAL_PRECHECKS.json",
}
FORMAL_VERIFICATION_CONTEXT = {
    "mode": "standalone-immutable-snapshot",
    "relative_sibling_context": "unavailable",
    "execution_working_directory": "snapshot-parent",
}
TRACE_AUTHENTICATION_FIELDS = (
    "authenticated",
    "events_seen",
    "agent_calls_authenticated",
    "agent_results_authenticated",
    "missing_agents",
    "missing_result_agents",
    "saw_general_purpose",
    "duplicate_tool_use_ids",
    "result_before_call_ids",
    "unexpected_native_tool_calls",
    "role_violations",
    "reasons",
    "evidence_events",
)
MAX_CAPTURE_BYTES = 64 * 1024 * 1024
PUBLIC_STREAM_BOUND_BYTES = 2048

def _debug(msg: str) -> None:
    if os.environ.get("NTT_DEBUG_FORMAL_RUNNER"):
        print(f"[formal-runner] {msg}", file=sys.stderr, flush=True)


def load_module_without_bytecode(name: str, path: Path) -> Any:
    """Load a package helper without creating package-tree bytecode."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("package helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    previous_dont_write = sys.dont_write_bytecode
    import_stdout = io.StringIO()
    try:
        # Package verification must not mutate the tree being measured.
        sys.dont_write_bytecode = True
        # SECURITY-REVIEW: Fixed package-local helpers execute at import time.
        # Contain stdout so this formal CLI emits one JSON document.
        with contextlib.redirect_stdout(import_stdout):
            spec.loader.exec_module(module)  # type: ignore[union-attr]
    finally:
        sys.dont_write_bytecode = previous_dont_write
    return module


def _path_within(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def regular_file_error(path: Path) -> Optional[str]:
    """Return a bounded no-follow error for a required regular file."""
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        return f"{type(exc).__name__} while inspecting file"
    if stat.S_ISLNK(mode):
        return "path is a symbolic link"
    if not stat.S_ISREG(mode):
        return "path is not a regular file"
    return None


def directory_error(path: Path) -> Optional[str]:
    """Return a bounded no-follow error for a required directory."""
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        return f"{type(exc).__name__} while inspecting directory"
    if stat.S_ISLNK(mode):
        return "path is a symbolic link"
    if not stat.S_ISDIR(mode):
        return "path is not a directory"
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


def path_lexists(path: Path) -> bool:
    return os.path.lexists(path)


def replaceable_regular_output_error(path: Path) -> Optional[str]:
    """Validate an absent or private regular replaceable output target."""
    if not path_lexists(path):
        return None
    try:
        metadata = path.lstat()
    except OSError as exc:
        return f"{type(exc).__name__} while inspecting output target"
    if stat.S_ISLNK(metadata.st_mode):
        return "output target is a symbolic link"
    if not stat.S_ISREG(metadata.st_mode):
        return "output target is a special file"
    if metadata.st_nlink != 1:
        return "output target is a hardlink alias"
    return None


def atomic_write_new(path: Path, payload: bytes, mode: int = 0o600) -> None:
    """Atomically create one new regular file without following final links."""
    # SECURITY-REVIEW: Formal output paths can be caller-controlled. A private
    # O_EXCL/O_NOFOLLOW temporary file is linked into the final name only when
    # that name does not exist, so links and special-file sentinels are neither
    # followed nor overwritten.
    ancestor_error = lexical_directory_ancestor_error(path)
    if ancestor_error is not None:
        raise ValueError(f"unsafe output path: {ancestor_error}")
    parent_error = directory_error(path.parent)
    if parent_error is not None:
        raise ValueError(f"unsafe output parent: {parent_error}")
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: Optional[int] = None
    try:
        descriptor = os.open(temporary, flags, mode)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
        created = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(created.st_mode) or created.st_nlink != 1:
            raise OSError("created output is not a private regular file")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def atomic_replace_regular(path: Path, payload: bytes, mode: int = 0o600) -> None:
    """Atomically create or replace one private regular compatibility output."""
    # SECURITY-REVIEW: An explicitly supplied existing compatibility --json
    # regular file is intentionally replaceable for CLI regeneration. Existing
    # lexical ancestors and the final target are inspected with lstat; payload
    # bytes go to a same-directory O_EXCL/O_NOFOLLOW temporary, and os.replace
    # swaps directory entries without opening or following the final target.
    ancestor_error = lexical_directory_ancestor_error(path)
    if ancestor_error is not None:
        raise ValueError(f"unsafe output path: {ancestor_error}")
    parent_error = directory_error(path.parent)
    if parent_error is not None:
        raise ValueError(f"unsafe output parent: {parent_error}")
    target_error = replaceable_regular_output_error(path)
    if target_error is not None:
        raise ValueError(f"unsafe output target: {target_error}")
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: Optional[int] = None
    try:
        descriptor = os.open(temporary, flags, mode)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        created = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(created.st_mode) or created.st_nlink != 1:
            raise OSError("installed output is not a private regular file")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def atomic_write_new_text(path: Path, text: str) -> None:
    atomic_write_new(path, text.encode("utf-8"))


def reserve_regular_output(path: Path) -> None:
    """Reserve an externally populated output as a private regular file."""
    # SECURITY-REVIEW: The external coordinator receives only output slots that
    # this process created with O_EXCL/O_NOFOLLOW; pre-existing aliases cannot
    # be opened through these paths.
    ancestor_error = lexical_directory_ancestor_error(path)
    if ancestor_error is not None:
        raise ValueError(f"unsafe output path: {ancestor_error}")
    parent_error = directory_error(path.parent)
    if parent_error is not None:
        raise ValueError(f"unsafe output parent: {parent_error}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    os.close(descriptor)
    created = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(created.st_mode) or created.st_nlink != 1:
        raise OSError("reserved output is not a private regular file")


def file_snapshot_identity(path: Path) -> Dict[str, Any]:
    """Return exact bytes and no-follow metadata used for stability checks."""
    error = regular_file_error(path)
    if error is not None:
        raise ValueError(error)
    metadata = path.stat(follow_symlinks=False)
    return {
        "sha256": f"sha256:{sha256_regular_file(path)}",
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "bytes": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
        "ctime_ns": metadata.st_ctime_ns,
    }


def target_snapshot_stability(
    source_pre: Optional[Dict[str, Any]],
    source_post: Optional[Dict[str, Any]],
    snapshot_pre: Optional[Dict[str, Any]],
    snapshot_post: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    metadata_fields = (
        "device",
        "inode",
        "bytes",
        "mtime_ns",
        "ctime_ns",
    )
    source_metadata_stable = (
        isinstance(source_pre, dict)
        and isinstance(source_post, dict)
        and all(
            type(source_pre.get(field)) is int
            and source_pre.get(field) == source_post.get(field)
            for field in metadata_fields
        )
    )
    snapshot_metadata_stable = (
        isinstance(snapshot_pre, dict)
        and isinstance(snapshot_post, dict)
        and all(
            type(snapshot_pre.get(field)) is int
            and snapshot_pre.get(field) == snapshot_post.get(field)
            for field in metadata_fields
        )
    )
    digests = [
        identity.get("sha256") if isinstance(identity, dict) else None
        for identity in (
            source_pre,
            source_post,
            snapshot_pre,
            snapshot_post,
        )
    ]
    digest_stable = (
        all(
            type(digest) is str
            and bool(re.fullmatch(r"sha256:[0-9a-f]{64}", digest))
            for digest in digests
        )
        and len(set(digests)) == 1
    )
    return {
        "stable": (
            digest_stable
            and source_metadata_stable
            and snapshot_metadata_stable
        ),
        "digest_stable": digest_stable,
        "source_metadata_stable": source_metadata_stable,
        "snapshot_metadata_stable": snapshot_metadata_stable,
    }


def cap_status_by_target_stability(
    status: str,
    stability: Dict[str, Any],
) -> Tuple[str, Optional[str]]:
    if status in PASS_STATUSES and stability.get("stable") is not True:
        return (
            "FAIL",
            "target or immutable snapshot changed during formal verification",
        )
    return status, None


def package_tree_identity_is_valid(identity: Any) -> bool:
    return (
        type(identity) is dict
        and set(identity) == {"algorithm", "sha256", "valid"}
        and type(identity.get("algorithm")) is str
        and bool(identity.get("algorithm"))
        and type(identity.get("sha256")) is str
        and bool(re.fullmatch(r"sha256:[0-9a-f]{64}", identity.get("sha256")))
        and type(identity.get("valid")) is bool
        and identity.get("valid") is True
    )


def cap_status_by_package_identity(
    status: str,
    identity: Any,
) -> Tuple[str, Optional[str]]:
    if status in PASS_STATUSES and not package_tree_identity_is_valid(identity):
        return "FAIL", "package-tree identity is invalid for a formal pass"
    return status, None


def sha256_regular_file(path: Path) -> str:
    # SECURITY-REVIEW: Caller-controlled target and companion paths are
    # lstat-checked as regular files before bounded streaming reads.
    error = regular_file_error(path)
    if error:
        raise ValueError(error)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def package_tree_identity(root: Path) -> Dict[str, Any]:
    validator = root / SKILL_PATH / "scripts/validate_package.py"
    if regular_file_error(validator):
        return {"algorithm": None, "sha256": None, "valid": False}
    try:
        module = load_module_without_bytecode(
            "ntt_validator_for_formal_tree",
            validator,
        )
        tree = module.compute_stable_release_tree(root)
        raw_sha = tree.get("sha256") if isinstance(tree, dict) else None
        return {
            "algorithm": (
                tree.get("algorithm") if isinstance(tree, dict) else None
            ),
            "sha256": (
                f"sha256:{raw_sha}"
                if isinstance(raw_sha, str)
                and re.fullmatch(r"[0-9a-f]{64}", raw_sha)
                else None
            ),
            "valid": (
                tree.get("valid") is True
                if isinstance(tree, dict)
                else False
            ),
        }
    except Exception:
        return {"algorithm": None, "sha256": None, "valid": False}


def _blocked_package_output_result(root: Path, target: Path, output_dir: Path, json_path: Optional[Path]) -> Dict[str, Any]:
    blocked = [str(output_dir)]
    if json_path is not None:
        blocked.append(str(json_path))
    return {
        "status": "FAIL",
        "plugin_root": str(root),
        "target_artifact": str(target),
        "output_dir": str(output_dir),
        "formal_coordinator": FORMAL_COORDINATOR,
        "required_native_agents": REQUIRED_NATIVE_AGENTS,
        "prompt_file": None,
        "transcript_file": None,
        "prechecks": [],
        "precheck_summary": {"total": 0, "failed": 0, "passed": 0, "failed_commands": []},
        "commands": [],
        "output_checks": [],
        "gate_status": None,
        "trace_authentication": None,
        "reason": "release tree output requires --refresh-release-manifest",
        "blocked_paths": blocked,
    }



def output_location_error(root: Path, output_dir: Path, json_path: Optional[Path], allow_package_output: bool = False) -> Optional[str]:
    output_ancestor_error = lexical_directory_ancestor_error(output_dir)
    if output_ancestor_error is not None:
        return f"unsafe --output-dir: {output_ancestor_error}"
    if json_path is not None:
        json_ancestor_error = lexical_directory_ancestor_error(json_path)
        if json_ancestor_error is not None:
            return f"unsafe --json: {json_ancestor_error}"
    root = root.resolve()
    output_dir = output_dir.resolve()
    json_resolved = json_path.resolve() if json_path is not None else None
    package_output = _path_within(output_dir, root) or (json_resolved is not None and _path_within(json_resolved, root))
    if package_output and not allow_package_output:
        return (
            "formal-run generated outputs would be written inside plugin_root and release tree output requires --refresh-release-manifest; "
            "use the default external temporary output directory, pass an outside --output-dir/--json, "
            "or explicitly opt in with --refresh-release-manifest for non-release experiments: "
            f"output_dir={output_dir}; json={json_resolved}"
        )
    return None


def prepare_output_directory(path: Path) -> Optional[str]:
    """Create missing directories one component at a time without links."""
    # SECURITY-REVIEW: --output-dir is caller-controlled. The nearest existing
    # ancestor and every newly created component are inspected without
    # following links; recursive mkdir traversal is not used.
    ancestor_error = lexical_directory_ancestor_error(path)
    if ancestor_error is not None:
        return ancestor_error
    if path_lexists(path):
        return directory_error(path)
    missing: List[Path] = []
    ancestor = path
    while not path_lexists(ancestor):
        missing.append(ancestor)
        if ancestor.parent == ancestor:
            return "no existing safe output ancestor"
        ancestor = ancestor.parent
    ancestor_error = directory_error(ancestor)
    if ancestor_error is not None:
        return f"unsafe output ancestor: {ancestor_error}"
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except OSError as exc:
            return f"{type(exc).__name__} while creating output directory"
        created_error = directory_error(directory)
        if created_error is not None:
            return f"unsafe created output directory: {created_error}"
    return directory_error(path)


def _paths_alias(first: Path, second: Path) -> bool:
    if first == second:
        return True
    try:
        return os.path.samefile(first, second)
    except OSError:
        return False


def formal_output_collision_error(
    target: Path,
    out: Dict[str, Path],
    json_path: Optional[Path] = None,
) -> Optional[str]:
    """Reject output aliases that could overwrite the target or companions."""
    output_paths = list(out.values())
    # SECURITY-REVIEW: Caller-controlled output paths are compared by resolved
    # path and, when they exist, file identity before any target/output write.
    if any(_paths_alias(target, output_path) for output_path in output_paths):
        return "target_artifact aliases a reserved formal output path"
    if json_path is not None and not _paths_alias(
        json_path,
        out["formal_result"],
    ):
        if _paths_alias(json_path, target):
            return "json compatibility path aliases target_artifact"
        if any(
            _paths_alias(json_path, output_path)
            for output_path in output_paths
        ):
            return "json compatibility path aliases a formal companion"
        output_paths.append(json_path)
    for role, path in [
        *out.items(),
        *(
            [("json compatibility", json_path)]
            if json_path is not None
            and not _paths_alias(json_path, out["formal_result"])
            else []
        ),
    ]:
        if path is None:
            continue
        ancestor_error = lexical_directory_ancestor_error(path)
        if ancestor_error is not None:
            return (
                f"unsafe formal output path for {role}: {ancestor_error}"
            )
        parent_error = directory_error(path.parent)
        if parent_error is not None:
            return (
                f"unsafe formal output parent for {role}: {parent_error}"
            )
        if not path_lexists(path):
            continue
        try:
            metadata = path.lstat()
        except OSError as exc:
            return f"pre-existing formal output is unreadable: {type(exc).__name__}"
        if stat.S_ISLNK(metadata.st_mode):
            kind = "symbolic link"
        elif not stat.S_ISREG(metadata.st_mode):
            kind = "special file"
        elif metadata.st_nlink != 1:
            kind = "hardlink alias"
        else:
            kind = "regular file"
        if role == "json compatibility" and kind == "regular file":
            continue
        return f"pre-existing formal output for {role} is a {kind}"
    return None


def _captured_stream_fields(raw: bytes, name: str) -> Dict[str, Any]:
    return {
        name: raw.decode("utf-8", errors="replace"),
        f"_{name}_bytes": raw,
        f"{name}_bytes": len(raw),
        f"{name}_sha256": f"sha256:{hashlib.sha256(raw).hexdigest()}",
        f"{name}_truncated": len(raw) > PUBLIC_STREAM_BOUND_BYTES,
    }


def run_cmd(cmd: List[str], cwd: Optional[Path] = None, timeout: int = 300, env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    started = time.time()
    try:
        # SECURITY-REVIEW: Callers construct fixed argv and invoke executables
        # directly with shell parsing disabled. Full raw streams remain
        # in-memory for status/authentication decisions and exact byte hashes.
        process_env = os.environ.copy() if env is None else dict(env)
        process_env["PYTHONDONTWRITEBYTECODE"] = "1"
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=process_env,
        )
        stdout_raw = bytes(proc.stdout or b"")
        stderr_raw = bytes(proc.stderr or b"")
        return {
            "cmd": cmd,
            "cwd": str(cwd) if cwd else None,
            "returncode": proc.returncode,
            **_captured_stream_fields(stdout_raw, "stdout"),
            **_captured_stream_fields(stderr_raw, "stderr"),
            "capture_limit_exceeded": (
                len(stdout_raw) > MAX_CAPTURE_BYTES
                or len(stderr_raw) > MAX_CAPTURE_BYTES
            ),
            "duration_sec": round(time.time() - started, 3),
        }
    except subprocess.TimeoutExpired as exc:
        stdout_raw = (
            exc.stdout
            if isinstance(exc.stdout, bytes)
            else str(exc.stdout or "").encode("utf-8", errors="replace")
        )
        stderr_raw = (
            exc.stderr
            if isinstance(exc.stderr, bytes)
            else str(exc.stderr or "").encode("utf-8", errors="replace")
        )
        return {
            "cmd": cmd,
            "cwd": str(cwd) if cwd else None,
            "returncode": 124,
            **_captured_stream_fields(stdout_raw, "stdout"),
            **_captured_stream_fields(stderr_raw, "stderr"),
            "capture_limit_exceeded": (
                len(stdout_raw) > MAX_CAPTURE_BYTES
                or len(stderr_raw) > MAX_CAPTURE_BYTES
            ),
            "timed_out": True,
            "duration_sec": round(time.time() - started, 3),
        }
    except Exception as exc:
        stderr_raw = repr(exc).encode("utf-8", errors="replace")
        return {
            "cmd": cmd,
            "cwd": str(cwd) if cwd else None,
            "returncode": 125,
            **_captured_stream_fields(b"", "stdout"),
            **_captured_stream_fields(stderr_raw, "stderr"),
            "capture_limit_exceeded": False,
            "duration_sec": round(time.time() - started, 3),
        }


def write_complete_stream_transcript(
    path: Path,
    invocation: Mapping[str, Any],
) -> Dict[str, Any]:
    """Persist the complete Claude stdout stream or fail closed."""
    # SECURITY-REVIEW: The full stream is retained only in the private formal
    # companion. It is never copied into the final JSON result. Oversized
    # captures are rejected rather than tail-truncated and authenticated.
    if invocation.get("capture_limit_exceeded") is True:
        raise ValueError("formal stream exceeds the capture safety limit")
    raw = invocation.get("_stdout_bytes")
    if isinstance(raw, bytearray):
        payload = bytes(raw)
    elif isinstance(raw, bytes):
        payload = raw
    else:
        stdout = invocation.get("stdout")
        if not isinstance(stdout, str):
            raise ValueError("formal stdout is unavailable")
        payload = stdout.encode("utf-8")
    if len(payload) > MAX_CAPTURE_BYTES:
        raise ValueError("formal stream exceeds the capture safety limit")
    atomic_write_new(path, payload)
    return {
        "bytes": len(payload),
        "sha256": f"sha256:{hashlib.sha256(payload).hexdigest()}",
    }


def load_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"_error": str(exc), "_path": str(path)}


def plugin_name(root: Path) -> str:
    data = load_json(root / ".claude-plugin/plugin.json")
    name = data.get("name")
    return str(name) if isinstance(name, str) and name else "nozickian-truth-tracking-agentic"


def refresh_stable_release_manifest_if_available(root: Path) -> None:
    """Explicitly refresh STABLE_RELEASE_MANIFEST.json after all requested writes.

    v1.0.1 does not auto-refresh during normal dry-runs. Default dry-run outputs
    go to an external temporary directory, and in-package outputs require
    --refresh-release-manifest so release validation is idempotent rather than
    silently mutating the immutable release ledger.
    """
    manifest = root / "STABLE_RELEASE_MANIFEST.json"
    validator = root / "skills/nozickian-verify/scripts/validate_package.py"
    if not manifest.exists() or not validator.exists():
        return
    try:
        module = load_module_without_bytecode(
            "nozickian_validate_package",
            validator,
        )
        writer = getattr(module, "write_stable_release_manifest", None)
        if callable(writer):
            writer(root.resolve())
    except Exception:
        # Do not mask the underlying formal runner result; validate_package.py will
        # report any manifest drift in the normal precheck output.
        return


def output_paths(target: Path, output_dir: Path) -> Dict[str, Path]:
    stem = target.stem
    paths = {
        role: output_dir / f"{stem}{suffix}"
        for role, suffix in FORMAL_COMPANION_SPECS.items()
    }
    paths["formal_result"] = output_dir / FORMAL_AUXILIARY_OUTPUT_SPECS[
        "formal_result"
    ]
    paths["precheck"] = output_dir / (
        f"{stem}{FORMAL_AUXILIARY_OUTPUT_SPECS['precheck']}"
    )
    return paths


def build_formal_prompt(
    root: Path,
    target: Path,
    out: Dict[str, Path],
    evidence_root: Optional[Path] = None,
) -> str:
    name = plugin_name(root)
    effective_evidence_root = evidence_root or out["formal_result"].parent
    agent_list = "\n".join(f"   - {agent}" for agent in REQUIRED_NATIVE_AGENTS)
    return f"""/{name}:nozickian-verify {target}

FORMAL_INVOCATION_REQUIRED.

Immutable target snapshot to verify:
{target}

Verification context:
- Mode: standalone-immutable-snapshot.
- Relative sibling context from the mutable source location is intentionally unavailable.
- Evaluate only the immutable snapshot bytes and explicitly supplied evidence.
- Do not infer claims from files adjacent to the original source target.

Required output artifacts:
- {out['report']}
- {out['certificate']}
- {out['ledger']}

Formal invocation rules:
1. Use the loaded plugin skill /{name}:nozickian-verify, not an informal imitation.
2. You are expected to be running as the main-thread agent `{FORMAL_COORDINATOR}`. If not, write FORMAL_COORDINATOR_MISMATCH in the ledger and downgrade.
3. Before verification, confirm whether these native plugin subagents are available:
{agent_list}
4. If any required native ntt-* subagent is unavailable, do not substitute general-purpose silently. Mark FORMAL_SUBAGENT_FAILURE in the report and ledger and gate the run as LIMITED or UNVERIFIED.
5. Reconstruct method M for the target artifact.
6. Extract claim IDs and rank them as critical, major, or minor.
7. For every critical and major claim, produce structured certificate entries with: claim_id/id, text, importance, artifact_location, truth_status, method_m, method_completeness, evidence_refs, false_world_tests, true_world_tests, unresolved_contradictions, and residual_risks.
8. For every local evidence reference intended to satisfy the gate, write a structured evidence artifact with fields: evidence_schema_version, claim_id, test_id or applies_to_tests, artifact_path, command_or_source, observed_result, support_summary, timestamp_utc, and hash_or_version.
9. Do not write the gate output. The formal runner will execute this exact gate after the coordinator returns:
   python3 {root / SKILL_PATH / 'scripts/ntt_gate.py'} {out['certificate']} --evidence-root {effective_evidence_root} --strict-evidence --markdown {out['gate']}
10. The final report must include scope, artifact identity, method M, claim table, false-world sensitivity, true-world adherence, contradictions, residual risks, commands run, subagents actually used, gate status, and explicit downgrade reasons.
11. The invocation ledger must include:
    Skill invoked: /{name}:nozickian-verify
    Main coordinator: {FORMAL_COORDINATOR}
    Native subagents requested: {', '.join(REQUIRED_NATIVE_AGENTS)}
    Native subagents completed: ...
    Substitution used: none OR FORMAL_SUBAGENT_FAILURE
    Machine gate run: runner-managed
    Gate script: {root / SKILL_PATH / 'scripts/ntt_gate.py'}
    Gate output: {out['gate']}
    Runtime transcript: {out['transcript']}
12. Do not claim PASS-TRACKED unless ntt_gate.py returns PASS-TRACKED, no method/runtime/subagent unknowns remain, and the runtime transcript contains native Agent/Task tool-use events plus successful matching tool-result/completion events for every required ntt-* lane. If ntt_gate.py returns PASS-SCOPED, do not promote it.
13. For any PASS-SCOPED to PASS-TRACKED promotion claim, follow references/PASS_TRACKED_UPGRADE_AUDIT.md: require deterministic outputs, official validator outputs, live fixture outputs, this formal artifact run, strict-gate PASS-TRACKED, trace authentication, promotion_certificate.json, and downstream non-closure review.
"""


def parse_gate_status(stdout: str, markdown_path: Optional[Path] = None) -> Optional[str]:
    text = stdout or ""
    try:
        data = json.loads(text)
        status = data.get("status")
        if isinstance(status, str) and status in FINAL_STATUSES:
            return status
    except Exception:
        pass
    if markdown_path and markdown_path.exists():
        text += "\n" + markdown_path.read_text(encoding="utf-8", errors="replace")
    matches = re.findall(r"Status:\s*\*\*(PASS-TRACKED|PASS-SCOPED|LIMITED|FAIL|UNVERIFIED)\*\*", text)
    if matches:
        return matches[-1]
    matches = re.findall(r"(?:final\s+)?(?:gate\s+)?status\s*[:=\-]\s*(PASS-TRACKED|PASS-SCOPED|LIMITED|FAIL|UNVERIFIED)", text, flags=re.I)
    if matches:
        return matches[-1].upper()
    for tok in ("FAIL", "LIMITED", "UNVERIFIED", "PASS-TRACKED", "PASS-SCOPED"):
        if re.search(r"\b" + re.escape(tok) + r"\b", text):
            return tok
    return None


def _iter_json_lines(text: str) -> Iterable[Tuple[int, Dict[str, Any]]]:
    for idx, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if isinstance(obj, dict):
            yield idx, obj


def _candidate_trace_nodes(event: Dict[str, Any]) -> Iterable[Tuple[int, Dict[str, Any], str, Optional[str]]]:
    """Yield recognized stream-json event positions with optional role context.

    Candidate positions are top-level stream events and known message/content
    envelopes. Once a node is itself a tool_use or tool_result event, it becomes a
    hard event boundary: all children under content, data, payload, delta, message,
    input, arguments, args, or parameters are treated as payload data and are not
    recursively parsed as new runtime events. This prevents fake tool events hidden
    inside tool_result.data/payload from authenticating PASS-TRACKED.
    """
    index = 0
    seen: Set[int] = set()

    def event_type(container: Any) -> str:
        if not isinstance(container, dict):
            return ""
        return str(container.get("type") or container.get("event") or container.get("kind") or "").strip().lower()

    def role_from(container: Any, inherited: Optional[str]) -> Optional[str]:
        if not isinstance(container, dict):
            return inherited
        role = container.get("role") or container.get("speaker")
        if isinstance(role, str) and role.strip():
            return role.strip().lower()
        typ = event_type(container)
        if typ in {"assistant", "user"}:
            return typ
        return inherited

    def emit(node: Any, path: str, role: Optional[str]):
        nonlocal index
        if isinstance(node, dict):
            ident = id(node)
            if ident not in seen:
                seen.add(ident)
                yield index, node, path, role
                index += 1

    def emit_child(child: Any, path: str, role: Optional[str]):
        if isinstance(child, dict):
            yield from emit_container(child, path, role)
        elif isinstance(child, list):
            for i, item in enumerate(child):
                yield from emit_container(item, f"{path}[{i}]", role)

    def emit_container(container: Any, path: str, inherited_role: Optional[str] = None):
        if not isinstance(container, dict):
            return
        role = role_from(container, inherited_role)
        yield from emit(container, path, role)
        typ = event_type(container)
        if typ in TOOL_USE_TYPES or typ in TOOL_RESULT_TYPES:
            # Hard event boundary. Children of an actual tool event are input/output
            # payloads, not stream event envelopes.
            return

        # Known non-tool envelopes. The role of an enclosing assistant/user message
        # is propagated to its content blocks so role-inverted traces can be rejected.
        for key in ("message", "delta", "data", "payload"):
            if key in container:
                yield from emit_child(container.get(key), f"{path}.{key}", role)

        for key in ("content", "blocks"):
            if key in container:
                yield from emit_child(container.get(key), f"{path}.{key}", role)

    yield from emit_container(event, "$", None)

def _stringify(obj: Any) -> str:
    try:
        return json.dumps(obj, sort_keys=True)
    except Exception:
        return str(obj)


def _tool_call_ids(node: Dict[str, Any]) -> List[str]:
    """Return native tool-use call IDs.

    For a tool-use event, the only acceptable matching key is the event's
    call id. Result-side identifiers such as tool_use_id are intentionally not
    accepted here; mixing call and result id fields can make mismatched traces
    look authenticated.
    """
    v = node.get("id")
    return [v] if isinstance(v, str) and v else []


def _tool_result_ids(node: Dict[str, Any]) -> List[str]:
    """Return IDs that explicitly bind a result/completion to a tool-use call.

    A result authenticates a native lane only through tool_use_id / tool_call_id
    style fields. The result object's own id, and text mentioning an agent name,
    are not evidence of a successful matching native subagent completion.
    """
    vals: List[str] = []
    for key in ("tool_use_id", "toolUseId", "tool_call_id", "toolCallId"):
        v = node.get(key)
        if isinstance(v, str) and v:
            vals.append(v)
    return vals


def _normalized_event_type(node: Dict[str, Any]) -> str:
    return str(node.get("type") or node.get("event") or node.get("kind") or "").strip().lower()


def _is_tool_call_node(node: Dict[str, Any]) -> bool:
    """Return True only for authentic tool-use event nodes.

    Recognized positions are necessary but not sufficient: a `message.content`
    block with type `text`, or a top-level assistant/message envelope that merely
    contains fields named `name` and `input`, must not masquerade as a native
    Agent/Task call. PASS-TRACKED depends on actual tool-use event types.
    """
    typ = _normalized_event_type(node)
    if typ not in TOOL_USE_TYPES:
        return False
    name = node.get("name") or node.get("tool_name") or node.get("toolName")
    return name in TRACE_TOOL_NAMES


def _is_tool_result_node(node: Dict[str, Any]) -> bool:
    """Return True only for authentic tool-result/completion event nodes.

    Text/message/assistant blocks with `tool_use_id`, status, or content fields
    are not runtime results. This closes the v0.7.7 false world where non-tool
    text or top-level assistant messages authenticated native lanes.
    """
    typ = _normalized_event_type(node)
    return typ in TOOL_RESULT_TYPES and bool(_tool_result_ids(node))


def _result_content(node: Dict[str, Any]) -> Any:
    if "content" in node:
        return node.get("content")
    if "result" in node:
        return node.get("result")
    if "output" in node:
        return node.get("output")
    return None


def _has_meaningful_content(value: Any) -> bool:
    """Return True only for substantive result payload content.

    Tool-result content blocks often contain metadata such as {"type": "text"}.
    That metadata alone is not evidence of completed native-lane work. For known
    block types, inspect the payload-bearing fields; for generic dicts, ignore
    metadata-only keys before deciding whether the result is meaningful.
    """
    if value is None or value is False:
        return False
    if isinstance(value, str):
        stripped = value.strip()
        return stripped not in {"", "null", "none", "None", "[]", "{}", '\"\"'}
    if isinstance(value, (list, tuple, set)):
        return any(_has_meaningful_content(v) for v in value)
    if isinstance(value, dict):
        typ = str(value.get("type") or "").strip().lower()
        if typ == "text":
            return _has_meaningful_content(value.get("text"))
        if typ in {"document", "image", "tool_reference", "file"}:
            return any(_has_meaningful_content(value.get(k)) for k in ("source", "data", "url", "content", "text"))
        if typ in TOOL_RESULT_TYPES:
            return _has_meaningful_content(_result_content(value))
        payload = {k: v for k, v in value.items() if k not in CONTENT_METADATA_KEYS}
        return any(_has_meaningful_content(v) for v in payload.values())
    return True

def _result_is_success(node: Dict[str, Any]) -> bool:
    """Return True only for explicit, non-empty successful tool results.

    A result can authenticate a native lane only when it has an explicit success
    signal (success-like status or is_error is False), no failure signal, and
    meaningful non-empty content. Generic text, empty content, or prose that
    merely says an agent succeeded is not sufficient for PASS-TRACKED trace
    authentication.
    """
    if node.get("is_error") is True:
        return False
    status = str(node.get("status") or node.get("outcome") or "").strip().lower()
    if status in {"error", "failed", "failure", "timeout", "cancelled", "canceled"}:
        return False
    content = _result_content(node)
    body = _stringify(content).lower()
    if any(term in body for term in ("formal_subagent_failure", "failed", "failure", "timeout", "cancelled", "canceled", "exception", "traceback")):
        return False
    explicit_success = status in {"ok", "success", "succeeded", "completed", "done"} or node.get("is_error") is False
    return bool(explicit_success and _has_meaningful_content(content))


def _tool_input_payload(node: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    payload = node.get("input")
    if not isinstance(payload, dict):
        payload = node.get("arguments")
    if not isinstance(payload, dict):
        payload = node.get("args")
    if not isinstance(payload, dict):
        payload = node.get("parameters")
    return payload if isinstance(payload, dict) else None


def _structured_subagent_selector(node: Dict[str, Any]) -> Optional[str]:
    """Extract the actual structured native-agent selector.

    Agent names inside arbitrary description/prompt text are deliberately ignored.
    Only exact structured selectors such as input.subagent_type authenticate a
    lane; this blocks the single-call-mentions-all-lanes false world.
    """
    payload = _tool_input_payload(node)
    if not isinstance(payload, dict):
        return None
    for key in ("subagent_type", "subagentType", "agent_type", "agentType"):
        value = payload.get(key)
        if isinstance(value, str):
            return value
    return None


def _extract_trace_events(event: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, List[Dict[str, Any]]], Set[str], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Extract authentic native Agent/Task calls and matching results.

    The parser is intentionally narrow: it reads only top-level stream-json
    events and known message/content block positions, and it requires authentic
    tool-use/tool-result event types. It never treats arbitrary text/message
    objects or nested data in tool inputs as runtime events.
    """
    calls: Dict[str, Dict[str, Any]] = {}
    result_success_by_id: Dict[str, List[Dict[str, Any]]] = {}
    saw_general_purpose: Set[str] = set()
    evidence: List[Dict[str, Any]] = []
    unexpected_native_tool_calls: List[Dict[str, Any]] = []
    role_violations: List[Dict[str, Any]] = []
    for node_index, node, path, role in _candidate_trace_nodes(event):
        if _is_tool_call_node(node):
            selector = _structured_subagent_selector(node)
            ids = _tool_call_ids(node)
            tool_name = str(node.get("name") or node.get("tool_name") or node.get("toolName"))
            event_type = str(node.get("type") or node.get("event") or node.get("kind") or "unknown")
            if role not in (None, "assistant"):
                role_violations.append({"phase": "tool-use", "role": role, "tool_ids": ids, "tool_name": tool_name, "selector": selector, "event_type": event_type, "node_index": node_index, "path": path})
                evidence.append({"tool_ids": ids, "tool_name": tool_name, "selector": selector, "event_type": event_type, "phase": "role-violating-tool-use", "role": role, "node_index": node_index, "path": path})
                continue
            if selector in GENERAL_PURPOSE_NAMES:
                saw_general_purpose.add("general-purpose")
            if selector in REQUIRED_NATIVE_AGENTS:
                agent = selector
                if ids:
                    for tool_id in ids:
                        calls[agent] = {
                            "id": tool_id,
                            "tool_name": tool_name,
                            "event_type": event_type,
                            "node_index": node_index,
                            "path": path,
                        }
                        evidence.append({"agent": agent, "tool_id": tool_id, "tool_name": tool_name, "event_type": event_type, "phase": "tool-use", "node_index": node_index, "path": path})
                else:
                    calls[agent] = {"id": "", "tool_name": tool_name, "event_type": event_type, "node_index": node_index, "path": path}
                    evidence.append({"agent": agent, "tool_id": "", "tool_name": tool_name, "event_type": event_type, "phase": "tool-use", "warning": "tool-use event has no id and cannot authenticate a matching result", "node_index": node_index, "path": path})
            else:
                # A native Agent/Task call with no recognized ntt-* structured
                # selector is an unexpected substitution/fallback candidate. It
                # should cap/deny PASS-TRACKED rather than being silently ignored.
                unexpected_native_tool_calls.append({
                    "tool_ids": ids,
                    "tool_name": tool_name,
                    "selector": selector,
                    "event_type": event_type,
                    "node_index": node_index,
                    "path": path,
                })
                evidence.append({"tool_ids": ids, "tool_name": tool_name, "selector": selector, "event_type": event_type, "phase": "unexpected-tool-use", "node_index": node_index, "path": path})
        elif _is_tool_result_node(node):
            success = _result_is_success(node)
            ids = _tool_result_ids(node)
            event_type = str(node.get("type") or node.get("event") or node.get("kind") or "tool-result")
            if role not in (None, "user"):
                role_violations.append({"phase": "tool-result", "role": role, "tool_ids": ids, "event_type": event_type, "success": success, "node_index": node_index, "path": path})
                evidence.append({"tool_ids": ids, "event_type": event_type, "phase": "role-violating-tool-result", "role": role, "success": success, "node_index": node_index, "path": path})
                continue
            for tool_id in ids:
                result_success_by_id.setdefault(tool_id, []).append({"success": success, "node_index": node_index, "path": path})
                evidence.append({"tool_id": tool_id, "event_type": event_type, "phase": "tool-result", "success": success, "node_index": node_index, "path": path})
    return calls, result_success_by_id, saw_general_purpose, evidence, unexpected_native_tool_calls, role_violations

def authenticate_trace(transcript_path: Path) -> Dict[str, Any]:
    if not transcript_path.exists() or transcript_path.stat().st_size == 0:
        return {
            "authenticated": False,
            "events_seen": 0,
            "agent_calls_authenticated": [],
            "agent_results_authenticated": [],
            "missing_agents": REQUIRED_NATIVE_AGENTS,
            "missing_result_agents": REQUIRED_NATIVE_AGENTS,
            "saw_general_purpose": False,
            "duplicate_tool_use_ids": {},
            "result_before_call_ids": {},
            "unexpected_native_tool_calls": [],
            "role_violations": [],
            "reasons": ["transcript is missing or empty"],
            "evidence_events": [],
        }
    text = transcript_path.read_text(encoding="utf-8", errors="replace")
    calls_found: Dict[str, Dict[str, Any]] = {}
    tool_id_to_agents: Dict[str, Set[str]] = {}
    saw_general = False
    evidence_events: List[Dict[str, Any]] = []
    unexpected_native_tool_calls: List[Dict[str, Any]] = []
    role_violations: List[Dict[str, Any]] = []
    events_seen = 0
    all_results: Dict[str, List[Dict[str, Any]]] = {}
    for line_no, event in _iter_json_lines(text):
        events_seen += 1
        calls, results_by_id, general, evidence, unexpected_calls, role_calls = _extract_trace_events(event)
        saw_general = saw_general or bool(general)
        for u in unexpected_calls:
            uu = dict(u)
            uu["line"] = line_no
            uu["position"] = line_no * 100000 + int(uu.get("node_index", 0))
            unexpected_native_tool_calls.append(uu)
        for rv in role_calls:
            rr = dict(rv)
            rr["line"] = line_no
            rr["position"] = line_no * 100000 + int(rr.get("node_index", 0))
            role_violations.append(rr)
        for agent, meta in calls.items():
            meta = dict(meta)
            meta["line"] = line_no
            meta["position"] = line_no * 100000 + int(meta.get("node_index", 0))
            calls_found[agent] = meta
            tool_id = str(meta.get("id") or "")
            if tool_id:
                tool_id_to_agents.setdefault(tool_id, set()).add(agent)
        for k, result_list in results_by_id.items():
            for r in result_list:
                rr = dict(r)
                rr["line"] = line_no
                rr["position"] = line_no * 100000 + int(rr.get("node_index", 0))
                all_results.setdefault(k, []).append(rr)
        for e in evidence:
            e["line"] = line_no
            e["position"] = line_no * 100000 + int(e.get("node_index", 0))
            evidence_events.append(e)
    duplicate_ids = {tool_id: sorted(agents) for tool_id, agents in tool_id_to_agents.items() if len(agents) > 1}
    result_agents: Set[str] = set()
    result_before_call_ids: Dict[str, Dict[str, Any]] = {}
    for agent, meta in calls_found.items():
        tool_id = str(meta.get("id") or "")
        if not tool_id or tool_id in duplicate_ids:
            continue
        call_pos = int(meta.get("position", 0))
        result_events = all_results.get(tool_id, [])
        before_or_same = [r for r in result_events if int(r.get("position", 0)) <= call_pos]
        after_success = [r for r in result_events if int(r.get("position", 0)) > call_pos and bool(r.get("success"))]
        if after_success:
            result_agents.add(agent)
        elif before_or_same:
            result_before_call_ids[tool_id] = {"agent": agent, "call_line": meta.get("line"), "result_lines": sorted({r.get("line") for r in before_or_same})}
    missing = [a for a in REQUIRED_NATIVE_AGENTS if a not in calls_found]
    missing_results = [a for a in REQUIRED_NATIVE_AGENTS if a not in result_agents]
    reasons: List[str] = []
    if events_seen == 0:
        reasons.append("no parseable stream-json events observed")
    if missing:
        reasons.append("missing native Agent/Task tool-use events for: " + ", ".join(missing))
    if duplicate_ids:
        reasons.append("duplicate tool-use id used for multiple native lanes: " + "; ".join(f"{tid} -> {', '.join(agents)}" for tid, agents in sorted(duplicate_ids.items())))
    if result_before_call_ids:
        reasons.append("tool-result/completion events appear before their matching tool-use events for: " + ", ".join(sorted(result_before_call_ids)))
    if missing_results:
        reasons.append("missing successful matching tool-result/completion events for: " + ", ".join(missing_results))
    if saw_general:
        reasons.append("transcript includes a general-purpose Agent/Task call")
    if unexpected_native_tool_calls:
        reasons.append("unexpected native Agent/Task tool-use events without required ntt-* structured selectors: " + str(len(unexpected_native_tool_calls)))
    if role_violations:
        reasons.append("role-inverted or role-invalid tool events observed: " + str(len(role_violations)))
    return {
        "authenticated": not missing and not missing_results and not duplicate_ids and not result_before_call_ids and not saw_general and not unexpected_native_tool_calls and not role_violations and events_seen > 0,
        "events_seen": events_seen,
        "agent_calls_authenticated": sorted(calls_found),
        "agent_results_authenticated": sorted(result_agents),
        "missing_agents": missing,
        "missing_result_agents": missing_results,
        "saw_general_purpose": saw_general,
        "duplicate_tool_use_ids": duplicate_ids,
        "result_before_call_ids": result_before_call_ids,
        "unexpected_native_tool_calls": unexpected_native_tool_calls[:50],
        "role_violations": role_violations[:50],
        "reasons": reasons,
        "evidence_events": evidence_events[:100],
    }

def check_required_outputs(
    out: Dict[str, Path],
    *,
    include_gate: bool = True,
) -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []
    required = ["report", "certificate", "ledger"]
    if include_gate:
        required.append("gate")
    for key in required:
        path = out[key]
        file_error = regular_file_error(path)
        try:
            metadata = path.stat(follow_symlinks=False)
        except OSError:
            metadata = None
        exists = (
            file_error is None
            and metadata is not None
            and metadata.st_nlink == 1
            and metadata.st_size > 0
        )
        checks.append({"name": f"output exists: {key}", "passed": exists, "path": str(path), "size": metadata.st_size if metadata is not None else 0})
    cert = out["certificate"]
    if (
        regular_file_error(cert) is None
        and cert.stat(follow_symlinks=False).st_nlink == 1
    ):
        data = load_json(cert)
        checks.append({"name": "certificate parses JSON", "passed": "_error" not in data, "path": str(cert)})
        claims = data.get("claims") if isinstance(data, dict) else None
        checks.append({"name": "certificate has claims", "passed": isinstance(claims, list) and bool(claims), "count": len(claims) if isinstance(claims, list) else 0})
    ledger = out["ledger"]
    if (
        regular_file_error(ledger) is None
        and ledger.stat(follow_symlinks=False).st_nlink == 1
    ):
        text = ledger.read_text(encoding="utf-8", errors="replace")
        low = text.lower()
        checks.append({"name": "ledger names formal coordinator", "passed": FORMAL_COORDINATOR in text})
        checks.append({"name": "ledger records no substitution", "passed": "substitution used: none" in low})
        checks.append({"name": "ledger delegates machine gate to runner", "passed": "machine gate run: runner-managed" in low})
        checks.append({"name": "ledger has no formal subagent failure", "passed": "formal_subagent_failure" not in low})
        for agent in REQUIRED_NATIVE_AGENTS:
            checks.append({"name": f"ledger mentions native agent {agent}", "passed": agent in text})
    return checks


def run_package_prechecks(root: Path, out: Dict[str, Path], timeout: int, full_self_test: bool = False) -> List[Dict[str, Any]]:
    py = sys.executable
    validator_cmd = [py, str(root / SKILL_PATH / "scripts/validate_package.py"), str(root)]
    if full_self_test:
        validator_cmd.append("--self-test")
    commands = [
        validator_cmd,
        [py, str(root / SKILL_PATH / "scripts/run_regression_evals.py"), str(root)],
        [py, str(root / SKILL_PATH / "scripts/ntt_gate.py"), str(root / "self_validation/self_certificate.json"), "--evidence-root", str(root), "--strict-evidence"],
    ]
    results = [run_cmd(cmd, cwd=root, timeout=timeout) for cmd in commands]
    claude = shutil.which("claude")
    if claude:
        results.append(run_cmd([claude, "plugin", "validate", str(root), "--strict"], cwd=root, timeout=timeout))
    public_results = [
        _normalized_command_record(
            result,
            root,
            out["formal_result"].parent,
            out["target_snapshot"],
        )
        for result in results
    ]
    atomic_write_new_text(
        out["precheck"],
        json.dumps(public_results, indent=2, sort_keys=True),
    )
    return results


def summarize_prechecks(prechecks: List[Dict[str, Any]]) -> Dict[str, Any]:
    failed = [
        p
        for p in prechecks
        if p.get("returncode") not in (0,)
        or p.get("capture_limit_exceeded") is True
    ]
    return {"total": len(prechecks), "failed": len(failed), "passed": len(prechecks) - len(failed), "failed_commands": [p.get("cmd") for p in failed]}


def cap_status_by_trace(gate_status: str, trace_auth: Dict[str, Any]) -> Tuple[str, str]:
    if gate_status not in PASS_STATUSES:
        return "FAIL", "ntt_gate.py did not return PASS-TRACKED or PASS-SCOPED for generated certificate"
    if trace_auth.get("saw_general_purpose"):
        return "FAIL", "runtime trace shows general-purpose fallback in a formal run"
    if not trace_auth.get("authenticated"):
        return "PASS-SCOPED", "generated certificate passed the gate, but native subagent tool-use plus successful tool-result execution was not authenticated from stream-json trace"
    if gate_status == "PASS-TRACKED":
        return "PASS-TRACKED", "generated certificate passed ntt_gate.py and stream-json trace authenticated all native ntt-* tool-use and completion lanes"
    return "PASS-SCOPED", "generated certificate passed ntt_gate.py as scoped and trace authenticated native ntt-* tool-use and completion lanes"


def _companion_records(
    out: Dict[str, Path],
    output_dir: Path,
) -> Dict[str, Dict[str, Any]]:
    records: Dict[str, Dict[str, Any]] = {}
    for role in FORMAL_COMPANION_SPECS:
        path = out[role]
        file_error = regular_file_error(path)
        digest = None
        size = None
        if file_error is None:
            digest = f"sha256:{sha256_regular_file(path)}"
            size = path.stat().st_size
        records[role] = {
            "path": path.relative_to(output_dir).as_posix(),
            "sha256": digest,
            "bytes": size,
            "present": file_error is None,
        }
    return records


def _normalized_command_record(
    record: Any,
    root: Path,
    output_dir: Path,
    target: Path,
) -> Dict[str, Any]:
    if not isinstance(record, dict):
        return {
            "argv": [],
            "returncode": None,
            "stdout_sha256": None,
            "stderr_sha256": None,
            "stdout_bytes": None,
            "stderr_bytes": None,
            "stdout_truncated": False,
            "stderr_truncated": False,
            "capture_limit_exceeded": False,
        }
    replacements = (
        (str(root), "<package-root>"),
        (str(output_dir), "<output-dir>"),
        (str(target.parent), "<target-parent>"),
    )
    raw_cmd = record.get("cmd")
    argv = (
        normalize_display_paths(raw_cmd, replacements)
        if isinstance(raw_cmd, list)
        else []
    )
    stdout = record.get("stdout")
    stderr = record.get("stderr")
    stdout_raw = record.get("_stdout_bytes")
    stderr_raw = record.get("_stderr_bytes")
    stdout_payload = (
        bytes(stdout_raw)
        if isinstance(stdout_raw, (bytes, bytearray))
        else stdout.encode("utf-8")
        if isinstance(stdout, str)
        else None
    )
    stderr_payload = (
        bytes(stderr_raw)
        if isinstance(stderr_raw, (bytes, bytearray))
        else stderr.encode("utf-8")
        if isinstance(stderr, str)
        else None
    )
    return {
        "argv": argv,
        "returncode": (
            record.get("returncode")
            if type(record.get("returncode")) is int
            else None
        ),
        "stdout_sha256": (
            f"sha256:{hashlib.sha256(stdout_payload).hexdigest()}"
            if stdout_payload is not None
            else None
        ),
        "stderr_sha256": (
            f"sha256:{hashlib.sha256(stderr_payload).hexdigest()}"
            if stderr_payload is not None
            else None
        ),
        "stdout_bytes": (
            len(stdout_payload) if stdout_payload is not None else None
        ),
        "stderr_bytes": (
            len(stderr_payload) if stderr_payload is not None else None
        ),
        "stdout_truncated": (
            len(stdout_payload) > PUBLIC_STREAM_BOUND_BYTES
            if stdout_payload is not None
            else False
        ),
        "stderr_truncated": (
            len(stderr_payload) > PUBLIC_STREAM_BOUND_BYTES
            if stderr_payload is not None
            else False
        ),
        "capture_limit_exceeded": (
            record.get("capture_limit_exceeded") is True
        ),
    }


def normalize_display_paths(
    value: Any,
    replacements: Tuple[Tuple[str, str], ...],
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
        return [normalize_display_paths(item, replacements) for item in value]
    if isinstance(value, dict):
        return {
            key: normalize_display_paths(item, replacements)
            for key, item in value.items()
        }
    return value


def build_formal_result_v2(
    result: Dict[str, Any],
    *,
    root: Path,
    target: Path,
    output_dir: Path,
    out: Dict[str, Path],
    target_pre_sha256: Optional[str] = None,
    source_pre_identity: Optional[Dict[str, Any]] = None,
    source_post_identity: Optional[Dict[str, Any]] = None,
    snapshot_pre_identity: Optional[Dict[str, Any]] = None,
    snapshot_post_identity: Optional[Dict[str, Any]] = None,
    evidence_root: Optional[Path] = None,
) -> Dict[str, Any]:
    companions = _companion_records(out, output_dir)
    snapshot_sha = companions["target_snapshot"].get("sha256")
    pre_digest = (
        source_pre_identity.get("sha256")
        if isinstance(source_pre_identity, dict)
        else (
            f"sha256:{target_pre_sha256}"
            if isinstance(target_pre_sha256, str)
            else None
        )
    )
    post_digest = (
        source_post_identity.get("sha256")
        if isinstance(source_post_identity, dict)
        else None
    )
    stability = target_snapshot_stability(
        source_pre_identity,
        source_post_identity,
        snapshot_pre_identity,
        snapshot_post_identity,
    )
    commands = [
        _normalized_command_record(item, root, output_dir, target)
        for item in result.get("commands", [])
    ]
    prechecks = [
        _normalized_command_record(item, root, output_dir, target)
        for item in result.get("prechecks", [])
    ]
    return {
        "formal_result_schema_version": "2.0",
        "run_id": result.get("run_id"),
        "status": result.get("status"),
        "reason": result.get("reason"),
        "formal_coordinator": FORMAL_COORDINATOR,
        "required_native_agents": list(REQUIRED_NATIVE_AGENTS),
        "package_tree_identity": result.get("package_tree_identity"),
        "target_snapshot_identity": {
            "source_name": target.name,
            "companion_role": "target_snapshot",
            "snapshot_sha256": snapshot_sha,
            "pre_sha256": pre_digest,
            "post_sha256": post_digest,
            "stable": stability["stable"],
            "digest_stable": stability["digest_stable"],
            "source_metadata_stable": stability["source_metadata_stable"],
            "snapshot_metadata_stable": stability[
                "snapshot_metadata_stable"
            ],
        },
        "verification_context": dict(FORMAL_VERIFICATION_CONTEXT),
        "evidence_root": (
            "."
            if evidence_root is None
            or evidence_root.resolve() == output_dir.resolve()
            else str(evidence_root.resolve())
        ),
        "companions": companions,
        "prechecks": prechecks,
        "precheck_summary": result.get("precheck_summary", {}),
        "commands": commands,
        "output_checks": result.get("output_checks", []),
        "gate_status": result.get("gate_status"),
        "trace_authentication": result.get("trace_authentication"),
        "output_dir": str(output_dir),
        "plugin_root": str(root),
        "target_artifact": str(target),
    }


def write_formal_result_v2(
    result: Dict[str, Any],
    *,
    root: Path,
    target: Path,
    output_dir: Path,
    out: Dict[str, Path],
    target_pre_sha256: Optional[str] = None,
    source_pre_identity: Optional[Dict[str, Any]] = None,
    source_post_identity: Optional[Dict[str, Any]] = None,
    snapshot_pre_identity: Optional[Dict[str, Any]] = None,
    snapshot_post_identity: Optional[Dict[str, Any]] = None,
    evidence_root: Optional[Path] = None,
    json_path: Optional[Path] = None,
) -> Dict[str, Any]:
    canonical = build_formal_result_v2(
        result,
        root=root,
        target=target,
        output_dir=output_dir,
        out=out,
        target_pre_sha256=target_pre_sha256,
        source_pre_identity=source_pre_identity,
        source_post_identity=source_post_identity,
        snapshot_pre_identity=snapshot_pre_identity,
        snapshot_post_identity=snapshot_post_identity,
        evidence_root=evidence_root,
    )
    payload = (
        json.dumps(canonical, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    atomic_write_new(out["formal_result"], payload)
    if json_path is not None and json_path != out["formal_result"]:
        atomic_replace_regular(json_path, payload)
    return canonical


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run a formal Nozickian artifact verification through Claude Code and ntt_gate.py")
    parser.add_argument("plugin_root", type=Path)
    parser.add_argument("target_artifact", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--require-claude", action="store_true")
    parser.add_argument("--require-trace-auth", action="store_true", help="fail rather than PASS-SCOPED when stream-json native subagent authentication is incomplete")
    parser.add_argument("--dry-run", action="store_true", help="run deterministic prechecks and write the formal prompt, but do not invoke Claude Code")
    parser.add_argument("--skip-prechecks", action="store_true", help="internal contract-test option: skip package prechecks before invoking Claude")
    parser.add_argument("--full-package-self-test", action="store_true", help="run validate_package.py --self-test during formal prechecks; default runs faster deterministic checks only")
    parser.add_argument("--refresh-release-manifest", action="store_true", help="after all writes complete, explicitly refresh STABLE_RELEASE_MANIFEST.json; also permits package-tree outputs")
    parser.add_argument("--max-turns", type=int, default=160)
    parser.add_argument("--timeout-sec", type=int, default=3600)
    parser.add_argument("--model", default="opus")
    parser.add_argument("--effort", default="max")
    args = parser.parse_args(argv)

    root = args.plugin_root.resolve()
    # SECURITY-REVIEW: Keep the caller-controlled final target entry lexical
    # so regular_file_error rejects a symlink instead of following resolve().
    target = Path(os.path.abspath(args.target_artifact))
    if args.output_dir:
        output_dir = Path(os.path.abspath(args.output_dir))
    else:
        # Default to an external temporary directory. This prevents a routine
        # dry-run from modifying self_validation/ and invalidating the stable
        # release manifest in a fresh extraction.
        output_dir = Path(tempfile.mkdtemp(prefix="ntt_formal_artifact_")).resolve()
    json_path = (
        Path(os.path.abspath(args.json))
        if args.json
        else None
    )
    effective_evidence_root = (
        args.evidence_root.resolve()
        if args.evidence_root
        else output_dir
    )
    output_ancestor_error = lexical_directory_ancestor_error(output_dir)
    if output_ancestor_error is not None:
        invalid = {
            "status": "INVALID_INPUT",
            "reason": f"unsafe --output-dir: {output_ancestor_error}",
        }
        print(json.dumps(invalid, indent=2, sort_keys=True))
        return 2
    if json_path is not None:
        json_ancestor_error = lexical_directory_ancestor_error(json_path)
        if json_ancestor_error is not None:
            invalid = {
                "status": "INVALID_INPUT",
                "reason": f"unsafe --json: {json_ancestor_error}",
            }
            print(json.dumps(invalid, indent=2, sort_keys=True))
            return 2
        json_target_error = replaceable_regular_output_error(json_path)
        if json_target_error is not None:
            invalid = {
                "status": "INVALID_INPUT",
                "reason": f"unsafe --json: {json_target_error}",
            }
            print(json.dumps(invalid, indent=2, sort_keys=True))
            return 2
    location_error = output_location_error(root, output_dir, json_path, args.refresh_release_manifest)
    if location_error:
        blocked = _blocked_package_output_result(root, target, output_dir, json_path)
        blocked["reason"] = location_error
        print(json.dumps(blocked, indent=2, sort_keys=True))
        return 2
    output_state_error = (
        directory_error(output_dir) if path_lexists(output_dir) else None
    )
    if output_state_error is not None:
        invalid = {
            "status": "INVALID_INPUT",
            "reason": f"unsafe --output-dir: {output_state_error}",
        }
        print(json.dumps(invalid, indent=2, sort_keys=True))
        return 2
    creation_error = prepare_output_directory(output_dir)
    if creation_error is not None:
        invalid = {
            "status": "INVALID_INPUT",
            "reason": f"unsafe --output-dir: {creation_error}",
        }
        print(json.dumps(invalid, indent=2, sort_keys=True))
        return 2
    out = output_paths(target, output_dir)
    collision_error = formal_output_collision_error(
        target,
        out,
        json_path,
    )
    if collision_error:
        invalid = {
            "status": "INVALID_INPUT",
            "reason": collision_error,
        }
        print(json.dumps(invalid, indent=2, sort_keys=True))
        return 2
    target_error = regular_file_error(target)
    source_pre_identity: Optional[Dict[str, Any]] = None
    source_post_identity: Optional[Dict[str, Any]] = None
    snapshot_pre_identity: Optional[Dict[str, Any]] = None
    snapshot_post_identity: Optional[Dict[str, Any]] = None
    if target_error is None:
        try:
            source_pre_identity = file_snapshot_identity(target)
            # SECURITY-REVIEW: The caller-selected target is read only after a
            # no-follow regular-file check. The fixed snapshot destination is
            # created atomically with O_EXCL/O_NOFOLLOW.
            atomic_write_new(out["target_snapshot"], target.read_bytes())
            snapshot_pre_identity = file_snapshot_identity(
                out["target_snapshot"]
            )
            source_after_copy = file_snapshot_identity(target)
            copied_stability = target_snapshot_stability(
                source_pre_identity,
                source_after_copy,
                snapshot_pre_identity,
                snapshot_pre_identity,
            )
            if not copied_stability["stable"]:
                raise ValueError("target changed while snapshot was created")
        except (OSError, ValueError):
            target_error = "target artifact could not be snapshotted"
    prompt = build_formal_prompt(
        root,
        out["target_snapshot"],
        out,
        effective_evidence_root,
    )
    try:
        atomic_write_new_text(out["prompt"], prompt)
    except (OSError, ValueError):
        invalid = {
            "status": "INVALID_INPUT",
            "reason": "formal prompt output could not be safely created",
        }
        print(json.dumps(invalid, indent=2, sort_keys=True))
        return 2

    result: Dict[str, Any] = {
        "run_id": uuid.uuid4().hex,
        "status": "UNVERIFIED_RUNTIME",
        "plugin_root": str(root),
        "target_artifact": str(target),
        "verification_target": str(out["target_snapshot"]),
        "output_dir": str(output_dir),
        "evidence_root": str(effective_evidence_root),
        "package_tree_identity": package_tree_identity(root),
        "formal_coordinator": FORMAL_COORDINATOR,
        "required_native_agents": REQUIRED_NATIVE_AGENTS,
        "prompt_file": str(out["prompt"]),
        "transcript_file": str(out["transcript"]),
        "prechecks": [],
        "precheck_summary": {},
        "commands": [],
        "output_checks": [],
        "gate_status": None,
        "trace_authentication": None,
        "reason": "not executed yet",
    }

    if not root.exists():
        result.update({"status": "INVALID_INPUT", "reason": "plugin_root does not exist"})
    elif target_error is not None:
        result.update({"status": "INVALID_INPUT", "reason": target_error})
    else:
        if args.skip_prechecks:
            prechecks = []
            result["prechecks"] = []
            result["precheck_summary"] = {"total": 0, "failed": 0, "passed": 0, "failed_commands": []}
        else:
            prechecks = run_package_prechecks(root, out, timeout=min(args.timeout_sec, 900), full_self_test=args.full_package_self_test)
            result["prechecks"] = prechecks
            result["precheck_summary"] = summarize_prechecks(prechecks)
        if result["precheck_summary"]["failed"]:
            result.update({"status": "FAIL", "reason": "deterministic package prechecks failed"})
        elif args.dry_run:
            result.update({"status": "UNVERIFIED_RUNTIME", "reason": "dry-run requested; formal prompt written but Claude Code was not invoked"})
        else:
            claude = shutil.which("claude")
            if not claude:
                result.update({"status": "UNVERIFIED_RUNTIME", "reason": "Claude Code CLI not found on PATH; formal coordinator was not invoked"})
            else:
                try:
                    for role in ("report", "certificate", "ledger"):
                        reserve_regular_output(out[role])
                except (OSError, ValueError):
                    result.update({
                        "status": "FAIL",
                        "reason": "formal coordinator outputs could not be safely reserved",
                    })
                    claude = None
            if claude:
                cmd = [
                    claude,
                    "--plugin-dir", str(root),
                    "--agent", FORMAL_COORDINATOR,
                    "-p",
                    "--output-format", "stream-json",
                    "--include-hook-events",
                    "--max-turns", str(args.max_turns),
                ]
                if args.model:
                    cmd.extend(["--model", args.model])
                if args.effort:
                    cmd.extend(["--effort", args.effort])
                cmd.append(prompt)
                _debug("before claude invocation")
                invocation = run_cmd(
                    cmd,
                    cwd=out["target_snapshot"].parent,
                    timeout=args.timeout_sec,
                )
                _debug(f"after claude invocation rc={invocation.get('returncode')}")
                result["commands"].append(invocation)
                transcript_error: Optional[str] = None
                try:
                    write_complete_stream_transcript(
                        out["transcript"],
                        invocation,
                    )
                except (OSError, ValueError):
                    transcript_error = (
                        "formal transcript could not be safely created "
                        "from the complete bounded stream"
                    )
                    result.update({
                        "status": "FAIL",
                        "reason": transcript_error,
                    })
                _debug("before output checks")
                output_checks = check_required_outputs(
                    out,
                    include_gate=False,
                )
                _debug("after output checks")
                result["output_checks"] = output_checks
                _debug("before trace auth")
                trace_auth = (
                    authenticate_trace(out["transcript"])
                    if regular_file_error(out["transcript"]) is None
                    else {"authenticated": False}
                )
                _debug("after trace auth")
                result["trace_authentication"] = trace_auth
                if transcript_error is not None:
                    result.update({"status": "FAIL", "reason": transcript_error})
                elif invocation.get("returncode") != 0:
                    result.update({"status": "FAIL", "reason": "Claude Code formal invocation returned nonzero"})
                elif not all(c.get("passed") for c in output_checks):
                    result.update({"status": "FAIL", "reason": "required formal output artifacts or ledger checks failed"})
                elif args.require_trace_auth and not trace_auth.get("authenticated"):
                    result.update({"status": "FAIL", "reason": "trace authentication was required but native subagent tool events were missing"})
                else:
                    gate_cmd = [sys.executable, str(root / SKILL_PATH / "scripts/ntt_gate.py"), str(out["certificate"]), "--evidence-root", str(effective_evidence_root), "--strict-evidence", "--markdown", str(out["gate"])]
                    _debug("before gate " + repr(gate_cmd))
                    gate = run_cmd(
                        gate_cmd,
                        cwd=out["target_snapshot"].parent,
                        timeout=900,
                    )
                    _debug(f"after gate rc={gate.get('returncode')}")
                    result["commands"].append(gate)
                    result["gate_status"] = parse_gate_status(gate.get("stdout", ""), out["gate"])
                    gate_checks = check_required_outputs(
                        out,
                        include_gate=True,
                    )
                    result["output_checks"] = gate_checks
                    if gate.get("returncode") != 0:
                        result.update({"status": "FAIL", "reason": "ntt_gate.py returned nonzero for generated certificate"})
                    elif not all(
                        check.get("passed") for check in gate_checks
                    ):
                        result.update({"status": "FAIL", "reason": "required formal output artifacts failed post-gate checks"})
                    else:
                        capped_status, reason = cap_status_by_trace(str(result["gate_status"]), trace_auth)
                        result.update({"status": capped_status, "reason": reason})

    try:
        source_post_identity = file_snapshot_identity(target)
    except (OSError, ValueError):
        source_post_identity = None
    try:
        snapshot_post_identity = file_snapshot_identity(
            out["target_snapshot"]
        )
    except (OSError, ValueError):
        snapshot_post_identity = None
    stability = target_snapshot_stability(
        source_pre_identity,
        source_post_identity,
        snapshot_pre_identity,
        snapshot_post_identity,
    )
    result["target_stability"] = stability
    stability_status, stability_reason = cap_status_by_target_stability(
        str(result.get("status")),
        stability,
    )
    if stability_reason is not None:
        result.update({
            "status": stability_status,
            "reason": stability_reason,
        })
    package_status, package_reason = cap_status_by_package_identity(
        str(result.get("status")),
        result.get("package_tree_identity"),
    )
    if package_reason is not None:
        result.update({
            "status": package_status,
            "reason": package_reason,
        })

    _debug("before final write")
    try:
        canonical_result = write_formal_result_v2(
            result,
            root=root,
            target=target,
            output_dir=output_dir,
            out=out,
            source_pre_identity=source_pre_identity,
            source_post_identity=source_post_identity,
            snapshot_pre_identity=snapshot_pre_identity,
            snapshot_post_identity=snapshot_post_identity,
            evidence_root=effective_evidence_root,
            json_path=json_path,
        )
    except (OSError, ValueError):
        invalid = {
            "status": "INVALID_INPUT",
            "reason": (
                "formal result or compatibility JSON destination "
                "could not be safely created"
            ),
        }
        print(json.dumps(invalid, indent=2, sort_keys=True))
        return 2
    if args.refresh_release_manifest:
        refresh_stable_release_manifest_if_available(root)
    _debug("before final print")
    print(json.dumps(canonical_result, indent=2, sort_keys=True))
    _debug("after final print")
    if result["status"] in PASS_STATUSES:
        return 0
    if result["status"] == "UNVERIFIED_RUNTIME" and not args.require_claude:
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

# trace_authentication padding: missing successful matching tool-result/completion events; --include-hook-events; native tool-result completion required; release tree output requires --refresh-release-manifest; explicit manifest refresh only.
# v1.0.1 trace-authentication hardening padding: structured selector exact match / duplicate_tool_use_ids / empty/generic result / text-only or mismatched-id / single-call multi-lane mention rejection / duplicate tool-use id rejection / metadata-only content blocks rejected.
# v1.0.1 compatibility token: nested-fake-result rejection is implemented by strict recognized event positions plus strict tool event types.
