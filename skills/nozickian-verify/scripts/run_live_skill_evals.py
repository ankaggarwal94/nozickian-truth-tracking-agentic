#!/usr/bin/env python3
"""Live Claude Code plugin eval harness for Nozickian verification.

This harness is intentionally evidence-producing and conservative. It can run
actual slash-command fixture invocations in non-interactive print mode when the
Claude Code CLI is installed. If the runtime cannot be exercised, it records
UNVERIFIED_RUNTIME rather than treating a version check as a pass.
"""
from __future__ import annotations
import argparse, contextlib, ctypes, hashlib, importlib.util, io, json, math, os, re, shutil, signal, stat, subprocess, sys, tempfile, threading, time, unicodedata, uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Dict, List, Mapping, Sequence, Tuple, cast

STATUS_TOKENS = ("PASS-TRACKED", "PASS-SCOPED", "LIMITED", "FAIL", "UNVERIFIED")
ACCEPTABLE_PASS_STATUSES = {"PASS-TRACKED", "PASS-SCOPED"}
REJECT_STATUSES = {"LIMITED", "FAIL", "UNVERIFIED"}
POSITIVE_ENVELOPE_STATUSES = {
    "ok",
    "success",
    "succeeded",
    "complete",
    "completed",
    "done",
}
REQUIRED_OUTPUT_TERMS = ("method", "false-world", "true-world", "gate")
PROVENANCE_SCHEMA_VERSION = "1.0"
CLAUDE_VERSION_PATTERN = r"\b\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?(?:\s+\(Claude Code\))?\b"
RAW_EXTERNAL_TRANSCRIPT_POLICY = (
    "Raw external Claude transcripts captured separately from this harness may "
    "retain literal resolved paths. Bundled and harness-written JSON summaries "
    "use normalized-display values."
)
MAX_CAPTURE_BYTES = 64 * 1024 * 1024
FIXTURE_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
PIPE_CLOSE_GRACE_SEC = 0.5
READER_JOIN_GRACE_SEC = 1.0
DETACHED_CHILD_CLEANUP_TIMEOUT_SEC = 0.5
DETACHED_CHILD_QUIET_SEC = 0.05
MAX_PROC_SCAN_ENTRIES = 100_000
_SUBREAPER_ENABLED: bool | None = None


class DuplicateJsonKeyError(ValueError):
    """A JSON object repeats a key and is therefore ambiguous."""


def _strict_json_object(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    value: Dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateJsonKeyError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def strict_json_loads(text: str) -> Any:
    """Parse standards-compliant JSON without duplicate-key last-wins."""
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


def _linux_process_graph() -> Tuple[int, Dict[int, Tuple[int, int]]]:
    """Return self host PID and host-pid -> (parent, signalable pid) graph."""
    self_host_pid = int(Path("/proc/self").resolve(strict=True).name)
    with Path("/proc/self/status").open(
        "r", encoding="utf-8", errors="replace"
    ) as stream:
        self_status = stream.read(64 * 1024)
    self_namespace_pids: List[int] | None = None
    for line in self_status.splitlines():
        if line.startswith("NSpid:"):
            try:
                self_namespace_pids = [
                    int(value) for value in line.split(":", 1)[1].split()
                ]
            except ValueError as exc:
                raise OSError("invalid self NSpid identity") from exc
            break
    if not self_namespace_pids:
        raise OSError("/proc status lacks NSpid")
    if self_namespace_pids[0] != self_host_pid:
        raise OSError("/proc self host identity mismatch")
    namespace_depth = len(self_namespace_pids)
    graph: Dict[int, Tuple[int, int]] = {}
    scanned = 0
    with os.scandir("/proc") as entries:
        for entry in entries:
            if not entry.name.isdigit():
                continue
            scanned += 1
            if scanned > MAX_PROC_SCAN_ENTRIES:
                raise OSError("/proc process scan bound exceeded")
            try:
                with open(
                    os.path.join(entry.path, "status"),
                    "r",
                    encoding="utf-8",
                    errors="replace",
                ) as stream:
                    status = stream.read(64 * 1024)
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
            parent_host_pid: int | None = None
            namespace_pids: List[int] | None = None
            try:
                for line in status.splitlines():
                    if line.startswith("PPid:"):
                        parent_host_pid = int(line.split(":", 1)[1].strip())
                    elif line.startswith("NSpid:"):
                        namespace_pids = [
                            int(value)
                            for value in line.split(":", 1)[1].split()
                        ]
            except ValueError as exc:
                raise OSError("invalid numeric identity in /proc status") from exc
            if (
                parent_host_pid is not None
                and namespace_pids
                and len(namespace_pids) >= namespace_depth
                and namespace_pids[0] == int(entry.name)
                and namespace_pids[namespace_depth - 1] > 0
            ):
                graph[int(entry.name)] = (
                    parent_host_pid,
                    namespace_pids[namespace_depth - 1],
                )
    if self_host_pid not in graph:
        raise OSError("/proc process graph omits self")
    return self_host_pid, graph


def _linux_descendant_closure(
    graph: Mapping[int, Tuple[int, int]], roots: set[int]
) -> set[int]:
    """Return roots and their complete transitive host-PID descendants."""
    children: Dict[int, set[int]] = {}
    for host_pid, (parent_host_pid, _namespace_pid) in graph.items():
        children.setdefault(parent_host_pid, set()).add(host_pid)
    closure: set[int] = set()
    pending = list(roots)
    while pending:
        host_pid = pending.pop()
        if host_pid in closure:
            continue
        closure.add(host_pid)
        pending.extend(children.get(host_pid, ()))
    return closure


def _enable_linux_child_subreaper() -> bool:
    """Enable Linux orphan reparenting so setsid descendants remain visible."""
    global _SUBREAPER_ENABLED
    if _SUBREAPER_ENABLED is not None:
        return _SUBREAPER_ENABLED
    if not sys.platform.startswith("linux"):
        _SUBREAPER_ENABLED = False
        return False
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
        if prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
            raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER failed")
        _linux_process_graph()
    except (AttributeError, OSError, ValueError):
        _SUBREAPER_ENABLED = False
    else:
        _SUBREAPER_ENABLED = True
    return _SUBREAPER_ENABLED


def process_containment_scope() -> Dict[str, Any]:
    detached_contained = _enable_linux_child_subreaper()
    return {
        "mechanism": (
            "linux-child-subreaper-plus-process-group"
            if detached_contained
            else "initial-posix-process-group"
            if os.name == "posix"
            else "leader-process-only"
        ),
        "cleanup_after_leader_exit": os.name == "posix",
        "detached_session_descendants_contained": detached_contained,
    }


def _reap_child_nonblocking(pid: int) -> None:
    try:
        os.waitpid(pid, os.WNOHANG)
    except (ChildProcessError, ProcessLookupError):
        pass


def _cleanup_detached_descendants(
    baseline: Mapping[str, Any] | None,
) -> Dict[str, Any]:
    """Kill/reap the full nonbaseline descendant closure to bounded quiescence."""
    if baseline is None:
        return {
            "supported": False,
            "survivor_seen": False,
            "cleanup_complete": False,
            "pids_seen": 0,
        }
    parent_host_pid = baseline.get("parent_host_pid")
    baseline_roots = baseline.get("baseline_roots")
    if type(parent_host_pid) is not int or not isinstance(baseline_roots, set):
        return {
            "supported": True,
            "survivor_seen": False,
            "cleanup_complete": False,
            "pids_seen": 0,
        }
    deadline = time.monotonic() + DETACHED_CHILD_CLEANUP_TIMEOUT_SEC
    quiet_since: float | None = None
    seen_host_pids: set[int] = set()
    while time.monotonic() < deadline:
        observed_self_host_pid, graph = _linux_process_graph()
        if observed_self_host_pid != parent_host_pid:
            return {
                "supported": True,
                "survivor_seen": bool(seen_host_pids),
                "cleanup_complete": False,
                "pids_seen": len(seen_host_pids),
            }
        all_descendants = _linux_descendant_closure(
            graph, {parent_host_pid}
        ) - {parent_host_pid}
        excluded = _linux_descendant_closure(
            graph, baseline_roots
        )
        current_host_pids = all_descendants - excluded
        if current_host_pids:
            seen_host_pids.update(current_host_pids)
            quiet_since = None
            # Compute one complete tree snapshot before signaling. This avoids
            # the depth-times-scan escape of direct-child-only subreaping.
            for host_pid in current_host_pids:
                namespace_pid = graph[host_pid][1]
                try:
                    os.kill(namespace_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            for host_pid in current_host_pids:
                if graph[host_pid][0] == parent_host_pid:
                    _reap_child_nonblocking(graph[host_pid][1])
        else:
            if quiet_since is None:
                quiet_since = time.monotonic()
            elif time.monotonic() - quiet_since >= DETACHED_CHILD_QUIET_SEC:
                break
        time.sleep(0.005)
    observed_self_host_pid, graph = _linux_process_graph()
    all_descendants = _linux_descendant_closure(
        graph, {observed_self_host_pid}
    ) - {observed_self_host_pid}
    excluded = _linux_descendant_closure(graph, baseline_roots)
    remaining = all_descendants - excluded
    for host_pid in remaining:
        namespace_pid = graph[host_pid][1]
        try:
            os.kill(namespace_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if graph[host_pid][0] == observed_self_host_pid:
            _reap_child_nonblocking(namespace_pid)
    return {
        "supported": True,
        "survivor_seen": bool(seen_host_pids),
        "cleanup_complete": not remaining,
        "pids_seen": len(seen_host_pids),
    }


def normalize_display(
    value: Any,
    replacements: Sequence[Tuple[str, str]],
) -> Any:
    """Recursively normalize exact producer paths for display serialization."""
    ordered = sorted(
        ((raw, display) for raw, display in replacements if raw),
        key=lambda item: len(item[0]),
        reverse=True,
    )
    if isinstance(value, str):
        normalized = value
        for raw, display in ordered:
            normalized = re.sub(
                re.escape(raw) + r"(?=$|[\\/])",
                lambda _match, replacement=display: replacement,
                normalized,
            )
        return normalized
    if isinstance(value, list):
        return [normalize_display(item, ordered) for item in value]
    if isinstance(value, tuple):
        return [normalize_display(item, ordered) for item in value]
    if isinstance(value, Mapping):
        return {
            key: normalize_display(item, ordered)
            for key, item in value.items()
        }
    return value


def _cleanup_spawned_process_after_setup_failure(
    proc: subprocess.Popen[Any],
    baseline: Mapping[str, Any],
    readers: Sequence[threading.Thread],
) -> None:
    """Own and clean a child if pipe-reader setup fails after Popen."""
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except (OSError, ProcessLookupError):
        try:
            proc.kill()
        except OSError:
            pass
    try:
        proc.wait(timeout=READER_JOIN_GRACE_SEC)
    except (OSError, subprocess.TimeoutExpired):
        try:
            proc.kill()
            proc.wait(timeout=READER_JOIN_GRACE_SEC)
        except (OSError, subprocess.TimeoutExpired):
            pass
    try:
        _cleanup_detached_descendants(baseline)
    except Exception:
        pass
    for stream in (proc.stdout, proc.stderr):
        if stream is None:
            continue
        try:
            stream.close()
        except (OSError, ValueError):
            pass
    for reader in readers:
        if reader.ident is None:
            continue
        try:
            reader.join(timeout=READER_JOIN_GRACE_SEC)
        except RuntimeError:
            pass


def _drain_bounded_stream(
    stream: Any,
    stop: threading.Event,
) -> Dict[str, Any]:
    """Drain one pipe completely or record a fail-closed reader error."""
    retained = bytearray()
    digest = hashlib.sha256()
    observed = 0
    exceeded = False
    read_error: str | None = None
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
    except (OSError, ValueError) as exc:
        read_error = f"{type(exc).__name__}: stream read failed"
        stop.set()
    finally:
        try:
            stream.close()
        except Exception:
            pass
    return {
        "raw": bytes(retained),
        "observed": observed,
        "sha256": digest.hexdigest(),
        "exceeded": exceeded,
        "read_error": read_error,
    }


def run_cmd(
    cmd: List[str],
    cwd: Path | None = None,
    timeout: int = 300,
    display_replacements: Sequence[Tuple[str, str]] = (),
) -> Dict[str, Any]:
    literal_cmd = list(cmd)
    display_cmd = normalize_display(literal_cmd, display_replacements)
    display_cmd[0] = "<claude-cli>"
    command_metadata = {
        "representation": "normalized-display",
        "resolution_strategy": "shutil.which-once-to-resolved-absolute-target",
        "resolved_executable_path_recorded": False,
        "normalized_fields": ["cmd", "stdout", "stderr"],
        "raw_external_transcript_policy": RAW_EXTERNAL_TRANSCRIPT_POLICY,
    }
    started = time.time()
    try:
        containment_scope = process_containment_scope()
        if containment_scope.get(
            "detached_session_descendants_contained"
        ) is not True:
            raise OSError("detached-descendant containment is unavailable")
        self_host_pid, initial_graph = _linux_process_graph()
        baseline = {
            "parent_host_pid": self_host_pid,
            "baseline_roots": {
                host_pid
                for host_pid, (parent_host_pid, _namespace_pid)
                in initial_graph.items()
                if parent_host_pid == self_host_pid
            },
        }
        stop = threading.Event()
        states: Dict[str, Dict[str, Any]] = {}

        def drain(name: str, stream: Any) -> None:
            states[name] = _drain_bounded_stream(stream, stop)

        # SECURITY-REVIEW: Fixed argv invokes the PATH-resolved Claude executable
        # directly; no shell parsing or command-string interpolation is used.
        # Each pipe is drained concurrently and bounded while the child runs.
        proc = subprocess.Popen(
            literal_cmd,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=(os.name == "posix"),
        )
        readers: List[threading.Thread] = []
        try:
            assert proc.stdout is not None and proc.stderr is not None
            readers = [
                threading.Thread(target=drain, args=("stdout", proc.stdout), daemon=True),
                threading.Thread(target=drain, args=("stderr", proc.stderr), daemon=True),
            ]
            for reader in readers:
                reader.start()
        except BaseException:
            _cleanup_spawned_process_after_setup_failure(
                proc,
                baseline,
                readers,
            )
            raise
        deadline = time.monotonic() + timeout
        timed_out = False
        descendant_pipe_leak = False
        process_group_terminated = False
        process_group_cleanup_attempted = False
        normal_exit_group_survivor = False
        leader_exited_at: float | None = None

        def terminate_group() -> bool:
            nonlocal process_group_cleanup_attempted, process_group_terminated
            process_group_cleanup_attempted = True
            try:
                if os.name == "posix":
                    os.killpg(proc.pid, signal.SIGKILL)
                else:
                    proc.kill()
                process_group_terminated = True
                return True
            except ProcessLookupError:
                return False
            except OSError:
                try:
                    proc.kill()
                    process_group_terminated = True
                    return True
                except OSError:
                    return False

        while True:
            if stop.is_set():
                terminate_group()
                break
            if proc.poll() is not None:
                # The leader's exit starts the containment boundary. Kill the
                # original group immediately, then sweep the complete detached
                # descendant graph below; waiting on inherited pipes would
                # grant descendants a post-leader mutation window.
                if os.name == "posix":
                    normal_exit_group_survivor = terminate_group()
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
        # Reap detached descendants before joining pipe readers. A child can
        # call setsid(2) while retaining stdout/stderr; waiting for those pipes
        # first would grant it an avoidable post-leader mutation window.
        detached_cleanup = _cleanup_detached_descendants(baseline)
        detached_descendant_survivor = bool(
            detached_cleanup.get("survivor_seen")
        )
        process_containment_cleanup_complete = bool(
            detached_cleanup.get("cleanup_complete")
        )
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
        descendant_pipe_leak = reader_join_timed_out
        empty_sha = hashlib.sha256(b"").hexdigest()
        stdout_state = states.get("stdout", {"raw": b"", "observed": 0, "sha256": empty_sha, "exceeded": False, "read_error": "reader state missing"})
        stderr_state = states.get("stderr", {"raw": b"", "observed": 0, "sha256": empty_sha, "exceeded": False, "read_error": "reader state missing"})
        exceeded = bool(stdout_state["exceeded"] or stderr_state["exceeded"])
        stream_read_error = bool(
            stdout_state.get("read_error")
            or stderr_state.get("read_error")
        )
        stdout_text = bytes(stdout_state["raw"]).decode("utf-8", errors="replace")
        stderr_text = bytes(stderr_state["raw"]).decode("utf-8", errors="replace")
        return {
            "cmd": display_cmd,
            "command_metadata": command_metadata,
            "returncode": (
                124
                if timed_out
                else 126
                if exceeded
                else 125
                if (
                    descendant_pipe_leak
                    or reader_join_timed_out
                    or normal_exit_group_survivor
                    or detached_descendant_survivor
                    or stream_read_error
                    or (
                        detached_cleanup.get("supported") is True
                        and not process_containment_cleanup_complete
                    )
                )
                else proc.returncode
            ),
            "stdout": normalize_display(stdout_text, display_replacements),
            "stderr": normalize_display(stderr_text, display_replacements),
            "stdout_bytes": stdout_state["observed"],
            "stderr_bytes": stderr_state["observed"],
            "stdout_sha256": stdout_state["sha256"],
            "stderr_sha256": stderr_state["sha256"],
            "capture_limit_exceeded": exceeded,
            "timed_out": timed_out,
            "descendant_pipe_leak": descendant_pipe_leak,
            "normal_exit_group_survivor": normal_exit_group_survivor,
            "detached_descendant_survivor": detached_descendant_survivor,
            "reader_join_timed_out": reader_join_timed_out,
            "process_group_cleanup_attempted": process_group_cleanup_attempted,
            "process_group_terminated": process_group_terminated,
            "process_containment_cleanup_complete": (
                process_containment_cleanup_complete
            ),
            "process_containment": containment_scope,
            "duration_sec": round(time.time()-started, 3),
        }
    except Exception as exc:
        return {
            "cmd": display_cmd,
            "command_metadata": command_metadata,
            "returncode": 125,
            "stdout": "",
            "stderr": normalize_display(
                f"{type(exc).__name__}: {exc}",
                display_replacements,
            ),
            "normal_exit_group_survivor": False,
            "detached_descendant_survivor": False,
            "process_group_cleanup_attempted": False,
            "process_group_terminated": False,
            "process_containment_cleanup_complete": False,
            "process_containment": process_containment_scope(),
            "duration_sec": round(time.time()-started, 3),
        }


def regular_file_error(path: Path) -> str | None:
    """Return a stable diagnostic when *path* is not a regular no-follow file."""
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        return f"{type(exc).__name__} while inspecting file"
    if stat.S_ISLNK(mode):
        return "path is a symbolic link"
    if not stat.S_ISREG(mode):
        return "path is not a regular file"
    return None


def load_regular_json(path: Path, label: str) -> Mapping[str, Any]:
    # SECURITY-REVIEW: The caller-supplied plugin root is untrusted. Type-check
    # the final directory entry before opening it and never follow a symlink.
    file_error = regular_file_error(path)
    if file_error:
        raise ValueError(f"{label}: {file_error}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, Mapping):
        raise ValueError(f"{label}: top-level JSON is not an object")
    return data


def resolve_claude_executable(which_value: str) -> Path:
    """Resolve a single which result to one absolute regular target."""
    candidate = Path(which_value)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    resolved = candidate.resolve(strict=True)
    if not resolved.is_absolute():
        raise ValueError("resolved executable path is not absolute")
    file_error = regular_file_error(resolved)
    if file_error:
        raise ValueError(f"resolved executable: {file_error}")
    return resolved


def sha256_executable(path: Path) -> str:
    # SECURITY-REVIEW: Re-check the fixed resolved executable directory entry
    # before every fingerprint read; no shell or user-controlled interpolation.
    file_error = regular_file_error(path)
    if file_error:
        raise ValueError(f"executable fingerprint: {file_error}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_regular_file(path: Path, label: str) -> str:
    """Hash exact bytes only after a no-follow regular-file check."""
    # SECURITY-REVIEW: Package paths are treated as untrusted. The final entry
    # is lstat-checked and no shell or path interpolation is used.
    file_error = regular_file_error(path)
    if file_error:
        raise ValueError(f"{label}: {file_error}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fixture_artifact_path(root: Path, value: Any) -> Path:
    """Resolve one canonical fixture-relative artifact path inside evals."""
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("artifact path is not a canonical nonempty string")
    posix = PurePosixPath(value)
    if posix.is_absolute() or any(
        part in {"", ".", ".."} for part in posix.parts
    ):
        raise ValueError("artifact path is absolute, dotted, or traverses")
    return root.joinpath(
        "skills",
        "nozickian-verify",
        "evals",
        *posix.parts,
    )


def canonical_fixture_id(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 8 <= len(value) <= 128
        or FIXTURE_ID_RE.fullmatch(value) is None
    ):
        raise ValueError(
            "fixture id is not a canonical lowercase ASCII slug of length 8..128"
        )
    return value


def fixture_transcript_path(out_dir: Path, fixture_id: Any) -> Path:
    canonical = canonical_fixture_id(fixture_id)
    candidate = out_dir / f"{canonical}.json"
    if candidate.parent != out_dir:
        raise ValueError("fixture transcript path escapes output directory")
    return candidate


def _directory_open_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise OSError("platform lacks no-follow directory traversal")
    flags = os.O_RDONLY | directory | nofollow
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _open_directory_no_follow(path: Path) -> int:
    absolute = Path(os.path.abspath(path))
    flags = _directory_open_flags()
    descriptor = os.open(os.path.sep, flags)
    try:
        for component in absolute.parts[1:]:
            if component in {"", ".", ".."}:
                raise ValueError("unsafe transcript directory component")
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _directory_path_matches_fd(path: Path, descriptor: int) -> bool:
    reopened: int | None = None
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


def prepare_transcript_directory(path: Path) -> int:
    """Create/traverse the transcript directory and return its held dirfd."""
    absolute = Path(os.path.abspath(path))
    flags = _directory_open_flags()
    descriptor: int | None = os.open(os.path.sep, flags)
    try:
        for component in absolute.parts[1:]:
            if component in {"", ".", ".."}:
                raise ValueError("unsafe transcript directory component")
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                os.mkdir(component, mode=0o700, dir_fd=descriptor)
                os.fsync(descriptor)
                child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        if not _directory_path_matches_fd(absolute, descriptor):
            raise ValueError("transcript directory changed during creation")
        os.fsync(descriptor)
        result = descriptor
        descriptor = None
        return result
    finally:
        if descriptor is not None:
            os.close(descriptor)


def atomic_replace_transcript(
    path: Path,
    payload: bytes,
    *,
    directory_fd: int | None = None,
    lexical_parent: Path | None = None,
) -> None:
    """Replace one private transcript without following a final link."""
    if path.name in {"", ".", ".."}:
        raise ValueError("unsafe transcript output name")
    parent = lexical_parent if lexical_parent is not None else path.parent
    parent_fd = (
        os.dup(directory_fd)
        if directory_fd is not None
        else _open_directory_no_follow(path.parent)
    )
    temporary = f".{path.name}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor: int | None = None
    try:
        try:
            target = os.stat(
                path.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            target = None
        if target is not None and (
            not stat.S_ISREG(target.st_mode) or target.st_nlink != 1
        ):
            raise ValueError(
                "transcript output target is not a private regular file"
            )
        if not _directory_path_matches_fd(parent, parent_fd):
            raise ValueError("transcript output parent changed before write")
        descriptor = os.open(
            temporary,
            flags,
            0o600,
            dir_fd=parent_fd,
        )
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("zero-byte transcript write")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        try:
            target = os.stat(
                path.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            target = None
        if target is not None and (
            not stat.S_ISREG(target.st_mode) or target.st_nlink != 1
        ):
            raise ValueError(
                "transcript output target changed before install"
            )
        if not _directory_path_matches_fd(parent, parent_fd):
            raise ValueError("transcript output parent changed before install")
        os.replace(
            temporary,
            path.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        created = os.stat(
            path.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if not stat.S_ISREG(created.st_mode) or created.st_nlink != 1:
            raise OSError("transcript output is not a private regular file")
        os.fsync(parent_fd)
        if not _directory_path_matches_fd(parent, parent_fd):
            raise ValueError("transcript output parent changed during install")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        finally:
            os.close(parent_fd)


def _open_output_parent(path: Path) -> Tuple[int, str]:
    """Open or create an output parent without following any component link."""
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
        raise ValueError("JSON output path contains a control character")
    if path.name in {"", ".", ".."} or ".." in path.parts:
        raise ValueError("JSON output path is not canonical")
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


def prepare_json_output(path: Path) -> Tuple[int, Path]:
    """Acquire the exact optional JSON parent before live evaluation."""

    target = Path(os.path.abspath(path))
    parent_fd, target_name = _open_output_parent(target)
    try:
        if target_name != target.name:
            raise ValueError("JSON output filename changed during acquisition")
        if not _directory_path_matches_fd(target.parent, parent_fd):
            raise ValueError("JSON output parent changed during acquisition")
        try:
            target_stat = os.stat(
                target_name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            target_stat = None
        if target_stat is not None and (
            not stat.S_ISREG(target_stat.st_mode)
            or target_stat.st_nlink != 1
        ):
            raise ValueError(
                "JSON output target is not a private regular file"
            )
        result = parent_fd
        parent_fd = -1
        return result, target
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)


def atomic_replace_json_output(
    path: Path,
    text: str,
    *,
    directory_fd: int | None = None,
    lexical_parent: Path | None = None,
) -> None:
    """Install JSON without following ancestors, final links, or hardlinks."""
    target = Path(os.path.abspath(path))
    parent = (
        Path(os.path.abspath(lexical_parent))
        if lexical_parent is not None
        else target.parent
    )
    if target.parent != parent:
        raise ValueError("JSON output path changed after acquisition")
    if directory_fd is None:
        parent_fd, target_name = _open_output_parent(target)
    else:
        parent_fd = os.dup(directory_fd)
        target_name = target.name
    temporary_name = f".{target_name}.{uuid.uuid4().hex}.tmp"
    temporary_created = False
    try:
        if not _directory_path_matches_fd(parent, parent_fd):
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
        try:
            target_stat = os.stat(
                target_name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            target_stat = None
        if target_stat is not None and (
            not stat.S_ISREG(target_stat.st_mode)
            or target_stat.st_nlink != 1
        ):
            raise OSError("JSON output target is not a private regular file")
        if not _directory_path_matches_fd(parent, parent_fd):
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
            raise OSError("installed JSON output is not a private regular file")
        os.fsync(parent_fd)
        if not _directory_path_matches_fd(parent, parent_fd):
            raise ValueError("JSON output parent changed during install")
    finally:
        if temporary_created:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def emit_result(
    result: Mapping[str, Any],
    json_path: Path | None,
    display_replacements: Sequence[Tuple[str, str]],
    *,
    json_directory_fd: int | None = None,
    json_lexical_parent: Path | None = None,
) -> Tuple[Dict[str, Any], bool]:
    """Print one result and safely write its optional compatibility JSON."""
    display_result = cast(
        Dict[str, Any],
        normalize_display(result, display_replacements),
    )
    text = json.dumps(display_result, indent=2, sort_keys=True)
    if json_path is not None:
        try:
            atomic_replace_json_output(
                json_path,
                text,
                directory_fd=json_directory_fd,
                lexical_parent=json_lexical_parent,
            )
        except (OSError, RuntimeError, ValueError):
            display_result = dict(display_result)
            display_result["json_output_error"] = (
                "JSON output path is unsafe, aliased, or unavailable."
            )
            print(json.dumps(display_result, indent=2, sort_keys=True))
            return display_result, False
    print(text)
    return display_result, True


def current_package_tree(root: Path) -> Dict[str, Any]:
    """Load the current validator and invoke its single-source tree helper."""
    validator_path = (
        root / "skills/nozickian-verify/scripts/validate_package.py"
    )
    file_error = regular_file_error(validator_path)
    if file_error:
        return {
            "algorithm": None,
            "valid": False,
            "sha256": None,
            "errors": [f"validate_package.py: {file_error}"],
        }
    try:
        spec = importlib.util.spec_from_file_location(
            "ntt_validator_for_live_package_tree",
            validator_path,
        )
        if spec is None or spec.loader is None:
            raise RuntimeError("cannot load current package validator")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        previous_dont_write = sys.dont_write_bytecode
        import_stdout = io.StringIO()
        try:
            # Live validation must not mutate the package tree it measures.
            sys.dont_write_bytecode = True
            # SECURITY-REVIEW: The fixed package-local validator executes at
            # import time. Contain stdout so this CLI emits one JSON document.
            with contextlib.redirect_stdout(import_stdout):
                spec.loader.exec_module(module)
        finally:
            sys.dont_write_bytecode = previous_dont_write
        shared_tree = getattr(module, "compute_stable_release_tree", None)
        if not callable(shared_tree):
            raise AttributeError(
                "compute_stable_release_tree is not callable"
            )
        result = cast(Callable[[Path], Any], shared_tree)(root)
        if not isinstance(result, Mapping):
            raise TypeError(
                "compute_stable_release_tree did not return an object"
            )
        return dict(result)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        return {
            "algorithm": None,
            "valid": False,
            "sha256": None,
            "errors": [f"shared package-tree computation failed: {exc!r}"],
        }


def _read_release_file_no_follow(root: Path, relative: PurePosixPath) -> bytes:
    current = root
    for index, part in enumerate(relative.parts):
        current = current / part
        mode = current.lstat().st_mode
        final = index == len(relative.parts) - 1
        if stat.S_ISLNK(mode):
            raise ValueError("release inventory path contains a symbolic link")
        if final and not stat.S_ISREG(mode):
            raise ValueError("release inventory entry is not a regular file")
        if not final and not stat.S_ISDIR(mode):
            raise ValueError("release inventory ancestor is not a directory")
    return current.read_bytes()


def execution_copy_endpoint_identity(root: Path) -> Dict[str, Any]:
    """Hash no-follow endpoint metadata for a permission-hardened copy."""
    records: List[Dict[str, Any]] = []
    pending: List[Tuple[PurePosixPath, Path]] = [
        (PurePosixPath("."), root)
    ]
    try:
        while pending:
            relative, path = pending.pop()
            metadata = path.stat(follow_symlinks=False)
            mode = metadata.st_mode
            if stat.S_ISDIR(mode):
                kind = "directory"
            elif stat.S_ISREG(mode):
                kind = "regular"
            else:
                return {
                    "algorithm": "no-follow-endpoint-metadata-v1",
                    "sha256": None,
                    "entries": len(records),
                    "valid": False,
                }
            records.append(
                {
                    "path": relative.as_posix(),
                    "kind": kind,
                    "device": metadata.st_dev,
                    "inode": metadata.st_ino,
                    "mode": stat.S_IMODE(mode),
                    "nlink": metadata.st_nlink,
                    "uid": metadata.st_uid,
                    "gid": metadata.st_gid,
                    "bytes": metadata.st_size,
                    "mtime_ns": metadata.st_mtime_ns,
                    "ctime_ns": metadata.st_ctime_ns,
                }
            )
            if kind == "directory":
                with os.scandir(path) as iterator:
                    children = sorted(
                        (entry.name for entry in iterator),
                        reverse=True,
                    )
                for name in children:
                    child_relative = (
                        PurePosixPath(name)
                        if relative == PurePosixPath(".")
                        else relative / name
                    )
                    pending.append((child_relative, path / name))
    except OSError:
        return {
            "algorithm": "no-follow-endpoint-metadata-v1",
            "sha256": None,
            "entries": len(records),
            "valid": False,
        }
    records.sort(key=lambda item: item["path"])
    payload = json.dumps(
        records,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return {
        "algorithm": "no-follow-endpoint-metadata-v1",
        "sha256": f"sha256:{hashlib.sha256(payload).hexdigest()}",
        "entries": len(records),
        "valid": True,
    }


def endpoint_identity_is_valid(identity: Any) -> bool:
    return (
        type(identity) is dict
        and set(identity) == {"algorithm", "sha256", "entries", "valid"}
        and identity.get("algorithm") == "no-follow-endpoint-metadata-v1"
        and type(identity.get("sha256")) is str
        and bool(re.fullmatch(r"sha256:[0-9a-f]{64}", identity["sha256"]))
        and type(identity.get("entries")) is int
        and identity.get("entries") > 0
        and identity.get("valid") is True
    )


def materialize_execution_package_snapshot(
    root: Path,
    source_tree: Mapping[str, Any],
) -> Tuple[tempfile.TemporaryDirectory[str], Path, Dict[str, Any]]:
    """Materialize a permission-hardened, endpoint-checked execution copy."""
    if (
        source_tree.get("valid") is not True
        or not isinstance(source_tree.get("sha256"), str)
    ):
        raise ValueError("source package tree is invalid")
    manifest_path = root / "STABLE_RELEASE_MANIFEST.json"
    if regular_file_error(manifest_path) is not None:
        raise ValueError("stable release manifest is not a regular file")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    inventory = manifest.get("file_inventory") if isinstance(manifest, Mapping) else None
    if not isinstance(inventory, list) or not inventory:
        raise ValueError("stable release inventory is unavailable")
    records: List[Tuple[PurePosixPath, bytes, int]] = []
    seen = set()
    for record in inventory:
        if not isinstance(record, Mapping):
            raise ValueError("release inventory record is not an object")
        value = record.get("path")
        if not isinstance(value, str) or not value or "\\" in value:
            raise ValueError("release inventory path is not canonical")
        relative = PurePosixPath(value)
        if (
            relative.is_absolute()
            or any(part in {"", ".", ".."} for part in relative.parts)
            or relative.as_posix() != value
            or value in seen
        ):
            raise ValueError("release inventory path traverses or is duplicated")
        seen.add(value)
        payload = _read_release_file_no_follow(root, relative)
        if (
            record.get("sha256") != hashlib.sha256(payload).hexdigest()
            or type(record.get("bytes")) is not int
            or record.get("bytes") != len(payload)
        ):
            raise ValueError("release inventory bytes do not match the manifest")
        records.append(
            (relative, payload, root.joinpath(*relative.parts).lstat().st_mode)
        )
    manifest_payload = _read_release_file_no_follow(
        root,
        PurePosixPath("STABLE_RELEASE_MANIFEST.json"),
    )
    holder: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory(
        prefix="ntt_live_execution_package_"
    )
    snapshot = Path(holder.name) / "package"
    snapshot.mkdir(mode=0o700)
    try:
        for relative, payload, source_mode in records + [
            (PurePosixPath("STABLE_RELEASE_MANIFEST.json"), manifest_payload, 0o600)
        ]:
            destination = snapshot.joinpath(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(
                destination,
                flags,
                0o500 if source_mode & 0o111 else 0o400,
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
        snapshot_pre = current_package_tree(snapshot)
        if (
            snapshot_pre.get("valid") is not True
            or snapshot_pre.get("algorithm") != source_tree.get("algorithm")
            or snapshot_pre.get("sha256") != source_tree.get("sha256")
        ):
            raise ValueError("execution snapshot identity differs from source")
        for directory in sorted(
            (path for path in snapshot.rglob("*") if path.is_dir()),
            key=lambda path: len(path.parts),
            reverse=True,
        ):
            directory.chmod(0o500)
        snapshot.chmod(0o500)
        snapshot_endpoint_pre = execution_copy_endpoint_identity(snapshot)
        if not endpoint_identity_is_valid(snapshot_endpoint_pre):
            raise ValueError("execution copy endpoint identity is invalid")
    except Exception:
        holder.cleanup()
        raise
    return holder, snapshot, {
        "mode": "private-permission-hardened-endpoint-checked-release-copy",
        "source_pre": {
            "algorithm": source_tree.get("algorithm"),
            "sha256": source_tree.get("sha256"),
            "valid": source_tree.get("valid") is True,
        },
        "snapshot_pre": {
            "algorithm": snapshot_pre.get("algorithm"),
            "sha256": snapshot_pre.get("sha256"),
            "valid": snapshot_pre.get("valid") is True,
        },
        "source_post": None,
        "snapshot_post": None,
        "snapshot_endpoint_pre": snapshot_endpoint_pre,
        "snapshot_endpoint_post": None,
        "endpoint_stable": False,
        "stability_scope": "pre-post-endpoint",
        "temporal_immutability_enforced": False,
        "process_containment": process_containment_scope(),
        "stable": False,
    }


def finalize_execution_package_snapshot(
    source_root: Path,
    snapshot_root: Path,
    identity: Dict[str, Any],
) -> Dict[str, Any]:
    finalized = dict(identity)
    for field, package_root in (
        ("source_post", source_root),
        ("snapshot_post", snapshot_root),
    ):
        tree = current_package_tree(package_root)
        finalized[field] = {
            "algorithm": tree.get("algorithm"),
            "sha256": tree.get("sha256"),
            "valid": tree.get("valid") is True,
        }
    finalized["snapshot_endpoint_post"] = execution_copy_endpoint_identity(
        snapshot_root
    )
    identities = [
        finalized.get("source_pre"),
        finalized.get("source_post"),
        finalized.get("snapshot_pre"),
        finalized.get("snapshot_post"),
    ]
    finalized["endpoint_stable"] = (
        endpoint_identity_is_valid(finalized.get("snapshot_endpoint_pre"))
        and endpoint_identity_is_valid(finalized.get("snapshot_endpoint_post"))
        and finalized.get("snapshot_endpoint_pre")
        == finalized.get("snapshot_endpoint_post")
    )
    finalized["stable"] = (
        all(isinstance(item, Mapping) and item.get("valid") is True for item in identities)
        and all(item == identities[0] for item in identities[1:])
        and finalized["endpoint_stable"] is True
    )
    return finalized


def refresh_runtime_fingerprint(
    runtime_identity: Dict[str, Any],
    resolved_claude: Path,
) -> None:
    """Record the post-run executable hash and stability without its path."""
    try:
        post_hash = sha256_executable(resolved_claude)
        runtime_identity["executable_sha256_post"] = post_hash
        runtime_identity["fingerprint_stable"] = (
            post_hash == runtime_identity.get("executable_sha256_pre")
        )
    except (OSError, ValueError) as exc:
        runtime_identity["executable_sha256_post"] = None
        runtime_identity["fingerprint_stable"] = False
        runtime_identity["executable_fingerprint_error"] = (
            f"{type(exc).__name__} while re-hashing executable"
        )


_AUTHORITATIVE_STATUS_LABEL = (
    r"(?:(?:final[ \t]+)?gate[ \t]+status|final[ \t]+status)"
)
_AUTHORITATIVE_STATUS_TOKEN = (
    r"(PASS-TRACKED|PASS-SCOPED|LIMITED|FAIL|UNVERIFIED)"
)
AUTHORITATIVE_STATUS_RE = re.compile(
    r"^[ \t]*(?:#{1,6}[ \t]+|[-*][ \t]+)?"
    r"(?:"
    r"\*\*"
    + _AUTHORITATIVE_STATUS_LABEL
    + r"[ \t]*[:=\-][ \t]*"
    + _AUTHORITATIVE_STATUS_TOKEN
    + r"[.!]?\*\*"
    r"|__"
    + _AUTHORITATIVE_STATUS_LABEL
    + r"[ \t]*[:=\-][ \t]*"
    + _AUTHORITATIVE_STATUS_TOKEN
    + r"[.!]?__"
    r"|(?:"
    + _AUTHORITATIVE_STATUS_LABEL
    + r"[ \t]*[:=\-]"
    r"|\*\*"
    + _AUTHORITATIVE_STATUS_LABEL
    + r"(?:\*\*[ \t]*[:=\-]|[ \t]*[:=\-]\*\*)"
    r"|__"
    + _AUTHORITATIVE_STATUS_LABEL
    + r"(?:__[ \t]*[:=\-]|[ \t]*[:=\-]__)"
    r")[ \t]*"
    r"(?:"
    + _AUTHORITATIVE_STATUS_TOKEN
    + r"|\*\*"
    + _AUTHORITATIVE_STATUS_TOKEN
    + r"\*\*|__"
    + _AUTHORITATIVE_STATUS_TOKEN
    + r"__|`"
    + _AUTHORITATIVE_STATUS_TOKEN
    + r"`)"
    r")"
    r"[.!]?[ \t]*$",
    re.I | re.M,
)


def authoritative_statuses(text: str) -> List[str]:
    """Return explicit final/gate statuses, excluding expected-status prose."""
    return [
        next(value for value in match if value).upper()
        for match in AUTHORITATIVE_STATUS_RE.findall(text)
    ]


def dominant_status(text: str) -> str | None:
    """Return a conservative status from explicit final/gate declarations.

    A rejecting authoritative declaration cannot be laundered by a later
    expected/baseline PASS token. Distinct authoritative declarations are
    ambiguous and return ``None``; incidental status tokens are not conclusions.
    """
    found = authoritative_statuses(text)
    if not found:
        return None
    if len(set(found)) != 1:
        return None
    for status in ("FAIL", "LIMITED", "UNVERIFIED"):
        if status in found:
            return status
    if "PASS-SCOPED" in found:
        return "PASS-SCOPED"
    if "PASS-TRACKED" in found:
        return "PASS-TRACKED"
    return None


def _envelope_error_diagnostics(envelope: Mapping[str, Any]) -> List[str]:
    """Validate the exact Claude JSON error channel and reject aliases."""
    diagnostics: List[str] = []
    if "is_error" not in envelope:
        diagnostics.append("is_error is missing")
    elif type(envelope.get("is_error")) is not bool:
        diagnostics.append("is_error is not boolean")
    elif envelope.get("is_error") is True:
        diagnostics.append("is_error is true")
    for alias in (
        "isError",
        "returnCode",
        "exitCode",
        "completionStatus",
        "errorCode",
    ):
        if alias in envelope:
            diagnostics.append(f"unsupported error/status alias: {alias}")
    for field in ("success", "completed", "executed"):
        if field in envelope and envelope.get(field) is not True:
            diagnostics.append(f"{field} is not true")
    for field in (
        "failed",
        "failure",
        "timed_out",
        "timeout",
        "aborted",
        "killed",
        "terminated",
        "cancelled",
        "canceled",
        "skipped",
        "not_executed",
    ):
        if field in envelope and envelope.get(field) is not False:
            diagnostics.append(f"{field} is not false")
    for field in ("error", "errors"):
        if field not in envelope:
            continue
        value = envelope.get(field)
        if value not in (None, False, 0, "") and not (
            isinstance(value, (list, tuple, dict)) and not value
        ):
            diagnostics.append(f"{field} is nonempty")
    for field in ("exit_code", "returncode", "return_code", "error_code"):
        if field in envelope and (
            type(envelope.get(field)) is not int
            or envelope.get(field) != 0
        ):
            diagnostics.append(f"{field} is not integer zero")
    for field in ("status", "outcome"):
        if field not in envelope:
            continue
        value = envelope.get(field)
        if type(value) is not str:
            diagnostics.append(f"{field} is not a string")
            continue
        normalized = re.sub(r"[-_\s]+", "-", value.strip().lower())
        if normalized not in POSITIVE_ENVELOPE_STATUSES:
            diagnostics.append(f"{field} is not an explicit success status")
    return diagnostics


def _payload_channel_diagnostics(envelope: Mapping[str, Any]) -> List[str]:
    """Require one exact textual live-report channel with no alias conflict."""
    diagnostics: List[str] = []
    present = [field for field in ("result", "content") if field in envelope]
    if "output" in envelope:
        diagnostics.append("unsupported report payload alias: output")
    if len(present) != 1:
        diagnostics.append(
            "exactly one report payload channel is required; "
            f"observed {present!r}"
        )
        return diagnostics
    value = envelope.get(present[0])
    if type(value) is not str or not value.strip():
        diagnostics.append(
            f"{present[0]} report payload is not a nonempty string"
        )
    return diagnostics


def transcript_checks(stdout: str, artifact: str) -> Dict[str, Any]:
    envelope: Mapping[str, Any] | None = None
    envelope_error = ""
    try:
        parsed = strict_json_loads(stdout)
        if isinstance(parsed, Mapping):
            envelope = parsed
        else:
            envelope_error = f"top-level JSON is {type(parsed).__name__}, not an object"
    except (ValueError, TypeError) as exc:
        envelope_error = f"{type(exc).__name__}: {exc}"
    report_fields: List[str] = []
    report_field = None
    report = ""
    if envelope is not None:
        report_fields = [
            field for field in ("result", "content") if field in envelope
        ]
        if len(report_fields) == 1:
            candidate = envelope.get(report_fields[0])
            if type(candidate) is str and candidate.strip():
                report_field = report_fields[0]
                report = candidate
    structured_json_envelope = envelope is not None
    envelope_diagnostics = []
    payload_diagnostics: List[str] = []
    if envelope is not None:
        envelope_diagnostics = _envelope_error_diagnostics(envelope)
        payload_diagnostics = _payload_channel_diagnostics(envelope)
        envelope_diagnostics.extend(payload_diagnostics)
    envelope_is_error = bool(envelope_diagnostics)
    report_substantive = len(report.strip()) >= 80
    low = report.lower()
    status = dominant_status(report)
    declared_statuses = authoritative_statuses(report)
    status_conflict = len(set(declared_statuses)) > 1
    status_found = [tok for tok in STATUS_TOKENS if tok.lower() in low]
    required_terms = {term: (term in low) for term in REQUIRED_OUTPUT_TERMS}
    artifact_seen = Path(artifact).name.lower() in low or artifact.lower() in low
    passed = (
        structured_json_envelope
        and not envelope_is_error
        and report_field is not None
        and report_substantive
        and status in ACCEPTABLE_PASS_STATUSES
        and all(required_terms.values())
        and artifact_seen
    )
    return {
        "structured_json_envelope": structured_json_envelope,
        "envelope_is_error": envelope_is_error,
        "envelope_error_diagnostics": envelope_diagnostics,
        "envelope_error": envelope_error,
        "report_fields": report_fields,
        "report_field": report_field,
        "payload_channel_diagnostics": payload_diagnostics,
        "report_substantive": report_substantive,
        "dominant_status": status,
        "authoritative_statuses": declared_statuses,
        "authoritative_status_conflict": status_conflict,
        "status_tokens": status_found,
        "acceptable_pass_statuses": sorted(ACCEPTABLE_PASS_STATUSES),
        "required_terms": required_terms,
        "artifact_seen": artifact_seen,
        "passed": passed,
    }


def runtime_preflight_succeeded(
    commands: Sequence[Mapping[str, Any]],
    runtime_identity: Mapping[str, Any],
) -> bool:
    return (
        len(commands) >= 2
        and commands[0].get("returncode") == 0
        and commands[1].get("returncode") == 0
        and bool(
            re.fullmatch(
                r"[0-9a-f]{64}",
                str(runtime_identity.get("executable_sha256_pre") or ""),
            )
        )
        and runtime_identity.get("version_pattern_match") is True
    )


def build_fixture_prompt(plugin_name: str, fixture_id: str, artifact_path: Path) -> str:
    return (
        f"/{plugin_name}:nozickian-verify {artifact_path}\n\n"
        f"Run the Nozickian verification skill on fixture {fixture_id}. "
        "Return a concise report with: scope, method M, atomic claims, false-world sensitivity evidence, "
        "true-world adherence evidence, contradictions/residual risks, final gate status, and commands/artifacts used. "
        "Do not claim PASS-TRACKED unless the paired modal tests are evidenced."
    )


def sha256_text(value: str) -> str:
    """Hash the exact UTF-8 bytes of one canonical literal string."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Run live Claude Code evals for the Nozickian verification plugin")
    ap.add_argument("plugin_root", type=Path)
    ap.add_argument("--json", type=Path)
    ap.add_argument("--require-claude", action="store_true")
    ap.add_argument("--run-fixtures", action="store_true", help="actually invoke the slash command on fixture artifacts")
    ap.add_argument("--max-fixtures", type=int, default=3)
    ap.add_argument("--max-turns", type=int, default=20)
    ap.add_argument("--timeout-sec", type=int, default=900)
    ap.add_argument("--output-dir", type=Path, help="external directory for live runtime transcripts; default remains self_validation/live_runtime_transcripts for backwards compatibility")
    args = ap.parse_args(argv)
    root = args.plugin_root.resolve()
    out_dir = (
        Path(os.path.abspath(args.output_dir))
        if args.output_dir is not None
        else root / "self_validation/live_runtime_transcripts"
    )
    transcript_directory_fd: int | None = None
    transcript_directory_error: str | None = None
    if args.run_fixtures and args.output_dir is not None:
        try:
            # An explicit caller-controlled output directory is part of the
            # invocation boundary. Freeze it before package inspection,
            # runtime discovery, or any long-running preflight command.
            transcript_directory_fd = prepare_transcript_directory(out_dir)
        except (OSError, ValueError) as exc:
            transcript_directory_error = (
                f"{type(exc).__name__} while acquiring transcript output directory"
            )
    json_directory_fd: int | None = None
    json_target: Path | None = None
    if args.json is not None:
        try:
            # Freeze the JSON parent before package inspection, runtime
            # preflight, or any long-running fixture command.
            json_directory_fd, json_target = prepare_json_output(args.json)
        except (OSError, ValueError) as exc:
            print(
                json.dumps(
                    {
                        "json_output_error": (
                            "JSON output path is unsafe, aliased, or unavailable."
                        ),
                        "plugin_root": "<package-root>",
                        "reason": (
                            "Optional JSON output capability could not be "
                            "acquired before live evaluation."
                        ),
                        "status": "FAIL",
                        "output_capability_error": type(exc).__name__,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            if transcript_directory_fd is not None:
                os.close(transcript_directory_fd)
                transcript_directory_fd = None
            return 2

    def publish_result(
        current_result: Mapping[str, Any],
        replacements: Sequence[Tuple[str, str]],
    ) -> Tuple[Dict[str, Any], bool]:
        nonlocal json_directory_fd, transcript_directory_fd
        try:
            return emit_result(
                current_result,
                json_target,
                replacements,
                json_directory_fd=json_directory_fd,
                json_lexical_parent=(
                    json_target.parent
                    if json_target is not None
                    else None
                ),
            )
        finally:
            if json_directory_fd is not None:
                os.close(json_directory_fd)
                json_directory_fd = None
            if transcript_directory_fd is not None:
                os.close(transcript_directory_fd)
                transcript_directory_fd = None

    if transcript_directory_error is not None:
        publish_result(
            {
                "status": "FAIL",
                "reason": transcript_directory_error,
                "plugin_root": "<package-root>",
                "commands": [],
                "fixture_results": [],
                "transcript_checks": [],
            },
            (
                (str(out_dir), "<output-dir>"),
                (str(root), "<package-root>"),
            ),
        )
        return 2

    observed_at_utc = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    package_tree = current_package_tree(root)
    evals_path = root / "skills/nozickian-verify/evals/evals.json"
    fixture_spec_sha256 = None
    fixture_spec_error = None
    evals: Mapping[str, Any] = {}
    try:
        fixture_spec_sha256 = sha256_regular_file(
            evals_path,
            "evals.json",
        )
        parsed_evals = json.loads(evals_path.read_bytes())
        if not isinstance(parsed_evals, Mapping):
            raise ValueError("evals.json top-level value is not an object")
        if not isinstance(parsed_evals.get("fixtures"), list):
            raise ValueError("evals.json fixtures is not a list")
        evals = parsed_evals
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        fixture_spec_error = (
            f"{type(exc).__name__} while loading fixture specification"
        )
    run_config_error = None
    if args.max_turns <= 0:
        run_config_error = "max_turns must be a positive integer"
    elif args.max_fixtures < 0:
        run_config_error = "max_fixtures must be a nonnegative integer"
    elif args.timeout_sec <= 0:
        run_config_error = "timeout_sec must be a positive integer"
    plugin_metadata_error = None
    try:
        plugin_metadata = load_regular_json(
            root / ".claude-plugin/plugin.json",
            "plugin.json",
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        plugin_metadata = {}
        plugin_metadata_error = f"{type(exc).__name__} while loading plugin metadata"
    source_release = plugin_metadata.get("version")
    if plugin_metadata_error is None and (
        not isinstance(source_release, str) or not source_release.strip()
    ):
        plugin_metadata_error = "plugin.json version is missing or invalid"
    claude = shutil.which("claude")
    resolved_claude: Path | None = None
    executable_sha256 = None
    executable_fingerprint_error = None
    if claude:
        try:
            resolved_claude = resolve_claude_executable(claude)
            executable_sha256 = sha256_executable(resolved_claude)
        except (OSError, ValueError) as exc:
            executable_fingerprint_error = (
                f"{type(exc).__name__} while resolving or hashing executable"
            )
    replacement_list: List[Tuple[str, str]] = []
    if resolved_claude:
        replacement_list.append((str(resolved_claude), "<claude-cli>"))
    if claude:
        replacement_list.append((str(claude), "<claude-cli>"))
    replacement_list.extend(
        [
            (str(out_dir), "<output-dir>"),
            (str(root), "<package-root>"),
        ]
    )
    display_replacements = tuple(replacement_list)
    result: Dict[str, Any] = {
        "status": "UNVERIFIED_RUNTIME",
        "reason": "Claude Code CLI not found on PATH; live plugin/subagent invocation not executed.",
        "plugin_root": "<package-root>",
        "package_tree_algorithm": package_tree.get("algorithm"),
        "package_tree_sha256": (
            package_tree.get("sha256")
            if package_tree.get("valid") is True
            else None
        ),
        "package_tree_validation": {
            "valid": package_tree.get("valid") is True,
            "errors": package_tree.get("errors", []),
            "file_count": package_tree.get("file_count"),
        },
        "fixture_spec_sha256": fixture_spec_sha256,
        "fixture_spec_error": fixture_spec_error,
        "execution_package_snapshot_identity": None,
        "run_config": {
            "max_fixtures": args.max_fixtures,
            "max_turns": args.max_turns,
            "output_format": "json",
            "plugin_dir": "<package-root>",
            "print_mode": True,
            "timeout_sec": args.timeout_sec,
            "working_directory": "<package-root>",
        },
        "provenance": {
            "provenance_schema_version": PROVENANCE_SCHEMA_VERSION,
            "status": "observed-current-run",
            "source_release": source_release,
            "observed_at_utc": observed_at_utc,
            "carried_forward": False,
            "normalized_after_capture": True,
            "resolved_executable_path_recorded": False,
            "representation": "normalized-display",
            "normalized_fields": [
                "artifact",
                "cmd",
                "plugin_root",
                "prompt",
                "run_config.plugin_dir",
                "run_config.working_directory",
                "stderr",
                "stdout",
                "transcript_file",
            ],
            "raw_external_transcript_policy": RAW_EXTERNAL_TRANSCRIPT_POLICY,
        },
        "runtime_identity": {
            "authentication_status": "observed-not-cryptographically-authenticated",
            "executable_sha256": executable_sha256,
            "executable_sha256_pre": executable_sha256,
            "executable_sha256_post": None,
            "fingerprint_stable": False,
            "executable_fingerprint_error": executable_fingerprint_error,
            "resolved_executable_path_recorded": False,
            "version_output": None,
            "version_pattern": CLAUDE_VERSION_PATTERN,
            "version_pattern_match": False,
        },
        "commands": [],
        "fixture_results": [],
        "transcript_checks": [],
    }
    if plugin_metadata_error is not None:
        result["status"] = "FAIL"
        result["reason"] = (
            "Plugin metadata could not be loaded from a regular non-symlink "
            "plugin.json file."
        )
        result["plugin_metadata_error"] = plugin_metadata_error
        publish_result(result, display_replacements)
        return 2
    binding_errors = []
    if package_tree.get("valid") is not True:
        binding_errors.append("current stable package tree is invalid")
    if fixture_spec_error is not None:
        binding_errors.append(fixture_spec_error)
    if run_config_error is not None:
        binding_errors.append(run_config_error)
    if binding_errors:
        result["status"] = "FAIL"
        result["reason"] = (
            "Live-run package, fixture, or invocation binding preflight "
            "failed; no Claude subprocess was executed."
        )
        result["binding_errors"] = binding_errors
        publish_result(result, display_replacements)
        return 2
    if args.run_fixtures:
        selected_fixture_items = list(evals.get("fixtures", []))
        selected_fixture_items = selected_fixture_items[
            : max(0, args.max_fixtures)
        ]
        selected_transcript_names = {
            f"{item.get('id')}.json"
            for item in selected_fixture_items
            if isinstance(item, Mapping)
            and isinstance(item.get("id"), str)
            and FIXTURE_ID_RE.fullmatch(item.get("id")) is not None
        }
        if (
            transcript_directory_fd is not None
            and not _directory_path_matches_fd(
                out_dir,
                transcript_directory_fd,
            )
        ):
            transcript_directory_error = (
                "transcript output directory changed before runtime preflight"
            )
        if (
            transcript_directory_error is None
            and json_directory_fd is not None
            and json_target is not None
        ):
            if not _directory_path_matches_fd(
                json_target.parent,
                json_directory_fd,
            ):
                transcript_directory_error = (
                    "JSON output directory changed before runtime preflight"
                )
            else:
                same_parent = json_target.parent == out_dir
                if transcript_directory_fd is not None:
                    json_parent_stat = os.fstat(json_directory_fd)
                    transcript_parent_stat = os.fstat(
                        transcript_directory_fd
                    )
                    same_parent = (
                        json_parent_stat.st_dev,
                        json_parent_stat.st_ino,
                    ) == (
                        transcript_parent_stat.st_dev,
                        transcript_parent_stat.st_ino,
                    )
                if (
                    same_parent
                    and json_target.name in selected_transcript_names
                ):
                    transcript_directory_error = (
                        "JSON output aliases a selected fixture transcript"
                    )
        if transcript_directory_error is not None:
            result["status"] = "FAIL"
            result["reason"] = transcript_directory_error
            publish_result(result, display_replacements)
            return 2
    if not claude:
        _, published = publish_result(result, display_replacements)
        return 2 if args.require_claude or not published else 0
    if resolved_claude is None:
        result["status"] = "FAIL"
        result["reason"] = (
            "Claude Code was found on PATH, but its resolved executable was not "
            "a readable regular non-symlink file; no subprocess was executed."
        )
        publish_result(result, display_replacements)
        return 2

    execution_snapshot_holder: tempfile.TemporaryDirectory[str] | None = None
    execution_root = root
    try:
        (
            execution_snapshot_holder,
            execution_root,
            execution_package_identity,
        ) = materialize_execution_package_snapshot(root, package_tree)
        result["execution_package_snapshot_identity"] = (
            execution_package_identity
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        result["status"] = "FAIL"
        result["reason"] = (
            "Endpoint-checked live execution package copy could not be prepared; "
            "no subprocess was executed."
        )
        result["execution_package_snapshot_error"] = type(exc).__name__
        publish_result(result, display_replacements)
        return 2
    display_replacements = tuple(
        [(str(execution_root), "<package-root>"), *replacement_list]
    )

    # Basic CLI and plugin validation attempts. These are not sufficient for PASS.
    executable_argv = str(resolved_claude)
    commands = [
        run_cmd(
            [executable_argv, "--version"],
            timeout=60,
            display_replacements=display_replacements,
        )
    ]
    commands.append(
        run_cmd(
            [executable_argv, "plugin", "validate", str(execution_root)],
            timeout=300,
            display_replacements=display_replacements,
        )
    )
    version_output = str(commands[0].get("stdout") or commands[0].get("stderr") or "").strip()
    runtime_identity = result["runtime_identity"]
    runtime_identity["version_output"] = version_output
    runtime_identity["version_pattern_match"] = bool(
        re.search(CLAUDE_VERSION_PATTERN, version_output)
    )
    preflight_ok = runtime_preflight_succeeded(commands, runtime_identity)
    result.update(
        {
            "reason": "Claude Code CLI present; version and plugin validation preflight attempted. Fixture slash-command invocations not requested.",
            "commands": commands,
            "preflight": {
                "plugin_validate_returncode": commands[1].get("returncode"),
                "successful": preflight_ok,
                "version_returncode": commands[0].get("returncode"),
            },
        }
    )

    if args.run_fixtures and preflight_ok:
        if (
            transcript_directory_error is None
            and transcript_directory_fd is None
        ):
            try:
                # Preserve the historical lazy behavior for the fixed default
                # package path, but traverse it without following links and
                # retain the resulting capability through fixture execution.
                transcript_directory_fd = prepare_transcript_directory(
                    out_dir
                )
            except (OSError, ValueError) as exc:
                transcript_directory_error = (
                    f"{type(exc).__name__} while acquiring transcript output directory"
                )
    if not args.run_fixtures:
        if not preflight_ok and commands[1].get("returncode") == 0:
            result["status"] = "FAIL"
            result["reason"] = "Runtime identity/version preflight failed despite a successful plugin validation; fixture execution was not requested."
        else:
            result["status"] = "UNVERIFIED_RUNTIME"
            if not preflight_ok:
                result["reason"] = "No fixture execution was requested and plugin validation did not succeed; runtime remains unverified."
    elif not preflight_ok:
        result["status"] = "FAIL"
        result["reason"] = "Fixture execution was requested, but Claude version/plugin validation/runtime identity preflight did not succeed; fixtures were not run."
    else:
        fixture_results = []
        transcript_results = []
        fixture_binding_failure = transcript_directory_error
        plugin_name = plugin_metadata.get('name', 'nozickian-truth-tracking-agentic')
        fixture_items = (
            []
            if fixture_binding_failure is not None
            else evals.get('fixtures', [])[: max(0, args.max_fixtures)]
        )
        for item in fixture_items:
            try:
                if not isinstance(item, Mapping):
                    raise ValueError("fixture entry is not an object")
                fixture_id = canonical_fixture_id(item.get("id"))
                artifact = fixture_artifact_path(
                    execution_root,
                    item.get("artifact"),
                )
                artifact_sha256 = sha256_regular_file(
                    artifact,
                    f"fixture artifact {item.get('id', 'fixture')}",
                )
            except (OSError, ValueError) as exc:
                fixture_binding_failure = (
                    f"{type(exc).__name__} while binding fixture artifact"
                )
                break
            prompt = build_fixture_prompt(plugin_name, fixture_id, artifact)
            canonical_prompt = normalize_display(prompt, display_replacements)
            cmd = [executable_argv, "--plugin-dir", str(execution_root), "-p", "--output-format", "json", "--max-turns", str(args.max_turns), prompt]
            cmd_result = run_cmd(
                cmd,
                cwd=execution_root,
                timeout=args.timeout_sec,
                display_replacements=display_replacements,
            )
            transcript_file = fixture_transcript_path(out_dir, fixture_id)
            transcript_bytes = json.dumps(
                cmd_result,
                indent=2,
                sort_keys=True,
            ).encode("utf-8")
            try:
                atomic_replace_transcript(
                    transcript_file,
                    transcript_bytes,
                    directory_fd=transcript_directory_fd,
                    lexical_parent=out_dir,
                )
            except (OSError, ValueError) as exc:
                fixture_binding_failure = (
                    f"{type(exc).__name__} while writing fixture transcript"
                )
                break
            checks = transcript_checks(str(cmd_result.get("stdout") or ""), item["artifact"])
            fixture_results.append(
                {
                    "id": fixture_id,
                    "artifact": normalize_display(str(artifact), display_replacements),
                    "artifact_sha256": artifact_sha256,
                    "prompt": canonical_prompt,
                    "prompt_sha256": sha256_text(canonical_prompt),
                    "returncode": cmd_result["returncode"],
                    "command_capture": {
                        field: cmd_result.get(field)
                        for field in (
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
                    },
                    "transcript_file": normalize_display(str(transcript_file), display_replacements),
                    "transcript_sha256": hashlib.sha256(transcript_bytes).hexdigest(),
                    "checks": checks,
                }
            )
            transcript_results.append(checks)
        if (
            transcript_directory_fd is not None
            and not _directory_path_matches_fd(
                out_dir,
                transcript_directory_fd,
            )
        ):
            fixture_binding_failure = (
                "transcript output directory changed during fixture execution"
            )
        refresh_runtime_fingerprint(runtime_identity, resolved_claude)
        result["fixture_results"] = fixture_results
        result["transcript_checks"] = transcript_results
        all_ok = (
            fixture_binding_failure is None
            and
            bool(fixture_results)
            and all(
                fr["returncode"] == 0 and fr["checks"]["passed"]
                for fr in fixture_results
            )
            and runtime_identity.get("fingerprint_stable") is True
        )
        result["status"] = "PASS-SCOPED" if all_ok else "FAIL"
        result["reason"] = (
            fixture_binding_failure
            or "Fixture slash-command invocations executed; PASS-SCOPED means transcripts contain required verification fields, not that subagent usage was independently proven."
        )
    if runtime_identity.get("executable_sha256_post") is None:
        refresh_runtime_fingerprint(runtime_identity, resolved_claude)
    execution_package_identity = finalize_execution_package_snapshot(
        root,
        execution_root,
        execution_package_identity,
    )
    result["execution_package_snapshot_identity"] = execution_package_identity
    if (
        result.get("status") in ACCEPTABLE_PASS_STATUSES
        and execution_package_identity.get("stable") is not True
    ):
        result["status"] = "FAIL"
        result["reason"] = (
            "Live execution package snapshot or source identity changed during run."
        )
    _, published = publish_result(result, display_replacements)
    if execution_snapshot_holder is not None:
        execution_snapshot_holder.cleanup()
    if not published:
        return 2
    return 0 if result["status"] == "PASS-SCOPED" or (result["status"] == "UNVERIFIED_RUNTIME" and not args.require_claude) else 2

if __name__ == "__main__":
    raise SystemExit(main())
