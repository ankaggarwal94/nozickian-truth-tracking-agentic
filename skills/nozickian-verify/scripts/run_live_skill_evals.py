#!/usr/bin/env python3
"""Live Claude Code plugin eval harness for Nozickian verification.

This harness is intentionally evidence-producing and conservative. It can run
actual slash-command fixture invocations in non-interactive print mode when the
Claude Code CLI is installed. If the runtime cannot be exercised, it records
UNVERIFIED_RUNTIME rather than treating a version check as a pass.
"""
from __future__ import annotations
import argparse, contextlib, hashlib, importlib.util, io, json, os, re, shutil, signal, stat, subprocess, sys, tempfile, threading, time, uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Dict, List, Mapping, Sequence, Tuple, cast

STATUS_TOKENS = ("PASS-TRACKED", "PASS-SCOPED", "LIMITED", "FAIL", "UNVERIFIED")
ACCEPTABLE_PASS_STATUSES = {"PASS-TRACKED", "PASS-SCOPED"}
REJECT_STATUSES = {"LIMITED", "FAIL", "UNVERIFIED"}
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
                    "sha256": digest.hexdigest(),
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
        process_group_terminated = False
        leader_exited_at: float | None = None

        def terminate_group() -> None:
            nonlocal process_group_terminated
            process_group_terminated = True
            try:
                if os.name == "posix":
                    os.killpg(proc.pid, signal.SIGKILL)
                else:
                    proc.kill()
            except ProcessLookupError:
                pass
            except OSError:
                try:
                    proc.kill()
                except OSError:
                    pass

        while True:
            if stop.is_set():
                terminate_group()
                break
            if proc.poll() is not None:
                if not any(reader.is_alive() for reader in readers):
                    break
                if leader_exited_at is None:
                    leader_exited_at = time.monotonic()
                if time.monotonic() - leader_exited_at >= PIPE_CLOSE_GRACE_SEC:
                    descendant_pipe_leak = True
                    terminate_group()
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
        empty_sha = hashlib.sha256(b"").hexdigest()
        stdout_state = states.get("stdout", {"raw": b"", "observed": 0, "sha256": empty_sha, "exceeded": False})
        stderr_state = states.get("stderr", {"raw": b"", "observed": 0, "sha256": empty_sha, "exceeded": False})
        exceeded = bool(stdout_state["exceeded"] or stderr_state["exceeded"])
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
                if descendant_pipe_leak or reader_join_timed_out
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
            "reader_join_timed_out": reader_join_timed_out,
            "process_group_terminated": process_group_terminated,
            "duration_sec": round(time.time()-started, 3),
        }
    except OSError as exc:
        return {
            "cmd": display_cmd,
            "command_metadata": command_metadata,
            "returncode": 125,
            "stdout": "",
            "stderr": normalize_display(
                f"{type(exc).__name__}: {exc}",
                display_replacements,
            ),
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


def atomic_replace_transcript(path: Path, payload: bytes) -> None:
    """Replace one private transcript without following a final link."""
    try:
        parent_mode = path.parent.lstat().st_mode
    except OSError as exc:
        raise ValueError("transcript output parent is unavailable") from exc
    if stat.S_ISLNK(parent_mode) or not stat.S_ISDIR(parent_mode):
        raise ValueError("transcript output parent is not a real directory")
    if os.path.lexists(path):
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
        ):
            raise ValueError("transcript output target is not a private regular file")
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        created = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(created.st_mode) or created.st_nlink != 1:
            raise OSError("transcript output is not a private regular file")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


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


def materialize_execution_package_snapshot(
    root: Path,
    source_tree: Mapping[str, Any],
) -> Tuple[tempfile.TemporaryDirectory[str], Path, Dict[str, Any]]:
    """Materialize the manifest-bound package used by every live invocation."""
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
    except Exception:
        holder.cleanup()
        raise
    return holder, snapshot, {
        "mode": "private-read-only-stable-release-snapshot",
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
    identities = [
        finalized.get("source_pre"),
        finalized.get("source_post"),
        finalized.get("snapshot_pre"),
        finalized.get("snapshot_post"),
    ]
    finalized["stable"] = (
        all(isinstance(item, Mapping) and item.get("valid") is True for item in identities)
        and all(item == identities[0] for item in identities[1:])
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


def dominant_status(text: str) -> str | None:
    """Return the most authoritative final status found in a transcript.

    Prefer explicit final/gate status phrases. Fall back to status tokens only
    when no rejecting status appears. This prevents a transcript saying
    ``gate status FAIL`` from passing merely because it contains verification
    keywords or an incidental PASS token.
    """
    status_re = r"(?:final\s+)?(?:gate\s+)?status\s*[:=\-]\s*(PASS-TRACKED|PASS-SCOPED|LIMITED|FAIL|UNVERIFIED)"
    matches = re.findall(status_re, text, flags=re.I)
    if matches:
        return matches[-1].upper()
    found = [tok for tok in STATUS_TOKENS if re.search(r"\b"+re.escape(tok)+r"\b", text, flags=re.I)]
    if any(tok in found for tok in REJECT_STATUSES):
        # Rejecting statuses dominate incidental pass labels when no explicit final status exists.
        for tok in ("FAIL", "LIMITED", "UNVERIFIED"):
            if tok in found:
                return tok
    for tok in ("PASS-TRACKED", "PASS-SCOPED"):
        if tok in found:
            return tok
    return None


def transcript_checks(stdout: str, artifact: str) -> Dict[str, Any]:
    envelope: Mapping[str, Any] | None = None
    envelope_error = ""
    try:
        parsed = json.loads(stdout)
        if isinstance(parsed, Mapping):
            envelope = parsed
        else:
            envelope_error = f"top-level JSON is {type(parsed).__name__}, not an object"
    except (json.JSONDecodeError, TypeError) as exc:
        envelope_error = f"{type(exc).__name__}: {exc}"
    report_field = None
    report = ""
    if envelope is not None:
        for candidate_field in ("result", "content"):
            candidate = envelope.get(candidate_field)
            if isinstance(candidate, str) and candidate.strip():
                report_field = candidate_field
                report = candidate
                break
    structured_json_envelope = envelope is not None
    envelope_is_error = bool(envelope.get("is_error") is True) if envelope is not None else False
    report_substantive = len(report.strip()) >= 80
    low = report.lower()
    status = dominant_status(report)
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
        "envelope_error": envelope_error,
        "report_field": report_field,
        "report_substantive": report_substantive,
        "dominant_status": status,
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
    out_dir = (
        args.output_dir.resolve()
        if args.output_dir
        else root / "self_validation/live_runtime_transcripts"
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
        display_result = normalize_display(result, display_replacements)
        if args.json:
            args.json.parent.mkdir(parents=True, exist_ok=True)
            args.json.write_text(
                json.dumps(display_result, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        print(json.dumps(display_result, indent=2, sort_keys=True))
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
        display_result = normalize_display(result, display_replacements)
        if args.json:
            args.json.parent.mkdir(parents=True, exist_ok=True)
            args.json.write_text(
                json.dumps(display_result, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        print(json.dumps(display_result, indent=2, sort_keys=True))
        return 2
    if not claude:
        display_result = normalize_display(result, display_replacements)
        if args.json:
            args.json.parent.mkdir(parents=True, exist_ok=True); args.json.write_text(json.dumps(display_result, indent=2, sort_keys=True), encoding="utf-8")
        print(json.dumps(display_result, indent=2, sort_keys=True))
        return 2 if args.require_claude else 0
    if resolved_claude is None:
        result["status"] = "FAIL"
        result["reason"] = (
            "Claude Code was found on PATH, but its resolved executable was not "
            "a readable regular non-symlink file; no subprocess was executed."
        )
        display_result = normalize_display(result, display_replacements)
        if args.json:
            args.json.parent.mkdir(parents=True, exist_ok=True)
            args.json.write_text(
                json.dumps(display_result, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        print(json.dumps(display_result, indent=2, sort_keys=True))
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
            "Immutable live execution package snapshot could not be prepared; "
            "no subprocess was executed."
        )
        result["execution_package_snapshot_error"] = type(exc).__name__
        display_result = normalize_display(result, display_replacements)
        if args.json:
            args.json.parent.mkdir(parents=True, exist_ok=True)
            args.json.write_text(
                json.dumps(display_result, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        print(json.dumps(display_result, indent=2, sort_keys=True))
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
        fixture_binding_failure = None
        plugin_name = plugin_metadata.get('name', 'nozickian-truth-tracking-agentic')
        for item in evals.get('fixtures', [])[: max(0, args.max_fixtures)]:
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
            out_dir.mkdir(parents=True, exist_ok=True)
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
                atomic_replace_transcript(transcript_file, transcript_bytes)
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
                    "transcript_file": normalize_display(str(transcript_file), display_replacements),
                    "transcript_sha256": hashlib.sha256(transcript_bytes).hexdigest(),
                    "checks": checks,
                }
            )
            transcript_results.append(checks)
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
    display_result = normalize_display(result, display_replacements)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True); args.json.write_text(json.dumps(display_result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(display_result, indent=2, sort_keys=True))
    if execution_snapshot_holder is not None:
        execution_snapshot_holder.cleanup()
    return 0 if result["status"] == "PASS-SCOPED" or (result["status"] == "UNVERIFIED_RUNTIME" and not args.require_claude) else 2

if __name__ == "__main__":
    raise SystemExit(main())
