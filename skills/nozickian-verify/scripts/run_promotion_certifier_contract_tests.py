#!/usr/bin/env python3
"""End-to-end contracts for the v1.0.3 promotion certifier.

All synthetic builders live here so production certification code contains no
fixture executables, bundle builders, or test-runner entry points.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
import uuid
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

SKILL_SCRIPTS = Path("skills/nozickian-verify/scripts")
# macOS may expose the temp root through /var -> /private/var. Resolve that
# platform alias so positive controls do not themselves contain a link.
CANONICAL_TEMP_ROOT = Path(tempfile.gettempdir()).resolve()


def _output_directory_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise OSError("platform lacks no-follow output traversal")
    flags = os.O_RDONLY | nofollow | directory
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


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
        raise ValueError("JSON output path is not canonical")
    return absolute


def _open_or_create_output_parent(path: Path) -> int:
    flags = _output_directory_flags()
    descriptor = os.open(os.path.sep, flags)
    try:
        for component in path.parent.parts[1:]:
            if component in {"", ".", ".."}:
                raise ValueError("unsafe JSON output directory component")
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                os.mkdir(component, mode=0o700, dir_fd=descriptor)
                os.fsync(descriptor)
                child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _directory_path_matches_fd(path: Path, descriptor: int) -> bool:
    observed: int | None = None
    try:
        flags = _output_directory_flags()
        observed = os.open(os.path.sep, flags)
        for component in path.parts[1:]:
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
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise ValueError("JSON output target is not a private regular file")


def _acquire_json_output_capability(path: Path) -> tuple[Path, int]:
    absolute = _canonical_output_path(path)
    descriptor = _open_or_create_output_parent(absolute)
    try:
        _require_replaceable_json_target(descriptor, absolute.name)
        if not _directory_path_matches_fd(absolute.parent, descriptor):
            raise ValueError("JSON output parent identity is unstable")
        return absolute, descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _atomic_replace_json_output(
    path: Path,
    text: str,
    *,
    directory_fd: int,
) -> None:
    parent_fd = os.dup(directory_fd)
    temporary = f".{path.name}.{uuid.uuid4().hex}.tmp"
    descriptor: int | None = None
    temporary_created = False
    try:
        _require_replaceable_json_target(parent_fd, path.name)
        if not _directory_path_matches_fd(path.parent, parent_fd):
            raise ValueError("JSON output parent changed before write")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        descriptor = os.open(
            temporary,
            flags,
            0o600,
            dir_fd=parent_fd,
        )
        temporary_created = True
        payload = text.encode("utf-8")
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("zero-byte JSON output write")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        _require_replaceable_json_target(parent_fd, path.name)
        if not _directory_path_matches_fd(path.parent, parent_fd):
            raise ValueError("JSON output parent changed before install")
        os.replace(
            temporary,
            path.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        temporary_created = False
        installed = os.stat(
            path.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if not stat.S_ISREG(installed.st_mode) or installed.st_nlink != 1:
            raise OSError("installed JSON output is not private")
        os.fsync(parent_fd)
        if not _directory_path_matches_fd(path.parent, parent_fd):
            raise ValueError("JSON output parent changed during install")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_created:
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("contract dependency is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    previous_dont_write = sys.dont_write_bytecode
    import_stdout = io.StringIO()
    try:
        sys.dont_write_bytecode = True
        # SECURITY-REVIEW: Fixed package-local dependencies execute at import
        # time. Contain stdout so this contract CLI emits one JSON document.
        with contextlib.redirect_stdout(import_stdout):
            spec.loader.exec_module(module)  # type: ignore[union-attr]
    finally:
        sys.dont_write_bytecode = previous_dont_write
    return module


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def bytecode_entries(root: Path) -> set[str]:
    """Return Python bytecode/cruft paths without following directory links."""
    entries: set[str] = set()
    # SECURITY-REVIEW: The contract scans only the caller-selected package
    # tree, does not follow symlinked directories, and performs no writes.
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = [
            name
            for name in directories
            if name not in {".git"}
        ]
        current_path = Path(current)
        for name in directories:
            if name == "__pycache__":
                entries.add(
                    (current_path / name).relative_to(root).as_posix()
                )
        for name in files:
            if name.endswith((".pyc", ".pyo")):
                entries.add(
                    (current_path / name).relative_to(root).as_posix()
                )
    return entries


def refresh_structured_evidence(certifier: Any, package_root: Path) -> None:
    evidence_dir = package_root / "self_validation/evidence"
    for evidence_path in sorted(evidence_dir.glob("*.json")):
        value = json.loads(evidence_path.read_text(encoding="utf-8"))
        artifact_path = value.get("artifact_path")
        if type(artifact_path) is not str or not artifact_path:
            continue
        relative = Path(artifact_path)
        if relative.is_absolute() or ".." in relative.parts:
            continue
        target = package_root / relative
        if certifier.regular_file_error(target) is None:
            value["hash_or_version"] = (
                f"sha256:{certifier.sha256_path(target)}"
            )
            write_json(evidence_path, value)


def prepare_ephemeral_package(
    certifier: Any,
    source_root: Path,
    destination: Path,
) -> None:
    # SECURITY-REVIEW: The caller-selected source is copied only into a
    # disposable directory. Symlinks are preserved so production no-follow
    # validation sees them rather than dereferencing external targets.
    shutil.copytree(
        source_root,
        destination,
        symlinks=True,
        ignore=shutil.ignore_patterns(
            ".git",
            "__pycache__",
            "*.pyc",
            ".DS_Store",
        ),
    )
    validator = load_module(
        "ntt_validator_for_promotion_contract",
        destination / SKILL_SCRIPTS / "validate_package.py",
    )
    refresh_structured_evidence(certifier, destination)
    validator.update_manifest(destination)
    validator.write_stable_release_manifest(destination)


def write_deterministic_captures(
    certifier: Any,
    package_root: Path,
    bundle: Path,
) -> None:
    tree = certifier.package_tree_sha256(package_root)
    if tree.get("valid") is not True:
        raise RuntimeError("disposable package tree is invalid")
    tree_identity = {
        "algorithm": tree["algorithm"],
        "sha256": f"sha256:{tree['sha256']}",
    }
    commands = certifier.deterministic_suite_commands(package_root)
    for suite, rel in certifier.DETERMINISTIC_FILES.items():
        execution = certifier.run_cmd(commands[suite], cwd=package_root)
        stdout = execution.get("stdout")
        if (
            not certifier.returncode_is_integer_zero(
                execution.get("returncode")
            )
            or type(stdout) is not str
        ):
            failed: List[str] = []
            try:
                parsed_failure = json.loads(stdout or "")
                failed = [
                    str(check.get("name"))
                    for check in parsed_failure.get("checks", [])
                    if isinstance(check, Mapping)
                    and check.get("passed") is False
                ][:12]
            except (TypeError, ValueError):
                pass
            raise RuntimeError(
                f"deterministic capture failed: {suite}; failed={failed!r}"
            )
        result = json.loads(stdout)
        certifier.deterministic_semantic_projection(suite, result)
        write_json(
            bundle / rel,
            {
                "capture_schema_version": (
                    certifier.DETERMINISTIC_CAPTURE_SCHEMA
                ),
                "suite": suite,
                "argv": certifier.normalized_argv(
                    commands[suite],
                    package_root,
                ),
                "returncode": 0,
                "package_tree_identity": tree_identity,
                "stdout_sha256": (
                    "sha256:"
                    + hashlib.sha256(stdout.encode("utf-8")).hexdigest()
                ),
                "result_sha256": (
                    "sha256:"
                    + certifier.canonical_json_sha256(result)
                ),
                "result": result,
            },
        )


def write_fake_official_tools(bin_dir: Path) -> None:
    bin_dir.mkdir(parents=True, exist_ok=True)
    claude_script = (
        "#!/usr/bin/env python3\n"
        "from pathlib import Path\n"
        "import os\n"
        "import sys\n"
        "root = Path.cwd().resolve()\n"
        "args = sys.argv[1:]\n"
        "argv_ok = (len(args) == 4 and args[:2] == ['plugin', 'validate'] "
        "and Path(args[2]).resolve() == root and args[3] == '--strict')\n"
        "if not argv_ok:\n"
        "    print('Validation failed: unexpected argv', file=sys.stderr)\n"
        "    raise SystemExit(2)\n"
        "mode = os.environ.get('NTT_CONTRACT_CLAUDE_OUTPUT_MODE')\n"
        "if mode == 'early-failure-large-tail':\n"
        "    sys.stdout.write('Validation failed: synthetic early failure\\n')\n"
        "    sys.stdout.write('neutral validator progress\\n' * 2200)\n"
        "    raise SystemExit(0)\n"
        "print(f'Validating plugin manifest: {root / \".claude-plugin/plugin.json\"}')\n"
        "print()\n"
        "print('✔ Validation passed')\n"
        "if mode == 'stderr-text-failure':\n"
        "    print('Status: failed', file=sys.stderr)\n"
        "elif mode == 'stderr-json-failure':\n"
        "    print('{\"status\":\"failed\"}', file=sys.stderr)\n"
        "elif mode == 'stderr-jsonl-failure':\n"
        "    print('{\"event\":\"start\"}', file=sys.stderr)\n"
        "    print('{\"status\":\"failed\"}', file=sys.stderr)\n"
        "raise SystemExit(0)\n"
    )
    skills_ref_script = (
        "#!/usr/bin/env python3\n"
        "from pathlib import Path\n"
        "import json\n"
        "import sys\n"
        "root = Path.cwd().resolve()\n"
        "args = sys.argv[1:]\n"
        "argv_ok = (len(args) == 2 and args[0] == 'validate' and "
        "Path(args[1]).resolve() == root / 'skills/nozickian-verify')\n"
        "if not argv_ok:\n"
        "    print(json.dumps({'status': 'FAIL', 'returncode': 2}))\n"
        "    raise SystemExit(2)\n"
        "print(json.dumps({'status': 'PASS', 'returncode': 0}, sort_keys=True))\n"
        "raise SystemExit(0)\n"
    )
    for name, script in (
        ("claude", claude_script),
        ("skills-ref", skills_ref_script),
    ):
        executable = bin_dir / name
        executable.write_text(script, encoding="utf-8")
        executable.chmod(0o755)


def write_official_policies(
    certifier: Any,
    bundle: Path,
) -> None:
    for spec in certifier.PROMOTION_EVIDENCE_SPECS.values():
        if spec.get("kind") != "official-policy":
            continue
        write_json(
            bundle / spec["path"],
            {
                "policy_schema_version": certifier.OFFICIAL_POLICY_SCHEMA,
                "required_validator_id": spec["validator_id"],
            },
        )


def supported_process_containment_scope(producer: Any) -> Dict[str, Any]:
    """Obtain the same fail-closed Linux scope required in production."""
    if hasattr(producer, "prepare_process_containment"):
        state = producer.prepare_process_containment()
        scope = state.get("scope") if isinstance(state, Mapping) else None
        enabled = isinstance(state, Mapping) and state.get("enabled") is True
    else:
        scope = producer.process_containment_scope()
        enabled = True
    expected = {
        "mechanism": "linux-child-subreaper-plus-process-group",
        "cleanup_after_leader_exit": True,
        "detached_session_descendants_contained": True,
    }
    if enabled is not True or scope != expected:
        raise RuntimeError(
            "promotion contracts require supported detached-session containment"
        )
    return dict(expected)


def safe_command_capture(scope: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "returncode": 0,
        "capture_limit_exceeded": False,
        "timed_out": False,
        "descendant_pipe_leak": False,
        "reader_join_timed_out": False,
        "normal_exit_group_survivor": False,
        "detached_descendant_survivor": False,
        "process_group_cleanup_attempted": True,
        "process_group_terminated": False,
        "process_containment_cleanup_complete": True,
        "process_containment": dict(scope),
    }


def safe_raw_command(
    cmd: Sequence[str],
    scope: Mapping[str, Any],
    *,
    stdout: str = "",
    stderr: str = "",
) -> Dict[str, Any]:
    return {
        "cmd": list(cmd),
        "stdout": stdout,
        "stderr": stderr,
        **safe_command_capture(scope),
    }


def write_live_bundle(
    certifier: Any,
    package_root: Path,
    bundle: Path,
    fake_claude: Path,
) -> None:
    live = load_module(
        "ntt_live_for_promotion_contract",
        package_root / SKILL_SCRIPTS / "run_live_skill_evals.py",
    )
    plugin = json.loads(
        (package_root / ".claude-plugin/plugin.json").read_text(
            encoding="utf-8"
        )
    )
    evals_path = package_root / "skills/nozickian-verify/evals/evals.json"
    evals = json.loads(evals_path.read_text(encoding="utf-8"))
    tree = certifier.package_tree_sha256(package_root)
    containment_scope = supported_process_containment_scope(live)
    fixture_results: List[Dict[str, Any]] = []
    transcript_checks: List[Dict[str, Any]] = []
    for fixture in evals["fixtures"]:
        fixture_id = fixture["id"]
        artifact = fixture["artifact"]
        artifact_path = live.fixture_artifact_path(package_root, artifact)
        prompt = live.build_fixture_prompt(
            plugin["name"],
            fixture_id,
            artifact_path,
        )
        canonical_prompt = live.normalize_display(
            prompt,
            ((str(package_root), "<package-root>"),),
        )
        stdout = json.dumps(
            {
                "type": "result",
                "subtype": "success",
                "duration_ms": 10,
                "duration_api_ms": 8,
                "ttft_ms": 1,
                "is_error": False,
                "api_error_status": None,
                "num_turns": 1,
                "stop_reason": "end_turn",
                "total_cost_usd": 0.0,
                "usage": {"input_tokens": 1, "output_tokens": 1},
                "modelUsage": {},
                "permission_denials": [],
                "structured_output": None,
                "deferred_tool_use": None,
                "terminal_reason": "completed",
                "fast_mode_state": "off",
                "uuid": str(uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"promotion-live:{fixture_id}",
                )),
                "session_id": "promotion-live-contract-session",
                "result": (
                    f"Verification report for {Path(artifact).name}: method M "
                    "was inspected; false-world sensitivity and true-world "
                    "adherence were tested.\n"
                    "Final gate status: PASS-SCOPED."
                ),
            },
            sort_keys=True,
        )
        replay = live.transcript_checks(stdout, artifact)
        transcript_path = (
            bundle
            / "live_fixtures/transcripts"
            / f"{fixture_id}.json"
        )
        command_capture = safe_command_capture(containment_scope)
        write_json(
            transcript_path,
            {
                "cmd": [
                    "<claude-cli>",
                    "--plugin-dir",
                    "<package-root>",
                    "-p",
                    "--output-format",
                    "json",
                    "--max-turns",
                    "20",
                    canonical_prompt,
                ],
                "returncode": 0,
                "stdout": stdout,
                "stderr": "",
                **{
                    key: value
                    for key, value in command_capture.items()
                    if key != "returncode"
                },
            },
        )
        fixture_results.append(
            {
                "id": fixture_id,
                "artifact": live.normalize_display(
                    str(artifact_path),
                    ((str(package_root), "<package-root>"),),
                ),
                "artifact_sha256": certifier.sha256_path(artifact_path),
                "prompt": canonical_prompt,
                "prompt_sha256": hashlib.sha256(
                    canonical_prompt.encode("utf-8")
                ).hexdigest(),
                "returncode": 0,
                "command_capture": command_capture,
                "transcript_file": f"<output-dir>/{fixture_id}.json",
                "transcript_sha256": certifier.sha256_path(
                    transcript_path
                ),
                "checks": replay,
            }
        )
        transcript_checks.append(replay)
    executable_sha = certifier.sha256_path(fake_claude)
    live_tree_identity = {
        "algorithm": tree["algorithm"],
        "sha256": tree["sha256"],
        "valid": True,
    }
    live_endpoint_identity = live.execution_copy_endpoint_identity(
        package_root
    )
    write_json(
        bundle / "live_fixtures/live_runtime_eval_result.json",
        {
            "status": certifier.PASS_SCOPED,
            "reason": "synthetic contract origin traversed the live lane",
            "package_tree_algorithm": tree["algorithm"],
            "package_tree_sha256": tree["sha256"],
            "fixture_spec_sha256": certifier.sha256_path(evals_path),
            "execution_package_snapshot_identity": {
                "mode": "private-permission-hardened-endpoint-checked-release-copy",
                "source_pre": live_tree_identity,
                "source_post": live_tree_identity,
                "snapshot_pre": live_tree_identity,
                "snapshot_post": live_tree_identity,
                "snapshot_endpoint_pre": live_endpoint_identity,
                "snapshot_endpoint_post": live_endpoint_identity,
                "endpoint_stable": True,
                "stability_scope": "pre-post-endpoint",
                "temporal_immutability_enforced": False,
                "process_containment": containment_scope,
                "stable": True,
            },
            "run_config": {
                "max_fixtures": len(fixture_results),
                "max_turns": 20,
                "output_format": "json",
                "plugin_dir": "<package-root>",
                "print_mode": True,
                "timeout_sec": 900,
                "working_directory": "<package-root>",
            },
            "provenance": {
                "provenance_schema_version": (
                    certifier.LIVE_PROVENANCE_SCHEMA_VERSION
                ),
                "evidence_origin": "synthetic-contract",
                "status": "observed-current-run",
                "source_release": plugin["version"],
                "observed_at_utc": "2026-07-13T00:00:00Z",
                "carried_forward": False,
                "resolved_executable_path_recorded": False,
            },
            "runtime_identity": {
                "authentication_status": (
                    "observed-not-cryptographically-authenticated"
                ),
                "executable_sha256": executable_sha,
                "executable_sha256_pre": executable_sha,
                "executable_sha256_post": executable_sha,
                "fingerprint_stable": True,
                "executable_fingerprint_error": None,
                "resolved_executable_path_recorded": False,
                "version_output": "2.1.205 (Claude Code)",
                "version_pattern_match": True,
            },
            "commands": [
                {
                    "cmd": ["<claude-cli>", "--version"],
                    **safe_command_capture(containment_scope),
                },
                {
                    "cmd": [
                        "<claude-cli>",
                        "plugin",
                        "validate",
                        "<package-root>",
                    ],
                    **safe_command_capture(containment_scope),
                },
            ],
            "preflight": {
                "successful": True,
                "version_returncode": 0,
                "plugin_validate_returncode": 0,
            },
            "fixture_results": fixture_results,
            "transcript_checks": transcript_checks,
        },
    )


def synthetic_method() -> Dict[str, Any]:
    return {
        "producer": "Ephemeral aggregate contract fixture producer.",
        "checker": "Production strict gate and promotion certifier.",
        "artifacts": ["formal certificate", "typed evidence"],
        "environment": ["disposable local filesystem", "Python 3"],
        "tools": ["fixed argv subprocesses", "SHA-256"],
        "evidence_process": "Each claim and modal test binds exact bytes.",
        "graders_or_tests": ["ntt_gate.py", "aggregate contract"],
        "trace_or_logs": ["typed formal transcript companion"],
    }


def write_strict_gate_evidence(
    gate: Any,
    evidence_root: Path,
    *,
    claim: Mapping[str, Any],
    records_dir: str,
    observations_dir: str,
    modal_cases: Sequence[Tuple[str, Dict[str, Any], str]],
    certificate_assurance: Mapping[str, Any],
) -> Tuple[List[str], str, str]:
    """Write proposition- and modal-bound evidence for one synthetic claim."""
    claim_id = str(claim.get("id") or "")
    claim_text = str(claim.get("text") or "")
    claim_digest = gate._proposition_sha256(  # pylint: disable=protected-access
        claim_text
    )
    if type(claim_digest) is not str:
        raise RuntimeError("synthetic claim proposition could not be hashed")
    prefixed_claim_digest = f"sha256:{claim_digest}"
    claim_contract_digest = gate._claim_contract_sha256(  # pylint: disable=protected-access
        claim,
        certificate_assurance,
    )
    if type(claim_contract_digest) is not str:
        raise RuntimeError("synthetic claim contract could not be hashed")
    prefixed_contract_digest = f"sha256:{claim_contract_digest}"

    claim_refs: List[str] = []
    for name in ("claim-a", "claim-b"):
        artifact_rel = f"{observations_dir}/{name}.txt"
        artifact = evidence_root / artifact_rel
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(
            f"Independent synthetic claim evidence {name} for {claim_id}.\n",
            encoding="utf-8",
        )
        record_rel = f"{records_dir}/{name}.json"
        write_json(
            evidence_root / record_rel,
            {
                "evidence_schema_version": gate.EVIDENCE_SCHEMA_VERSION,
                "claim_id": claim_id,
                "claim_proposition_sha256": prefixed_claim_digest,
                "claim_contract_schema_version": (
                    gate.CLAIM_CONTRACT_SCHEMA_VERSION
                ),
                "claim_contract_sha256": prefixed_contract_digest,
                "artifact_path": artifact_rel,
                "command_or_source": "fixed aggregate contract producer",
                "observed_result": (
                    f"Claim evidence {name} independently supported {claim_id}."
                ),
                "support_summary": (
                    "This record binds exact synthetic claim bytes and the "
                    "canonical claim proposition."
                ),
                "timestamp_utc": "2026-07-13T00:00:00Z",
                "hash_or_version": f"sha256:{gate.sha256_path(artifact)}",
            },
        )
        claim_refs.append(record_rel)

    ledger_rel = f"{observations_dir}/modal-observation-ledger.json"
    observations: Dict[str, Dict[str, Any]] = {}
    modal_wrappers: List[Tuple[str, Dict[str, Any]]] = []
    for name, test, observed_result in modal_cases:
        test_id = str(test["id"])
        test_kind = str(test["kind"])
        record_rel = f"{records_dir}/{name}.json"
        test["evidence_refs"] = [record_rel]
        modal_digest = gate._modal_case_sha256(  # pylint: disable=protected-access
            test,
            claim_text,
            test_kind,
            observed_result,
            claim_contract_sha256=prefixed_contract_digest,
        )
        if type(modal_digest) is not str:
            raise RuntimeError("synthetic modal case could not be hashed")
        prefixed_modal_digest = f"sha256:{modal_digest}"
        observation_id = f"OBS-{claim_id}-{test_id}"
        observations[observation_id] = {
            "claim_id": claim_id,
            "test_id": test_id,
            "kind": test_kind,
            "claim_proposition_sha256": prefixed_claim_digest,
            "claim_contract_sha256": prefixed_contract_digest,
            "modal_case_sha256": prefixed_modal_digest,
            "result": test["result"],
            "outcome": test["outcome"],
            "observed_result": observed_result,
        }
        modal_wrappers.append(
            (
                record_rel,
                {
                    "evidence_schema_version": gate.EVIDENCE_SCHEMA_VERSION,
                    "claim_id": claim_id,
                    "claim_proposition_sha256": prefixed_claim_digest,
                    "claim_contract_schema_version": (
                        gate.CLAIM_CONTRACT_SCHEMA_VERSION
                    ),
                    "claim_contract_sha256": prefixed_contract_digest,
                    "test_id": test_id,
                    "modal_case_sha256": prefixed_modal_digest,
                    "observation_id": observation_id,
                    "artifact_path": ledger_rel,
                    "command_or_source": "fixed aggregate contract producer",
                    "observed_result": observed_result,
                    "support_summary": (
                        "This record binds the exact synthetic modal case to "
                        "a dedicated observation."
                    ),
                    "timestamp_utc": "2026-07-13T00:00:00Z",
                },
            )
        )

    ledger = evidence_root / ledger_rel
    write_json(
        ledger,
        {
            "observation_schema_version": gate.OBSERVATION_SCHEMA_VERSION,
            "observations": observations,
        },
    )
    ledger_digest = f"sha256:{gate.sha256_path(ledger)}"
    for record_rel, wrapper in modal_wrappers:
        wrapper["hash_or_version"] = ledger_digest
        write_json(evidence_root / record_rel, wrapper)
    return claim_refs, prefixed_claim_digest, prefixed_contract_digest


def write_formal_bundle(
    certifier: Any,
    package_root: Path,
    bundle: Path,
    fake_claude: Path,
    gate: Any,
) -> Path:
    formal = load_module(
        "ntt_formal_for_promotion_contract",
        package_root
        / SKILL_SCRIPTS
        / "run_formal_artifact_verification.py",
    )
    result_dir = bundle / "formal_artifacts/artifact-001"
    result_dir.mkdir(parents=True, exist_ok=True)
    target = bundle / "formal_artifacts/synthetic-target.md"
    target.write_text(
        "Synthetic contract target with a stable independently hashed claim.\n",
        encoding="utf-8",
    )
    out = formal.output_paths(target, result_dir)
    out["target_snapshot"].write_bytes(target.read_bytes())
    source_pre = formal.file_snapshot_identity(target)
    snapshot_pre = formal.file_snapshot_identity(out["target_snapshot"])
    method = synthetic_method()

    claim_text = "Every synthetic formal lane is independently checked."
    claim_identity = {
        "id": "C-SYNTHETIC",
        "text": claim_text,
        "scope": (
            "Only the disposable synthetic formal bundle generated by this "
            "contract test."
        ),
        "importance": "critical",
        "artifact_location": "synthetic-target.md",
        "method_m": method,
    }
    false_tests = [
        {
            "id": "FW-A",
            "kind": "false_world",
            "target_claim": "C-SYNTHETIC",
            "perturbation": "Replace one artifact with stale bytes.",
            "expected_behavior": "The strict gate rejects stale bytes.",
            "observed_behavior": "The gate rejected the false claim.",
            "outcome": "rejected_false_claim",
            "result": "pass",
            "world_contract": {
                "schema_version": gate.WORLD_CONTRACT_SCHEMA_VERSION,
                "semantic_equivalence_class": "formal.stale-artifact",
                "operator": "replace",
                "target": "artifact.digest",
                "precondition": "The artifact matches its recorded digest.",
                "state_delta": "The artifact contains stale bytes.",
                "oracle": "The strict gate recomputes and compares the digest.",
                "expected_outcome": "rejected_false_claim",
            },
        },
        {
            "id": "FW-B",
            "kind": "false_world",
            "target_claim": "C-SYNTHETIC",
            "perturbation": "Swap one typed companion role.",
            "expected_behavior": "The strict gate rejects the swap.",
            "observed_behavior": "The gate blocked the false claim.",
            "outcome": "blocked",
            "result": "pass",
            "world_contract": {
                "schema_version": gate.WORLD_CONTRACT_SCHEMA_VERSION,
                "semantic_equivalence_class": "formal.swap-companion-role",
                "operator": "mutate",
                "target": "artifact.identity",
                "precondition": "Every companion occupies its declared role.",
                "state_delta": "Two companion roles are exchanged.",
                "oracle": "The strict gate checks typed role bindings.",
                "expected_outcome": "blocked",
            },
        },
    ]
    true_tests = [{
        "id": "TW-A",
        "kind": "true_world",
        "target_claim": "C-SYNTHETIC",
        "variant": "Retain equivalent bytes.",
        "expected_behavior": "The gate retains the true claim.",
        "observed_behavior": "The gate retained the true claim.",
        "outcome": "retained_true_claim",
        "result": "pass",
        "world_contract": {
            "schema_version": gate.WORLD_CONTRACT_SCHEMA_VERSION,
            "semantic_equivalence_class": "formal.retain-equivalent-bytes",
            "operator": "preserve",
            "target": "artifact.digest",
            "precondition": "The recorded artifact is true under method M.",
            "state_delta": "Only a semantically equivalent representation remains.",
            "oracle": "The strict gate confirms the same bound evidence.",
            "expected_outcome": "retained_true_claim",
        },
    }]
    claim_identity.update({
        "truth_status": "executed_confirmed",
        "evidence_refs": [
            "evidence/claim-a.json",
            "evidence/claim-b.json",
        ],
        "false_world_tests": false_tests,
        "true_world_tests": true_tests,
        "unresolved_contradictions": [],
        "residual_risks": [],
    })
    false_tests[0]["evidence_refs"] = ["evidence/fw-a.json"]
    false_tests[1]["evidence_refs"] = ["evidence/fw-b.json"]
    true_tests[0]["evidence_refs"] = ["evidence/tw-a.json"]
    assurance_certificate = {
        "schema_version": "2.0",
        "method_manifest": method,
        "scope_limitations": [],
        "claims": [claim_identity],
    }
    certificate_assurance = gate._certificate_assurance_payload(  # pylint: disable=protected-access
        assurance_certificate,
        gate._resolve_downstream_policy("generic"),  # pylint: disable=protected-access
    )
    (
        claim_refs,
        proposition_digest,
        claim_contract_digest,
    ) = write_strict_gate_evidence(
        gate,
        result_dir,
        claim=claim_identity,
        records_dir="evidence",
        observations_dir="observations",
        certificate_assurance=certificate_assurance,
        modal_cases=[
            (
                "fw-a",
                false_tests[0],
                "The strict gate observed and rejected stale artifact bytes.",
            ),
            (
                "fw-b",
                false_tests[1],
                "The strict gate observed and blocked the companion role swap.",
            ),
            (
                "tw-a",
                true_tests[0],
                "The strict gate observed and retained the equivalent bytes.",
            ),
        ],
    )
    certificate = {
        "schema_version": "2.0",
        "method_manifest": method,
        "scope_limitations": [],
        "claims": [
            {
                **claim_identity,
                "proposition_sha256": proposition_digest,
                "claim_contract_schema_version": (
                    gate.CLAIM_CONTRACT_SCHEMA_VERSION
                ),
                "claim_contract_sha256": claim_contract_digest,
                "truth_status": "executed_confirmed",
                "evidence_refs": claim_refs,
                "false_world_tests": false_tests,
                "true_world_tests": true_tests,
                "unresolved_contradictions": [],
            }
        ],
    }
    write_json(out["certificate"], certificate)
    gate_result = gate.evaluate_certificate(
        certificate,
        evidence_root=result_dir,
        strict_evidence=True,
    )
    if gate_result.get("status") != certifier.PASS_TRACKED:
        raise RuntimeError("synthetic formal gate did not pass")
    out["gate"].write_text(
        gate.to_markdown(gate_result, out["certificate"]),
        encoding="utf-8",
    )
    out["report"].write_text(
        "# Synthetic formal report\n\nAll modeled lanes passed.\n",
        encoding="utf-8",
    )
    out["ledger"].write_text(
        (
            "Substitution used: none\n"
            "Machine gate run: runner-managed\n"
            f"Main coordinator: {formal.FORMAL_COORDINATOR}\n"
            + "\n".join(certifier.REQUIRED_NATIVE_AGENTS)
            + "\n"
        ),
        encoding="utf-8",
    )
    out["prompt"].write_text(
        formal.build_formal_prompt(
            package_root,
            out["target_snapshot"],
            out,
            result_dir,
        ),
        encoding="utf-8",
    )
    transcript_lines: List[Dict[str, Any]] = []
    for agent in certifier.REQUIRED_NATIVE_AGENTS:
        tool_id = f"toolu-{agent}"
        transcript_lines.extend(
            [
                {
                    "type": "assistant",
                    "message": {
                        "content": [{
                            "id": tool_id,
                            "type": "tool_use",
                            "name": "Agent",
                            "input": {
                                "subagent_type": agent,
                                "description": f"Run {agent}",
                            },
                        }]
                    },
                },
                {
                    "type": "user",
                    "message": {
                        "content": [{
                            "type": "tool_result",
                            "tool_use_id": tool_id,
                            "status": "success",
                            "is_error": False,
                            "content": f"{agent} completed with findings.",
                        }]
                    },
                },
            ]
        )
    out["transcript"].write_text(
        "\n".join(json.dumps(item) for item in [
            *transcript_lines,
            {
                "type": "result",
                "subtype": "success",
                "duration_ms": 10,
                "duration_api_ms": 8,
                "ttft_ms": 1,
                "is_error": False,
                "api_error_status": None,
                "num_turns": len(transcript_lines) // 2 + 1,
                "stop_reason": "end_turn",
                "total_cost_usd": 0.0,
                "usage": {"input_tokens": 1, "output_tokens": 1},
                "modelUsage": {},
                "permission_denials": [],
                "structured_output": None,
                "deferred_tool_use": None,
                "terminal_reason": "completed",
                "fast_mode_state": "off",
                "uuid": "00000000-0000-4000-8000-000000000003",
                "session_id": "promotion-formal-contract-session",
                "result": (
                    "Formal coordinator completed after all native lanes."
                ),
            },
        ]) + "\n",
        encoding="utf-8",
    )
    trace_auth = formal.authenticate_trace(out["transcript"])
    formal_tree_identity = {
        "algorithm": certifier.package_tree_sha256(package_root)["algorithm"],
        "sha256": (
            "sha256:" + certifier.package_tree_sha256(package_root)["sha256"]
        ),
        "valid": True,
    }
    executable_file_identity = formal.file_snapshot_identity(fake_claude)
    formal_endpoint_identity = formal.execution_copy_endpoint_identity(
        package_root
    )
    containment_scope = supported_process_containment_scope(formal)
    prechecks = [
        safe_raw_command(
            [
                sys.executable,
                str(package_root / SKILL_SCRIPTS / "validate_package.py"),
                str(package_root),
            ],
            containment_scope,
        ),
        safe_raw_command(
            [
                sys.executable,
                str(package_root / SKILL_SCRIPTS / "run_regression_evals.py"),
                str(package_root),
            ],
            containment_scope,
        ),
        safe_raw_command(
            [
                sys.executable,
                str(package_root / SKILL_SCRIPTS / "ntt_gate.py"),
                str(package_root / "self_validation/self_certificate.json"),
                "--evidence-root",
                str(package_root),
                "--strict-evidence",
                "--downstream-policy",
                "package-self",
            ],
            containment_scope,
        ),
        safe_raw_command(
            [
                str(fake_claude.resolve()),
                "plugin",
                "validate",
                str(package_root),
                "--strict",
            ],
            containment_scope,
        ),
    ]
    commands = [
        safe_raw_command(
            [str(fake_claude.resolve()), "--version"],
            containment_scope,
            stdout="2.1.205 (Claude Code)\n",
        ),
        safe_raw_command(
            [
                str(fake_claude.resolve()),
                "--plugin-dir",
                str(package_root),
                "--agent",
                formal.FORMAL_COORDINATOR,
                "-p",
                "--output-format",
                "stream-json",
                "--include-hook-events",
                "--max-turns",
                "20",
                out["prompt"].read_text(encoding="utf-8"),
            ],
            containment_scope,
            stdout=out["transcript"].read_text(encoding="utf-8"),
        ),
        safe_raw_command(
            [
                sys.executable,
                str(package_root / SKILL_SCRIPTS / "ntt_gate.py"),
                str(out["certificate"]),
                "--evidence-root",
                str(result_dir),
                "--strict-evidence",
                "--markdown",
                str(out["gate"]),
            ],
            containment_scope,
        ),
    ]
    output_checks = formal.check_required_outputs(out, include_gate=True)
    if not output_checks or not all(
        check.get("passed") is True for check in output_checks
    ):
        raise RuntimeError("synthetic formal output checks did not pass")
    result = {
        "run_id": "synthetic-aggregate-run-001",
        "status": certifier.PASS_SCOPED,
        "reason": (
            "synthetic origin is endpoint-checked with supported process "
            "containment, but temporal immutability is not enforced"
        ),
        "package_tree_identity": formal_tree_identity,
        "execution_package_snapshot_identity": {
            "mode": "private-permission-hardened-endpoint-checked-release-copy",
            "source_pre": formal_tree_identity,
            "source_post": formal_tree_identity,
            "snapshot_pre": formal_tree_identity,
            "snapshot_post": formal_tree_identity,
            "snapshot_endpoint_pre": formal_endpoint_identity,
            "snapshot_endpoint_post": formal_endpoint_identity,
            "endpoint_stable": True,
            "stability_scope": "pre-post-endpoint",
            "temporal_immutability_enforced": False,
            "process_containment": containment_scope,
            "stable": True,
        },
        "runtime_identity": {
            "resolved_executable_path": str(fake_claude.resolve()),
            "version_output": "2.1.205 (Claude Code)",
            "version_pattern": formal.CLAUDE_VERSION_PATTERN,
            "version_pattern_match": True,
            "executable_sha256_pre": certifier.sha256_path(fake_claude),
            "executable_sha256_post": certifier.sha256_path(fake_claude),
            "executable_identity_pre": executable_file_identity,
            "executable_identity_post": executable_file_identity,
            "fingerprint_stable": True,
            "error": None,
        },
        "commands": commands,
        "prechecks": prechecks,
        "precheck_summary": {
            "total": len(prechecks),
            "passed": len(prechecks),
            "failed": 0,
            "failed_commands": [],
        },
        "output_checks": output_checks,
        "gate_status": certifier.PASS_TRACKED,
        "trace_authentication": trace_auth,
        "_execution_root": str(package_root),
    }
    canonical = formal.build_formal_result_v2(
        result,
        root=package_root,
        target=target,
        output_dir=result_dir,
        out=out,
        source_pre_identity=source_pre,
        source_post_identity=formal.file_snapshot_identity(target),
        snapshot_pre_identity=snapshot_pre,
        snapshot_post_identity=formal.file_snapshot_identity(
            out["target_snapshot"]
        ),
        evidence_root=result_dir,
        evidence_origin="synthetic-contract",
    )
    write_json(out["formal_result"], canonical)
    return out["formal_result"]


def write_passing_promotion_claim(
    certifier: Any,
    gate: Any,
    bundle: Path,
    claim_id: str,
    slug: str,
    *,
    certificate_assurance: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Write one independently gate-passable promotion claim and evidence."""
    method = synthetic_method()
    claim_text = f"Independent promotion claim {claim_id} is tracked."
    claim_identity = {
        "id": claim_id,
        "text": claim_text,
        "scope": (
            f"Only the disposable synthetic promotion fixture {slug} and "
            "its explicitly bound evidence."
        ),
        "importance": "critical",
        "artifact_location": f"promotion_claims/{slug}",
        "method_m": method,
    }
    false_tests = [
        {
            "id": f"FW-{slug.upper()}-A",
            "kind": "false_world",
            "target_claim": claim_id,
            "perturbation": "Replace the first observation with stale bytes.",
            "expected_behavior": "The strict gate rejects the stale claim.",
            "observed_behavior": "The strict gate rejected the stale claim.",
            "outcome": "rejected_false_claim",
            "result": "pass",
            "world_contract": {
                "schema_version": gate.WORLD_CONTRACT_SCHEMA_VERSION,
                "semantic_equivalence_class": f"{slug}.stale-observation",
                "operator": "replace",
                "target": "evidence_wrapper.artifact_digest",
                "precondition": "The observation matches its recorded digest.",
                "state_delta": "The observation is replaced by stale bytes.",
                "oracle": "The strict gate recomputes the evidence digest.",
                "expected_outcome": "rejected_false_claim",
            },
        },
        {
            "id": f"FW-{slug.upper()}-B",
            "kind": "false_world",
            "target_claim": claim_id,
            "perturbation": "Remove the independent source binding.",
            "expected_behavior": "The strict gate blocks the claim.",
            "observed_behavior": "The strict gate blocked the claim.",
            "outcome": "blocked",
            "result": "pass",
            "world_contract": {
                "schema_version": gate.WORLD_CONTRACT_SCHEMA_VERSION,
                "semantic_equivalence_class": f"{slug}.remove-source-binding",
                "operator": "remove",
                "target": "certificate.evidence_refs",
                "precondition": "The claim has an independent source binding.",
                "state_delta": "The independent source binding is absent.",
                "oracle": "The strict gate requires bound structured evidence.",
                "expected_outcome": "blocked",
            },
        },
    ]
    true_tests = [{
        "id": f"TW-{slug.upper()}-A",
        "kind": "true_world",
        "target_claim": claim_id,
        "variant": "Retain equivalent independently bound bytes.",
        "expected_behavior": "The strict gate retains the true claim.",
        "observed_behavior": "The strict gate retained the true claim.",
        "outcome": "retained_true_claim",
        "result": "pass",
        "world_contract": {
            "schema_version": gate.WORLD_CONTRACT_SCHEMA_VERSION,
            "semantic_equivalence_class": f"{slug}.retain-equivalent-bytes",
            "operator": "preserve",
            "target": "evidence_wrapper.artifact_digest",
            "precondition": "The evidence supports the true claim.",
            "state_delta": "Equivalent independently bound bytes are retained.",
            "oracle": "The strict gate confirms the same evidence contract.",
            "expected_outcome": "retained_true_claim",
        },
    }]
    records_dir = f"promotion_claims/{slug}/records"
    claim_identity.update({
        "truth_status": "executed_confirmed",
        "evidence_refs": [
            f"{records_dir}/claim-a.json",
            f"{records_dir}/claim-b.json",
        ],
        "false_world_tests": false_tests,
        "true_world_tests": true_tests,
        "unresolved_contradictions": [],
        "residual_risks": [],
    })
    false_tests[0]["evidence_refs"] = [f"{records_dir}/false-a.json"]
    false_tests[1]["evidence_refs"] = [f"{records_dir}/false-b.json"]
    true_tests[0]["evidence_refs"] = [f"{records_dir}/true-a.json"]
    if certificate_assurance is None:
        return claim_identity
    (
        claim_refs,
        proposition_digest,
        claim_contract_digest,
    ) = write_strict_gate_evidence(
        gate,
        bundle,
        claim=claim_identity,
        records_dir=records_dir,
        observations_dir=f"promotion_claims/{slug}/observations",
        certificate_assurance=certificate_assurance,
        modal_cases=[
            (
                "false-a",
                false_tests[0],
                "The strict gate observed and rejected the stale claim.",
            ),
            (
                "false-b",
                false_tests[1],
                "The strict gate observed and blocked the unbound claim.",
            ),
            (
                "true-a",
                true_tests[0],
                "The strict gate observed and retained the true claim.",
            ),
        ],
    )
    return {
        **claim_identity,
        "proposition_sha256": proposition_digest,
        "claim_contract_schema_version": (
            gate.CLAIM_CONTRACT_SCHEMA_VERSION
        ),
        "claim_contract_sha256": claim_contract_digest,
        "truth_status": "executed_confirmed",
        "evidence_refs": claim_refs,
        "false_world_tests": false_tests,
        "true_world_tests": true_tests,
        "unresolved_contradictions": [],
        "residual_risks": [],
    }


def write_promotion_certificate(
    certifier: Any,
    gate: Any,
    package_root: Path,
    bundle: Path,
    formal_result: Path,
) -> None:
    plugin = json.loads(
        (package_root / ".claude-plugin/plugin.json").read_text(
            encoding="utf-8"
        )
    )
    tree = certifier.package_tree_sha256(package_root)
    dependencies = certifier.required_promotion_dependencies(False)
    role_paths = {
        role: (
            certifier.relpath(bundle, formal_result)
            if role == "formal.result"
            else spec["path"]
        )
        for role, spec in certifier.PROMOTION_EVIDENCE_SPECS.items()
    }
    nodes = {
        role: {
            "path": path,
            "sha256": (
                f"sha256:{certifier.sha256_path(bundle / path)}"
            ),
            "depends_on": dependencies[role],
        }
        for role, path in role_paths.items()
    }
    certificate = {
            "promotion_schema_version": "2.0",
            "origin": "synthetic-contract",
            "upgrade_from_status": certifier.PASS_SCOPED,
            "requested_status": certifier.PASS_TRACKED,
            "package_version": plugin["version"],
            "package_tree_sha256": f"sha256:{tree['sha256']}",
            "method_m_upgrade": {},
            "live_result_bindings": {},
            "evidence": {
                "schema_version": certifier.PROMOTION_EVIDENCE_SCHEMA,
                "nodes": nodes,
            },
            "claims": [
                write_passing_promotion_claim(
                    certifier,
                    gate,
                    bundle,
                    "C-UPSTREAM",
                    "upstream",
                )
            ],
            "derived_or_downstream_claims": [],
            "downstream_review": {
                "performed": True,
                "claims_identified": [],
                "none_identified_reason": (
                    "The synthetic baseline contains no downstream claim."
                ),
            },
        }
    certificate_assurance = gate._certificate_assurance_payload(  # pylint: disable=protected-access
        certificate,
        gate._resolve_downstream_policy("promotion-v2"),  # pylint: disable=protected-access
    )
    certificate["claims"] = [
        write_passing_promotion_claim(
            certifier,
            gate,
            bundle,
            "C-UPSTREAM",
            "upstream",
            certificate_assurance=certificate_assurance,
        )
    ]
    method_m, method_error = certifier.expected_promotion_method_m(
        package_root,
        bundle,
        certificate,
    )
    if method_error is not None or not isinstance(method_m, dict):
        raise RuntimeError(
            f"synthetic promotion method M could not be bound: {method_error}"
        )
    certificate["method_m_upgrade"] = method_m
    certificate["live_result_bindings"] = method_m["live"]
    write_json(bundle / "promotion_certificate.json", certificate)


def refresh_node_hash(
    certifier: Any,
    package_root: Path,
    bundle: Path,
    certificate: Dict[str, Any],
    role: str,
) -> None:
    node = certificate["evidence"]["nodes"][role]
    node["sha256"] = (
        f"sha256:{certifier.sha256_path(bundle / node['path'])}"
    )
    method_m, method_error = certifier.expected_promotion_method_m(
        package_root,
        bundle,
        certificate,
    )
    # Coherent positive mutations rebind method M. Deliberately malformed
    # lane mutations retain their prior binding so the production certifier
    # can reject both the malformed lane and the now-stale method commitment.
    if method_error is None and isinstance(method_m, dict):
        certificate["method_m_upgrade"] = method_m
        certificate["live_result_bindings"] = method_m["live"]


def certifier_cli(
    package_root: Path,
    bundle: Path,
    *,
    allow_official_scope_exclusion: bool = False,
    env: Optional[Mapping[str, str]] = None,
    json_path: Optional[Path] = None,
) -> tuple[int, Dict[str, Any], Dict[str, Any]]:
    production_script = (
        package_root
        / SKILL_SCRIPTS
        / "certify_pass_tracked_upgrade.py"
    )
    command = [
        sys.executable,
        str(production_script),
        str(package_root),
        str(bundle),
    ]
    if allow_official_scope_exclusion:
        command.append("--allow-official-validator-scope-exclusion")
    if json_path is not None:
        command.extend(["--json", str(json_path)])
    # SECURITY-REVIEW: This invokes the copied production certifier through a
    # fixed argv list with shell parsing disabled. Bundle data never enters argv.
    completed = subprocess.run(
        command,
        cwd=package_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=1800,
        check=False,
        env=dict(env) if env is not None else None,
    )
    try:
        result = json.loads(completed.stdout)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("production certifier CLI did not return JSON") from exc
    if not isinstance(result, dict):
        raise RuntimeError("production certifier CLI JSON is not an object")
    completed_args = (
        list(completed.args)
        if isinstance(completed.args, (list, tuple))
        else []
    )
    invocation = {
        "argv": completed_args,
        "returncode": completed.returncode,
        "stdout_sha256": (
            "sha256:"
            + hashlib.sha256(completed.stdout.encode("utf-8")).hexdigest()
        ),
        "stderr_sha256": (
            "sha256:"
            + hashlib.sha256(completed.stderr.encode("utf-8")).hexdigest()
        ),
        "production_script": (
            len(completed_args) >= 2
            and Path(completed_args[1]).resolve()
            == production_script.resolve()
        ),
        "parsed_result_object": True,
    }
    invocation["verified"] = (
        invocation["production_script"] is True
        and invocation["parsed_result_object"] is True
        and completed_args == command
        and type(completed.returncode) is int
    )
    return completed.returncode, result, invocation


EXPECTED_DETERMINISTIC_SUITES = (
    "package_validation",
    "gate_result",
    "regression",
    "gate_contract",
    "formal_contract",
)
EXPECTED_OFFICIAL_VALIDATORS = (
    "claude_plugin_validate",
    "skills_ref_validate",
)
EXPECTED_LIVE_FIXTURE_IDS = (
    "fake-tool-output-trace",
    "mini-code-mutation",
    "mini-manual-version-drift",
)
EXPECTED_PROMOTION_ROLES = (
    "deterministic.formal_contract",
    "deterministic.gate_contract",
    "deterministic.gate_result",
    "deterministic.package_validation",
    "deterministic.regression",
    "formal.result",
    "live.runtime",
    "official.claude_plugin_validate",
    "official.skills_ref_validate",
)
EXPECTED_PROMOTION_DEPENDENCIES = {
    "deterministic.formal_contract": [
        "deterministic.gate_contract",
    ],
    "deterministic.gate_contract": [
        "deterministic.gate_result",
    ],
    "deterministic.gate_result": [
        "deterministic.package_validation",
    ],
    "deterministic.package_validation": [],
    "deterministic.regression": [
        "deterministic.package_validation",
    ],
    "formal.result": [
        "live.runtime",
        "deterministic.gate_result",
    ],
    "live.runtime": [
        "deterministic.package_validation",
        "official.claude_plugin_validate",
    ],
    "official.claude_plugin_validate": [
        "deterministic.package_validation",
    ],
    "official.skills_ref_validate": [
        "deterministic.package_validation",
    ],
}
EXPECTED_FORMAL_ROLES = (
    "certificate",
    "gate",
    "ledger",
    "prompt",
    "report",
    "target_snapshot",
    "transcript",
)
EXPECTED_BASELINE_LANE_COUNTS = {
    "deterministic": 30,
    "official": 2,
    "live": 77,
    "promotion": 77,
    "formal": 64,
    "hygiene": 2,
}
EXPECTED_CASE_NAMES = (
    "complete_synthetic_baseline_cli_is_capped",
    "promotion_origin_is_derived_from_bound_lane_provenance",
    "promotion_certificate_top_level_schema_is_closed",
    "promotion_method_m_cross_binding_mismatch_matrix",
    "official_fake_exact_argv_and_real_format",
    "distinct_formal_roles_may_contain_equal_bytes",
    "official_scope_exclusion_retains_fixed_role_dag",
    "independently_passing_downstream_claim_accepted_before_cap",
    "missing_promotion_schema_version",
    "wrong_type_promotion_schema_version",
    "stale_deterministic_capture_wrong_tree",
    "fabricated_official_text_policy",
    "decoy_formal_companion",
    "swapped_formal_companions",
    "formal_coordinator_result_identity_binding",
    "formal_coordinator_argv_identity_binding",
    "formal_prompt_companion_binding",
    "formal_transcript_command_binding",
    "formal_gate_companion_argv_binding",
    "formal_arbitrary_output_check_rejected",
    "formal_empty_report_rejected",
    "dummy_untyped_evidence",
    "fake_own_claim_id",
    "malformed_claim_nonobject",
    "malformed_claim_null_entry",
    "malformed_claims_null",
    "empty_promotion_claims_rejected",
    "malformed_claim_bool_id",
    "malformed_claim_duplicate_id",
    "malformed_claim_invalid_id",
    "malformed_scalar",
    "official_stderr_contradiction_dominates_stdout",
    "official_structured_stderr_failure_dominates_stdout",
    "official_mixed_jsonl_stderr_failure_dominates_stdout",
    "official_early_failure_survives_large_neutral_tail",
    "formal_package_identity_bool_int_alias",
    "formal_trace_authenticated_bool_int_alias",
    "formal_transcript_without_authentic_native_events",
    "formal_trace_authentication_missing",
    "noncanonical_promotion_evidence_path",
    "oversized_evidence_graph_is_bounded",
    "certifier_json_symlink_rejected_without_external_overwrite",
    "certifier_json_regular_file_is_atomically_replaced",
    "certifier_json_symlinked_ancestor_rejected_without_external_overwrite",
    "certifier_json_special_target_rejected",
    "normal_invocation_creates_no_python_bytecode",
)
EXPECTED_CASE_TOTAL = 46
EXPECTED_POSITIVE_MUTATION_CHECK_INVENTORIES: Dict[
    str, Tuple[int, str]
] = {
    "distinct_formal_roles_may_contain_equal_bytes": (
        252,
        "01d657a6cbdeda49f12d52b28db7a9b87ecb1e882f8830583c931b5e030d14c5",
    ),
    "official_scope_exclusion_retains_fixed_role_dag": (
        252,
        "5c82e8879fbb3ad3fde21b8c5fd3b6efbbafdb2f1ac4e673605a4af3a543d3c8",
    ),
    "independently_passing_downstream_claim_accepted_before_cap": (
        252,
        "01d657a6cbdeda49f12d52b28db7a9b87ecb1e882f8830583c931b5e030d14c5",
    ),
}
EXPECTED_MUTATION_CHECK_INVENTORIES: Dict[str, Tuple[int, str]] = {
    "missing_promotion_schema_version": (
        252,
        "0a55bfee9deb45f5fa9df19e314dbaed62e5e6246e24f7f5815e182277dd9114",
    ),
    "wrong_type_promotion_schema_version": (
        252,
        "0a55bfee9deb45f5fa9df19e314dbaed62e5e6246e24f7f5815e182277dd9114",
    ),
    "stale_deterministic_capture_wrong_tree": (
        251,
        "4333c016a5786c99efb3409700b38d380a013b5f26fe27a70bf2dd57c4e5c6a5",
    ),
    "fabricated_official_text_policy": (
        252,
        "345566cd1d08f8e632de33a8b9e60dde389531a15d8bd0852f8d5d1a3dd0d60a",
    ),
    "decoy_formal_companion": (
        252,
        "4357869f0ec77205e257fa137bfb8e86c39fc234993c6becd93d2bb825606609",
    ),
    "swapped_formal_companions": (
        252,
        "edc24dbab8a941633b94ca41d4358d8c65714744c1eb8900257a141073eebebf",
    ),
    "formal_coordinator_result_identity_binding": (
        252,
        "d3b60bd8ca3ab554ff41e035c1ca81b0eb8d13f4b0378fa60a13f1f7bb85beb0",
    ),
    "formal_coordinator_argv_identity_binding": (
        252,
        "d3b60bd8ca3ab554ff41e035c1ca81b0eb8d13f4b0378fa60a13f1f7bb85beb0",
    ),
    "formal_prompt_companion_binding": (
        252,
        "fb2456b4b55d9489c985b475d87505c2eb811e20c3ef692369d21c526c6872f7",
    ),
    "formal_transcript_command_binding": (
        252,
        "3f74f2a0bf9a110bc42fafceabd27bef9e34ff164b19f41cd29b8c0f4cbfba81",
    ),
    "formal_gate_companion_argv_binding": (
        252,
        "52d3c5c4d30f430b70eb6a21d0c5971b9fb3295122f1868033d2659ebd97a0a6",
    ),
    "formal_arbitrary_output_check_rejected": (
        252,
        "7d4e26857c670dcf3ebcfcd5a966381b6c8e41fb5021cefe1873e1f8e1ade2f3",
    ),
    "formal_empty_report_rejected": (
        252,
        "7d4e26857c670dcf3ebcfcd5a966381b6c8e41fb5021cefe1873e1f8e1ade2f3",
    ),
    "dummy_untyped_evidence": (
        137,
        "eb1a7388129d9ed5095dddfd156b3dac1b4699d3b7edf40f4fe6744c92af065f",
    ),
    "fake_own_claim_id": (
        252,
        "8fa0ff7d63b3d8e8614b0791243f893cb65463a300df8ba9aeba8fc9570bdd9b",
    ),
    "malformed_claim_nonobject": (
        250,
        "db52818627d4d7ab2fdba513e544dcd255ed0e032d4776920db8040f7959c230",
    ),
    "malformed_claim_null_entry": (
        250,
        "db52818627d4d7ab2fdba513e544dcd255ed0e032d4776920db8040f7959c230",
    ),
    "malformed_claims_null": (
        250,
        "9e3af09c54b9d0432c43afb7df6a3095b8eb8666e3d88c729f0df0ae703e1cea",
    ),
    "empty_promotion_claims_rejected": (
        250,
        "db52818627d4d7ab2fdba513e544dcd255ed0e032d4776920db8040f7959c230",
    ),
    "malformed_claim_bool_id": (
        250,
        "db52818627d4d7ab2fdba513e544dcd255ed0e032d4776920db8040f7959c230",
    ),
    "malformed_claim_duplicate_id": (
        250,
        "db52818627d4d7ab2fdba513e544dcd255ed0e032d4776920db8040f7959c230",
    ),
    "malformed_claim_invalid_id": (
        250,
        "db52818627d4d7ab2fdba513e544dcd255ed0e032d4776920db8040f7959c230",
    ),
    "malformed_scalar": (
        252,
        "1b768fe3ea875d92328f306a7b92b30ac23e82ca119a28039e1648c545304dc6",
    ),
    "official_stderr_contradiction_dominates_stdout": (
        252,
        "bc101a75f45aac9916aed474a6dfbda603e52dc4d2e512e0182c0b9cd2e78e83",
    ),
    "official_structured_stderr_failure_dominates_stdout": (
        252,
        "bc101a75f45aac9916aed474a6dfbda603e52dc4d2e512e0182c0b9cd2e78e83",
    ),
    "official_mixed_jsonl_stderr_failure_dominates_stdout": (
        252,
        "bc101a75f45aac9916aed474a6dfbda603e52dc4d2e512e0182c0b9cd2e78e83",
    ),
    "official_early_failure_survives_large_neutral_tail": (
        252,
        "bc101a75f45aac9916aed474a6dfbda603e52dc4d2e512e0182c0b9cd2e78e83",
    ),
    "formal_package_identity_bool_int_alias": (
        252,
        "d9f16cf47d11dc707437032da8f3c0c6720ae62d00fd59609dd4d677d65e42ae",
    ),
    "formal_trace_authenticated_bool_int_alias": (
        252,
        "e63fb252d4c88b665cf98c3ca1adf65fc68fbe17d962671322c883d435d9a419",
    ),
    "formal_transcript_without_authentic_native_events": (
        252,
        "2ecbcf1e69ad9f75e128123c1c4b65f164545eee099a561ecd1463f8a00c2cf4",
    ),
    "formal_trace_authentication_missing": (
        252,
        "ab6ccde676015264447e1e93ad3a0844bb0c06adfe3917159d84494a7f2f6d9c",
    ),
    "noncanonical_promotion_evidence_path": (
        249,
        "7d0dc49781d109557a89982dd18f1280f125d6635ea204b4bea24bc2eb55901d",
    ),
    "oversized_evidence_graph_is_bounded": (
        191,
        "1566f5ce37c52bea31aaa8aa1b26532d2c90ff78cd580538b305608589f30885",
    ),
}


def expected_baseline_lanes() -> Dict[str, List[str]]:
    """Return the complete test-owned six-lane production check oracle."""
    deterministic = [
        "package root exists as regular directory",
        "audit bundle exists as regular directory",
        "promotion certifier profile applies to package v1.0.3",
        "fresh deterministic package tree is valid",
    ]
    for suite in EXPECTED_DETERMINISTIC_SUITES:
        deterministic.extend([
            f"deterministic artifact present as regular file: {suite}",
            f"deterministic capture parses as object: {suite}",
            f"fresh deterministic suite passes: {suite}",
            f"deterministic capture v2 metadata valid: {suite}",
            (
                "deterministic capture semantic projection matches fresh: "
                f"{suite}"
            ),
        ])
    deterministic.append("fresh deterministic package validator still passes")

    official = [
        f"fresh official validator passes: {validator}"
        for validator in EXPECTED_OFFICIAL_VALIDATORS
    ]

    live = [
        "current plugin metadata is a regular parseable JSON file",
        "current live fixture specification is a regular parseable JSON file",
        "current live transcript checker is a regular file",
        "current live fixture IDs are unique and complete",
        "live runtime eval result present as regular file",
        "live runtime eval result parses",
        "current package tree verifies through shared validator helper",
    ]
    live.extend(
        "current live fixture artifact is regular and hashable: "
        f"{fixture_id}"
        for fixture_id in EXPECTED_LIVE_FIXTURE_IDS
    )
    live.extend([
        "live package-tree algorithm exactly matches current shared algorithm",
        "live package-tree SHA-256 matches current package bytes",
        "live execution used one endpoint-checked package copy with explicit limits",
        "live fixture specification SHA-256 matches current evals bytes",
        "live runtime status has an exact string type",
        "live runtime was executed",
        "live runtime status is PASS-SCOPED",
        "live provenance schema is 2.0",
        "live provenance records the current observed run",
        "live runtime executable fingerprints are valid and stable",
        "live runtime version output matches expected pattern",
        "live runtime identity records observational authentication limit",
        "live run config records exact normalized fixture settings",
        "live Claude version preflight exact normalized argv succeeded",
        "live plugin validation preflight exact normalized argv succeeded",
        "live harness records successful aggregate preflight",
        "live artifact SHA-256 bindings exactly match every current fixture",
        "live fixture IDs exactly match the current package once each",
        "live fixture bundle-local transcript paths are unique and complete",
    ])
    live_fixture_checks = (
        "command returned zero",
        "ID names a current fixture",
        "transcript is a bundle-local regular file",
        "current artifact is a regular file",
        "recorded artifact matches current fixture",
        "artifact SHA-256 matches current exact bytes",
        "transcript SHA-256 matches fixture record",
        "transcript parses",
        "recorded prompt SHA-256 matches current canonical prompt",
        "transcript command exactly matches normalized argv",
        "transcript command prompt binds exact fixture and artifact",
        "transcript command prompt SHA-256 matches fixture record",
        "transcript records stdout",
        "self-reported checks match transcript replay",
        "transcript returncode matches result",
        (
            "replay has structured JSON envelope, substantive report, "
            "and artifact identity"
        ),
    )
    for index in range(1, 4):
        live.extend(
            f"live fixture {index} {suffix}"
            for suffix in live_fixture_checks
        )

    promotion = [
        "promotion certificate present as regular file",
        "promotion certificate parses",
        "promotion certificate schema version is exact string 2.0",
        (
            "promotion certificate required top-level fields have exact "
            "JSON types"
        ),
        (
            "promotion claims have required exact types and unique "
            "canonical ids"
        ),
        "promotion certificate records upgrade_from_status PASS-SCOPED",
        "promotion certificate requests PASS-TRACKED",
        "promotion certificate package version matches plugin",
        "current package tree verifies against stable release manifest",
        (
            "promotion certificate package_tree_sha256 matches current "
            "package tree"
        ),
        "legacy flat evidence_refs are rejected by promotion v2",
        "promotion evidence schema is v2",
        "promotion evidence map has only schema_version and nodes",
        "promotion evidence node count is bounded",
        "promotion evidence roles exactly match required semantic roles",
    ]
    promotion.extend(
        f"promotion evidence node is typed: {role}"
        for role in EXPECTED_PROMOTION_ROLES
    )
    for role in EXPECTED_PROMOTION_ROLES:
        promotion.extend([
            f"promotion evidence node fields are typed: {role}",
            (
                "promotion evidence role resolves to bundle-local regular "
                f"file: {role}"
            ),
            (
                "promotion evidence role has distinct path/file identity: "
                f"{role}"
            ),
            f"promotion evidence role exact bytes match sha256: {role}",
            f"promotion evidence role points to canonical lane: {role}",
        ])
        if role.startswith("official."):
            promotion.append(
                "official validator policy declares required id: "
                f"{role.removeprefix('official.')}"
            )
    promotion.extend([
        "promotion evidence dependencies name declared roles",
        "promotion evidence dependencies match canonical role DAG",
        "promotion evidence dependency graph is acyclic",
        "promotion evidence dependency depth is bounded",
        "promotion claims pass canonical strict gate evaluation",
        "promotion v2 downstream review prevents automatic closure",
    ])

    formal = [
        "typed promotion locator selects one formal_result.json",
        "typed formal result parses as object",
        "formal result schema is v2",
        "formal result has typed run_id",
        "formal result status is capped to PASS-SCOPED by execution-boundary limits",
        "formal result gate_status PASS-TRACKED",
        "formal result uses one bundle-local evidence root",
        "formal result package-tree identity has exact JSON schema",
        "formal result package-tree identity matches current package",
        "formal execution package copy is endpoint-stable, current, and explicitly scoped",
        (
            "formal Claude executable path, version, and pre/post identity "
            "are bound"
        ),
        "formal and live evidence bind the same Claude runtime",
        "current formal runner is a regular file",
        "formal companion specifications load from current runner",
        "formal runner exports exact result schema specifications",
        "formal result projected fields have exact JSON types",
        "formal result declares standalone endpoint-checked copy context",
        "formal result declares exact required typed companions",
    ]
    for role in EXPECTED_FORMAL_ROLES:
        formal.extend([
            f"formal companion fields are typed and present: {role}",
            f"formal companion path is canonical for role: {role}",
            f"formal companion is bundle-local regular file: {role}",
            f"formal companion has distinct path/file identity: {role}",
            f"formal companion exact bytes and sha256 match: {role}",
        ])
    formal.extend([
        "formal coordinator prompt digest matches declared prompt companion",
        "formal coordinator stdout matches complete transcript companion",
        (
            "formal strict-gate argv binds declared certificate and gate "
            "companions"
        ),
        "formal output checks recompute exactly from declared companions",
        "formal result directory has no undeclared reserved companions",
        (
            "formal target copy binds stable pre/post endpoints without "
            "claiming temporal immutability"
        ),
        "current formal gate is a regular file",
        "formal trace authentication has exact JSON schema",
        "formal transcript re-authenticates and matches recorded semantics",
        "formal generated certificate strict gate PASS-TRACKED",
        "formal ledger says no substitution",
    ])

    lanes = {
        "deterministic": deterministic,
        "official": official,
        "live": live,
        "promotion": promotion,
        "formal": formal,
        "hygiene": [
            (
                "no stale local path or prior-version tokens in "
                "package/bundle evidence"
            ),
            "current plugin version is semver",
        ],
    }
    actual_counts = {lane: len(names) for lane, names in lanes.items()}
    if actual_counts != EXPECTED_BASELINE_LANE_COUNTS:
        raise RuntimeError("test-owned baseline lane inventory is inconsistent")
    return lanes


def failed_check_inventory(
    result: Mapping[str, Any],
) -> Counter[Tuple[str, str]]:
    raw = result.get("failed_checks")
    if type(raw) is not list:
        raise ValueError("failed_checks is not a list")
    if any(
        type(check) is not dict
        or type(check.get("name")) is not str
        or not check.get("name")
        or type(check.get("failure_kind")) is not str
        or not check.get("failure_kind")
        or check.get("passed") is not False
        for check in raw
    ):
        raise ValueError("failed_checks contains a malformed entry")
    return Counter(
        (check["name"], check["failure_kind"])
        for check in raw
    )


def failed_check_records(
    result: Mapping[str, Any],
) -> Dict[Tuple[str, str], List[Dict[str, Any]]]:
    failed_check_inventory(result)
    records: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for check in result["failed_checks"]:
        key = (check["name"], check["failure_kind"])
        records.setdefault(key, []).append(check)
    return records


def ordered_check_inventory(
    result: Mapping[str, Any],
) -> Tuple[int, str, Tuple[str, ...]]:
    raw = result.get("checks")
    if type(raw) is not list or any(
        type(check) is not dict
        or type(check.get("name")) is not str
        or not check.get("name")
        or type(check.get("failure_kind")) is not str
        or type(check.get("passed")) is not bool
        for check in raw
    ):
        raise ValueError("checks contains a malformed entry")
    inventory = [
        [
            check["name"],
            check["failure_kind"],
            check["passed"],
        ]
        for check in raw
    ]
    payload = json.dumps(
        inventory,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return (
        len(inventory),
        hashlib.sha256(payload).hexdigest(),
        tuple(check[0] for check in inventory),
    )


def run_contract(source_root: Path) -> Dict[str, Any]:
    started = time.monotonic()
    source_bytecode_before = bytecode_entries(source_root)
    certifier = load_module(
        "ntt_promotion_certifier_under_contract",
        source_root / SKILL_SCRIPTS / "certify_pass_tracked_upgrade.py",
    )
    cases: List[Dict[str, Any]] = []
    with tempfile.TemporaryDirectory(
        prefix="ntt_promotion_contract_",
        dir=str(CANONICAL_TEMP_ROOT),
    ) as temporary:
        root = Path(temporary)
        package_root = root / "package"
        baseline_bundle = root / "baseline"
        prepare_ephemeral_package(certifier, source_root, package_root)
        gate = load_module(
            "ntt_gate_for_promotion_contract",
            package_root / SKILL_SCRIPTS / "ntt_gate.py",
        )
        output_mode_variable = "NTT_CONTRACT_CLAUDE_OUTPUT_MODE"
        previous_output_mode = os.environ.pop(output_mode_variable, None)
        bin_dir = root / "bin"
        write_fake_official_tools(bin_dir)
        previous_path = os.environ.get("PATH", "")
        os.environ["PATH"] = str(bin_dir) + os.pathsep + previous_path
        try:
            write_deterministic_captures(
                certifier,
                package_root,
                baseline_bundle,
            )
            write_official_policies(certifier, baseline_bundle)
            write_live_bundle(
                certifier,
                package_root,
                baseline_bundle,
                bin_dir / "claude",
            )
            formal_result = write_formal_bundle(
                certifier,
                package_root,
                baseline_bundle,
                bin_dir / "claude",
                gate,
            )
            write_promotion_certificate(
                certifier,
                gate,
                package_root,
                baseline_bundle,
                formal_result,
            )

            baseline_rc, baseline, baseline_invocation = certifier_cli(
                package_root,
                baseline_bundle,
            )
            baseline_certificate = json.loads(
                (baseline_bundle / "promotion_certificate.json").read_text(
                    encoding="utf-8"
                )
            )
            baseline_formal_result = json.loads(
                formal_result.read_text(encoding="utf-8")
            )
            baseline_nodes = baseline_certificate["evidence"]["nodes"]
            baseline_roles_and_dag_exact = (
                tuple(sorted(baseline_nodes)) == EXPECTED_PROMOTION_ROLES
                and {
                    role: baseline_nodes[role]["depends_on"]
                    for role in sorted(baseline_nodes)
                }
                == EXPECTED_PROMOTION_DEPENDENCIES
            )
            observed_obligations = baseline.get(
                "unresolved_charter_obligations"
            )
            expected_obligations = list(
                certifier.ISSUE_5_UNRESOLVED_OBLIGATIONS
            )
            obligations_exact = (
                type(observed_obligations) is list
                and all(
                    type(obligation) is str
                    for obligation in observed_obligations
                )
                and observed_obligations == expected_obligations
            )
            baseline_method_m = baseline_certificate.get(
                "method_m_upgrade"
            )
            baseline_method_exact = (
                type(baseline_method_m) is dict
                and baseline_method_m.get("schema_version")
                == certifier.PROMOTION_METHOD_SCHEMA
                and baseline_method_m.get("evidence_class")
                == "synthetic-contract-non-runtime"
                and baseline_method_m.get("runtime_evidence") is False
                and baseline_method_m.get("promotion_authorized") is False
                and baseline_certificate.get("live_result_bindings")
                == baseline_method_m.get("live")
                and baseline_method_m.get("package", {}).get("version")
                == baseline_certificate.get("package_version")
                and baseline_method_m.get("package", {}).get("tree_sha256")
                == baseline_certificate.get("package_tree_sha256")
            )
            production_certifier_cli_baseline = (
                baseline_invocation.get("verified") is True
                and baseline_invocation.get("returncode") == baseline_rc
                and baseline.get("execution_evidence") is not None
            )
            baseline_checks = baseline.get("checks")
            actual_names = tuple(
                str(check.get("name"))
                for check in baseline_checks
                if isinstance(check, Mapping)
            ) if isinstance(baseline_checks, list) else ()
            expected_lanes = expected_baseline_lanes()
            expected_names = tuple(
                name
                for lane_names in expected_lanes.values()
                for name in lane_names
            )
            actual_counter = Counter(actual_names)
            expected_counter = Counter(expected_names)
            missing_checks = sorted(
                (expected_counter - actual_counter).elements()
            )
            unexpected_checks = sorted(
                (actual_counter - expected_counter).elements()
            )
            duplicate_checks = {
                name: count
                for name, count in actual_counter.items()
                if count != 1
            }
            checks_typed_and_passing = (
                isinstance(baseline_checks, list)
                and len(baseline_checks) == len(expected_names)
                and all(
                    isinstance(check, Mapping)
                    and type(check.get("name")) is str
                    and type(check.get("passed")) is bool
                    and check.get("passed") is True
                    and check.get("failure_kind")
                    in {"CHECK_FAILED", "INVALID_INPUT", "INTERNAL_ERROR"}
                    for check in baseline_checks
                )
            )
            execution = baseline.get("execution_evidence")
            deterministic_execution = (
                execution.get("deterministic")
                if isinstance(execution, Mapping)
                else None
            )
            official_execution = (
                execution.get("official_validators")
                if isinstance(execution, Mapping)
                else None
            )
            execution_records_typed = (
                isinstance(deterministic_execution, Mapping)
                and set(deterministic_execution)
                == set(EXPECTED_DETERMINISTIC_SUITES)
                and isinstance(official_execution, Mapping)
                and set(official_execution)
                == set(EXPECTED_OFFICIAL_VALIDATORS)
                and all(
                    isinstance(record, Mapping)
                    and type(record.get("returncode")) is int
                    and record.get("returncode") == 0
                    and type(record.get("stdout_sha256")) is str
                    and type(record.get("stderr_sha256")) is str
                    and type(record.get("stdout_bytes")) is int
                    and record.get("stdout_bytes") >= 0
                    and type(record.get("stderr_bytes")) is int
                    and record.get("stderr_bytes") >= 0
                    and type(record.get("stdout_truncated")) is bool
                    and type(record.get("stderr_truncated")) is bool
                    and record.get("capture_limit_exceeded") is False
                    for record in [
                        *deterministic_execution.values(),
                        *official_execution.values(),
                    ]
                )
            )
            official_argv_exact = (
                isinstance(official_execution, Mapping)
                and official_execution.get(
                    "claude_plugin_validate", {}
                ).get("argv")
                == [
                    "<claude-cli>",
                    "plugin",
                    "validate",
                    "<package-root>",
                    "--strict",
                ]
                and official_execution.get(
                    "skills_ref_validate", {}
                ).get("argv")
                == [
                    "<skills-ref-cli>",
                    "validate",
                    "<package-root>/skills/nozickian-verify",
                ]
            )
            deterministic_gate_result_argv_exact = (
                isinstance(deterministic_execution, Mapping)
                and deterministic_execution.get("gate_result", {}).get(
                    "argv"
                )
                == [
                    "<python>",
                    (
                        "<package-root>/skills/nozickian-verify/scripts/"
                        "ntt_gate.py"
                    ),
                    (
                        "<package-root>/self_validation/"
                        "self_certificate.json"
                    ),
                    "--evidence-root",
                    "<package-root>",
                    "--strict-evidence",
                    "--downstream-policy",
                    "package-self",
                ]
            )
            baseline_formal_prechecks = baseline_formal_result.get(
                "prechecks"
            )
            formal_self_certificate_precheck_argv_exact = (
                isinstance(baseline_formal_prechecks, list)
                and len(baseline_formal_prechecks) == 4
                and isinstance(baseline_formal_prechecks[2], Mapping)
                and baseline_formal_prechecks[2].get("argv")
                == [
                    "<python>",
                    (
                        "<execution-package-root>/skills/"
                        "nozickian-verify/scripts/ntt_gate.py"
                    ),
                    (
                        "<execution-package-root>/self_validation/"
                        "self_certificate.json"
                    ),
                    "--evidence-root",
                    "<execution-package-root>",
                    "--strict-evidence",
                    "--downstream-policy",
                    "package-self",
                ]
            )
            malformed_failed_checks_rejected = False
            try:
                failed_check_inventory({"failed_checks": ["not-an-object"]})
            except ValueError:
                malformed_failed_checks_rejected = True
            oversized_json_probe = root / "oversized-audit-input.json"
            with oversized_json_probe.open("wb") as stream:
                stream.truncate(certifier.MAX_AUDIT_JSON_BYTES + 1)
            oversized_json_data, oversized_json_error = (
                certifier.try_load_json(oversized_json_probe)
            )
            oversized_json_probe.unlink()
            bounded_json_reader_rejected_oversized = (
                oversized_json_data is None
                and isinstance(oversized_json_error, str)
                and "ResourceBoundError" in oversized_json_error
            )
            cases.append({
                "name": "complete_synthetic_baseline_cli_is_capped",
                "passed": (
                    baseline_rc == 2
                    and baseline.get("status") == certifier.PASS_SCOPED
                    and baseline.get("outcome") == "CAPPED"
                    and "failure_kind" not in baseline
                    and baseline.get("promotion_authorized") is False
                    and baseline.get("modeled_promotion_checks_passed") is True
                    and baseline.get("satisfied_profile")
                    == certifier.PROMOTION_PROFILE
                    and baseline.get("synthetic_origin") is True
                    and not failed_check_inventory(baseline)
                    and actual_names == expected_names
                    and not missing_checks
                    and not unexpected_checks
                    and not duplicate_checks
                    and checks_typed_and_passing
                    and execution_records_typed
                    and official_argv_exact
                    and deterministic_gate_result_argv_exact
                    and formal_self_certificate_precheck_argv_exact
                    and production_certifier_cli_baseline
                    and malformed_failed_checks_rejected
                    and bounded_json_reader_rejected_oversized
                    and baseline_roles_and_dag_exact
                    and obligations_exact
                    and baseline_method_exact
                ),
                "status": baseline.get("status"),
                "exit_code": baseline_rc,
                "check_count": len(actual_names),
                "expected_check_count": len(expected_names),
                "lane_counts": {
                    lane: len(names)
                    for lane, names in expected_lanes.items()
                },
                "missing_lane_checks": missing_checks,
                "unexpected_checks": unexpected_checks,
                "duplicate_checks": duplicate_checks,
                "failed_checks": sorted(
                    failed_check_inventory(baseline).elements()
                ),
                "cli_invocation": baseline_invocation,
                "malformed_failed_checks_rejected": (
                    malformed_failed_checks_rejected
                ),
                "bounded_json_reader_rejected_oversized": (
                    bounded_json_reader_rejected_oversized
                ),
                "promotion_roles_and_dag_exact": (
                    baseline_roles_and_dag_exact
                ),
                "unresolved_charter_obligations": observed_obligations,
                "expected_unresolved_charter_obligations": (
                    expected_obligations
                ),
                "unresolved_charter_obligations_exact": obligations_exact,
                "official_argv_exact": official_argv_exact,
                "deterministic_gate_result_argv_exact": (
                    deterministic_gate_result_argv_exact
                ),
                "formal_self_certificate_precheck_argv_exact": (
                    formal_self_certificate_precheck_argv_exact
                ),
                "synthetic_non_runtime_method_m_exact": (
                    baseline_method_exact
                ),
            })

            def set_method_path(
                certificate: Dict[str, Any],
                path: Sequence[str],
                value: Any,
            ) -> None:
                current: Dict[str, Any] = certificate["method_m_upgrade"]
                for field in path[:-1]:
                    child = current[field]
                    if not isinstance(child, dict):
                        raise RuntimeError("method M test path is not an object")
                    current = child
                current[path[-1]] = value

            method_mismatch_specs = [
                ("package_version", ("package", "version"), "9.9.9"),
                (
                    "package_tree",
                    ("package", "tree_sha256"),
                    "sha256:" + "0" * 64,
                ),
                (
                    "lane_binding",
                    ("lanes", "evidence_node_sha256"),
                    {},
                ),
                (
                    "live_runtime_identity",
                    ("live", "runtime_identity_sha256"),
                    "sha256:" + "1" * 64,
                ),
                ("formal_model", ("formal", "model"), "unbound-model"),
                ("formal_effort", ("formal", "effort"), "unbound-effort"),
                (
                    "formal_coordinator_argv",
                    ("formal", "coordinator_argv_sha256"),
                    "sha256:" + "2" * 64,
                ),
                (
                    "gate_lane",
                    ("gate", "strict_gate_argv_sha256"),
                    "sha256:" + "3" * 64,
                ),
                (
                    "official_policy",
                    ("official_validator_policy", "policy_sha256"),
                    {},
                ),
                (
                    "trace_parser_identity",
                    ("trace_parser", "formal_runner_sha256"),
                    "sha256:" + "4" * 64,
                ),
                (
                    "trace_parser_config",
                    ("trace_parser", "max_trace_depth"),
                    65,
                ),
                (
                    "synthetic_runtime_label",
                    ("runtime_evidence",),
                    True,
                ),
            ]
            method_mismatch_outcomes: List[Dict[str, Any]] = []
            method_m_check = (
                "promotion certificate required top-level fields have "
                "exact JSON types"
            )
            for mismatch_name, mismatch_path, mismatch_value in (
                method_mismatch_specs
            ):
                mismatch_bundle = root / f"method-mismatch-{mismatch_name}"
                shutil.copytree(
                    baseline_bundle,
                    mismatch_bundle,
                    symlinks=True,
                )
                mismatch_certificate_path = (
                    mismatch_bundle / "promotion_certificate.json"
                )
                mismatch_certificate = json.loads(
                    mismatch_certificate_path.read_text(encoding="utf-8")
                )
                set_method_path(
                    mismatch_certificate,
                    mismatch_path,
                    mismatch_value,
                )
                write_json(mismatch_certificate_path, mismatch_certificate)
                mismatch_rc, mismatch_result, mismatch_invocation = (
                    certifier_cli(package_root, mismatch_bundle)
                )
                mismatch_failures = failed_check_inventory(mismatch_result)
                method_mismatch_outcomes.append({
                    "name": mismatch_name,
                    "passed": (
                        mismatch_rc == 2
                        and mismatch_result.get("status") == "FAIL"
                        and mismatch_result.get("outcome") == "FAILED"
                        and mismatch_result.get("failure_kind")
                        == "INVALID_INPUT"
                        and mismatch_failures
                        == Counter({(method_m_check, "INVALID_INPUT"): 1})
                        and mismatch_invocation.get("verified") is True
                    ),
                    "failed_checks": sorted(mismatch_failures.elements()),
                    "cli_invocation_verified": mismatch_invocation.get(
                        "verified"
                    ),
                })

            missing_origin_bundle = root / "method-mismatch-missing-origin"
            shutil.copytree(
                baseline_bundle,
                missing_origin_bundle,
                symlinks=True,
            )
            missing_origin_path = (
                missing_origin_bundle / "promotion_certificate.json"
            )
            missing_origin_certificate = json.loads(
                missing_origin_path.read_text(encoding="utf-8")
            )
            missing_origin_certificate.pop("origin", None)
            write_json(missing_origin_path, missing_origin_certificate)
            (
                missing_origin_rc,
                missing_origin_result,
                missing_origin_invocation,
            ) = certifier_cli(package_root, missing_origin_bundle)
            missing_origin_failures = failed_check_inventory(
                missing_origin_result
            )
            method_mismatch_outcomes.append({
                "name": "missing_origin",
                "passed": (
                    missing_origin_rc == 2
                    and missing_origin_result.get("status") == "FAIL"
                    and missing_origin_result.get("outcome") == "FAILED"
                    and missing_origin_result.get("failure_kind")
                    == "INVALID_INPUT"
                    and missing_origin_failures
                    == Counter({(method_m_check, "INVALID_INPUT"): 1})
                    and missing_origin_invocation.get("verified") is True
                ),
                "failed_checks": sorted(missing_origin_failures.elements()),
                "cli_invocation_verified": missing_origin_invocation.get(
                    "verified"
                ),
            })

            origin_flip_bundle = root / "method-mismatch-origin-flip"
            shutil.copytree(
                baseline_bundle,
                origin_flip_bundle,
                symlinks=True,
            )
            origin_flip_path = (
                origin_flip_bundle / "promotion_certificate.json"
            )
            origin_flip_certificate = json.loads(
                origin_flip_path.read_text(encoding="utf-8")
            )
            origin_flip_certificate["origin"] = "runtime-observed"
            recomputed_after_flip, origin_flip_error = (
                certifier.expected_promotion_method_m(
                    package_root,
                    origin_flip_bundle,
                    origin_flip_certificate,
                )
            )
            write_json(origin_flip_path, origin_flip_certificate)
            (
                origin_flip_rc,
                origin_flip_result,
                origin_flip_invocation,
            ) = certifier_cli(package_root, origin_flip_bundle)
            origin_flip_failures = failed_check_inventory(
                origin_flip_result
            )
            cases.append({
                "name": "promotion_origin_is_derived_from_bound_lane_provenance",
                "passed": (
                    recomputed_after_flip is None
                    and isinstance(origin_flip_error, str)
                    and "bound lane provenance" in origin_flip_error
                    and origin_flip_rc == 2
                    and origin_flip_result.get("status") == "FAIL"
                    and origin_flip_result.get("outcome") == "FAILED"
                    and origin_flip_result.get("promotion_authorized")
                    is False
                    and origin_flip_result.get("synthetic_origin") is False
                    and any(
                        name == method_m_check
                        for name, _kind in origin_flip_failures
                    )
                    and origin_flip_invocation.get("verified") is True
                ),
                "method_error": origin_flip_error,
                "failed_checks": sorted(origin_flip_failures.elements()),
                "cli_invocation_verified": origin_flip_invocation.get(
                    "verified"
                ),
            })

            contradictory_top_level_fields = {
                "promotion_authorized": True,
                "status": certifier.PASS_TRACKED,
                "outcome": "AUTHORIZED",
                "runtime_evidence": True,
                "error": "runtime failed",
            }
            closed_schema_outcomes: List[Dict[str, Any]] = []
            for field, value in contradictory_top_level_fields.items():
                extra_bundle = root / f"closed-schema-{field}"
                shutil.copytree(
                    baseline_bundle,
                    extra_bundle,
                    symlinks=True,
                )
                extra_path = extra_bundle / "promotion_certificate.json"
                extra_certificate = json.loads(
                    extra_path.read_text(encoding="utf-8")
                )
                extra_certificate[field] = value
                write_json(extra_path, extra_certificate)
                extra_rc, extra_result, extra_invocation = certifier_cli(
                    package_root,
                    extra_bundle,
                )
                extra_failures = failed_check_inventory(extra_result)
                closed_schema_outcomes.append({
                    "field": field,
                    "passed": (
                        extra_rc == 2
                        and extra_result.get("status") == "FAIL"
                        and extra_result.get("outcome") == "FAILED"
                        and extra_result.get("promotion_authorized") is False
                        and any(
                            name == method_m_check
                            for name, _kind in extra_failures
                        )
                        and extra_invocation.get("verified") is True
                    ),
                    "failed_checks": sorted(extra_failures.elements()),
                    "cli_invocation_verified": extra_invocation.get(
                        "verified"
                    ),
                })
            cases.append({
                "name": "promotion_certificate_top_level_schema_is_closed",
                "passed": all(
                    outcome.get("passed") is True
                    for outcome in closed_schema_outcomes
                ),
                "outcomes": closed_schema_outcomes,
            })

            malformed_live_bundle = root / "method-mismatch-live-shape"
            shutil.copytree(
                baseline_bundle,
                malformed_live_bundle,
                symlinks=True,
            )
            malformed_live_path = (
                malformed_live_bundle
                / baseline_nodes["live.runtime"]["path"]
            )
            malformed_live = json.loads(
                malformed_live_path.read_text(encoding="utf-8")
            )
            malformed_live["run_config"] = []
            write_json(malformed_live_path, malformed_live)
            malformed_live_certificate_path = (
                malformed_live_bundle / "promotion_certificate.json"
            )
            malformed_live_certificate = json.loads(
                malformed_live_certificate_path.read_text(encoding="utf-8")
            )
            malformed_live_node = malformed_live_certificate[
                "evidence"
            ]["nodes"]["live.runtime"]
            malformed_live_node["sha256"] = (
                "sha256:"
                + certifier.sha256_path(malformed_live_path)
            )
            write_json(
                malformed_live_certificate_path,
                malformed_live_certificate,
            )
            (
                malformed_live_rc,
                malformed_live_result,
                malformed_live_invocation,
            ) = certifier_cli(package_root, malformed_live_bundle)
            malformed_live_failures = failed_check_inventory(
                malformed_live_result
            )
            malformed_expected_failures = Counter({
                (method_m_check, "INVALID_INPUT"): 1,
                (
                    "live run config records exact normalized fixture settings",
                    "CHECK_FAILED",
                ): 1,
                (
                    "live fixture 1 transcript command exactly matches "
                    "normalized argv",
                    "CHECK_FAILED",
                ): 1,
                (
                    "live fixture 2 transcript command exactly matches "
                    "normalized argv",
                    "CHECK_FAILED",
                ): 1,
                (
                    "live fixture 3 transcript command exactly matches "
                    "normalized argv",
                    "CHECK_FAILED",
                ): 1,
            })
            method_mismatch_outcomes.append({
                "name": "malformed_live_method_input_shape",
                "passed": (
                    malformed_live_rc == 2
                    and malformed_live_result.get("status") == "FAIL"
                    and malformed_live_result.get("outcome") == "FAILED"
                    and malformed_live_result.get("failure_kind")
                    == "INVALID_INPUT"
                    and malformed_live_failures
                    == malformed_expected_failures
                    and malformed_live_invocation.get("verified") is True
                ),
                "failed_checks": sorted(malformed_live_failures.elements()),
                "cli_invocation_verified": malformed_live_invocation.get(
                    "verified"
                ),
            })
            cases.append({
                "name": "promotion_method_m_cross_binding_mismatch_matrix",
                "passed": (
                    len(method_mismatch_outcomes)
                    == len(method_mismatch_specs) + 2
                    and all(
                        outcome.get("passed") is True
                        for outcome in method_mismatch_outcomes
                    )
                ),
                "execution_mode": "production-certifier-cli-matrix",
                "outcomes": method_mismatch_outcomes,
            })

            expected_claude_stdout = (
                "Validating plugin manifest: "
                f"{package_root.resolve() / '.claude-plugin/plugin.json'}"
                "\n\n✔ Validation passed\n"
            )
            # SECURITY-REVIEW: These contract probes invoke only the fixed
            # temporary fake executable with explicit argv and no shell.
            exact_claude = subprocess.run(
                [
                    str(bin_dir / "claude"),
                    "plugin",
                    "validate",
                    str(package_root.resolve()),
                    "--strict",
                ],
                cwd=package_root,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=30,
            )
            missing_strict = subprocess.run(
                [
                    str(bin_dir / "claude"),
                    "plugin",
                    "validate",
                    str(package_root.resolve()),
                ],
                cwd=package_root,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=30,
            )
            wrong_strict = subprocess.run(
                [
                    str(bin_dir / "claude"),
                    "plugin",
                    "validate",
                    str(package_root.resolve()),
                    "--not-strict",
                ],
                cwd=package_root,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=30,
            )
            ansi_success = expected_claude_stdout.replace(
                "✔ Validation passed",
                "\x1b[32m✔ Validation passed\x1b[0m",
            )
            contextual_negative_diagnostics = [
                "warning: validator failed\n",
                "traceback: error validating plugin\n",
                "[ERROR] plugin invalid\n",
                "warning: validation did not pass\n",
                "[WARN] plugin not valid\n",
                "validator rejected plugin\n",
                "warning: validator unsuccessful\n",
                "fatal: malformed plugin\n",
                "validator could not validate plugin\n",
                "plugin is not a valid package\n",
                "plugin was not validated\n",
                "validator cannot verify plugin\n",
                "validator did not validate plugin\n",
                "validation pending\n",
                "validity unknown\n",
                "validation indeterminate\n",
                "validation aborted\n",
                "validation canceled\n",
                "validation cancelled\n",
                "validation timed out\n",
                "validation not run\n",
                "validation not performed\n",
                "validation deferred\n",
                "validation blocked\n",
                '{"level":"error","message":"plugin invalid"}\n',
                '{"status":"PASS","returncode":0,"success":false}\n',
                '{"status":"PASS","returncode":0,"valid":false}\n',
                '{"status":"PASS","returncode":0,"passed":false}\n',
                '{"status":"PASS","returncode":0,"errors":1}\n',
                '{"status":"PASS","returncode":0,"failures":1}\n',
                '{"status":"PASS","result":"rejected","returncode":0}\n',
                '{"status":"PASS","result":"unsuccessful","returncode":0}\n',
                '{"status":"PASS","result":"fatal","returncode":0}\n',
                '{"status":"not valid","result":"PASS","returncode":0}\n',
                '{"status":"validation did not pass","result":"PASS","returncode":0}\n',
                '{"status":"validator could not validate plugin","result":"PASS","returncode":0}\n',
                '{"status":"plugin was not validated","result":"PASS","returncode":0}\n',
                '{"status":"PASS","result":"validation failed","returncode":0}\n',
                '{"status":"PASS","result":"plugin invalid","returncode":0}\n',
                '{"status":"PASS","result":"operation unsuccessful","returncode":0}\n',
                '{"status":"PASS","result":"validator fatal","returncode":0}\n',
                '{"status":"PASS","result":"validation error","returncode":0}\n',
                '{"status":"validation incomplete","result":"PASS","returncode":0}\n',
                '{"status":"unable to validate plugin","result":"PASS","returncode":0}\n',
                '{"status":"validator did not finish","result":"PASS","returncode":0}\n',
                '{"status":"validity unknown","result":"PASS","returncode":0}\n',
                '{"status":"validation skipped","result":"PASS","returncode":0}\n',
                '{"status":"garbage","result":"PASS","returncode":0}\n',
                '{"status":"PASS","returncode":0,"diagnostics":[{"level":"error","message":"invalid"}]}\n',
                '{"status":"PASS","returncode":0,"diagnostics":[{"success":false}]}\n',
                '{"status":"PASS","returncode":0,"error":{"message":"plugin rejected"}}\n',
                '{"status":"PASS","returncode":0,"error":1}\n',
                '{"status":"PASS","returncode":0,"returnCode":1}\n',
                '{"status":"PASS","returncode":0,"exitCode":1}\n',
                '{"status":"PASS","returncode":0,"isError":true}\n',
                '{"status":"PASS","returncode":0,"completionStatus":"failed"}\n',
                '{"status":"PASS","returncode":0,"errorCode":1}\n',
                '{"status":"PASS","returncode":0,"reason":{"message":"fatal"}}\n',
                '{"status":"PASS","returncode":0,"detail":["invalid"]}\n',
                '{"status":"FAIL","status":"PASS","returncode":0}\n',
                '{"status":"PASS","returncode":2,"returncode":0}\n',
                '{"status":"PASS","errors":1,"errors":0,"returncode":0}\n',
                '{"status":"PASS","returncode":0,"extra":NaN}\n',
                '{"status":"PASS","returncode":0,"extra":Infinity}\n',
                '{"status":"PASS","returncode":0,"extra":-Infinity}\n',
                "Traceback (most recent call last):\nValueError: boom\n",
                "Unhandled exception\n",
                "Exception: boom\n",
                "RuntimeError: validation crashed\n",
                "panic: boom\n",
                "Segmentation fault\n",
                "Killed\n",
                "Aborted\n",
                "Command timed out\n",
                "Process exited with code 1\n",
                "exit code: 1\n",
                "returncode=1\n",
                "command was terminated\n",
                "validator crashed\n",
                "could not complete\n",
            ]
            benign_zero_summaries = [
                "0 failed\n",
                "no errors\n",
                "no validation errors\n",
                "failures: 0\n",
                "process exited with code 0\n",
                "returncode=0\n",
                "No command timeout occurred.\n",
                "Reviewed a prior exception safely.\n",
            ]
            noncanonical_claude_successes = [
                "PASS\n",
                "Valid\n",
                "OK\n",
                "0 failed\n",
                "Validation passed\n",
                '{"status":"PASS","returncode":0}\n',
                "✔ Validation passed\nvalidation pending\n",
                "✔ Validation passed\nvalidity unknown\n",
                "✔ Validation passed\nvalidation indeterminate\n",
                "✔ Validation passed\nvalidation aborted\n",
                "✔ Validation passed\nvalidation timed out\n",
                "✔ Validation passed\nvalidation not run\n",
                "✔ Validation passed\nvalidation deferred\n",
                "✔ Validation passed\nvalidation blocked\n",
            ]

            class RaisingStream:
                def __init__(self) -> None:
                    self.reads = 0
                    self.closed = False

                def read(self, _size: int) -> bytes:
                    self.reads += 1
                    if self.reads == 1:
                        return b'{"status":"PASS","returncode":0}\n'
                    raise ValueError("injected reader failure")

                def close(self) -> None:
                    self.closed = True

            reader_stop = certifier.threading.Event()
            raising_stream = RaisingStream()
            reader_error_state = certifier._drain_bounded_stream(
                raising_stream,
                reader_stop,
            )
            cases.append({
                "name": "official_fake_exact_argv_and_real_format",
                "passed": (
                    exact_claude.returncode == 0
                    and reader_error_state.get("read_error")
                    == "ValueError: stream read failed"
                    and reader_stop.is_set()
                    and raising_stream.closed
                    and reader_error_state.get("raw")
                    == b'{"status":"PASS","returncode":0}\n'
                    and exact_claude.stdout == expected_claude_stdout
                    and exact_claude.stderr == ""
                    and certifier.official_validator_status(
                        ansi_success,
                        "",
                        validator_id="claude_plugin_validate",
                    )[0]
                    is True
                    and certifier.json_validator_status({
                        "status": "PASS",
                        "returncode": 0,
                        "success": True,
                        "errors": 0,
                        "diagnostics": [],
                    })[0]
                    is True
                    and missing_strict.returncode != 0
                    and wrong_strict.returncode != 0
                    and "unexpected argv" in missing_strict.stderr
                    and "unexpected argv" in wrong_strict.stderr
                    and all(
                        certifier.official_validator_status(
                            ansi_success,
                            diagnostic,
                            validator_id="claude_plugin_validate",
                        )[0]
                        is False
                        for diagnostic in contextual_negative_diagnostics
                    )
                    and all(
                        certifier.official_validator_status(
                            ansi_success,
                            summary,
                            validator_id="claude_plugin_validate",
                        )[0]
                        is True
                        for summary in benign_zero_summaries
                    )
                    and all(
                        certifier.official_validator_status(
                            candidate,
                            "",
                            validator_id="claude_plugin_validate",
                        )[0]
                        is False
                        for candidate in noncanonical_claude_successes
                    )
                    and certifier.official_validator_status(
                        "[" * 20_000 + "0" + "]" * 20_000,
                        "",
                        validator_id="skills_ref_validate",
                    )[0]
                    is False
                    and certifier.official_validator_status(
                        '{"status":' + "9" * 10_000 + "}",
                        "",
                        validator_id="skills_ref_validate",
                    )[0]
                    is False
                    and certifier.official_validator_status(
                        '{"status":"PASS","returncode":0,"extra":1e999}',
                        "",
                        validator_id="skills_ref_validate",
                    )[0]
                    is False
                    and certifier.official_validator_status(
                        '{"status":"PASS","returncode":0,"extra":1e308}',
                        "",
                        validator_id="skills_ref_validate",
                    )[0]
                    is True
                    and all(
                        certifier.official_validator_status(
                            candidate,
                            "",
                            validator_id="skills_ref_validate",
                        )[0]
                        is False
                        for candidate in (
                            '{"status":"PASS","returncode":0}\n'
                            '{"status":"MAYBE","returncode":0}\n',
                            '{"status":"MAYBE","returncode":0}\n'
                            '{"status":"PASS","returncode":0}\n',
                            '{"status":"PASS","returncode":0}\n'
                            '{"result":"pending","returncode":0}\n',
                        )
                    )
                    and certifier.official_validator_status(
                        '{"status":"PASS","returncode":0,'
                        '"diagnostics":[{"diagnostics":['
                        '{"level":"error",'
                        '"message":"validation failed"}]}]}',
                        "",
                        validator_id="skills_ref_validate",
                    )[0]
                    is False
                    and certifier.official_validator_status(
                        '{"status":"PASS","returncode":0,'
                        '"diagnostics":[{"diagnostics":[]}]}',
                        "",
                        validator_id="skills_ref_validate",
                    )[0]
                    is True
                    and all(
                        certifier.official_validator_status(
                            candidate,
                            "",
                            validator_id="skills_ref_validate",
                        )[0]
                        is False
                        for candidate in (
                            '{"status":"PASS","returncode":0,'
                            '"is_error":true}',
                            '{"status":"PASS","returncode":0,'
                            '"exit_code":1}',
                            '{"status":"PASS","returncode":0,'
                            '"error_code":1}',
                            '{"status":"PASS","returncode":0,'
                            '"timed_out":true}',
                            '{"status":"PASS","returncode":0,'
                            '"completed":false}',
                        )
                    )
                    and certifier.official_validator_status(
                        '{"status":"PASS","returncode":0,'
                        '"is_error":false,"exit_code":0,'
                        '"error_code":0,"timed_out":false,'
                        '"completed":true,"failed":false}',
                        "",
                        validator_id="skills_ref_validate",
                    )[0]
                    is True
                ),
                "exact_returncode": exact_claude.returncode,
                "missing_strict_returncode": missing_strict.returncode,
                "wrong_strict_returncode": wrong_strict.returncode,
                "observed_stdout": exact_claude.stdout,
                "contextual_negative_diagnostics": (
                    contextual_negative_diagnostics
                ),
                "benign_zero_summaries": benign_zero_summaries,
                "reader_error_state": {
                    key: value
                    for key, value in reader_error_state.items()
                    if key != "raw"
                },
                "noncanonical_claude_successes": (
                    noncanonical_claude_successes
                ),
            })

            equal_content_bundle = root / "distinct_roles_equal_bytes"
            shutil.copytree(
                baseline_bundle,
                equal_content_bundle,
                symlinks=True,
            )
            equal_result_path = (
                equal_content_bundle
                / "formal_artifacts/artifact-001/formal_result.json"
            )
            equal_result = json.loads(
                equal_result_path.read_text(encoding="utf-8")
            )
            equal_result_dir = equal_result_path.parent
            report_path = (
                equal_result_dir
                / equal_result["companions"]["report"]["path"]
            )
            ledger_path = (
                equal_result_dir
                / equal_result["companions"]["ledger"]["path"]
            )
            report_path.write_bytes(ledger_path.read_bytes())
            equal_result["companions"]["report"].update({
                "sha256": (
                    f"sha256:{certifier.sha256_path(report_path)}"
                ),
                "bytes": report_path.stat().st_size,
            })
            write_json(equal_result_path, equal_result)
            equal_certificate_path = (
                equal_content_bundle / "promotion_certificate.json"
            )
            equal_certificate = json.loads(
                equal_certificate_path.read_text(encoding="utf-8")
            )
            refresh_node_hash(
                certifier,
                package_root,
                equal_content_bundle,
                equal_certificate,
                "formal.result",
            )
            write_json(equal_certificate_path, equal_certificate)
            (
                equal_content_rc,
                equal_content,
                equal_content_invocation,
            ) = certifier_cli(
                package_root,
                equal_content_bundle,
            )
            (
                equal_content_check_count,
                equal_content_check_sha256,
                _equal_content_check_names,
            ) = ordered_check_inventory(equal_content)
            (
                expected_equal_content_check_count,
                expected_equal_content_check_sha256,
            ) = EXPECTED_POSITIVE_MUTATION_CHECK_INVENTORIES[
                "distinct_formal_roles_may_contain_equal_bytes"
            ]
            equal_content_inventory_matches = (
                equal_content_check_count
                == expected_equal_content_check_count
                and equal_content_check_sha256
                == expected_equal_content_check_sha256
            )
            cases.append({
                "name": "distinct_formal_roles_may_contain_equal_bytes",
                "passed": (
                    equal_content_rc == 2
                    and equal_content.get("status") == certifier.PASS_SCOPED
                    and equal_content.get("modeled_promotion_checks_passed")
                    is True
                    and not failed_check_inventory(equal_content)
                    and equal_content_invocation.get("verified") is True
                    and equal_content_inventory_matches
                ),
                "execution_mode": "production-certifier-cli",
                "exit_code": equal_content_rc,
                "status": equal_content.get("status"),
                "cli_invocation_verified": (
                    equal_content_invocation.get("verified")
                ),
                "failed_checks": sorted(
                    failed_check_inventory(equal_content).elements()
                ),
                "observed_check_count": equal_content_check_count,
                "expected_check_count": (
                    expected_equal_content_check_count
                ),
                "observed_check_sha256": equal_content_check_sha256,
                "expected_check_sha256": (
                    expected_equal_content_check_sha256
                ),
                "check_inventory_matched": (
                    equal_content_inventory_matches
                ),
            })

            unavailable_bin = root / "official_tools_unavailable"
            unavailable_bin.mkdir()
            unavailable_env = dict(os.environ)
            unavailable_env["PATH"] = str(unavailable_bin)
            (
                scope_excluded_rc,
                scope_excluded,
                scope_excluded_invocation,
            ) = certifier_cli(
                package_root,
                baseline_bundle,
                allow_official_scope_exclusion=True,
                env=unavailable_env,
            )
            (
                scope_excluded_check_count,
                scope_excluded_check_sha256,
                _scope_excluded_check_names,
            ) = ordered_check_inventory(scope_excluded)
            (
                expected_scope_excluded_check_count,
                expected_scope_excluded_check_sha256,
            ) = EXPECTED_POSITIVE_MUTATION_CHECK_INVENTORIES[
                "official_scope_exclusion_retains_fixed_role_dag"
            ]
            scope_excluded_execution = (
                scope_excluded.get("execution_evidence", {})
                .get("official_validators")
            )
            scope_excluded_records_exact = (
                type(scope_excluded_execution) is dict
                and set(scope_excluded_execution)
                == set(EXPECTED_OFFICIAL_VALIDATORS)
                and all(
                    type(record) is dict
                    and record.get("available") is False
                    and record.get("scope_excluded") is True
                    for record in scope_excluded_execution.values()
                )
            )
            scope_excluded_inventory_matches = (
                scope_excluded_check_count
                == expected_scope_excluded_check_count
                and scope_excluded_check_sha256
                == expected_scope_excluded_check_sha256
            )
            cases.append({
                "name": "official_scope_exclusion_retains_fixed_role_dag",
                "passed": (
                    scope_excluded_rc == 2
                    and scope_excluded.get("status") == certifier.PASS_SCOPED
                    and scope_excluded.get("outcome") == "CAPPED"
                    and scope_excluded.get("modeled_promotion_checks_passed")
                    is True
                    and scope_excluded.get(
                        "official_validator_scope_exclusion_requested"
                    )
                    is True
                    and not failed_check_inventory(scope_excluded)
                    and scope_excluded_invocation.get("verified") is True
                    and scope_excluded_records_exact
                    and baseline_roles_and_dag_exact
                    and scope_excluded_inventory_matches
                ),
                "execution_mode": "production-certifier-cli",
                "exit_code": scope_excluded_rc,
                "status": scope_excluded.get("status"),
                "cli_invocation_verified": (
                    scope_excluded_invocation.get("verified")
                ),
                "official_execution_records_exact": (
                    scope_excluded_records_exact
                ),
                "promotion_roles_and_dag_exact": (
                    baseline_roles_and_dag_exact
                ),
                "observed_check_count": scope_excluded_check_count,
                "expected_check_count": (
                    expected_scope_excluded_check_count
                ),
                "observed_check_sha256": scope_excluded_check_sha256,
                "expected_check_sha256": (
                    expected_scope_excluded_check_sha256
                ),
                "check_inventory_matched": (
                    scope_excluded_inventory_matches
                ),
            })

            downstream_bundle = root / "independent_downstream_claim"
            shutil.copytree(
                baseline_bundle,
                downstream_bundle,
                symlinks=True,
            )
            downstream_certificate_path = (
                downstream_bundle / "promotion_certificate.json"
            )
            downstream_certificate = json.loads(
                downstream_certificate_path.read_text(encoding="utf-8")
            )
            downstream_certificate["claims"].append(
                write_passing_promotion_claim(
                    certifier,
                    gate,
                    downstream_bundle,
                    "C-INDEPENDENT",
                    "independent",
                )
            )
            independently_tested_text = (
                "Independent promotion claim C-INDEPENDENT is tracked."
            )
            downstream_certificate["derived_or_downstream_claims"] = [{
                "id": "D-INDEPENDENT",
                "from_claim_ids": ["C-UPSTREAM"],
                "derived_claim": independently_tested_text,
                "status": certifier.PASS_TRACKED,
                "own_claim_id": "C-INDEPENDENT",
                "proposition_binding": {
                    "schema_version": "1.0",
                    "canonical_text_sha256": (
                        "sha256:"
                        + gate._proposition_sha256(  # pylint: disable=protected-access
                            independently_tested_text
                        )
                    ),
                },
            }]
            downstream_certificate["downstream_review"] = {
                "performed": True,
                "claims_identified": ["D-INDEPENDENT"],
            }
            downstream_assurance = gate._certificate_assurance_payload(  # pylint: disable=protected-access
                downstream_certificate,
                gate._resolve_downstream_policy("promotion-v2"),  # pylint: disable=protected-access
            )
            downstream_certificate["claims"] = [
                write_passing_promotion_claim(
                    certifier,
                    gate,
                    downstream_bundle,
                    "C-UPSTREAM",
                    "upstream",
                    certificate_assurance=downstream_assurance,
                ),
                write_passing_promotion_claim(
                    certifier,
                    gate,
                    downstream_bundle,
                    "C-INDEPENDENT",
                    "independent",
                    certificate_assurance=downstream_assurance,
                ),
            ]
            downstream_method_m, downstream_method_error = (
                certifier.expected_promotion_method_m(
                    package_root,
                    downstream_bundle,
                    downstream_certificate,
                )
            )
            if (
                downstream_method_error is not None
                or not isinstance(downstream_method_m, dict)
            ):
                raise RuntimeError(
                    "downstream promotion method M could not be rebound: "
                    f"{downstream_method_error}"
                )
            downstream_certificate["method_m_upgrade"] = downstream_method_m
            downstream_certificate["live_result_bindings"] = (
                downstream_method_m["live"]
            )
            write_json(downstream_certificate_path, downstream_certificate)
            (
                downstream_rc,
                downstream_outcome,
                downstream_invocation,
            ) = certifier_cli(package_root, downstream_bundle)
            (
                downstream_check_count,
                downstream_check_sha256,
                _downstream_check_names,
            ) = ordered_check_inventory(downstream_outcome)
            (
                expected_downstream_check_count,
                expected_downstream_check_sha256,
            ) = EXPECTED_POSITIVE_MUTATION_CHECK_INVENTORIES[
                "independently_passing_downstream_claim_accepted_before_cap"
            ]
            downstream_inventory_matches = (
                downstream_check_count == expected_downstream_check_count
                and downstream_check_sha256
                == expected_downstream_check_sha256
            )
            downstream_checks = {
                check.get("name"): check
                for check in downstream_outcome.get("checks", [])
                if isinstance(check, Mapping)
            }
            canonical_claim_check = downstream_checks.get(
                "promotion claims pass canonical strict gate evaluation",
                {},
            )
            nonclosure_check = downstream_checks.get(
                "promotion v2 downstream review prevents automatic closure",
                {},
            )
            cases.append({
                "name": (
                    "independently_passing_downstream_claim_accepted_before_cap"
                ),
                "passed": (
                    downstream_rc == 2
                    and downstream_outcome.get("status")
                    == certifier.PASS_SCOPED
                    and downstream_outcome.get("outcome") == "CAPPED"
                    and downstream_outcome.get(
                        "modeled_promotion_checks_passed"
                    )
                    is True
                    and downstream_outcome.get("promotion_authorized") is False
                    and canonical_claim_check.get("passed") is True
                    and canonical_claim_check.get("details", {}).get(
                        "claim_statuses"
                    )
                    == {
                        "C-INDEPENDENT": "PASS",
                        "C-UPSTREAM": "PASS",
                    }
                    and nonclosure_check.get("passed") is True
                    and nonclosure_check.get("details")
                    == {"records": 1, "reasons": []}
                    and not failed_check_inventory(downstream_outcome)
                    and downstream_invocation.get("verified") is True
                    and downstream_inventory_matches
                ),
                "execution_mode": "production-certifier-cli",
                "exit_code": downstream_rc,
                "status": downstream_outcome.get("status"),
                "cli_invocation_verified": downstream_invocation.get(
                    "verified"
                ),
                "canonical_claim_details": canonical_claim_check.get(
                    "details"
                ),
                "downstream_details": nonclosure_check.get("details"),
                "observed_check_count": downstream_check_count,
                "expected_check_count": expected_downstream_check_count,
                "observed_check_sha256": downstream_check_sha256,
                "expected_check_sha256": expected_downstream_check_sha256,
                "check_inventory_matched": downstream_inventory_matches,
            })

            def run_mutation(
                name: str,
                mutate: Callable[[Path], None],
                expected_failure_kind: str,
                expected_failures: Sequence[Tuple[str, str, str]],
                *,
                expected_omitted_lane: Optional[str] = None,
                expected_recorded_details: Optional[
                    Mapping[Tuple[str, str], Any]
                ] = None,
                outcome_oracle: Optional[
                    Callable[[Mapping[str, Any]], bool]
                ] = None,
                env_updates: Optional[Mapping[str, str]] = None,
            ) -> None:
                mutation_bundle = root / name
                shutil.copytree(
                    baseline_bundle,
                    mutation_bundle,
                    symlinks=True,
                )
                mutate(mutation_bundle)
                case_started = time.monotonic()
                invocation_env = None
                if env_updates is not None:
                    invocation_env = dict(os.environ)
                    invocation_env.update(env_updates)
                outcome_rc, outcome, invocation = certifier_cli(
                    package_root,
                    mutation_bundle,
                    env=invocation_env,
                )
                duration_sec = round(time.monotonic() - case_started, 3)
                failed_checks_valid = True
                try:
                    actual_failures = failed_check_inventory(outcome)
                    records_by_failure = failed_check_records(outcome)
                except ValueError:
                    failed_checks_valid = False
                    actual_failures = Counter()
                    records_by_failure = {}
                expected_inventory = Counter(
                    (check_name, failure_kind)
                    for check_name, failure_kind, _details_token
                    in expected_failures
                )
                detail_matches: Dict[str, bool] = {}
                recorded_detail_matches: Dict[str, bool] = {}
                detail_expectations_valid = bool(expected_failures)
                recorded_expectations = dict(
                    expected_recorded_details or {}
                )
                expected_failure_keys = {
                    (check_name, failure_kind)
                    for check_name, failure_kind, _details_token
                    in expected_failures
                }
                recorded_expectations_valid = (
                    set(recorded_expectations).issubset(
                        expected_failure_keys
                    )
                )
                for check_name, failure_kind, details_token in expected_failures:
                    key = (check_name, failure_kind)
                    records = records_by_failure.get(key, [])
                    token_valid = (
                        type(details_token) is str
                        and bool(details_token.strip())
                    )
                    detail_matches[
                        f"{check_name} [{failure_kind}]"
                    ] = (
                        token_valid
                        and len(records) == 1
                        and details_token
                        in json.dumps(
                            records[0].get("details"),
                            sort_keys=True,
                        )
                    )
                    detail_expectations_valid = (
                        detail_expectations_valid and token_valid
                    )
                    if key in recorded_expectations:
                        details = (
                            records[0].get("details")
                            if len(records) == 1
                            else None
                        )
                        recorded_detail_matches[
                            f"{check_name} [{failure_kind}]"
                        ] = (
                            isinstance(details, Mapping)
                            and details.get("recorded")
                            == recorded_expectations[key]
                        )
                details_match = (
                    detail_expectations_valid
                    and all(detail_matches.values())
                    and recorded_expectations_valid
                    and all(recorded_detail_matches.values())
                )
                inventory_valid = True
                try:
                    (
                        observed_check_count,
                        observed_check_sha256,
                        observed_check_names,
                    ) = ordered_check_inventory(outcome)
                except ValueError:
                    inventory_valid = False
                    observed_check_count = 0
                    observed_check_sha256 = ""
                    observed_check_names = ()
                expected_check_count, expected_check_sha256 = (
                    EXPECTED_MUTATION_CHECK_INVENTORIES[name]
                )
                inventory_matches = (
                    inventory_valid
                    and observed_check_count == expected_check_count
                    and observed_check_sha256 == expected_check_sha256
                )
                omitted_lane_matches = True
                omitted_lane_present_checks: List[str] = []
                if expected_omitted_lane is not None:
                    omitted_lane_names = set(
                        expected_baseline_lanes()[expected_omitted_lane]
                    )
                    omitted_lane_present_checks = sorted(
                        omitted_lane_names.intersection(
                            observed_check_names
                        )
                    )
                    omitted_lane_matches = not omitted_lane_present_checks
                outcome_oracle_matched = (
                    outcome_oracle(outcome)
                    if outcome_oracle is not None
                    else True
                )
                cases.append({
                    "name": name,
                    "passed": (
                        outcome_rc == 2
                        and outcome.get("status") == "FAIL"
                        and outcome.get("outcome") == "FAILED"
                        and outcome.get("failure_kind")
                        == expected_failure_kind
                        and outcome.get("promotion_authorized") is False
                        and "satisfied_profile" not in outcome
                        and failed_checks_valid
                        and actual_failures == expected_inventory
                        and details_match
                        and inventory_matches
                        and omitted_lane_matches
                        and outcome_oracle_matched
                        and invocation.get("verified") is True
                    ),
                    "execution_mode": "production-certifier-cli",
                    "exit_code": outcome_rc,
                    "duration_sec": duration_sec,
                    "status": outcome.get("status"),
                    "failure_kind": outcome.get("failure_kind"),
                    "failed_checks": sorted(actual_failures.elements()),
                    "expected_failed_checks": sorted(
                        expected_inventory.elements()
                    ),
                    "failed_checks_shape_valid": failed_checks_valid,
                    "detail_matches": detail_matches,
                    "recorded_detail_matches": (
                        recorded_detail_matches
                    ),
                    "details_matched": details_match,
                    "observed_check_count": observed_check_count,
                    "expected_check_count": expected_check_count,
                    "observed_check_sha256": observed_check_sha256,
                    "expected_check_sha256": expected_check_sha256,
                    "check_inventory_matched": inventory_matches,
                    "expected_omitted_lane": expected_omitted_lane,
                    "omitted_lane_present_checks": (
                        omitted_lane_present_checks
                    ),
                    "omitted_lane_matched": omitted_lane_matches,
                    "outcome_oracle_matched": outcome_oracle_matched,
                    "cli_invocation_verified": invocation.get("verified"),
                })

            def update_certificate(
                bundle: Path,
                mutate: Callable[[Dict[str, Any]], None],
            ) -> None:
                path = bundle / "promotion_certificate.json"
                certificate = json.loads(path.read_text(encoding="utf-8"))
                mutate(certificate)
                write_json(path, certificate)

            run_mutation(
                "missing_promotion_schema_version",
                lambda bundle: update_certificate(
                    bundle,
                    lambda certificate: certificate.pop(
                        "promotion_schema_version"
                    ),
                ),
                "INVALID_INPUT",
                [(
                    "promotion certificate schema version is exact string 2.0",
                    "INVALID_INPUT",
                    "\"recorded_type\": \"NoneType\"",
                )],
            )

            run_mutation(
                "wrong_type_promotion_schema_version",
                lambda bundle: update_certificate(
                    bundle,
                    lambda certificate: certificate.update({
                        "promotion_schema_version": 2.0,
                    }),
                ),
                "INVALID_INPUT",
                [(
                    "promotion certificate schema version is exact string 2.0",
                    "INVALID_INPUT",
                    "\"recorded_type\": \"float\"",
                )],
            )

            def stale_deterministic(bundle: Path) -> None:
                path = (
                    bundle
                    / certifier.DETERMINISTIC_FILES["package_validation"]
                )
                capture = json.loads(path.read_text(encoding="utf-8"))
                capture["package_tree_identity"]["sha256"] = (
                    "sha256:" + "0" * 64
                )
                write_json(path, capture)
                update_certificate(
                    bundle,
                    lambda certificate: refresh_node_hash(
                        certifier,
                        package_root,
                        bundle,
                        certificate,
                        "deterministic.package_validation",
                    ),
                )

            run_mutation(
                "stale_deterministic_capture_wrong_tree",
                stale_deterministic,
                "INVALID_INPUT",
                [
                    ((
                        "deterministic capture v2 metadata valid: "
                        "package_validation"
                    ), "INVALID_INPUT", "package_tree_identity"),
                ],
            )

            def fabricated_official(bundle: Path) -> None:
                spec = certifier.PROMOTION_EVIDENCE_SPECS[
                    "official.claude_plugin_validate"
                ]
                (bundle / spec["path"]).write_text(
                    "Valid\n",
                    encoding="utf-8",
                )
                update_certificate(
                    bundle,
                    lambda certificate: refresh_node_hash(
                        certifier,
                        package_root,
                        bundle,
                        certificate,
                        "official.claude_plugin_validate",
                    ),
                )

            run_mutation(
                "fabricated_official_text_policy",
                fabricated_official,
                "INVALID_INPUT",
                [
                    ((
                        "official validator policy declares required id: "
                        "claude_plugin_validate"
                    ), "INVALID_INPUT", "JSONDecodeError"),
                ],
            )

            def decoy_formal(bundle: Path) -> None:
                (
                    bundle
                    / "formal_artifacts/artifact-001/"
                    "decoy_NOZICKIAN_REPORT.md"
                ).write_text("decoy\n", encoding="utf-8")

            run_mutation(
                "decoy_formal_companion",
                decoy_formal,
                "INVALID_INPUT",
                [
                    ((
                        "formal result directory has no undeclared reserved "
                        "companions"
                    ), "INVALID_INPUT", "decoy_NOZICKIAN_REPORT.md"),
                ],
            )

            def swapped_formal(bundle: Path) -> None:
                path = (
                    bundle
                    / "formal_artifacts/artifact-001/formal_result.json"
                )
                result = json.loads(path.read_text(encoding="utf-8"))
                first = result["companions"]["report"]
                second = result["companions"]["certificate"]
                result["companions"]["report"] = second
                result["companions"]["certificate"] = first
                write_json(path, result)
                update_certificate(
                    bundle,
                    lambda certificate: refresh_node_hash(
                        certifier,
                        package_root,
                        bundle,
                        certificate,
                        "formal.result",
                    ),
                )

            run_mutation(
                "swapped_formal_companions",
                swapped_formal,
                "INVALID_INPUT",
                [
                    (
                        "formal companion path is canonical for role: "
                        "certificate",
                        "INVALID_INPUT",
                        "synthetic-target_NOZICKIAN_REPORT.md",
                    ),
                    (
                        "formal companion path is canonical for role: report",
                        "INVALID_INPUT",
                        "synthetic-target_NOZICKIAN_certificate.json",
                    ),
                    (
                        "formal generated certificate strict gate "
                        "PASS-TRACKED",
                        "CHECK_FAILED",
                        "INVALID_INPUT",
                    ),
                    (
                        "formal output checks recompute exactly from declared "
                        "companions",
                        "CHECK_FAILED",
                        '"recomputed"',
                    ),
                    ((
                        "formal result directory has no undeclared reserved "
                        "companions"
                    ), "INVALID_INPUT", "synthetic-target_NOZICKIAN_certificate.json"),
                    (
                        "formal strict-gate argv binds declared certificate "
                        "and gate companions",
                        "CHECK_FAILED",
                        '"command_certificate"',
                    ),
                ],
                expected_recorded_details={
                    (
                        "formal companion path is canonical for role: "
                        "certificate",
                        "INVALID_INPUT",
                    ): "synthetic-target_NOZICKIAN_REPORT.md",
                    (
                        "formal companion path is canonical for role: report",
                        "INVALID_INPUT",
                    ): "synthetic-target_NOZICKIAN_certificate.json",
                },
            )

            def mutate_formal_result(
                bundle: Path,
                mutate: Callable[[Dict[str, Any]], None],
            ) -> None:
                result_path = (
                    bundle
                    / "formal_artifacts/artifact-001/formal_result.json"
                )
                result = json.loads(
                    result_path.read_text(encoding="utf-8")
                )
                mutate(result)
                write_json(result_path, result)
                update_certificate(
                    bundle,
                    lambda certificate: refresh_node_hash(
                        certifier,
                        package_root,
                        bundle,
                        certificate,
                        "formal.result",
                    ),
                )

            def substitute_formal_coordinator_result(bundle: Path) -> None:
                mutate_formal_result(
                    bundle,
                    lambda result: result.__setitem__(
                        "formal_coordinator",
                        "attacker-result-coordinator",
                    ),
                )

            run_mutation(
                "formal_coordinator_result_identity_binding",
                substitute_formal_coordinator_result,
                "INVALID_INPUT",
                [(
                    "formal result projected fields have exact JSON types",
                    "INVALID_INPUT",
                    "attacker-result-coordinator",
                )],
            )

            def substitute_formal_coordinator_argv(bundle: Path) -> None:
                mutate_formal_result(
                    bundle,
                    lambda result: result["commands"][1]["argv"].__setitem__(
                        4,
                        "attacker-argv-coordinator",
                    ),
                )

            run_mutation(
                "formal_coordinator_argv_identity_binding",
                substitute_formal_coordinator_argv,
                "INVALID_INPUT",
                [(
                    "formal result projected fields have exact JSON types",
                    "INVALID_INPUT",
                    "attacker-argv-coordinator",
                )],
            )

            def substitute_formal_prompt(bundle: Path) -> None:
                mutate_formal_result(
                    bundle,
                    lambda result: result["commands"][1]["argv"].__setitem__(
                        -1,
                        "sha256:" + "d" * 64,
                    ),
                )

            run_mutation(
                "formal_prompt_companion_binding",
                substitute_formal_prompt,
                "CHECK_FAILED",
                [(
                    "formal coordinator prompt digest matches declared "
                    "prompt companion",
                    "CHECK_FAILED",
                    "sha256:dddddddd",
                )],
            )

            def mismatch_formal_transcript_command(bundle: Path) -> None:
                def mutate(result: Dict[str, Any]) -> None:
                    result["commands"][1]["stdout_sha256"] = (
                        "sha256:" + "e" * 64
                    )

                mutate_formal_result(bundle, mutate)

            run_mutation(
                "formal_transcript_command_binding",
                mismatch_formal_transcript_command,
                "CHECK_FAILED",
                [(
                    "formal coordinator stdout matches complete transcript "
                    "companion",
                    "CHECK_FAILED",
                    "sha256:eeeeeeee",
                )],
            )

            def mismatch_formal_gate_companions(bundle: Path) -> None:
                def mutate(result: Dict[str, Any]) -> None:
                    gate_argv = result["commands"][2]["argv"]
                    gate_argv[2] = (
                        "<output-dir>/attacker_NOZICKIAN_certificate.json"
                    )
                    gate_argv[7] = (
                        "<output-dir>/attacker_NOZICKIAN_GATE.md"
                    )

                mutate_formal_result(bundle, mutate)

            run_mutation(
                "formal_gate_companion_argv_binding",
                mismatch_formal_gate_companions,
                "CHECK_FAILED",
                [(
                    "formal strict-gate argv binds declared certificate and "
                    "gate companions",
                    "CHECK_FAILED",
                    "attacker_NOZICKIAN_certificate.json",
                )],
            )

            def replace_formal_output_checks(bundle: Path) -> None:
                mutate_formal_result(
                    bundle,
                    lambda result: result.__setitem__(
                        "output_checks",
                        [{
                            "name": "attacker self-attested pass",
                            "passed": True,
                        }],
                    ),
                )

            run_mutation(
                "formal_arbitrary_output_check_rejected",
                replace_formal_output_checks,
                "CHECK_FAILED",
                [(
                    "formal output checks recompute exactly from declared "
                    "companions",
                    "CHECK_FAILED",
                    "attacker self-attested pass",
                )],
            )

            def empty_formal_report(bundle: Path) -> None:
                def mutate(result: Dict[str, Any]) -> None:
                    report_record = result["companions"]["report"]
                    report_path = (
                        bundle
                        / "formal_artifacts/artifact-001"
                        / report_record["path"]
                    )
                    report_path.write_bytes(b"")
                    report_record.update({
                        "sha256": (
                            "sha256:"
                            + hashlib.sha256(b"").hexdigest()
                        ),
                        "bytes": 0,
                        "present": True,
                    })

                mutate_formal_result(bundle, mutate)

            run_mutation(
                "formal_empty_report_rejected",
                empty_formal_report,
                "CHECK_FAILED",
                [(
                    "formal output checks recompute exactly from declared "
                    "companions",
                    "CHECK_FAILED",
                    "output exists: report",
                )],
            )

            def dummy_evidence(bundle: Path) -> None:
                def mutate(certificate: Dict[str, Any]) -> None:
                    certificate["evidence"]["nodes"]["formal.result"] = (
                        "dummy-untyped-evidence"
                    )
                update_certificate(bundle, mutate)

            run_mutation(
                "dummy_untyped_evidence",
                dummy_evidence,
                "INVALID_INPUT",
                [
                    (
                        "promotion certificate required top-level fields "
                        "have exact JSON types",
                        "INVALID_INPUT",
                        "promotion evidence node is malformed: formal.result",
                    ),
                    (
                        "promotion evidence node is typed: formal.result",
                        "INVALID_INPUT",
                        "node is not an object",
                    ),
                ],
                expected_omitted_lane="formal",
            )

            def fake_own_claim(bundle: Path) -> None:
                def mutate(certificate: Dict[str, Any]) -> None:
                    certificate["derived_or_downstream_claims"] = [{
                        "id": "D-FAKE",
                        "from_claim_ids": ["C-UPSTREAM"],
                        "derived_claim": "A fake downstream pass.",
                        "status": certifier.PASS_TRACKED,
                        "own_claim_id": "C-FAKE",
                        "reason": "Fabricated independent identifier.",
                    }]
                    certificate["downstream_review"] = {
                        "performed": True,
                        "claims_identified": ["D-FAKE"],
                    }
                    fake_assurance = gate._certificate_assurance_payload(  # pylint: disable=protected-access
                        certificate,
                        gate._resolve_downstream_policy(  # pylint: disable=protected-access
                            "promotion-v2"
                        ),
                    )
                    certificate["claims"] = [
                        write_passing_promotion_claim(
                            certifier,
                            gate,
                            bundle,
                            "C-UPSTREAM",
                            "upstream",
                            certificate_assurance=fake_assurance,
                        )
                    ]
                update_certificate(bundle, mutate)

            run_mutation(
                "fake_own_claim_id",
                fake_own_claim,
                "INVALID_INPUT",
                [
                    ((
                        "promotion v2 downstream review prevents automatic "
                        "closure"
                    ), "INVALID_INPUT", "cites missing independent claim C-FAKE"),
                ],
            )

            run_mutation(
                "malformed_claim_nonobject",
                lambda bundle: update_certificate(
                    bundle,
                    lambda certificate: certificate.update({"claims": [7]}),
                ),
                "INVALID_INPUT",
                [(
                    (
                        "promotion claims have required exact types and "
                        "unique canonical ids"
                    ),
                    "INVALID_INPUT",
                    "claims[0] is not an object (number)",
                )],
            )

            run_mutation(
                "malformed_claim_null_entry",
                lambda bundle: update_certificate(
                    bundle,
                    lambda certificate: certificate.update(
                        {"claims": [None]}
                    ),
                ),
                "INVALID_INPUT",
                [(
                    (
                        "promotion claims have required exact types and "
                        "unique canonical ids"
                    ),
                    "INVALID_INPUT",
                    "claims[0] is not an object (null)",
                )],
            )

            run_mutation(
                "malformed_claims_null",
                lambda bundle: update_certificate(
                    bundle,
                    lambda certificate: certificate.update({"claims": None}),
                ),
                "INVALID_INPUT",
                [
                    (
                        "promotion certificate required top-level fields "
                        "have exact JSON types",
                        "INVALID_INPUT",
                        '"claims"',
                    ),
                    (
                        "promotion claims have required exact types and "
                        "unique canonical ids",
                        "INVALID_INPUT",
                        "claims is not an array",
                    ),
                ],
            )

            run_mutation(
                "empty_promotion_claims_rejected",
                lambda bundle: update_certificate(
                    bundle,
                    lambda certificate: certificate.update({"claims": []}),
                ),
                "INVALID_INPUT",
                [(
                    (
                        "promotion claims have required exact types and "
                        "unique canonical ids"
                    ),
                    "INVALID_INPUT",
                    "claims must contain at least one promotion claim",
                )],
            )

            run_mutation(
                "malformed_claim_bool_id",
                lambda bundle: update_certificate(
                    bundle,
                    lambda certificate: certificate["claims"][0].update(
                        {"id": True}
                    ),
                ),
                "INVALID_INPUT",
                [(
                    (
                        "promotion claims have required exact types and "
                        "unique canonical ids"
                    ),
                    "INVALID_INPUT",
                    "id is not a canonical claim identifier",
                )],
            )

            def duplicate_claim_id(bundle: Path) -> None:
                def mutate(certificate: Dict[str, Any]) -> None:
                    certificate["claims"].append(
                        json.loads(json.dumps(certificate["claims"][0]))
                    )
                update_certificate(bundle, mutate)

            run_mutation(
                "malformed_claim_duplicate_id",
                duplicate_claim_id,
                "INVALID_INPUT",
                [(
                    (
                        "promotion claims have required exact types and "
                        "unique canonical ids"
                    ),
                    "INVALID_INPUT",
                    "duplicate promotion claim id: C-UPSTREAM",
                )],
            )

            run_mutation(
                "malformed_claim_invalid_id",
                lambda bundle: update_certificate(
                    bundle,
                    lambda certificate: certificate["claims"][0].update(
                        {"id": "invalid claim id"}
                    ),
                ),
                "INVALID_INPUT",
                [(
                    (
                        "promotion claims have required exact types and "
                        "unique canonical ids"
                    ),
                    "INVALID_INPUT",
                    "id is not a canonical claim identifier",
                )],
            )

            run_mutation(
                "malformed_scalar",
                lambda bundle: update_certificate(
                    bundle,
                    lambda certificate: certificate["evidence"].update({
                        "schema_version": 7
                    }),
                ),
                "INVALID_INPUT",
                [(
                    "promotion evidence schema is v2",
                    "INVALID_INPUT",
                    "7",
                )],
            )

            def preserve_bound_claude(_bundle: Path) -> None:
                pass

            run_mutation(
                "official_stderr_contradiction_dominates_stdout",
                preserve_bound_claude,
                "CHECK_FAILED",
                [
                    ((
                        "fresh official validator passes: "
                        "claude_plugin_validate"
                    ), "CHECK_FAILED", "anchored negative status"),
                ],
                env_updates={
                    "NTT_CONTRACT_CLAUDE_OUTPUT_MODE": (
                        "stderr-text-failure"
                    ),
                },
            )

            run_mutation(
                "official_structured_stderr_failure_dominates_stdout",
                preserve_bound_claude,
                "CHECK_FAILED",
                [((
                    "fresh official validator passes: "
                    "claude_plugin_validate"
                ), "CHECK_FAILED",
                    "stderr contradiction: explicit negative JSON status",
                )],
                env_updates={
                    "NTT_CONTRACT_CLAUDE_OUTPUT_MODE": (
                        "stderr-json-failure"
                    ),
                },
            )

            run_mutation(
                "official_mixed_jsonl_stderr_failure_dominates_stdout",
                preserve_bound_claude,
                "CHECK_FAILED",
                [((
                    "fresh official validator passes: "
                    "claude_plugin_validate"
                ), "CHECK_FAILED",
                    "stderr contradiction: line 2 explicit negative "
                    "JSON status",
                )],
                env_updates={
                    "NTT_CONTRACT_CLAUDE_OUTPUT_MODE": (
                        "stderr-jsonl-failure"
                    ),
                },
            )

            large_failure_payload = (
                "Validation failed: synthetic early failure\n"
                + ("neutral validator progress\n" * 2200)
            )

            large_failure_bytes = large_failure_payload.encode("utf-8")
            large_failure_sha256 = (
                "sha256:" + hashlib.sha256(large_failure_bytes).hexdigest()
            )

            def large_failure_oracle(outcome: Mapping[str, Any]) -> bool:
                record = (
                    outcome.get("execution_evidence", {})
                    .get("official_validators", {})
                    .get("claude_plugin_validate", {})
                )
                return (
                    isinstance(record, Mapping)
                    and len(large_failure_bytes) > 50000
                    and record.get("stdout_bytes")
                    == len(large_failure_bytes)
                    and record.get("stdout_sha256")
                    == large_failure_sha256
                    and record.get("stdout_truncated") is True
                    and record.get("capture_limit_exceeded") is False
                    and record.get("argv")
                    == [
                        "<claude-cli>",
                        "plugin",
                        "validate",
                        "<package-root>",
                        "--strict",
                    ]
                )

            run_mutation(
                "official_early_failure_survives_large_neutral_tail",
                preserve_bound_claude,
                "CHECK_FAILED",
                [((
                    "fresh official validator passes: "
                    "claude_plugin_validate"
                ), "CHECK_FAILED",
                    "stdout contradiction: line 1 contains an anchored "
                    "negative status",
                )],
                outcome_oracle=large_failure_oracle,
                env_updates={
                    "NTT_CONTRACT_CLAUDE_OUTPUT_MODE": (
                        "early-failure-large-tail"
                    ),
                },
            )

            def bool_int_package_identity(bundle: Path) -> None:
                result_path = (
                    bundle
                    / "formal_artifacts/artifact-001/formal_result.json"
                )
                result = json.loads(
                    result_path.read_text(encoding="utf-8")
                )
                result["package_tree_identity"]["valid"] = 1
                write_json(result_path, result)
                update_certificate(
                    bundle,
                    lambda certificate: refresh_node_hash(
                        certifier,
                        package_root,
                        bundle,
                        certificate,
                        "formal.result",
                    ),
                )

            run_mutation(
                "formal_package_identity_bool_int_alias",
                bool_int_package_identity,
                "INVALID_INPUT",
                [
                    ((
                        "formal result package-tree identity has exact JSON "
                        "schema"
                    ), "INVALID_INPUT", "\"valid\": 1"),
                    ((
                        "formal result package-tree identity matches current "
                        "package"
                    ), "CHECK_FAILED", "\"valid\": 1"),
                ],
            )

            def bool_int_trace_authentication(bundle: Path) -> None:
                result_path = (
                    bundle
                    / "formal_artifacts/artifact-001/formal_result.json"
                )
                result = json.loads(
                    result_path.read_text(encoding="utf-8")
                )
                result["trace_authentication"]["authenticated"] = 1
                write_json(result_path, result)
                update_certificate(
                    bundle,
                    lambda certificate: refresh_node_hash(
                        certifier,
                        package_root,
                        bundle,
                        certificate,
                        "formal.result",
                    ),
                )

            run_mutation(
                "formal_trace_authenticated_bool_int_alias",
                bool_int_trace_authentication,
                "INVALID_INPUT",
                [
                    (
                        "formal trace authentication has exact JSON schema",
                        "INVALID_INPUT",
                        "\"authenticated_type\": \"int\"",
                    ),
                    (
                        "formal transcript re-authenticates and matches "
                        "recorded semantics",
                        "CHECK_FAILED",
                        "\"recorded_authenticated\": 1",
                    ),
                ],
            )

            def transcript_without_authentic_native_events(
                bundle: Path,
            ) -> None:
                result_path = (
                    bundle
                    / "formal_artifacts/artifact-001/formal_result.json"
                )
                result = json.loads(
                    result_path.read_text(encoding="utf-8")
                )
                transcript_record = result["companions"]["transcript"]
                transcript_path = (
                    result_path.parent / transcript_record["path"]
                )
                transcript_bytes = (
                    json.dumps({
                        "type": "assistant",
                        "message": {
                            "content": [{
                                "type": "text",
                                "text": (
                                    "Synthetic prose only; no native tool "
                                    "events were emitted."
                                ),
                            }],
                        },
                    }, sort_keys=True)
                    + "\n"
                ).encode("utf-8")
                transcript_path.write_bytes(transcript_bytes)
                transcript_record.update({
                    "sha256": (
                        "sha256:"
                        + hashlib.sha256(transcript_bytes).hexdigest()
                    ),
                    "bytes": len(transcript_bytes),
                    "present": True,
                })
                write_json(result_path, result)
                update_certificate(
                    bundle,
                    lambda certificate: refresh_node_hash(
                        certifier,
                        package_root,
                        bundle,
                        certificate,
                        "formal.result",
                    ),
                )

            run_mutation(
                "formal_transcript_without_authentic_native_events",
                transcript_without_authentic_native_events,
                "CHECK_FAILED",
                [
                    (
                        "formal coordinator stdout matches complete transcript "
                        "companion",
                        "CHECK_FAILED",
                        '"companion_transcript_sha256"',
                    ),
                    (
                        "formal transcript re-authenticates and matches "
                        "recorded semantics",
                        "CHECK_FAILED",
                        "\"parsed_authenticated\": false",
                    ),
                ],
            )

            def missing_trace_authentication(bundle: Path) -> None:
                result_path = (
                    bundle
                    / "formal_artifacts/artifact-001/formal_result.json"
                )
                result = json.loads(
                    result_path.read_text(encoding="utf-8")
                )
                result.pop("trace_authentication")
                write_json(result_path, result)
                update_certificate(
                    bundle,
                    lambda certificate: refresh_node_hash(
                        certifier,
                        package_root,
                        bundle,
                        certificate,
                        "formal.result",
                    ),
                )

            run_mutation(
                "formal_trace_authentication_missing",
                missing_trace_authentication,
                "INVALID_INPUT",
                [
                    (
                        "promotion certificate required top-level fields "
                        "have exact JSON types",
                        "INVALID_INPUT",
                        "formal method inputs have invalid JSON shapes",
                    ),
                    ((
                        "formal result projected fields have exact JSON types"
                    ), "INVALID_INPUT",
                        "\"trace_authentication_present\": false"),
                    (
                        "formal trace authentication has exact JSON schema",
                        "INVALID_INPUT",
                        "\"authenticated_type\": null",
                    ),
                    (
                        "formal transcript re-authenticates and matches "
                        "recorded semantics",
                        "CHECK_FAILED",
                        "\"recorded_authenticated\": null",
                    ),
                ],
            )

            def noncanonical_path(bundle: Path) -> None:
                update_certificate(
                    bundle,
                    lambda certificate: certificate["evidence"]["nodes"][
                        "live.runtime"
                    ].update({
                        "path": "./live_fixtures/"
                        "live_runtime_eval_result.json"
                    }),
                )

            run_mutation(
                "noncanonical_promotion_evidence_path",
                noncanonical_path,
                "INVALID_INPUT",
                [
                    (
                        "promotion certificate required top-level fields "
                        "have exact JSON types",
                        "INVALID_INPUT",
                        "promotion evidence path is invalid: live.runtime",
                    ),
                    ((
                        "promotion evidence role resolves to bundle-local "
                        "regular file: live.runtime"
                    ), "INVALID_INPUT", "path is empty, dotted, or traverses"),
                ],
            )

            def oversized_graph(bundle: Path) -> None:
                def mutate(certificate: Dict[str, Any]) -> None:
                    nodes = certificate["evidence"]["nodes"]
                    for index in range(certifier.MAX_EVIDENCE_NODES + 1):
                        nodes[f"attacker.{index}"] = {
                            "path": "promotion_certificate.json",
                            "sha256": "sha256:" + "0" * 64,
                            "depends_on": [],
                        }
                update_certificate(bundle, mutate)

            run_mutation(
                "oversized_evidence_graph_is_bounded",
                oversized_graph,
                "INVALID_INPUT",
                [
                    (
                        "promotion certificate required top-level fields "
                        "have exact JSON types",
                        "INVALID_INPUT",
                        "promotion evidence roles are incomplete",
                    ),
                    (
                        "promotion evidence node count is bounded",
                        "INVALID_INPUT",
                        "\"maximum\"",
                    ),
                ],
            )
            external_sentinel = root / "external-json-sentinel.txt"
            sentinel_bytes = b"external certifier sentinel must remain intact\n"
            external_sentinel.write_bytes(sentinel_bytes)
            unsafe_json = root / "unsafe-certifier-result.json"
            unsafe_json.symlink_to(external_sentinel)
            (
                unsafe_json_rc,
                unsafe_json_result,
                unsafe_json_invocation,
            ) = certifier_cli(
                package_root,
                baseline_bundle,
                json_path=unsafe_json,
            )
            cases.append({
                "name": (
                    "certifier_json_symlink_rejected_without_external_overwrite"
                ),
                "passed": (
                    unsafe_json_rc == 2
                    and unsafe_json_result
                    == {
                        "status": "FAIL",
                        "outcome": "FAILED",
                        "failure_kind": "INVALID_INPUT",
                        "promotion_authorized": False,
                        "reason": "unsafe --json output path was rejected",
                    }
                    and unsafe_json_invocation.get("verified") is True
                    and unsafe_json.is_symlink()
                    and external_sentinel.read_bytes() == sentinel_bytes
                ),
                "execution_mode": "production-certifier-cli",
                "exit_code": unsafe_json_rc,
                "status": unsafe_json_result.get("status"),
                "failure_kind": unsafe_json_result.get("failure_kind"),
                "cli_invocation_verified": unsafe_json_invocation.get(
                    "verified"
                ),
                "sentinel_unchanged": (
                    external_sentinel.read_bytes() == sentinel_bytes
                ),
            })
            replaceable_json = root / "replaceable-certifier-result.json"
            original_regular_bytes = b"replace this regular result\n"
            replaceable_json.write_bytes(original_regular_bytes)
            original_regular_metadata = replaceable_json.lstat()
            original_regular_identity = (
                original_regular_metadata.st_dev,
                original_regular_metadata.st_ino,
            )
            (
                replace_rc,
                replace_result,
                replace_invocation,
            ) = certifier_cli(
                package_root,
                baseline_bundle,
                json_path=replaceable_json,
            )
            replaced_bytes = replaceable_json.read_bytes()
            try:
                replaced_result = json.loads(replaced_bytes)
            except (TypeError, ValueError):
                replaced_result = None
            replace_metadata = replaceable_json.lstat()
            replacement_identity = (
                replace_metadata.st_dev,
                replace_metadata.st_ino,
            )
            replace_temp_residue = sorted(
                entry.name
                for entry in root.iterdir()
                if entry.name.startswith(
                    f".{replaceable_json.name}."
                )
                and entry.name.endswith(".tmp")
            )
            cases.append({
                "name": "certifier_json_regular_file_is_atomically_replaced",
                "passed": (
                    replace_rc == 2
                    and replace_result.get("status") == certifier.PASS_SCOPED
                    and replace_result.get("outcome") == "CAPPED"
                    and replace_result.get("modeled_promotion_checks_passed")
                    is True
                    and not failed_check_inventory(replace_result)
                    and "failure_kind" not in replace_result
                    and replace_invocation.get("verified") is True
                    and replaced_bytes != original_regular_bytes
                    and replaced_result == replace_result
                    and stat.S_ISREG(replace_metadata.st_mode)
                    and replace_metadata.st_nlink == 1
                    and replacement_identity != original_regular_identity
                    and not replace_temp_residue
                ),
                "execution_mode": "production-certifier-cli",
                "exit_code": replace_rc,
                "status": replace_result.get("status"),
                "cli_invocation_verified": replace_invocation.get("verified"),
                "modeled_promotion_checks_passed": replace_result.get(
                    "modeled_promotion_checks_passed"
                ),
                "failed_checks": sorted(
                    failed_check_inventory(replace_result).elements()
                ),
                "stdout_json_equal": replaced_result == replace_result,
                "inode_replaced": (
                    replacement_identity != original_regular_identity
                ),
                "private_regular": (
                    stat.S_ISREG(replace_metadata.st_mode)
                    and replace_metadata.st_nlink == 1
                ),
                "temp_residue": replace_temp_residue,
            })

            ancestor_external = root / "certifier-ancestor-external"
            ancestor_nested = ancestor_external / "nested"
            ancestor_nested.mkdir(parents=True)
            ancestor_sentinel = ancestor_nested / "result.json"
            ancestor_sentinel_bytes = (
                b"ancestor sentinel must remain unchanged\n"
            )
            ancestor_sentinel.write_bytes(ancestor_sentinel_bytes)
            ancestor_link = root / "certifier-ancestor-link"
            ancestor_link.symlink_to(
                ancestor_external,
                target_is_directory=True,
            )
            ancestor_json = ancestor_link / "nested/result.json"
            (
                ancestor_rc,
                ancestor_result,
                ancestor_invocation,
            ) = certifier_cli(
                package_root,
                baseline_bundle,
                json_path=ancestor_json,
            )
            cases.append({
                "name": (
                    "certifier_json_symlinked_ancestor_rejected_without_"
                    "external_overwrite"
                ),
                "passed": (
                    ancestor_rc == 2
                    and ancestor_result.get("failure_kind") == "INVALID_INPUT"
                    and ancestor_result.get("reason")
                    == "unsafe --json output path was rejected"
                    and ancestor_invocation.get("verified") is True
                    and ancestor_link.is_symlink()
                    and ancestor_sentinel.read_bytes()
                    == ancestor_sentinel_bytes
                ),
                "execution_mode": "production-certifier-cli",
                "exit_code": ancestor_rc,
                "status": ancestor_result.get("status"),
                "failure_kind": ancestor_result.get("failure_kind"),
                "cli_invocation_verified": ancestor_invocation.get("verified"),
                "sentinel_unchanged": (
                    ancestor_sentinel.read_bytes()
                    == ancestor_sentinel_bytes
                ),
            })

            special_json = root / "special-certifier-result.json"
            os.mkfifo(special_json)
            (
                special_rc,
                special_result,
                special_invocation,
            ) = certifier_cli(
                package_root,
                baseline_bundle,
                json_path=special_json,
            )
            cases.append({
                "name": "certifier_json_special_target_rejected",
                "passed": (
                    special_rc == 2
                    and special_result.get("failure_kind") == "INVALID_INPUT"
                    and special_result.get("reason")
                    == "unsafe --json output path was rejected"
                    and special_invocation.get("verified") is True
                    and stat.S_ISFIFO(special_json.lstat().st_mode)
                ),
                "execution_mode": "production-certifier-cli",
                "exit_code": special_rc,
                "status": special_result.get("status"),
                "failure_kind": special_result.get("failure_kind"),
                "cli_invocation_verified": special_invocation.get("verified"),
            })
            source_bytecode_after = bytecode_entries(source_root)
            package_bytecode_after = bytecode_entries(package_root)
            cases.append({
                "name": "normal_invocation_creates_no_python_bytecode",
                "passed": (
                    not source_bytecode_before
                    and
                    source_bytecode_after == source_bytecode_before
                    and not package_bytecode_after
                ),
                "source_before": sorted(source_bytecode_before),
                "source_after": sorted(source_bytecode_after),
                "disposable_package_bytecode": sorted(
                    package_bytecode_after
                ),
            })
        finally:
            os.environ["PATH"] = previous_path
            if previous_output_mode is None:
                os.environ.pop(output_mode_variable, None)
            else:
                os.environ[output_mode_variable] = previous_output_mode
    actual_case_names = tuple(
        str(case.get("name")) for case in cases
    )
    case_inventory_matches = (
        EXPECTED_CASE_TOTAL == len(EXPECTED_CASE_NAMES)
        and actual_case_names == EXPECTED_CASE_NAMES
        and len(cases) == EXPECTED_CASE_TOTAL
    )
    passed = sum(case.get("passed") is True for case in cases)
    all_negative_cases_use_production_cli = all(
        case.get("execution_mode") == "production-certifier-cli"
        and case.get("cli_invocation_verified") is True
        for case in cases
        if case.get("name") in EXPECTED_MUTATION_CHECK_INVENTORIES
    ) and sum(
        case.get("name") in EXPECTED_MUTATION_CHECK_INVENTORIES
        for case in cases
    ) == len(EXPECTED_MUTATION_CHECK_INVENTORIES)
    contract_passed = (
        passed == EXPECTED_CASE_TOTAL
        and case_inventory_matches
        and production_certifier_cli_baseline
        and all_negative_cases_use_production_cli
    )
    return {
        "status": "PASS" if contract_passed else "FAIL",
        "production_certifier_cli_baseline": (
            production_certifier_cli_baseline
        ),
        "all_negative_cases_use_production_cli": (
            all_negative_cases_use_production_cli
        ),
        "case_inventory_matches": case_inventory_matches,
        "actual_case_names": list(actual_case_names),
        "expected_case_names": list(EXPECTED_CASE_NAMES),
        "expected_total": EXPECTED_CASE_TOTAL,
        "actual_total": len(cases),
        "duration_sec": round(time.monotonic() - started, 3),
        "total": EXPECTED_CASE_TOTAL,
        "passed": passed,
        "cases": cases,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run aggregate promotion certifier contracts"
    )
    parser.add_argument("package_root", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)
    source_root = Path(os.path.abspath(args.package_root))
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
    try:
        result = run_contract(source_root)
    except Exception as exc:
        result = {
            "status": "FAIL",
            "failure_kind": "INTERNAL_ERROR",
            "reason": (
                "aggregate promotion contract failed unexpectedly: "
                f"{type(exc).__name__}"
            ),
            "total": 0,
            "passed": 0,
            "cases": [],
        }
    text = json.dumps(result, indent=2, sort_keys=True)
    if output_path is not None and output_directory_fd is not None:
        try:
            _atomic_replace_json_output(
                output_path,
                text + "\n",
                directory_fd=output_directory_fd,
            )
        except (OSError, RuntimeError, ValueError):
            failed_result = dict(result)
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
    return 0 if result.get("status") == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
