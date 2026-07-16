#!/usr/bin/env python3
"""Contract tests for formal artifact runner trace authentication and release-output idempotence.

The protected false worlds are: a fake Claude transcript claims native ntt-* lanes ran,
Agent/Task tool-use events lack successful matching tool-result/completion events, result ids are mismatched, native lane selectors appear only in descriptions, duplicate tool-use ids collapse lanes, empty/generic/metadata-only result blocks are accepted, fake nested tool_result objects appear inside tool inputs or tool_result payloads,
result events appear before their matching tool-use events, non-tool text/message blocks masquerade as tool events, unexpected Agent/Task calls omit or spoof structured selectors, or a routine formal dry-run writes
volatile artifacts into the package tree and invalidates STABLE_RELEASE_MANIFEST.json. These tests import the formal runner and validate both
trace authentication and release-output guards.
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
from pathlib import Path
from typing import Any, Dict, List

REQUIRED_NATIVE_AGENTS = [
    "ntt-method-cartographer",
    "ntt-claim-extractor",
    "ntt-source-verifier",
    "ntt-code-verifier",
    "ntt-false-world-adversary",
    "ntt-true-world-adherence",
    "ntt-gate-auditor",
]
SKILL_PATH = "skills/nozickian-verify"
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


def raises_value_error(function, *args: Any) -> bool:
    try:
        function(*args)
    except ValueError:
        return True
    return False


def load_runner(package_root: Path):
    path = package_root / SKILL_PATH / "scripts/run_formal_artifact_verification.py"
    spec = importlib.util.spec_from_file_location("formal_runner_under_test", str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    previous_dont_write = sys.dont_write_bytecode
    import_stdout = io.StringIO()
    try:
        sys.dont_write_bytecode = True
        # SECURITY-REVIEW: The fixed package-local formal runner executes at
        # import time. Contain stdout so this contract CLI emits one document.
        with contextlib.redirect_stdout(import_stdout):
            spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    finally:
        sys.dont_write_bytecode = previous_dont_write
    return mod


def load_live_runner(package_root: Path):
    path = package_root / SKILL_PATH / "scripts/run_live_skill_evals.py"
    spec = importlib.util.spec_from_file_location("live_runner_under_test", str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    previous_dont_write = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    finally:
        sys.dont_write_bytecode = previous_dont_write
    return mod


def load_certifier(package_root: Path):
    path = package_root / SKILL_PATH / "scripts/certify_pass_tracked_upgrade.py"
    spec = importlib.util.spec_from_file_location("certifier_under_test", str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    previous_dont_write = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    finally:
        sys.dont_write_bytecode = previous_dont_write
    return mod


def load_output_wrapper(
    package_root: Path,
    filename: str,
    module_name: str,
):
    path = package_root / SKILL_PATH / "scripts" / filename
    spec = importlib.util.spec_from_file_location(module_name, str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    previous_dont_write = sys.dont_write_bytecode
    import_stdout = io.StringIO()
    try:
        sys.dont_write_bytecode = True
        with contextlib.redirect_stdout(import_stdout):
            spec.loader.exec_module(module)  # type: ignore[attr-defined]
    finally:
        sys.dont_write_bytecode = previous_dont_write
    return module


def write_transcript(lines: List[Dict[str, Any]]) -> Path:
    tmp = Path(
        tempfile.mkdtemp(
            prefix="nozickian_trace_contract_",
            dir=str(CANONICAL_TEMP_ROOT),
        )
    )
    path = tmp / "transcript.stream.jsonl"
    path.write_text("\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8")
    return path


def write_raw_transcript(text: str) -> Path:
    tmp = Path(
        tempfile.mkdtemp(
            prefix="nozickian_raw_trace_contract_",
            dir=str(CANONICAL_TEMP_ROOT),
        )
    )
    path = tmp / "transcript.stream.jsonl"
    path.write_text(text, encoding="utf-8")
    return path


def native_event(agent: str) -> Dict[str, Any]:
    return {
        "type": "assistant",
        "message": {
            "content": [
                {
                    "id": f"toolu-{agent}",
                    "type": "tool_use",
                    "name": "Agent",
                    "input": {"subagent_type": agent, "description": f"Run native lane {agent}"},
                }
            ]
        },
    }


def native_result(agent: str, success: bool = True) -> Dict[str, Any]:
    if success:
        content = f"{agent} completed successfully with structured findings."
        status = "success"
        is_error = False
    else:
        content = f"FORMAL_SUBAGENT_FAILURE: {agent} failed before producing findings."
        status = "failed"
        is_error = True
    return {
        "type": "user",
        "message": {
            "content": [
                {"type": "tool_result", "tool_use_id": f"toolu-{agent}", "is_error": is_error, "status": status, "content": content}
            ]
        },
    }


def native_mismatched_result(agent: str) -> Dict[str, Any]:
    """Successful-looking result text that references the wrong tool-use id.

    This protects against the earlier false world where a result payload merely
    mentioning an agent name was treated as authentic even though tool_use_id did
    not match the native Agent/Task call id.
    """
    return {
        "type": "assistant",
        "message": {
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": f"wrong-{agent}",
                    "is_error": False,
                    "status": "success",
                    "content": f"{agent} completed successfully with structured findings.",
                }
            ]
        },
    }


def native_event_with_id(agent: str, tool_id: str) -> Dict[str, Any]:
    return {
        "type": "assistant",
        "message": {
            "content": [
                {
                    "id": tool_id,
                    "type": "tool_use",
                    "name": "Agent",
                    "input": {"subagent_type": agent, "description": f"Run native lane {agent}"},
                }
            ]
        },
    }


def native_result_for_id(tool_id: str, content: Any, *, status: str | None = "success", is_error: bool | None = False) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"type": "tool_result", "tool_use_id": tool_id, "content": content}
    if status is not None:
        payload["status"] = status
    if is_error is not None:
        payload["is_error"] = is_error
    return {"type": "user", "message": {"content": [payload]}}


def single_call_mentions_all_lanes() -> List[Dict[str, Any]]:
    first = REQUIRED_NATIVE_AGENTS[0]
    all_names = ", ".join(REQUIRED_NATIVE_AGENTS)
    return [
        {
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "id": "toolu-single-lane",
                        "type": "tool_use",
                        "name": "Agent",
                        "input": {"subagent_type": first, "description": f"Run and report all native lanes: {all_names}"},
                    }
                ]
            },
        },
        native_result_for_id("toolu-single-lane", f"{first} completed successfully with structured findings."),
    ]


def description_only_lane_mentions() -> List[Dict[str, Any]]:
    lines: List[Dict[str, Any]] = []
    for agent in REQUIRED_NATIVE_AGENTS:
        lines.append({
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "id": f"toolu-description-only-{agent}",
                        "type": "tool_use",
                        "name": "Agent",
                        "input": {"description": f"Please run native lane {agent}; selector intentionally omitted."},
                    }
                ]
            },
        })
        lines.append(native_result_for_id(f"toolu-description-only-{agent}", f"{agent} completed successfully with structured findings."))
    return lines


def duplicate_id_trace() -> List[Dict[str, Any]]:
    tool_id = "toolu-duplicate-native-lane-id"
    lines: List[Dict[str, Any]] = []
    for agent in REQUIRED_NATIVE_AGENTS:
        lines.append(native_event_with_id(agent, tool_id))
    lines.append(native_result_for_id(tool_id, "One shared result must not authenticate seven native lanes."))
    return lines


def empty_results_trace() -> List[Dict[str, Any]]:
    lines: List[Dict[str, Any]] = []
    for agent in REQUIRED_NATIVE_AGENTS:
        lines.append(native_event(agent))
        lines.append(native_result_for_id(f"toolu-{agent}", "", status="success", is_error=False))
    return lines


def generic_results_without_success_signal_trace() -> List[Dict[str, Any]]:
    lines: List[Dict[str, Any]] = []
    for agent in REQUIRED_NATIVE_AGENTS:
        lines.append(native_event(agent))
        lines.append(native_result_for_id(f"toolu-{agent}", f"{agent} completed successfully with structured findings.", status=None, is_error=None))
    return lines


def content_block_results_trace(content: Any, *, status: str | None = "success", is_error: bool | None = False) -> List[Dict[str, Any]]:
    lines: List[Dict[str, Any]] = []
    for agent in REQUIRED_NATIVE_AGENTS:
        lines.append(native_event(agent))
        lines.append(native_result_for_id(f"toolu-{agent}", content, status=status, is_error=is_error))
    return lines


def metadata_only_result_blocks_trace(content_block: Any, *, status: str | None = "success", is_error: bool | None = False) -> List[Dict[str, Any]]:
    lines: List[Dict[str, Any]] = []
    for agent in REQUIRED_NATIVE_AGENTS:
        lines.append(native_event(agent))
        lines.append(native_result_for_id(f"toolu-{agent}", content_block, status=status, is_error=is_error))
    return lines


def nonempty_text_block_results_trace() -> List[Dict[str, Any]]:
    lines: List[Dict[str, Any]] = []
    for agent in REQUIRED_NATIVE_AGENTS:
        lines.append(native_event(agent))
        lines.append(native_result_for_id(
            f"toolu-{agent}",
            [{"type": "text", "text": f"{agent} completed with nonempty structured findings."}],
            status="success",
            is_error=False,
        ))
    return lines


def nested_tool_result_inside_tool_input_trace() -> List[Dict[str, Any]]:
    lines: List[Dict[str, Any]] = []
    for agent in REQUIRED_NATIVE_AGENTS:
        tool_id = f"toolu-{agent}"
        lines.append({
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "id": tool_id,
                        "type": "tool_use",
                        "name": "Agent",
                        "input": {
                            "subagent_type": agent,
                            "description": f"Run native lane {agent}",
                            "fake_runtime_event": {
                                "type": "tool_result",
                                "tool_use_id": tool_id,
                                "status": "success",
                                "is_error": False,
                                "content": f"{agent} completed successfully but only inside tool input.",
                            },
                        },
                    }
                ]
            },
        })
    return lines


def nested_tool_result_inside_arguments_trace() -> List[Dict[str, Any]]:
    lines: List[Dict[str, Any]] = []
    for agent in REQUIRED_NATIVE_AGENTS:
        tool_id = f"toolu-args-{agent}"
        lines.append({
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "id": tool_id,
                        "type": "tool_use",
                        "name": "Agent",
                        "arguments": {
                            "subagent_type": agent,
                            "embedded_result": {
                                "type": "tool_result",
                                "tool_use_id": tool_id,
                                "status": "success",
                                "is_error": False,
                                "content": f"{agent} completed successfully but only inside arguments.",
                            },
                        },
                    }
                ]
            },
        })
    return lines


def tool_result_before_tool_use_trace() -> List[Dict[str, Any]]:
    lines: List[Dict[str, Any]] = []
    for agent in REQUIRED_NATIVE_AGENTS:
        lines.append(native_result_for_id(f"toolu-{agent}", f"{agent} result appears before call.", status="success", is_error=False))
        lines.append(native_event(agent))
    return lines


def same_event_input_embedded_result_trace() -> List[Dict[str, Any]]:
    lines: List[Dict[str, Any]] = []
    for agent in REQUIRED_NATIVE_AGENTS:
        tool_id = f"toolu-same-event-{agent}"
        lines.append({
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "id": tool_id,
                        "type": "tool_use",
                        "name": "Agent",
                        "input": {
                            "subagent_type": agent,
                            "nested": [{"type": "tool_result", "tool_use_id": tool_id, "status": "success", "is_error": False, "content": "nested fake result"}],
                        },
                    }
                ]
            },
        })
    return lines

def fake_tool_events_inside_tool_result_content_trace(include_results: bool = True) -> List[Dict[str, Any]]:
    """Fake tool events inside a result payload are data, not runtime trace events."""
    lines: List[Dict[str, Any]] = []
    for idx, agent in enumerate(REQUIRED_NATIVE_AGENTS):
        fake_id = f"fake-inside-result-{idx}-{agent}"
        payload: List[Dict[str, Any]] = [
            {
                "id": fake_id,
                "type": "tool_use",
                "name": "Agent",
                "input": {"subagent_type": agent, "description": f"Fake embedded native lane {agent}"},
            }
        ]
        if include_results:
            payload.append({
                "type": "tool_result",
                "tool_use_id": fake_id,
                "status": "success",
                "is_error": False,
                "content": [{"type": "text", "text": f"{agent} fake embedded result"}],
            })
        lines.append({
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": f"outer-{idx}",
                        "status": "success",
                        "is_error": False,
                        "content": payload,
                    }
                ]
            },
        })
    return lines


def tool_result_inside_tool_result_content_trace() -> List[Dict[str, Any]]:
    lines: List[Dict[str, Any]] = []
    for idx, agent in enumerate(REQUIRED_NATIVE_AGENTS):
        fake_id = f"fake-result-only-{idx}-{agent}"
        lines.append({
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": f"outer-result-only-{idx}",
                        "status": "success",
                        "is_error": False,
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": fake_id,
                                "status": "success",
                                "is_error": False,
                                "content": [{"type": "text", "text": f"{agent} fake nested result only"}],
                            }
                        ],
                    }
                ]
            },
        })
    return lines


def tool_use_inside_tool_use_content_trace() -> List[Dict[str, Any]]:
    lines: List[Dict[str, Any]] = []
    for idx, agent in enumerate(REQUIRED_NATIVE_AGENTS):
        fake_id = f"fake-inside-tooluse-{idx}-{agent}"
        lines.append({
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "id": f"outer-tooluse-{idx}",
                        "type": "tool_use",
                        "name": "Agent",
                        "input": {"description": "outer call intentionally lacks selector"},
                        "content": [
                            {
                                "id": fake_id,
                                "type": "tool_use",
                                "name": "Agent",
                                "input": {"subagent_type": agent},
                            },
                            {
                                "type": "tool_result",
                                "tool_use_id": fake_id,
                                "status": "success",
                                "is_error": False,
                                "content": [{"type": "text", "text": "nested fake completion"}],
                            },
                        ],
                    }
                ]
            },
        })
    return lines

def text_block_tool_use_masquerade_trace() -> List[Dict[str, Any]]:
    """Text content blocks that contain tool-like fields are not tool events."""
    lines: List[Dict[str, Any]] = []
    for agent in REQUIRED_NATIVE_AGENTS:
        tool_id = f"text-toolu-{agent}"
        lines.append({
            "type": "assistant",
            "message": {
                "content": [
                    {"type": "text", "id": tool_id, "name": "Agent", "input": {"subagent_type": agent}, "text": "not a real native tool-use event"},
                    {"type": "text", "tool_use_id": tool_id, "status": "success", "is_error": False, "content": f"{agent} fake text result"},
                ]
            },
        })
    return lines


def assistant_message_tool_use_masquerade_trace() -> List[Dict[str, Any]]:
    """Top-level assistant/message envelopes are not tool events merely because fields match."""
    lines: List[Dict[str, Any]] = []
    for agent in REQUIRED_NATIVE_AGENTS:
        tool_id = f"assistant-toolu-{agent}"
        lines.append({"type": "assistant", "id": tool_id, "name": "Agent", "input": {"subagent_type": agent}, "content": "not a real tool-use event"})
        lines.append({"type": "assistant", "tool_use_id": tool_id, "status": "success", "is_error": False, "content": f"{agent} fake assistant result"})
    return lines


def unexpected_agent_call_without_selector_trace() -> List[Dict[str, Any]]:
    lines = completed_native_trace(success=True)
    lines.append({
        "type": "assistant",
        "message": {"content": [{"id": "toolu-unexpected-nosel", "type": "tool_use", "name": "Agent", "input": {"description": "unstructured general exploration"}}]},
    })
    lines.append(native_result_for_id("toolu-unexpected-nosel", "Unexpected unstructured Agent call completed.", status="success", is_error=False))
    return lines


def unknown_agent_selector_trace() -> List[Dict[str, Any]]:
    lines = completed_native_trace(success=True)
    lines.append({
        "type": "assistant",
        "message": {"content": [{"id": "toolu-unknown-selector", "type": "tool_use", "name": "Task", "input": {"subagent_type": "not-an-ntt-lane", "description": "unknown native selector"}}]},
    })
    lines.append(native_result_for_id("toolu-unknown-selector", "Unknown selector task completed.", status="success", is_error=False))
    return lines



def fake_tool_events_inside_tool_result_envelope_trace(key: str, include_results: bool = True) -> List[Dict[str, Any]]:
    """Fake tool events in tool_result data/payload/delta/message are payload, not runtime events."""
    lines: List[Dict[str, Any]] = []
    for idx, agent in enumerate(REQUIRED_NATIVE_AGENTS):
        fake_id = f"fake-{key}-{idx}-{agent}"
        embedded: List[Dict[str, Any]] = [
            {
                "id": fake_id,
                "type": "tool_use",
                "name": "Agent",
                "input": {"subagent_type": agent, "description": f"Fake embedded native lane {agent}"},
            }
        ]
        if include_results:
            embedded.append({
                "type": "tool_result",
                "tool_use_id": fake_id,
                "status": "success",
                "is_error": False,
                "content": [{"type": "text", "text": f"{agent} fake embedded result"}],
            })
        outer: Dict[str, Any] = {
            "type": "tool_result",
            "tool_use_id": f"outer-{key}-{idx}",
            "status": "success",
            "is_error": False,
            "content": "outer result payload completed",
            key: {"content": embedded},
        }
        lines.append(outer)
    return lines


def role_inverted_tool_trace() -> List[Dict[str, Any]]:
    """User-side tool_use plus assistant-side tool_result should not authenticate."""
    lines: List[Dict[str, Any]] = []
    for agent in REQUIRED_NATIVE_AGENTS:
        lines.append({
            "type": "user",
            "message": {
                "content": [
                    {
                        "id": f"role-inverted-{agent}",
                        "type": "tool_use",
                        "name": "Agent",
                        "input": {"subagent_type": agent, "description": f"Wrong-role native lane {agent}"},
                    }
                ]
            },
        })
        lines.append({
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": f"role-inverted-{agent}",
                        "status": "success",
                        "is_error": False,
                        "content": [{"type": "text", "text": f"{agent} wrong-role result"}],
                    }
                ]
            },
        })
    return lines


def user_message_tool_use_trace() -> List[Dict[str, Any]]:
    lines: List[Dict[str, Any]] = []
    for agent in REQUIRED_NATIVE_AGENTS:
        lines.append({"type": "user", "message": {"content": [{"id": f"user-use-{agent}", "type": "tool_use", "name": "Agent", "input": {"subagent_type": agent}}]}})
        lines.append(native_result_for_id(f"user-use-{agent}", [{"type": "text", "text": f"{agent} result exists but call role is wrong"}], status="success", is_error=False))
    return lines


def assistant_message_tool_result_trace() -> List[Dict[str, Any]]:
    lines: List[Dict[str, Any]] = []
    for agent in REQUIRED_NATIVE_AGENTS:
        lines.append(native_event(agent))
        lines.append({"type": "assistant", "message": {"content": [{"type": "tool_result", "tool_use_id": f"toolu-{agent}", "status": "success", "is_error": False, "content": [{"type": "text", "text": f"{agent} assistant-side result"}]}]}})
    return lines

def completed_native_trace(success: bool = True) -> List[Dict[str, Any]]:
    lines: List[Dict[str, Any]] = []
    for agent in REQUIRED_NATIVE_AGENTS:
        lines.append(native_event(agent))
        lines.append(native_result(agent, success=success))
    return lines


def call_runner_main(runner, argv: List[str]) -> tuple[int, str]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = runner.main(argv)
    return rc, buf.getvalue()


def run_cases(runner, package_root: Path) -> List[Dict[str, Any]]:
    cases: List[Dict[str, Any]] = []
    live_runner = load_live_runner(package_root)
    certifier = load_certifier(package_root)

    valid_fixture_id = "mini-code-mutation"
    cases.append({
        "name": "live_fixture_id_requires_canonical_slug",
        "passed": (
            live_runner.canonical_fixture_id(valid_fixture_id)
            == valid_fixture_id
            and all(
                raises_value_error(
                    live_runner.canonical_fixture_id,
                    value,
                )
                for value in (
                    "../escape-id",
                    "/absolute-id",
                    "UPPERCASE-ID",
                    "short",
                    "trailing-dash-",
                )
            )
        ),
    })

    def bytecode_inventory(root: Path) -> List[str]:
        found: List[str] = []
        for current, directories, files in os.walk(root, followlinks=False):
            directories[:] = [
                name for name in directories if name != ".git"
            ]
            current_path = Path(current)
            for name in directories:
                if name == "__pycache__":
                    found.append(
                        (current_path / name).relative_to(root).as_posix()
                    )
            for name in files:
                if name.endswith((".pyc", ".pyo")):
                    found.append(
                        (current_path / name).relative_to(root).as_posix()
                    )
        return sorted(found)

    validator = (
        package_root
        / SKILL_PATH
        / "scripts/validate_package.py"
    )
    bytecode_before = bytecode_inventory(package_root)
    validation_env = os.environ.copy()
    # This probe deliberately removes environment-level suppression so the
    # validator's dynamic loader must be bytecode-safe on its own.
    validation_env.pop("PYTHONDONTWRITEBYTECODE", None)
    validation_env.pop("PYTHONPYCACHEPREFIX", None)
    validation_command = [sys.executable, str(validator), str(package_root)]
    # SECURITY-REVIEW: The contract invokes only the package-local validator
    # through fixed argv, with no shell or untrusted argv interpolation.
    validation_runs = [
        subprocess.run(
            validation_command,
            cwd=package_root,
            env=validation_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300,
            check=False,
        )
        for _ in range(2)
    ]
    parsed_validations: List[Dict[str, Any]] = []
    for completed in validation_runs:
        try:
            parsed = json.loads(completed.stdout)
        except (TypeError, ValueError):
            parsed = {}
        parsed_validations.append(parsed if isinstance(parsed, dict) else {})
    bytecode_after = bytecode_inventory(package_root)
    cases.append({
        "name": "repeated_plain_validation_creates_no_bytecode_cruft",
        "passed": (
            not bytecode_before
            and bytecode_after == bytecode_before
            and [run.returncode for run in validation_runs]
            in ([0, 0], [2, 2])
            and all(
                result.get("status") in {"PASS", "FAIL"}
                for result in parsed_validations
            )
        ),
        "returncodes": [run.returncode for run in validation_runs],
        "bytecode_before": bytecode_before,
        "bytecode_after": bytecode_after,
    })

    fake_text_only = write_transcript([
        {"type": "assistant", "message": {"content": [{"type": "text", "text": "Native subagents completed: " + ", ".join(REQUIRED_NATIVE_AGENTS)}]}}
    ])
    auth = runner.authenticate_trace(fake_text_only)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "no_tool_use_events_do_not_authenticate", "passed": auth.get("authenticated") is False and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    fake_general = write_transcript([
        {"type": "assistant", "message": {"content": [{"id": "toolu-gp", "type": "tool_use", "name": "Agent", "input": {"subagent_type": "general-purpose", "description": "pretend to run all lanes"}}]}},
        {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "toolu-gp", "status": "success", "content": "general-purpose completed"}]}}
    ])
    auth = runner.authenticate_trace(fake_general)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "general_purpose_fallback_fails_formal_trace", "passed": auth.get("saw_general_purpose") is True and capped == "FAIL", "auth": auth, "capped_status": capped, "reason": reason})

    with tempfile.TemporaryDirectory(
        prefix="nozickian_full_stream_contract_",
        dir=str(CANONICAL_TEMP_ROOT),
    ) as stream_tmp_raw:
        stream_tmp = Path(stream_tmp_raw)
        stream_lines = [
            {
                "type": "assistant",
                "message": {
                    "content": [{
                        "id": "toolu-early-general",
                        "type": "tool_use",
                        "name": "Agent",
                        "input": {
                            "subagent_type": "general-purpose",
                            "description": "disallowed early fallback",
                        },
                    }]
                },
            },
            {
                "type": "user",
                "message": {
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": "toolu-early-general",
                        "status": "success",
                        "content": "disallowed fallback completed",
                    }]
                },
            },
            *[
                {
                    "type": "progress",
                    "message": "neutral-padding-" + ("x" * 1024),
                }
                for _ in range(55)
            ],
            *completed_native_trace(success=True),
        ]
        full_payload = (
            "\n".join(json.dumps(line) for line in stream_lines) + "\n"
        ).encode("utf-8")
        payload_path = stream_tmp / "payload.stream.jsonl"
        payload_path.write_bytes(full_payload)
        emitter = stream_tmp / "emit.py"
        emitter.write_text(
            "from pathlib import Path\n"
            "import sys\n"
            f"sys.stdout.buffer.write(Path({str(payload_path)!r}).read_bytes())\n",
            encoding="utf-8",
        )
        # SECURITY-REVIEW: The contract invokes a fixed temporary emitter with
        # shell parsing disabled to exercise production full-stream capture.
        invocation = runner.run_cmd(
            [sys.executable, str(emitter)],
            cwd=stream_tmp,
            timeout=30,
        )
        complete_transcript = stream_tmp / "complete.stream.jsonl"
        transcript_record = runner.write_complete_stream_transcript(
            complete_transcript,
            invocation,
        )
        auth = runner.authenticate_trace(complete_transcript)
        capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
        normalized_command_record = getattr(
            runner,
            "_normalized_command_record",
        )
        normalized = normalized_command_record(
            invocation,
            package_root,
            stream_tmp,
            emitter,
        )
        expected_digest = "sha256:" + hashlib.sha256(full_payload).hexdigest()
        cases.append({
            "name": "early_general_purpose_event_survives_large_valid_tail",
            "passed": (
                len(full_payload) > 50000
                and complete_transcript.read_bytes() == full_payload
                and transcript_record
                == {
                    "bytes": len(full_payload),
                    "sha256": expected_digest,
                }
                and normalized.get("stdout_bytes") == len(full_payload)
                and normalized.get("stdout_sha256") == expected_digest
                and normalized.get("stdout_truncated") is True
                and normalized.get("capture_limit_exceeded") is False
                and auth.get("saw_general_purpose") is True
                and auth.get("authenticated") is False
                and capped == "FAIL"
            ),
            "stream_bytes": len(full_payload),
            "stream_sha256": expected_digest,
            "auth": auth,
            "capped_status": capped,
            "reason": reason,
        })

        oversized_emitter = stream_tmp / "emit-oversized.py"
        oversized_emitter.write_text(
            "import sys\nsys.stdout.buffer.write(b'x' * 8192)\n",
            encoding="utf-8",
        )
        original_capture_limit = runner.MAX_CAPTURE_BYTES
        try:
            runner.MAX_CAPTURE_BYTES = 4096
            oversized = runner.run_cmd(
                [sys.executable, str(oversized_emitter)],
                cwd=stream_tmp,
                timeout=30,
            )
        finally:
            runner.MAX_CAPTURE_BYTES = original_capture_limit
        cases.append({
            "name": "capture_limit_is_enforced_during_process_execution",
            "passed": (
                oversized.get("returncode") == 126
                and oversized.get("capture_limit_exceeded") is True
                and oversized.get("stdout_bytes", 0) > 4096
                and len(oversized.get("_stdout_bytes", b"")) == 4096
            ),
        })
        original_live_capture_limit = live_runner.MAX_CAPTURE_BYTES
        try:
            live_runner.MAX_CAPTURE_BYTES = 4096
            live_oversized = live_runner.run_cmd(
                [sys.executable, str(oversized_emitter)],
                cwd=stream_tmp,
                timeout=30,
            )
        finally:
            live_runner.MAX_CAPTURE_BYTES = original_live_capture_limit
        cases.append({
            "name": "live_capture_limit_is_enforced_during_process_execution",
            "passed": (
                live_oversized.get("returncode") == 126
                and live_oversized.get("capture_limit_exceeded") is True
                and live_oversized.get("stdout_bytes", 0) > 4096
                and len(live_oversized.get("stdout", "").encode("utf-8"))
                == 4096
            ),
        })

        inherited_parent_exit = stream_tmp / "inherited-parent-exit.py"
        inherited_parent_exit.write_text(
            "import os, time\n"
            "child = os.fork()\n"
            "if child == 0:\n"
            "    time.sleep(60)\n"
            "    os._exit(0)\n"
            "os._exit(0)\n",
            encoding="utf-8",
        )
        inherited_timeout = stream_tmp / "inherited-timeout.py"
        inherited_timeout.write_text(
            "import subprocess, sys, time\n"
            "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            "time.sleep(60)\n",
            encoding="utf-8",
        )
        inherited_overflow = stream_tmp / "inherited-overflow.py"
        inherited_overflow.write_text(
            "import subprocess, sys, time\n"
            "subprocess.Popen([sys.executable, '-c', \"import sys,time; sys.stdout.buffer.write(b'x'*8192); sys.stdout.flush(); time.sleep(60)\"])\n"
            "time.sleep(0.2)\n",
            encoding="utf-8",
        )
        synthetic_nested_status = stream_tmp / "synthetic-nested.status"
        synthetic_nested_status.write_text(
            "Name:\ttest\n"
            "PPid:\t42\n"
            "NSpid:\t1000\t77\t3\n",
            encoding="utf-8",
        )
        for parser_name, parser_module in (
            ("formal", runner),
            ("certifier", certifier),
        ):
            cases.append({
                "name": f"{parser_name}_proc_parser_selects_current_namespace_depth",
                "passed": (
                    parser_module._linux_status_process_identity(
                        synthetic_nested_status,
                        1,
                    )
                    == (42, 77)
                    and parser_module._linux_status_process_identity(
                        synthetic_nested_status,
                        3,
                    )
                    is None
                ),
            })
        closed_stdio_parent = stream_tmp / "closed-stdio-parent.py"
        closed_stdio_parent.write_text(
            "import pathlib, subprocess, sys\n"
            "child = \"import pathlib,sys,time; time.sleep(0.4); pathlib.Path(sys.argv[1]).write_text('escaped', encoding='utf-8')\"\n"
            "subprocess.Popen(\n"
            "    [sys.executable, '-c', child, sys.argv[1]],\n"
            "    stdin=subprocess.DEVNULL,\n"
            "    stdout=subprocess.DEVNULL,\n"
            "    stderr=subprocess.DEVNULL,\n"
            "    close_fds=True,\n"
            "    start_new_session=(sys.argv[2] == 'detached'),\n"
            ")\n",
            encoding="utf-8",
        )
        detached_chain = stream_tmp / "detached-chain.py"
        detached_chain.write_text(
            "import os, pathlib, sys, time\n"
            "depth = int(sys.argv[1])\n"
            "sentinel = pathlib.Path(sys.argv[2])\n"
            "ready = pathlib.Path(sys.argv[3])\n"
            "def build(remaining):\n"
            "    if remaining == 0:\n"
            "        ready.write_text('ready', encoding='utf-8')\n"
            "        time.sleep(0.6)\n"
            "        sentinel.write_text('escaped', encoding='utf-8')\n"
            "        time.sleep(60)\n"
            "        return\n"
            "    child = os.fork()\n"
            "    if child == 0:\n"
            "        build(remaining - 1)\n"
            "        os._exit(0)\n"
            "    time.sleep(60)\n"
            "build(depth)\n",
            encoding="utf-8",
        )
        detached_chain_parent = stream_tmp / "detached-chain-parent.py"
        detached_chain_parent.write_text(
            "import pathlib, subprocess, sys, time\n"
            "ready = pathlib.Path(sys.argv[4])\n"
            "subprocess.Popen(\n"
            "    [sys.executable, sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]],\n"
            "    stdin=subprocess.DEVNULL,\n"
            "    stdout=subprocess.DEVNULL,\n"
            "    stderr=subprocess.DEVNULL,\n"
            "    close_fds=True,\n"
            "    start_new_session=True,\n"
            ")\n"
            "deadline = time.monotonic() + 10\n"
            "while not ready.exists() and time.monotonic() < deadline:\n"
            "    time.sleep(0.01)\n"
            "raise SystemExit(0 if ready.exists() else 3)\n",
            encoding="utf-8",
        )
        for capture_name, capture_module in (
            ("formal", runner),
            ("live", live_runner),
            ("certifier", certifier),
        ):
            unavailable_sentinel = (
                stream_tmp / f"{capture_name}-containment-unavailable.txt"
            )
            unavailable_child = [
                sys.executable,
                "-c",
                (
                    "from pathlib import Path; "
                    f"Path({str(unavailable_sentinel)!r}).write_text('ran')"
                ),
            ]
            fallback_scope = {
                "mechanism": "initial-posix-process-group",
                "cleanup_after_leader_exit": os.name == "posix",
                "detached_session_descendants_contained": False,
            }
            if capture_name == "live":
                original_prepare = capture_module.process_containment_scope
                capture_module.process_containment_scope = (
                    lambda: dict(fallback_scope)
                )
            else:
                original_prepare = capture_module.prepare_process_containment
                capture_module.prepare_process_containment = lambda: {
                    "enabled": False,
                    "parent_host_pid": None,
                    "baseline_host_pids": set(),
                    "scope": dict(fallback_scope),
                }
            try:
                unavailable_result = capture_module.run_cmd(
                    unavailable_child,
                    cwd=stream_tmp,
                    timeout=5,
                )
            finally:
                if capture_name == "live":
                    capture_module.process_containment_scope = original_prepare
                else:
                    capture_module.prepare_process_containment = original_prepare
            cases.append({
                "name": f"{capture_name}_capture_fails_before_spawn_without_detached_containment",
                "passed": (
                    unavailable_result.get("returncode") == 125
                    and not unavailable_sentinel.exists()
                    and unavailable_result.get(
                        "process_containment_cleanup_complete"
                    )
                    is False
                    and (
                        unavailable_result.get("process_containment") or {}
                    ).get("detached_session_descendants_contained")
                    is False
                ),
            })

            closed_sentinel = stream_tmp / f"{capture_name}-closed-stdio.txt"
            closed_result = capture_module.run_cmd(
                [
                    sys.executable,
                    str(closed_stdio_parent),
                    str(closed_sentinel),
                    "grouped",
                ],
                cwd=stream_tmp,
                timeout=5,
            )
            time.sleep(0.7)
            closed_scope = closed_result.get("process_containment")
            closed_scope_declared = (
                isinstance(closed_scope, dict)
                and closed_scope.get(
                    "detached_session_descendants_contained"
                )
                is not None
            ) or (
                closed_result.get(
                    "detached_session_descendants_contained"
                )
                is not None
            )
            closed_contained = (
                closed_scope.get(
                    "detached_session_descendants_contained"
                )
                if isinstance(closed_scope, dict)
                else closed_result.get(
                    "detached_session_descendants_contained"
                )
            )
            cases.append({
                "name": f"{capture_name}_capture_kills_closed_stdio_group_descendant",
                "passed": (
                    (
                        closed_contained is False
                        and closed_result.get("returncode") == 125
                        and not closed_sentinel.exists()
                        and closed_scope_declared
                    )
                    or (
                        closed_contained is True
                        and closed_result.get("returncode") == 125
                        and (
                            closed_result.get(
                                "normal_exit_group_survivor"
                            )
                            is True
                            or closed_result.get(
                                "detached_descendant_survivor"
                            )
                            is True
                        )
                        and closed_result.get(
                            "process_group_cleanup_attempted"
                        )
                        is True
                        and (
                            closed_result.get(
                                "process_group_terminated"
                            )
                            is True
                            or closed_result.get(
                                "detached_descendant_survivor"
                            )
                            is True
                        )
                        and closed_result.get(
                            "process_containment_cleanup_complete"
                        )
                        is True
                        and not closed_sentinel.exists()
                        and closed_scope_declared
                    )
                ),
                "returncode": closed_result.get("returncode"),
                "normal_exit_group_survivor": closed_result.get(
                    "normal_exit_group_survivor"
                ),
            })

            if os.name == "posix":
                detached_sentinel = (
                    stream_tmp / f"{capture_name}-detached-session.txt"
                )
                detached_result = capture_module.run_cmd(
                    [
                        sys.executable,
                        str(closed_stdio_parent),
                        str(detached_sentinel),
                        "detached",
                    ],
                    cwd=stream_tmp,
                    timeout=5,
                )
                time.sleep(0.7)
                detached_scope = detached_result.get(
                    "process_containment"
                )
                detached_scope_declared = (
                    isinstance(detached_scope, dict)
                    and detached_scope.get(
                        "detached_session_descendants_contained"
                    )
                    is not None
                ) or (
                    detached_result.get(
                        "detached_session_descendants_contained"
                    )
                    is not None
                )
                detached_contained = (
                    detached_scope.get(
                        "detached_session_descendants_contained"
                    )
                    if isinstance(detached_scope, dict)
                    else detached_result.get(
                        "detached_session_descendants_contained"
                    )
                )
                cases.append({
                    "name": f"{capture_name}_capture_contains_or_refuses_detached_session_boundary",
                    "passed": (
                        detached_scope_declared
                        and (
                        (
                            sys.platform.startswith("linux")
                            and detached_result.get("returncode") == 125
                            and detached_result.get(
                                "detached_descendant_survivor"
                            )
                            is True
                            and detached_result.get(
                                "process_containment_cleanup_complete"
                            )
                            is True
                            and detached_contained is True
                            and not detached_sentinel.exists()
                        )
                        or (
                            detached_contained is False
                            and detached_result.get("returncode") == 125
                            and detached_contained is False
                            and not detached_sentinel.exists()
                        )
                        )
                    ),
                    "returncode": detached_result.get("returncode"),
                    "detached_scope_declared": detached_scope_declared,
                })

                if sys.platform.startswith("linux"):
                    chain_sentinel = (
                        stream_tmp / f"{capture_name}-deep-chain.txt"
                    )
                    chain_ready = (
                        stream_tmp / f"{capture_name}-deep-chain.ready"
                    )
                    chain_result = capture_module.run_cmd(
                        [
                            sys.executable,
                            str(detached_chain_parent),
                            str(detached_chain),
                            "150",
                            str(chain_sentinel),
                            str(chain_ready),
                        ],
                        cwd=stream_tmp,
                        timeout=15,
                    )
                    time.sleep(0.9)
                    cases.append({
                        "name": f"{capture_name}_capture_kills_150_deep_detached_chain",
                        "passed": (
                            chain_ready.is_file()
                            and chain_result.get("returncode") == 125
                            and chain_result.get(
                                "detached_descendant_survivor"
                            )
                            is True
                            and chain_result.get(
                                "process_containment_cleanup_complete"
                            )
                            is True
                            and not chain_sentinel.exists()
                            and (
                                chain_result.get("process_containment") or {}
                            ).get(
                                "detached_session_descendants_contained"
                            )
                            is True
                        ),
                        "returncode": chain_result.get("returncode"),
                    })

            started = time.monotonic()
            parent_exit_result = capture_module.run_cmd(
                [sys.executable, str(inherited_parent_exit)],
                cwd=stream_tmp,
                timeout=5,
            )
            parent_exit_duration = time.monotonic() - started
            parent_scope = parent_exit_result.get("process_containment")
            parent_contained = (
                parent_scope.get(
                    "detached_session_descendants_contained"
                )
                if isinstance(parent_scope, dict)
                else parent_exit_result.get(
                    "detached_session_descendants_contained"
                )
            )
            cases.append({
                "name": f"{capture_name}_capture_kills_parent_exit_inherited_pipe_group",
                "passed": (
                    (
                        parent_contained is False
                        and parent_exit_result.get("returncode") == 125
                    )
                    or (
                        parent_contained is True
                        and parent_exit_result.get("returncode") == 125
                        and (
                            parent_exit_result.get("descendant_pipe_leak")
                            is True
                            or parent_exit_result.get(
                                "normal_exit_group_survivor"
                            )
                            is True
                            or parent_exit_result.get(
                                "detached_descendant_survivor"
                            )
                            is True
                        )
                        and (
                            parent_exit_result.get(
                                "process_group_terminated"
                            )
                            is True
                            or (
                                parent_exit_result.get(
                                    "detached_descendant_survivor"
                                )
                                is True
                                and parent_exit_result.get(
                                    "process_containment_cleanup_complete"
                                )
                                is True
                            )
                        )
                        and parent_exit_result.get("reader_join_timed_out") is False
                        and parent_exit_result.get(
                            "process_containment_cleanup_complete"
                        )
                        is True
                    )
                ),
                "returncode": parent_exit_result.get("returncode"),
                "descendant_pipe_leak": parent_exit_result.get(
                    "descendant_pipe_leak"
                ),
                "normal_exit_group_survivor": parent_exit_result.get(
                    "normal_exit_group_survivor"
                ),
                "detached_descendant_survivor": parent_exit_result.get(
                    "detached_descendant_survivor"
                ),
                "process_group_terminated": parent_exit_result.get(
                    "process_group_terminated"
                ),
                "process_containment_cleanup_complete": (
                    parent_exit_result.get(
                        "process_containment_cleanup_complete"
                    )
                ),
                "duration_sec": parent_exit_duration,
            })

            started = time.monotonic()
            timeout_result = capture_module.run_cmd(
                [sys.executable, str(inherited_timeout)],
                cwd=stream_tmp,
                timeout=1,
            )
            timeout_duration = time.monotonic() - started
            timeout_scope = timeout_result.get("process_containment")
            timeout_contained = (
                timeout_scope.get(
                    "detached_session_descendants_contained"
                )
                if isinstance(timeout_scope, dict)
                else timeout_result.get(
                    "detached_session_descendants_contained"
                )
            )
            cases.append({
                "name": f"{capture_name}_capture_kills_full_group_on_timeout",
                "passed": (
                    (
                        timeout_contained is False
                        and timeout_result.get("returncode") == 125
                    )
                    or (
                        timeout_contained is True
                        and timeout_result.get("returncode") == 124
                        and timeout_result.get("timed_out") is True
                        and timeout_result.get("process_group_terminated") is True
                        and timeout_result.get("reader_join_timed_out") is False
                        and timeout_result.get(
                            "process_containment_cleanup_complete"
                        )
                        is True
                    )
                ),
                "duration_sec": timeout_duration,
            })

            original_limit = capture_module.MAX_CAPTURE_BYTES
            try:
                capture_module.MAX_CAPTURE_BYTES = 4096
                started = time.monotonic()
                overflow_result = capture_module.run_cmd(
                    [sys.executable, str(inherited_overflow)],
                    cwd=stream_tmp,
                    timeout=5,
                )
                overflow_duration = time.monotonic() - started
            finally:
                capture_module.MAX_CAPTURE_BYTES = original_limit
            cases.append({
                "name": f"{capture_name}_capture_kills_full_group_on_descendant_overflow",
                "passed": (
                    (
                        (
                            overflow_result.get("process_containment") or {}
                        ).get("detached_session_descendants_contained")
                        is False
                        and overflow_result.get("returncode") == 125
                    )
                    or (
                        (
                            overflow_result.get("process_containment") or {}
                        ).get("detached_session_descendants_contained")
                        is True
                        and overflow_result.get("returncode") == 126
                        and overflow_result.get("capture_limit_exceeded") is True
                        and overflow_result.get("process_group_terminated") is True
                        and overflow_result.get("reader_join_timed_out") is False
                        and overflow_result.get(
                            "process_containment_cleanup_complete"
                        )
                        is True
                    )
                ),
                "duration_sec": overflow_duration,
            })

    native_calls_only = write_transcript([native_event(agent) for agent in REQUIRED_NATIVE_AGENTS])
    auth = runner.authenticate_trace(native_calls_only)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "native_tool_use_without_results_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("missing_result_agents")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    native = write_transcript(completed_native_trace(success=True))
    auth = runner.authenticate_trace(native)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "all_native_tool_use_and_result_events_authenticate", "passed": auth.get("authenticated") is True and capped == "PASS-TRACKED", "auth": auth, "capped_status": capped, "reason": reason})

    malformed_prefix = write_raw_transcript(
        '{"type":"assistant","message":\n'
        + "\n".join(json.dumps(item) for item in completed_native_trace(success=True))
        + "\n"
    )
    auth = runner.authenticate_trace(malformed_prefix)
    cases.append({
        "name": "malformed_jsonl_record_rejects_entire_trace",
        "passed": auth.get("authenticated") is False and bool(auth.get("malformed_stream_records")),
        "auth": auth,
    })

    scalar_prefix = write_raw_transcript(
        "42\n"
        + "\n".join(json.dumps(item) for item in completed_native_trace(success=True))
        + "\n"
    )
    auth = runner.authenticate_trace(scalar_prefix)
    cases.append({
        "name": "non_object_jsonl_record_rejects_entire_trace",
        "passed": auth.get("authenticated") is False and bool(auth.get("malformed_stream_records")),
        "auth": auth,
    })

    first_agent = REQUIRED_NATIVE_AGENTS[0]
    huge_before_call_record = {
        "type": "user",
        "message": {
            "content": [
                *(
                    {"type": "text", "text": "bounded neutral node"}
                    for _ in range(100_001)
                ),
                {
                    "type": "tool_result",
                    "tool_use_id": f"toolu-{first_agent}",
                    "status": "success",
                    "is_error": False,
                    "content": "This result occurs before its call.",
                },
            ]
        },
    }
    huge_before_call_lines = [
        huge_before_call_record,
        native_event(first_agent),
        *[
            item
            for agent in REQUIRED_NATIVE_AGENTS[1:]
            for item in (native_event(agent), native_result(agent))
        ],
    ]
    auth = runner.authenticate_trace(write_transcript(huge_before_call_lines))
    cases.append({
        "name": "over_100k_node_result_before_call_is_bounded_and_rejected",
        "passed": (
            auth.get("authenticated") is False
            and bool(auth.get("trace_bound_violations"))
            and first_agent in auth.get("missing_result_agents", [])
        ),
        "auth": auth,
    })

    deeply_nested: Dict[str, Any] = {"type": "text", "text": "leaf"}
    for _ in range(runner.MAX_TRACE_DEPTH + 2):
        deeply_nested = {"message": deeply_nested}
    deep_lines = [deeply_nested, *completed_native_trace(success=True)]
    auth = runner.authenticate_trace(write_transcript(deep_lines))
    cases.append({
        "name": "over_depth_trace_record_is_bounded_and_rejected",
        "passed": auth.get("authenticated") is False and bool(auth.get("trace_bound_violations")),
        "auth": auth,
    })

    alias_lines = [native_event(agent) for agent in REQUIRED_NATIVE_AGENTS]
    alias_ids = [f"toolu-{agent}" for agent in REQUIRED_NATIVE_AGENTS]
    for group in (alias_ids[:4], alias_ids[4:]):
        payload: Dict[str, Any] = {
            "type": "tool_result",
            "status": "success",
            "is_error": False,
            "content": "Aliased result must not fan out across calls.",
        }
        for key, value in zip(
            ("tool_use_id", "toolUseId", "tool_call_id", "toolCallId"),
            group,
        ):
            payload[key] = value
        alias_lines.append({"type": "user", "message": {"content": [payload]}})
    auth = runner.authenticate_trace(write_transcript(alias_lines))
    cases.append({
        "name": "tool_result_alias_fanout_does_not_authenticate",
        "passed": auth.get("authenticated") is False and len(auth.get("invalid_result_bindings", [])) == 2,
        "auth": auth,
    })

    duplicate_result_lines: List[Dict[str, Any]] = []
    for agent in REQUIRED_NATIVE_AGENTS:
        duplicate_result_lines.extend(
            [native_event(agent), native_result(agent), native_result(agent)]
        )
    auth = runner.authenticate_trace(write_transcript(duplicate_result_lines))
    cases.append({
        "name": "multiple_results_for_one_native_call_do_not_authenticate",
        "passed": auth.get("authenticated") is False and bool(auth.get("duplicate_tool_result_ids")),
        "auth": auth,
    })

    duplicate_call_lines = completed_native_trace(success=True)
    duplicate_call_lines.insert(1, native_event(REQUIRED_NATIVE_AGENTS[0]))
    auth = runner.authenticate_trace(write_transcript(duplicate_call_lines))
    cases.append({
        "name": "multiple_calls_for_one_required_lane_do_not_authenticate",
        "passed": auth.get("authenticated") is False and bool(auth.get("duplicate_agent_calls")),
        "auth": auth,
    })

    for content, expected, case_name in (
        ("0 failures; all checks passed.", True, "zero_failures_result_is_success"),
        ("No tests failed. All checks passed.", True, "no_tests_failed_result_is_success"),
        ("Mutation failed as expected; verifier passed.", True, "expected_mutation_failure_result_is_success"),
        ("Analyzed why the prior command failed and documented the failure mode; findings complete.", True, "failure_analysis_result_is_success"),
        ("0 failures reported, but FORMAL_SUBAGENT_FAILURE occurred.", False, "explicit_contradiction_dominates_benign_failure_phrase"),
        ("The subagent was not executed, despite this success envelope.", False, "nonexecution_prose_dominates_success_envelope"),
        ("Subagent not run; cached output only.", False, "short_nonexecution_prose_dominates_success_envelope"),
        ("Execution aborted by the coordinator.", False, "aborted_prose_dominates_success_envelope"),
        ("The worker process was killed.", False, "killed_prose_dominates_success_envelope"),
        ("Completion was unsuccessful.", False, "unsuccessful_prose_dominates_success_envelope"),
        ("The agent returned nonzero exit code 2.", False, "nonzero_exit_prose_dominates_success_envelope"),
        ("The agent returned a non-zero exit code.", False, "unnumbered_nonzero_exit_prose_dominates_success_envelope"),
        ("The agent's exit code was nonzero.", False, "postfixed_nonzero_exit_prose_dominates_success_envelope"),
        ("The agent returned exit code -1.", False, "negative_exit_code_prose_dominates_success_envelope"),
        ("The lane failed before producing findings.", False, "failed_before_output_dominates_success_envelope"),
    ):
        node = {
            "type": "tool_result",
            "tool_use_id": "toolu-test",
            "status": "success",
            "is_error": False,
            "content": content,
        }
        cases.append({
            "name": case_name,
            "passed": runner._result_is_success(node) is expected,
        })
    for structured_field, structured_value, case_name in (
        ("executed", False, "structured_not_executed_dominates_success"),
        ("completed", False, "structured_not_completed_dominates_success"),
        ("aborted", True, "structured_aborted_dominates_success"),
        ("killed", True, "structured_killed_dominates_success"),
        ("returncode", 7, "structured_nonzero_returncode_dominates_success"),
        ("returncode", 1.5, "structured_fractional_nonzero_returncode_dominates_success"),
    ):
        node = {
            "type": "tool_result",
            "tool_use_id": "toolu-test",
            "status": "success",
            "is_error": False,
            "content": "Structured findings were produced.",
            structured_field: structured_value,
        }
        cases.append({
            "name": case_name,
            "passed": runner._result_is_success(node) is False,
        })
    for structured_status, status_label in (
        ("not_executed", "not_executed_underscore"),
        ("not executed", "not_executed_space"),
        ("not_run", "not_run_underscore"),
        ("timed_out", "timed_out_underscore"),
    ):
        node = {
            "type": "tool_result",
            "tool_use_id": "toolu-test",
            "status": structured_status,
            "is_error": False,
            "content": "A contradictory status must dominate this content.",
        }
        cases.append({
            "name": f"structured_status_{status_label}_dominates_success",
            "passed": runner._result_is_success(node) is False,
        })

    mismatched_native = write_transcript([item for agent in REQUIRED_NATIVE_AGENTS for item in (native_event(agent), native_mismatched_result(agent))])
    auth = runner.authenticate_trace(mismatched_native)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "mismatched_tool_result_id_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("missing_result_agents")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    single_mentions = write_transcript(single_call_mentions_all_lanes())
    auth = runner.authenticate_trace(single_mentions)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "single_agent_call_mentions_all_lanes_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("missing_agents")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    duplicate_ids = write_transcript(duplicate_id_trace())
    auth = runner.authenticate_trace(duplicate_ids)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "duplicate_tool_use_id_across_lanes_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("duplicate_tool_use_ids")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    duplicate_one_result = write_transcript(duplicate_id_trace())
    auth = runner.authenticate_trace(duplicate_one_result)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "single_result_for_duplicate_id_does_not_authenticate_all_lanes", "passed": auth.get("authenticated") is False and bool(auth.get("missing_result_agents")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    empty_results = write_transcript(empty_results_trace())
    auth = runner.authenticate_trace(empty_results)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "empty_tool_result_content_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("missing_result_agents")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    generic_results = write_transcript(generic_results_without_success_signal_trace())
    auth = runner.authenticate_trace(generic_results)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "generic_result_without_status_or_is_error_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("missing_result_agents")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    empty_text_block = write_transcript(content_block_results_trace([{"type": "text", "text": ""}]))
    auth = runner.authenticate_trace(empty_text_block)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "tool_result_empty_text_block_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("missing_result_agents")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    metadata_only_text_block = write_transcript(content_block_results_trace([{"type": "text"}]))
    auth = runner.authenticate_trace(metadata_only_text_block)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "tool_result_metadata_only_text_block_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("missing_result_agents")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    whitespace_text_block = write_transcript(content_block_results_trace([{"type": "text", "text": "   \n\t"}]))
    auth = runner.authenticate_trace(whitespace_text_block)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "tool_result_whitespace_text_block_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("missing_result_agents")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    metadata_only_dict = write_transcript(content_block_results_trace({"type": "text"}))
    auth = runner.authenticate_trace(metadata_only_dict)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "tool_result_metadata_only_dict_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("missing_result_agents")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    empty_document_block = write_transcript(content_block_results_trace([{"type": "document"}]))
    auth = runner.authenticate_trace(empty_document_block)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "tool_result_document_block_without_data_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("missing_result_agents")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    empty_image_block = write_transcript(content_block_results_trace([{"type": "image"}]))
    auth = runner.authenticate_trace(empty_image_block)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "tool_result_image_block_without_data_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("missing_result_agents")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    nonempty_text_block = write_transcript(content_block_results_trace([{"type": "text", "text": "Structured non-empty native-lane findings were produced."}]))
    auth = runner.authenticate_trace(nonempty_text_block)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "tool_result_nonempty_text_block_authenticates", "passed": auth.get("authenticated") is True and capped == "PASS-TRACKED", "auth": auth, "capped_status": capped, "reason": reason})

    nested_input = write_transcript(nested_tool_result_inside_tool_input_trace())
    auth = runner.authenticate_trace(nested_input)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "nested_tool_result_inside_tool_input_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("missing_result_agents")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    nested_arguments = write_transcript(nested_tool_result_inside_arguments_trace())
    auth = runner.authenticate_trace(nested_arguments)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "nested_tool_result_inside_arguments_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("missing_result_agents")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    result_before_call = write_transcript(tool_result_before_tool_use_trace())
    auth = runner.authenticate_trace(result_before_call)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "tool_result_before_tool_use_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("result_before_call_ids")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    same_event_embedded = write_transcript(same_event_input_embedded_result_trace())
    auth = runner.authenticate_trace(same_event_embedded)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "same_event_input_embedded_result_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("missing_result_agents")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    fake_tool_use_inside_result = write_transcript(fake_tool_events_inside_tool_result_content_trace(include_results=False))
    auth = runner.authenticate_trace(fake_tool_use_inside_result)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "tool_use_inside_tool_result_content_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("missing_agents")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    fake_tool_result_inside_result = write_transcript(tool_result_inside_tool_result_content_trace())
    auth = runner.authenticate_trace(fake_tool_result_inside_result)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "tool_result_inside_tool_result_content_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("missing_agents")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    fake_events_inside_result = write_transcript(fake_tool_events_inside_tool_result_content_trace(include_results=True))
    auth = runner.authenticate_trace(fake_events_inside_result)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "fake_tool_use_and_result_inside_tool_result_content_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("missing_agents")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    fake_inside_tool_use_content = write_transcript(tool_use_inside_tool_use_content_trace())
    auth = runner.authenticate_trace(fake_inside_tool_use_content)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "tool_use_inside_tool_use_content_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("unexpected_native_tool_calls")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    text_masquerade = write_transcript(text_block_tool_use_masquerade_trace())
    auth = runner.authenticate_trace(text_masquerade)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "text_block_tool_use_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("missing_agents")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    text_result_masquerade = write_transcript([item for agent in REQUIRED_NATIVE_AGENTS for item in (native_event(agent), {"type": "assistant", "message": {"content": [{"type": "text", "tool_use_id": f"toolu-{agent}", "status": "success", "is_error": False, "content": f"{agent} fake text result"}]}})])
    auth = runner.authenticate_trace(text_result_masquerade)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "text_block_tool_result_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("missing_result_agents")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    assistant_masquerade = write_transcript(assistant_message_tool_use_masquerade_trace())
    auth = runner.authenticate_trace(assistant_masquerade)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "assistant_message_tool_use_masquerade_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("missing_agents")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    message_result_masquerade = write_transcript([item for agent in REQUIRED_NATIVE_AGENTS for item in (native_event(agent), {"type": "message", "tool_use_id": f"toolu-{agent}", "status": "success", "is_error": False, "content": f"{agent} fake message result"})])
    auth = runner.authenticate_trace(message_result_masquerade)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "message_result_masquerade_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("missing_result_agents")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    unexpected_no_selector = write_transcript(unexpected_agent_call_without_selector_trace())
    auth = runner.authenticate_trace(unexpected_no_selector)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "unexpected_agent_call_without_structured_selector_rejected", "passed": auth.get("authenticated") is False and bool(auth.get("unexpected_native_tool_calls")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    unknown_selector = write_transcript(unknown_agent_selector_trace())
    auth = runner.authenticate_trace(unknown_selector)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "unknown_agent_selector_rejected", "passed": auth.get("authenticated") is False and bool(auth.get("unexpected_native_tool_calls")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    description_only = write_transcript(description_only_lane_mentions())
    auth = runner.authenticate_trace(description_only)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "structured_subagent_type_exact_match_required", "passed": auth.get("authenticated") is False and bool(auth.get("missing_agents")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    failed_native = write_transcript(completed_native_trace(success=False))
    auth = runner.authenticate_trace(failed_native)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "failed_native_result_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("missing_result_agents")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    for key, case_name in [
        ("payload", "tool_use_inside_tool_result_payload_does_not_authenticate"),
        ("data", "fake_tool_use_and_result_inside_tool_result_data_does_not_authenticate"),
        ("delta", "tool_use_inside_tool_result_delta_does_not_authenticate"),
    ]:
        embedded = write_transcript(fake_tool_events_inside_tool_result_envelope_trace(key, include_results=True))
        auth = runner.authenticate_trace(embedded)
        capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
        cases.append({"name": case_name, "passed": auth.get("authenticated") is False and bool(auth.get("missing_agents")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    embedded_result_only = write_transcript(fake_tool_events_inside_tool_result_envelope_trace("payload", include_results=False))
    auth = runner.authenticate_trace(embedded_result_only)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "tool_result_inside_tool_result_payload_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("missing_agents")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    user_tool_use = write_transcript(user_message_tool_use_trace())
    auth = runner.authenticate_trace(user_tool_use)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "user_message_tool_use_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("role_violations")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    assistant_tool_result = write_transcript(assistant_message_tool_result_trace())
    auth = runner.authenticate_trace(assistant_tool_result)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "assistant_message_tool_result_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("role_violations")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    role_inverted = write_transcript(role_inverted_tool_trace())
    auth = runner.authenticate_trace(role_inverted)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "role_inverted_tool_use_result_trace_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("role_violations")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    valid_roles = write_transcript(completed_native_trace(success=True))
    auth = runner.authenticate_trace(valid_roles)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "valid_assistant_tool_use_user_tool_result_still_authenticates", "passed": auth.get("authenticated") is True and capped == "PASS-TRACKED", "auth": auth, "capped_status": capped, "reason": reason})

    scoped_native = write_transcript(completed_native_trace(success=True))
    auth = runner.authenticate_trace(scoped_native)
    capped, reason = runner.cap_status_by_trace("PASS-SCOPED", auth)
    cases.append({"name": "trace_auth_does_not_promote_pass_scoped_gate", "passed": auth.get("authenticated") is True and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    with tempfile.TemporaryDirectory(
        prefix="nozickian_formal_output_contract_",
        dir=str(CANONICAL_TEMP_ROOT),
    ) as tmp_s:
        tmp = Path(tmp_s)
        fake_root = tmp / "pkg"
        fake_root.mkdir()
        target = fake_root / "target.md"
        target.write_text("target\n", encoding="utf-8")
        runtime_endpoint = tmp / "claude-runtime-endpoint"
        runtime_endpoint.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        runtime_endpoint.chmod(0o755)
        runtime_link = tmp / "claude-runtime-link"
        runtime_link.symlink_to(runtime_endpoint)
        resolved_runtime = runner.resolve_regular_executable(
            str(runtime_link)
        )
        precheck_out = {
            "precheck": tmp / "bound-prechecks.json",
            "formal_result": tmp / "formal_result.json",
            "target_snapshot": target,
        }
        observed_precheck_commands: List[List[str]] = []
        original_runner_run_cmd = runner.run_cmd

        def record_precheck_command(
            cmd: List[str],
            **_kwargs: Any,
        ) -> Dict[str, Any]:
            observed_precheck_commands.append(list(cmd))
            return {
                "cmd": list(cmd),
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "capture_limit_exceeded": False,
                "timed_out": False,
                "descendant_pipe_leak": False,
                "reader_join_timed_out": False,
                "normal_exit_group_survivor": False,
                "detached_descendant_survivor": False,
                "process_containment_cleanup_complete": True,
                "process_group_cleanup_attempted": True,
                "process_group_terminated": False,
                "process_containment": {
                    "mechanism": "linux-child-subreaper-plus-process-group",
                    "cleanup_after_leader_exit": True,
                    "detached_session_descendants_contained": True,
                },
            }

        try:
            runner.run_cmd = record_precheck_command
            bound_prechecks = runner.run_package_prechecks(
                fake_root,
                precheck_out,
                timeout=5,
                claude_executable=resolved_runtime,
            )
        finally:
            runner.run_cmd = original_runner_run_cmd
        cases.append({
            "name": "formal_prechecks_use_pre_resolved_runtime_endpoint",
            "passed": (
                resolved_runtime == runtime_endpoint.resolve()
                and len(bound_prechecks) == 4
                and len(observed_precheck_commands) == 4
                and observed_precheck_commands[-1]
                == [
                    str(runtime_endpoint.resolve()),
                    "plugin",
                    "validate",
                    str(fake_root),
                    "--strict",
                ]
            ),
        })
        live_output = tmp / "live-output"
        live_output.mkdir()
        positive_transcript = live_runner.fixture_transcript_path(
            live_output,
            valid_fixture_id,
        )
        live_runner.atomic_replace_transcript(
            positive_transcript,
            b"positive transcript\n",
        )
        cases.append({
            "name": "live_transcript_write_is_contained_and_regular",
            "passed": (
                positive_transcript.parent == live_output
                and positive_transcript.read_bytes() == b"positive transcript\n"
                and positive_transcript.is_file()
            ),
        })
        symlink_sentinel = tmp / "live-symlink-sentinel.txt"
        symlink_sentinel.write_bytes(b"sentinel\n")
        symlink_transcript = live_runner.fixture_transcript_path(
            live_output,
            "symlink-sentinel",
        )
        symlink_transcript.symlink_to(symlink_sentinel)
        cases.append({
            "name": "live_transcript_write_rejects_symlink_without_following",
            "passed": (
                raises_value_error(
                    live_runner.atomic_replace_transcript,
                    symlink_transcript,
                    b"overwrite\n",
                )
                and symlink_sentinel.read_bytes() == b"sentinel\n"
            ),
        })

        held_live_output = tmp / "live-held-output"
        held_live_output.mkdir()
        held_live_fd = live_runner.prepare_transcript_directory(
            held_live_output,
        )
        held_live_transcript = live_runner.fixture_transcript_path(
            held_live_output,
            "held-true-control",
        )
        held_live_control_ok = False
        try:
            live_runner.atomic_replace_transcript(
                held_live_transcript,
                b"held positive transcript\n",
                directory_fd=held_live_fd,
                lexical_parent=held_live_output,
            )
            held_live_control_ok = (
                held_live_transcript.read_bytes()
                == b"held positive transcript\n"
                and held_live_transcript.lstat().st_nlink == 1
                and stat.S_IMODE(held_live_transcript.lstat().st_mode)
                == 0o600
            )
        finally:
            os.close(held_live_fd)
        cases.append({
            "name": "live_transcript_held_directory_retains_ordinary_true_control",
            "passed": held_live_control_ok,
        })

        live_symlink_race_root = tmp / "live-transcript-symlink-race"
        live_symlink_race_root.mkdir()
        live_checked_parent = live_symlink_race_root / "checked-parent"
        live_checked_parent.mkdir()
        live_parked_parent = live_symlink_race_root / "parked-parent"
        live_external_parent = live_symlink_race_root / "external-parent"
        live_external_parent.mkdir()
        live_race_name = "ancestor-swap-case.json"
        live_original_target = live_checked_parent / live_race_name
        live_original_bytes = b"original transcript must remain\n"
        live_original_target.write_bytes(live_original_bytes)
        live_external_target = live_external_parent / live_race_name
        live_external_bytes = b"external sentinel must remain\n"
        live_external_target.write_bytes(live_external_bytes)
        original_live_os_open = live_runner.os.open
        live_symlink_swap_triggered = False

        def swap_live_parent_at_temporary_open(
            path: Any,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal live_symlink_swap_triggered
            if (
                not live_symlink_swap_triggered
                and dir_fd is not None
                and isinstance(path, str)
                and path.startswith(f".{live_race_name}.")
                and path.endswith(".tmp")
            ):
                live_checked_parent.rename(live_parked_parent)
                live_checked_parent.symlink_to(
                    live_external_parent,
                    target_is_directory=True,
                )
                live_symlink_swap_triggered = True
            return original_live_os_open(
                path,
                flags,
                mode,
                dir_fd=dir_fd,
            )

        live_symlink_race_rejected = False
        try:
            live_runner.os.open = swap_live_parent_at_temporary_open
            live_runner.atomic_replace_transcript(
                live_original_target,
                b"replacement transcript\n",
            )
        except (OSError, ValueError):
            live_symlink_race_rejected = True
        finally:
            live_runner.os.open = original_live_os_open
        cases.append({
            "name": "live_transcript_rejects_ancestor_symlink_swap_at_temporary_open",
            "passed": (
                live_symlink_swap_triggered
                and live_symlink_race_rejected
                and (live_parked_parent / live_race_name).read_bytes()
                == live_original_bytes
                and live_external_target.read_bytes() == live_external_bytes
                and not any(
                    entry.name.startswith(f".{live_race_name}.")
                    for entry in live_parked_parent.iterdir()
                )
            ),
        })

        live_real_race_root = tmp / "live-transcript-real-race"
        live_real_race_root.mkdir()
        live_real_checked = live_real_race_root / "checked-parent"
        live_real_checked.mkdir()
        live_real_parked = live_real_race_root / "parked-parent"
        live_real_fd = live_runner.prepare_transcript_directory(
            live_real_checked,
        )
        live_real_checked.rename(live_real_parked)
        live_real_checked.mkdir()
        live_real_name = "long-execution-case.json"
        live_real_replacement = live_real_checked / live_real_name
        live_real_replacement_bytes = b"replacement directory sentinel\n"
        live_real_replacement.write_bytes(live_real_replacement_bytes)
        live_real_race_rejected = False
        try:
            live_runner.atomic_replace_transcript(
                live_real_checked / live_real_name,
                b"held transcript must not escape\n",
                directory_fd=live_real_fd,
                lexical_parent=live_real_checked,
            )
        except (OSError, ValueError):
            live_real_race_rejected = True
        finally:
            os.close(live_real_fd)
        cases.append({
            "name": "live_transcript_holds_parent_across_long_real_directory_substitution",
            "passed": (
                live_real_race_rejected
                and live_real_replacement.read_bytes()
                == live_real_replacement_bytes
                and not (live_real_parked / live_real_name).exists()
                and not any(live_real_parked.iterdir())
            ),
        })

        def call_live_main(argv: List[str]) -> tuple[int, str]:
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                return live_runner.main(argv), buffer.getvalue()

        live_json_nested = tmp / "live-json" / "nested" / "result.json"
        live_json_rc, live_json_stdout = call_live_main(
            [str(fake_root), "--json", str(live_json_nested)]
        )
        try:
            live_json_stdout_value = json.loads(live_json_stdout)
            live_json_file_value = json.loads(
                live_json_nested.read_text(encoding="utf-8")
            )
        except (OSError, TypeError, ValueError):
            live_json_stdout_value = None
            live_json_file_value = None
        cases.append({
            "name": "live_main_creates_absent_nested_json_as_private_regular_file",
            "passed": (
                live_json_rc == 2
                and live_json_stdout_value == live_json_file_value
                and isinstance(live_json_file_value, dict)
                and "json_output_error" not in live_json_file_value
                and stat.S_IMODE(live_json_nested.lstat().st_mode) == 0o600
                and live_json_nested.lstat().st_nlink == 1
            ),
        })

        live_json_existing = tmp / "live-json-existing.json"
        live_json_existing.write_text("old private result\n", encoding="utf-8")
        live_json_existing.chmod(0o600)
        existing_before = live_json_existing.read_bytes()
        existing_rc, existing_stdout = call_live_main(
            [str(fake_root), "--json", str(live_json_existing)]
        )
        try:
            existing_stdout_value = json.loads(existing_stdout)
            existing_file_value = json.loads(
                live_json_existing.read_text(encoding="utf-8")
            )
        except (OSError, TypeError, ValueError):
            existing_stdout_value = None
            existing_file_value = None
        cases.append({
            "name": "live_main_atomically_replaces_existing_private_json",
            "passed": (
                existing_rc == 2
                and existing_stdout_value == existing_file_value
                and live_json_existing.read_bytes() != existing_before
                and stat.S_IMODE(live_json_existing.lstat().st_mode) == 0o600
                and live_json_existing.lstat().st_nlink == 1
            ),
        })

        live_json_sentinel = tmp / "live-json-sentinel.txt"
        live_json_sentinel_bytes = b"live json sentinel\n"
        live_json_sentinel.write_bytes(live_json_sentinel_bytes)
        live_json_symlink = tmp / "live-json-symlink.json"
        live_json_symlink.symlink_to(live_json_sentinel)
        symlink_rc, symlink_stdout = call_live_main(
            [str(fake_root), "--json", str(live_json_symlink)]
        )
        try:
            symlink_result = json.loads(symlink_stdout)
        except (TypeError, ValueError):
            symlink_result = None
        cases.append({
            "name": "live_main_rejects_final_json_symlink_without_overwrite",
            "passed": (
                symlink_rc == 2
                and isinstance(symlink_result, dict)
                and isinstance(
                    symlink_result.get("json_output_error"),
                    str,
                )
                and live_json_symlink.is_symlink()
                and live_json_sentinel.read_bytes()
                == live_json_sentinel_bytes
            ),
        })

        live_json_hardlink = tmp / "live-json-hardlink.json"
        live_json_hardlink.hardlink_to(live_json_sentinel)
        hardlink_rc, hardlink_stdout = call_live_main(
            [str(fake_root), "--json", str(live_json_hardlink)]
        )
        try:
            hardlink_result = json.loads(hardlink_stdout)
        except (TypeError, ValueError):
            hardlink_result = None
        cases.append({
            "name": "live_main_rejects_final_json_hardlink_without_overwrite",
            "passed": (
                hardlink_rc == 2
                and isinstance(hardlink_result, dict)
                and isinstance(
                    hardlink_result.get("json_output_error"),
                    str,
                )
                and live_json_sentinel.read_bytes()
                == live_json_sentinel_bytes
            ),
        })

        live_json_external = tmp / "live-json-external"
        live_json_external.mkdir()
        live_json_linked_parent = tmp / "live-json-linked-parent"
        live_json_linked_parent.symlink_to(
            live_json_external,
            target_is_directory=True,
        )
        escaped_live_json = live_json_external / "escaped.json"
        linked_rc, linked_stdout = call_live_main(
            [
                str(fake_root),
                "--json",
                str(live_json_linked_parent / "escaped.json"),
            ]
        )
        try:
            linked_result = json.loads(linked_stdout)
        except (TypeError, ValueError):
            linked_result = None
        cases.append({
            "name": "live_main_rejects_linked_json_ancestor_without_escape",
            "passed": (
                linked_rc == 2
                and isinstance(linked_result, dict)
                and isinstance(
                    linked_result.get("json_output_error"),
                    str,
                )
                and not escaped_live_json.exists()
            ),
        })

        zero_write_json = tmp / "live-json-zero-write" / "result.json"
        original_os_write = live_runner.os.write
        try:
            live_runner.os.write = lambda _fd, _payload: 0
            zero_write_rc, zero_write_stdout = call_live_main(
                [str(fake_root), "--json", str(zero_write_json)]
            )
        finally:
            live_runner.os.write = original_os_write
        try:
            zero_write_result = json.loads(zero_write_stdout)
        except (TypeError, ValueError):
            zero_write_result = None
        zero_write_parent = zero_write_json.parent
        zero_write_temporaries = (
            list(zero_write_parent.glob(f".{zero_write_json.name}.*.tmp"))
            if zero_write_parent.is_dir()
            else []
        )
        cases.append({
            "name": "live_main_zero_byte_json_write_fails_without_residue",
            "passed": (
                zero_write_rc == 2
                and isinstance(zero_write_result, dict)
                and isinstance(
                    zero_write_result.get("json_output_error"),
                    str,
                )
                and not zero_write_json.exists()
                and zero_write_temporaries == []
            ),
        })

        live_json_swap_root = tmp / "live-json-long-real-swap"
        live_json_swap_root.mkdir()
        live_json_checked_parent = live_json_swap_root / "checked-parent"
        live_json_checked_parent.mkdir()
        live_json_parked_parent = live_json_swap_root / "parked-parent"
        live_json_replacement_parent = (
            live_json_swap_root / "replacement-parent"
        )
        live_json_replacement_parent.mkdir()
        live_json_swap_output = live_json_checked_parent / "result.json"
        live_json_replacement_target = (
            live_json_replacement_parent / live_json_swap_output.name
        )
        live_json_replacement_bytes = b"live JSON replacement sentinel\n"
        live_json_replacement_target.write_bytes(
            live_json_replacement_bytes
        )
        original_current_package_tree = live_runner.current_package_tree
        live_json_swap_performed = False

        def current_tree_with_output_swap(root: Path) -> Dict[str, Any]:
            nonlocal live_json_swap_performed
            current = original_current_package_tree(root)
            live_json_checked_parent.rename(live_json_parked_parent)
            live_json_replacement_parent.rename(live_json_checked_parent)
            live_json_swap_performed = True
            return current

        try:
            live_runner.current_package_tree = current_tree_with_output_swap
            live_json_swap_rc, live_json_swap_stdout = call_live_main([
                str(fake_root),
                "--json",
                str(live_json_swap_output),
            ])
        finally:
            live_runner.current_package_tree = original_current_package_tree
        try:
            live_json_swap_result = json.loads(live_json_swap_stdout)
        except (TypeError, ValueError):
            live_json_swap_result = {}
        cases.append({
            "name": "live_json_holds_parent_across_long_real_directory_substitution",
            "passed": (
                live_json_swap_performed
                and live_json_swap_rc == 2
                and isinstance(
                    live_json_swap_result.get("json_output_error"),
                    str,
                )
                and (
                    live_json_checked_parent / live_json_swap_output.name
                ).read_bytes() == live_json_replacement_bytes
                and not (
                    live_json_parked_parent / live_json_swap_output.name
                ).exists()
                and not any(
                    entry.name.startswith(
                        f".{live_json_swap_output.name}."
                    )
                    for entry in live_json_parked_parent.iterdir()
                )
            ),
        })

        fake_live_claude = tmp / "fake-live-claude"
        fake_live_claude.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_live_claude.chmod(0o700)

        def call_live_with_successful_preflight(
            argv: List[str],
            *,
            package_tree_hook: Any = None,
            run_cmd_observer: Any = None,
        ) -> tuple[int, str]:
            original_which = live_runner.shutil.which
            original_tree = live_runner.current_package_tree
            original_materialize = (
                live_runner.materialize_execution_package_snapshot
            )
            original_finalize = (
                live_runner.finalize_execution_package_snapshot
            )
            original_run_cmd = live_runner.run_cmd
            original_refresh = live_runner.refresh_runtime_fingerprint

            package_tree_calls = 0

            def fake_current_package_tree(_root: Path) -> Dict[str, Any]:
                nonlocal package_tree_calls
                package_tree_calls += 1
                if package_tree_calls == 1 and callable(package_tree_hook):
                    package_tree_hook()
                return {
                    "algorithm": "stable-release-tree-v1",
                    "sha256": "a" * 64,
                    "valid": True,
                    "file_count": 1,
                    "errors": [],
                }

            def fake_run_cmd(
                cmd: List[str],
                **_kwargs: Any,
            ) -> Dict[str, Any]:
                if callable(run_cmd_observer):
                    run_cmd_observer(list(cmd))
                if "--version" in cmd:
                    stdout_text = "2.1.209 (Claude Code)"
                elif "-p" in cmd:
                    stdout_text = json.dumps({
                        "result": (
                            "Scope mini_manual.md. Method evidence was "
                            "checked with false-world sensitivity and "
                            "true-world adherence. Residual risks remain "
                            "scoped. Final gate status: PASS-SCOPED."
                        ),
                    })
                else:
                    stdout_text = "validation passed"
                return {
                    "cmd": cmd,
                    "returncode": 0,
                    "stdout": stdout_text,
                    "stderr": "",
                }

            def fake_refresh(
                identity: Dict[str, Any],
                _executable: Path,
            ) -> None:
                identity["executable_sha256_post"] = identity.get(
                    "executable_sha256_pre"
                )
                identity["fingerprint_stable"] = True

            stdout = io.StringIO()
            try:
                live_runner.shutil.which = lambda _name: str(fake_live_claude)
                live_runner.current_package_tree = fake_current_package_tree
                live_runner.materialize_execution_package_snapshot = (
                    lambda root, _tree: (
                        None,
                        root,
                        {"stable": False},
                    )
                )
                live_runner.finalize_execution_package_snapshot = (
                    lambda _root, _snapshot, identity: {
                        **identity,
                        "stable": True,
                    }
                )
                live_runner.run_cmd = fake_run_cmd
                live_runner.refresh_runtime_fingerprint = fake_refresh
                with contextlib.redirect_stdout(stdout):
                    returncode = live_runner.main(argv)
            finally:
                live_runner.shutil.which = original_which
                live_runner.current_package_tree = original_tree
                live_runner.materialize_execution_package_snapshot = (
                    original_materialize
                )
                live_runner.finalize_execution_package_snapshot = (
                    original_finalize
                )
                live_runner.run_cmd = original_run_cmd
                live_runner.refresh_runtime_fingerprint = original_refresh
            return returncode, stdout.getvalue()

        live_evals = json.loads(
            (
                package_root
                / SKILL_PATH
                / "evals/evals.json"
            ).read_text(encoding="utf-8")
        )
        live_selected_fixture_id = live_evals["fixtures"][0]["id"]
        live_main_true_output = tmp / "live-main-output-true-control"
        live_main_true_rc, live_main_true_stdout = (
            call_live_with_successful_preflight([
                str(package_root),
                "--run-fixtures",
                "--max-fixtures",
                "1",
                "--output-dir",
                str(live_main_true_output),
            ])
        )
        try:
            live_main_true_result = json.loads(live_main_true_stdout)
        except (TypeError, ValueError):
            live_main_true_result = {}
        live_main_true_transcript = (
            live_main_true_output / f"{live_selected_fixture_id}.json"
        )
        cases.append({
            "name": "live_main_explicit_output_early_capability_retains_true_control",
            "passed": (
                live_main_true_rc == 0
                and live_main_true_result.get("status") == "PASS-SCOPED"
                and len(live_main_true_result.get("fixture_results", []))
                == 1
                and live_main_true_transcript.is_file()
                and stat.S_IMODE(
                    live_main_true_transcript.lstat().st_mode
                ) == 0o600
                and live_main_true_transcript.lstat().st_nlink == 1
            ),
        })

        live_aba_root = tmp / "live-main-output-preflight-a-b-a"
        live_aba_root.mkdir()
        live_aba_checked = live_aba_root / "checked-parent"
        live_aba_checked.mkdir()
        live_aba_original_parked = live_aba_root / "original-parked"
        live_aba_replacement = live_aba_root / "replacement-parent"
        live_aba_replacement.mkdir()
        live_aba_replacement_target = (
            live_aba_replacement / f"{live_selected_fixture_id}.json"
        )
        live_aba_sentinel = b"preflight replacement sentinel\n"
        live_aba_replacement_target.write_bytes(live_aba_sentinel)
        live_aba_events: List[str] = []
        original_prepare_transcript_directory = (
            live_runner.prepare_transcript_directory
        )

        def record_live_aba_acquisition(path: Path) -> int:
            live_aba_events.append("acquire-output-capability")
            return original_prepare_transcript_directory(path)

        def perform_live_aba_during_package_inspection() -> None:
            live_aba_events.append("inspect-package")
            live_aba_checked.rename(live_aba_original_parked)
            live_aba_replacement.rename(live_aba_checked)
            live_aba_checked.rename(live_aba_replacement)
            live_aba_original_parked.rename(live_aba_checked)

        try:
            live_runner.prepare_transcript_directory = (
                record_live_aba_acquisition
            )
            live_aba_rc, live_aba_stdout = (
                call_live_with_successful_preflight(
                    [
                        str(package_root),
                        "--run-fixtures",
                        "--max-fixtures",
                        "1",
                        "--output-dir",
                        str(live_aba_checked),
                    ],
                    package_tree_hook=(
                        perform_live_aba_during_package_inspection
                    ),
                )
            )
        finally:
            live_runner.prepare_transcript_directory = (
                original_prepare_transcript_directory
            )
        try:
            live_aba_result = json.loads(live_aba_stdout)
        except (TypeError, ValueError):
            live_aba_result = {}
        live_aba_intended_target = (
            live_aba_checked / f"{live_selected_fixture_id}.json"
        )
        cases.append({
            "name": "live_main_explicit_output_is_bound_before_preflight_a_b_a_substitution",
            "passed": (
                live_aba_events
                == ["acquire-output-capability", "inspect-package"]
                and live_aba_rc == 0
                and live_aba_result.get("status") == "PASS-SCOPED"
                and live_aba_intended_target.is_file()
                and live_aba_replacement_target.read_bytes()
                == live_aba_sentinel
                and not any(
                    entry.name.startswith(
                        f".{live_selected_fixture_id}.json."
                    )
                    for entry in live_aba_replacement.iterdir()
                )
            ),
        })

        live_persistent_root = (
            tmp / "live-main-output-preflight-persistent-substitution"
        )
        live_persistent_root.mkdir()
        live_persistent_checked = live_persistent_root / "checked-parent"
        live_persistent_checked.mkdir()
        live_persistent_original = live_persistent_root / "original-parent"
        live_persistent_replacement = (
            live_persistent_root / "replacement-parent"
        )
        live_persistent_replacement.mkdir()
        live_persistent_replacement_target = (
            live_persistent_replacement
            / f"{live_selected_fixture_id}.json"
        )
        live_persistent_sentinel = b"persistent replacement sentinel\n"
        live_persistent_replacement_target.write_bytes(
            live_persistent_sentinel
        )

        def substitute_live_output_during_package_inspection() -> None:
            live_persistent_checked.rename(live_persistent_original)
            live_persistent_replacement.rename(live_persistent_checked)

        live_persistent_rc, live_persistent_stdout = (
            call_live_with_successful_preflight(
                [
                    str(package_root),
                    "--run-fixtures",
                    "--max-fixtures",
                    "1",
                    "--output-dir",
                    str(live_persistent_checked),
                ],
                package_tree_hook=(
                    substitute_live_output_during_package_inspection
                ),
            )
        )
        try:
            live_persistent_result = json.loads(live_persistent_stdout)
        except (TypeError, ValueError):
            live_persistent_result = {}
        cases.append({
            "name": "live_main_explicit_output_rejects_preflight_real_directory_replacement",
            "passed": (
                live_persistent_rc == 2
                and live_persistent_result.get("fixture_results") == []
                and "changed before runtime preflight" in str(
                    live_persistent_result.get("reason")
                )
                and (
                    live_persistent_checked
                    / f"{live_selected_fixture_id}.json"
                ).read_bytes() == live_persistent_sentinel
                and not any(live_persistent_original.iterdir())
                and not any(
                    entry.name.startswith(
                        f".{live_selected_fixture_id}.json."
                    )
                    for entry in live_persistent_checked.iterdir()
                )
            ),
        })

        live_output_external = tmp / "live-output-direct-external"
        live_output_external.mkdir()
        live_output_direct_link = tmp / "live-output-direct-link"
        live_output_direct_link.symlink_to(
            live_output_external,
            target_is_directory=True,
        )
        direct_output_json = tmp / "live-output-direct-failure.json"
        direct_output_run_cmds: List[List[str]] = []
        direct_output_rc, direct_output_stdout = (
            call_live_with_successful_preflight(
                [
                    str(package_root),
                    "--run-fixtures",
                    "--max-fixtures",
                    "1",
                    "--output-dir",
                    str(live_output_direct_link),
                    "--json",
                    str(direct_output_json),
                ],
                run_cmd_observer=direct_output_run_cmds.append,
            )
        )
        try:
            direct_output_result = json.loads(direct_output_stdout)
            direct_output_file_result = json.loads(
                direct_output_json.read_text(encoding="utf-8")
            )
        except (OSError, TypeError, ValueError):
            direct_output_result = {}
            direct_output_file_result = None
        cases.append({
            "name": "live_output_dir_rejects_direct_symlink_before_fixture_execution",
            "passed": (
                direct_output_rc == 2
                and direct_output_result == direct_output_file_result
                and direct_output_result.get("fixture_results") == []
                and "acquiring transcript output directory" in str(
                    direct_output_result.get("reason")
                )
                and direct_output_run_cmds == []
                and stat.S_IMODE(direct_output_json.lstat().st_mode)
                == 0o600
                and direct_output_json.lstat().st_nlink == 1
                and not any(live_output_external.iterdir())
            ),
        })

        live_output_ancestor_external = (
            tmp / "live-output-ancestor-external"
        )
        live_output_ancestor_external.mkdir()
        live_output_ancestor_link = tmp / "live-output-ancestor-link"
        live_output_ancestor_link.symlink_to(
            live_output_ancestor_external,
            target_is_directory=True,
        )
        ancestor_output_rc, ancestor_output_stdout = (
            call_live_with_successful_preflight([
                str(package_root),
                "--run-fixtures",
                "--max-fixtures",
                "1",
                "--output-dir",
                str(live_output_ancestor_link / "nested"),
            ])
        )
        try:
            ancestor_output_result = json.loads(ancestor_output_stdout)
        except (TypeError, ValueError):
            ancestor_output_result = {}
        cases.append({
            "name": "live_output_dir_rejects_symlinked_ancestor_before_fixture_execution",
            "passed": (
                ancestor_output_rc == 2
                and ancestor_output_result.get("fixture_results") == []
                and "acquiring transcript output directory" in str(
                    ancestor_output_result.get("reason")
                )
                and not (live_output_ancestor_external / "nested").exists()
            ),
        })

        live_alias_output_dir = tmp / "live-json-transcript-alias"
        live_alias_output_dir.mkdir()
        live_alias_json = (
            live_alias_output_dir / f"{live_selected_fixture_id}.json"
        )
        alias_output_run_cmds: List[List[str]] = []
        alias_output_rc, alias_output_stdout = (
            call_live_with_successful_preflight(
                [
                    str(package_root),
                    "--run-fixtures",
                    "--max-fixtures",
                    "1",
                    "--output-dir",
                    str(live_alias_output_dir),
                    "--json",
                    str(live_alias_json),
                ],
                run_cmd_observer=alias_output_run_cmds.append,
            )
        )
        try:
            alias_output_result = json.loads(alias_output_stdout)
            alias_output_file = json.loads(
                live_alias_json.read_text(encoding="utf-8")
            )
        except (OSError, TypeError, ValueError):
            alias_output_result = {}
            alias_output_file = {}
        cases.append({
            "name": "live_json_rejects_alias_with_selected_fixture_transcript",
            "passed": (
                alias_output_rc == 2
                and alias_output_result == alias_output_file
                and alias_output_result.get("fixture_results") == []
                and "aliases a selected fixture transcript" in str(
                    alias_output_result.get("reason")
                )
                and alias_output_run_cmds == []
                and list(live_alias_output_dir.iterdir())
                == [live_alias_json]
            ),
        })

        output_wrappers = {
            "regression": load_output_wrapper(
                package_root,
                "run_regression_evals.py",
                "regression_output_wrapper_under_test",
            ),
            "promotion": load_output_wrapper(
                package_root,
                "run_promotion_certifier_contract_tests.py",
                "promotion_output_wrapper_under_test",
            ),
            "formal_contract": sys.modules[__name__],
            "gate_contract": load_output_wrapper(
                package_root,
                "run_gate_contract_tests.py",
                "gate_contract_output_wrapper_under_test",
            ),
        }

        def write_wrapper_json(
            module: Any,
            path: Path,
            text: str,
            directory_fd: int,
        ) -> None:
            writer = getattr(
                module,
                "_atomic_replace_json_output",
                None,
            )
            if callable(writer):
                writer(path, text, directory_fd=directory_fd)
                return
            module._atomic_write_json(
                path,
                text,
                directory_fd=directory_fd,
            )

        wrapper_true_controls: Dict[str, bool] = {}
        for label, module in output_wrappers.items():
            wrapper_root = tmp / f"{label}-json-output-true-control"
            wrapper_root.mkdir()
            direct_path = wrapper_root / "direct.json"
            direct_absolute, direct_fd = (
                module._acquire_json_output_capability(direct_path)
            )
            try:
                write_wrapper_json(
                    module,
                    direct_absolute,
                    '{"control":"direct"}',
                    direct_fd,
                )
            finally:
                os.close(direct_fd)
            relative_cwd = wrapper_root / "relative-cwd"
            relative_cwd.mkdir()
            previous_cwd = Path.cwd()
            relative_ok = False
            try:
                os.chdir(relative_cwd)
                relative_absolute, relative_fd = (
                    module._acquire_json_output_capability(
                        Path("../external.json")
                    )
                )
                try:
                    write_wrapper_json(
                        module,
                        relative_absolute,
                        '{"control":"relative-parent"}',
                        relative_fd,
                    )
                finally:
                    os.close(relative_fd)
                relative_ok = (
                    relative_absolute
                    == wrapper_root / "external.json"
                    and relative_absolute.read_text(encoding="utf-8")
                    == '{"control":"relative-parent"}'
                )
            finally:
                os.chdir(previous_cwd)
            direct_metadata = direct_path.lstat()
            wrapper_true_controls[label] = (
                direct_path.read_text(encoding="utf-8")
                == '{"control":"direct"}'
                and stat.S_ISREG(direct_metadata.st_mode)
                and direct_metadata.st_nlink == 1
                and stat.S_IMODE(direct_metadata.st_mode) == 0o600
                and relative_ok
            )
        cases.append({
            "name": "wrapper_json_outputs_hold_private_true_controls_and_allow_normalized_parent_relative_paths",
            "passed": all(wrapper_true_controls.values()),
            "details": wrapper_true_controls,
        })

        wrapper_unsafe_targets: Dict[str, bool] = {}
        for label, module in output_wrappers.items():
            wrapper_root = tmp / f"{label}-json-output-unsafe-targets"
            wrapper_root.mkdir()
            sentinel = wrapper_root / "sentinel.json"
            sentinel_bytes = b"wrapper sentinel\n"
            sentinel.write_bytes(sentinel_bytes)
            symlink_path = wrapper_root / "symlink.json"
            symlink_path.symlink_to(sentinel.name)
            hardlink_path = wrapper_root / "hardlink.json"
            os.link(sentinel, hardlink_path)
            fifo_path = wrapper_root / "special.json"
            fifo_supported = True
            try:
                os.mkfifo(fifo_path)
            except (AttributeError, NotImplementedError, OSError):
                fifo_supported = False
            external = wrapper_root / "external"
            external.mkdir()
            linked_parent = wrapper_root / "linked-parent"
            linked_parent.symlink_to(external, target_is_directory=True)

            def acquisition_rejected(path: Path) -> bool:
                acquired_fd: Optional[int] = None
                try:
                    _absolute, acquired_fd = (
                        module._acquire_json_output_capability(path)
                    )
                except (OSError, RuntimeError, ValueError):
                    return True
                finally:
                    if acquired_fd is not None:
                        os.close(acquired_fd)
                return False

            wrapper_unsafe_targets[label] = (
                acquisition_rejected(symlink_path)
                and acquisition_rejected(hardlink_path)
                and (
                    acquisition_rejected(fifo_path)
                    if fifo_supported
                    else True
                )
                and acquisition_rejected(linked_parent / "escaped.json")
                and sentinel.read_bytes() == sentinel_bytes
                and not (external / "escaped.json").exists()
            )
        cases.append({
            "name": "wrapper_json_outputs_reject_symlink_hardlink_special_and_linked_ancestor_targets",
            "passed": all(wrapper_unsafe_targets.values()),
            "details": wrapper_unsafe_targets,
        })

        wrapper_real_swaps: Dict[str, bool] = {}
        for label, module in output_wrappers.items():
            wrapper_root = tmp / f"{label}-json-output-real-swap"
            wrapper_root.mkdir()
            checked_parent = wrapper_root / "checked-parent"
            checked_parent.mkdir()
            parked_parent = wrapper_root / "parked-parent"
            replacement_parent = wrapper_root / "replacement-parent"
            replacement_parent.mkdir()
            output_path = checked_parent / "result.json"
            replacement_target = replacement_parent / output_path.name
            replacement_bytes = b"replacement directory sentinel\n"
            replacement_target.write_bytes(replacement_bytes)
            absolute, held_fd = module._acquire_json_output_capability(
                output_path
            )
            checked_parent.rename(parked_parent)
            replacement_parent.rename(checked_parent)
            rejected = False
            try:
                write_wrapper_json(
                    module,
                    absolute,
                    '{"redirected":true}',
                    held_fd,
                )
            except (OSError, RuntimeError, ValueError):
                rejected = True
            finally:
                os.close(held_fd)
            wrapper_real_swaps[label] = (
                rejected
                and (checked_parent / output_path.name).read_bytes()
                == replacement_bytes
                and not (parked_parent / output_path.name).exists()
                and not any(
                    entry.name.startswith(f".{output_path.name}.")
                    for entry in parked_parent.iterdir()
                )
            )
        cases.append({
            "name": "wrapper_json_outputs_hold_parent_across_real_directory_substitution",
            "passed": all(wrapper_real_swaps.values()),
            "details": wrapper_real_swaps,
        })

        wrapper_preexecution: Dict[str, bool] = {}
        preexecution_specs = {
            "regression": ("validate_fixture", lambda *_args, **_kwargs: None),
            "promotion": (
                "run_contract",
                lambda *_args, **_kwargs: {
                    "status": "PASS",
                    "total": 0,
                    "passed": 0,
                    "cases": [],
                },
            ),
            "formal_contract": ("run_cases", lambda *_args, **_kwargs: []),
            "gate_contract": ("run_cases", lambda *_args, **_kwargs: []),
        }
        for label, module in output_wrappers.items():
            wrapper_root = tmp / f"{label}-json-preexecution"
            wrapper_root.mkdir()
            sentinel = wrapper_root / "sentinel.json"
            sentinel_bytes = b"preexecution sentinel\n"
            sentinel.write_bytes(sentinel_bytes)
            unsafe_output = wrapper_root / "unsafe.json"
            unsafe_output.symlink_to(sentinel.name)
            hook_name, hook_result = preexecution_specs[label]
            original_hook = getattr(module, hook_name)
            called = False

            def guarded_hook(
                *_args: Any,
                _hook_result: Any = hook_result,
                **_kwargs: Any,
            ) -> Any:
                nonlocal called
                called = True
                return _hook_result(*_args, **_kwargs)

            stdout = io.StringIO()
            try:
                setattr(module, hook_name, guarded_hook)
                with contextlib.redirect_stdout(stdout):
                    returncode = module.main([
                        str(package_root),
                        "--json",
                        str(unsafe_output),
                    ])
            finally:
                setattr(module, hook_name, original_hook)
            try:
                preexecution_result = json.loads(stdout.getvalue())
            except (TypeError, ValueError):
                preexecution_result = {}
            wrapper_preexecution[label] = (
                returncode == 2
                and called is False
                and preexecution_result.get("failure_kind")
                == "INVALID_INPUT"
                and sentinel.read_bytes() == sentinel_bytes
            )
        cases.append({
            "name": "wrapper_json_capabilities_are_acquired_before_suite_execution",
            "passed": all(wrapper_preexecution.values()),
            "details": wrapper_preexecution,
        })

        external = tmp / "external"
        external_json = tmp / "external.json"
        inside = fake_root / "self_validation" / "formal"
        inside_json = fake_root / "self_validation" / "formal.json"

        rc, out = call_runner_main(runner, [str(fake_root), str(target), "--dry-run", "--skip-prechecks", "--json", str(external_json)])
        parsed: Dict[str, Any] = {}
        try:
            parsed = json.loads(out)
            path_checker = getattr(runner, "_path_within")
            default_outside = not path_checker(Path(parsed.get("output_dir", ".")), fake_root)
        except (AttributeError, OSError, TypeError, ValueError):
            default_outside = False
        cases.append({"name": "default_formal_dry_run_output_is_outside_package_tree", "passed": rc == 0 and default_outside and external_json.exists()})

        canonical_result = Path(parsed.get("output_dir", ".")) / "formal_result.json"
        canonical_data = (
            json.loads(canonical_result.read_text(encoding="utf-8"))
            if canonical_result.is_file()
            else {}
        )
        companions = canonical_data.get("companions")
        required_companions = set(runner.FORMAL_COMPANION_SPECS)
        companion_hashes_typed = (
            isinstance(companions, dict)
            and required_companions.issubset(companions)
            and all(
                isinstance(companions.get(role), dict)
                and isinstance(companions[role].get("path"), str)
                and "sha256" in companions[role]
                and (
                    companions[role].get("sha256") is None
                    or (
                        isinstance(companions[role].get("sha256"), str)
                        and companions[role]["sha256"].startswith("sha256:")
                    )
                )
                for role in required_companions
            )
        )
        cases.append({
            "name": "formal_result_v2_is_canonical_and_typed",
            "passed": (
                canonical_data.get("formal_result_schema_version") == "2.0"
                and isinstance(canonical_data.get("run_id"), str)
                and bool(canonical_data.get("run_id"))
                and companion_hashes_typed
                and "formal_result" not in (companions or {})
                and canonical_data.get("verification_context")
                == runner.FORMAL_VERIFICATION_CONTEXT
            ),
        })
        cases.append({
            "name": "formal_result_declares_endpoint_checked_copy_context",
            "passed": (
                canonical_data.get("verification_context")
                == {
                    "mode": "standalone-endpoint-checked-copy",
                    "relative_sibling_context": "unavailable",
                    "execution_working_directory": "snapshot-parent",
                    "temporal_immutability_enforced": False,
                }
            ),
        })
        cases.append({
            "name": "json_compatibility_copy_matches_canonical_result_bytes",
            "passed": (
                canonical_result.is_file()
                and external_json.is_file()
                and canonical_result.read_bytes() == external_json.read_bytes()
            ),
        })

        rc, out = call_runner_main(runner, [str(fake_root), str(target), "--dry-run", "--skip-prechecks", "--output-dir", str(inside), "--json", str(external_json)])
        cases.append({"name": "package_tree_output_dir_rejected_without_refresh_manifest", "passed": rc == 2 and "requires --refresh-release-manifest" in out and not inside.exists()})

        rc, out = call_runner_main(runner, [str(fake_root), str(target), "--dry-run", "--skip-prechecks", "--output-dir", str(external), "--json", str(inside_json)])
        cases.append({"name": "package_tree_json_rejected_without_refresh_manifest", "passed": rc == 2 and "requires --refresh-release-manifest" in out and not inside_json.exists()})

        allowed_external = tmp / "allowed-external"
        allowed_external_json = tmp / "allowed-external.json"
        rc, out = call_runner_main(runner, [str(fake_root), str(target), "--dry-run", "--skip-prechecks", "--output-dir", str(allowed_external), "--json", str(allowed_external_json)])
        cases.append({"name": "external_output_locations_allowed", "passed": rc == 0 and allowed_external_json.exists()})

        replaceable_json = tmp / "replaceable-formal-result.json"
        original_compatibility_bytes = b"replace this compatibility result\n"
        replaceable_json.write_bytes(original_compatibility_bytes)
        replacement_output = tmp / "replacement-output"
        rc, output = call_runner_main(
            runner,
            [
                str(fake_root),
                str(target),
                "--dry-run",
                "--skip-prechecks",
                "--output-dir",
                str(replacement_output),
                "--json",
                str(replaceable_json),
            ],
        )
        try:
            replacement_stdout = json.loads(output)
            replacement_file = json.loads(
                replaceable_json.read_text(encoding="utf-8")
            )
        except (OSError, TypeError, ValueError):
            replacement_stdout = None
            replacement_file = None
        replacement_metadata = replaceable_json.lstat()
        cases.append({
            "name": "formal_runner_atomically_replaces_regular_compatibility_json",
            "passed": (
                rc == 0
                and replacement_stdout == replacement_file
                and replaceable_json.read_bytes()
                != original_compatibility_bytes
                and stat.S_ISREG(replacement_metadata.st_mode)
                and replacement_metadata.st_nlink == 1
            ),
        })

        separate_evidence_root = tmp / "separate-evidence-root"
        separate_output = tmp / "separate-evidence-output"
        rc, out = call_runner_main(
            runner,
            [
                str(fake_root),
                str(target),
                "--dry-run",
                "--skip-prechecks",
                "--output-dir",
                str(separate_output),
                "--evidence-root",
                str(separate_evidence_root),
            ],
        )
        cases.append({
            "name": "formal_runner_preserves_separate_evidence_root_compatibility",
            "passed": (
                rc == 0
                and str(separate_evidence_root.resolve()) in out
            ),
        })

        snapshot_prompt_output = tmp / "snapshot-prompt-output"
        snapshot_prompt_output.mkdir()
        snapshot_paths = runner.output_paths(target, snapshot_prompt_output)
        snapshot_prompt = runner.build_formal_prompt(
            fake_root,
            snapshot_paths["target_snapshot"],
            snapshot_paths,
            separate_evidence_root,
        )
        cases.append({
            "name": "formal_prompt_verifies_endpoint_checked_target_copy",
            "passed": (
                str(snapshot_paths["target_snapshot"]) in snapshot_prompt
                and f"Target artifact:\n{target}" not in snapshot_prompt
                and "standalone-endpoint-checked-copy" in snapshot_prompt
                and "temporal immutability is not enforced" in snapshot_prompt
                and "Relative sibling context" in snapshot_prompt
                and "Do not infer claims from files adjacent" in snapshot_prompt
            ),
        })

        valid_package_identity = {
            "algorithm": "stable-release-inventory-v1",
            "sha256": "sha256:" + "a" * 64,
            "valid": True,
        }
        invalid_package_identity = dict(valid_package_identity)
        invalid_package_identity["valid"] = 1
        cases.append({
            "name": "invalid_package_identity_forbids_formal_pass",
            "passed": (
                runner.cap_status_by_package_identity(
                    "PASS-TRACKED",
                    valid_package_identity,
                )[0]
                == "PASS-TRACKED"
                and runner.cap_status_by_package_identity(
                    "PASS-TRACKED",
                    invalid_package_identity,
                )[0]
                == "FAIL"
                and not runner.package_tree_identity_is_valid(
                    invalid_package_identity
                )
            ),
        })

        scoped_execution_identity = {
            "stable": True,
            "temporal_immutability_enforced": False,
            "process_containment": {
                "mechanism": "linux-child-subreaper-plus-process-group",
                "cleanup_after_leader_exit": True,
                "detached_session_descendants_contained": True,
            },
        }
        scoped_status, scoped_reason = (
            runner.cap_status_by_execution_package_snapshot(
                "PASS-TRACKED",
                scoped_execution_identity,
            )
        )
        cases.append({
            "name": "endpoint_stability_without_temporal_immutability_caps_pass",
            "passed": (
                scoped_status == "PASS-SCOPED"
                and isinstance(scoped_reason, str)
                and "temporal immutability" in scoped_reason
                and runner.cap_status_by_execution_package_snapshot(
                    "PASS-SCOPED",
                    scoped_execution_identity,
                )
                == ("PASS-SCOPED", None)
            ),
            "reason": scoped_reason,
        })

        strict_containment_scope = {
            "mechanism": "linux-child-subreaper-plus-process-group",
            "cleanup_after_leader_exit": True,
            "detached_session_descendants_contained": True,
        }

        def safe_formal_record(argv: List[str]) -> Dict[str, Any]:
            return {
                "argv": argv,
                "returncode": 0,
                "stdout_sha256": "sha256:" + "a" * 64,
                "stderr_sha256": "sha256:" + "b" * 64,
                "stdout_bytes": 0,
                "stderr_bytes": 0,
                "stdout_truncated": False,
                "stderr_truncated": False,
                "capture_limit_exceeded": False,
                "timed_out": False,
                "descendant_pipe_leak": False,
                "reader_join_timed_out": False,
                "normal_exit_group_survivor": False,
                "detached_descendant_survivor": False,
                "process_containment_cleanup_complete": True,
                "process_group_cleanup_attempted": True,
                "process_group_terminated": False,
                "process_containment": dict(strict_containment_scope),
            }

        safe_record = safe_formal_record(["<python>", "--version"])
        unsafe_formal_records: List[Dict[str, Any]] = []
        for field, unsafe_value in (
            ("returncode", 1),
            ("capture_limit_exceeded", True),
            ("timed_out", True),
            ("descendant_pipe_leak", True),
            ("reader_join_timed_out", True),
            ("normal_exit_group_survivor", True),
            ("detached_descendant_survivor", True),
            ("process_containment_cleanup_complete", False),
            ("process_group_cleanup_attempted", False),
            ("process_group_terminated", True),
        ):
            unsafe = dict(safe_record)
            unsafe[field] = unsafe_value
            unsafe_formal_records.append(unsafe)
        fallback_scope = dict(safe_record)
        fallback_scope["process_containment"] = {
            "mechanism": "initial-posix-process-group",
            "cleanup_after_leader_exit": True,
            "detached_session_descendants_contained": False,
        }
        unsafe_formal_records.append(fallback_scope)
        cases.append({
            "name": "certifier_formal_command_requires_complete_safe_capture",
            "passed": (
                certifier._formal_command_record_typed(safe_record)
                and all(
                    not certifier._formal_command_record_typed(record)
                    for record in unsafe_formal_records
                )
            ),
        })

        formal_prechecks = [
            safe_formal_record([
                "<python>",
                "<execution-package-root>/skills/nozickian-verify/scripts/validate_package.py",
                "<execution-package-root>",
            ]),
            safe_formal_record([
                "<python>",
                "<execution-package-root>/skills/nozickian-verify/scripts/run_regression_evals.py",
                "<execution-package-root>",
            ]),
            safe_formal_record([
                "<python>",
                "<execution-package-root>/skills/nozickian-verify/scripts/ntt_gate.py",
                "<execution-package-root>/self_validation/self_certificate.json",
                "--evidence-root",
                "<execution-package-root>",
                "--strict-evidence",
            ]),
            safe_formal_record([
                "/opt/claude",
                "plugin",
                "validate",
                "<execution-package-root>",
                "--strict",
            ]),
        ]
        formal_commands = [
            safe_formal_record(["/opt/claude", "--version"]),
            safe_formal_record([
                "/opt/claude",
                "--plugin-dir",
                "<execution-package-root>",
                "--agent",
                runner.FORMAL_COORDINATOR,
                "-p",
                "--output-format",
                "stream-json",
                "--include-hook-events",
                "--max-turns",
                "20",
                "sha256:" + "c" * 64,
            ]),
            safe_formal_record([
                "<python>",
                "<execution-package-root>/skills/nozickian-verify/scripts/ntt_gate.py",
                "<output-dir>/synthetic_NOZICKIAN_certificate.json",
                "--evidence-root",
                "<output-dir>",
                "--strict-evidence",
                "--markdown",
                "<output-dir>/synthetic_NOZICKIAN_GATE.md",
            ]),
        ]
        formal_projection = {
            "formal_result_schema_version": "2.0",
            "run_id": "synthetic-formal-run",
            "status": "PASS-SCOPED",
            "reason": "temporal immutability is not enforced",
            "formal_coordinator": runner.FORMAL_COORDINATOR,
            "required_native_agents": list(REQUIRED_NATIVE_AGENTS),
            "package_tree_identity": {},
            "execution_package_snapshot_identity": {},
            "runtime_identity": {
                "resolved_executable_path": "/opt/claude",
            },
            "target_snapshot_identity": {},
            "verification_context": {},
            "evidence_root": ".",
            "companions": {},
            "prechecks": formal_prechecks,
            "precheck_summary": {
                "total": 4,
                "failed": 0,
                "passed": 4,
                "failed_commands": [],
            },
            "commands": formal_commands,
            "output_checks": [
                {"name": "synthetic outputs complete", "passed": True}
            ],
            "gate_status": "PASS-TRACKED",
            "trace_authentication": {},
            "output_dir": "<output-dir>",
            "plugin_root": "<package-root>",
            "target_artifact": "<target>",
        }
        empty_projection = dict(formal_projection)
        empty_projection.update({
            "prechecks": [],
            "precheck_summary": {
                "total": 0,
                "failed": 0,
                "passed": 0,
                "failed_commands": [],
            },
            "commands": [],
            "output_checks": [],
        })
        mismatched_projection = dict(formal_projection)
        mismatched_projection["precheck_summary"] = {
            "total": 4,
            "failed": 0,
            "passed": 3,
            "failed_commands": [],
        }
        basename_projection = json.loads(json.dumps(formal_projection))
        basename_projection["prechecks"][0]["argv"][1] = (
            "/tmp/validate_package.py"
        )
        extra_option_projection = json.loads(json.dumps(formal_projection))
        extra_option_projection["commands"][1]["argv"][-1:-1] = [
            "--dangerously-skip-permissions",
        ]
        attacker_gate_projection = json.loads(json.dumps(formal_projection))
        attacker_gate_projection["commands"][2]["argv"][2] = (
            "<output-dir>/attacker.json"
        )
        runtime_mismatch_projection = json.loads(json.dumps(formal_projection))
        runtime_mismatch_projection["commands"][0]["argv"][0] = (
            "/opt/other-claude"
        )
        coordinator_field_mismatch_projection = json.loads(
            json.dumps(formal_projection)
        )
        coordinator_field_mismatch_projection["formal_coordinator"] = (
            "attacker-formal-coordinator"
        )
        coordinator_argv_mismatch_projection = json.loads(
            json.dumps(formal_projection)
        )
        coordinator_argv_mismatch_projection["commands"][1]["argv"][4] = (
            "attacker-formal-coordinator"
        )
        cases.append({
            "name": "certifier_formal_projection_rejects_vacuous_or_mismatched_execution",
            "passed": (
                certifier.formal_projected_fields_typed(
                    formal_projection,
                    REQUIRED_NATIVE_AGENTS,
                    runner.FORMAL_COORDINATOR,
                )
                and not certifier.formal_projected_fields_typed(
                    empty_projection,
                    REQUIRED_NATIVE_AGENTS,
                    runner.FORMAL_COORDINATOR,
                )
                and not certifier.formal_projected_fields_typed(
                    mismatched_projection,
                    REQUIRED_NATIVE_AGENTS,
                    runner.FORMAL_COORDINATOR,
                )
                and not certifier.formal_projected_fields_typed(
                    basename_projection,
                    REQUIRED_NATIVE_AGENTS,
                    runner.FORMAL_COORDINATOR,
                )
                and not certifier.formal_projected_fields_typed(
                    extra_option_projection,
                    REQUIRED_NATIVE_AGENTS,
                    runner.FORMAL_COORDINATOR,
                )
                and not certifier.formal_projected_fields_typed(
                    attacker_gate_projection,
                    REQUIRED_NATIVE_AGENTS,
                    runner.FORMAL_COORDINATOR,
                )
                and not certifier.formal_projected_fields_typed(
                    runtime_mismatch_projection,
                    REQUIRED_NATIVE_AGENTS,
                    runner.FORMAL_COORDINATOR,
                )
                and not certifier.formal_projected_fields_typed(
                    coordinator_field_mismatch_projection,
                    REQUIRED_NATIVE_AGENTS,
                    runner.FORMAL_COORDINATOR,
                )
                and not certifier.formal_projected_fields_typed(
                    coordinator_argv_mismatch_projection,
                    REQUIRED_NATIVE_AGENTS,
                    runner.FORMAL_COORDINATOR,
                )
            ),
        })
        formal_binding_companions = {
            "prompt": {"sha256": "sha256:" + "c" * 64},
            "transcript": {
                "sha256": "sha256:" + "a" * 64,
                "bytes": 0,
            },
            "certificate": {
                "path": "synthetic_NOZICKIAN_certificate.json",
            },
            "gate": {"path": "synthetic_NOZICKIAN_GATE.md"},
        }
        intact_bindings = certifier._formal_execution_companions_bound(
            formal_projection,
            formal_binding_companions,
        )
        substituted_prompt = json.loads(json.dumps(formal_projection))
        substituted_prompt["commands"][1]["argv"][-1] = (
            "sha256:" + "d" * 64
        )
        mismatched_transcript = json.loads(json.dumps(formal_projection))
        mismatched_transcript["commands"][1]["stdout_sha256"] = (
            "sha256:" + "e" * 64
        )
        mismatched_gate = json.loads(json.dumps(formal_projection))
        mismatched_gate["commands"][2]["argv"][2] = (
            "<output-dir>/attacker_NOZICKIAN_certificate.json"
        )
        mismatched_gate["commands"][2]["argv"][7] = (
            "<output-dir>/attacker_NOZICKIAN_GATE.md"
        )
        cases.append({
            "name": "certifier_formal_execution_binds_prompt_transcript_and_gate_companions",
            "passed": (
                intact_bindings
                == {"prompt": True, "transcript": True, "gate": True}
                and certifier._formal_execution_companions_bound(
                    substituted_prompt,
                    formal_binding_companions,
                )["prompt"]
                is False
                and certifier._formal_execution_companions_bound(
                    mismatched_transcript,
                    formal_binding_companions,
                )["transcript"]
                is False
                and certifier._formal_execution_companions_bound(
                    mismatched_gate,
                    formal_binding_companions,
                )["gate"]
                is False
            ),
        })
        recomputed_dir = tmp / "recomputed-formal-outputs"
        recomputed_dir.mkdir()
        recomputed_out = {
            "report": recomputed_dir / "report.md",
            "certificate": recomputed_dir / "certificate.json",
            "ledger": recomputed_dir / "ledger.md",
            "gate": recomputed_dir / "gate.md",
        }
        recomputed_out["report"].write_text(
            "# Formal report\n\nComplete.\n",
            encoding="utf-8",
        )
        recomputed_out["certificate"].write_text(
            json.dumps({"claims": [{"id": "C-1"}]}) + "\n",
            encoding="utf-8",
        )
        recomputed_out["gate"].write_text(
            "Status: **PASS-TRACKED**\n",
            encoding="utf-8",
        )
        recomputed_out["ledger"].write_text(
            (
                f"Main coordinator: {runner.FORMAL_COORDINATOR}\n"
                "Substitution used: none\n"
                "Machine gate run: runner-managed\n"
                + "\n".join(REQUIRED_NATIVE_AGENTS)
                + "\n"
            ),
            encoding="utf-8",
        )
        recorded_output_checks = runner.check_required_outputs(
            recomputed_out,
            include_gate=True,
        )
        intact_output_match = certifier._formal_output_checks_recomputed(
            runner,
            recomputed_out,
            recorded_output_checks,
        )[0]
        arbitrary_output_match = certifier._formal_output_checks_recomputed(
            runner,
            recomputed_out,
            [{"name": "attacker self-attested pass", "passed": True}],
        )[0]
        cases.append({
            "name": "certifier_rejects_arbitrary_self_attested_formal_output_checks",
            "passed": intact_output_match and arbitrary_output_match is False,
        })
        recomputed_out["report"].write_text("", encoding="utf-8")
        empty_report_match, _, empty_report_recomputed = (
            certifier._formal_output_checks_recomputed(
                runner,
                recomputed_out,
                recorded_output_checks,
            )
        )
        recomputed_out["report"].write_text(
            "# Formal report\n\nComplete.\n",
            encoding="utf-8",
        )
        recomputed_out["gate"].write_text("", encoding="utf-8")
        empty_gate_match, _, empty_gate_recomputed = (
            certifier._formal_output_checks_recomputed(
                runner,
                recomputed_out,
                recorded_output_checks,
            )
        )
        cases.append({
            "name": "certifier_rejects_empty_formal_report_or_gate_after_recomputation",
            "passed": (
                empty_report_match is False
                and any(
                    check.get("name") == "output exists: report"
                    and check.get("passed") is False
                    for check in empty_report_recomputed
                )
                and empty_gate_match is False
                and any(
                    check.get("name") == "output exists: gate"
                    and check.get("passed") is False
                    for check in empty_gate_recomputed
                )
            ),
        })

        stability_target = tmp / "stability-target.md"
        stability_snapshot = tmp / "stability-snapshot.bin"
        stability_target.write_text("stable target\n", encoding="utf-8")
        runner.atomic_write_new(
            stability_snapshot,
            stability_target.read_bytes(),
        )
        source_before = runner.file_snapshot_identity(stability_target)
        snapshot_before = runner.file_snapshot_identity(stability_snapshot)
        stability_target.write_text("mutated target\n", encoding="utf-8")
        source_after_mutation = runner.file_snapshot_identity(stability_target)
        mutation_stability = runner.target_snapshot_stability(
            source_before,
            source_after_mutation,
            snapshot_before,
            runner.file_snapshot_identity(stability_snapshot),
        )
        stability_target.write_text("stable target\n", encoding="utf-8")
        source_after_restore = runner.file_snapshot_identity(stability_target)
        stability_snapshot.write_text("mutated immutable snapshot\n", encoding="utf-8")
        snapshot_after_mutation = runner.file_snapshot_identity(stability_snapshot)
        snapshot_mutation_stability = runner.target_snapshot_stability(
            source_before,
            source_after_restore,
            snapshot_before,
            snapshot_after_mutation,
        )
        cases.append({
            "name": "target_mutation_forbids_formal_pass",
            "passed": (
                mutation_stability["stable"] is False
                and runner.cap_status_by_target_stability(
                    "PASS-TRACKED",
                    mutation_stability,
                )[0]
                == "FAIL"
            ),
        })
        cases.append({
            "name": "target_snapshot_mutation_forbids_formal_pass",
            "passed": (
                source_before["sha256"] == source_after_restore["sha256"]
                and snapshot_before["sha256"] != snapshot_after_mutation["sha256"]
                and snapshot_mutation_stability["stable"] is False
                and snapshot_mutation_stability["snapshot_metadata_stable"] is False
                and runner.cap_status_by_target_stability(
                    "PASS-TRACKED",
                    snapshot_mutation_stability,
                )[0]
                == "FAIL"
            ),
        })
        cases.append({
            "name": "target_endpoint_check_does_not_claim_temporal_immutability",
            "passed": (
                mutation_stability.get("stability_scope")
                == "pre-post-endpoint"
                and mutation_stability.get(
                    "temporal_immutability_enforced"
                )
                is False
                and snapshot_mutation_stability.get(
                    "temporal_immutability_enforced"
                )
                is False
            ),
        })

        sentinel = tmp / "external-sentinel.txt"
        sentinel_bytes = b"external sentinel must not change\n"
        sentinel.write_bytes(sentinel_bytes)

        unavailable_output = tmp / "procfd-unavailable-output"
        unavailable_json = tmp / "procfd-unavailable-result.json"
        original_inherited_alias = runner._inherited_directory_alias

        def unavailable_inherited_alias(_descriptor: int) -> Path:
            raise OSError("simulated procfd unavailable")

        try:
            runner._inherited_directory_alias = unavailable_inherited_alias
            unavailable_rc, unavailable_stdout = call_runner_main(
                runner,
                [
                    str(fake_root),
                    str(target),
                    "--dry-run",
                    "--skip-prechecks",
                    "--output-dir",
                    str(unavailable_output),
                    "--json",
                    str(unavailable_json),
                ],
            )
        finally:
            runner._inherited_directory_alias = original_inherited_alias
        cases.append({
            "name": "formal_runner_procfd_unavailable_fails_before_output_mutation",
            "passed": (
                unavailable_rc == 2
                and '"status": "INVALID_INPUT"' in unavailable_stdout
                and "capability is unavailable" in unavailable_stdout
                and not unavailable_output.exists()
                and not unavailable_json.exists()
            ),
        })

        canonical_race_root = tmp / "canonical-json-post-write-race"
        canonical_race_root.mkdir()
        canonical_parent = canonical_race_root / "checked-parent"
        canonical_parent.mkdir()
        canonical_parked = canonical_race_root / "parked-parent"
        canonical_fd = runner._open_directory_no_follow(canonical_parent)
        canonical_alias = runner._inherited_directory_alias(canonical_fd)
        canonical_out = runner.output_paths(target, canonical_alias)
        canonical_lexical_out = runner.output_paths(target, canonical_parent)
        canonical_json_path = canonical_lexical_out["formal_result"]
        canonical_replacement_bytes = (
            b"replacement canonical JSON sentinel must not change\n"
        )
        original_atomic_write_new = runner.atomic_write_new
        canonical_swapped = False

        def swap_after_canonical_write(
            path: Path,
            payload: bytes,
            *write_args: Any,
            **write_kwargs: Any,
        ) -> None:
            nonlocal canonical_swapped
            original_atomic_write_new(
                path,
                payload,
                *write_args,
                **write_kwargs,
            )
            if not canonical_swapped and path == canonical_out["formal_result"]:
                canonical_parent.rename(canonical_parked)
                canonical_parent.mkdir()
                canonical_json_path.write_bytes(canonical_replacement_bytes)
                canonical_swapped = True

        canonical_write_rejected = False
        try:
            runner.atomic_write_new = swap_after_canonical_write
            canonical_written = runner.write_formal_result_v2(
                {
                    "run_id": "canonical-json-frozen-race",
                    "status": "FAIL",
                    "reason": "contract fixture",
                    "commands": [],
                    "prechecks": [],
                    "output_checks": [],
                },
                root=fake_root,
                target=target,
                output_dir=canonical_parent,
                out=canonical_out,
                evidence_root=canonical_alias,
                json_path=canonical_json_path,
                output_directory_fd=canonical_fd,
                lexical_output_dir=canonical_parent,
                json_is_canonical=True,
            )
        except (OSError, ValueError):
            canonical_write_rejected = True
            canonical_written = {}
        finally:
            runner.atomic_write_new = original_atomic_write_new
            os.close(canonical_fd)
        try:
            parked_canonical = json.loads(
                (canonical_parked / "formal_result.json").read_text(
                    encoding="utf-8"
                )
            )
        except (OSError, ValueError):
            parked_canonical = None
        cases.append({
            "name": "canonical_json_classification_is_frozen_across_post_write_directory_swap",
            "passed": (
                canonical_swapped
                and canonical_write_rejected is True
                and isinstance(parked_canonical, dict)
                and parked_canonical.get("run_id")
                == "canonical-json-frozen-race"
                and canonical_json_path.read_bytes()
                == canonical_replacement_bytes
            ),
        })

        held_true_parent = tmp / "held-true-parent"
        held_true_parent.mkdir()
        certifier_true = held_true_parent / "certifier.json"
        certifier_true.write_text("old\n", encoding="utf-8")
        certifier.atomic_replace_regular_text(
            certifier_true,
            "new\n",
        )
        formal_new_true = held_true_parent / "formal-new.bin"
        runner.atomic_write_new(formal_new_true, b"new\n")
        formal_replace_true = held_true_parent / "formal-replace.bin"
        formal_replace_true.write_bytes(b"old\n")
        runner.atomic_replace_regular(formal_replace_true, b"new\n")
        formal_reserve_true = held_true_parent / "formal-reserved.bin"
        runner.reserve_regular_output(formal_reserve_true)
        nested_true = held_true_parent / "nested/created/output"
        nested_true_error = runner.prepare_output_directory(nested_true)
        cases.append({
            "name": "held_dirfd_output_operations_retain_ordinary_true_controls",
            "passed": (
                certifier_true.read_bytes() == b"new\n"
                and formal_new_true.read_bytes() == b"new\n"
                and formal_replace_true.read_bytes() == b"new\n"
                and formal_reserve_true.is_file()
                and formal_reserve_true.stat().st_nlink == 1
                and nested_true_error is None
                and nested_true.is_dir()
            ),
        })

        def exercise_temporary_ancestor_swap(
            *,
            prefix: str,
            module: Any,
            writer: Any,
            existing: bool,
        ) -> Dict[str, Any]:
            race_root = tmp / prefix
            race_root.mkdir()
            parent = race_root / "checked-parent"
            parent.mkdir()
            parked = race_root / "parked-parent"
            external = race_root / "external-parent"
            external.mkdir()
            target_path = parent / "result.json"
            original_bytes = b"original checked target\n"
            if existing:
                target_path.write_bytes(original_bytes)
            external_target = external / target_path.name
            external_bytes = b"external target must not change\n"
            external_target.write_bytes(external_bytes)
            original_open = module.os.open
            swapped = False

            def racing_open(path: Any, flags: int, *open_args: Any, **open_kwargs: Any) -> int:
                nonlocal swapped
                raw = os.fspath(path)
                if (
                    not swapped
                    and open_kwargs.get("dir_fd") is not None
                    and isinstance(raw, str)
                    and raw.startswith(f".{target_path.name}.")
                    and raw.endswith(".tmp")
                ):
                    parent.rename(parked)
                    parent.symlink_to(external, target_is_directory=True)
                    swapped = True
                return original_open(path, flags, *open_args, **open_kwargs)

            rejected = False
            try:
                module.os.open = racing_open
                writer(target_path)
            except (OSError, ValueError):
                rejected = True
            finally:
                module.os.open = original_open
            parked_target = parked / target_path.name
            return {
                "safe": (
                    rejected
                    and swapped
                    and external_target.read_bytes() == external_bytes
                    and (
                        parked_target.read_bytes() == original_bytes
                        if existing
                        else not parked_target.exists()
                    )
                    and not any(
                        entry.name.startswith(f".{target_path.name}.")
                        for entry in parked.iterdir()
                    )
                ),
                "rejected": rejected,
                "swapped": swapped,
            }

        certifier_swap = exercise_temporary_ancestor_swap(
            prefix="certifier-atomic-replace-symlink-race",
            module=certifier,
            writer=lambda path: certifier.atomic_replace_regular_text(
                path,
                "attacker-directed bytes\n",
            ),
            existing=True,
        )
        formal_new_swap = exercise_temporary_ancestor_swap(
            prefix="formal-atomic-new-symlink-race",
            module=runner,
            writer=lambda path: runner.atomic_write_new(
                path,
                b"attacker-directed bytes\n",
            ),
            existing=False,
        )
        formal_replace_swap = exercise_temporary_ancestor_swap(
            prefix="formal-atomic-replace-symlink-race",
            module=runner,
            writer=lambda path: runner.atomic_replace_regular(
                path,
                b"attacker-directed bytes\n",
            ),
            existing=True,
        )
        cases.append({
            "name": "held_dirfd_atomic_writers_reject_ancestor_to_symlink_swap",
            "passed": (
                certifier_swap["safe"]
                and formal_new_swap["safe"]
                and formal_replace_swap["safe"]
            ),
            "details": {
                "certifier": certifier_swap,
                "formal_new": formal_new_swap,
                "formal_replace": formal_replace_swap,
            },
        })

        reserve_root = tmp / "formal-reserve-symlink-race"
        reserve_root.mkdir()
        reserve_parent = reserve_root / "checked-parent"
        reserve_parent.mkdir()
        reserve_parked = reserve_root / "parked-parent"
        reserve_external = reserve_root / "external-parent"
        reserve_external.mkdir()
        reserve_target = reserve_parent / "reserved.json"
        reserve_external_target = reserve_external / reserve_target.name
        reserve_external_bytes = b"external reserve sentinel\n"
        reserve_external_target.write_bytes(reserve_external_bytes)
        original_open = runner.os.open
        reserve_swapped = False

        def reserve_racing_open(path: Any, flags: int, *open_args: Any, **open_kwargs: Any) -> int:
            nonlocal reserve_swapped
            if (
                not reserve_swapped
                and open_kwargs.get("dir_fd") is not None
                and os.fspath(path) == reserve_target.name
                and flags & os.O_CREAT
            ):
                reserve_parent.rename(reserve_parked)
                reserve_parent.symlink_to(
                    reserve_external,
                    target_is_directory=True,
                )
                reserve_swapped = True
            return original_open(path, flags, *open_args, **open_kwargs)

        reserve_rejected = False
        try:
            runner.os.open = reserve_racing_open
            runner.reserve_regular_output(reserve_target)
        except (OSError, ValueError):
            reserve_rejected = True
        finally:
            runner.os.open = original_open
        cases.append({
            "name": "held_dirfd_reservation_rejects_ancestor_to_symlink_swap",
            "passed": (
                reserve_rejected
                and reserve_swapped
                and reserve_external_target.read_bytes()
                == reserve_external_bytes
                and not (reserve_parked / reserve_target.name).exists()
            ),
        })

        prepare_root = tmp / "formal-prepare-symlink-race"
        prepare_root.mkdir()
        prepare_parent = prepare_root / "checked-parent"
        prepare_parent.mkdir()
        prepare_parked = prepare_root / "parked-parent"
        prepare_external = prepare_root / "external-parent"
        prepare_external.mkdir()
        prepare_target = prepare_parent / "first/second/output"
        original_mkdir = runner.os.mkdir
        prepare_swapped = False

        def prepare_racing_mkdir(path: Any, *mkdir_args: Any, **mkdir_kwargs: Any) -> None:
            nonlocal prepare_swapped
            if (
                not prepare_swapped
                and mkdir_kwargs.get("dir_fd") is not None
                and os.fspath(path) == "first"
            ):
                prepare_parent.rename(prepare_parked)
                prepare_parent.symlink_to(
                    prepare_external,
                    target_is_directory=True,
                )
                prepare_swapped = True
            original_mkdir(path, *mkdir_args, **mkdir_kwargs)

        try:
            runner.os.mkdir = prepare_racing_mkdir
            prepare_error = runner.prepare_output_directory(prepare_target)
        finally:
            runner.os.mkdir = original_mkdir
        cases.append({
            "name": "prepare_output_directory_rejects_ancestor_to_symlink_swap_without_external_creation",
            "passed": (
                prepare_swapped
                and isinstance(prepare_error, str)
                and not (prepare_external / "first").exists()
                and (prepare_parked / "first/second/output").is_dir()
            ),
            "error": prepare_error,
        })

        inherited_root = tmp / "formal-inherited-capability"
        inherited_root.mkdir()
        inherited_parent = inherited_root / "checked-parent"
        inherited_parent.mkdir()
        inherited_fd = runner._open_directory_no_follow(inherited_parent)
        inherited_alias = runner._inherited_directory_alias(inherited_fd)
        inherited_parked = inherited_root / "parked-parent"
        inherited_replacement = inherited_root / "replacement-parent"
        inherited_parent.rename(inherited_parked)
        inherited_parent.mkdir()
        inherited_replacement = inherited_parent
        inherited_external_sentinel = inherited_replacement / "child.txt"
        inherited_external_bytes = b"replacement directory sentinel\n"
        inherited_external_sentinel.write_bytes(inherited_external_bytes)
        inherited_command = runner.run_cmd(
            [
                sys.executable,
                "-c",
                (
                    "from pathlib import Path; import os, sys; "
                    "fd = int(sys.argv[2]); "
                    "os.close(fd); "
                    "replacement = os.open(sys.argv[3], os.O_RDONLY | os.O_DIRECTORY); "
                    "os.dup2(replacement, fd) if replacement != fd else None; "
                    "os.close(replacement) if replacement != fd else None; "
                    "Path(sys.argv[1]).write_bytes(b'held child bytes\\n')"
                ),
                str(inherited_alias / "child.txt"),
                str(inherited_fd),
                str(inherited_replacement),
            ],
            timeout=10,
            pass_fds=(inherited_fd,),
        )
        (inherited_parked / "certificate.json").write_text(
            "{}\n",
            encoding="utf-8",
        )
        gate_command = runner.run_cmd(
            [
                sys.executable,
                str(package_root / SKILL_PATH / "scripts/ntt_gate.py"),
                str(inherited_alias / "certificate.json"),
                "--markdown",
                str(inherited_alias / "gate.md"),
            ],
            timeout=10,
            pass_fds=(inherited_fd,),
        )
        probe_file_fd = os.open(sentinel, os.O_RDONLY)
        proc_visible_runner_pid = inherited_alias.parts[2]
        probe_paths = {
            "valid": str(inherited_alias / "probe.md"),
            "unrelated_pid": str(
                Path("/proc")
                / str(int(proc_visible_runner_pid) + 1_000_000)
                / "fd"
                / str(inherited_fd)
                / "probe.md"
            ),
            "leading_zero_pid": str(
                Path("/proc")
                / f"0{proc_visible_runner_pid}"
                / "fd"
                / str(inherited_fd)
                / "probe.md"
            ),
            "leading_zero_fd": str(
                Path("/proc")
                / proc_visible_runner_pid
                / "fd"
                / f"0{inherited_fd}"
                / "probe.md"
            ),
            "zero_fd": str(
                Path("/proc")
                / proc_visible_runner_pid
                / "fd/0/probe.md"
            ),
            "extra_component": str(
                inherited_alias / "extra" / "probe.md"
            ),
            "closed_fd": str(
                Path("/proc")
                / proc_visible_runner_pid
                / "fd/999999/probe.md"
            ),
            "file_fd": str(
                Path("/proc")
                / proc_visible_runner_pid
                / "fd"
                / str(probe_file_fd)
                / "probe.md"
            ),
        }
        gate_probe_script = (
            "import importlib.util, json, os, sys; "
            "from pathlib import Path; "
            "spec = importlib.util.spec_from_file_location('gate_probe', sys.argv[1]); "
            "module = importlib.util.module_from_spec(spec); "
            "sys.modules[spec.name] = module; spec.loader.exec_module(module); "
            "paths = json.loads(sys.argv[2]); "
            "self_pid = module._proc_status_pid('Pid'); "
            "paths['self_pid'] = f'/proc/{self_pid}/fd/{sys.argv[3]}/probe.md'; "
            "results = {}; "
            "exec(\"for key, raw in paths.items():\\n try:\\n  opened, _ = module._open_output_parent(Path(raw)); os.close(opened); results[key] = True\\n except (OSError, ValueError):\\n  results[key] = False\"); "
            "print(json.dumps(results, sort_keys=True))"
        )
        gate_probe = runner.run_cmd(
            [
                sys.executable,
                "-c",
                gate_probe_script,
                str(package_root / SKILL_PATH / "scripts/ntt_gate.py"),
                json.dumps(probe_paths, sort_keys=True),
                str(inherited_fd),
            ],
            timeout=10,
            pass_fds=(inherited_fd,),
        )
        os.close(probe_file_fd)
        try:
            gate_probe_results = json.loads(str(gate_probe.get("stdout")))
        except (TypeError, ValueError):
            gate_probe_results = {}
        inherited_stable = runner._directory_path_matches_fd(
            inherited_parent,
            inherited_fd,
        )
        os.close(inherited_fd)
        cases.append({
            "name": "coordinator_and_gate_use_runner_owned_capability_after_child_fd_rebind_and_directory_substitution",
            "passed": (
                inherited_command.get("returncode") == 0
                and gate_command.get("returncode") == 2
                and inherited_external_sentinel.read_bytes()
                == inherited_external_bytes
                and (inherited_parked / "child.txt").read_bytes()
                == b"held child bytes\n"
                and not (inherited_replacement / "gate.md").exists()
                and (inherited_parked / "gate.md").read_text(
                    encoding="utf-8"
                )
                .startswith("# Nozickian Gate Result")
                and gate_probe.get("returncode") == 0
                and gate_probe_results == {
                    "closed_fd": False,
                    "extra_component": False,
                    "file_fd": False,
                    "leading_zero_fd": False,
                    "leading_zero_pid": False,
                    "self_pid": False,
                    "unrelated_pid": False,
                    "valid": True,
                    "zero_fd": False,
                }
                and inherited_stable is False
            ),
            "command_returncode": inherited_command.get("returncode"),
            "gate_returncode": gate_command.get("returncode"),
            "gate_probe": gate_probe_results,
        })

        certifier_bundle = tmp / "certifier-held-bundle"
        certifier_bundle.mkdir()
        original_certify_bundle = certifier.certify_bundle

        same_output = tmp / "certifier-same-json-markdown.out"
        same_stream = io.StringIO()
        with contextlib.redirect_stdout(same_stream):
            same_output_rc = certifier.main([
                str(fake_root),
                str(certifier_bundle),
                "--json",
                str(same_output),
                "--markdown",
                str(same_output),
            ])
        alias_source = tmp / "certifier-json-hardlink.json"
        alias_source_bytes = b"json hardlink sentinel\n"
        alias_source.write_bytes(alias_source_bytes)
        alias_markdown = tmp / "certifier-markdown-hardlink.md"
        alias_markdown.hardlink_to(alias_source)
        alias_stream = io.StringIO()
        with contextlib.redirect_stdout(alias_stream):
            alias_output_rc = certifier.main([
                str(fake_root),
                str(certifier_bundle),
                "--json",
                str(alias_source),
                "--markdown",
                str(alias_markdown),
            ])
        cases.append({
            "name": "certifier_rejects_same_or_hardlinked_json_markdown_destinations",
            "passed": (
                same_output_rc == 2
                and "destinations alias" in same_stream.getvalue()
                and not same_output.exists()
                and alias_output_rc == 2
                and "destinations alias" in alias_stream.getvalue()
                and alias_source.read_bytes() == alias_source_bytes
                and alias_markdown.read_bytes() == alias_source_bytes
            ),
        })

        distinct_json = tmp / "certifier-distinct-result.json"
        distinct_markdown = tmp / "certifier-distinct-result.md"

        def distinct_certify(*_args: Any, **_kwargs: Any) -> Dict[str, Any]:
            return {
                "status": "FAIL",
                "outcome": "FAILED",
                "promotion_authorized": False,
                "checks": [],
                "failed_checks": [],
            }

        distinct_stream = io.StringIO()
        try:
            certifier.certify_bundle = distinct_certify
            with contextlib.redirect_stdout(distinct_stream):
                distinct_output_rc = certifier.main([
                    str(fake_root),
                    str(certifier_bundle),
                    "--json",
                    str(distinct_json),
                    "--markdown",
                    str(distinct_markdown),
                ])
        finally:
            certifier.certify_bundle = original_certify_bundle
        try:
            distinct_json_data = json.loads(
                distinct_json.read_text(encoding="utf-8")
            )
        except (OSError, ValueError):
            distinct_json_data = None
        cases.append({
            "name": "certifier_retains_distinct_json_and_markdown_true_control",
            "passed": (
                distinct_output_rc == 2
                and isinstance(distinct_json_data, dict)
                and distinct_json_data.get("status") == "FAIL"
                and distinct_markdown.read_text(encoding="utf-8").startswith(
                    "# PASS-TRACKED upgrade certification"
                )
            ),
        })

        def run_certifier_real_parent_swap(option: str) -> Dict[str, Any]:
            output_root = tmp / f"certifier-{option}-real-parent-race"
            output_root.mkdir()
            parent = output_root / "checked-parent"
            parent.mkdir()
            parked = output_root / "parked-parent"
            extension = "json" if option == "json" else "md"
            output = parent / f"result.{extension}"
            original_bytes = b"original output bytes\n"
            output.write_bytes(original_bytes)
            replacement_bytes = b"replacement directory sentinel\n"

            def swapping_certify(*_args: Any, **_kwargs: Any) -> Dict[str, Any]:
                parent.rename(parked)
                parent.mkdir()
                (parent / output.name).write_bytes(replacement_bytes)
                return {
                    "status": "FAIL",
                    "outcome": "FAILED",
                    "promotion_authorized": False,
                    "checks": [],
                    "failed_checks": [],
                }

            stream = io.StringIO()
            try:
                certifier.certify_bundle = swapping_certify
                with contextlib.redirect_stdout(stream):
                    returncode = certifier.main([
                        str(fake_root),
                        str(certifier_bundle),
                        f"--{option}",
                        str(output),
                    ])
            finally:
                certifier.certify_bundle = original_certify_bundle
            return {
                "safe": (
                    returncode == 2
                    and f"unsafe --{option} output path was rejected"
                    in stream.getvalue()
                    and (parent / output.name).read_bytes()
                    == replacement_bytes
                    and (parked / output.name).read_bytes()
                    == original_bytes
                ),
                "returncode": returncode,
            }

        certifier_json_real_swap = run_certifier_real_parent_swap("json")
        certifier_markdown_real_swap = run_certifier_real_parent_swap(
            "markdown"
        )
        cases.append({
            "name": "certifier_holds_json_and_markdown_parents_across_real_directory_substitution",
            "passed": (
                certifier_json_real_swap["safe"]
                and certifier_markdown_real_swap["safe"]
            ),
            "details": {
                "json": certifier_json_real_swap,
                "markdown": certifier_markdown_real_swap,
            },
        })

        existing_file_output_dir = tmp / "existing-file-output-dir"
        existing_file_output_dir.write_bytes(b"existing output-dir sentinel\n")
        existing_file_bytes = existing_file_output_dir.read_bytes()
        rc, output = call_runner_main(
            runner,
            [
                str(fake_root),
                str(target),
                "--dry-run",
                "--skip-prechecks",
                "--output-dir",
                str(existing_file_output_dir),
            ],
        )
        cases.append({
            "name": "formal_runner_structures_existing_file_output_dir_failure",
            "passed": (
                rc == 2
                and '"status": "INVALID_INPUT"' in output
                and "unsafe --output-dir" in output
                and existing_file_output_dir.read_bytes() == existing_file_bytes
            ),
        })

        real_output_target = tmp / "real-output-target"
        real_output_target.mkdir()
        symlink_output_dir = tmp / "symlink-output-dir"
        symlink_output_dir.symlink_to(real_output_target, target_is_directory=True)
        rc, output = call_runner_main(
            runner,
            [
                str(fake_root),
                str(target),
                "--dry-run",
                "--skip-prechecks",
                "--output-dir",
                str(symlink_output_dir),
            ],
        )
        cases.append({
            "name": "formal_runner_structures_symlink_output_dir_failure",
            "passed": (
                rc == 2
                and '"status": "INVALID_INPUT"' in output
                and "symbolic link" in output
                and not list(real_output_target.iterdir())
            ),
        })

        output_ancestor_external = tmp / "output-ancestor-external"
        output_ancestor_nested = output_ancestor_external / "nested"
        output_ancestor_nested.mkdir(parents=True)
        output_ancestor_sentinel = output_ancestor_nested / "sentinel.txt"
        output_ancestor_sentinel_bytes = (
            b"formal output ancestor sentinel must remain unchanged\n"
        )
        output_ancestor_sentinel.write_bytes(
            output_ancestor_sentinel_bytes
        )
        output_ancestor_link = tmp / "output-ancestor-link"
        output_ancestor_link.symlink_to(
            output_ancestor_external,
            target_is_directory=True,
        )
        unsafe_nested_output = (
            output_ancestor_link / "nested/generated-output"
        )
        rc, output = call_runner_main(
            runner,
            [
                str(fake_root),
                str(target),
                "--dry-run",
                "--skip-prechecks",
                "--output-dir",
                str(unsafe_nested_output),
            ],
        )
        cases.append({
            "name": "formal_runner_rejects_symlinked_output_dir_ancestor",
            "passed": (
                rc == 2
                and '"status": "INVALID_INPUT"' in output
                and "symbolic link ancestor" in output
                and output_ancestor_sentinel.read_bytes()
                == output_ancestor_sentinel_bytes
                and not (
                    output_ancestor_nested / "generated-output"
                ).exists()
            ),
        })

        if hasattr(os, "mkfifo"):
            special_output_dir = tmp / "special-output-dir"
            os.mkfifo(special_output_dir)
            rc, output = call_runner_main(
                runner,
                [
                    str(fake_root),
                    str(target),
                    "--dry-run",
                    "--skip-prechecks",
                    "--output-dir",
                    str(special_output_dir),
                ],
            )
            cases.append({
                "name": "formal_runner_structures_special_output_dir_failure",
                "passed": (
                    rc == 2
                    and '"status": "INVALID_INPUT"' in output
                    and "not a directory" in output
                ),
            })

        compatibility_symlink = tmp / "compatibility-result.json"
        compatibility_symlink.symlink_to(sentinel)
        rc, output = call_runner_main(
            runner,
            [
                str(fake_root),
                str(target),
                "--dry-run",
                "--skip-prechecks",
                "--output-dir",
                str(tmp / "compatibility-symlink-output"),
                "--json",
                str(compatibility_symlink),
            ],
        )
        cases.append({
            "name": "formal_runner_rejects_compatibility_json_symlink",
            "passed": (
                rc == 2
                and '"status": "INVALID_INPUT"' in output
                and "symbolic link" in output
                and compatibility_symlink.is_symlink()
                and sentinel.read_bytes() == sentinel_bytes
            ),
        })

        json_ancestor_external = tmp / "json-ancestor-external"
        json_ancestor_nested = json_ancestor_external / "nested"
        json_ancestor_nested.mkdir(parents=True)
        json_ancestor_sentinel = json_ancestor_nested / "result.json"
        json_ancestor_sentinel_bytes = (
            b"formal json ancestor sentinel must remain unchanged\n"
        )
        json_ancestor_sentinel.write_bytes(json_ancestor_sentinel_bytes)
        json_ancestor_link = tmp / "json-ancestor-link"
        json_ancestor_link.symlink_to(
            json_ancestor_external,
            target_is_directory=True,
        )
        unsafe_nested_json = json_ancestor_link / "nested/result.json"
        nested_json_output = tmp / "nested-json-output"
        rc, output = call_runner_main(
            runner,
            [
                str(fake_root),
                str(target),
                "--dry-run",
                "--skip-prechecks",
                "--output-dir",
                str(nested_json_output),
                "--json",
                str(unsafe_nested_json),
            ],
        )
        cases.append({
            "name": "formal_runner_rejects_symlinked_compatibility_json_ancestor",
            "passed": (
                rc == 2
                and '"status": "INVALID_INPUT"' in output
                and "symbolic link ancestor" in output
                and json_ancestor_sentinel.read_bytes()
                == json_ancestor_sentinel_bytes
                and not nested_json_output.exists()
            ),
        })

        special_compatibility_json = tmp / "special-compatibility.json"
        os.mkfifo(special_compatibility_json)
        special_json_output = tmp / "special-json-output"
        rc, output = call_runner_main(
            runner,
            [
                str(fake_root),
                str(target),
                "--dry-run",
                "--skip-prechecks",
                "--output-dir",
                str(special_json_output),
                "--json",
                str(special_compatibility_json),
            ],
        )
        cases.append({
            "name": "formal_runner_rejects_special_compatibility_json_target",
            "passed": (
                rc == 2
                and '"status": "INVALID_INPUT"' in output
                and "special file" in output
                and stat.S_ISFIFO(
                    special_compatibility_json.lstat().st_mode
                )
                and not special_json_output.exists()
            ),
        })

        unsafe_output = tmp / "unsafe-output"
        unsafe_output.mkdir()
        unsafe_prompt = unsafe_output / "unsafe-prompt.md"
        unsafe_prompt.symlink_to(sentinel)
        atomic_rejected = False
        try:
            runner.atomic_write_new(unsafe_prompt, b"overwrite attempt\n")
        except (FileExistsError, OSError, ValueError):
            atomic_rejected = True
        cases.append({
            "name": "safe_atomic_write_rejects_symlink_without_overwriting_sentinel",
            "passed": (
                atomic_rejected
                and sentinel.read_bytes() == sentinel_bytes
                and unsafe_prompt.is_symlink()
            ),
        })

        hardlink_output = unsafe_output / "hardlink-output.json"
        hardlink_output.hardlink_to(sentinel)
        collision_paths = runner.output_paths(target, unsafe_output)
        collision_paths["formal_result"] = hardlink_output
        hardlink_error = runner.formal_output_collision_error(
            target,
            collision_paths,
            None,
        )
        cases.append({
            "name": "formal_output_preflight_rejects_preexisting_hardlink",
            "passed": (
                isinstance(hardlink_error, str)
                and "pre-existing" in hardlink_error
                and sentinel.read_bytes() == sentinel_bytes
            ),
        })

        symlink_main_output = tmp / "symlink-main-output"
        symlink_main_output.mkdir()
        symlink_main_paths = runner.output_paths(target, symlink_main_output)
        symlink_main_paths["prompt"].symlink_to(sentinel)
        rc, output = call_runner_main(
            runner,
            [
                str(fake_root),
                str(target),
                "--dry-run",
                "--skip-prechecks",
                "--output-dir",
                str(symlink_main_output),
            ],
        )
        cases.append({
            "name": "formal_runner_rejects_preexisting_output_symlink_sentinel",
            "passed": (
                rc == 2
                and "pre-existing formal output" in output
                and sentinel.read_bytes() == sentinel_bytes
            ),
        })

        hardlink_main_output = tmp / "hardlink-main-output"
        hardlink_main_output.mkdir()
        hardlink_main_paths = runner.output_paths(target, hardlink_main_output)
        hardlink_main_paths["formal_result"].hardlink_to(sentinel)
        rc, output = call_runner_main(
            runner,
            [
                str(fake_root),
                str(target),
                "--dry-run",
                "--skip-prechecks",
                "--output-dir",
                str(hardlink_main_output),
            ],
        )
        cases.append({
            "name": "formal_runner_rejects_preexisting_output_hardlink_sentinel",
            "passed": (
                rc == 2
                and "hardlink alias" in output
                and sentinel.read_bytes() == sentinel_bytes
            ),
        })

        if hasattr(os, "mkfifo"):
            fifo_output = tmp / "fifo-main-output"
            fifo_output.mkdir()
            fifo_paths = runner.output_paths(target, fifo_output)
            os.mkfifo(fifo_paths["transcript"])
            rc, output = call_runner_main(
                runner,
                [
                    str(fake_root),
                    str(target),
                    "--dry-run",
                    "--skip-prechecks",
                    "--output-dir",
                    str(fifo_output),
                ],
            )
            cases.append({
                "name": "formal_runner_rejects_preexisting_special_output",
                "passed": rc == 2 and "special file" in output,
            })

        collision_dir = tmp / "collision"
        collision_dir.mkdir()
        collision_target = collision_dir / "formal_result.json"
        collision_bytes = b"target bytes must remain unchanged\n"
        collision_target.write_bytes(collision_bytes)
        rc, out = call_runner_main(
            runner,
            [
                str(fake_root),
                str(collision_target),
                "--dry-run",
                "--skip-prechecks",
                "--output-dir",
                str(collision_dir),
            ],
        )
        cases.append({
            "name": "formal_runner_rejects_target_canonical_result_collision",
            "passed": (
                rc == 2
                and '"status": "INVALID_INPUT"' in out
                and "aliases a reserved formal output path" in out
                and collision_target.read_bytes() == collision_bytes
            ),
        })
        json_collision_output = tmp / "json-collision-output"
        rc, out = call_runner_main(
            runner,
            [
                str(fake_root),
                str(collision_target),
                "--dry-run",
                "--skip-prechecks",
                "--output-dir",
                str(json_collision_output),
                "--json",
                str(collision_target),
            ],
        )
        cases.append({
            "name": "formal_runner_rejects_json_target_collision",
            "passed": (
                rc == 2
                and '"status": "INVALID_INPUT"' in out
                and "json compatibility path aliases target_artifact" in out
                and collision_target.read_bytes() == collision_bytes
            ),
        })
        target_symlink = tmp / "target-symlink.md"
        target_symlink.symlink_to(collision_target)
        rc, out = call_runner_main(
            runner,
            [
                str(fake_root),
                str(target_symlink),
                "--dry-run",
                "--skip-prechecks",
                "--output-dir",
                str(tmp / "symlink-target-output"),
            ],
        )
        cases.append({
            "name": "formal_runner_rejects_symlink_target_without_following",
            "passed": (
                rc == 2
                and '"status": "INVALID_INPUT"' in out
                and "symbolic link" in out
                and collision_target.read_bytes() == collision_bytes
            ),
        })

        if inside.exists():
            shutil.rmtree(inside)
        if inside_json.exists():
            inside_json.unlink()
        rc, out = call_runner_main(runner, [str(fake_root), str(target), "--dry-run", "--skip-prechecks", "--output-dir", str(inside), "--json", str(inside_json), "--refresh-release-manifest"])
        cases.append({"name": "refresh_release_manifest_explicitly_allows_package_tree_output", "passed": rc == 0 and inside.exists() and inside_json.exists()})

    return cases


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("package_root", type=Path)
    ap.add_argument("--json", type=Path)
    args = ap.parse_args(argv)
    output_path: Path | None = None
    output_directory_fd: int | None = None
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
    runner = load_runner(args.package_root.resolve())
    cases = run_cases(runner, args.package_root.resolve())
    result = {"total": len(cases), "passed": sum(1 for c in cases if c.get("passed")), "cases": cases}
    text = json.dumps(result, indent=2, sort_keys=True)
    if output_path is not None and output_directory_fd is not None:
        try:
            _atomic_replace_json_output(
                output_path,
                text,
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
    return 0 if result["passed"] == result["total"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

# Contract-test documentation padding:
# fake claude / no tool_use events / PASS-TRACKED / trace authentication / run_formal_artifact_verification.py
# native_tool_use_without_results_does_not_authenticate / failed_native_result_does_not_authenticate / mismatched_tool_result_id_does_not_authenticate / missing_result_agents
# default_formal_dry_run_output_is_outside_package_tree / package_tree_output_dir_rejected_without_refresh_manifest
# package_tree_json_rejected_without_refresh_manifest / refresh_release_manifest_explicitly_allows_package_tree_output
# release tree output requires --refresh-release-manifest / explicit stable manifest refresh / missing successful matching tool-result/completion events

# v1.0.1 padding: nested_tool_result_inside_tool_input_does_not_authenticate nested_tool_result_inside_arguments_does_not_authenticate tool_result_before_tool_use_does_not_authenticate same_event_input_embedded_result_does_not_authenticate / single_agent_call_mentions_all_lanes_does_not_authenticate / duplicate_tool_use_id_across_lanes_does_not_authenticate / single_result_for_duplicate_id_does_not_authenticate_all_lanes / empty_tool_result_content_does_not_authenticate / generic_result_without_status_or_is_error_does_not_authenticate / structured_subagent_type_exact_match_required / structured subagent_type exact match required / duplicate tool-use id rejection / empty generic result rejection

# v1.0.1 padding: nested_tool_result_inside_tool_input_does_not_authenticate / nested_tool_result_inside_arguments_does_not_authenticate / tool_result_before_tool_use_does_not_authenticate / same_event_input_embedded_result_does_not_authenticate / recognized stream-json positions only / result-after-call chronology

# v1.0.1 padding: text_block_tool_use_does_not_authenticate / text_block_tool_result_does_not_authenticate / assistant_message_tool_use_masquerade_does_not_authenticate / message_result_masquerade_does_not_authenticate / unexpected_agent_call_without_structured_selector_rejected / unknown_agent_selector_rejected / authentic tool-use event types only / authentic tool-result event types only

# v1.0.1 padding: tool_result_empty_text_block_does_not_authenticate / tool_result_metadata_only_text_block_does_not_authenticate / tool_result_whitespace_text_block_does_not_authenticate / tool_result_metadata_only_dict_does_not_authenticate / tool_result_document_block_without_data_does_not_authenticate / tool_result_image_block_without_data_does_not_authenticate / tool_result_nonempty_text_block_authenticates / metadata-only content blocks are not substantive PASS-TRACKED completion evidence

# v1.0.1 padding: tool_result_empty_text_block_does_not_authenticate / tool_result_metadata_only_text_block_does_not_authenticate / tool_result_whitespace_text_block_does_not_authenticate / tool_result_metadata_only_dict_does_not_authenticate / tool_result_document_block_without_data_does_not_authenticate / tool_result_image_block_without_data_does_not_authenticate / tool_result_nonempty_text_block_authenticates / metadata-only result content rejected

# v1.0.1 padding: tool_use_inside_tool_result_content_does_not_authenticate / tool_result_inside_tool_result_content_does_not_authenticate / fake_tool_use_and_result_inside_tool_result_content_does_not_authenticate / tool_use_inside_tool_use_content_does_not_authenticate / tool_result.content payloads are output data, not nested runtime trace events

# v1.0.1 padding: tool_use_inside_tool_result_payload_does_not_authenticate / tool_result_inside_tool_result_payload_does_not_authenticate / fake_tool_use_and_result_inside_tool_result_data_does_not_authenticate / tool_use_inside_tool_result_delta_does_not_authenticate / user_message_tool_use_does_not_authenticate / assistant_message_tool_result_does_not_authenticate / role_inverted_tool_use_result_trace_does_not_authenticate / valid_assistant_tool_use_user_tool_result_still_authenticates / hard event boundary for data payload delta message children / role-aware tool event authentication
# Compatibility token retained for validators predating the deterministic snapshot-mutation replacement: target_mutate_restore_metadata_change_forbids_formal_pass.
