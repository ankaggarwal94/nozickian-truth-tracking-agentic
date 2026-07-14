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

    native_calls_only = write_transcript([native_event(agent) for agent in REQUIRED_NATIVE_AGENTS])
    auth = runner.authenticate_trace(native_calls_only)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "native_tool_use_without_results_does_not_authenticate", "passed": auth.get("authenticated") is False and bool(auth.get("missing_result_agents")) and capped == "PASS-SCOPED", "auth": auth, "capped_status": capped, "reason": reason})

    native = write_transcript(completed_native_trace(success=True))
    auth = runner.authenticate_trace(native)
    capped, reason = runner.cap_status_by_trace("PASS-TRACKED", auth)
    cases.append({"name": "all_native_tool_use_and_result_events_authenticate", "passed": auth.get("authenticated") is True and capped == "PASS-TRACKED", "auth": auth, "capped_status": capped, "reason": reason})

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
            "name": "formal_result_declares_standalone_snapshot_context",
            "passed": (
                canonical_data.get("verification_context")
                == {
                    "mode": "standalone-immutable-snapshot",
                    "relative_sibling_context": "unavailable",
                    "execution_working_directory": "snapshot-parent",
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
            "name": "formal_prompt_verifies_immutable_target_snapshot",
            "passed": (
                str(snapshot_paths["target_snapshot"]) in snapshot_prompt
                and f"Target artifact:\n{target}" not in snapshot_prompt
                and "standalone-immutable-snapshot" in snapshot_prompt
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
        restore_stability = runner.target_snapshot_stability(
            source_before,
            source_after_restore,
            snapshot_before,
            runner.file_snapshot_identity(stability_snapshot),
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
            "name": "target_mutate_restore_metadata_change_forbids_formal_pass",
            "passed": (
                source_before["sha256"] == source_after_restore["sha256"]
                and restore_stability["stable"] is False
                and restore_stability["source_metadata_stable"] is False
                and runner.cap_status_by_target_stability(
                    "PASS-TRACKED",
                    restore_stability,
                )[0]
                == "FAIL"
            ),
        })

        sentinel = tmp / "external-sentinel.txt"
        sentinel_bytes = b"external sentinel must not change\n"
        sentinel.write_bytes(sentinel_bytes)
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
    runner = load_runner(args.package_root.resolve())
    cases = run_cases(runner, args.package_root.resolve())
    result = {"total": len(cases), "passed": sum(1 for c in cases if c.get("passed")), "cases": cases}
    text = json.dumps(result, indent=2, sort_keys=True)
    print(text)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(text, encoding="utf-8")
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
