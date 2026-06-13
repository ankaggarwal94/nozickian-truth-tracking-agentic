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
import importlib.util
import io
import json
import shutil
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


def load_runner(package_root: Path):
    path = package_root / SKILL_PATH / "scripts/run_formal_artifact_verification.py"
    spec = importlib.util.spec_from_file_location("formal_runner_under_test", str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod


def write_transcript(lines: List[Dict[str, Any]]) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="nozickian_trace_contract_"))
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

    with tempfile.TemporaryDirectory(prefix="nozickian_formal_output_contract_") as tmp_s:
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
        try:
            parsed = json.loads(out)
            path_checker = getattr(runner, "_path_with", getattr(runner, "_path_within"))
            default_outside = not path_checker(Path(parsed.get("output_dir", ".")), fake_root)
        except Exception:
            default_outside = False
        cases.append({"name": "default_formal_dry_run_output_is_outside_package_tree", "passed": rc == 0 and default_outside and external_json.exists()})

        rc, out = call_runner_main(runner, [str(fake_root), str(target), "--dry-run", "--skip-prechecks", "--output-dir", str(inside), "--json", str(external_json)])
        cases.append({"name": "package_tree_output_dir_rejected_without_refresh_manifest", "passed": rc == 2 and "requires --refresh-release-manifest" in out and not inside.exists()})

        rc, out = call_runner_main(runner, [str(fake_root), str(target), "--dry-run", "--skip-prechecks", "--output-dir", str(external), "--json", str(inside_json)])
        cases.append({"name": "package_tree_json_rejected_without_refresh_manifest", "passed": rc == 2 and "requires --refresh-release-manifest" in out and not inside_json.exists()})

        rc, out = call_runner_main(runner, [str(fake_root), str(target), "--dry-run", "--skip-prechecks", "--output-dir", str(external), "--json", str(external_json)])
        cases.append({"name": "external_output_locations_allowed", "passed": rc == 0 and external_json.exists()})

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
