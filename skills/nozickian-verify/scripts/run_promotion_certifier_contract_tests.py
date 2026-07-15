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
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

SKILL_SCRIPTS = Path("skills/nozickian-verify/scripts")
# macOS may expose the temp root through /var -> /private/var. Resolve that
# platform alias so positive controls do not themselves contain a link.
CANONICAL_TEMP_ROOT = Path(tempfile.gettempdir()).resolve()


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
                "is_error": False,
                "result": (
                    f"Verification report for {Path(artifact).name}: method M "
                    "was inspected; false-world sensitivity and true-world "
                    "adherence were tested; final gate status: PASS-SCOPED."
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
    write_json(
        bundle / "live_fixtures/live_runtime_eval_result.json",
        {
            "status": certifier.PASS_SCOPED,
            "reason": "synthetic contract origin traversed the live lane",
            "package_tree_algorithm": tree["algorithm"],
            "package_tree_sha256": tree["sha256"],
            "fixture_spec_sha256": certifier.sha256_path(evals_path),
            "execution_package_snapshot_identity": {
                "mode": "private-read-only-stable-release-snapshot",
                "source_pre": live_tree_identity,
                "source_post": live_tree_identity,
                "snapshot_pre": live_tree_identity,
                "snapshot_post": live_tree_identity,
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
                {"cmd": ["<claude-cli>", "--version"], "returncode": 0},
                {
                    "cmd": [
                        "<claude-cli>",
                        "plugin",
                        "validate",
                        "<package-root>",
                    ],
                    "returncode": 0,
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
    claim_id: str,
    claim_text: str,
    records_dir: str,
    observations_dir: str,
    modal_cases: Sequence[Tuple[str, Dict[str, Any], str]],
) -> Tuple[List[str], str]:
    """Write proposition- and modal-bound evidence for one synthetic claim."""
    claim_digest = gate._proposition_sha256(  # pylint: disable=protected-access
        claim_text
    )
    if type(claim_digest) is not str:
        raise RuntimeError("synthetic claim proposition could not be hashed")
    prefixed_claim_digest = f"sha256:{claim_digest}"

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
                "evidence_schema_version": "1.0",
                "claim_id": claim_id,
                "claim_proposition_sha256": prefixed_claim_digest,
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
            "modal_case_sha256": prefixed_modal_digest,
            "result": test["result"],
            "outcome": test["outcome"],
            "observed_result": observed_result,
        }
        modal_wrappers.append(
            (
                record_rel,
                {
                    "evidence_schema_version": "1.0",
                    "claim_id": claim_id,
                    "claim_proposition_sha256": prefixed_claim_digest,
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
            "observation_schema_version": "1.0",
            "observations": observations,
        },
    )
    ledger_digest = f"sha256:{gate.sha256_path(ledger)}"
    for record_rel, wrapper in modal_wrappers:
        wrapper["hash_or_version"] = ledger_digest
        write_json(evidence_root / record_rel, wrapper)
    return claim_refs, prefixed_claim_digest


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
    }]
    claim_refs, proposition_digest = write_strict_gate_evidence(
        gate,
        result_dir,
        claim_id="C-SYNTHETIC",
        claim_text=claim_text,
        records_dir="evidence",
        observations_dir="observations",
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
                "id": "C-SYNTHETIC",
                "text": claim_text,
                "proposition_sha256": proposition_digest,
                "importance": "critical",
                "artifact_location": "synthetic-target.md",
                "truth_status": "executed_confirmed",
                "method_m": method,
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
        "Substitution used: none\nMachine gate run: runner-managed\n",
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
        "\n".join(json.dumps(item) for item in transcript_lines) + "\n",
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
    result = {
        "run_id": "synthetic-aggregate-run-001",
        "status": certifier.PASS_TRACKED,
        "reason": "synthetic origin exercises production validation only",
        "package_tree_identity": formal_tree_identity,
        "execution_package_snapshot_identity": {
            "mode": "private-read-only-stable-release-snapshot",
            "source_pre": formal_tree_identity,
            "source_post": formal_tree_identity,
            "snapshot_pre": formal_tree_identity,
            "snapshot_post": formal_tree_identity,
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
        "commands": [],
        "prechecks": [],
        "precheck_summary": {
            "total": 0,
            "passed": 0,
            "failed": 0,
            "failed_commands": [],
        },
        "output_checks": [],
        "gate_status": certifier.PASS_TRACKED,
        "trace_authentication": trace_auth,
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
    )
    write_json(out["formal_result"], canonical)
    return out["formal_result"]


def write_passing_promotion_claim(
    certifier: Any,
    gate: Any,
    bundle: Path,
    claim_id: str,
    slug: str,
) -> Dict[str, Any]:
    """Write one independently gate-passable promotion claim and evidence."""
    method = synthetic_method()
    claim_text = f"Independent promotion claim {claim_id} is tracked."
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
    }]
    claim_refs, proposition_digest = write_strict_gate_evidence(
        gate,
        bundle,
        claim_id=claim_id,
        claim_text=claim_text,
        records_dir=f"promotion_claims/{slug}/records",
        observations_dir=f"promotion_claims/{slug}/observations",
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
        "id": claim_id,
        "text": claim_text,
        "proposition_sha256": proposition_digest,
        "importance": "critical",
        "artifact_location": f"promotion_claims/{slug}",
        "truth_status": "executed_confirmed",
        "method_m": method,
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
    write_json(
        bundle / "promotion_certificate.json",
        {
            "promotion_schema_version": "2.0",
            "origin": "synthetic-contract",
            "upgrade_from_status": certifier.PASS_SCOPED,
            "requested_status": certifier.PASS_TRACKED,
            "package_version": plugin["version"],
            "package_tree_sha256": f"sha256:{tree['sha256']}",
            "method_m_upgrade": {
                "synthetic_contract": True,
            },
            "live_result_bindings": {
                "synthetic_contract": True,
            },
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
        },
    )


def refresh_node_hash(
    certifier: Any,
    bundle: Path,
    certificate: Dict[str, Any],
    role: str,
) -> None:
    node = certificate["evidence"]["nodes"][role]
    node["sha256"] = (
        f"sha256:{certifier.sha256_path(bundle / node['path'])}"
    )


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
    "formal": 60,
    "hygiene": 2,
}
EXPECTED_CASE_NAMES = (
    "complete_synthetic_baseline_cli_is_capped",
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
EXPECTED_CASE_TOTAL = 36
EXPECTED_POSITIVE_MUTATION_CHECK_INVENTORIES: Dict[
    str, Tuple[int, str]
] = {
    "distinct_formal_roles_may_contain_equal_bytes": (
        248,
        "1434e80fb2ce1a002d30754e9e304dbe76565e69c3e35ce87232d731550a131a",
    ),
    "official_scope_exclusion_retains_fixed_role_dag": (
        248,
        "c14c9c71638af1d5d92d81f741f8ca8632e2bd3ebf4eb2ba37bf9584dbbd8e82",
    ),
    "independently_passing_downstream_claim_accepted_before_cap": (
        248,
        "1434e80fb2ce1a002d30754e9e304dbe76565e69c3e35ce87232d731550a131a",
    ),
}
EXPECTED_MUTATION_CHECK_INVENTORIES: Dict[str, Tuple[int, str]] = {
    "missing_promotion_schema_version": (
        248,
        "dc10831b2f5a77ff28849f2df0f76cd7a10193e28683c28ccac9fb7ac7351eb1",
    ),
    "wrong_type_promotion_schema_version": (
        248,
        "dc10831b2f5a77ff28849f2df0f76cd7a10193e28683c28ccac9fb7ac7351eb1",
    ),
    "stale_deterministic_capture_wrong_tree": (
        247,
        "c332bbed3124a0618cb608e30692c14615c0e90c7545a563359b14b6a341ff89",
    ),
    "fabricated_official_text_policy": (
        248,
        "16c653f90403f29ccfb2a74c8c7564437f70c278740595d30b0b068fef7dcc04",
    ),
    "decoy_formal_companion": (
        248,
        "45f07302bc8c224aa4be995922e849dbd7218bdc1182af70be1f020124db0bd0",
    ),
    "swapped_formal_companions": (
        248,
        "4919306cc591c504c47ebee43ab32c99353b903ce722b61500278eba2b34b439",
    ),
    "dummy_untyped_evidence": (
        137,
        "a8c9b84d54b814b0bc38cba9e2733fd96c5e7055195a073754c2fae549712cdd",
    ),
    "fake_own_claim_id": (
        248,
        "b9939876216c9b7438c6437b656b9611f031daa5c2b655c432c1af50c2dcfd32",
    ),
    "malformed_claim_nonobject": (
        246,
        "62ee2bfd88f361bc5f6168dbdd8b0c9517020e827fff67f7acffbdde86158b1e",
    ),
    "malformed_claim_null_entry": (
        246,
        "62ee2bfd88f361bc5f6168dbdd8b0c9517020e827fff67f7acffbdde86158b1e",
    ),
    "malformed_claims_null": (
        246,
        "52dfc65ed6c92deb8a74cae081ccbc6739b84e96711aefd078b68def77db2d05",
    ),
    "empty_promotion_claims_rejected": (
        246,
        "62ee2bfd88f361bc5f6168dbdd8b0c9517020e827fff67f7acffbdde86158b1e",
    ),
    "malformed_claim_bool_id": (
        246,
        "62ee2bfd88f361bc5f6168dbdd8b0c9517020e827fff67f7acffbdde86158b1e",
    ),
    "malformed_claim_duplicate_id": (
        246,
        "62ee2bfd88f361bc5f6168dbdd8b0c9517020e827fff67f7acffbdde86158b1e",
    ),
    "malformed_claim_invalid_id": (
        246,
        "62ee2bfd88f361bc5f6168dbdd8b0c9517020e827fff67f7acffbdde86158b1e",
    ),
    "malformed_scalar": (
        248,
        "71b94642bc99aa9ff8d007194b7c5595922ccc858d220310e68a5921f7d97098",
    ),
    "official_stderr_contradiction_dominates_stdout": (
        248,
        "80f784a62273ec0ead79259d9f586c08eef911a76c254ef9b53fe641d1c2a2c9",
    ),
    "official_structured_stderr_failure_dominates_stdout": (
        248,
        "80f784a62273ec0ead79259d9f586c08eef911a76c254ef9b53fe641d1c2a2c9",
    ),
    "official_mixed_jsonl_stderr_failure_dominates_stdout": (
        248,
        "80f784a62273ec0ead79259d9f586c08eef911a76c254ef9b53fe641d1c2a2c9",
    ),
    "official_early_failure_survives_large_neutral_tail": (
        248,
        "80f784a62273ec0ead79259d9f586c08eef911a76c254ef9b53fe641d1c2a2c9",
    ),
    "formal_package_identity_bool_int_alias": (
        248,
        "107f445ca7a77476394fb11dc0f62e29800e476d7a6d88d26c4841c199492474",
    ),
    "formal_trace_authenticated_bool_int_alias": (
        248,
        "3adeca4bc50f722074aa4aad0ef50e498f9e1ff8262ec170ba91b0dd2c56fc6c",
    ),
    "formal_transcript_without_authentic_native_events": (
        248,
        "efdb862db6bf05cb3a41b5523a26a8c8002c66578aa07ce1a7d3eda02833340c",
    ),
    "formal_trace_authentication_missing": (
        248,
        "a2e92b27f3ee285085c3dbec88920d150790d9c6865e5d1b4cb17d44ae000053",
    ),
    "noncanonical_promotion_evidence_path": (
        245,
        "7e07360bd4b80c2887c0a04565107b65e1ef87211a5f10fd93bff572138dc691",
    ),
    "oversized_evidence_graph_is_bounded": (
        187,
        "a5ffa330df71635dc1417c3dccf3de13d5bc6cead624db16c08fe74a917bae0a",
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
        "live execution used one stable immutable package snapshot",
        "live fixture specification SHA-256 matches current evals bytes",
        "live runtime status has an exact string type",
        "live runtime was executed",
        "live runtime status is PASS-SCOPED",
        "live provenance schema is 1.0",
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
        "formal result status PASS-TRACKED",
        "formal result gate_status PASS-TRACKED",
        "formal result uses one bundle-local evidence root",
        "formal result package-tree identity has exact JSON schema",
        "formal result package-tree identity matches current package",
        "formal execution package snapshot is stable and current",
        (
            "formal Claude executable path, version, and pre/post identity "
            "are bound"
        ),
        "formal and live evidence bind the same Claude runtime",
        "current formal runner is a regular file",
        "formal companion specifications load from current runner",
        "formal runner exports exact result schema specifications",
        "formal result projected fields have exact JSON types",
        "formal result declares standalone immutable snapshot context",
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
        "formal result directory has no undeclared reserved companions",
        "formal target snapshot binds stable pre/post digest",
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
            malformed_failed_checks_rejected = False
            try:
                failed_check_inventory({"failed_checks": ["not-an-object"]})
            except ValueError:
                malformed_failed_checks_rejected = True
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
                    and production_certifier_cli_baseline
                    and malformed_failed_checks_rejected
                    and baseline_roles_and_dag_exact
                    and obligations_exact
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
                "promotion_roles_and_dag_exact": (
                    baseline_roles_and_dag_exact
                ),
                "unresolved_charter_obligations": observed_obligations,
                "expected_unresolved_charter_obligations": (
                    expected_obligations
                ),
                "unresolved_charter_obligations_exact": obligations_exact,
                "official_argv_exact": official_argv_exact,
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
            cases.append({
                "name": "official_fake_exact_argv_and_real_format",
                "passed": (
                    exact_claude.returncode == 0
                    and exact_claude.stdout == expected_claude_stdout
                    and exact_claude.stderr == ""
                    and certifier.official_validator_status(
                        ansi_success,
                        "",
                        validator_id="claude_plugin_validate",
                    )[0]
                    is True
                    and missing_strict.returncode != 0
                    and wrong_strict.returncode != 0
                    and "unexpected argv" in missing_strict.stderr
                    and "unexpected argv" in wrong_strict.stderr
                ),
                "exact_returncode": exact_claude.returncode,
                "missing_strict_returncode": missing_strict.returncode,
                "wrong_strict_returncode": wrong_strict.returncode,
                "observed_stdout": exact_claude.stdout,
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
                    ((
                        "formal result directory has no undeclared reserved "
                        "companions"
                    ), "INVALID_INPUT", "synthetic-target_NOZICKIAN_certificate.json"),
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
                [(
                    "promotion evidence node is typed: formal.result",
                    "INVALID_INPUT",
                    "node is not an object",
                )],
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
                        bundle,
                        certificate,
                        "formal.result",
                    ),
                )

            run_mutation(
                "formal_transcript_without_authentic_native_events",
                transcript_without_authentic_native_events,
                "CHECK_FAILED",
                [(
                    "formal transcript re-authenticates and matches "
                    "recorded semantics",
                    "CHECK_FAILED",
                    "\"parsed_authenticated\": false",
                )],
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
                [(
                    "promotion evidence node count is bounded",
                    "INVALID_INPUT",
                    "\"maximum\"",
                )],
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
            cases.append({
                "name": "certifier_json_regular_file_is_atomically_replaced",
                "passed": (
                    replace_rc == 2
                    and replace_result.get("status") == certifier.PASS_SCOPED
                    and replace_result.get("outcome") == "CAPPED"
                    and replace_invocation.get("verified") is True
                    and replaced_bytes != original_regular_bytes
                    and replaced_result == replace_result
                    and stat.S_ISREG(replace_metadata.st_mode)
                    and replace_metadata.st_nlink == 1
                ),
                "execution_mode": "production-certifier-cli",
                "exit_code": replace_rc,
                "status": replace_result.get("status"),
                "cli_invocation_verified": replace_invocation.get("verified"),
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
    print(text)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(text + "\n", encoding="utf-8")
    return 0 if result.get("status") == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
