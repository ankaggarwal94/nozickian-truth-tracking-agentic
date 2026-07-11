#!/usr/bin/env python3
"""Certify a PASS-SCOPED to PASS-TRACKED upgrade bundle.

This script is deliberately conservative. It does not run Claude Code itself; it
checks an external audit bundle produced by the documented upgrade workflow. It
rejects dry-runs, missing official validators, missing live fixture evidence,
missing formal artifact evidence, missing strict-gate PASS-TRACKED status,
missing native stream-json trace authentication, and downstream automatic
closure. It is intended to be the final machine-readable guard before a human or
CI system records a PASS-TRACKED promotion.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
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
DETERMINISTIC_FILES = {
    "package_validation": "deterministic/package_validation.json",
    "gate_result": "deterministic/gate_result.json",
    "regression": "deterministic/regression_eval_result.json",
    "gate_contract": "deterministic/gate_contract_results.json",
    "formal_contract": "deterministic/formal_runner_contract_results.json",
    "manifest_check": "deterministic/manifest_check.txt",
}
OFFICIAL_VALIDATOR_CANDIDATES = {
    "claude_plugin_validate": [
        "official_validators/claude_plugin_validate.json",
        "official_validators/claude_plugin_validate.txt",
        "official_validators/plugin_validate.json",
        "official_validators/plugin_validate.txt",
    ],
    "skills_ref_validate": [
        "official_validators/skills_ref_validate.json",
        "official_validators/skills_ref_validate.txt",
        "official_validators/skill_validate.json",
        "official_validators/skill_validate.txt",
    ],
}


@dataclass
class Check:
    name: str
    passed: bool
    severity: str = "critical"
    details: Any = None


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
        return None, repr(exc)


def relpath(root: Path, path: Path) -> str:
    return os.path.relpath(path, root).replace(os.sep, "/")


def path_lexists(path: Path) -> bool:
    return os.path.lexists(path)


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
            yield current, "unreadable-directory", repr(exc)
            continue
        child_dirs: List[Path] = []
        for entry in entries:
            path = Path(entry.path)
            try:
                mode = entry.stat(follow_symlinks=False).st_mode
            except OSError as exc:
                yield path, "unreadable", repr(exc)
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


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def run_cmd(cmd: Sequence[str], cwd: Optional[Path] = None, timeout: int = 900) -> Dict[str, Any]:
    try:
        # SECURITY-REVIEW: The certifier constructs fixed argv for the
        # package-local validator and never invokes a shell.
        proc = subprocess.run(list(cmd), cwd=str(cwd) if cwd else None, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return {"cmd": list(cmd), "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr[-50000:]}
    except subprocess.TimeoutExpired as exc:
        return {"cmd": list(cmd), "returncode": 124, "stdout": str(exc.stdout or "")[-50000:], "stderr": "timeout"}
    except Exception as exc:
        return {"cmd": list(cmd), "returncode": 125, "stdout": "", "stderr": repr(exc)}


def status_of(data: Any) -> str:
    if isinstance(data, Mapping):
        raw = data.get("status") or data.get("result") or data.get("gate_status")
        return str(raw or "").strip().upper()
    text = str(data or "")
    for token in (PASS_TRACKED, PASS_SCOPED, UNVERIFIED_RUNTIME, "LIMITED", "FAIL", "PASS", "UNVERIFIED"):
        if re.search(r"\b" + re.escape(token) + r"\b", text, flags=re.I):
            return token
    return ""


def file_status_from_text(path: Path) -> Tuple[bool, str]:
    text = read_regular_text(path, errors="replace")
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


def deterministic_checks(
    package_root: Path,
    bundle: Path,
    _run_fresh_compat: bool,
) -> List[Check]:
    """Check bundled outputs and always rerun the current basic validator.

    ``_run_fresh_compat`` preserves the public call/CLI shape used by older
    automation. It no longer disables the fresh validator because promotion
    must never rely only on a captured package-validation artifact.
    """
    checks: List[Check] = []
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
            continue
        if path.suffix == ".json":
            data, err = try_load_json(path)
            checks.append(Check(f"deterministic artifact parses: {name}", err is None, details=err or rel))
            if data is None:
                continue
            if name == "package_validation":
                checks.append(Check("package validation status PASS", data.get("status") == "PASS" and int(data.get("critical_failed", 1)) == 0, details={"status": data.get("status"), "critical_failed": data.get("critical_failed"), "checks": [data.get("checks_passed"), data.get("checks_total")]}))
            elif name == "gate_result":
                checks.append(Check("package self-gate does not fail", data.get("status") in {PASS_TRACKED, PASS_SCOPED}, details={"status": data.get("status"), "summary": data.get("summary")}))
            elif name == "regression":
                checks.append(Check("regression evals pass", data.get("status") == "PASS" and int(data.get("checks_failed", 0)) == 0, details={"status": data.get("status"), "checks_failed": data.get("checks_failed")}))
            elif name in {"gate_contract", "formal_contract"}:
                total = int(data.get("total", 0) or 0)
                passed = int(data.get("passed", 0) or 0)
                checks.append(Check(f"{name} suite all cases pass", total > 0 and passed == total, details={"passed": passed, "total": total}))
        else:
            text = read_regular_text(path, errors="replace")
            checks.append(Check("behavior manifest check says OK", "FAILED" not in text and "No such file" not in text and bool(text.strip()), details=text[-500:]))
    validator = package_root / "skills/nozickian-verify/scripts/validate_package.py"
    validator_error = regular_file_error(validator)
    if validator_error is None:
        cmd = [
            sys.executable,
            str(validator),
            str(package_root),
            "--skip-release-idempotence",
        ]
        result = run_cmd(cmd, cwd=package_root)
        ok = returncode_is_integer_zero(result.get("returncode"))
        try:
            parsed = json.loads(result.get("stdout", "{}"))
            ok = (
                ok
                and parsed.get("status") == "PASS"
                and int(parsed.get("critical_failed", 1)) == 0
            )
            details: Any = {
                "returncode": result.get("returncode"),
                "status": parsed.get("status"),
                "critical_failed": parsed.get("critical_failed"),
                "compatibility_flag_requested": bool(_run_fresh_compat),
                "fresh_validation_unconditional": True,
            }
        except Exception:
            details = {
                "returncode": result.get("returncode"),
                "stderr": result.get("stderr")[-1000:],
                "compatibility_flag_requested": bool(_run_fresh_compat),
                "fresh_validation_unconditional": True,
            }
    else:
        ok = False
        details = {
            "error": validator_error,
            "compatibility_flag_requested": bool(_run_fresh_compat),
            "fresh_validation_unconditional": True,
        }
    checks.append(
        Check(
            "fresh deterministic package validator still passes",
            ok,
            details=details,
        )
    )
    return checks


def official_validator_checks(bundle: Path, allow_scope_exclusion: bool) -> List[Check]:
    checks: List[Check] = []
    for name, rels in OFFICIAL_VALIDATOR_CANDIDATES.items():
        found = next((bundle / rel for rel in rels if path_lexists(bundle / rel)), None)
        if found is None:
            checks.append(Check(f"official validator present: {name}", allow_scope_exclusion, severity="major" if allow_scope_exclusion else "critical", details="missing official validator output; retaining scope limitation if allowed"))
            continue
        file_error = regular_file_error(found)
        checks.append(
            Check(
                f"official validator is regular file: {name}",
                file_error is None,
                details=file_error or relpath(bundle, found),
            )
        )
        if file_error is not None:
            continue
        if found.suffix == ".json":
            data, err = try_load_json(found)
            checks.append(Check(f"official validator parses: {name}", err is None, details=err or relpath(bundle, found)))
            if data is None:
                continue
            ok, reason, status_details = json_validator_status(data)
            checks.append(
                Check(
                    f"official validator passed: {name}",
                    ok,
                    details={
                        "file": relpath(bundle, found),
                        "reason": reason,
                        **status_details,
                    },
                )
            )
        else:
            try:
                ok, reason = file_status_from_text(found)
            except (OSError, ValueError) as exc:
                ok, reason = False, repr(exc)
            checks.append(Check(f"official validator passed: {name}", ok, details={"file": relpath(bundle, found), "reason": reason}))
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
    path = bundle / "live_fixtures/live_runtime_eval_result.json"
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
            artifact_error = repr(exc)
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
    checks.append(Check("live runtime was executed", status not in {None, "", UNVERIFIED_RUNTIME, "UNVERIFIED", "FAIL", "LIMITED"}, details={"status": status, "reason": data.get("reason")}))
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
            and identity_mapping.get("executable_fingerprint_error") in {None, ""},
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
    )
    plugin_preflight_ok = (
        plugin_command.get("cmd") == expected_plugin_argv
        and returncode_is_integer_zero(plugin_command.get("returncode"))
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
            checks.append(Check(f"live fixture {idx} command returned zero", returncode_is_integer_zero(item.get("returncode")), details={"id": fixture_id, "returncode": item.get("returncode")}))
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
                artifact_error = repr(exc)
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
                    returncode_is_integer_zero(
                        transcript_data.get("returncode")
                    )
                    and returncode_is_integer_zero(item.get("returncode")),
                    details={
                        "id": fixture_id,
                        "result_returncode": item.get("returncode"),
                        "transcript_returncode": transcript_data.get("returncode"),
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


def find_formal_results(bundle: Path) -> Tuple[List[Path], List[Dict[str, Any]]]:
    root = bundle / "formal_artifacts"
    paths: Dict[str, Path] = {}
    unsafe: List[Dict[str, Any]] = []
    for path, kind, error in walk_tree_no_follow(root):
        if kind == "regular":
            if path.name == "formal_result.json" or (
                "formal_result" in path.name and path.suffix == ".json"
            ):
                paths[relpath(bundle, path)] = path
        elif kind in {"symlink", "special", "unreadable", "unreadable-directory", "invalid"}:
            unsafe.append(
                {
                    "path": relpath(bundle, path),
                    "kind": kind,
                    "error": error,
                }
            )
    return [paths[key] for key in sorted(paths)], unsafe


def matching_regular_files(directory: Path, pattern: str) -> Tuple[List[Path], List[str]]:
    matches: List[Path] = []
    errors: List[str] = []
    try:
        entries = sorted(directory.iterdir(), key=lambda path: path.name)
    except OSError as exc:
        return [], [repr(exc)]
    for path in entries:
        if not path.match(pattern):
            continue
        file_error = regular_file_error(path)
        if file_error:
            errors.append(file_error)
        else:
            matches.append(path)
    return matches, errors


def formal_artifact_checks(package_root: Path, bundle: Path) -> List[Check]:
    checks: List[Check] = []
    results, unsafe = find_formal_results(bundle)
    checks.append(
        Check(
            "formal artifact tree has no symlink, special, or unreadable inputs",
            not unsafe,
            details=unsafe,
        )
    )
    checks.append(Check("at least one formal artifact result present", bool(results), details=[relpath(bundle, p) for p in results]))
    if not results:
        return checks
    runner_path = package_root / "skills/nozickian-verify/scripts/run_formal_artifact_verification.py"
    gate_path = package_root / "skills/nozickian-verify/scripts/ntt_gate.py"
    runner_error = regular_file_error(runner_path)
    gate_error = regular_file_error(gate_path)
    checks.append(Check("formal runner source is a regular file", runner_error is None, details=runner_error))
    checks.append(Check("strict gate source is a regular file", gate_error is None, details=gate_error))
    if runner_error is not None or gate_error is not None:
        return checks
    runner = load_module("ntt_formal_runner_for_promotion", runner_path)
    gate = load_module("ntt_gate_for_promotion", gate_path)
    for idx, path in enumerate(results, start=1):
        data, err = try_load_json(path)
        checks.append(Check(f"formal result {idx} parses", err is None, details=err or relpath(bundle, path)))
        if not isinstance(data, Mapping):
            continue
        checks.append(Check(f"formal result {idx} status PASS-TRACKED", data.get("status") == PASS_TRACKED, details={"status": data.get("status"), "reason": data.get("reason")}))
        checks.append(Check(f"formal result {idx} gate_status PASS-TRACKED", data.get("gate_status") == PASS_TRACKED, details=data.get("gate_status")))
        auth = data.get("trace_authentication") or {}
        checks.append(Check(f"formal result {idx} trace authenticated", isinstance(auth, Mapping) and auth.get("authenticated") is True, details=auth))
        if isinstance(auth, Mapping):
            missing = list(auth.get("missing_agents") or []) + list(auth.get("missing_result_agents") or [])
            checks.append(Check(f"formal result {idx} no missing native lane events", not missing, details=missing))
            calls = set(auth.get("agent_calls_authenticated") or [])
            results_auth = set(auth.get("agent_results_authenticated") or [])
            checks.append(Check(f"formal result {idx} all required native lanes authenticated", set(REQUIRED_NATIVE_AGENTS).issubset(calls) and set(REQUIRED_NATIVE_AGENTS).issubset(results_auth), details={"calls": sorted(calls), "results": sorted(results_auth)}))
            checks.append(Check(f"formal result {idx} no general-purpose fallback", auth.get("saw_general_purpose") is False, details=auth.get("saw_general_purpose")))
            checks.append(Check(f"formal result {idx} no role violations", not auth.get("role_violations"), details=auth.get("role_violations")))
        result_dir = path.parent
        transcript_pointer = data.get("transcript_file")
        transcript_name = (
            PurePosixPath(str(transcript_pointer).replace("\\", "/")).name
            if isinstance(transcript_pointer, str) and transcript_pointer.strip()
            else ""
        )
        transcript = result_dir / transcript_name if transcript_name else Path("")
        transcript_error = (
            regular_file_error(transcript)
            if transcript_name
            else "formal result does not name a transcript"
        )
        checks.append(
            Check(
                f"formal result {idx} transcript is self-contained regular file",
                transcript_error is None,
                details={
                    "bundle_path": relpath(bundle, transcript) if transcript_name else None,
                    "ignored_pointer": transcript_pointer,
                    "error": transcript_error,
                },
            )
        )
        if transcript_error is None:
            parsed_auth = runner.authenticate_trace(transcript)
            checks.append(Check(f"formal result {idx} transcript re-authenticates", parsed_auth.get("authenticated") is True, details=parsed_auth))
        certs, cert_errors = matching_regular_files(
            result_dir,
            "*_NOZICKIAN_certificate.json",
        )
        checks.append(
            Check(
                f"formal result {idx} generated certificate is self-contained regular file",
                bool(certs) and not cert_errors,
                details={
                    "files": [relpath(bundle, item) for item in certs],
                    "errors": cert_errors,
                },
            )
        )
        for cert in certs[:1]:
            try:
                cert_data = load_json(cert)
                gate_result = gate.evaluate_certificate(
                    cert_data,
                    evidence_root=result_dir,
                    strict_evidence=True,
                )
                checks.append(Check(f"formal result {idx} generated certificate strict gate PASS-TRACKED", gate_result.get("status") == PASS_TRACKED, details={"status": gate_result.get("status"), "summary": gate_result.get("summary"), "reasons": gate_result.get("reasons")}))
                downstream_violations = gate_result.get("summary", {}).get("downstream_nonclosure_violations", 0)
                checks.append(Check(f"formal result {idx} no downstream non-closure violations", downstream_violations == 0, details=gate_result.get("summary")))
            except Exception as exc:
                checks.append(Check(f"formal result {idx} generated certificate strict gate evaluates", False, details=repr(exc)))
        ledgers, ledger_errors = matching_regular_files(
            result_dir,
            "*_NOZICKIAN_INVOCATION_LEDGER.md",
        )
        checks.append(
            Check(
                f"formal result {idx} invocation ledger is self-contained regular file",
                bool(ledgers) and not ledger_errors,
                details={
                    "files": [relpath(bundle, item) for item in ledgers],
                    "errors": ledger_errors,
                },
            )
        )
        if ledgers:
            text = read_regular_text(ledgers[0], errors="replace").lower()
            checks.append(Check(f"formal result {idx} ledger says no substitution", "substitution used: none" in text and "formal_subagent_failure" not in text, details=ledgers[0].name))
    return checks


URI_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:")


def safe_relative_posix_path(value: Any) -> Tuple[Optional[PurePosixPath], Optional[str]]:
    if not isinstance(value, str) or not value:
        return None, "path is not a nonempty string"
    if "\\" in value:
        return None, "path uses a non-canonical separator"
    if URI_SCHEME_RE.match(value):
        return None, "path has a URI scheme"
    posix = PurePosixPath(value)
    if posix.is_absolute():
        return None, "path is absolute"
    if not posix.parts or any(part in {"", ".", ".."} for part in posix.parts):
        return None, "path is empty, dotted, or traverses"
    return posix, None


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
                "shared package-tree computation failed: " + repr(exc)
            ],
        }


def bundle_evidence_ref_errors(bundle: Path, refs: Any) -> List[str]:
    if not isinstance(refs, list):
        return ["evidence_refs is not a list"]
    errors: List[str] = []
    seen_raw: set[str] = set()
    seen_canonical: set[str] = set()
    bundle_root = bundle.resolve()
    for index, ref in enumerate(refs, start=1):
        posix, path_error = safe_relative_posix_path(ref)
        if path_error is not None or posix is None:
            errors.append(f"evidence_refs[{index}]: {path_error}")
            continue
        raw = posix.as_posix()
        if raw in seen_raw:
            errors.append(f"evidence_refs[{index}]: duplicate path {raw}")
            continue
        seen_raw.add(raw)
        candidate = bundle.joinpath(*posix.parts)
        file_error = regular_file_error(candidate)
        if file_error:
            errors.append(f"evidence_refs[{index}]: {file_error}")
            continue
        try:
            resolved = candidate.resolve(strict=True)
            canonical = resolved.relative_to(bundle_root).as_posix()
        except (OSError, ValueError):
            errors.append(f"evidence_refs[{index}]: path resolves outside audit bundle")
            continue
        if canonical in seen_canonical:
            errors.append(
                f"evidence_refs[{index}]: duplicate canonical path {canonical}"
            )
            continue
        seen_canonical.add(canonical)
    return errors


def promotion_certificate_checks(package_root: Path, bundle: Path) -> List[Check]:
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
    checks.append(Check("promotion certificate records upgrade_from_status PASS-SCOPED", data.get("upgrade_from_status") == PASS_SCOPED, details=data.get("upgrade_from_status")))
    checks.append(Check("promotion certificate requests PASS-TRACKED", data.get("requested_status") == PASS_TRACKED, details=data.get("requested_status")))
    plugin = try_load_json(package_root / ".claude-plugin/plugin.json")[0] or {}
    current_version = str(plugin.get("version") or "")
    checks.append(Check("promotion certificate package version matches plugin", str(data.get("package_version") or data.get("plugin_version") or "") == current_version, details={"certificate": data.get("package_version") or data.get("plugin_version"), "plugin": current_version}))
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
    refs = data.get("evidence_refs")
    checks.append(Check("promotion certificate has evidence refs", isinstance(refs, list) and len(refs) >= 5, details=f"count={len(refs) if isinstance(refs, list) else 'n/a'}"))
    ref_errors = bundle_evidence_ref_errors(bundle, refs)
    checks.append(
        Check(
            "promotion certificate evidence refs are unique bundle-local regular files",
            not ref_errors,
            details=ref_errors,
        )
    )
    downstream = data.get("derived_or_downstream_claims") or []
    if downstream:
        bad = [r for r in downstream if isinstance(r, Mapping) and str(r.get("status") or "").upper() in {PASS_TRACKED, PASS_SCOPED, "PASS", "VERIFIED"} and not r.get("own_claim_id")]
        checks.append(Check("promotion certificate has no automatic downstream pass inheritance", not bad, details=bad[:3]))
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
        for p, kind, entry_error in walk_tree_no_follow(
            root,
            skip_dir_names=(".git", "__pycache__"),
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
                text = read_regular_text(p, errors="replace")
            except Exception as exc:
                unsafe.append(
                    {
                        "root": root_label,
                        "path": rel,
                        "kind": "unreadable",
                        "error": repr(exc),
                    }
                )
                continue
            for pat in stale_patterns:
                m = re.search(pat, text)
                if m:
                    hits.append({"root": root_label, "path": rel, "pattern": pat, "excerpt": text[max(0, m.start()-60):m.end()+60].replace("\n", " ")})
                    break
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


def summarize(checks: List[Check], allow_official_scope_exclusion: bool) -> Dict[str, Any]:
    critical_failed = [c for c in checks if c.severity == "critical" and not c.passed]
    major_failed = [c for c in checks if c.severity == "major" and not c.passed]
    if critical_failed:
        status = "FAIL"
    elif major_failed or allow_official_scope_exclusion:
        status = PASS_SCOPED
    else:
        status = PASS_TRACKED
    return {
        "status": status,
        "checks_total": len(checks),
        "checks_passed": sum(1 for c in checks if c.passed),
        "critical_failed": len(critical_failed),
        "major_failed": len(major_failed),
        "checks": [asdict(c) for c in checks],
        "failed_checks": [asdict(c) for c in checks if not c.passed],
    }


def to_markdown(result: Mapping[str, Any]) -> str:
    lines = ["# PASS-TRACKED upgrade certification", "", f"Status: **{result.get('status')}**", "", "| Check | Severity | Result | Details |", "|---|---|---:|---|"]
    for c in result.get("checks", []):
        details = json.dumps(c.get("details"), sort_keys=True)[:600] if c.get("details") is not None else ""
        lines.append(f"| {c.get('name')} | {c.get('severity')} | {'PASS' if c.get('passed') else 'FAIL'} | {details} |")
    return "\n".join(lines) + "\n"


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

    package_root = args.package_root.resolve()
    bundle = args.audit_bundle.resolve()
    checks: List[Check] = []
    package_root_error = directory_error(package_root)
    bundle_error = directory_error(bundle)
    checks.append(Check("package root exists as regular directory", package_root_error is None, details=package_root_error or str(package_root)))
    checks.append(Check("audit bundle exists as regular directory", bundle_error is None, details=bundle_error or str(bundle)))
    if package_root_error is None and bundle_error is None:
        checks.extend(deterministic_checks(package_root, bundle, args.run_fresh_package_validator))
        checks.extend(official_validator_checks(bundle, args.allow_official_validator_scope_exclusion))
        checks.extend(live_fixture_checks(package_root, bundle))
        checks.extend(formal_artifact_checks(package_root, bundle))
        checks.extend(promotion_certificate_checks(package_root, bundle))
        checks.extend(stale_token_checks(package_root, bundle))
    result = summarize(checks, args.allow_official_validator_scope_exclusion)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(to_markdown(result), encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == PASS_TRACKED else 2


if __name__ == "__main__":
    raise SystemExit(main())
