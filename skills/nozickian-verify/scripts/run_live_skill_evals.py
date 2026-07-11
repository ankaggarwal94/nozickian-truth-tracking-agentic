#!/usr/bin/env python3
"""Live Claude Code plugin eval harness for Nozickian verification.

This harness is intentionally evidence-producing and conservative. It can run
actual slash-command fixture invocations in non-interactive print mode when the
Claude Code CLI is installed. If the runtime cannot be exercised, it records
UNVERIFIED_RUNTIME rather than treating a version check as a pass.
"""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, os, re, shutil, stat, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Mapping, Sequence, Tuple

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
        proc = subprocess.run(literal_cmd, cwd=str(cwd) if cwd else None, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
        return {
            "cmd": display_cmd,
            "command_metadata": command_metadata,
            "returncode": proc.returncode,
            "stdout": normalize_display(proc.stdout[-12000:], display_replacements),
            "stderr": normalize_display(proc.stderr[-12000:], display_replacements),
            "duration_sec": round(time.time()-started, 3),
        }
    except subprocess.TimeoutExpired as exc:
        stdout = (exc.stdout or "")[-12000:] if isinstance(exc.stdout, str) else ""
        stderr = (exc.stderr or "")[-12000:] if isinstance(exc.stderr, str) else "timeout"
        return {
            "cmd": display_cmd,
            "command_metadata": command_metadata,
            "returncode": 124,
            "stdout": normalize_display(stdout, display_replacements),
            "stderr": normalize_display(stderr, display_replacements),
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
        spec.loader.exec_module(module)
        shared_tree = getattr(module, "compute_stable_release_tree", None)
        if not callable(shared_tree):
            raise AttributeError(
                "compute_stable_release_tree is not callable"
            )
        result = shared_tree(root)
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
            "errors": [f"shared package-tree computation failed: {exc!r}"],
        }


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
            [executable_argv, "plugin", "validate", str(root)],
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
                artifact = fixture_artifact_path(root, item.get("artifact"))
                artifact_sha256 = sha256_regular_file(
                    artifact,
                    f"fixture artifact {item.get('id', 'fixture')}",
                )
            except (OSError, ValueError) as exc:
                fixture_binding_failure = (
                    f"{type(exc).__name__} while binding fixture artifact"
                )
                break
            prompt = build_fixture_prompt(plugin_name, item.get('id','fixture'), artifact)
            canonical_prompt = normalize_display(prompt, display_replacements)
            out_dir.mkdir(parents=True, exist_ok=True)
            cmd = [executable_argv, "--plugin-dir", str(root), "-p", "--output-format", "json", "--max-turns", str(args.max_turns), prompt]
            cmd_result = run_cmd(
                cmd,
                cwd=root,
                timeout=args.timeout_sec,
                display_replacements=display_replacements,
            )
            transcript_file = out_dir / f"{item.get('id','fixture')}.json"
            transcript_bytes = json.dumps(
                cmd_result,
                indent=2,
                sort_keys=True,
            ).encode("utf-8")
            transcript_file.write_bytes(transcript_bytes)
            checks = transcript_checks(str(cmd_result.get("stdout") or ""), item["artifact"])
            fixture_results.append(
                {
                    "id": item.get('id'),
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
    display_result = normalize_display(result, display_replacements)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True); args.json.write_text(json.dumps(display_result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(display_result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS-SCOPED" or (result["status"] == "UNVERIFIED_RUNTIME" and not args.require_claude) else 2

if __name__ == "__main__":
    raise SystemExit(main())
