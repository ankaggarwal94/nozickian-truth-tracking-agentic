#!/usr/bin/env python3
"""Live Claude Code plugin eval harness for Nozickian verification.

This harness is intentionally evidence-producing and conservative. It can run
actual slash-command fixture invocations in non-interactive print mode when the
Claude Code CLI is installed. If the runtime cannot be exercised, it records
UNVERIFIED_RUNTIME rather than treating a version check as a pass.
"""
from __future__ import annotations
import argparse, json, os, re, shutil, subprocess, sys, tempfile, time
from pathlib import Path
from typing import Any, Dict, List

STATUS_TOKENS = ("PASS-TRACKED", "PASS-SCOPED", "LIMITED", "FAIL", "UNVERIFIED")
ACCEPTABLE_PASS_STATUSES = {"PASS-TRACKED", "PASS-SCOPED"}
REJECT_STATUSES = {"LIMITED", "FAIL", "UNVERIFIED"}
REQUIRED_OUTPUT_TERMS = ("method", "false-world", "true-world", "gate")


def run_cmd(cmd: List[str], cwd: Path | None = None, timeout: int = 300) -> Dict[str, Any]:
    started = time.time()
    try:
        proc = subprocess.run(cmd, cwd=str(cwd) if cwd else None, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return {"cmd": cmd, "returncode": proc.returncode, "stdout": proc.stdout[-12000:], "stderr": proc.stderr[-12000:], "duration_sec": round(time.time()-started, 3)}
    except subprocess.TimeoutExpired as exc:
        return {"cmd": cmd, "returncode": 124, "stdout": (exc.stdout or "")[-12000:] if isinstance(exc.stdout, str) else "", "stderr": (exc.stderr or "")[-12000:] if isinstance(exc.stderr, str) else "timeout", "duration_sec": round(time.time()-started, 3)}


def extract_json_strings(value: Any) -> List[str]:
    strings: List[str] = []
    if isinstance(value, str):
        strings.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            strings.extend(extract_json_strings(v))
    elif isinstance(value, list):
        for v in value:
            strings.extend(extract_json_strings(v))
    return strings


def dominant_status(text: str) -> str | None:
    """Return the most authoritative final status found in a transcript.

    Prefer explicit final/gate status phrases. Fall back to status tokens only
    when no rejecting status appears. This prevents a transcript saying
    ``gate status FAIL`` from passing merely because it contains verification
    keywords or an incidental PASS token.
    """
    # If Claude returns JSON, inspect all string values as text too.
    candidates = [text]
    try:
        parsed = json.loads(text)
        candidates.extend(extract_json_strings(parsed))
    except Exception:
        pass
    joined = "\n".join(candidates)
    status_re = r"(?:final\s+)?(?:gate\s+)?status\s*[:=\-]\s*(PASS-TRACKED|PASS-SCOPED|LIMITED|FAIL|UNVERIFIED)"
    matches = re.findall(status_re, joined, flags=re.I)
    if matches:
        return matches[-1].upper()
    found = [tok for tok in STATUS_TOKENS if re.search(r"\b"+re.escape(tok)+r"\b", joined, flags=re.I)]
    if any(tok in found for tok in REJECT_STATUSES):
        # Rejecting statuses dominate incidental pass labels when no explicit final status exists.
        for tok in ("FAIL", "LIMITED", "UNVERIFIED"):
            if tok in found:
                return tok
    for tok in ("PASS-TRACKED", "PASS-SCOPED"):
        if tok in found:
            return tok
    return None


def transcript_checks(text: str, artifact: str) -> Dict[str, Any]:
    low = text.lower()
    status = dominant_status(text)
    status_found = [tok for tok in STATUS_TOKENS if tok.lower() in low]
    required_terms = {term: (term in low) for term in REQUIRED_OUTPUT_TERMS}
    artifact_seen = Path(artifact).name.lower() in low or artifact.lower() in low
    passed = status in ACCEPTABLE_PASS_STATUSES and all(required_terms.values()) and artifact_seen
    return {
        "dominant_status": status,
        "status_tokens": status_found,
        "acceptable_pass_statuses": sorted(ACCEPTABLE_PASS_STATUSES),
        "required_terms": required_terms,
        "artifact_seen": artifact_seen,
        "passed": passed,
    }


def build_fixture_prompt(plugin_name: str, fixture_id: str, artifact_path: Path) -> str:
    return (
        f"/{plugin_name}:nozickian-verify {artifact_path}\n\n"
        f"Run the Nozickian verification skill on fixture {fixture_id}. "
        "Return a concise report with: scope, method M, atomic claims, false-world sensitivity evidence, "
        "true-world adherence evidence, contradictions/residual risks, final gate status, and commands/artifacts used. "
        "Do not claim PASS-TRACKED unless the paired modal tests are evidenced."
    )


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
    claude = shutil.which("claude")
    result: Dict[str, Any] = {
        "status": "UNVERIFIED_RUNTIME",
        "reason": "Claude Code CLI not found on PATH; live plugin/subagent invocation not executed.",
        "plugin_root": str(root),
        "commands": [],
        "fixture_results": [],
        "transcript_checks": [],
    }
    if not claude:
        if args.json:
            args.json.parent.mkdir(parents=True, exist_ok=True); args.json.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 2 if args.require_claude else 0

    # Basic CLI and plugin validation attempts. These are not sufficient for PASS.
    commands = [run_cmd([claude, "--version"], timeout=60)]
    commands.append(run_cmd([claude, "plugin", "validate", str(root)], timeout=300))
    result.update({"reason": "Claude Code CLI present; plugin validate attempted. Fixture slash-command invocations not requested.", "commands": commands})

    if not args.run_fixtures:
        result["status"] = "UNVERIFIED_RUNTIME"
    else:
        evals_path = root / "skills/nozickian-verify/evals/evals.json"
        evals = json.loads(evals_path.read_text(encoding="utf-8"))
        fixture_results = []
        transcript_results = []
        plugin_name = json.loads((root/'.claude-plugin/plugin.json').read_text(encoding='utf-8')).get('name', 'nozickian-verification')
        for item in evals.get('fixtures', [])[: max(0, args.max_fixtures)]:
            artifact = root / "skills/nozickian-verify/evals" / item["artifact"]
            prompt = build_fixture_prompt(plugin_name, item.get('id','fixture'), artifact)
            out_dir = (args.output_dir.resolve() if args.output_dir else root / "self_validation/live_runtime_transcripts")
            out_dir.mkdir(parents=True, exist_ok=True)
            cmd = [claude, "--plugin-dir", str(root), "-p", "--output-format", "json", "--max-turns", str(args.max_turns), prompt]
            cmd_result = run_cmd(cmd, cwd=root, timeout=args.timeout_sec)
            transcript_file = out_dir / f"{item.get('id','fixture')}.json"
            transcript_file.write_text(json.dumps(cmd_result, indent=2, sort_keys=True), encoding="utf-8")
            combined = (cmd_result.get('stdout') or '') + "\n" + (cmd_result.get('stderr') or '')
            checks = transcript_checks(combined, item["artifact"])
            fixture_results.append({"id": item.get('id'), "artifact": str(artifact), "returncode": cmd_result["returncode"], "transcript_file": str(transcript_file), "checks": checks})
            transcript_results.append(checks)
        result["fixture_results"] = fixture_results
        result["transcript_checks"] = transcript_results
        all_ok = bool(fixture_results) and all(fr["returncode"] == 0 and fr["checks"]["passed"] for fr in fixture_results)
        result["status"] = "PASS-SCOPED" if all_ok else "FAIL"
        result["reason"] = "Fixture slash-command invocations executed; PASS-SCOPED means transcripts contain required verification fields, not that subagent usage was independently proven."
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True); args.json.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS-SCOPED" or (result["status"] == "UNVERIFIED_RUNTIME" and not args.require_claude) else 2

if __name__ == "__main__":
    raise SystemExit(main())
