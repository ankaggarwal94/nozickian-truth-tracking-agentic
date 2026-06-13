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
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

PASS_TRACKED = "PASS-TRACKED"
PASS_SCOPED = "PASS-SCOPED"
UNVERIFIED_RUNTIME = "UNVERIFIED_RUNTIME"
FAIL_STATUSES = {"FAIL", "LIMITED", "UNVERIFIED", UNVERIFIED_RUNTIME}
PASSISH = {PASS_TRACKED, PASS_SCOPED, "PASS"}
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
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def try_load_json(path: Path) -> Tuple[Optional[Any], Optional[str]]:
    try:
        return load_json(path), None
    except Exception as exc:
        return None, repr(exc)


def relpath(root: Path, path: Path) -> str:
    return str(path.resolve().relative_to(root.resolve())).replace(os.sep, "/")


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def run_cmd(cmd: Sequence[str], cwd: Optional[Path] = None, timeout: int = 900) -> Dict[str, Any]:
    try:
        proc = subprocess.run(list(cmd), cwd=str(cwd) if cwd else None, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return {"cmd": list(cmd), "returncode": proc.returncode, "stdout": proc.stdout[-50000:], "stderr": proc.stderr[-50000:]}
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
    text = path.read_text(encoding="utf-8", errors="replace")
    lower = text.lower()
    if "traceback" in lower or "error" in lower and "0 errors" not in lower:
        return False, "validator text contains error/traceback"
    # Accept common success markers but require nonempty text.
    ok_markers = ["pass", "valid", "success", "0 failed", "all checks", "ok"]
    if any(m in lower for m in ok_markers) and len(text.strip()) > 5:
        return True, "text contains success marker"
    return False, "no success marker found"


def deterministic_checks(package_root: Path, bundle: Path, run_fresh: bool) -> List[Check]:
    checks: List[Check] = []
    for name, rel in DETERMINISTIC_FILES.items():
        path = bundle / rel
        checks.append(Check(f"deterministic artifact present: {name}", path.exists(), details=rel))
        if not path.exists():
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
            text = path.read_text(encoding="utf-8", errors="replace")
            checks.append(Check("behavior manifest check says OK", "FAILED" not in text and "No such file" not in text and bool(text.strip()), details=text[-500:]))
    if run_fresh:
        validator = package_root / "skills/nozickian-verify/scripts/validate_package.py"
        cmd = [sys.executable, str(validator), str(package_root), "--skip-release-idempotence"]
        result = run_cmd(cmd, cwd=package_root)
        ok = result.get("returncode") == 0
        try:
            parsed = json.loads(result.get("stdout", "{}"))
            ok = ok and parsed.get("status") == "PASS" and int(parsed.get("critical_failed", 1)) == 0
            details: Any = {"returncode": result.get("returncode"), "status": parsed.get("status"), "critical_failed": parsed.get("critical_failed")}
        except Exception:
            details = {"returncode": result.get("returncode"), "stderr": result.get("stderr")[-1000:]}
        checks.append(Check("fresh deterministic package validator still passes", ok, details=details))
    return checks


def official_validator_checks(bundle: Path, allow_scope_exclusion: bool) -> List[Check]:
    checks: List[Check] = []
    for name, rels in OFFICIAL_VALIDATOR_CANDIDATES.items():
        found = next((bundle / rel for rel in rels if (bundle / rel).exists()), None)
        if found is None:
            checks.append(Check(f"official validator present: {name}", allow_scope_exclusion, severity="major" if allow_scope_exclusion else "critical", details="missing official validator output; retaining scope limitation if allowed"))
            continue
        if found.suffix == ".json":
            data, err = try_load_json(found)
            checks.append(Check(f"official validator parses: {name}", err is None, details=err or relpath(bundle, found)))
            if data is None:
                continue
            returncode = data.get("returncode")
            status = str(data.get("status") or data.get("result") or "").lower()
            ok = returncode == 0 or status in {"pass", "passed", "valid", "success"}
            checks.append(Check(f"official validator passed: {name}", ok, details={"returncode": returncode, "status": status, "file": relpath(bundle, found)}))
        else:
            ok, reason = file_status_from_text(found)
            checks.append(Check(f"official validator passed: {name}", ok, details={"file": relpath(bundle, found), "reason": reason}))
    return checks


def live_fixture_checks(bundle: Path) -> List[Check]:
    checks: List[Check] = []
    path = bundle / "live_fixtures/live_runtime_eval_result.json"
    checks.append(Check("live runtime eval result present", path.exists(), details=relpath(bundle, path) if path.exists() else str(path)))
    if not path.exists():
        return checks
    data, err = try_load_json(path)
    checks.append(Check("live runtime eval result parses", err is None, details=err))
    if data is None:
        return checks
    status = data.get("status")
    checks.append(Check("live runtime was executed", status not in {None, "", UNVERIFIED_RUNTIME, "UNVERIFIED", "FAIL", "LIMITED"}, details={"status": status, "reason": data.get("reason")}))
    fixtures = data.get("fixture_results")
    checks.append(Check("live fixture result list nonempty", isinstance(fixtures, list) and len(fixtures) > 0, details=f"count={len(fixtures) if isinstance(fixtures, list) else 'n/a'}"))
    if isinstance(fixtures, list):
        for idx, item in enumerate(fixtures, start=1):
            if not isinstance(item, Mapping):
                checks.append(Check(f"live fixture {idx} object", False, details=item)); continue
            checks.append(Check(f"live fixture {idx} command returned zero", item.get("returncode") == 0, details={"id": item.get("id"), "returncode": item.get("returncode")}))
            c = item.get("checks") or {}
            checks.append(Check(f"live fixture {idx} transcript check passed", isinstance(c, Mapping) and c.get("passed") is True, details={"id": item.get("id"), "checks": c}))
            transcript_file = item.get("transcript_file")
            if transcript_file:
                # Transcript path may be absolute on the producing machine; for this bundle, prefer a relative copy under live_fixtures/transcripts.
                rel_candidate = bundle / "live_fixtures/transcripts" / Path(str(transcript_file)).name
                checks.append(Check(f"live fixture {idx} transcript copied into bundle", rel_candidate.exists() or Path(str(transcript_file)).exists(), severity="major", details=str(rel_candidate)))
    return checks


def find_formal_results(bundle: Path) -> List[Path]:
    paths = sorted((bundle / "formal_artifacts").glob("**/formal_result.json"))
    paths += sorted((bundle / "formal_artifacts").glob("**/*formal_result*.json"))
    dedup: Dict[str, Path] = {}
    for p in paths:
        dedup[str(p.resolve())] = p
    return list(dedup.values())


def formal_artifact_checks(package_root: Path, bundle: Path) -> List[Check]:
    checks: List[Check] = []
    results = find_formal_results(bundle)
    checks.append(Check("at least one formal artifact result present", bool(results), details=[relpath(bundle, p) for p in results]))
    if not results:
        return checks
    runner = load_module("ntt_formal_runner_for_promotion", package_root / "skills/nozickian-verify/scripts/run_formal_artifact_verification.py")
    gate = load_module("ntt_gate_for_promotion", package_root / "skills/nozickian-verify/scripts/ntt_gate.py")
    for idx, path in enumerate(results, start=1):
        data, err = try_load_json(path)
        checks.append(Check(f"formal result {idx} parses", err is None, details=err or relpath(bundle, path)))
        if data is None:
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
        output_dir = Path(str(data.get("output_dir") or path.parent)).resolve()
        if not output_dir.exists():
            output_dir = path.parent.resolve()
        transcript = Path(str(data.get("transcript_file") or ""))
        if not transcript.is_absolute():
            transcript = (output_dir / transcript.name) if transcript.name else next(iter(output_dir.glob("*_NOZICKIAN_FORMAL_TRANSCRIPT.stream.jsonl")), Path(""))
        checks.append(Check(f"formal result {idx} transcript exists", transcript.exists(), details=str(transcript)))
        if transcript.exists():
            parsed_auth = runner.authenticate_trace(transcript)
            checks.append(Check(f"formal result {idx} transcript re-authenticates", parsed_auth.get("authenticated") is True, details=parsed_auth))
        certs = sorted(output_dir.glob("*_NOZICKIAN_certificate.json"))
        checks.append(Check(f"formal result {idx} generated certificate exists", bool(certs), details=[str(p) for p in certs]))
        for cert in certs[:1]:
            try:
                cert_data = load_json(cert)
                gate_result = gate.evaluate_certificate(cert_data, evidence_root=Path(str(data.get("evidence_root") or output_dir)).resolve(), strict_evidence=True)
                checks.append(Check(f"formal result {idx} generated certificate strict gate PASS-TRACKED", gate_result.get("status") == PASS_TRACKED, details={"status": gate_result.get("status"), "summary": gate_result.get("summary"), "reasons": gate_result.get("reasons")}))
                downstream_violations = gate_result.get("summary", {}).get("downstream_nonclosure_violations", 0)
                checks.append(Check(f"formal result {idx} no downstream non-closure violations", downstream_violations == 0, details=gate_result.get("summary")))
            except Exception as exc:
                checks.append(Check(f"formal result {idx} generated certificate strict gate evaluates", False, details=repr(exc)))
        ledgers = sorted(output_dir.glob("*_NOZICKIAN_INVOCATION_LEDGER.md"))
        checks.append(Check(f"formal result {idx} invocation ledger exists", bool(ledgers), details=[str(p) for p in ledgers]))
        if ledgers:
            text = ledgers[0].read_text(encoding="utf-8", errors="replace").lower()
            checks.append(Check(f"formal result {idx} ledger says no substitution", "substitution used: none" in text and "formal_subagent_failure" not in text, details=ledgers[0].name))
    return checks


def promotion_certificate_checks(package_root: Path, bundle: Path) -> List[Check]:
    checks: List[Check] = []
    path = bundle / "promotion_certificate.json"
    checks.append(Check("promotion certificate present", path.exists(), details=str(path)))
    if not path.exists():
        return checks
    data, err = try_load_json(path)
    checks.append(Check("promotion certificate parses", err is None, details=err))
    if data is None:
        return checks
    checks.append(Check("promotion certificate records upgrade_from_status PASS-SCOPED", data.get("upgrade_from_status") == PASS_SCOPED, details=data.get("upgrade_from_status")))
    checks.append(Check("promotion certificate requests PASS-TRACKED", data.get("requested_status") == PASS_TRACKED, details=data.get("requested_status")))
    plugin = try_load_json(package_root / ".claude-plugin/plugin.json")[0] or {}
    current_version = str(plugin.get("version") or "")
    checks.append(Check("promotion certificate package version matches plugin", str(data.get("package_version") or data.get("plugin_version") or "") == current_version, details={"certificate": data.get("package_version") or data.get("plugin_version"), "plugin": current_version}))
    digest = data.get("package_sha256") or data.get("package_tree_sha256")
    checks.append(Check("promotion certificate records package hash", isinstance(digest, str) and (digest.startswith("sha256:") or re.fullmatch(r"[0-9a-fA-F]{64}", digest or "")), severity="major", details=digest))
    refs = data.get("evidence_refs") or data.get("evidence") or []
    checks.append(Check("promotion certificate has evidence refs", isinstance(refs, list) and len(refs) >= 5, details=f"count={len(refs) if isinstance(refs, list) else 'n/a'}"))
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
    prior_root = "nozickian-verification-team-internal-v" + prior_patch
    stale_patterns = [re.escape(local_data), re.escape(local_home), prior_label, prior_patch, prior_probe, prior_root]
    hits: List[Dict[str, Any]] = []
    for root in (package_root, bundle):
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if not p.is_file() or "__pycache__" in p.parts or p.suffix == ".pyc":
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for pat in stale_patterns:
                m = re.search(pat, text)
                if m:
                    hits.append({"path": str(p), "pattern": pat, "excerpt": text[max(0, m.start()-60):m.end()+60].replace("\n", " ")})
                    break
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
    parser.add_argument("--run-fresh-package-validator", action="store_true", help="also rerun validate_package.py against the supplied package root")
    parser.add_argument("--allow-official-validator-scope-exclusion", action="store_true", help="do not fail when official Claude Code validators are missing; the result remains PASS-SCOPED rather than PASS-TRACKED")
    args = parser.parse_args(argv)

    package_root = args.package_root.resolve()
    bundle = args.audit_bundle.resolve()
    checks: List[Check] = []
    checks.append(Check("package root exists", package_root.is_dir(), details=str(package_root)))
    checks.append(Check("audit bundle exists", bundle.is_dir(), details=str(bundle)))
    if package_root.is_dir():
        checks.extend(deterministic_checks(package_root, bundle, args.run_fresh_package_validator))
        checks.extend(official_validator_checks(bundle, args.allow_official_validator_scope_exclusion))
        checks.extend(live_fixture_checks(bundle))
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
