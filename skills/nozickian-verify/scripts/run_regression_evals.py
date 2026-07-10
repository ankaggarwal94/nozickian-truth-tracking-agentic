#!/usr/bin/env python3
"""Deterministic regression checks for the team/internal Nozickian verifier.

These are not live Claude Code evals. They are quick, reproducible checks that
fixture definitions still exercise claim decomposition, method identification,
nearby false-world rejection, nearby true-world retention, and gate evidence.
"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from typing import Any, Dict, List

REQUIRED_FIXTURE_FIELDS = ["id", "artifact", "task", "expected_claims", "false_worlds", "true_worlds", "expected_gate"]
REQUIRED_CLAIM_FIELDS = ["id", "text", "importance"]
REQUIRED_FALSE_FIELDS = ["id", "target_claim_ids", "perturbation", "expected_behavior", "success_criteria", "evidence_required"]
REQUIRED_TRUE_FIELDS = ["id", "target_claim_ids", "variant", "expected_behavior", "success_criteria", "evidence_required"]
ACCEPTABLE_GATE_STATUSES = {"PASS-SCOPED", "PASS-TRACKED", "LIMITED", "FAIL", "UNVERIFIED"}


def add(checks: List[Dict[str, Any]], name: str, passed: bool, details: str = "") -> None:
    checks.append({"name": name, "passed": bool(passed), "details": details})


def validate_fixture(root: Path, fixture: Dict[str, Any], checks: List[Dict[str, Any]]) -> None:
    fid = str(fixture.get("id", "<missing>"))
    for field in REQUIRED_FIXTURE_FIELDS:
        add(checks, f"{fid}: fixture has {field}", field in fixture, str(fixture.get(field)))
    artifact = fixture.get("artifact")
    if isinstance(artifact, str):
        p = root / "skills/nozickian-verify/evals" / artifact
        add(checks, f"{fid}: artifact exists", p.exists(), str(p))
        if p.exists():
            text = p.read_text(encoding="utf-8", errors="replace")
            add(checks, f"{fid}: artifact nonempty", len(text.strip()) >= 20, f"chars={len(text)}")
    claims = fixture.get("expected_claims")
    claim_ids = set()
    add(checks, f"{fid}: claims list nonempty", isinstance(claims, list) and bool(claims), "")
    if isinstance(claims, list):
        for c in claims:
            if not isinstance(c, dict):
                add(checks, f"{fid}: claim object", False, repr(c)); continue
            cid = c.get("id"); claim_ids.add(cid)
            for field in REQUIRED_CLAIM_FIELDS:
                add(checks, f"{fid}/{cid}: claim has {field}", bool(c.get(field)), str(c.get(field)))
            add(checks, f"{fid}/{cid}: claim importance valid", c.get("importance") in {"critical", "major", "minor"}, str(c.get("importance")))
    for world_field, required, text_field in [("false_worlds", REQUIRED_FALSE_FIELDS, "perturbation"), ("true_worlds", REQUIRED_TRUE_FIELDS, "variant")]:
        worlds = fixture.get(world_field)
        add(checks, f"{fid}: {world_field} list nonempty", isinstance(worlds, list) and bool(worlds), "")
        if not isinstance(worlds, list):
            continue
        for w in worlds:
            if not isinstance(w, dict):
                add(checks, f"{fid}: {world_field} object", False, repr(w)); continue
            wid = w.get("id")
            for field in required:
                add(checks, f"{fid}/{wid}: {world_field} has {field}", field in w and bool(w.get(field)) is not False, str(w.get(field)))
            targets = set(w.get("target_claim_ids", [])) if isinstance(w.get("target_claim_ids"), list) else set()
            add(checks, f"{fid}/{wid}: target claims known", bool(targets) and targets.issubset(claim_ids), str(sorted(targets)))
            add(checks, f"{fid}/{wid}: {text_field} substantive", isinstance(w.get(text_field), str) and len(w[text_field]) >= 30, str(w.get(text_field)))
            sc = w.get("success_criteria")
            add(checks, f"{fid}/{wid}: success criteria multi-part", isinstance(sc, list) and len(sc) >= 2, str(sc))
            add(checks, f"{fid}/{wid}: evidence explicitly required", w.get("evidence_required") is True, str(w.get("evidence_required")))
    gate = fixture.get("expected_gate")
    add(checks, f"{fid}: expected gate status recognized", isinstance(gate, str) and gate in ACCEPTABLE_GATE_STATUSES, str(gate))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run deterministic regression checks for Nozickian eval fixtures")
    parser.add_argument("root", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    checks: List[Dict[str, Any]] = []
    eval_path = root / "skills/nozickian-verify/evals/evals.json"
    add(checks, "evals.json exists", eval_path.exists(), str(eval_path))
    if eval_path.exists():
        try:
            data = json.loads(eval_path.read_text(encoding="utf-8"))
            add(checks, "evals.json parses", True, "")
        except Exception as exc:
            data = {}
            add(checks, "evals.json parses", False, str(exc))
        fixtures = data.get("fixtures")
        add(checks, "at least three fixture tasks", isinstance(fixtures, list) and len(fixtures) >= 3, f"count={len(fixtures) if isinstance(fixtures, list) else 'n/a'}")
        if isinstance(fixtures, list):
            for fixture in fixtures:
                if isinstance(fixture, dict):
                    validate_fixture(root, fixture, checks)
                else:
                    add(checks, "fixture is object", False, repr(fixture))
    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed
    result = {"status": "PASS" if failed == 0 else "FAIL", "checks_total": len(checks), "checks_passed": passed, "checks_failed": failed, "checks": checks}
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if failed == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
