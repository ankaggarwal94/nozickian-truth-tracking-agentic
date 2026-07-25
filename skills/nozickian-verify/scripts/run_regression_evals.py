#!/usr/bin/env python3
"""Deterministic regression checks for the team/internal Nozickian verifier.

These are not live Claude Code evals. They are quick, reproducible checks that
fixture definitions still exercise claim decomposition, method identification,
nearby false-world rejection, nearby true-world retention, and gate evidence.
"""
from __future__ import annotations
import argparse, json, os, re, stat, sys, unicodedata, uuid
from pathlib import Path
from typing import Any, Dict, List, Mapping

REQUIRED_FIXTURE_FIELDS = ["id", "artifact", "task", "expected_claims", "false_worlds", "true_worlds", "expected_gate"]
REQUIRED_CLAIM_FIELDS = ["id", "text", "importance"]
REQUIRED_FALSE_FIELDS = ["id", "target_claim_ids", "perturbation", "expected_behavior", "success_criteria", "evidence_required"]
REQUIRED_TRUE_FIELDS = ["id", "target_claim_ids", "variant", "expected_behavior", "success_criteria", "evidence_required"]
ACCEPTABLE_GATE_STATUSES = {"PASS-SCOPED", "PASS-TRACKED", "LIMITED", "FAIL", "UNVERIFIED"}


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


def add(checks: List[Dict[str, Any]], name: str, passed: bool, details: str = "") -> None:
    checks.append({"name": name, "passed": bool(passed), "details": details})


def normalize_cli_display(value: Any, package_root: Path) -> Any:
    """Normalize only the exact package root or a rooted child path."""
    root_text = str(package_root.resolve())
    if isinstance(value, str):
        return re.sub(
            re.escape(root_text) + r"(?=$|[\\/])",
            lambda _match: "<package-root>",
            value,
        )
    if isinstance(value, list):
        return [normalize_cli_display(item, package_root) for item in value]
    if isinstance(value, tuple):
        return [normalize_cli_display(item, package_root) for item in value]
    if isinstance(value, Mapping):
        return {
            key: normalize_cli_display(item, package_root)
            for key, item in value.items()
        }
    return value


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
                "checks_total": 0,
                "checks_passed": 0,
                "checks_failed": 0,
                "checks": [],
            }, indent=2, sort_keys=True))
            return 2
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
    display_result = normalize_cli_display(result, root)
    text = json.dumps(display_result, indent=2, sort_keys=True)
    if output_path is not None and output_directory_fd is not None:
        try:
            _atomic_replace_json_output(
                output_path,
                text,
                directory_fd=output_directory_fd,
            )
        except (OSError, RuntimeError, ValueError):
            failed_result = dict(display_result)
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
    return 0 if failed == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
