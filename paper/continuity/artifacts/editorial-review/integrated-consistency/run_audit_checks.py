#!/usr/bin/env python3
"""Run the pinned audit calculation and its optimized-mode negative control."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time


if not __debug__:
    print("ERROR: run the audit verifier without Python optimization.", file=sys.stderr)
    raise SystemExit(2)


OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[4]
BASELINE = "c7581ebc21f5d080d90840c13b52c793bcac9317"
CHECKER = OUT / "focused_checks.py"


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def run(name: str, switches: list[str]) -> dict:
    command = [sys.executable, *switches, str(CHECKER)]
    environment = os.environ.copy()
    environment.pop("PYTHONOPTIMIZE", None)
    start = datetime.now(timezone.utc).isoformat()
    monotonic_start = time.perf_counter_ns()
    process = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True)
    elapsed = time.perf_counter_ns() - monotonic_start
    finish = datetime.now(timezone.utc).isoformat()
    logs = {}
    for stream, content in (("stdout", process.stdout), ("stderr", process.stderr)):
        path = OUT / (name + "." + stream + ".log")
        path.write_bytes(content)
        logs[stream] = {"path": path.name, "sha256": digest(content), "bytes": len(content)}
    return {
        "command": command,
        "cwd": str(ROOT),
        "environment_control": {"PYTHONOPTIMIZE": "removed; optimization selected by command flags"},
        "started_at_utc": start,
        "finished_at_utc": finish,
        "elapsed_ns": elapsed,
        "exit_code": process.returncode,
        "logs": logs,
    }


def main() -> None:
    regular = run("regular", [])
    require(regular["exit_code"] == 0, "Regular audit calculation failed; see regular.stderr.log")
    receipt_paths = [OUT / "source-manifest.json", OUT / "focused-checks.json"]
    before_negative = {path.name: digest(path.read_bytes()) for path in receipt_paths}
    optimized = run("optimized", ["-O"])
    require(optimized["exit_code"] == 2, "Optimized audit must exit with code 2")
    require(
        "requires enabled assertions" in (OUT / "optimized.stderr.log").read_text(),
        "Optimized rejection must identify the assertion requirement",
    )
    require((OUT / "optimized.stdout.log").read_bytes() == b"", "Optimized run emitted a success response")
    after_negative = {path.name: digest(path.read_bytes()) for path in receipt_paths}
    require(before_negative == after_negative, "Optimized run changed a successful audit receipt")

    manifest = json.loads((OUT / "source-manifest.json").read_text())
    focused = json.loads((OUT / "focused-checks.json").read_text())
    require(manifest["baseline_commit"] == focused["baseline_commit"] == BASELINE, "Baseline mismatch")
    require(focused["status"] == "pass", "Focused calculation did not pass")
    require(focused["checker_sha256"] == digest(CHECKER.read_bytes()), "Checker receipt identity mismatch")
    labels = {label for entry in manifest["files"] for label in entry.get("labels", {})}
    used = set(re.findall(
        r"`((?:def|eq|lem|thm|prop|cor):[\w-]+)`", (OUT / "audit.md").read_text()
    ))
    require(used <= labels, "Unresolved baseline labels: " + repr(sorted(used - labels)))
    archives_verified = 0
    live_tex_differences = []
    for entry in manifest["files"]:
        content = subprocess.check_output(
            ["git", "show", BASELINE + ":" + entry["path"]], cwd=ROOT
        )
        require(digest(content) == entry["sha256"], "Historical manifest digest mismatch: " + entry["path"])
        require(len(content) == entry["bytes"], "Historical manifest length mismatch: " + entry["path"])
        current = ROOT / entry["path"]
        if entry.get("archived_workspace_bytes_verified"):
            require(current.read_bytes() == content, "Archived input changed: " + entry["path"])
            archives_verified += 1
        elif not current.exists() or current.read_bytes() != content:
            live_tex_differences.append(entry["path"])
    result = {
        "baseline_commit": BASELINE,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "pass",
        "runtime": {
            "python": sys.version,
            "python_executable": sys.executable,
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "verifier_optimization_level": sys.flags.optimize,
        },
        "working_head_observed": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "head_is_provenance_only": True,
        "historical_manifest_files_verified": len(manifest["files"]),
        "archived_workspace_inputs_verified": archives_verified,
        "audit_label_references_resolve": len(used),
        "current_tex_differences_from_baseline": live_tex_differences,
        "current_tex_bytes_used_as_historical_inputs": False,
        "regular": regular,
        "optimized_negative_control": optimized,
        "optimized_run_preserved_successful_receipts": True,
        "scope": "Audit package only; canonical manuscript, PDF, integration record and archived source pins are read-only",
        "artifacts": [
            {"path": path.name, "sha256": digest(path.read_bytes()), "bytes": path.stat().st_size}
            for path in sorted(OUT.iterdir())
            if path.is_file() and path.name != "verification.json"
        ],
    }
    (OUT / "verification.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({
        "status": result["status"],
        "baseline_commit": BASELINE,
        "historical_source_files": len(manifest["files"]),
        "verified_archived_inputs": archives_verified,
        "regular_exit_code": regular["exit_code"],
        "optimized_exit_code": optimized["exit_code"],
        "optimized_receipts_unchanged": True,
        "current_tex_differences": len(live_tex_differences),
    }))


if __name__ == "__main__":
    main()
