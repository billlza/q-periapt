#!/usr/bin/env python3
"""Capture local SDK call timings, preserving raw pairs and exact source/binary identity.

This is a native Rust/ABI diagnostic, not release/device/TLS acceptance.
Output directories are exclusive: prior attempts are never overwritten.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOTS = (
    "crates/q-periapt-core/", "crates/q-periapt-kem/",
    "crates/q-periapt-backends/", "crates/q-periapt-mlkem-native-sys/",
    "crates/q-periapt-policy/", "crates/q-periapt-sig/",
    "crates/q-periapt-ffi/", "crates/q-periapt-sdk/",
)


def read_command(*args: str) -> str:
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources() -> dict[str, str]:
    paths = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
    ).decode().split("\0")
    selected = {
        p for p in paths
        if p in {"Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "research/sdk-alpha1/capture.py"}
        or p.startswith(SOURCE_ROOTS)
    }
    return {p: digest(ROOT / p) for p in sorted(selected)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=1000)
    args = parser.parse_args()
    if not 100 <= args.samples <= 5000:
        parser.error("--samples must be 100..=5000")
    # Exclusive creation protects previous observations, including failed ones.
    args.output.mkdir(parents=True, exist_ok=False)
    before = sources()
    record = {
        "schema": 1,
        "kind": "local_sdk_path_diagnostic",
        "status": "incomplete",
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "base_commit": read_command("git", "rev-parse", "HEAD"),
        "branch": read_command("git", "branch", "--show-current"),
        "dirty_worktree": bool(read_command("git", "status", "--porcelain")),
        "source_files_sha256": before,
        "source_manifest_sha256": hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "rustc": read_command("rustc", "--version"),
        "cargo": read_command("cargo", "--version"),
        "samples_per_path": args.samples,
        "measurement": "paired_single_call_wall_time_including_explicit_secret_export",
        "excluded": ["policy_verification", "key_generation", "network", "TLS", "foreign_language_marshalling"],
        "load_before": os.getloadavg(),
        "cpu_and_power_controls": "uncontrolled; no host settings changed",
        "release_claim_eligible": False,
    }
    manifest = args.output / "manifest.json"
    try:
        with (args.output / "build.log").open("w") as log:
            subprocess.run(["cargo", "build", "--locked", "--release", "-p", "q-periapt-ffi", "--example", "sdk_path_perf"], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True)
        if sources() != before:
            raise RuntimeError("source changed during build")
        metadata = json.loads(read_command("cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"))
        binary = Path(metadata["target_directory"]) / "release/examples/sdk_path_perf"
        if platform.system() == "Windows":
            binary = binary.with_suffix(".exe")
        record["binary"] = str(binary)
        record["binary_sha256"] = digest(binary)
        with (args.output / "samples.jsonl").open("w") as raw, (args.output / "summary.txt").open("w") as summary:
            subprocess.run([str(binary), str(args.samples)], cwd=ROOT, stdout=raw, stderr=summary, check=True)
        if sources() != before or digest(binary) != record["binary_sha256"]:
            raise RuntimeError("source or binary changed during measurement")
        record["samples_sha256"] = digest(args.output / "samples.jsonl")
        record["summary_sha256"] = digest(args.output / "summary.txt")
        record["load_after"] = os.getloadavg()
        record["status"] = "captured"
    except (OSError, subprocess.CalledProcessError, RuntimeError) as error:
        record["status"] = "failed"
        record["error"] = str(error)
        raise
    finally:
        record["finished_utc"] = datetime.now(timezone.utc).isoformat()
        manifest.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"Captured local diagnostic: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
