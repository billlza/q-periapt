#!/usr/bin/env python3
"""Build and measure real C/Swift SDK paths; diagnostic only, never a release proof.

Five independent process blocks alternate executable and within-pair call order.
Raw samples, unsuccessful attempts, source/build identities and dyld observations
are retained. Existing core performance proofs/budgets are not reinterpreted.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess

from bounded_process import capture_stdout
from evidence_io import parse_strict_json_bytes
from sdk_connection_interop import freeze, verify_client_load
from standard_tls_interop import ROOT, identity, read_log, require

CELLS = (("generate_key", 0),) + tuple(
    (operation, context) for context in (32, 4096, 65536)
    for operation in ("encapsulate", "decapsulate"))
FIELDS = {"schema", "surface", "operation", "context_bytes", "phase", "warmup_pairs",
          "legacy_raw_ns", "owner_raw_ns"}
BLOCKS = 5


def parse_samples(raw: bytes, surface: str, count: int, phase: int) -> list[dict]:
    require(len(raw) <= 2_097_152, "raw diagnostic exceeds 2 MiB")
    rows = [parse_strict_json_bytes(line, label="SDK timing row") for line in raw.splitlines()]
    require(len(rows) == len(CELLS), "missing or extra diagnostic cells")
    for row, (operation, context) in zip(rows, CELLS, strict=True):
        require(isinstance(row, dict) and set(row) == FIELDS, "timing fields differ")
        require(row["surface"] == surface and row["operation"] == operation, "timing path/order differs")
        for name, value in (("schema", 1), ("context_bytes", context), ("phase", phase), ("warmup_pairs", 64)):
            require(type(row[name]) is int and row[name] == value, f"invalid {name}")
        for name in ("legacy_raw_ns", "owner_raw_ns"):
            values = row[name]
            require(isinstance(values, list) and len(values) == count, "sample count differs")
            require(all(type(x) is int and 0 < x < (1 << 53) for x in values), "invalid elapsed nanoseconds")
    return rows


def quantiles(values: list[int]) -> dict[str, int]:
    ordered = sorted(values)
    return {f"p{p}": ordered[math.ceil(len(ordered) * p / 100) - 1] for p in (50, 95, 99)}


def summarize(rows: list[dict]) -> list[dict]:
    result = []
    for row in rows:
        old, new = (quantiles(row[key]) for key in ("legacy_raw_ns", "owner_raw_ns"))
        result.append({"operation": row["operation"], "context_bytes": row["context_bytes"],
                       "legacy_ns": old, "owner_ns": new,
                       "ratio_of_quantiles": {p: new[p] / old[p] for p in old}})
    return result


def source_map() -> dict[str, str]:
    paths = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT
    ).decode().split("\0")
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in sorted(set(paths)) if name and not name.startswith("research/sdk-alpha1/evidence/")
            and (ROOT / name).is_file()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=1000)
    args = parser.parse_args()
    require(platform.system() == "Darwin", "this C/Swift driver requires native macOS")
    require(200 <= args.samples <= 5000 and args.samples % 2 == 0, "samples must be even and 200..5000")
    output = args.output.resolve()
    # Build products must stay outside the source inventory, including failed runs.
    require(output.is_relative_to(ROOT / "target"), "diagnostic output must be inside repository target/")
    output.mkdir(mode=0o700)
    binary = output / "bin"
    binary.mkdir(mode=0o700)
    os.chdir(ROOT)
    before = source_map()
    manifest = {"schema": 1, "completed": False, "release_claim_eligible": False,
                "started_utc": datetime.now(timezone.utc).isoformat(), "platform": platform.platform(),
                "machine": platform.machine(), "base_commit": subprocess.check_output(
                    ["git", "rev-parse", "HEAD"], text=True).strip(),
                "source_files_sha256": before, "source_manifest_sha256": hashlib.sha256(
                    json.dumps(before, sort_keys=True).encode()).hexdigest(),
                "samples_per_path_per_block": args.samples, "blocks": BLOCKS,
                "warmup_pairs_per_cell": 64, "schedule": "alternating AB/BA pairs; block phase alternates",
                "quantile_estimator": "nearest-rank", "cpu_power_controls": "uncontrolled; no settings changed",
                "clocks": {"c": "clock_gettime_nsec_np(CLOCK_UPTIME_RAW)",
                           "swift": "DispatchTime.now().uptimeNanoseconds"},
                "included": ["platform RNG for keygen/encapsulation", "native input/shape checks",
                             "public-key output for keygen", "combined-secret output and erasure",
                             "owner disposal", "public Swift wrapper and marshalling costs"],
                "excluded": ["policy verification", "key import/setup", "persistent storage", "async dispatch",
                             "network/TLS", "allocation counts", "concurrency", "energy", "installed packages"],
                "comparison": "same source/provider, signed ContextBound policy and imported key; not historical release binaries",
                "commands": [], "observations": []}

    def command(argv: list[str], name: str, *, environment: dict | None = None, timeout: int = 300) -> bytes:
        record = {"argv": argv, "name": name, "returncode": None}
        manifest["commands"].append(record)
        # Retain partial stdout on deadline/output failure; reuse the repository's
        # bounded process-group cleanup. Native stderr is checked against 1 MiB.
        with (output / f"{name}.stdout").open("xb") as out, (output / f"{name}.stderr").open("xb") as err:
            result = capture_stdout(argv, timeout_seconds=timeout, maximum_bytes=2_097_152,
                                    stderr=err.fileno(), environment=environment, output_sink=out.write)
        record["returncode"] = result.returncode
        read_log(output / f"{name}.stderr")
        require(result.returncode == 0, f"command failed: {name}")
        return result.stdout

    try:
        for name, argv in (("rustc-version", ["rustc", "-vV"]), ("cargo-version", ["cargo", "--version"]),
                           ("swift-version", ["swift", "--version"]), ("cc-version", ["cc", "--version"]),
                           ("host-cpu", ["sysctl", "machdep.cpu.brand_string", "hw.physicalcpu", "hw.logicalcpu"])):
            command(argv, name)
        command(["cargo", "build", "--locked", "--release", "-p", "q-periapt-ffi", "--lib"], "native-build", timeout=900)
        target = parse_strict_json_bytes(command(
            ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"], "cargo-metadata"),
            label="SDK performance Cargo metadata")["target_directory"]
        library = freeze(Path(target) / "release/libq_periapt_ffi_abi2.dylib", binary / "libq_periapt_ffi_abi2.dylib")
        c = binary / "c_sdk_path_perf"
        command(["cc", "-O3", "-std=c11", "-Wall", "-Wextra", "-Werror", "bindings/c/sdk_path_perf.c",
                 "-Icrates/q-periapt-ffi/include", "-Ibindings/c", f"-L{binary}", "-lq_periapt_ffi_abi2",
                 f"-Wl,-rpath,{binary}", "-o", str(c)], "c-build")
        swift_args = ["swift", "build", "--package-path", "bindings/swift", "--configuration", "release",
                      "--product", "QPeriaptPathProbe", "--scratch-path", str(output / "swift-build"),
                      "-Xlinker", f"-L{binary}", "-Xswiftc", "-strict-concurrency=complete",
                      "-Xswiftc", "-warnings-as-errors"]
        command(swift_args, "swift-build", timeout=900)
        swift_bin = Path(command(swift_args + ["--show-bin-path"], "swift-bin-path").decode().strip())
        swift = freeze(swift_bin / "QPeriaptPathProbe", binary / "QPeriaptPathProbe")
        fixture = freeze(ROOT / "bindings/signed-policy-vectors.json", output / "signed-policy-vectors.json")
        identities = {name: identity(path) for name, path in (("c", c), ("swift", swift), ("library", library), ("fixture", fixture))}
        manifest["binaries_and_fixture"] = identities
        require(source_map() == before, "source changed during build")
        environment = {k: v for k, v in os.environ.items() if not k.startswith("DYLD_")}
        environment.update(DYLD_LIBRARY_PATH=str(binary), DYLD_PRINT_LIBRARIES="1")
        manifest["load_before"] = os.getloadavg()
        for block in range(BLOCKS):
            for surface in (("c", "swift") if block % 2 == 0 else ("swift", "c")):
                executable = c if surface == "c" else swift
                argv = [str(executable)] + ([str(fixture)] if surface == "swift" else [])
                name = f"block-{block}-{surface}"
                load = os.getloadavg()
                raw = command(argv + [str(args.samples), str(block % 2)], name, environment=environment, timeout=120)
                verify_client_load(read_log(output / f"{name}.stderr"), executable, library, static=False)
                rows = parse_samples(raw, surface + "_dynamic", args.samples, block % 2)
                manifest["observations"].append({"block": block, "surface": surface, "load_before": load,
                                                 "raw": f"{name}.stdout", "cells": summarize(rows)})
        manifest["load_after"] = os.getloadavg()
        require(source_map() == before, "source changed during measurement")
        require({name: identity(Path(value["path"])) for name, value in identities.items()} == identities,
                "binary/fixture changed during measurement")
        manifest["completed"] = True
    except BaseException as error:
        manifest["failure"] = {"kind": type(error).__name__, "message": str(error)}
        raise
    finally:
        manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
        manifest["evidence_sha256"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                      for p in sorted(output.iterdir()) if p.is_file()}
        with (output / "manifest.json").open("x") as stream:
            stream.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    # Descriptive ranges across all five blocks; no post-hoc block selection or
    # fabricated confidence interval/non-regression pass on an uncontrolled host.
    for surface in ("c", "swift"):
        blocks = [x for x in manifest["observations"] if x["surface"] == surface]
        for index, (operation, context) in enumerate(CELLS):
            parts = []
            for p in ("p50", "p95", "p99"):
                ratios = [b["cells"][index]["ratio_of_quantiles"][p] for b in blocks]
                parts.append(f"{p}={statistics.median(ratios):.3f} [{min(ratios):.3f},{max(ratios):.3f}]")
            print(f"{surface} {operation} context={context}: owner/legacy block ratio median [range] " + "; ".join(parts))


if __name__ == "__main__":
    main()
