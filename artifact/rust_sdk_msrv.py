#!/usr/bin/env python3
"""Run the public API consumer of pinned SDK archives on the actual Rust 1.85 compiler."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

import rust_sdk_profile as sdk
from evidence_io import parse_strict_json_bytes

ROOT = Path(__file__).resolve().parent.parent
RUSTC = "rustc 1.85.0 (4d91de4e4 2025-02-17)"


def source_inputs() -> dict:
    identity = sdk.source_identity()
    for name in ("artifact/rust_sdk_msrv.py", "artifact/python-run.sh", "artifact/python-env.sh",
                 "artifact/python_bootstrap.py"):
        identity["files"][name] = sdk.snapshot(ROOT / name).sha256
    return identity


def validate_report(data: bytes, expected_digest: str, actual_digest: str, current: str) -> dict:
    sdk.require(re.fullmatch(r"[a-f0-9]{64}", expected_digest) is not None
                and actual_digest == expected_digest, "Rust cohort report digest differs")
    report = parse_strict_json_bytes(data, label="Rust cohort report")
    sdk.require(type(report["schema_version"]) is int and report["schema_version"] == 1
                and report["sources_unchanged"] is True,
                "Rust cohort did not complete source-bound package qualification")
    sdk.require(report["version"] == sdk.VERSION and report["profile"] == sdk.PROFILE
                and type(report["native_abi_major"]) is int and report["native_abi_major"] == 2
                and set(report["crates"]) == set(sdk.COHORT), "Rust cohort identity differs")
    sdk.require(re.fullmatch(r"[a-f0-9]{64}", current) is not None
                and report["source_inputs"]["rust_workspace_sha256"] == current,
                "Rust cohort does not identify current workspace inputs")
    return report


def tool_identity(toolchain: Path) -> dict:
    return {name: {"path": str(toolchain / "bin" / name),
                   "sha256": sdk.snapshot(toolchain / "bin" / name, maximum=256 * 1024**2).sha256}
            for name in ("cargo", "rustc", "rustdoc")}


def qualify(args: argparse.Namespace) -> dict:
    sdk.validate_no_registry_credentials(os.environ)
    sdk.require(os.uname().sysname in {"Darwin", "Linux"}, "public host-store consumer requires a Unix host")
    before = source_inputs()
    report_snapshot = sdk.snapshot(args.report)
    report = validate_report(report_snapshot.data, args.report_sha256, report_snapshot.sha256,
                             before["rust_workspace_sha256"])
    output = args.output.absolute()
    sdk.require(not output.exists() and not output.is_symlink() and output.is_relative_to(ROOT / "target"),
                "MSRV output must be fresh and under target")
    sdk.require(shutil.disk_usage(ROOT).free >= 2 * 1024**3, "MSRV consumer needs 2 GiB free")
    toolchain = args.toolchain_root.resolve(strict=True)
    tools_before = tool_identity(toolchain)
    cargo_home = args.cargo_home.resolve(strict=True)
    sdk.require(not any((cargo_home / name).exists() or (cargo_home / name).is_symlink()
                        for name in ("config", "config.toml", "credentials", "credentials.toml")),
                "offline Cargo cache contains config/credential overrides")
    output.mkdir(parents=True, mode=0o700)
    outside = Path(tempfile.mkdtemp(prefix="qperiapt-rust-sdk-msrv-")).resolve()
    sdk.require(not outside.is_relative_to(ROOT), "MSRV consumer must be outside checkout")
    sdk.write_json(output / "location.json", {"path": str(outside)})
    sdk.write_json(output / "sources-before.json", before)
    result = {"kind": "qperiapt.rust_sdk_msrv_qualification", "schema_version": 1,
              "version": sdk.VERSION, "native_abi_major": 2, "completed": False,
              "release_claim_eligible": False, "host_os": os.uname().sysname,
              "host_arch": os.uname().machine, "outside_checkout": str(outside),
              "rust_report_sha256": report_snapshot.sha256, "tool_binaries": tools_before,
              "source_inputs": before, "publication_performed": False,
              "scope": "public APIs from nine pinned archives on this host; not full workspace development tests or a platform matrix"}
    try:
        consumer = outside / "consumer"
        sdk.prepare_consumer_fixture(consumer)
        sdk.extract_recorded_crates(consumer, args.report.parent, report["crates"])
        sdk.copy(ROOT / "Cargo.lock", consumer / "Cargo.lock")
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(("CARGO_", "RUST", "DYLD_", "LD_"))}
        environment.update(CARGO_HOME=str(cargo_home), CARGO_NET_OFFLINE="true", CARGO_TERM_COLOR="never",
                           CARGO_TARGET_DIR=str(outside / "target"), CARGO_INCREMENTAL="0",
                           RUSTC=str(toolchain / "bin/rustc"), RUSTDOC=str(toolchain / "bin/rustdoc"),
                           RUSTFLAGS="-D warnings", RUSTDOCFLAGS="-D warnings")

        def run(argv: list[str], label: str) -> bytes:
            return sdk.command(argv, output / label, consumer, environment=environment)

        compiler = run([str(toolchain / "bin/rustc"), "--version", "--verbose"], "rustc").decode()
        sdk.require(compiler.splitlines()[0] == RUSTC, "MSRV qualification requires the actual Rust 1.85.0 compiler")
        result["rustc"] = compiler
        result["cargo"] = run([str(toolchain / "bin/cargo"), "--version"], "cargo").decode().strip()
        sdk.require(result["cargo"].startswith("cargo 1.85.0 "), "MSRV Cargo version differs")
        cargo = [str(toolchain / "bin/cargo")]
        # The workspace lock must first acquire this external consumer identity.
        # Every remaining registry tuple is then checked before compiling; no
        # update or resolver downgrade is permitted to make the minimum pass.
        metadata = parse_strict_json_bytes(
            run([*cargo, "metadata", "--offline", "--format-version", "1"], "metadata"),
            label="MSRV Cargo metadata")
        lock = sdk.snapshot(consumer / "Cargo.lock")
        result["resolution"] = sdk.verify_consumer_resolution(metadata, consumer, lock.data,
                                                              sdk.snapshot(ROOT / "Cargo.lock").data)
        tested = run([*cargo, "test", "--locked", "--offline", "-j", "2"], "consumer-test")
        sdk.verify_consumer_tests(tested)
        sdk.require(sdk.snapshot(consumer / "Cargo.lock").sha256 == lock.sha256, "MSRV consumer changed its lock")
        sdk.copy(consumer / "Cargo.lock", output / "consumer-Cargo.lock")
        sdk.verify_consumed_sources(consumer, args.report.parent, report["crates"])
        sdk.require(sdk.snapshot(args.report).sha256 == report_snapshot.sha256, "Rust cohort report changed")
        sdk.require(source_inputs() == before and tool_identity(toolchain) == tools_before,
                    "MSRV source or tool identity changed during qualification")
        sdk.write_json(output / "sources-after.json", source_inputs())
        result.update(completed=True, sources_unchanged=True, tests=sorted(sdk.CONSUMER_TESTS))
    except Exception as error:
        result["failure"] = str(error)
        raise
    finally:
        sdk.write_json(output / "RUST_SDK_MSRV.json", result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("output", "report", "cargo-home", "toolchain-root"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--report-sha256", required=True)
    report = qualify(parser.parse_args())
    print(json.dumps({key: report[key] for key in ("completed", "host_os", "host_arch", "tests",
                                                  "resolution", "release_claim_eligible")}, indent=2))


if __name__ == "__main__":
    main()
