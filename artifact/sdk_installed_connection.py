#!/usr/bin/env python3
"""Exercise packaged Swift and Rust SDKs across real local TCP; native Linux remains separate."""
from __future__ import annotations

import argparse
import contextlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

import apple_sdk_profile as apple
import rust_sdk_profile as rust
from bounded_process import capture_output
from c_package_manifest import rust_workspace_source_digest
from deterministic_archive import extract_zip
from evidence_io import (fresh_output_directory, load_json_object_snapshot,
                         parse_strict_json_bytes, read_regular_snapshot)
from sdk_connection_interop import StaticClientLinkage, run_boundary

ROOT = Path(__file__).resolve().parent.parent
SWIFT_FIXTURE = "bindings/swift/SDKConnectionConsumer/Package.swift"
SWIFT_WORKLOAD = "bindings/swift/Examples/ConnectionProbe/main.swift"
RUST_FIXTURE = "bindings/rust/SDKConnectionConsumer/Cargo.toml"
CONSUMER_NAME = "q-periapt-connection-package-consumer"
MAX_INPUT = 512 * 1024 * 1024


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def snapshot(path: Path):
    return read_regular_snapshot(path, maximum=MAX_INPUT, label="installed connection input")


def pinned(path: Path, digest: str):
    require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "expected input digest is not canonical SHA-256")
    value = snapshot(path)
    require(value.sha256 == digest, f"installed connection input digest differs: {path.name}")
    return value


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as stream:
        stream.write(snapshot(source).data)


def source_inputs() -> dict:
    paths = (SWIFT_FIXTURE, SWIFT_WORKLOAD, RUST_FIXTURE,
             "artifact/sdk_installed_connection.py", "artifact/sdk_connection_interop.py",
             "artifact/standard_tls_interop.py", "artifact/apple_sdk_profile.py",
             "artifact/rust_sdk_profile.py", "artifact/c_package_manifest.py",
             "artifact/deterministic_archive.py", "artifact/evidence_io.py", "artifact/bounded_process.py",
             "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2-sdk-020.json",
             *("bindings/" + name for name in apple.POLICIES))
    return {"rust_workspace_sha256": rust_workspace_source_digest(ROOT),
            "files": {name: snapshot(ROOT / name).sha256 for name in paths}}


def same_native_sources(swift_source: dict, rust_report: dict, current: str) -> None:
    require(isinstance(current, str) and re.fullmatch(r"[0-9a-f]{64}", current) is not None,
            "current Rust workspace digest is invalid")
    require(swift_source.get("rust_workspace_build_inputs") ==
            rust_report.get("source_inputs", {}).get("rust_workspace_sha256") == current,
            "Swift and Rust packages must identify the same current Rust workspace inputs")


def verify_rust_resolution(metadata: dict, consumer: Path, lock: bytes, original_lock: bytes) -> dict:
    return rust.verify_consumer_resolution(metadata, consumer, lock, original_lock, consumer_name=CONSUMER_NAME)


def run_command(args: list[str], output: Path, label: str, cwd: Path, environment: dict) -> bytes:
    with contextlib.chdir(cwd):
        result = capture_output(args, timeout_seconds=900, maximum_stdout_bytes=32 * 1024 * 1024,
                                maximum_stderr_bytes=32 * 1024 * 1024, environment=environment)
    (output / f"{label}.stdout").write_bytes(result.stdout)
    (output / f"{label}.stderr").write_bytes(result.stderr)
    write_json(output / f"{label}.json", {"argv": args, "cwd": str(cwd), "returncode": result.returncode})
    require(result.returncode == 0, f"installed connection {label} failed; retained command output")
    text = (result.stdout + result.stderr).decode("utf-8")
    require(re.search(r"(?im)(?:^|[^a-z])(warning|error):", text) is None,
            f"installed connection {label} emitted warnings/errors")
    checked = text.replace(str(output), "${EVIDENCE_OUTPUT}")
    # Registry sources may live in the selected isolated offline cache under
    # target. Product dependency origins are independently checked in metadata.
    if "CARGO_HOME" in environment:
        cache = Path(environment["CARGO_HOME"]).resolve()
        require(cache != ROOT and not ROOT.is_relative_to(cache), "Cargo cache cannot contain the source checkout")
        checked = checked.replace(str(cache), "${CARGO_HOME}")
    require(str(ROOT) not in checked, f"installed consumer {label} refers to the source checkout")
    return result.stdout


def fresh_output_path(path: Path) -> Path:
    return fresh_output_directory(path, within=ROOT / "target", label="installed connection output")


def qualify(args: argparse.Namespace) -> dict:
    require(os.uname().sysname == "Darwin", "installed Swift connection qualification requires macOS")
    rust.validate_no_registry_credentials(os.environ)
    require(not any(value for key, value in os.environ.items() if key.startswith(("DYLD_", "LD_")) or
                    key in {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"}),
            "loader and Rust compiler overrides must be unset for installed qualification")
    before = source_inputs()
    swift = pinned(args.swift_zip, args.swift_sha256)
    native = apple.verified_xcframework_files(args.swift_native_zip, args.swift_native_sha256)
    report_snapshot = pinned(args.rust_report, args.rust_report_sha256)
    report = load_json_object_snapshot(args.rust_report, maximum=16 * 1024 * 1024, label="Rust cohort").value
    require(type(report["schema_version"]) is int and report["schema_version"] == 1 and report["sources_unchanged"] is True,
            "Rust cohort did not complete its source-bound package contract")
    require(report["version"] == rust.VERSION and report["profile"] == rust.PROFILE and report["native_abi_major"] == 2
            and set(report["crates"]) == set(rust.COHORT), "Rust cohort identity differs")
    output = fresh_output_path(args.output)
    require(shutil.disk_usage(ROOT).free >= 4 * 1024**3, "installed connection build needs 4 GiB free")
    output.mkdir(parents=True, mode=0o700)
    outside = Path(tempfile.mkdtemp(prefix="qperiapt-installed-connection-")).resolve()
    require(not outside.is_relative_to(ROOT), "installed consumers must be outside the checkout")
    write_json(output / "location.json", {"path": str(outside)})
    write_json(output / "sources-before.json", before)
    result = {"kind": "qperiapt.installed_connection_qualification", "completed": False,
              "release_claim_eligible": False, "network": "loopback", "client_platform": os.uname().sysname,
              "server_platform": os.uname().sysname, "native_linux_server_executed": False,
              "outside_checkout": str(outside), "abi_major": 2, "swift_zip_sha256": swift.sha256,
              "swift_native_zip_sha256": args.swift_native_sha256, "rust_report_sha256": report_snapshot.sha256}
    try:
        extract_zip(args.swift_zip, outside / "install", root_name="QPeriapt", mtime=apple.MTIME,
                    expected_sha256=swift.sha256, limits=apple.LIMITS)
        package = outside / "install/QPeriapt"
        swift_source = load_json_object_snapshot(package / apple.CONTENTS, maximum=2 * 1024 * 1024,
                                                 label="installed Swift manifest").value["source_inputs"]
        same_native_sources(swift_source, report, before["rust_workspace_sha256"])
        apple.verify_package(package, swift_source, cargo_lock=ROOT / "Cargo.lock", expected_native_files=native)
        for shipped, source in apple.SHIPPED_SOURCES.items():
            if shipped.startswith("Sources/"):
                require(snapshot(package / shipped).data == snapshot(ROOT / source).data,
                        "installed Swift wrapper differs from current source")
        swift_consumer = outside / "install/client"
        copy(ROOT / SWIFT_FIXTURE, swift_consumer / "Package.swift")
        copy(ROOT / SWIFT_WORKLOAD, swift_consumer / "Sources/QPeriaptConnectionProbe/main.swift")
        rust_consumer = outside / "server"
        copy(ROOT / RUST_FIXTURE, rust_consumer / "Cargo.toml")
        rust.extract_recorded_crates(rust_consumer, args.rust_report.parent, report["crates"])
        copy(ROOT / "Cargo.lock", rust_consumer / "Cargo.lock")
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(("CARGO_", "RUST", "SWIFT_", "DYLD_", "LD_"))}
        cargo_home = args.cargo_home.resolve(strict=True)
        require(not any((cargo_home / name).exists() for name in ("config", "config.toml", "credentials", "credentials.toml")),
                "selected offline Cargo cache must not contain config/credential overrides")
        environment.update(CARGO_HOME=str(cargo_home), CARGO_NET_OFFLINE="true", CARGO_TERM_COLOR="never",
                           CARGO_TARGET_DIR=str(outside / "rust-build"), RUSTFLAGS="-D warnings")
        toolchain = run_command(["rustc", "+1.98.1", "--version"], output, "rustc", outside, environment).decode().strip()
        require(toolchain == "rustc 1.98.1 (48a229cea 2026-09-01)", "installed Rust compiler differs")
        run_command(["cargo", "+1.98.1", "build", "--offline", "--bins", "-j", "2"], output, "rust-build", rust_consumer, environment)
        metadata = parse_strict_json_bytes(run_command(
            ["cargo", "+1.98.1", "metadata", "--locked", "--offline", "--format-version", "1"],
            output, "rust-metadata", rust_consumer, environment), label="installed connection Cargo metadata")
        result["rust_resolution"] = verify_rust_resolution(metadata, rust_consumer, snapshot(rust_consumer / "Cargo.lock").data,
                                                            snapshot(ROOT / "Cargo.lock").data)
        run_command(["cargo", "+1.98.1", "clippy", "--locked", "--offline", "--all-targets", "-j", "2", "--", "-D", "warnings"],
                    output, "rust-clippy", rust_consumer, environment)
        copy(rust_consumer / "Cargo.lock", output / "consumer-Cargo.lock")
        rust.verify_consumed_sources(rust_consumer, args.rust_report.parent, report["crates"])
        swift_environment = {key: value for key, value in environment.items() if not key.startswith(("CARGO_", "RUST"))}
        build_root = outside / "swift-build"
        link_map = output / "client-link.map"
        arguments = ["--package-path", str(swift_consumer), "--scratch-path", str(build_root), "--configuration", "release"]
        run_command(["swift", "build", *arguments, "--product", "QPeriaptConnectionProbe", "-j", "2",
                     "-Xswiftc", "-strict-concurrency=complete", "-Xswiftc", "-warnings-as-errors",
                     "-Xlinker", "-map", "-Xlinker", str(link_map)], output, "swift-build", outside, swift_environment)
        binary_dir = Path(run_command(["swift", "build", *arguments, "--show-bin-path"], output, "swift-bin", outside,
                                      swift_environment).decode().strip()).resolve(strict=True)
        require(binary_dir.is_relative_to(build_root), "installed Swift executable escaped its owned build tree")
        client = binary_dir / "QPeriaptConnectionProbe"
        library = binary_dir / "libq_periapt_ffi_abi2.a"
        expected_library = package / "Binaries/CQPeriapt.xcframework/macos-arm64/libq_periapt_ffi_abi2.a"
        require(snapshot(library).sha256 == snapshot(expected_library).sha256, "Swift selected a different static archive")
        architecture = {"arm64": "arm64"}.get(os.uname().machine)
        require(architecture is not None, "unsupported Swift host architecture")
        linkage = StaticClientLinkage(library, snapshot(expected_library).sha256, link_map, architecture)
        result["link_map"] = apple.verify_link_map(link_map, library, client, architecture)
        result["swift_client"] = {"sha256": snapshot(client).sha256, "static_library_sha256": linkage.library_sha256}
        boundary = run_boundary(output / "boundary", swift=client, server=outside / "rust-build/debug/connection_peer",
                                fixtures_binary=outside / "rust-build/debug/standard_peer", static_linkage=linkage)
        require(boundary["completed"] is True and len(boundary["observations"]) == 12, "installed boundary did not complete")
        result["boundary"] = {"manifest_sha256": snapshot(output / "boundary/manifest.json").sha256,
                              "cases": [row["case"] for row in boundary["observations"]]}
        apple.verify_package(package, swift_source, cargo_lock=ROOT / "Cargo.lock", expected_native_files=native)
        rust.verify_consumed_sources(rust_consumer, args.rust_report.parent, report["crates"])
        pinned(args.swift_zip, swift.sha256)
        apple.verified_xcframework_files(args.swift_native_zip, args.swift_native_sha256)
        pinned(args.rust_report, report_snapshot.sha256)
        require(source_inputs() == before, "installed connection source inputs changed during qualification")
        result["completed"] = True
    except Exception as error:
        result["failure"] = str(error)
        raise
    finally:
        write_json(output / "INSTALLED_CONNECTION.json", result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("output", "swift-zip", "swift-native-zip", "rust-report", "cargo-home"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("swift-sha256", "swift-native-sha256", "rust-report-sha256"):
        parser.add_argument("--" + name, required=True)
    print(json.dumps(qualify(parser.parse_args()), indent=2))


if __name__ == "__main__":
    main()
