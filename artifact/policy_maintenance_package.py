#!/usr/bin/env python3
"""Build and consume the native maintenance tool from qualified SDK crate bytes."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import tempfile
import tomllib

import deterministic_archive as archives
import rust_sdk_profile as sdk
import third_party_licenses as licenses
from c_package_manifest import EXPECTED_CARGO_VERSION, EXPECTED_RUSTC_VERSION
from evidence_io import fresh_output_directory, parse_strict_json_bytes
from git_provenance import run_git_text
from rust_sdk_msrv import tool_identity, validate_report

ROOT = Path(__file__).resolve().parent.parent
NAME = "q-periapt-cli"
TARGETS = {
    ("Darwin", "arm64"): "aarch64-apple-darwin",
    ("Linux", "x86_64"): "x86_64-unknown-linux-gnu",
    ("Linux", "aarch64"): "aarch64-unknown-linux-gnu",
}
RESOLVED_NAMES = frozenset((*sdk.COHORT[:8], NAME))
PAYLOAD_SOURCES = {
    "README.md": "docs/POLICY_MAINTENANCE.md",
    "LICENSE": "LICENSE",
    "LICENSES/Apache-2.0.txt": "LICENSES/Apache-2.0.txt",
    "LICENSES/MIT.txt": "LICENSES/MIT.txt",
    "LICENSES/Rust-1.98.1-library.html": "LICENSES/Rust-1.98.1-library.html",
    **{f"LICENSES/mlkem-native/{name}": f"crates/q-periapt-mlkem-native-sys/vendor/{name}" for name in (
        "LICENSE.mlkem-native", "LICENSE-INVENTORY.md", "PROVENANCE.md", "INVENTORY.sha256")},
}
KIND = "qperiapt.policy_maintenance_package"
MANIFEST_KEYS = frozenset({
    "schema_version", "kind", "version", "target", "source_commit", "builder_commit",
    "rust_report_sha256", "source_inputs", "source_date_epoch", "compiler", "tools",
    "release_profile", "rustflags", "features", "resolution", "runtime", "files",
})


def source_inputs() -> dict:
    identity = sdk.source_identity()
    for name in (*PAYLOAD_SOURCES.values(), "artifact/policy_maintenance_package.py",
                 "artifact/policy_store_migration_installed.py", "artifact/third_party_licenses.py",
                 "artifact/deterministic_archive.py", "artifact/rust_sdk_msrv.py",
                 "artifact/apple-sdk-rustc.sh", "artifact/python-run.sh", "artifact/python-env.sh",
                 "artifact/python_bootstrap.py"):
        identity["files"][name] = sdk.snapshot(ROOT / name).sha256
    return identity


def validate_resolution(metadata: dict, consumer: Path, lock: bytes, original: bytes) -> dict:
    rows = [p for p in metadata["packages"] if p["source"] is None]
    local = {p["name"]: p for p in rows}
    sdk.require(len(rows) == len(local) and set(local) == RESOLVED_NAMES,
                "maintenance consumer activated a different local dependency graph")
    for name, row in local.items():
        sdk.require(row["version"] == sdk.VERSION and Path(row["manifest_path"]).resolve()
                    == consumer / "packages" / f"{name}-{sdk.VERSION}" / "Cargo.toml",
                    "maintenance dependency came from outside its recorded archive")
    selected = [n for n in metadata["resolve"]["nodes"] if n["id"] == local[NAME]["id"]]
    sdk.require(len(selected) == 1 and "policy-store-migration" in selected[0]["features"]
                and "sdk-cbom" not in selected[0]["features"], "maintenance features differ")
    resolved, expected = sdk.external_lock(lock), sdk.external_lock(original)
    sdk.require(all(expected.get(k) == v for k, v in resolved.items()),
                "maintenance consumer changed external dependency identities")
    sdk.require({("redb", "2.6.4"), ("redb", "4.3.0"), ("twox-hash", "2.1.4")} <= resolved.keys(),
                "maintenance dependency closure is incomplete")
    return {"local_packages": sorted(local), "external_packages": len(resolved),
            "lockfile_sha256": hashlib.sha256(lock).hexdigest()}


def payload(root: Path) -> dict[str, dict]:
    rows = {}
    for path in sorted(root.rglob("*")):
        mode = path.lstat().st_mode
        sdk.require(not path.is_symlink(), "maintenance package contains a symlink")
        if stat.S_ISDIR(mode):
            continue
        sdk.require(stat.S_ISREG(mode), "maintenance package contains a special file")
        relative = path.relative_to(root).as_posix()
        if relative == "MANIFEST.json":
            continue
        expected_mode = 0o755 if relative == "bin/qperiapt" else 0o644
        sdk.require(stat.S_IMODE(mode) == expected_mode, "maintenance payload mode differs")
        value = sdk.snapshot(path)
        rows[relative] = {"bytes": value.size, "sha256": value.sha256, "mode": oct(expected_mode)}
    return rows


def verify_payload(root: Path, target: str, expected_manifest: str) -> dict:
    manifest_bytes = sdk.snapshot(root / "MANIFEST.json")
    sdk.require(manifest_bytes.sha256 == expected_manifest, "maintenance manifest digest differs")
    manifest = parse_strict_json_bytes(manifest_bytes.data, label="maintenance manifest")
    sdk.require(set(manifest) == MANIFEST_KEYS, "maintenance manifest fields differ")
    sdk.require(manifest["kind"] == KIND and type(manifest["schema_version"]) is int and manifest["schema_version"] == 1
                and manifest["version"] == sdk.VERSION and manifest["target"] == target,
                "maintenance package identity differs")
    inventory = licenses.verify(root, expected_target=target, root_package=NAME)
    expected = set(PAYLOAD_SOURCES) | {"bin/qperiapt", str(licenses.INVENTORY_RELATIVE)}
    expected.update(f["path"] for p in inventory["packages"] for f in p["license_files"])
    rows = payload(root)
    sdk.require(set(rows) == expected and rows == manifest["files"],
                "maintenance package has missing, changed or unexpected payload")
    return manifest


def qualify(args: argparse.Namespace) -> dict:
    sdk.validate_no_registry_credentials(os.environ)
    target = TARGETS.get((platform.system(), platform.machine()))
    sdk.require(target is not None, "maintenance packages support only macOS arm64 and native Linux")
    commit, dirty = sdk.inspect_package_source(ROOT, allow_dirty=False)
    sdk.require(not dirty, "maintenance packaging requires clean source")
    before = source_inputs()
    report_bytes = sdk.snapshot(args.report)
    report = validate_report(report_bytes.data, args.report_sha256, report_bytes.sha256,
                             before["rust_workspace_sha256"])
    sdk.require(report["git_dirty"] is False and report["diagnostic_only"] is False,
                "maintenance input must be a clean qualified Rust cohort")
    output = fresh_output_directory(args.output, within=ROOT / "target", label="maintenance output")
    sdk.require(shutil.disk_usage(ROOT).free >= 2 * 1024**3, "maintenance packaging needs 2 GiB free")
    toolchain = args.toolchain_root.resolve(strict=True)
    tools = tool_identity(toolchain)
    cache = args.cargo_home.resolve(strict=True)
    sdk.require(not any((cache / name).exists() or (cache / name).is_symlink()
                        for name in ("config", "config.toml", "credentials", "credentials.toml")),
                "maintenance Cargo cache has configuration or credentials")
    output.mkdir(mode=0o700, parents=True)
    outside = Path(tempfile.mkdtemp(prefix="qperiapt-policy-maintenance-")).resolve()
    sdk.require(not outside.is_relative_to(ROOT), "maintenance consumer must be outside checkout")
    consumer = outside / "consumer"
    consumer.mkdir()
    sdk.write_json(output / "location.json", {"consumer": str(consumer)})
    sdk.write_json(output / "sources-before.json", before)
    # Preserve the workspace's actual release profile for this archive consumer.
    profile = tomllib.loads(sdk.snapshot(ROOT / "Cargo.toml").data.decode())["profile"]["release"]
    sdk.require(all(type(v) in (str, bool, int) for v in profile.values()),
                "maintenance release profile contains unmodeled nested settings")
    manifest = '[workspace]\nresolver = "3"\nmembers = ["packages/q-periapt-cli-0.2.0"]\n\n[profile.release]\n'
    manifest += "".join(f"{key} = {json.dumps(value)}\n" for key, value in profile.items())
    (consumer / "Cargo.toml").write_text(manifest)
    sdk.extract_recorded_crates(consumer, args.report.parent, report["crates"])
    record = report["crates"][NAME]
    sdk.require(record["file"] == f"{NAME}-{sdk.VERSION}.crate", "maintenance CLI archive filename differs")
    cli = sdk.snapshot(args.report.parent / "crates" / record["file"])
    sdk.require(cli.sha256 == record["sha256"], "maintenance CLI archive digest differs")
    cli_files = sdk.archive_files(cli.data, NAME)
    sdk.require(set(cli_files) == set(record["files"]), "maintenance CLI archive inventory differs")
    cli_root = consumer / "packages" / f"{NAME}-{sdk.VERSION}"
    for relative, data in cli_files.items():
        path = cli_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(data)
    sdk.copy(ROOT / "Cargo.lock", consumer / "Cargo.lock")
    environment = {k: v for k, v in os.environ.items()
                   if not k.startswith(("CARGO_", "RUST", "DYLD_", "LD_", "MACOSX_", "IPHONEOS_"))}
    environment.update(CARGO_HOME=str(cache), CARGO_NET_OFFLINE="true", CARGO_TERM_COLOR="never",
        CARGO_TARGET_DIR=str(outside / "build"), CARGO_INCREMENTAL="0", CARGO_BUILD_JOBS="2",
        RUSTC=str(toolchain / "bin/rustc"), RUSTDOC=str(toolchain / "bin/rustdoc"),
        RUSTFLAGS="-D warnings -C strip=debuginfo", RUSTDOCFLAGS="-D warnings",
        DYLD_FALLBACK_LIBRARY_PATH=str(toolchain / "lib"))
    if target == "aarch64-apple-darwin":
        environment.update(RUSTC_WRAPPER=str(ROOT / "artifact/apple-sdk-rustc.sh"), MACOSX_DEPLOYMENT_TARGET="13.0")

    def run(label: str, argv: list[str], cwd: Path = consumer) -> bytes:
        return sdk.command(argv, output / label, cwd, environment=environment)

    cargo = str(toolchain / "bin/cargo")
    compiler = run("rustc", [str(toolchain / "bin/rustc"), "-vV"]).decode()
    sdk.require(compiler.splitlines()[0] == EXPECTED_RUSTC_VERSION
                and f"host: {target}" in compiler.splitlines(), "maintenance compiler or native host differs")
    sdk.require(run("cargo", [cargo, "--version"]).decode().strip() == EXPECTED_CARGO_VERSION,
                "maintenance Cargo version differs")
    # Resolution first adds the external workspace identity. Check every external
    # tuple before building with --locked; an unpublished optional rustls archive
    # is needed for resolution but is not activated by the maintenance feature.
    metadata = parse_strict_json_bytes(run("metadata", [cargo, "metadata", "--offline", "--format-version", "1",
        "--filter-platform", target, "--features", "policy-store-migration"]), label="maintenance metadata")
    resolution = validate_resolution(metadata, consumer, sdk.snapshot(consumer / "Cargo.lock").data,
                                    sdk.snapshot(ROOT / "Cargo.lock").data)
    run("build", [cargo, "build", "--release", "--locked", "--offline", "--target", target,
                  "-p", NAME, "--features", "policy-store-migration"])
    package_name = f"q-periapt-policy-maintenance-{sdk.VERSION}-{target}"
    package = output / package_name
    package.mkdir(mode=0o755)
    sdk.copy(outside / "build" / target / "release/qperiapt", package / "bin/qperiapt")
    (package / "bin/qperiapt").chmod(0o755)
    for destination, original in PAYLOAD_SOURCES.items():
        sdk.copy(ROOT / original, package / destination)
    inventory = licenses.collect(consumer, package, target, root_package=NAME, resolved_metadata=metadata)
    runtime = {"tested_system": platform.system(), "tested_release": platform.release(),
               "tested_machine": platform.machine(), "minimum_os_execution_qualified": False}
    if target == "aarch64-apple-darwin":
        arch = run("binary-arch", ["/usr/bin/lipo", "-archs", str(package / "bin/qperiapt")]).decode().strip()
        loads = run("binary-loads", ["/usr/bin/otool", "-l", str(package / "bin/qperiapt")]).decode()
        sdk.require(arch == "arm64" and re.search(r"\bminos 13\.0\b", loads) is not None,
                    "maintenance Mach-O architecture or deployment floor differs")
        runtime["declared_macos_deployment_target"] = "13.0"
    else:
        runtime["producer_libc"] = list(platform.libc_ver())
        run("binary-elf", ["readelf", "-hW", str(package / "bin/qperiapt")])
        run("binary-linkage", ["ldd", str(package / "bin/qperiapt")])
    version = run("binary-version", [str(package / "bin/qperiapt"), "--version"]).decode().strip()
    sdk.require(version == "qperiapt 0.2.0", "maintenance executable version differs")
    epoch = int(run_git_text(ROOT, ["show", "-s", "--format=%ct", commit]))
    manifest = {"schema_version": 1, "kind": KIND, "version": sdk.VERSION, "target": target,
        "source_commit": report["base_commit"], "builder_commit": commit,
        "rust_report_sha256": report_bytes.sha256, "source_inputs": before,
        "source_date_epoch": epoch, "compiler": compiler, "tools": tools,
        "release_profile": profile, "rustflags": environment["RUSTFLAGS"],
        "features": ["policy-store-migration"], "resolution": resolution,
        "runtime": runtime, "files": payload(package)}
    sdk.write_json(package / "MANIFEST.json", manifest)
    (package / "MANIFEST.json").chmod(0o644)
    pinned_manifest = sdk.snapshot(package / "MANIFEST.json").sha256
    verify_payload(package, target, pinned_manifest)
    archive = output / f"{package_name}.tar.gz"
    archives.create_tar_gz(package, archive, root_name=package_name, mtime=epoch)
    archive_digest = sdk.snapshot(archive, maximum=128 * 1024**2).sha256
    (output / f"{archive.name}.sha256").write_text(f"{archive_digest}  {archive.name}\n")
    installed = outside / "installed"
    archives.extract_tar_gz(archive, installed, root_name=package_name, mtime=epoch, expected_sha256=archive_digest)
    installed_root = installed / package_name
    verify_payload(installed_root, target, pinned_manifest)
    run("installed", ["sh", "artifact/python-run.sh", "artifact/policy_store_migration_installed.py",
                      "--binary", str(installed_root / "bin/qperiapt"), "--output", str(output / "installed")], ROOT)
    verify_payload(installed_root, target, pinned_manifest)
    sdk.verify_consumed_sources(consumer, args.report.parent, report["crates"], names=(*sdk.CONSUMER_CRATES, NAME))
    sdk.require(before == source_inputs() and sdk.inspect_package_source(ROOT, allow_dirty=False) == (commit, False)
                and tools == tool_identity(toolchain), "maintenance source or toolchain changed")
    sdk.require(sdk.snapshot(args.report).sha256 == report_bytes.sha256, "Rust package report changed")
    result = {"schema_version": 1, "kind": KIND, "completed": True, "target": target,
        "archive": archive.name, "archive_sha256": archive_digest, "manifest_sha256": pinned_manifest,
        "binary_sha256": manifest["files"]["bin/qperiapt"]["sha256"], "runtime": runtime,
        "source_commit": report["base_commit"], "builder_commit": commit,
        "license_packages": len(inventory["packages"]), "installed": str(installed_root),
        "sources_unchanged": True, "publication_performed": False, "release_claim_eligible": False}
    sdk.write_json(output / "RESULT.json", result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--report-sha256", required=True)
    parser.add_argument("--toolchain-root", required=True, type=Path)
    parser.add_argument("--cargo-home", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    print(json.dumps(qualify(parser.parse_args()), indent=2))


if __name__ == "__main__":
    main()
