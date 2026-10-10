#!/usr/bin/env python3
"""The owned SDK extension of the shared Apple package builder.

The XCFramework itself is built and checked by swift-xcframework.sh. This module
owns the closed alpha wrapper/consumer layout and never admits a signed release
receipt or rewrites the historical Apple distribution identity.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import zipfile

from apple_distribution import MAX_ARTIFACT_BYTES, _validate_xcframework_zip_bytes
from c_abi_contract import load_contract, verify_header, verify_static_library
from c_package_manifest import rust_workspace_source_digest
from deterministic_archive import ArchiveLimits, create_zip, extract_zip
from evidence_io import load_json_object_snapshot, read_regular_snapshot
from bounded_process import capture_stdout, capture_output
from package_bom import BomProfile, verify as verify_boms
from third_party_licenses import collect as collect_licenses, verify as verify_licenses

ROOT = Path(__file__).resolve().parent.parent
PROFILE = "sdk-020"
VERSION = "0.2.0"
CONTRACT = "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2-sdk-020.json"
SDK_FILES = (
    "ConnectionEngine.swift", "NetworkTransport.swift", "QPeriaptConnection.swift",
    "QPeriaptPersistentRuntime.swift", "QPeriaptPolicyRecovery.swift", "QPeriaptSDK.swift",
)
FIXTURE = "bindings/swift/SDKBinaryConsumerFixture"
HOST_TARGETS = ("aarch64-apple-darwin",)
TARGETS = (*HOST_TARGETS, "aarch64-apple-ios",
           "aarch64-apple-ios-sim", "x86_64-apple-ios")
SLICES = ("macos-arm64", "ios-arm64", "ios-arm64_x86_64-simulator")
POLICIES = ("signed-policy-vectors.json", "sdk-policy-revocation-vectors.json", "sdk-policy-update-vectors.json", "sdk-policy-recovery-vectors.json")
CONTENTS = "PACKAGE_CONTENTS.json"
ARCHIVE_NAME = "QPeriapt-Swift-SDK-0.2.0.zip"
MTIME = 946684800
LIMITS = ArchiveLimits(maximum_archive_bytes=512 * 1024 * 1024,
                       maximum_total_bytes=384 * 1024 * 1024)
SHIPPED_SOURCES = {
    **{f"Sources/QPeriaptSDK/{name}": f"bindings/swift/Sources/QPeriaptSDK/{name}" for name in SDK_FILES},
    "Sources/QPeriaptHybrid/QPeriaptHybrid.swift": "bindings/swift/Sources/QPeriaptHybrid/QPeriaptHybrid.swift",
    "README.md": "bindings/swift/SDKPackageREADME.md",
    **{name: name for name in ("LICENSE", "LICENSES/Apache-2.0.txt", "LICENSES/MIT.txt",
                              "LICENSES/Rust-1.98.1-library.html")},
    **{f"LICENSES/mlkem-native/{name}": f"crates/q-periapt-mlkem-native-sys/vendor/{name}"
       for name in ("INVENTORY.sha256", "LICENSE-INVENTORY.md", "LICENSE.mlkem-native", "PROVENANCE.md")},
}

PACKAGE = '''// swift-tools-version:5.9
import PackageDescription
let package = Package(
    name: "QPeriapt",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "QPeriaptSDK", targets: ["QPeriaptSDK"]),
        .library(name: "QPeriaptHybrid", targets: ["QPeriaptHybrid"])
    ],
    targets: [
        .binaryTarget(name: "CQPeriapt", path: "Binaries/CQPeriapt.xcframework"),
        .target(name: "QPeriaptSDK", dependencies: ["CQPeriapt"],
                linkerSettings: [.linkedLibrary("iconv")]),
        .target(name: "QPeriaptHybrid", dependencies: ["CQPeriapt"],
                linkerSettings: [.linkedLibrary("iconv")])
    ]
)
'''

CONSUMER_PACKAGE = '''// swift-tools-version:5.9
import PackageDescription
let package = Package(
    name: "QPeriaptSDKConsumer",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [.executable(name: "QPeriaptLinkProbe", targets: ["QPeriaptLinkProbe"])],
    dependencies: [.package(path: "../QPeriapt")],
    targets: [
        .executableTarget(name: "QPeriaptLinkProbe", dependencies: [
            .product(name: "QPeriaptSDK", package: "QPeriapt"),
            .product(name: "QPeriaptHybrid", package: "QPeriapt")]),
        .testTarget(name: "QPeriaptSDKBinaryConsumerTests", dependencies: [
            .product(name: "QPeriaptSDK", package: "QPeriapt"),
            .product(name: "QPeriaptHybrid", package: "QPeriapt")], resources: [.copy("Resources")])
    ]
)
'''


def copy_regular(source: Path, destination: Path) -> None:
    snapshot = read_regular_snapshot(source, maximum=2 * 1024 * 1024, label="Swift SDK source/fixture")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as out:
        out.write(snapshot.data)
    destination.chmod(0o644)


def verify_apple_exports(library: Path, llvm_nm: Path) -> dict:
    """Check each architecture, retaining the existing strict thin-ar parser."""
    contract = load_contract(ROOT / CONTRACT)
    snapshot = read_regular_snapshot(library, maximum=LIMITS.maximum_member_bytes, label="Apple SDK static archive")
    with tempfile.TemporaryDirectory(prefix="qperiapt-sdk-symbols-") as temporary:
        folder = Path(temporary)
        frozen = folder / "libq_periapt_ffi_abi2.a"
        frozen.write_bytes(snapshot.data)

        def lipo(arguments: list[str]) -> bytes:
            result = capture_output(["/usr/bin/xcrun", "lipo", *arguments], timeout_seconds=60,
                                    maximum_stdout_bytes=65536, maximum_stderr_bytes=65536)
            if result.returncode or result.stderr:
                raise ValueError("cannot inspect/extract the Apple SDK archive architectures")
            return result.stdout

        architectures = lipo(["-archs", str(frozen)]).decode("ascii").split()
        if not architectures or len(architectures) != len(set(architectures)) or not set(architectures) <= {"arm64", "x86_64"}:
            raise ValueError("Apple SDK archive has unsupported/duplicate architectures")
        for architecture in architectures:
            if len(architectures) == 1:
                thin = frozen
            else:
                (folder / architecture).mkdir()
                thin = folder / architecture / frozen.name
                lipo([str(frozen), "-thin", architecture, "-output", str(thin)])
            verify_static_library(contract, thin, "macos", llvm_nm)
    return {"abi_major": 2, "architectures": sorted(architectures), "exports_per_architecture": 51,
            "static_archive_sha256": snapshot.sha256, "status": "pass"}


def verify_link_map(path: Path, library: Path, probe: Path, architecture: str) -> dict:
    """Bind the final linker input to the slice selected and compared by the gate."""
    snapshot = read_regular_snapshot(path, maximum=16 * 1024 * 1024, label="SDK consumer link map")
    # Later literal-symbol names may contain raw non-UTF-8 bytes. The object
    # inventory itself is text; do not silently replace invalid path bytes.
    object_section, separator, _ = snapshot.data.partition(b"\n# Sections:\n")
    if not separator:
        raise ValueError("SDK link map lacks its object-list terminator")
    lines = object_section.decode("utf-8").splitlines()
    if architecture not in {"arm64", "x86_64"} or lines[:3] != [
            f"# Path: {probe}", f"# Arch: {architecture}", "# Object files:"]:
        raise ValueError("SDK link map has the wrong executable/architecture")
    objects = lines[3:]
    prefix = str(library) + "("
    ids, linked = set(), 0
    for line in objects:
        row = re.fullmatch(r"\[\s*([0-9]+)\] (.+)", line)
        if row is None or len(row[1]) > 8 or int(row[1]) in ids:
            raise ValueError("SDK link map has malformed/duplicate object rows")
        ids.add(int(row[1]))
        if "libq_periapt_ffi_abi2.a" in row[2]:
            if not row[2].startswith(prefix) or not row[2].endswith(")") or len(row[2]) <= len(prefix) + 1:
                raise ValueError("SDK link map selects a different Q-Periapt archive")
            linked += 1
    if not linked:
        raise ValueError("SDK link map contains no objects from the selected archive")
    return {"status": "pass", "architecture": architecture, "linked_archive_objects": linked,
            "link_map_sha256": snapshot.sha256}


def select_consumer_scheme(path: Path) -> str:
    document = load_json_object_snapshot(path, maximum=1024 * 1024, label="SDK consumer Xcode schemes").value
    workspace = document.get("workspace")
    if not isinstance(workspace, dict) or workspace.get("name") != "QPeriaptSDKConsumer":
        raise ValueError("Xcode scheme inventory is not the SDK consumer workspace")
    schemes = workspace.get("schemes")
    if (not isinstance(schemes, list) or not schemes or
            any(not isinstance(name, str) or not name for name in schemes) or len(set(schemes)) != len(schemes)):
        raise ValueError("SDK consumer scheme inventory is malformed")
    # Xcode 27 exposes the package scheme; earlier Xcode versions expose the
    # executable scheme. Both must still produce the exact final link probe.
    for name in ("QPeriaptLinkProbe", "QPeriaptSDKConsumer"):
        if name in schemes:
            return name
    raise ValueError("SDK consumer has no supported link-probe scheme")


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def source_identity() -> dict:
    """Bind dirty diagnostic builds to bytes, including newly added inputs."""
    paths = {ROOT / name for name in SHIPPED_SOURCES.values()}
    paths.update(ROOT / "bindings" / name for name in POLICIES)
    paths.update((ROOT / FIXTURE).rglob("*.swift"))
    paths.update((ROOT / "artifact").glob("*.py"))
    paths.update((ROOT / "artifact").glob("*.sh"))
    paths.add(ROOT / CONTRACT)
    paths.add(ROOT / "artifact/fixtures/sdk-native-020-tls-inventory.json")
    paths.add(ROOT / "bindings/swift/Sources/CQPeriapt/q_periapt.h")
    return {"rust_workspace_build_inputs": rust_workspace_source_digest(ROOT),
            "files": {p.relative_to(ROOT).as_posix(): read_regular_snapshot(
                p, maximum=2 * 1024 * 1024, label="Apple SDK build input").sha256 for p in sorted(paths)}}


def check_source_snapshot(path: Path) -> dict:
    previous = load_json_object_snapshot(path, maximum=2 * 1024 * 1024, label="SDK source snapshot").value
    if previous != source_identity():
        raise ValueError("Apple SDK source inputs changed during construction; retain this attempt and rebuild")
    return previous


def prepare_consumer(consumer: Path) -> None:
    consumer.mkdir(mode=0o700)
    (consumer / "Package.swift").write_text(CONSUMER_PACKAGE)
    for relative in ("Sources/QPeriaptLinkProbe/main.swift", "Tests/QPeriaptSDKBinaryConsumerTests/SDKTests.swift"):
        copy_regular(ROOT / FIXTURE / relative, consumer / relative)
    resources = consumer / "Tests/QPeriaptSDKBinaryConsumerTests/Resources"
    for name in POLICIES:
        copy_regular(ROOT / "bindings" / name, resources / name)


def prepare(xcframework_zip: Path, parent: Path, host_target: str) -> dict:
    """Create the self-contained Swift package and its public-API consumer."""
    parent = parent.resolve(strict=True)
    if host_target not in HOST_TARGETS:
        raise ValueError("SDK BOM tool requires an explicit Apple host target")
    # Xcode 26 names the workspace after this directory; Xcode 27 uses the
    # package name. Keep both identities equal to the checked consumer name.
    package, consumer = parent / "QPeriapt", parent / "QPeriaptSDKConsumer"
    if package.exists() or consumer.exists():
        raise ValueError("SDK package/consumer destination already exists")
    source = ROOT / "bindings/swift/Sources/QPeriaptSDK"
    if {p.name for p in source.iterdir()} != set(SDK_FILES):
        raise ValueError("SDK Swift source inventory differs; review packaging before proceeding")
    contract = load_contract(ROOT / CONTRACT)
    if contract.document["package"]["semver"] != VERSION or len(contract.export_names) != 51:
        raise ValueError("alpha SDK ABI contract differs")
    snapshot = read_regular_snapshot(xcframework_zip, maximum=MAX_ARTIFACT_BYTES, label="SDK XCFramework ZIP")
    _validate_xcframework_zip_bytes(snapshot.data, require_signature=False, profile=PROFILE)
    package.mkdir(mode=0o700)
    binaries = package / "Binaries"
    binaries.mkdir()
    # The validated snapshot has a closed regular-file inventory and safe paths.
    with zipfile.ZipFile(io.BytesIO(snapshot.data)) as archive:
        archive.extractall(binaries)
    for slice_name in SLICES:
        verify_header(contract, binaries / "CQPeriapt.xcframework" / slice_name / "Headers/q_periapt.h")
    (package / "Package.swift").write_text(PACKAGE)
    for destination, relative in SHIPPED_SOURCES.items():
        copy_regular(ROOT / relative, package / destination)
    boms = package / "share/q-periapt/bom"
    boms.mkdir(parents=True)
    for name, arguments in (("cbom", ["cbom", "--native-sdk"]), ("sbom", ["sbom", "--lock", str(ROOT / "Cargo.lock")])):
        command = ["cargo", "run", "--locked", "--release", "--quiet", "--target", host_target, "--manifest-path",
                   str(ROOT / "Cargo.toml"), "-p", "q-periapt-cli", "--features", "sdk-cbom", "--", *arguments]
        with (boms / f"{name}.cdx.json").open("xb") as output, (parent / f"{name}-build.log").open("xb") as log:
            result = capture_stdout(command, timeout_seconds=900, maximum_bytes=16 * 1024 * 1024,
                                    stderr=log.fileno(), output_sink=output.write)
        if result.returncode:
            raise ValueError(f"SDK {name} generation failed; retained {name}-build.log")
    verify_boms(package, cargo_lock=ROOT / "Cargo.lock", profile=BomProfile.NATIVE_SDK_020)
    for target in TARGETS:
        target_notices = package / "Notices" / target
        target_notices.mkdir(parents=True)
        collect_licenses(ROOT, target_notices, target)
        verify_licenses(target_notices, expected_target=target)
    prepare_consumer(consumer)
    for folder in (package, consumer):
        for path in folder.rglob("*.swift"):
            text = path.read_text()
            if "unsafeFlags" in text or "target/release" in text or str(ROOT) in text:
                raise ValueError(f"source-tree dependency leaked into SDK package: {path.name}")
    return {"profile": PROFILE, "version": VERSION, "abi_major": 2,
            "xcframework_zip_sha256": snapshot.sha256,
            "products": ["QPeriaptSDK", "QPeriaptHybrid"], "license_targets": list(TARGETS),
            "package_sources_sha256": {str(p.relative_to(package)): hashlib.sha256(p.read_bytes()).hexdigest()
                                       for p in sorted(package.rglob("*")) if p.is_file() and "Binaries" not in p.relative_to(package).parts}}


def inventory(package: Path) -> dict[str, str]:
    if package.is_symlink() or not package.is_dir():
        raise ValueError("Swift SDK package must be a regular directory")
    result = {}
    for path in sorted(package.rglob("*")):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise ValueError(f"non-regular Swift SDK package entry: {path.name}")
        relative = path.relative_to(package).as_posix()
        if relative != CONTENTS:
            result[relative] = read_regular_snapshot(path, maximum=LIMITS.maximum_member_bytes,
                                                     label="Swift SDK package entry").sha256
    return result


def verified_xcframework_files(path: Path, expected_sha256: str) -> dict[str, str]:
    """Freeze the already checked native artifact as the package's byte origin."""
    if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise ValueError("expected XCFramework digest must be canonical SHA-256")
    snapshot = read_regular_snapshot(path, maximum=MAX_ARTIFACT_BYTES, label="verified SDK XCFramework ZIP")
    if snapshot.sha256 != expected_sha256:
        raise ValueError("SDK XCFramework ZIP changed after native verification")
    _validate_xcframework_zip_bytes(snapshot.data, require_signature=False, profile=PROFILE)
    with zipfile.ZipFile(io.BytesIO(snapshot.data)) as archive:
        return {"Binaries/" + entry.filename: hashlib.sha256(archive.read(entry)).hexdigest()
                for entry in archive.infolist() if not entry.is_dir()}


def verify_package(package: Path, expected_source: dict, *, cargo_lock: Path | None,
                   expected_native_files: dict[str, str]) -> dict:
    manifest = load_json_object_snapshot(package / CONTENTS, maximum=2 * 1024 * 1024,
                                         label="Swift SDK contents").value
    actual = inventory(package)
    expected = {"schema_version": 1, "kind": "qperiapt.swift_sdk_contents", "profile": PROFILE,
                "version": VERSION, "abi_major": 2, "source_inputs": expected_source, "files": actual}
    if canonical_json(manifest) != canonical_json(expected):
        raise ValueError("Swift SDK contents/source manifest differs from the actual package")
    native_files = {name: digest for name, digest in actual.items() if name.startswith("Binaries/")}
    if not expected_native_files or native_files != expected_native_files:
        raise ValueError("Swift SDK native payload differs from the verified XCFramework ZIP")
    required = {*SHIPPED_SOURCES, "Package.swift", "share/q-periapt/bom/cbom.cdx.json",
                "share/q-periapt/bom/sbom.cdx.json", "Binaries/CQPeriapt.xcframework/Info.plist"}
    for slice_name in SLICES:
        for leaf in ("libq_periapt_ffi_abi2.a", "Headers/q_periapt.h", "Headers/module.modulemap"):
            required.add(f"Binaries/CQPeriapt.xcframework/{slice_name}/{leaf}")
    for target in TARGETS:
        prefix = f"Notices/{target}"
        notices = verify_licenses(package / prefix, expected_target=target)
        required.add(f"{prefix}/THIRD_PARTY/rust/INVENTORY.json")
        for dependency in notices["packages"]:
            required.update(f"{prefix}/{item['path']}" for item in dependency["license_files"])
    if actual.keys() != required:
        raise ValueError("Swift SDK package file inventory differs from the closed profile")
    if (package / "Package.swift").read_bytes() != PACKAGE.encode():
        raise ValueError("Swift SDK package manifest differs from the source-independent products")
    for shipped, source in SHIPPED_SOURCES.items():
        if actual[shipped] != expected_source["files"][source]:
            raise ValueError(f"Swift SDK shipped source differs: {shipped}")
    contract = load_contract(ROOT / CONTRACT)
    for slice_name in SLICES:
        verify_header(contract, package / "Binaries/CQPeriapt.xcframework" / slice_name / "Headers/q_periapt.h")
    verify_boms(package, cargo_lock=cargo_lock, profile=BomProfile.NATIVE_SDK_020)
    return manifest


def installed_consumer(archive: Path, archive_sha: str, expected_source: dict,
                       expected_native_files: dict[str, str], evidence: Path) -> dict:
    """Execute only an extracted package from a fresh directory outside the checkout."""
    evidence.mkdir(mode=0o700)
    temporary = Path(tempfile.mkdtemp(prefix="qperiapt-sdk-install-")).resolve()
    if temporary.is_relative_to(ROOT):
        raise ValueError("Swift SDK install probe must be outside the source checkout")
    # Retain failed attempts and log this private diagnostic path outside the
    # public manifest. The generated Swift consumer contains no project paths.
    (evidence / "install-location.txt").write_text(str(temporary) + "\n")
    extract_zip(archive, temporary / "install", root_name="QPeriapt", mtime=MTIME,
                expected_sha256=archive_sha, limits=LIMITS)
    package = temporary / "install/QPeriapt"
    verify_package(package, expected_source, cargo_lock=ROOT / "Cargo.lock", expected_native_files=expected_native_files)
    consumer = temporary / "install/consumer"
    prepare_consumer(consumer)
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("DYLD_", "LD_", "CARGO_", "RUST", "SWIFT_"))}
    records = {}

    def run(label: str, arguments: list[str]) -> bytes:
        path = evidence / f"{label}.log"
        with path.open("xb") as log:
            # A combined bounded stream preserves diagnostics even on timeout.
            result = capture_stdout(arguments, timeout_seconds=900, maximum_bytes=32 * 1024 * 1024,
                                    stderr=subprocess.STDOUT, environment=environment, output_sink=log.write)
        records[path.name] = hashlib.sha256(result.stdout).hexdigest()
        text = result.stdout.decode(errors="replace")
        if result.returncode or re.search(r"(?im)(?:^|[^a-z])(warning|error):", text):
            raise ValueError(f"installed Swift SDK {label} failed or emitted diagnostics; retained {evidence}")
        if str(ROOT) in text:
            raise ValueError("installed Swift SDK build refers to the source checkout")
        return result.stdout

    arguments = ["--package-path", str(consumer), "--scratch-path", str(temporary / "build")]
    tests = run("swift-test", ["swift", "test", *arguments, "-Xswiftc", "-strict-concurrency=complete",
                                "-Xswiftc", "-warnings-as-errors"])
    if b"Executed 6 tests, with 0 failures" not in tests:
        raise ValueError("installed Swift SDK test count differs")
    output = Path(run("swift-bin", ["swift", "build", *arguments, "--show-bin-path"]).decode().strip())
    if not output.resolve(strict=True).is_relative_to(temporary):
        raise ValueError("installed Swift SDK product escaped the owned build directory")
    probe = output / "QPeriaptLinkProbe"
    run("link-probe", [str(probe), "--invalid-policy-rejection"])
    selected = read_regular_snapshot(output / "libq_periapt_ffi_abi2.a", maximum=LIMITS.maximum_member_bytes,
                                    label="SwiftPM selected SDK archive")
    expected_library = package / "Binaries/CQPeriapt.xcframework/macos-arm64/libq_periapt_ffi_abi2.a"
    if selected.sha256 != read_regular_snapshot(expected_library, maximum=LIMITS.maximum_member_bytes,
                                               label="installed SDK archive").sha256:
        raise ValueError("installed SwiftPM selection differs from the exact packaged macOS slice")
    verify_package(package, expected_source, cargo_lock=ROOT / "Cargo.lock", expected_native_files=expected_native_files)
    return {"kind": "qperiapt.swift_sdk_installed_consumer", "outside_source_checkout": True,
            "archive_sha256": archive_sha, "executed_tests": 6, "failures": 0,
            "warning_or_error_diagnostics": 0, "log_sha256": records,
            "selected_static_archive_sha256": selected.sha256,
            "probe_sha256": read_regular_snapshot(probe, maximum=64 * 1024 * 1024, label="installed SDK probe").sha256}


def finish(parent: Path, dist: Path, source_snapshot: Path, xcframework_zip: Path,
           xcframework_sha256: str) -> dict:
    identity = check_source_snapshot(source_snapshot)
    native_files = verified_xcframework_files(xcframework_zip, xcframework_sha256)
    package = parent / "QPeriapt"
    manifest = {"schema_version": 1, "kind": "qperiapt.swift_sdk_contents", "profile": PROFILE,
                "version": VERSION, "abi_major": 2, "source_inputs": identity, "files": inventory(package)}
    with (package / CONTENTS).open("xb") as out:
        out.write(canonical_json(manifest))
    verify_package(package, identity, cargo_lock=ROOT / "Cargo.lock", expected_native_files=native_files)
    archive = dist / ARCHIVE_NAME
    if archive.exists():
        raise ValueError("SDK product archive already exists")
    audit = create_zip(package, archive, root_name="QPeriapt", mtime=MTIME, limits=LIMITS)
    installation = installed_consumer(archive, audit.archive_sha256, identity, native_files,
                                      parent / "installed-consumer-evidence")
    check_source_snapshot(source_snapshot)
    for path, expected_digest in ((archive, audit.archive_sha256), (xcframework_zip, xcframework_sha256)):
        if read_regular_snapshot(path, maximum=MAX_ARTIFACT_BYTES, label="verified SDK artifact").sha256 != expected_digest:
            raise ValueError("SDK artifact changed during installation verification")
    return {"path": ARCHIVE_NAME, "sha256": audit.archive_sha256, "bytes": audit.archive_bytes,
            "xcframework_zip_sha256": xcframework_sha256,
            "contents_manifest_sha256": hashlib.sha256(canonical_json(manifest)).hexdigest(),
            "installed_consumer": installation}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("snapshot")
    check = sub.add_parser("check-source")
    check.add_argument("--snapshot", type=Path, required=True)
    exports = sub.add_parser("check-exports")
    exports.add_argument("--library", type=Path, required=True)
    exports.add_argument("--llvm-nm", type=Path, required=True)
    link_map = sub.add_parser("check-link-map")
    link_map.add_argument("--map", type=Path, required=True)
    link_map.add_argument("--library", type=Path, required=True)
    link_map.add_argument("--probe", type=Path, required=True)
    link_map.add_argument("--architecture", choices=("arm64", "x86_64"), required=True)
    schemes = sub.add_parser("consumer-scheme")
    schemes.add_argument("--inventory", type=Path, required=True)
    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("--xcframework-zip", type=Path, required=True)
    prepare_parser.add_argument("--parent", type=Path, required=True)
    prepare_parser.add_argument("--host-target", choices=HOST_TARGETS, required=True)
    complete = sub.add_parser("finish")
    complete.add_argument("--parent", type=Path, required=True)
    complete.add_argument("--dist", type=Path, required=True)
    complete.add_argument("--source-snapshot", type=Path, required=True)
    complete.add_argument("--xcframework-zip", type=Path, required=True)
    complete.add_argument("--xcframework-sha256", required=True)
    args = parser.parse_args()
    if args.command == "snapshot":
        result = source_identity()
    elif args.command == "check-source":
        result = check_source_snapshot(args.snapshot)
    elif args.command == "prepare":
        result = prepare(args.xcframework_zip, args.parent, args.host_target)
    elif args.command == "check-exports":
        result = verify_apple_exports(args.library, args.llvm_nm)
    elif args.command == "check-link-map":
        result = verify_link_map(args.map, args.library, args.probe, args.architecture)
    elif args.command == "consumer-scheme":
        print(select_consumer_scheme(args.inventory))
        return
    else:
        result = finish(args.parent, args.dist, args.source_snapshot, args.xcframework_zip, args.xcframework_sha256)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
