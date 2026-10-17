"""Build the installed Continuity Apple binary package from the admitted C source.

This adds packaging and consumer admission to the existing native qualification;
it does not freeze qpc-owner/1, publish a release, or infer device execution.
"""
from pathlib import Path, PurePosixPath
import json
import os
import plistlib
import re

import continuity_c_consumer as c
import continuity_package as package
import rust_sdk_profile as sdk
import third_party_licenses as licenses
from deterministic_archive import ArchiveLimits, create_zip, extract_zip
from evidence_io import parse_strict_json_bytes

TARGETS = {
    "aarch64-apple-darwin": ("macos", None),
    "aarch64-apple-ios": ("ios", None),
    "aarch64-apple-ios-sim": ("ios", "simulator"),
}
NAME = "QPeriaptContinuity"
ARCHIVE = "QPeriaptContinuity-Apple-candidate.zip"
LIBRARY = "libq_periapt_continuity_c_consumer.a"
CONTENTS = "PACKAGE_CONTENTS.json"
MTIME = 1767225600
LIMITS = ArchiveLimits(maximum_archive_bytes=256 * 1024**2,
                       maximum_member_bytes=128 * 1024**2, maximum_total_bytes=256 * 1024**2)
MODULE = b'module CQPCOwner [system] {\n    header "qpc_owner.h"\n    export *\n}\n'
MANIFEST = b'''// swift-tools-version:6.0
// SPDX-License-Identifier: Apache-2.0 OR MIT
import PackageDescription
let package = Package(
    name: "QPeriaptContinuity",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [.library(name: "QPeriaptContinuity", targets: ["QPeriaptContinuity"])],
    targets: [
        .binaryTarget(name: "CQPCOwner", path: "CQPCOwner.xcframework"),
        .target(name: "QPeriaptContinuity", dependencies: ["CQPCOwner"],
                linkerSettings: [.linkedFramework("Security")]),
    ]
)
'''


def file_hashes(root: Path) -> dict[str, str]:
    result = {}
    for path in sorted(root.rglob("*")):
        sdk.require(not path.is_symlink(), "Apple package/source contains a symlink")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = sdk.snapshot(path, maximum=LIMITS.maximum_member_bytes).sha256
        else:
            sdk.require(path.is_dir(), "Apple package/source contains a special file")
    return result


def write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)
    path.chmod(0o644)


def copy(source: Path, destination: Path) -> None:
    write(destination, sdk.snapshot(source, maximum=LIMITS.maximum_member_bytes).data)


def built_static(data: bytes, consumer: Path, build: Path, target: str) -> Path:
    sdk.require(target in TARGETS, "unsupported Apple target")
    artifacts = []
    for line in data.splitlines():
        row = parse_strict_json_bytes(line, label="Apple Cargo artifact")
        if row.get("reason") == "compiler-artifact" and row.get("target", {}).get("name") == c.LIBRARY:
            sdk.require(row.get("manifest_path") == str(consumer / "Cargo.toml")
                        and row["target"].get("crate_types") == ["staticlib"]
                        and row.get("profile", {}).get("opt_level") == "3"
                        and row["profile"].get("test") is False,
                        "Apple static artifact provenance or profile differs")
            artifacts.extend(row.get("filenames", []))
    expected = build / target / "release" / LIBRARY
    sdk.require(artifacts == [str(expected)], "Apple static artifact is missing, ambiguous or outside its target")
    return expected


def verify_exports(data: bytes) -> None:
    exports = re.findall(rb"\b_(qpc_[A-Za-z0-9_]+)$", data, re.MULTILINE)
    names = [name.decode("ascii") for name in exports]
    sdk.require(len(names) == len(set(names)) and set(names) == c.EXPORTS,
                "Apple native owner exports differ or are duplicated")


def relative_path(value: object) -> str:
    sdk.require(isinstance(value, str) and bool(value), "missing XCFramework member path")
    path = PurePosixPath(value)
    sdk.require(not path.is_absolute() and ".." not in path.parts and str(path) == value
                and "\\" not in value, "invalid XCFramework member path")
    return value


def canonical_xcframework_info(data: bytes) -> bytes:
    info = plistlib.loads(data)
    rows = info.get("AvailableLibraries")
    sdk.require(isinstance(rows, list) and len(rows) == len(TARGETS)
                and all(isinstance(row, dict) for row in rows), "XCFramework slice inventory differs")
    identifiers = [relative_path(row.get("LibraryIdentifier")) for row in rows]
    sdk.require(len(set(identifiers)) == len(identifiers), "XCFramework slice identifiers are duplicated")
    # Xcode emits this semantically unordered inventory in varying order. Sort
    # metadata only; every native archive/header is still verified byte-for-byte.
    info["AvailableLibraries"] = sorted(rows, key=lambda row: row["LibraryIdentifier"])
    return plistlib.dumps(info, fmt=plistlib.FMT_XML, sort_keys=True)


def verify_xcframework(root: Path, binaries: dict, header: bytes) -> None:
    info = plistlib.loads(sdk.snapshot(root / "Info.plist").data)
    rows = info.get("AvailableLibraries")
    sdk.require(isinstance(rows, list) and len(rows) == len(TARGETS), "XCFramework slice count differs")
    observed = set()
    for row in rows:
        sdk.require(isinstance(row, dict) and row.get("SupportedArchitectures") == ["arm64"],
                    "XCFramework contains an unsupported architecture")
        platform = (row.get("SupportedPlatform"), row.get("SupportedPlatformVariant"))
        sdk.require(platform in TARGETS.values() and platform not in observed, "XCFramework platform missing or duplicated")
        observed.add(platform)
        target = next(name for name, expected in TARGETS.items() if expected == platform)
        folder = root / relative_path(row.get("LibraryIdentifier"))
        actual = sdk.snapshot(folder / relative_path(row.get("LibraryPath")), maximum=LIMITS.maximum_member_bytes)
        sdk.require(actual.sha256 == binaries[target]["sha256"], "XCFramework selected the wrong native target")
        headers = folder / relative_path(row.get("HeadersPath"))
        sdk.require(sdk.snapshot(headers / "qpc_owner.h").data == header
                    and sdk.snapshot(headers / "module.modulemap").data == MODULE,
                    "XCFramework C interface differs")
    sdk.require(observed == set(TARGETS.values()), "XCFramework platform set differs")


def verify_package(root: Path, expected: dict, binaries: dict, header: bytes) -> None:
    contents = parse_strict_json_bytes(sdk.snapshot(root / CONTENTS).data, label="Apple package contents")
    sdk.require(contents == expected, "Apple package manifest changed")
    files = file_hashes(root)
    files.pop(CONTENTS)
    sdk.require(files == expected["files"], "Apple package members or bytes changed")
    sdk.require(sdk.snapshot(root / "Package.swift").data == MANIFEST, "Apple package target definition differs")
    verify_xcframework(root / "CQPCOwner.xcframework", binaries, header)
    for target in TARGETS:
        licenses.verify(root / "LICENSES" / target, expected_target=target, root_package=c.NAME)


def qualify_apple(outside: Path, output: Path, environment: dict) -> dict:
    sdk.require((os.uname().sysname, os.uname().machine) == ("Darwin", "arm64"),
                "Continuity Apple packaging requires macOS arm64")
    sdk.require(not outside.resolve().is_relative_to(package.ROOT), "Apple consumer must be outside checkout")
    consumer = outside / "c-consumer"
    before = file_hashes(consumer)
    sdk.require("Cargo.lock" in before and "qpc_owner.h" in before, "admitted C package source is incomplete")
    work = outside / "apple-package"
    work.mkdir(mode=0o700)
    staging = work / NAME
    staging.mkdir(mode=0o700)
    evidence = output / "apple-package"
    evidence.mkdir(mode=0o700)
    result = {"schema_version": 1, "kind": "qperiapt.continuity_apple_package", "completed": False,
              "targets": list(TARGETS), "release_claim_eligible": False, "publication_performed": False,
              "physical_device_execution": False, "simulator_execution": False,
              "source_files": before, "native": {}, "scope": "installed Apple binary package, macOS public owner probe and iOS device/simulator consumer builds"}
    env = {key: value for key, value in environment.items()
           if key not in {"CC", "CXX", "AR", "LD", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "SDKROOT",
                          "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH", "LIBRARY_PATH"}
           and not key.startswith(("CC_", "CXX_", "AR_", "CFLAGS_", "CXXFLAGS_"))}
    build = work / "native-build"
    env.update(CARGO_TARGET_DIR=str(build), IPHONEOS_DEPLOYMENT_TARGET="16.0", MACOSX_DEPLOYMENT_TARGET="13.0")
    tool = Path(env["RUSTC"]).parent
    nm = tool.parent / "lib/rustlib/aarch64-apple-darwin/bin/llvm-nm"

    def run(argv: list[str], name: str, cwd: Path = consumer) -> bytes:
        return sdk.command(argv, evidence / name, cwd, environment=env)

    try:
        result["rustc"] = run([str(tool / "rustc"), "--version", "--verbose"], "rustc").decode()
        sdk.require(result["rustc"].splitlines()[0] == "rustc 1.98.1 (48a229cea 2026-09-01)", "Apple compiler differs")
        result["llvm_nm_sha256"] = sdk.snapshot(nm, maximum=c.MAX_BINARY).sha256
        result["xcode"] = run(["/usr/bin/xcodebuild", "-version"], "xcode-version").decode()
        header = sdk.snapshot(consumer / "qpc_owner.h").data
        sdk.require(header == sdk.snapshot(c.FIXTURE / "qpc_owner.h").data, "admitted C header differs from current source")
        headers = work / "headers"
        write(headers / "qpc_owner.h", header); write(headers / "module.modulemap", MODULE)
        arguments = ["/usr/bin/xcodebuild", "-create-xcframework"]
        for target in TARGETS:
            compiled = run([str(tool / "cargo"), "rustc", "--locked", "--offline", "--lib", "--release",
                            "--crate-type", "staticlib", "--target", target, "--message-format=json", "-j", "2"], "build-" + target)
            library = built_static(compiled, consumer, build, target)
            snapshot = sdk.snapshot(library, maximum=LIMITS.maximum_member_bytes)
            sdk.require(run(["/usr/bin/xcrun", "lipo", "-archs", str(library)], "arch-" + target).strip() == b"arm64",
                        "Apple library is not arm64 only")
            verify_exports(run([str(nm), "--defined-only", "--extern-only", str(library)], "exports-" + target))
            result["native"][target] = {"sha256": snapshot.sha256, "bytes": snapshot.size, "owner_exports": len(c.EXPORTS)}
            arguments += ["-library", str(library), "-headers", str(headers)]
            metadata = parse_strict_json_bytes(run([str(tool / "cargo"), "metadata", "--locked", "--offline",
                "--format-version", "1", "--filter-platform", target], "licenses-" + target), label="Apple runtime dependencies")
            notice_root = staging / "LICENSES" / target
            notice_root.mkdir(parents=True)
            licenses.collect(consumer, notice_root, target, root_package=c.NAME, resolved_metadata=metadata)
        run([*arguments, "-output", str(staging / "CQPCOwner.xcframework")], "xcframework")
        info = staging / "CQPCOwner.xcframework/Info.plist"
        info.write_bytes(canonical_xcframework_info(sdk.snapshot(info).data))
        write(staging / "Package.swift", MANIFEST)
        swift = package.ROOT / "bindings/swift/ContinuityPackageConsumer"
        for path in (swift / "Sources/QPeriaptContinuity").rglob("*"):
            if path.is_file(): copy(path, staging / path.relative_to(swift))
        copy(swift / "ApplePackageREADME.md", staging / "README.md")
        for name in ("LICENSE", "LICENSE-APACHE", "LICENSE-MIT"):
            copy(package.CANDIDATE / name, staging / name)
        for name in ("INVENTORY.sha256", "LICENSE-INVENTORY.md", "LICENSE.mlkem-native", "PROVENANCE.md"):
            copy(package.ROOT / "crates/q-periapt-mlkem-native-sys/vendor" / name,
                 staging / "LICENSES/mlkem-native" / name)
        copy(package.ROOT / "LICENSES/Rust-1.98.1-library.html", staging / "LICENSES/Rust-1.98.1-library.html")
        rust_docs = tool.parent / "share/doc/rust"
        sdk.require(sdk.snapshot(rust_docs / "COPYRIGHT-library.html").data
                    == sdk.snapshot(package.ROOT / "LICENSES/Rust-1.98.1-library.html").data,
                    "Rust standard-library notices differ from the pinned compiler")
        for path in (rust_docs / "licenses").rglob("*"):
            if path.is_file(): copy(path, staging / "LICENSES/rust-standard-library" / path.relative_to(rust_docs / "licenses"))
        contents = {"schema_version": 1, "kind": "qperiapt.continuity_apple_contents",
                    "targets": list(TARGETS), "files": file_hashes(staging)}
        write(staging / CONTENTS, (json.dumps(contents, indent=2, sort_keys=True) + "\n").encode())
        verify_package(staging, contents, result["native"], header)
        archive = output / ARCHIVE
        audit = create_zip(staging, archive, root_name=NAME, mtime=MTIME, limits=LIMITS)
        result["archive"] = {"file": ARCHIVE, "sha256": audit.archive_sha256, "bytes": audit.archive_bytes}
        installed = work / "installed"
        extract_zip(archive, installed, root_name=NAME, mtime=MTIME, expected_sha256=audit.archive_sha256, limits=LIMITS)
        verify_package(installed / NAME, contents, result["native"], header)
        from continuity_apple_consumer import qualify_consumer
        result["consumer"] = qualify_consumer(installed, evidence, env, result["native"])
        verify_package(installed / NAME, contents, result["native"], header)
        sdk.require(file_hashes(consumer) == before, "C package source changed during Apple packaging")
        sdk.require(sdk.snapshot(nm, maximum=c.MAX_BINARY).sha256 == result["llvm_nm_sha256"], "symbol tool changed")
        result.update(completed=True, archive={"file": ARCHIVE, "sha256": audit.archive_sha256,
                      "bytes": audit.archive_bytes}, installed_members_verified=True, sources_unchanged=True)
        return result
    except Exception as error:
        result["failure"] = str(error)
        raise
    finally:
        sdk.write_json(output / "CONTINUITY_APPLE_PACKAGE.json", result)
