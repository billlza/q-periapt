"""Repackage the published 0.2.0 Continuity Apple slices for static SwiftPM composition."""
import argparse
import json
import os
from pathlib import Path
import plistlib
import tempfile

import continuity_apple_package as apple
import continuity_c_consumer as owner
import continuity_package as package
import rust_sdk_profile as sdk
from deterministic_archive import create_zip, extract_zip
from evidence_io import parse_strict_json_bytes


BASE_SHA256 = "1766fa787498ae074fb9eec6cefc5e246805ea8f6dd4766445f49132cad1c8f1"
RECEIPT = "APPLE_PACKAGING_REVISION.json"


def build(base_archive: Path, output: Path) -> None:
    output = output.absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    with tempfile.TemporaryDirectory(prefix="qperiapt-apple-r1-", dir=output.parent) as name:
        work = Path(name).resolve()
        logs = work / "logs"
        logs.mkdir()
        env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "ZERO_AR_DATE": "1"}
        if "DEVELOPER_DIR" in os.environ:
            env["DEVELOPER_DIR"] = os.environ["DEVELOPER_DIR"]

        def run(args: list[str], label: str, cwd: Path = work) -> bytes:
            return sdk.command(args, logs / label, cwd, environment=env)

        extract_zip(base_archive, work / "original", root_name=apple.NAME, mtime=apple.MTIME,
                    expected_sha256=BASE_SHA256, limits=apple.LIMITS)
        original = work / "original" / apple.NAME
        recorded = parse_strict_json_bytes(sdk.snapshot(original / apple.CONTENTS).data, label="base Apple inventory")
        original_files = apple.file_hashes(original)
        del original_files[apple.CONTENTS]
        sdk.require(recorded["files"] == original_files, "base Apple package inventory differs")
        staging = work / apple.NAME
        for filename in original_files:
            if not filename.startswith("CQPCOwner.xcframework/") and filename != "README.md":
                apple.copy(original / filename, staging / filename)
        apple.copy(package.ROOT / "bindings/swift/ContinuityPackageConsumer/ApplePackageREADME.md", staging / "README.md")

        xc = original / "CQPCOwner.xcframework"
        info = plistlib.loads(sdk.snapshot(xc / "Info.plist").data)
        rows = {(row["SupportedPlatform"], row.get("SupportedPlatformVariant")): row for row in info["AvailableLibraries"]}
        header = sdk.snapshot(owner.FIXTURE / "qpc_owner.h").data
        inputs = {}
        receipt = {"schema_version": 1, "kind": "qperiapt.continuity_apple_packaging_revision",
                   "version": apple.VERSION, "packaging_revision": apple.PACKAGING_REVISION, "abi": "qpc-owner/1",
                   "base_release": "abi2-platforms-v0.2.0", "base_archive_sha256": BASE_SHA256,
                   "xcode": run(["/usr/bin/xcodebuild", "-version"], "xcode").decode().strip(),
                   "native": {}, "slices": {}}
        for target, platform in apple.TARGETS.items():
            row = rows[platform]
            folder = xc / apple.relative_path(row["LibraryIdentifier"])
            sdk.require(sdk.snapshot(folder / "Headers/qpc_owner.h").data == header, "base Apple owner header differs")
            library = folder / apple.LIBRARY
            arch = apple.ARCHITECTURES[target]
            if len(row["SupportedArchitectures"]) > 1:
                thin = work / "inputs" / target / apple.LIBRARY
                thin.parent.mkdir(parents=True)
                run(["/usr/bin/xcrun", "lipo", str(library), "-thin", arch, "-output", str(thin)], "thin-" + target)
                library = thin
            apple.verify_architectures(run(["/usr/bin/xcrun", "lipo", "-archs", str(library)], "arch-" + target), (arch,))
            snapshot = sdk.snapshot(library, maximum=apple.LIMITS.maximum_member_bytes)
            receipt["native"][target] = {"sha256": snapshot.sha256, "bytes": snapshot.size,
                                         "owner_exports": len(owner.EXPORTS)}
            inputs[target] = library
        apple.assemble_xcframework(inputs, work, staging, header, receipt, run)
        contents = apple.write_contents(staging)
        apple.verify_package(staging, contents, receipt["slices"], header)
        archive = work / apple.ARCHIVE
        audit = create_zip(staging, archive, root_name=apple.NAME, mtime=apple.MTIME, limits=apple.LIMITS)
        extract_zip(archive, work / "readback", root_name=apple.NAME, mtime=apple.MTIME,
                    expected_sha256=audit.archive_sha256, limits=apple.LIMITS)
        apple.verify_package(work / "readback" / apple.NAME, contents, receipt["slices"], header)
        receipt["archive"] = {"name": apple.ARCHIVE, "bytes": audit.archive_bytes, "sha256": audit.archive_sha256}
        (work / RECEIPT).write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        # Claim a new destination only after the complete archive has passed readback.
        output.mkdir()
        linked = []
        try:
            for source in (archive, work / RECEIPT):
                destination = output / source.name
                os.link(source, destination)
                linked.append(destination)
        except OSError:
            for destination in linked:
                destination.unlink()
            output.rmdir()
            raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-archive", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="new output directory")
    args = parser.parse_args()
    build(args.base_archive, args.output)
