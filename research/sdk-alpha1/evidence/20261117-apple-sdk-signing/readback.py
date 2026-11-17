"""Read back the selected signed SDK; run through its clean source's Python launcher."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

import apple_distribution as distribution
import apple_sdk_profile as sdk
from deterministic_archive import extract_zip

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--release-root", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
source = "b327970189259ac3a5dd2353db4a90b178a72431"
pins = {
    "CQPeriapt.xcframework.zip": "a64889174ff3490ad0da72a3cdad8c311a3e7a28b61ca921769861a695bc0f06",
    "QPeriapt-Swift-SDK-0.2.0.zip": "8278a687e0c6253f7254f864748a56d005257ede4a17ab758678a524d8d2bb2a",
    "APPLE_DISTRIBUTION.json": "0da5c27cf09cec2c945258b04fc03c9e126405f1ab961d75f01a7c8b92776683",
    "MANIFEST.json": "24be43ffc3df1ba19d0d568d1385d5d98b90ef17aa6f66dde4cf9ee074b5812a",
    "SHA256SUMS": "bf956a4bb52275bb18fe55ca83bfbdcda956c3f97a7ceb78afb113c8011b0ac8",
}


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    require(path.is_file() and not path.is_symlink(), "readback input is not a regular file")
    return hashlib.sha256(path.read_bytes()).hexdigest()


root = args.release_root.resolve(strict=True)
package_root = root / "q-periapt-swift-0.2.0"
evidence = root / "evidence"
require(subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=sdk.ROOT, text=True).strip() == source,
        "readback must use the independently selected producer source")
require(not subprocess.check_output(["git", "status", "--porcelain=v1"], cwd=sdk.ROOT),
        "producer source is not clean")
for name, expected in pins.items():
    require(digest(package_root / name) == expected, "selected artifact digest differs: " + name)
manifest = json.loads((package_root / "MANIFEST.json").read_bytes())
signed = json.loads((package_root / "APPLE_DISTRIBUTION.json").read_bytes())
require(manifest["git_commit"] == source and manifest["package_profile"] == "sdk-020",
        "SDK manifest source/profile differs")
require(signed["source_commit"] == source and signed["schema_version"] == 4,
        "signature distribution source/schema differs")
require(signed["origin_signature"]["certificate"]["sha256"] ==
        "6c8412fd1c9faeb286eefe4518d20d500ed911cfe5695020f125b73b89a509b3",
        "independently selected certificate differs")
identity = sdk.check_source_snapshot(evidence / "SOURCE_INPUTS.before.json")
require(identity == manifest["source_inputs"]["sdk_build_snapshot"], "manifest source inventory differs")
native = sdk.verified_xcframework_files(package_root / "CQPeriapt.xcframework.zip",
                                      pins["CQPeriapt.xcframework.zip"], require_signature=True)
projected = distribution.build_static_xcframework_distribution_evidence(
    artifact=package_root / "CQPeriapt.xcframework.zip", source_commit=source,
    swiftpm_checksum=pins["CQPeriapt.xcframework.zip"],
    signing_evidence=signed["origin_signature"], profile="sdk-020")
require(projected == signed, "replayed signature distribution differs")
args.output.mkdir(parents=True, mode=0o700, exist_ok=False)
extract_zip(package_root / "QPeriapt-Swift-SDK-0.2.0.zip", args.output / "installed",
            root_name="QPeriapt", mtime=sdk.MTIME,
            expected_sha256=pins["QPeriapt-Swift-SDK-0.2.0.zip"], limits=sdk.LIMITS)
installed = args.output / "installed/QPeriapt"
contents = sdk.verify_package(installed, identity, cargo_lock=sdk.ROOT / "Cargo.lock",
                              expected_native_files=native, require_signature=True)
result = subprocess.run(["/usr/bin/codesign", "--verify", "--strict", "--verbose=4",
                         str(installed / "Binaries/CQPeriapt.xcframework")],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
(args.output / "codesign.stdout").write_bytes(result.stdout)
(args.output / "codesign.stderr").write_bytes(result.stderr)
require(result.returncode == 0, "fresh extracted SDK failed codesign verification")
logs = manifest["consumer_verification"]["installed_swift_sdk"]["log_sha256"]
for name, expected in logs.items():
    require(digest(evidence / "installed-consumer-evidence" / name) == expected,
            "installed consumer log differs: " + name)
require(digest(evidence / "swift-binary-consumer.log") ==
        manifest["consumer_verification"]["macos_runtime_tests"]["log_sha256"], "host consumer log differs")
for name, expected in pins.items():
    require(digest(package_root / name) == expected, "artifact changed during readback: " + name)
report = {
    "schema_version": 1, "kind": "qperiapt.sdk020_apple_signing_readback", "completed": True,
    "source_commit": source,
    "source_tree": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=sdk.ROOT, text=True).strip(),
    "artifact_sha256": pins, "source_file_count": len(identity["files"]),
    "rust_workspace_build_inputs": identity["rust_workspace_build_inputs"],
    "native_file_count": len(native), "package_file_count": len(contents["files"]),
    "certificate_sha256": signed["origin_signature"]["certificate"]["sha256"],
    "signed_at": signed["origin_signature"]["signature"]["secure_timestamp"],
    "codesign_returncode": result.returncode,
    "producer_consumer_verification": manifest["consumer_verification"],
    "readback_scope": "Fresh signed-package extraction, strict signature verification, exact source and file identities, and original consumer log hashes. Consumer tests are the producer's retained executions, not newly rerun here.",
    "release_claim_eligible": False, "publication_performed": False,
}
(args.output / "READBACK.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
print(json.dumps({"completed": True, "source_commit": source,
                  "source_file_count": report["source_file_count"],
                  "native_file_count": report["native_file_count"],
                  "package_file_count": report["package_file_count"]}))
