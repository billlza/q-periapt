#!/usr/bin/env python3
"""Capture and reverify one trusted-local Xcode installation receipt.

The receipt detects accidental toolchain drift.  It deliberately does not hash
the complete Xcode bundle and is not an attestation against a hostile host.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import plistlib
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, NoReturn, Sequence

from bounded_process import BoundedProcessError, capture_stdout
from evidence_io import (
    EvidenceIOError,
    FileDigestSnapshot,
    FileSnapshot,
    consume_regular_snapshot,
    load_json_object_snapshot,
    read_regular_snapshot,
)


SCHEMA_VERSION = 1
RECEIPT_KIND = "qperiapt.apple_toolchain_receipt"
APPLICATIONS_ROOT = pathlib.Path("/Applications")
FIXED_DEVELOPER_DIR = pathlib.Path(
    "/Applications/Xcode-27.0.app/Contents/Developer"
)
REQUIRED_ROOT_UID = 0
EXPECTED_BUNDLE_IDENTIFIER = "com.apple.dt.Xcode"
EXPECTED_TEAM_IDENTIFIER = "59GAB85EFG"
EXPECTED_AUTHORITIES = (
    "Software Signing",
    "Apple Code Signing Certification Authority",
    "Apple Root CA",
)
TRUST_BOUNDARY = {
    "classification": "trusted_local",
    "detects": "accidental_toolchain_drift",
    "full_xcode_bundle_hashed": False,
    "hostile_host_attestation": False,
}

COMMAND_ENVIRONMENT_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
ALLOWED_COMMANDS = frozenset(
    {
        "/usr/bin/codesign",
        "/usr/sbin/spctl",
        "/usr/bin/xcodebuild",
        "/usr/bin/xcrun",
    }
)
MAX_COMMAND_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_CODE_RESOURCES_BYTES = 64 * 1024 * 1024
ARTIFACT_MAXIMUM_BYTES = {
    "code_resources": MAX_CODE_RESOURCES_BYTES,
    "info_plist": 1 * 1024 * 1024,
    "version_plist": 1 * 1024 * 1024,
    "xcode_executable": 16 * 1024 * 1024,
    "xcodebuild": 16 * 1024 * 1024,
    "swift_frontend": 192 * 1024 * 1024,
    "iphoneos_sdk_settings": 1 * 1024 * 1024,
}
MAX_RECEIPT_BYTES = 4 * 1024 * 1024
DEEP_VERIFY_TIMEOUT_SECONDS = 300
METADATA_COMMAND_TIMEOUT_SECONDS = 60

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MODE_RE = re.compile(r"^0[0-7]{3}$")
VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}(?:[-A-Za-z0-9.]+)?$")
BUILD_RE = re.compile(r"^[0-9]{1,3}[A-Z][0-9A-Za-z.]+$")
DTXCODE_RE = re.compile(r"^[0-9]+$")

ARTIFACT_PATHS = {
    "code_resources": pathlib.PurePosixPath(
        "Contents/_CodeSignature/CodeResources"
    ),
    "info_plist": pathlib.PurePosixPath("Contents/Info.plist"),
    "version_plist": pathlib.PurePosixPath("Contents/version.plist"),
    "xcode_executable": pathlib.PurePosixPath("Contents/MacOS/Xcode"),
    "xcodebuild": pathlib.PurePosixPath("Contents/Developer/usr/bin/xcodebuild"),
    "swift_frontend": pathlib.PurePosixPath(
        "Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/swift-frontend"
    ),
    "iphoneos_sdk_settings": pathlib.PurePosixPath(
        "Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/"
        "iPhoneOS.sdk/SDKSettings.plist"
    ),
}


class AppleToolchainError(ValueError):
    """The selected Xcode installation or receipt violates the contract."""


def _fail(message: str) -> NoReturn:
    raise AppleToolchainError(message)


@dataclass(frozen=True, slots=True)
class ToolchainLayout:
    app: pathlib.Path
    contents: pathlib.Path
    developer_dir: pathlib.Path
    directories: dict[str, dict[str, int | str]]


def _require_exact_keys(
    value: dict[str, Any], expected: set[str], label: str
) -> None:
    missing = expected - set(value)
    extra = set(value) - expected
    if missing or extra:
        _fail(
            f"{label} fields differ: missing={sorted(missing)} "
            f"extra={sorted(extra)}"
        )


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or not value.isprintable():
        _fail(f"{label} must be non-empty printable text")
    return value


def _require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        _fail(f"{label} must be 64 lowercase hexadecimal characters")
    return value


def _canonical_absolute_path(value: str | os.PathLike[str], label: str) -> pathlib.Path:
    try:
        candidate = pathlib.Path(value)
    except TypeError as exc:
        raise AppleToolchainError(f"{label} is not a filesystem path") from exc
    if not candidate.is_absolute():
        _fail(f"{label} must be absolute: {candidate}")
    normalized = pathlib.Path(os.path.abspath(candidate))
    if candidate != normalized:
        _fail(f"{label} is not canonically spelled: {candidate}")
    if not str(candidate).isprintable() or "\x00" in str(candidate):
        _fail(f"{label} contains unsupported characters")
    return candidate


def _directory_record(path: pathlib.Path, label: str) -> dict[str, int | str]:
    try:
        metadata = path.lstat()
    except (OSError, RuntimeError) as exc:
        raise AppleToolchainError(f"cannot inspect {label} {path}: {exc}") from exc
    mode = stat.S_IMODE(metadata.st_mode)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        _fail(f"{label} must be a non-symlink directory: {path}")
    if metadata.st_uid != REQUIRED_ROOT_UID:
        _fail(f"{label} must be root-owned: {path}")
    if mode & 0o022:
        _fail(f"{label} must not be group/world writable: {path}")
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": format(mode, "04o"),
    }


def _inspect_layout(
    developer_dir: str | os.PathLike[str],
) -> ToolchainLayout:
    if sys.platform != "darwin":
        _fail("Apple toolchain receipts require Darwin")
    selected = _canonical_absolute_path(developer_dir, "DEVELOPER_DIR")
    if selected.name != "Developer" or selected.parent.name != "Contents":
        _fail("DEVELOPER_DIR must end in .app/Contents/Developer")
    app = selected.parent.parent
    if app.suffix != ".app":
        _fail("DEVELOPER_DIR must resolve from an application bundle")

    try:
        applications_root = APPLICATIONS_ROOT.resolve(strict=True)
        resolved_app = app.resolve(strict=True)
        resolved_developer = selected.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise AppleToolchainError(
            f"cannot resolve selected Xcode installation: {exc}"
        ) from exc
    if resolved_app.parent != applications_root:
        _fail(f"selected Xcode app must be directly under {applications_root}")
    if resolved_app != app or resolved_developer != selected:
        _fail("selected Xcode app and DEVELOPER_DIR must not traverse symlinks")

    contents = app / "Contents"
    directories = {
        "app": _directory_record(app, "Xcode app"),
        "contents": _directory_record(contents, "Xcode Contents"),
        "developer": _directory_record(selected, "Xcode Developer directory"),
    }
    return ToolchainLayout(
        app=app,
        contents=contents,
        developer_dir=selected,
        directories=directories,
    )


def _command_environment(developer_dir: pathlib.Path) -> dict[str, str]:
    return {
        "PATH": COMMAND_ENVIRONMENT_PATH,
        "LC_ALL": "C",
        "LANG": "C",
        "DEVELOPER_DIR": str(developer_dir),
    }


def fixed_command_environment() -> dict[str, str]:
    """Return a fresh minimal environment for the fixed production toolchain."""

    return _command_environment(FIXED_DEVELOPER_DIR)


def _run_command(
    argv: Sequence[str],
    *,
    developer_dir: pathlib.Path,
    label: str,
    timeout_seconds: int,
    maximum_bytes: int = MAX_COMMAND_OUTPUT_BYTES,
) -> str:
    if not argv or argv[0] not in ALLOWED_COMMANDS:
        _fail(f"{label} command must use an allowed fixed executable")
    try:
        result = capture_stdout(
            argv,
            timeout_seconds=timeout_seconds,
            maximum_bytes=maximum_bytes,
            stderr=subprocess.STDOUT,
            environment=_command_environment(developer_dir),
        )
    except BoundedProcessError as exc:
        raise AppleToolchainError(
            f"{label} bounded process {exc.kind}: {exc}"
        ) from exc
    try:
        output = result.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AppleToolchainError(f"{label} output is not UTF-8") from exc
    if result.returncode != 0:
        detail = output.strip()
        suffix = f": {detail}" if detail else ""
        _fail(f"{label} failed with exit status {result.returncode}{suffix}")
    return output


def _single_prefixed_line(lines: list[str], prefix: str, label: str) -> str:
    values = [line[len(prefix) :] for line in lines if line.startswith(prefix)]
    if len(values) != 1 or not values[0]:
        _fail(f"codesign display must contain exactly one {label}")
    return values[0]


def parse_codesign_display(text: str, app: pathlib.Path) -> dict[str, Any]:
    """Parse the exact Apple identity facts required by the receipt."""

    try:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
    except (AttributeError, UnicodeError) as exc:
        raise AppleToolchainError("codesign display is not valid text") from exc
    if any(re.search(r"(^|[^A-Za-z])(warning|error):", line, re.I) for line in lines):
        _fail("codesign display contains warning/error diagnostics")
    executable = _single_prefixed_line(lines, "Executable=", "Executable")
    identifier = _single_prefixed_line(lines, "Identifier=", "Identifier")
    team = _single_prefixed_line(lines, "TeamIdentifier=", "TeamIdentifier")
    hash_type = _single_prefixed_line(lines, "Hash type=", "Hash type")
    full_cdhash = _single_prefixed_line(
        lines,
        "CandidateCDHashFull sha256=",
        "CandidateCDHashFull sha256",
    )
    authorities = tuple(
        line[len("Authority=") :]
        for line in lines
        if line.startswith("Authority=")
    )
    expected_executable = app / "Contents" / "MacOS" / "Xcode"
    if executable != str(expected_executable):
        _fail("codesign display executable differs from the selected Xcode app")
    if identifier != EXPECTED_BUNDLE_IDENTIFIER:
        _fail("codesign identifier is not com.apple.dt.Xcode")
    if team != EXPECTED_TEAM_IDENTIFIER:
        _fail("codesign TeamIdentifier is not the expected Apple team")
    if authorities != EXPECTED_AUTHORITIES:
        _fail("codesign authority chain is not the complete expected Apple chain")
    if hash_type != "sha256 size=32":
        _fail("codesign hash type is not SHA-256")
    _require_sha256(full_cdhash, "codesign CandidateCDHashFull")
    return {
        "identifier": identifier,
        "team_identifier": team,
        "authorities": list(authorities),
        "candidate_cdhash_full_sha256": full_cdhash,
        "deep_strict_verified": True,
    }


def parse_gatekeeper_assessment(text: str, app: pathlib.Path) -> dict[str, Any]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    accepted = f"{app}: accepted"
    if lines.count(accepted) != 1:
        _fail("Gatekeeper did not accept the selected Xcode app")
    sources = [line[len("source=") :] for line in lines if line.startswith("source=")]
    if sources != ["Apple System"]:
        _fail("Gatekeeper source is not exactly Apple System")
    allowed = {accepted, "source=Apple System"}
    if any(line not in allowed for line in lines):
        _fail("Gatekeeper assessment contains unexpected output")
    return {"accepted": True, "source": "Apple System"}


def _parse_plist(snapshot: FileSnapshot, label: str) -> dict[str, Any]:
    try:
        value = plistlib.loads(snapshot.data)
    except Exception as exc:  # plistlib exposes multiple parse-specific errors.
        raise AppleToolchainError(f"cannot parse {label}: {exc}") from exc
    if not isinstance(value, dict):
        _fail(f"{label} root must be a dictionary")
    return value


def _plist_string(value: dict[str, Any], key: str, label: str) -> str:
    return _require_string(value.get(key), f"{label} {key}")


def _parse_version_metadata(
    info_snapshot: FileSnapshot,
    version_snapshot: FileSnapshot,
    xcodebuild_output: str,
) -> dict[str, Any]:
    info = _parse_plist(info_snapshot, "Xcode Info.plist")
    version = _parse_plist(version_snapshot, "Xcode version.plist")
    info_values = {
        "bundle_identifier": _plist_string(
            info, "CFBundleIdentifier", "Xcode Info.plist"
        ),
        "bundle_short_version": _plist_string(
            info, "CFBundleShortVersionString", "Xcode Info.plist"
        ),
        "bundle_version": _plist_string(
            info, "CFBundleVersion", "Xcode Info.plist"
        ),
        "dtxcode": _plist_string(info, "DTXcode", "Xcode Info.plist"),
        "dtxcode_build": _plist_string(
            info, "DTXcodeBuild", "Xcode Info.plist"
        ),
    }
    version_values = {
        "bundle_short_version": _plist_string(
            version, "CFBundleShortVersionString", "Xcode version.plist"
        ),
        "bundle_version": _plist_string(
            version, "CFBundleVersion", "Xcode version.plist"
        ),
        "product_build_version": _plist_string(
            version, "ProductBuildVersion", "Xcode version.plist"
        ),
    }
    if info_values["bundle_identifier"] != EXPECTED_BUNDLE_IDENTIFIER:
        _fail("Xcode Info.plist bundle identifier is invalid")
    if (
        info_values["bundle_short_version"]
        != version_values["bundle_short_version"]
        or info_values["bundle_version"] != version_values["bundle_version"]
    ):
        _fail("Xcode Info.plist and version.plist versions differ")
    if VERSION_RE.fullmatch(info_values["bundle_short_version"]) is None:
        _fail("Xcode version is malformed")
    if DTXCODE_RE.fullmatch(info_values["dtxcode"]) is None:
        _fail("Xcode DTXcode value is malformed")
    if BUILD_RE.fullmatch(info_values["dtxcode_build"]) is None:
        _fail("Xcode Info.plist build value is malformed")
    if BUILD_RE.fullmatch(version_values["product_build_version"]) is None:
        _fail("Xcode ProductBuildVersion is malformed")

    output_lines = [
        line.strip() for line in xcodebuild_output.splitlines() if line.strip()
    ]
    if (
        len(output_lines) != 2
        or not output_lines[0].startswith("Xcode ")
        or not output_lines[1].startswith("Build version ")
    ):
        _fail("xcodebuild -version output is not the exact two-line format")
    reported_version = output_lines[0][len("Xcode ") :]
    reported_build = output_lines[1][len("Build version ") :]
    if reported_version != version_values["bundle_short_version"]:
        _fail("xcodebuild version differs from version.plist")
    if reported_build != version_values["product_build_version"]:
        _fail("xcodebuild build differs from version.plist")
    return {
        "xcode_version": reported_version,
        "build_version": reported_build,
        "info_plist": info_values,
        "version_plist": version_values,
    }


def parse_swift_version(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) != 2:
        _fail("swift --version output is not the exact two-line format")
    if not lines[0].startswith("swift-driver version: ") or "Apple Swift version " not in lines[0]:
        _fail("swift --version lacks an Apple Swift identity")
    if not lines[1].startswith("Target: "):
        _fail("swift --version lacks a target line")
    return lines[0]


ArtifactSnapshot = FileDigestSnapshot | FileSnapshot


def _artifact_snapshots(
    app: pathlib.Path,
    *,
    retain_plists: bool = True,
) -> dict[str, ArtifactSnapshot]:
    snapshots: dict[str, ArtifactSnapshot] = {}
    for name, relative in ARTIFACT_PATHS.items():
        path = app.joinpath(*relative.parts)
        try:
            if retain_plists and name in {"info_plist", "version_plist"}:
                snapshots[name] = read_regular_snapshot(
                    path,
                    maximum=ARTIFACT_MAXIMUM_BYTES[name],
                    label=f"Xcode toolchain artifact {name}",
                )
            else:
                snapshots[name] = consume_regular_snapshot(
                    path,
                    maximum=ARTIFACT_MAXIMUM_BYTES[name],
                    label=f"Xcode toolchain artifact {name}",
                )
        except EvidenceIOError as exc:
            raise AppleToolchainError(str(exc)) from exc
    return snapshots


def _artifact_receipt(
    snapshots: dict[str, ArtifactSnapshot],
) -> dict[str, dict[str, int | str]]:
    return {
        name: {
            "path": ARTIFACT_PATHS[name].as_posix(),
            "size": snapshot.size,
            "sha256": snapshot.sha256,
        }
        for name, snapshot in snapshots.items()
    }


def _require_unchanged_snapshots(
    before: dict[str, ArtifactSnapshot], after: dict[str, ArtifactSnapshot]
) -> None:
    for name in ARTIFACT_PATHS:
        if (
            before[name].size != after[name].size
            or before[name].sha256 != after[name].sha256
        ):
            _fail(f"Xcode toolchain artifact changed during capture: {name}")


def _capture_receipt_at(developer_dir: pathlib.Path) -> dict[str, Any]:
    """Test seam for capturing one explicitly supplied toolchain fixture."""

    layout = _inspect_layout(developer_dir)
    initial_artifacts = _artifact_snapshots(layout.app)
    info_snapshot = initial_artifacts["info_plist"]
    version_snapshot = initial_artifacts["version_plist"]
    if not isinstance(info_snapshot, FileSnapshot) or not isinstance(
        version_snapshot, FileSnapshot
    ):
        _fail("Xcode plist snapshots were not retained")

    deep_output = _run_command(
        [
            "/usr/bin/codesign",
            "--verify",
            "--deep",
            "--strict",
            str(layout.app),
        ],
        developer_dir=layout.developer_dir,
        label="Xcode deep codesign verification",
        timeout_seconds=DEEP_VERIFY_TIMEOUT_SECONDS,
    )
    if deep_output.strip():
        _fail("successful Xcode deep codesign verification emitted diagnostics")
    display_output = _run_command(
        [
            "/usr/bin/codesign",
            "--display",
            "--verbose=4",
            str(layout.app),
        ],
        developer_dir=layout.developer_dir,
        label="Xcode codesign display",
        timeout_seconds=METADATA_COMMAND_TIMEOUT_SECONDS,
    )
    signature = parse_codesign_display(display_output, layout.app)
    gatekeeper_output = _run_command(
        [
            "/usr/sbin/spctl",
            "--assess",
            "--type",
            "execute",
            "--verbose=4",
            str(layout.app),
        ],
        developer_dir=layout.developer_dir,
        label="Xcode Gatekeeper assessment",
        timeout_seconds=METADATA_COMMAND_TIMEOUT_SECONDS,
    )
    gatekeeper = parse_gatekeeper_assessment(gatekeeper_output, layout.app)
    xcodebuild_output = _run_command(
        ["/usr/bin/xcodebuild", "-version"],
        developer_dir=layout.developer_dir,
        label="xcodebuild version",
        timeout_seconds=METADATA_COMMAND_TIMEOUT_SECONDS,
    )
    version = _parse_version_metadata(
        info_snapshot,
        version_snapshot,
        xcodebuild_output,
    )
    swift_output = _run_command(
        ["/usr/bin/xcrun", "swift", "--version"],
        developer_dir=layout.developer_dir,
        label="Swift version",
        timeout_seconds=METADATA_COMMAND_TIMEOUT_SECONDS,
    )
    swift_version = parse_swift_version(swift_output)
    if signature["identifier"] != version["info_plist"]["bundle_identifier"]:
        _fail("codesign and Info.plist bundle identifiers differ")

    final_artifacts = _artifact_snapshots(layout.app, retain_plists=False)
    _require_unchanged_snapshots(initial_artifacts, final_artifacts)
    final_layout = _inspect_layout(layout.developer_dir)
    if final_layout.directories != layout.directories:
        _fail("Xcode directory identity changed during capture")

    receipt = {
        "schema_version": SCHEMA_VERSION,
        "kind": RECEIPT_KIND,
        "trust_boundary": dict(TRUST_BOUNDARY),
        "app_path": str(layout.app),
        "developer_dir": str(layout.developer_dir),
        "directories": layout.directories,
        "version": version,
        "swift_version": swift_version,
        "signature": signature,
        "gatekeeper": gatekeeper,
        "artifacts": _artifact_receipt(initial_artifacts),
    }
    _validate_receipt(receipt)
    return receipt


def capture_receipt() -> dict[str, Any]:
    """Capture the fixed release-lane Xcode installation receipt."""

    return _capture_receipt_at(FIXED_DEVELOPER_DIR)


def _validate_directory_identity(value: Any, label: str) -> None:
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    _require_exact_keys(value, {"device", "inode", "uid", "gid", "mode"}, label)
    for key in ("device", "inode", "uid", "gid"):
        field = value[key]
        if type(field) is not int or field < 0:
            _fail(f"{label}.{key} must be a non-negative integer")
    if value["uid"] != REQUIRED_ROOT_UID:
        _fail(f"{label}.uid is not root")
    mode = value["mode"]
    if not isinstance(mode, str) or MODE_RE.fullmatch(mode) is None:
        _fail(f"{label}.mode is malformed")
    if int(mode, 8) & 0o022:
        _fail(f"{label}.mode is group/world writable")


def _validate_receipt(receipt: dict[str, Any]) -> None:
    _require_exact_keys(
        receipt,
        {
            "schema_version",
            "kind",
            "trust_boundary",
            "app_path",
            "developer_dir",
            "directories",
            "version",
            "swift_version",
            "signature",
            "gatekeeper",
            "artifacts",
        },
        "Apple toolchain receipt",
    )
    if receipt["schema_version"] != SCHEMA_VERSION:
        _fail(f"Apple toolchain receipt schema must be {SCHEMA_VERSION}")
    if receipt["kind"] != RECEIPT_KIND:
        _fail("Apple toolchain receipt kind is invalid")
    if receipt["trust_boundary"] != TRUST_BOUNDARY:
        _fail("Apple toolchain receipt trust boundary is invalid")

    app_path = _canonical_absolute_path(receipt["app_path"], "receipt app_path")
    developer_dir = _canonical_absolute_path(
        receipt["developer_dir"], "receipt developer_dir"
    )
    if developer_dir != app_path / "Contents" / "Developer":
        _fail("receipt app_path and developer_dir differ")
    if developer_dir != FIXED_DEVELOPER_DIR:
        _fail("receipt does not select the fixed Apple release toolchain")

    directories = receipt["directories"]
    if not isinstance(directories, dict):
        _fail("receipt directories must be an object")
    _require_exact_keys(directories, {"app", "contents", "developer"}, "directories")
    for name in ("app", "contents", "developer"):
        _validate_directory_identity(directories[name], f"directories.{name}")

    version = receipt["version"]
    if not isinstance(version, dict):
        _fail("receipt version must be an object")
    _require_exact_keys(
        version,
        {"xcode_version", "build_version", "info_plist", "version_plist"},
        "version",
    )
    xcode_version = _require_string(version["xcode_version"], "version.xcode_version")
    build_version = _require_string(version["build_version"], "version.build_version")
    if VERSION_RE.fullmatch(xcode_version) is None or BUILD_RE.fullmatch(build_version) is None:
        _fail("receipt Xcode version/build is malformed")
    info = version["info_plist"]
    version_plist = version["version_plist"]
    if not isinstance(info, dict) or not isinstance(version_plist, dict):
        _fail("receipt plist version metadata is malformed")
    _require_exact_keys(
        info,
        {
            "bundle_identifier",
            "bundle_short_version",
            "bundle_version",
            "dtxcode",
            "dtxcode_build",
        },
        "version.info_plist",
    )
    _require_exact_keys(
        version_plist,
        {"bundle_short_version", "bundle_version", "product_build_version"},
        "version.version_plist",
    )
    for name, value in info.items():
        _require_string(value, f"version.info_plist.{name}")
    for name, value in version_plist.items():
        _require_string(value, f"version.version_plist.{name}")
    if info["bundle_identifier"] != EXPECTED_BUNDLE_IDENTIFIER:
        _fail("receipt Info.plist identifier is invalid")
    if (
        info["bundle_short_version"] != version_plist["bundle_short_version"]
        or info["bundle_version"] != version_plist["bundle_version"]
        or xcode_version != version_plist["bundle_short_version"]
        or build_version != version_plist["product_build_version"]
    ):
        _fail("receipt Xcode version metadata is inconsistent")
    swift_version = _require_string(receipt["swift_version"], "swift_version")
    if "Apple Swift version " not in swift_version:
        _fail("receipt Swift version is not an Apple Swift identity")
    if (
        VERSION_RE.fullmatch(info["bundle_short_version"]) is None
        or DTXCODE_RE.fullmatch(info["dtxcode"]) is None
        or BUILD_RE.fullmatch(info["dtxcode_build"]) is None
        or BUILD_RE.fullmatch(version_plist["product_build_version"]) is None
    ):
        _fail("receipt plist version metadata is malformed")

    signature = receipt["signature"]
    if not isinstance(signature, dict):
        _fail("receipt signature must be an object")
    _require_exact_keys(
        signature,
        {
            "identifier",
            "team_identifier",
            "authorities",
            "candidate_cdhash_full_sha256",
            "deep_strict_verified",
        },
        "signature",
    )
    if (
        signature["identifier"] != EXPECTED_BUNDLE_IDENTIFIER
        or signature["team_identifier"] != EXPECTED_TEAM_IDENTIFIER
        or signature["authorities"] != list(EXPECTED_AUTHORITIES)
        or signature["deep_strict_verified"] is not True
    ):
        _fail("receipt signature identity is invalid")
    _require_sha256(
        signature["candidate_cdhash_full_sha256"],
        "signature.candidate_cdhash_full_sha256",
    )

    gatekeeper = receipt["gatekeeper"]
    if gatekeeper != {"accepted": True, "source": "Apple System"}:
        _fail("receipt Gatekeeper state is invalid")

    artifacts = receipt["artifacts"]
    if not isinstance(artifacts, dict):
        _fail("receipt artifacts must be an object")
    _require_exact_keys(artifacts, set(ARTIFACT_PATHS), "artifacts")
    for name, expected_path in ARTIFACT_PATHS.items():
        entry = artifacts[name]
        if not isinstance(entry, dict):
            _fail(f"artifacts.{name} must be an object")
        _require_exact_keys(entry, {"path", "size", "sha256"}, f"artifacts.{name}")
        if entry["path"] != expected_path.as_posix():
            _fail(f"artifacts.{name}.path is invalid")
        size_limit = ARTIFACT_MAXIMUM_BYTES[name]
        if type(entry["size"]) is not int or not 0 < entry["size"] <= size_limit:
            _fail(f"artifacts.{name}.size is invalid")
        _require_sha256(entry["sha256"], f"artifacts.{name}.sha256")


def _compare_exact(expected: Any, actual: Any, path: str = "receipt") -> None:
    if type(expected) is not type(actual):
        _fail(f"{path} type changed")
    if isinstance(expected, dict):
        if set(expected) != set(actual):
            _fail(f"{path} fields changed")
        for key in sorted(expected):
            _compare_exact(expected[key], actual[key], f"{path}.{key}")
        return
    if isinstance(expected, list):
        if len(expected) != len(actual):
            _fail(f"{path} length changed")
        for index, (expected_item, actual_item) in enumerate(zip(expected, actual)):
            _compare_exact(expected_item, actual_item, f"{path}[{index}]")
        return
    if expected != actual:
        _fail(f"{path} changed: expected={expected!r} actual={actual!r}")


def verify_receipt(expected: dict[str, Any]) -> dict[str, Any]:
    """Re-capture the fixed release-lane Xcode state and require equality."""

    if not isinstance(expected, dict):
        _fail("expected Apple toolchain receipt must be an object")
    _validate_receipt(expected)
    current = capture_receipt()
    _compare_exact(expected, current)
    return current


def _json_bytes(receipt: dict[str, Any]) -> bytes:
    return (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _write_new_private_json(path: pathlib.Path, receipt: dict[str, Any]) -> str:
    _validate_receipt(receipt)
    output = _canonical_absolute_path(path, "receipt output")
    parent = output.parent
    try:
        resolved_parent = parent.resolve(strict=True)
    except OSError as exc:
        raise AppleToolchainError(f"cannot resolve receipt output directory: {exc}") from exc
    if resolved_parent != parent:
        _fail("receipt output directory must not be a symlink")
    try:
        parent_metadata = parent.lstat()
    except OSError as exc:
        raise AppleToolchainError(f"cannot inspect receipt output directory: {exc}") from exc
    if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(parent_metadata.st_mode):
        _fail("receipt output parent must be a non-symlink directory")

    payload = _json_bytes(receipt)
    if len(payload) > MAX_RECEIPT_BYTES:
        _fail(f"receipt output exceeds {MAX_RECEIPT_BYTES} bytes")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        directory_fd = os.open(parent, directory_flags)
    except OSError as exc:
        raise AppleToolchainError(f"cannot open receipt output directory: {exc}") from exc
    descriptor: int | None = None
    created = False
    primary: BaseException | None = None
    try:
        try:
            descriptor = os.open(output.name, flags, 0o600, dir_fd=directory_fd)
            created = True
        except FileExistsError as exc:
            raise AppleToolchainError(
                f"refusing to replace existing receipt output: {output}"
            ) from exc
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            _fail("receipt output is not one current-user private regular file")
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("receipt write made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.fsync(directory_fd)
        return hashlib.sha256(payload).hexdigest()
    except BaseException as exc:
        primary = exc
        if descriptor is not None:
            try:
                os.close(descriptor)
            except BaseException as cleanup_error:
                primary.add_note(
                    f"closing failed receipt output also failed: {cleanup_error}"
                )
            descriptor = None
        if created:
            try:
                os.unlink(output.name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            except BaseException as cleanup_error:
                primary.add_note(
                    f"removing failed receipt output also failed: {cleanup_error}"
                )
        raise
    finally:
        try:
            os.close(directory_fd)
        except BaseException as cleanup_error:
            if primary is not None:
                primary.add_note(
                    f"closing receipt output directory also failed: {cleanup_error}"
                )
            else:
                raise


def _private_receipt_metadata(metadata: os.stat_result) -> None:
    if (
        metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise EvidenceIOError(
            "Apple toolchain receipt must be current-user-owned with one link and mode 0600"
        )


def _load_private_receipt(path: pathlib.Path) -> dict[str, Any]:
    try:
        snapshot = load_json_object_snapshot(
            path,
            maximum=MAX_RECEIPT_BYTES,
            label="Apple toolchain receipt",
            validate_metadata=_private_receipt_metadata,
        )
    except EvidenceIOError as exc:
        raise AppleToolchainError(str(exc)) from exc
    _validate_receipt(snapshot.value)
    return snapshot.value


def _capture_command(args: argparse.Namespace) -> None:
    receipt = capture_receipt()
    output = _canonical_absolute_path(args.output, "receipt output")
    digest = _write_new_private_json(output, receipt)
    print(f"APPLE_TOOLCHAIN_RECEIPT={output} sha256={digest}")


def _verify_command(args: argparse.Namespace) -> None:
    receipt_path = _canonical_absolute_path(args.receipt, "receipt input")
    expected = _load_private_receipt(receipt_path)
    current = verify_receipt(expected)
    digest = hashlib.sha256(_json_bytes(current)).hexdigest()
    print(f"APPLE_TOOLCHAIN_RECEIPT_PASS sha256={digest}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    capture = subparsers.add_parser("capture")
    capture.add_argument("--output", type=pathlib.Path, required=True)
    capture.set_defaults(handler=_capture_command)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--receipt", type=pathlib.Path, required=True)
    verify.set_defaults(handler=_verify_command)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        args.handler(args)
    except (AppleToolchainError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
