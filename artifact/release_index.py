#!/usr/bin/env python3
"""Build and verify a local Q-Periapt release index.

The index is a packaging manifest, not a public release claim. It copies already
verified package artifacts into one local directory and records hashes plus proof
summaries. Raw device proof, build logs, profiles, and local device identifiers
must stay out of this index.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
from typing import Any


SCHEMA_VERSION = 1
KIND = "qperiapt.local_release_index"
FORBIDDEN_INDEX_TEXT = (
    "artifact/device-runs",
    ".mobileprovision",
    ".xcresult",
    "ProvisionedDevices",
    "TeamIdentifier",
    "000081",
    "emulator-",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"error: {message}")


def read_bytes(path: pathlib.Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise SystemExit(f"error: cannot read {path}: {exc}") from exc


def read_text(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise SystemExit(f"error: cannot read {path}: {exc}") from exc


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(read_text(path))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"error: cannot parse JSON {path}: {exc}") from exc
    require(isinstance(value, dict), f"JSON root is not an object: {path}")
    return value


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(read_bytes(path)).hexdigest()


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def run_line(args: list[str]) -> str:
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"error: cannot run {' '.join(args)}: {exc}") from exc


def git_commit(root: pathlib.Path) -> str:
    commit = run_line(["git", "-C", str(root), "rev-parse", "HEAD"])
    require(re.fullmatch(r"[0-9a-f]{40,64}", commit) is not None, f"git commit hash is malformed: {commit}")
    return commit


def git_dirty(root: pathlib.Path) -> bool:
    status = run_line(["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"])
    return bool(status)


def cargo_version(root: pathlib.Path) -> str:
    raw = run_line(["cargo", "metadata", "--locked", "--format-version", "1", "--no-deps"])
    data = json.loads(raw)
    for package in data.get("packages", []):
        if package.get("name") == "q-periapt-ffi":
            version = package.get("version")
            require(isinstance(version, str) and version, "q-periapt-ffi version is malformed")
            return version
    raise SystemExit("error: q-periapt-ffi package not found in cargo metadata")


def rust_host() -> str:
    for line in run_line(["rustc", "-vV"]).splitlines():
        if line.startswith("host: "):
            return line.split(": ", 1)[1]
    raise SystemExit("error: cannot determine rustc host triple")


def require_under(path: pathlib.Path, base: pathlib.Path, label: str) -> None:
    try:
        path.resolve().relative_to(base.resolve())
    except ValueError:
        raise SystemExit(f"error: {label} must be under {base}: {path}") from None


def require_relative_safe(path: str, label: str) -> None:
    require(path and not path.startswith(("/", "\\")), f"{label} must be a relative path: {path}")
    parts = pathlib.PurePosixPath(path).parts
    require(".." not in parts, f"{label} must not contain '..': {path}")


def copy_to_release(
    src: pathlib.Path,
    source_base: pathlib.Path,
    release_root: pathlib.Path,
    rel: str,
) -> dict[str, Any]:
    require_relative_safe(rel, "release artifact path")
    require_under(src, source_base, "release artifact source")
    dst = release_root / rel
    require_under(dst, release_root, "release artifact output")
    if src.is_symlink():
        raise SystemExit(f"error: release artifact source must not be a symlink: {src}")
    if not src.is_file():
        raise SystemExit(f"error: release artifact source missing: {src}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return {
        "path": rel,
        "sha256": sha256_file(dst),
        "bytes": dst.stat().st_size,
    }


def verify_sha256s(dist_dir: pathlib.Path) -> None:
    sums = dist_dir / "SHA256SUMS"
    if not sums.is_file():
        raise SystemExit(f"error: missing SHA256SUMS: {sums}")
    for line_no, line in enumerate(read_text(sums).splitlines(), start=1):
        if not line.strip():
            continue
        parts = line.split()
        require(len(parts) == 2, f"malformed SHA256SUMS line {line_no}: {line}")
        expected, rel = parts
        require(re.fullmatch(r"[0-9a-f]{64}", expected) is not None, f"malformed sha256 at {sums}:{line_no}")
        require_relative_safe(rel, f"SHA256SUMS path at {sums}:{line_no}")
        target = (dist_dir / rel).resolve()
        require_under(target, dist_dir, f"SHA256SUMS path at {sums}:{line_no}")
        require(target.is_file(), f"SHA256SUMS target missing: {target}")
        require(sha256_file(target) == expected, f"SHA256SUMS hash mismatch for {target}")


def package_dirty(manifest: dict[str, Any]) -> bool | None:
    if isinstance(manifest.get("git_dirty"), bool):
        return manifest["git_dirty"]
    if isinstance(manifest.get("source_tree_dirty"), bool):
        return manifest["source_tree_dirty"]
    return None


def validate_package_manifest(
    manifest_path: pathlib.Path,
    expected_commit: str,
    expected_version: str,
    channel: str,
    label: str,
) -> dict[str, Any]:
    manifest = load_json(manifest_path)
    commit = manifest.get("git_commit")
    require(commit == expected_commit, f"{label} manifest commit mismatch: {commit} != {expected_commit}")
    version = manifest.get("version")
    if version is not None:
        require(version == expected_version, f"{label} manifest version mismatch: {version} != {expected_version}")
    dirty = package_dirty(manifest)
    if channel == "release":
        require(dirty is False, f"{label} manifest lacks clean provenance or was generated dirty")
    return manifest


def artifact_entry(
    artifact_id: str,
    face: str,
    kind: str,
    files: list[dict[str, Any]],
    manifest_file: dict[str, Any],
    sha256s_file: dict[str, Any],
    boundary: dict[str, Any],
    verified_by: str,
    targets: list[str],
) -> dict[str, Any]:
    return {
        "id": artifact_id,
        "face": face,
        "type": kind,
        "files": files,
        "manifest": manifest_file,
        "sha256s": sha256s_file,
        "boundary": boundary,
        "verified_by": verified_by,
        "targets": targets,
    }


def proof_summary(path: pathlib.Path, proof_kind: str) -> dict[str, Any]:
    proof = load_json(path)
    summary: dict[str, Any] = {
        "kind": proof_kind,
        "sha256": sha256_file(path),
        "generated_at": proof.get("generated_at"),
        "source_tree_dirty": proof.get("source_tree_dirty"),
        "copied_raw_proof": False,
        "diagnostic_only": proof.get("source_tree_dirty") is True,
    }
    if proof_kind == "apple_matrix":
        devices = []
        for item in proof.get("devices", []):
            require(isinstance(item, dict), "Apple matrix device entry is malformed")
            devices.append(
                {
                    "label": item.get("label"),
                    "device_type": item.get("device_type"),
                    "product_type": item.get("product_type"),
                    "os_version": item.get("os_version"),
                    "os_build": item.get("os_build"),
                    "device_id_sha256_prefix": str(item.get("device_id_sha256", ""))[:12],
                    "run_id": item.get("run_id"),
                }
            )
        summary["devices"] = devices
    elif proof_kind == "android_runtime":
        device = proof.get("device")
        result = proof.get("result")
        require(isinstance(device, dict) and isinstance(result, dict), "Android proof is malformed")
        summary["device"] = {
            "kind": device.get("kind"),
            "model": device.get("model"),
            "sdk": device.get("sdk"),
            "abi": device.get("abi"),
            "serial_sha256_prefix": device.get("serial_sha256_prefix"),
            "raw_serial_recorded": device.get("raw_serial_recorded"),
        }
        summary["result"] = {
            "run_id": proof.get("run_id"),
            "test_count": result.get("test_count"),
            "passed_tests": result.get("passed_tests"),
        }
    return summary


def build_index(args: argparse.Namespace) -> pathlib.Path:
    root = pathlib.Path(args.root).resolve()
    channel = args.channel
    version = cargo_version(root)
    commit = git_commit(root)
    current_dirty = git_dirty(root)
    if channel == "release":
        require(not current_dirty, "release index requires a clean source tree")

    host = rust_host()
    target = root / "target"
    release_root = pathlib.Path(args.output_dir).resolve() if args.output_dir else target / "qperiapt-local-release" / version / commit
    require_under(release_root, target, "release index output")
    if release_root.exists():
        shutil.rmtree(release_root)
    release_root.mkdir(parents=True)

    c_package = f"q-periapt-c-abi-{version}-{host}"
    c_dir = target / "qperiapt-c-abi" / c_package
    c_manifest_path = c_dir / "MANIFEST.json"
    c_archive = target / "qperiapt-c-abi" / f"{c_package}.tar.gz"
    verify_sha256s(c_dir)
    c_manifest = validate_package_manifest(c_manifest_path, commit, version, channel, "C ABI")

    swift_dir = target / "qperiapt-swift-xcframework" / f"q-periapt-swift-{version}"
    swift_manifest_path = swift_dir / "MANIFEST.json"
    swift_zip = swift_dir / "CQPeriapt.xcframework.zip"
    verify_sha256s(swift_dir)
    swift_manifest = validate_package_manifest(swift_manifest_path, commit, version, channel, "Swift XCFramework")

    android_dir = target / "qperiapt-android-aar" / f"q-periapt-android-{version}"
    android_manifest_path = android_dir / "MANIFEST.json"
    android_aar = android_dir / f"q-periapt-android-{version}.aar"
    verify_sha256s(android_dir)
    android_manifest = validate_package_manifest(android_manifest_path, commit, version, channel, "Android AAR")

    artifacts = [
        artifact_entry(
            f"c-abi/{host}",
            "c-abi",
            "tar.gz",
            [copy_to_release(c_archive, target, release_root, f"packages/c/{c_archive.name}")],
            copy_to_release(c_manifest_path, target, release_root, "manifests/c/MANIFEST.json"),
            copy_to_release(c_dir / "SHA256SUMS", target, release_root, "manifests/c/SHA256SUMS"),
            {
                "package_only": False,
                "host_archive_only": True,
                "multi_target_release_pending": True,
                "git_dirty": package_dirty(c_manifest),
            },
            "artifact/c-package.sh",
            [host],
        ),
        artifact_entry(
            "swift/xcframework",
            "swift",
            "xcframework.zip",
            [copy_to_release(swift_zip, target, release_root, "packages/swift/CQPeriapt.xcframework.zip")],
            copy_to_release(swift_manifest_path, target, release_root, "manifests/swift/MANIFEST.json"),
            copy_to_release(swift_dir / "SHA256SUMS", target, release_root, "manifests/swift/SHA256SUMS"),
            {
                "package_only": True,
                "public_url_uploaded": False,
                "contains_raw_device_proof": False,
                "git_dirty": package_dirty(swift_manifest),
            },
            "artifact/swift-xcframework.sh",
            list(swift_manifest.get("targets", [])),
        ),
        artifact_entry(
            "android/aar",
            "android",
            "aar",
            [copy_to_release(android_aar, target, release_root, f"packages/android/{android_aar.name}")],
            copy_to_release(android_manifest_path, target, release_root, "manifests/android/MANIFEST.json"),
            copy_to_release(android_dir / "SHA256SUMS", target, release_root, "manifests/android/SHA256SUMS"),
            {
                "package_only": True,
                "device_runtime_proof": False,
                "runtime_proof_is_separate": True,
                "git_dirty": package_dirty(android_manifest),
            },
            "artifact/android-aar.sh",
            list(android_manifest.get("android", {}).get("abis", [])),
        ),
    ]

    proofs: dict[str, Any] = {}
    if args.apple_matrix_proof:
        apple_path = pathlib.Path(args.apple_matrix_proof).resolve()
        require_under(apple_path, root / "artifact" / "device-runs", "Apple matrix proof")
        proofs["apple_matrix"] = proof_summary(apple_path, "apple_matrix")
    if args.android_proof:
        android_path = pathlib.Path(args.android_proof).resolve()
        require_under(android_path, target, "Android runtime proof")
        proofs["android_runtime"] = proof_summary(android_path, "android_runtime")

    index = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "version": version,
        "channel": channel,
        "diagnostic_only": channel != "release",
        "generated_at": utc_now(),
        "git": {
            "commit": commit,
            "source_tree_dirty": current_dirty,
        },
        "release_boundary": {
            "public_release": False,
            "registry_uploaded": False,
            "raw_device_proofs_copied": False,
            "requires_clean_tree_for_release": True,
        },
        "artifacts": artifacts,
        "proof_summaries": proofs,
    }
    index_path = release_root / "index.json"
    write_json(index_path, index)
    validate_index_text(index_path)
    write_release_sums(release_root)
    latest = {
        "schema_version": SCHEMA_VERSION,
        "kind": "qperiapt.local_release_index.pointer",
        "version": version,
        "channel": channel,
        "index_path": str(index_path.relative_to(target)),
        "index_sha256": sha256_file(index_path),
        "generated_at": index["generated_at"],
    }
    latest_path = target / "qperiapt-local-release" / "latest.json"
    latest_path.parent.mkdir(parents=True, exist_ok=True)
    write_json(latest_path, latest)
    print(f"QPERIAPT_LOCAL_RELEASE_INDEX={index_path}")
    return index_path


def validate_index_text(index_path: pathlib.Path) -> None:
    text = read_text(index_path)
    for forbidden in FORBIDDEN_INDEX_TEXT:
        require(forbidden not in text, f"release index contains private/local token: {forbidden}")


def write_release_sums(release_root: pathlib.Path) -> None:
    files = sorted(p for p in release_root.rglob("*") if p.is_file() and p.name != "SHA256SUMS")
    lines = []
    for path in files:
        rel = path.relative_to(release_root).as_posix()
        require_relative_safe(rel, "release SHA256SUMS path")
        lines.append(f"{sha256_file(path)}  {rel}")
    (release_root / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def verify_index(args: argparse.Namespace) -> None:
    index_path = pathlib.Path(args.index).resolve()
    release_root = index_path.parent
    index = load_json(index_path)
    require(index.get("schema_version") == SCHEMA_VERSION, "unsupported release index schema")
    require(index.get("kind") == KIND, "release index kind mismatch")
    validate_index_text(index_path)
    artifacts = index.get("artifacts")
    require(isinstance(artifacts, list) and artifacts, "release index lacks artifacts")
    for artifact in artifacts:
        require(isinstance(artifact, dict), "artifact entry is malformed")
        for group in ("files",):
            files = artifact.get(group)
            require(isinstance(files, list) and files, f"artifact {artifact.get('id')} lacks {group}")
            for item in files:
                verify_index_file(release_root, item)
        verify_index_file(release_root, artifact.get("manifest"))
        verify_index_file(release_root, artifact.get("sha256s"))
    verify_sha256s(release_root)
    print("QPERIAPT_LOCAL_RELEASE_INDEX_VERIFY_PASS")


def verify_index_file(release_root: pathlib.Path, item: Any) -> None:
    require(isinstance(item, dict), "indexed file entry is not an object")
    rel = item.get("path")
    expected = item.get("sha256")
    require(isinstance(rel, str), "indexed file path is missing")
    require(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected) is not None, f"indexed file hash is malformed: {rel}")
    require_relative_safe(rel, "indexed file path")
    path = (release_root / rel).resolve()
    require_under(path, release_root, "indexed file")
    require(path.is_file(), f"indexed file missing: {path}")
    require(sha256_file(path) == expected, f"indexed file hash mismatch: {rel}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    emit = sub.add_parser("emit")
    emit.add_argument("--root", default=".")
    emit.add_argument("--channel", choices=["release", "diagnostic"], default="release")
    emit.add_argument("--output-dir", default="")
    emit.add_argument("--apple-matrix-proof", default="")
    emit.add_argument("--android-proof", default="")
    emit.set_defaults(func=build_index)

    verify = sub.add_parser("verify")
    verify.add_argument("--index", required=True)
    verify.set_defaults(func=verify_index)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
