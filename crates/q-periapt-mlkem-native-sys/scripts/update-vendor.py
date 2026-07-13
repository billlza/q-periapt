#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Reproduce the exact pinned mlkem-native import from a verified archive."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
from typing import BinaryIO
import urllib.request

UPSTREAM_COMMIT = "0ba906cb14b1c241476134d7403a811b382ca498"
ARCHIVE_URL = (
    "https://github.com/pq-code-package/mlkem-native/archive/"
    f"{UPSTREAM_COMMIT}.tar.gz"
)
EXPECTED_ARCHIVE_SHA256 = (
    "f1975616b99c86819fb959803b090370d206d2b5fc9639146b79ce846864d677"
)
EXPECTED_LICENSE_SHA256 = (
    "6393331d41b9fed47a9e18d21b9b844ae8e76bcad8b6da45604c132ae13f3029"
)
EXPECTED_FILE_COUNT = 124
ARCHIVE_ROOT = f"mlkem-native-{UPSTREAM_COMMIT}"
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
DOWNLOAD_CHUNK_BYTES = 1024 * 1024

CRATE_ROOT = Path(__file__).resolve().parents[1]
VENDOR_PARENT = CRATE_ROOT / "vendor"
VENDOR_ROOT = VENDOR_PARENT / "mlkem-native"
INVENTORY_PATH = VENDOR_PARENT / "INVENTORY.sha256"
LICENSE_PATH = VENDOR_PARENT / "LICENSE.mlkem-native"
VERIFY_SCRIPT = Path(__file__).with_name("verify-vendor.py")


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"vendor update failed: {message}")


def safe_archive_path(raw_path: str) -> PurePosixPath:
    path = PurePosixPath(raw_path)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        fail(f"unsafe archive path: {raw_path!r}")
    return path


def read_limited(source: BinaryIO, description: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = source.read(DOWNLOAD_CHUNK_BYTES)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_ARCHIVE_BYTES:
            fail(
                f"{description} exceeds the {MAX_ARCHIVE_BYTES}-byte "
                "archive size limit"
            )
        chunks.append(chunk)
    return b"".join(chunks)


def parse_content_length(raw_value: str | None) -> int | None:
    if raw_value is None:
        return None
    normalized = raw_value.strip()
    if not normalized.isascii() or not normalized.isdecimal():
        fail(f"archive download returned invalid Content-Length: {raw_value!r}")
    content_length = int(normalized)
    if content_length > MAX_ARCHIVE_BYTES:
        fail(
            f"archive download Content-Length {content_length} exceeds the "
            f"{MAX_ARCHIVE_BYTES}-byte archive size limit"
        )
    return content_length


def read_archive(archive_path: Path | None) -> bytes:
    if archive_path is not None:
        if archive_path.is_symlink() or not archive_path.is_file():
            fail(f"--archive must name a regular non-symlink file: {archive_path}")
        with archive_path.open("rb") as source:
            declared_size = os.fstat(source.fileno()).st_size
            if declared_size > MAX_ARCHIVE_BYTES:
                fail(
                    f"local archive size {declared_size} exceeds the "
                    f"{MAX_ARCHIVE_BYTES}-byte archive size limit"
                )
            archive = read_limited(source, "local archive")
        if len(archive) != declared_size:
            fail(
                "local archive size changed while it was being read: "
                f"expected {declared_size} bytes, read {len(archive)}"
            )
        return archive
    request = urllib.request.Request(
        ARCHIVE_URL,
        headers={"User-Agent": "q-periapt-vendor-updater/1"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        if response.status != 200:
            fail(f"archive download returned HTTP {response.status}")
        content_length = parse_content_length(response.headers.get("Content-Length"))
        archive = read_limited(response, "archive download")
        if content_length is not None and len(archive) != content_length:
            fail(
                "archive download length differs from Content-Length: "
                f"expected {content_length} bytes, read {len(archive)}"
            )
        return archive


def write_inventory(root: Path, destination: Path) -> None:
    files = sorted(path for path in root.rglob("*") if path.is_file())
    if len(files) != EXPECTED_FILE_COUNT:
        fail(f"expected {EXPECTED_FILE_COUNT} files, extracted {len(files)}")
    lines = [
        f"{digest_file(path)}  {path.relative_to(root).as_posix()}\n"
        for path in files
    ]
    destination.write_text("".join(lines), encoding="utf-8", newline="\n")


def stage_archive(archive: bytes, staging_root: Path) -> tuple[Path, Path, Path]:
    archive_path = staging_root / "source.tar.gz"
    archive_path.write_bytes(archive)
    staged_vendor = staging_root / "mlkem-native"
    staged_vendor.mkdir()
    staged_license = staging_root / "LICENSE.mlkem-native"
    staged_inventory = staging_root / "INVENTORY.sha256"

    source_prefix = PurePosixPath(ARCHIVE_ROOT) / "mlkem"
    license_name = (PurePosixPath(ARCHIVE_ROOT) / "LICENSE").as_posix()
    extracted_files = 0

    with tarfile.open(archive_path, mode="r:gz") as archive_file:
        for member in archive_file.getmembers():
            member_path = safe_archive_path(member.name)
            if member_path.as_posix() == license_name:
                if not member.isfile():
                    fail("upstream LICENSE is not a regular file")
                source = archive_file.extractfile(member)
                if source is None:
                    fail("unable to read upstream LICENSE")
                license_bytes = source.read()
                if digest_bytes(license_bytes) != EXPECTED_LICENSE_SHA256:
                    fail("upstream LICENSE hash mismatch")
                staged_license.write_bytes(license_bytes)
                continue

            try:
                relative_path = member_path.relative_to(source_prefix)
            except ValueError:
                continue
            if not relative_path.parts:
                continue
            destination = staged_vendor.joinpath(*relative_path.parts)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                fail(f"non-regular member in selected subtree: {member.name}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            source = archive_file.extractfile(member)
            if source is None:
                fail(f"unable to read {member.name}")
            with destination.open("xb") as output:
                shutil.copyfileobj(source, output)
            extracted_files += 1

    if extracted_files != EXPECTED_FILE_COUNT:
        fail(f"expected {EXPECTED_FILE_COUNT} files, extracted {extracted_files}")
    if not staged_license.is_file():
        fail("archive did not contain the expected upstream LICENSE")
    write_inventory(staged_vendor, staged_inventory)
    return staged_vendor, staged_license, staged_inventory


def replace_staged(staged_paths: tuple[Path, Path, Path]) -> None:
    destinations = (VENDOR_ROOT, LICENSE_PATH, INVENTORY_PATH)
    backups = tuple(path.with_name(f".{path.name}.backup") for path in destinations)
    if any(path.exists() for path in backups):
        fail("stale vendor backup exists; inspect it before retrying")

    moved_backups: list[tuple[Path, Path]] = []
    installed: list[Path] = []
    try:
        for destination, backup in zip(destinations, backups, strict=True):
            if destination.exists():
                destination.rename(backup)
                moved_backups.append((destination, backup))
        for staged, destination in zip(staged_paths, destinations, strict=True):
            staged.rename(destination)
            installed.append(destination)
    except BaseException:
        for destination in reversed(installed):
            if destination.is_dir():
                shutil.rmtree(destination)
            elif destination.exists():
                destination.unlink()
        for destination, backup in reversed(moved_backups):
            backup.rename(destination)
        raise
    else:
        for _, backup in moved_backups:
            if backup.is_dir():
                shutil.rmtree(backup)
            else:
                backup.unlink()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--archive",
        type=Path,
        help="use an existing archive instead of downloading the pinned URL",
    )
    args = parser.parse_args()

    archive = read_archive(args.archive)
    actual_archive_sha256 = digest_bytes(archive)
    if actual_archive_sha256 != EXPECTED_ARCHIVE_SHA256:
        fail(
            "archive SHA-256 mismatch: "
            f"expected {EXPECTED_ARCHIVE_SHA256}, found {actual_archive_sha256}"
        )

    VENDOR_PARENT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".mlkem-native-stage-", dir=VENDOR_PARENT) as temporary:
        staged_paths = stage_archive(archive, Path(temporary))
        replace_staged(staged_paths)

    subprocess.run([sys.executable, os.fspath(VERIFY_SCRIPT)], check=True)
    print(f"updated mlkem-native from commit {UPSTREAM_COMMIT}")


if __name__ == "__main__":
    main()
