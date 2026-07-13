#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Verify the pinned mlkem-native subtree without network access."""

from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath

EXPECTED_FILE_COUNT = 124
EXPECTED_LICENSE_SHA256 = (
    "6393331d41b9fed47a9e18d21b9b844ae8e76bcad8b6da45604c132ae13f3029"
)

CRATE_ROOT = Path(__file__).resolve().parents[1]
VENDOR_ROOT = CRATE_ROOT / "vendor" / "mlkem-native"
INVENTORY_PATH = CRATE_ROOT / "vendor" / "INVENTORY.sha256"
LICENSE_PATH = CRATE_ROOT / "vendor" / "LICENSE.mlkem-native"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"vendor verification failed: {message}")


def validate_inventory_path(raw_path: str) -> PurePosixPath:
    path = PurePosixPath(raw_path)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        fail(f"unsafe inventory path: {raw_path!r}")
    return path


def main() -> None:
    if VENDOR_ROOT.is_symlink():
        fail(f"vendor root must not be a symlink: {VENDOR_ROOT}")
    if not VENDOR_ROOT.is_dir():
        fail(f"missing directory {VENDOR_ROOT}")
    if not INVENTORY_PATH.is_file():
        fail(f"missing inventory {INVENTORY_PATH}")

    filesystem_entries = sorted(VENDOR_ROOT.rglob("*"))
    symlinks = [entry for entry in filesystem_entries if entry.is_symlink()]
    if symlinks:
        fail(f"symlinks are forbidden: {symlinks[0]}")
    non_regular = [
        entry
        for entry in filesystem_entries
        if not entry.is_dir() and not entry.is_file()
    ]
    if non_regular:
        fail(f"non-regular entry is forbidden: {non_regular[0]}")

    actual_files = {
        path.relative_to(VENDOR_ROOT).as_posix(): path
        for path in filesystem_entries
        if path.is_file()
    }
    if len(actual_files) != EXPECTED_FILE_COUNT:
        fail(
            f"expected {EXPECTED_FILE_COUNT} files, found {len(actual_files)}"
        )

    inventory: dict[str, str] = {}
    previous_path = ""
    for line_number, line in enumerate(
        INVENTORY_PATH.read_text(encoding="utf-8").splitlines(), start=1
    ):
        digest, separator, raw_path = line.partition("  ")
        if separator != "  " or len(digest) != 64:
            fail(f"malformed inventory line {line_number}")
        try:
            int(digest, 16)
        except ValueError:
            fail(f"non-hex digest on inventory line {line_number}")
        path = validate_inventory_path(raw_path).as_posix()
        if path <= previous_path:
            fail("inventory paths must be unique and strictly sorted")
        previous_path = path
        inventory[path] = digest

    if set(inventory) != set(actual_files):
        missing = sorted(set(actual_files) - set(inventory))
        extra = sorted(set(inventory) - set(actual_files))
        fail(f"inventory mismatch; missing={missing!r}, extra={extra!r}")

    for relative_path, expected_digest in inventory.items():
        actual_digest = sha256(actual_files[relative_path])
        if actual_digest != expected_digest:
            fail(
                f"hash mismatch for {relative_path}: "
                f"expected {expected_digest}, found {actual_digest}"
            )

    if sha256(LICENSE_PATH) != EXPECTED_LICENSE_SHA256:
        fail("upstream LICENSE hash mismatch")

    print(
        f"verified mlkem-native v1.2.0: {len(actual_files)} files, "
        "no symlinks, all SHA-256 digests match"
    )


if __name__ == "__main__":
    main()
