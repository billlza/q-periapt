#!/usr/bin/env python3
"""Fail closed when release bytes contain private paths or credential material."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
from dataclasses import dataclass
from typing import Iterable

from evidence_io import EvidenceIOError, read_regular_snapshot


MAX_RELEASE_FILE_BYTES = 512 * 1024 * 1024


class ReleaseBinaryScanError(ValueError):
    """A release file cannot be scanned safely or contains forbidden bytes."""


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Digest-bound result for one completely scanned regular file."""

    path: pathlib.Path
    bytes: int
    sha256: str


_DEFAULT_LITERALS = {
    "macOS user home": "/Users/",
    "Linux user home": "/home/",
    "macOS private temporary root": "/private/var/folders/",
    "Windows user home": "C:\\Users\\",
    "GitHub Windows workspace": "D:\\a\\",
    "Windows extended path": "\\\\?\\",
}

_CREDENTIAL_PATTERNS = {
    "private key marker": re.compile(
        rb"-----BEGIN [A-Z0-9 ]{0,64}PRIVATE KEY-----"
    ),
    "AWS access key": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "GitHub token": re.compile(
        rb"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"
    ),
    "bearer credential": re.compile(rb"(?i)bearer[ \t]+[A-Za-z0-9._~+/=-]{16,}"),
    "named token": re.compile(
        rb"(?i)(?:api|auth|access|secret)[_-]?token[ \t]*[:=][ \t]*[^\x00\r\n]{8,}"
    ),
    "named password": re.compile(
        rb"(?i)password[ \t]*[:=][ \t]*[^\x00\r\n]{8,}"
    ),
}

# Wide strings are common in PE resources.  Project them through a bounded
# buffer instead of decoding a second copy of a potentially 512 MiB binary.
# The overlap exceeds the longest minimum credential signature above.
_WIDE_SCAN_WINDOW_CHARS = 8192
_WIDE_SCAN_OVERLAP_CHARS = 256
_WIDE_ASCII_RUN_PATTERNS = {
    "UTF-16LE": (re.compile(rb"(?:[\x01-\x7f]\x00)+"), 0),
    "UTF-16BE": (re.compile(rb"(?:\x00[\x01-\x7f])+"), 1),
}


def _literal_encodings(text: str) -> tuple[bytes, bytes, bytes]:
    try:
        return (
            text.encode("utf-8"),
            text.encode("utf-16-le"),
            text.encode("utf-16-be"),
        )
    except UnicodeEncodeError as exc:
        raise ReleaseBinaryScanError(
            f"forbidden text cannot be encoded canonically: {text!r}"
        ) from exc


def _find_literal(data: bytes, text: str) -> int | None:
    offsets = [offset for encoded in _literal_encodings(text) if (offset := data.find(encoded)) >= 0]
    return min(offsets) if offsets else None


def _first_credential_match(data: bytes) -> tuple[str, int] | None:
    matches = [
        (match.start(), label)
        for label, pattern in _CREDENTIAL_PATTERNS.items()
        if (match := pattern.search(data)) is not None
    ]
    if not matches:
        return None
    offset, label = min(matches)
    return label, offset


def _find_wide_credential(
    data: bytes,
) -> tuple[str, int] | None:
    """Find ASCII-grammar credentials stored as UTF-16LE or UTF-16BE."""

    matches: list[tuple[str, int]] = []
    step = _WIDE_SCAN_WINDOW_CHARS - _WIDE_SCAN_OVERLAP_CHARS
    for run_pattern, character_byte in _WIDE_ASCII_RUN_PATTERNS.values():
        for run in run_pattern.finditer(data):
            run_start, run_end = run.span()
            character_count = (run_end - run_start) // 2
            window_start = 0
            while window_start < character_count:
                window_end = min(
                    character_count, window_start + _WIDE_SCAN_WINDOW_CHARS
                )
                projected = data[
                    run_start + character_byte + window_start * 2 :
                    run_start + character_byte + window_end * 2 :
                    2
                ]
                match = _first_credential_match(projected)
                if match is not None:
                    label, character_offset = match
                    matches.append(
                        (
                            label,
                            run_start + (window_start + character_offset) * 2,
                        )
                    )
                    break
                if window_end == character_count:
                    break
                window_start += step
    return min(matches, key=lambda item: item[1]) if matches else None


def scan_release_file(
    path: pathlib.Path,
    *,
    forbidden_text: Iterable[str] = (),
    maximum: int = MAX_RELEASE_FILE_BYTES,
) -> ScanResult:
    """Scan the exact regular-file snapshot used for the returned digest."""

    try:
        snapshot = read_regular_snapshot(
            pathlib.Path(path), maximum=maximum, label="release binary"
        )
    except EvidenceIOError as exc:
        raise ReleaseBinaryScanError(str(exc)) from exc

    literals = dict(_DEFAULT_LITERALS)
    for index, text in enumerate(forbidden_text):
        if not isinstance(text, str) or not text or "\x00" in text:
            raise ReleaseBinaryScanError(
                f"forbidden text {index} must be a non-empty NUL-free string"
            )
        literals[f"caller-forbidden text {index}"] = text

    for label, text in literals.items():
        offset = _find_literal(snapshot.data, text)
        if offset is not None:
            raise ReleaseBinaryScanError(
                f"release binary contains {label} at byte offset {offset}: {snapshot.path}"
            )

    credential = _first_credential_match(snapshot.data)
    if credential is not None:
        label, offset = credential
        raise ReleaseBinaryScanError(
            f"release binary contains {label} at byte offset {offset}: {snapshot.path}"
        )

    wide_credential = _find_wide_credential(snapshot.data)
    if wide_credential is not None:
        label, offset = wide_credential
        raise ReleaseBinaryScanError(
            f"release binary contains UTF-16 {label} at byte offset {offset}: {snapshot.path}"
        )

    return ScanResult(
        path=snapshot.path,
        bytes=snapshot.size,
        sha256=snapshot.sha256,
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", type=pathlib.Path)
    parser.add_argument(
        "--forbid-text",
        action="append",
        default=[],
        help="additional exact text forbidden in UTF-8, UTF-16LE, and UTF-16BE",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
        results = [
            scan_release_file(path, forbidden_text=args.forbid_text)
            for path in args.files
        ]
    except ReleaseBinaryScanError as exc:
        raise SystemExit(f"error: {exc}") from exc
    print(
        json.dumps(
            {
                "files": [
                    {
                        "bytes": result.bytes,
                        "path": str(result.path),
                        "sha256": result.sha256,
                    }
                    for result in results
                ],
                "status": "pass",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
