#!/usr/bin/env python3
"""Fail closed when release bytes contain private paths or credential material."""

from __future__ import annotations

import argparse
import hashlib
import json
import ntpath
import pathlib
import re
import struct
import sys
from dataclasses import dataclass
from typing import Iterable

from evidence_io import EvidenceIOError, read_regular_snapshot


MAX_RELEASE_FILE_BYTES = 512 * 1024 * 1024
MAX_FORBIDDEN_WINDOWS_PATH_CHARS = 32_767


class ReleaseBinaryScanError(ValueError):
    """A release file cannot be scanned safely or contains forbidden bytes."""


class ReleaseBinaryFinding(ReleaseBinaryScanError):
    """A finding whose category/offset can be reported without private bytes."""

    def __init__(self, label: str, offset: int, path: pathlib.Path, sha256: str,
                 windows_path_matches: tuple[tuple[int, int], ...] = (),
                 archive_location: dict[str, object] | None = None) -> None:
        super().__init__(f"release binary contains {label} at byte offset {offset}: {path}")
        self.label = label
        self.offset = offset
        self.sha256 = sha256
        self.windows_path_matches = windows_path_matches
        self.archive_location = archive_location


def _archive_finding_location(data: bytes, offset: int) -> dict[str, object] | None:
    """Advisory position/hashes only; this never admits an archive or prints its strings."""
    if not data.startswith(b"!<arch>\n"):
        return None
    cursor, index = 8, 0
    while cursor + 60 <= len(data):
        header = data[cursor:cursor + 60]
        length = header[48:58].strip()
        if header[58:] != b"`\n" or not length.isdigit():
            break
        size = int(length)
        start, end = cursor + 60, cursor + 60 + size
        if end > len(data):
            break
        if cursor <= offset < end:
            result: dict[str, object] = {"member_index": index,
                "member_header_sha256": hashlib.sha256(header).hexdigest(),
                "member_sha256": hashlib.sha256(data[start:end]).hexdigest(),
                "offset_in_member": offset - start, "region": "member-header" if offset < start else "member-data"}
            name = header[:16].strip()
            if name in (b"/", b"//", b"/SYM64/"):
                result["region"] = "long-name-table" if name == b"//" else "archive-index"
            elif size >= 20 and data[start:start + 2] == b"\x64\x86":
                _, sections, _, symbols, count, optional, _ = struct.unpack_from("<HHIIIHH", data, start)
                local = offset - start
                if symbols and symbols <= local < symbols + 18 * count <= size:
                    result["region"] = "coff-symbols"
                elif symbols and symbols + 18 * count <= local < size:
                    result["region"] = "coff-string-table-or-trailer"
                if optional == 0 and 20 + 40 * sections <= size:
                    for section in range(sections):
                        raw_name, _, _, raw_size, raw, _, _, _, _, _ = struct.unpack_from(
                            "<8sIIIIIIHHI", data, start + 20 + 40 * section)
                        if raw and raw <= local < raw + raw_size <= size:
                            result["region"] = "coff-section"
                            safe_names = (b".text", b".rdata", b".data", b".bss", b".pdata", b".xdata", b".debug$S", b".debug$T", b".drectve")
                            label = raw_name.rstrip(b"\0")
                            result["section"] = label.decode("ascii") if label in safe_names else "other"
                            break
            return result
        cursor = end + size % 2
        index += 1
    return {"region": "unclassified-archive-position"}


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
}

_WINDOWS_BYTE_COMPONENT = r'[^\\/\x00-\x1f<>:"|?*]'
_WINDOWS_TEXT_COMPONENT = r'[^\\/\x00-\x1f<>:"|?*]'
_WINDOWS_PATH_BOUNDARY = r'(?=[\\/\x00-\x1f<>:"|?* ]|$)'

_WINDOWS_PRIVATE_PATH_PATTERN_SOURCES = {
    "Windows user home": r"[A-Z]:[\\/]Users[\\/]",
    "MSYS Windows user home": r"/[A-Z]/Users/",
    "GitHub Windows workspace": r"D:[\\/]a[\\/]",
    "MSYS GitHub Windows workspace": r"/D/a/",
    "Windows extended drive path": (
        rf"[\\/]{{2}}\?[\\/][A-Z]:[\\/]{_WINDOWS_BYTE_COMPONENT}"
    ),
    "Windows extended UNC path": (
        rf"[\\/]{{2}}\?[\\/]UNC[\\/]"
        rf"{_WINDOWS_BYTE_COMPONENT}{{1,1020}}[\\/]"
        rf"{_WINDOWS_BYTE_COMPONENT}{{1,320}}"
        rf"{_WINDOWS_PATH_BOUNDARY}"
    ),
    "Windows extended namespace path": (
        rf"[\\/]{{2}}\?[\\/](?!UNC[\\/])"
        rf"{_WINDOWS_BYTE_COMPONENT}{{1,1020}}[\\/]"
        rf"{_WINDOWS_BYTE_COMPONENT}"
    ),
}
_WINDOWS_LOCAL_PATH_PATTERNS = {
    label: re.compile(source.encode("ascii"), re.IGNORECASE | re.ASCII)
    for label, source in _WINDOWS_PRIVATE_PATH_PATTERN_SOURCES.items()
    if not label.startswith("Windows extended")
}
_WINDOWS_EXTENDED_BYTE_PATTERNS = {
    label: re.compile(source.encode("ascii"), re.IGNORECASE | re.ASCII)
    for label, source in _WINDOWS_PRIVATE_PATH_PATTERN_SOURCES.items()
    if label.startswith("Windows extended")
}
_WINDOWS_EXTENDED_BYTE_GROUP_LABELS = {
    f"extended_path_{index}": label
    for index, label in enumerate(_WINDOWS_EXTENDED_BYTE_PATTERNS)
}
_WINDOWS_EXTENDED_BYTE_PATTERN = re.compile(
    b"|".join(
        b"(?P<"
        + group.encode("ascii")
        + b">"
        + _WINDOWS_PRIVATE_PATH_PATTERN_SOURCES[label].encode("ascii")
        + b")"
        for group, label in _WINDOWS_EXTENDED_BYTE_GROUP_LABELS.items()
    ),
    re.IGNORECASE | re.ASCII,
)
_WINDOWS_PATH_PREFILTER = re.compile(
    rb"(?i:Users|D:[\\/]|/D/a/|[\\/]{2}\?[\\/])",
    re.ASCII,
)
_WINDOWS_EXTENDED_TEXT_PATTERN_SOURCES = {
    "Windows extended drive path": (
        rf"[\\/]{{2}}\?[\\/][A-Z]:[\\/]{_WINDOWS_TEXT_COMPONENT}"
    ),
    "Windows extended UNC path": (
        rf"[\\/]{{2}}\?[\\/]UNC[\\/]"
        rf"{_WINDOWS_TEXT_COMPONENT}{{1,255}}[\\/]"
        rf"{_WINDOWS_TEXT_COMPONENT}{{1,80}}"
        rf"{_WINDOWS_PATH_BOUNDARY}"
    ),
    "Windows extended namespace path": (
        rf"[\\/]{{2}}\?[\\/](?!UNC[\\/])"
        rf"{_WINDOWS_TEXT_COMPONENT}{{1,255}}[\\/]"
        rf"{_WINDOWS_TEXT_COMPONENT}"
    ),
}
_WINDOWS_EXTENDED_TEXT_PATTERNS = {
    label: re.compile(source, re.IGNORECASE | re.ASCII)
    for label, source in _WINDOWS_EXTENDED_TEXT_PATTERN_SOURCES.items()
}

_WINDOWS_EXTENDED_MARKERS = tuple(
    first + second + "?" + third
    for first in "\\/"
    for second in "\\/"
    for third in "\\/"
)
_WIDE_WINDOWS_EXTENDED_MARKERS = {
    encoding: re.compile(
        b"|".join(
            re.escape(marker.encode(encoding))
            for marker in _WINDOWS_EXTENDED_MARKERS
        )
    )
    for encoding in ("utf-16-le", "utf-16-be")
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
_CREDENTIAL_PREFILTER = re.compile(
    rb"(?i:-----BEGIN|AKIA|gh[pousr]_|github_pat_|bearer[ \t]|"
    rb"(?:api|auth|access|secret)[_-]?token|password[ \t]*[:=])",
    re.ASCII,
)
# Wide strings are common in PE resources.  Project them through a bounded
# buffer instead of decoding a second copy of a potentially 512 MiB binary.
# The path overlap exceeds the longest bounded ASCII path grammar above.
_WIDE_SCAN_WINDOW_CHARS = 8192
_WIDE_PATH_SCAN_OVERLAP_CHARS = 2048
_WIDE_EXTENDED_PATH_WINDOW_CODE_UNITS = 1024
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


def _normalize_forbidden_windows_path(text: str, index: int) -> str:
    if (
        not isinstance(text, str)
        or not text
        or len(text) > MAX_FORBIDDEN_WINDOWS_PATH_CHARS
        or not text.isascii()
        or not text.isprintable()
        or "\x00" in text
    ):
        raise ReleaseBinaryScanError(
            f"forbidden Windows path {index} must be non-empty printable ASCII "
            f"of at most {MAX_FORBIDDEN_WINDOWS_PATH_CHARS} characters"
        )
    windows_text = text.replace("/", "\\")
    if windows_text.startswith(("\\\\?\\", "\\\\.\\", "\\??\\")):
        raise ReleaseBinaryScanError(
            f"forbidden Windows path {index} must not use a device or namespace prefix"
        )
    normalized = ntpath.normpath(text)
    drive, tail = ntpath.splitdrive(normalized)
    if not drive or tail in ("", "\\", "/") or not ntpath.isabs(normalized):
        raise ReleaseBinaryScanError(
            f"forbidden Windows path {index} must be an absolute non-volume-root path"
        )
    comparable_input = windows_text.rstrip("\\")
    comparable_normalized = normalized.replace("/", "\\").rstrip("\\")
    if re.fullmatch(r"[A-Za-z]:", drive, re.ASCII) is not None:
        root_components: list[str] = []
    elif drive.startswith("\\\\"):
        root_components = drive[2:].split("\\")
        if len(root_components) != 2 or any(not value for value in root_components):
            raise ReleaseBinaryScanError(
                f"forbidden Windows path {index} must use a canonical UNC root"
            )
    else:
        raise ReleaseBinaryScanError(
            f"forbidden Windows path {index} must use an ordinary drive or UNC root"
        )
    components = root_components + [
        component for component in tail.split("\\") if component
    ]
    if (
        ntpath.normcase(comparable_input)
        != ntpath.normcase(comparable_normalized)
        or any(
            component in (".", "..")
            or component.endswith(".")
            or component.endswith(" ")
            or any(character in '<>:"|?*' for character in component)
            for component in components
        )
    ):
        raise ReleaseBinaryScanError(
            f"forbidden Windows path {index} must use canonical path components"
        )
    return normalized


def _windows_path_spellings(path: str) -> tuple[str, ...]:
    spellings = [path]
    drive, tail = ntpath.splitdrive(path)
    if re.fullmatch(r"[A-Za-z]:", drive, re.ASCII) is not None:
        tail_without_separator = tail.lstrip("\\/")
        spellings.append(f"/{drive[0]}/{tail_without_separator}")
    return tuple(spellings)


def _windows_path_pattern(path: str, encoding: str) -> re.Pattern[bytes]:
    pieces: list[bytes] = []
    for character in path:
        if character in "\\/":
            pieces.append(
                b"(?:"
                + re.escape("\\".encode(encoding))
                + b"|"
                + re.escape("/".encode(encoding))
                + b")"
            )
        else:
            pieces.append(re.escape(character.encode(encoding)))
    return re.compile(b"".join(pieces), re.IGNORECASE | re.ASCII)


def _find_windows_path(data: bytes, path: str) -> int | None:
    matches: list[int] = []
    for spelling in _windows_path_spellings(path):
        for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
            match = _windows_path_pattern(spelling, encoding).search(data)
            if match is not None:
                matches.append(match.start())
    return min(matches) if matches else None


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


def _first_windows_private_path_match(data: bytes) -> tuple[str, int] | None:
    matches = [
        (match.start(), label)
        for label, pattern in _WINDOWS_LOCAL_PATH_PATTERNS.items()
        if (match := pattern.search(data)) is not None
    ]
    extended = _WINDOWS_EXTENDED_BYTE_PATTERN.search(data)
    if extended is not None and extended.lastgroup is not None:
        matches.append(
            (
                extended.start(),
                _WINDOWS_EXTENDED_BYTE_GROUP_LABELS[extended.lastgroup],
            )
        )
    if not matches:
        return None
    offset, label = min(matches)
    return label, offset


def _first_sensitive_match(data: bytes) -> tuple[str, int] | None:
    matches = [
        match
        for match in (
            _first_windows_private_path_match(data),
            _first_credential_match(data),
        )
        if match is not None
    ]
    return min(matches, key=lambda item: item[1]) if matches else None


def _first_prefiltered_sensitive_match(data: bytes) -> tuple[str, int] | None:
    matches: list[tuple[str, int]] = []
    if _WINDOWS_PATH_PREFILTER.search(data) is not None:
        path_match = _first_windows_private_path_match(data)
        if path_match is not None:
            matches.append(path_match)
    if _CREDENTIAL_PREFILTER.search(data) is not None:
        credential_match = _first_credential_match(data)
        if credential_match is not None:
            matches.append(credential_match)
    return min(matches, key=lambda item: item[1]) if matches else None


def _first_windows_extended_text_match(text: str) -> tuple[str, int] | None:
    matches = [
        (match.start(), label)
        for label, pattern in _WINDOWS_EXTENDED_TEXT_PATTERNS.items()
        if (match := pattern.search(text)) is not None
    ]
    if not matches:
        return None
    offset, label = min(matches)
    return label, offset


def _find_wide_ascii_sensitive_match(
    data: bytes,
) -> tuple[str, int] | None:
    """Scan genuine interleaved-ASCII UTF-16 runs once for all grammars."""

    best: tuple[str, int] | None = None
    step = _WIDE_SCAN_WINDOW_CHARS - _WIDE_PATH_SCAN_OVERLAP_CHARS
    for run_pattern, character_byte in _WIDE_ASCII_RUN_PATTERNS.values():
        for run in run_pattern.finditer(data):
            run_start, run_end = run.span()
            character_count = (run_end - run_start) // 2
            window_start = 0
            while window_start < character_count:
                window_end = min(
                    character_count,
                    window_start + _WIDE_SCAN_WINDOW_CHARS,
                )
                projected = data[
                    run_start + character_byte + window_start * 2 :
                    run_start + character_byte + window_end * 2 :
                    2
                ]
                match = _first_prefiltered_sensitive_match(projected)
                if match is not None:
                    label, character_offset = match
                    candidate = (
                        label,
                        run_start + (window_start + character_offset) * 2,
                    )
                    if best is None or candidate[1] < best[1]:
                        best = candidate
                    break
                if window_end == character_count:
                    break
                window_start += step
    return best


def _find_wide_extended_windows_private_path(
    data: bytes,
) -> tuple[str, int] | None:
    """Scan fixed UTF-16 windows for extended paths in linear bounded work.

    A bare namespace marker is common machine-code data. Decode at most one
    bounded copy per window/alignment/endianness, even when such markers are
    dense, instead of allocating once per marker. The overlap exceeds the
    longest accepted extended-path grammar, including surrogate pairs.
    """

    matches: list[tuple[str, int]] = []
    overlap = _WIDE_EXTENDED_PATH_WINDOW_CODE_UNITS
    step = _WIDE_SCAN_WINDOW_CHARS - overlap
    for encoding, marker_pattern in _WIDE_WINDOWS_EXTENDED_MARKERS.items():
        for alignment in (0, 1):
            code_units = (len(data) - alignment) // 2
            window_start = 0
            while window_start < code_units:
                window_end = min(
                    code_units,
                    window_start + _WIDE_SCAN_WINDOW_CHARS,
                )
                raw_start = alignment + window_start * 2
                raw_end = alignment + window_end * 2
                raw = data[raw_start:raw_end]
                if not any(
                    marker.start() % 2 == 0
                    for marker in marker_pattern.finditer(raw)
                ):
                    if window_end == code_units:
                        break
                    window_start += step
                    continue
                decoded = raw.decode(encoding, errors="surrogatepass")
                match = _first_windows_extended_text_match(decoded)
                if match is not None:
                    label, character_offset = match
                    byte_offset = len(
                        decoded[:character_offset].encode(
                            encoding,
                            errors="surrogatepass",
                        )
                    )
                    matches.append((label, raw_start + byte_offset))
                if window_end == code_units:
                    break
                window_start += step
    return min(matches, key=lambda item: item[1]) if matches else None


def scan_release_file(
    path: pathlib.Path,
    *,
    forbidden_text: Iterable[str] = (),
    forbidden_windows_paths: Iterable[str] = (),
    maximum: int = MAX_RELEASE_FILE_BYTES,
    collect_windows_matches: bool = False,
) -> ScanResult:
    """Scan the exact regular-file snapshot used for the returned digest."""

    try:
        snapshot = read_regular_snapshot(
            pathlib.Path(path), maximum=maximum, label="release binary"
        )
    except EvidenceIOError as exc:
        raise ReleaseBinaryScanError(str(exc)) from exc

    def finding(label: str, offset: int, matches: tuple[tuple[int, int], ...] = ()) -> ReleaseBinaryFinding:
        return ReleaseBinaryFinding(label, offset, snapshot.path, snapshot.sha256, matches,
            _archive_finding_location(snapshot.data, offset) if collect_windows_matches else None)

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
            raise finding(label, offset)

    windows_matches = []
    for index, text in enumerate(forbidden_windows_paths):
        normalized = _normalize_forbidden_windows_path(text, index)
        offset = _find_windows_path(snapshot.data, normalized)
        if offset is not None:
            if collect_windows_matches:
                windows_matches.append((index, offset))
                continue
            raise finding(f"caller-forbidden Windows path {index}", offset)
    if windows_matches:
        index, offset = windows_matches[0]
        raise finding(f"caller-forbidden Windows path {index}", offset, tuple(windows_matches))

    sensitive = _first_sensitive_match(snapshot.data)
    if sensitive is not None:
        label, offset = sensitive
        raise finding(label, offset)

    wide_ascii_sensitive = _find_wide_ascii_sensitive_match(snapshot.data)
    if wide_ascii_sensitive is not None:
        label, offset = wide_ascii_sensitive
        raise finding(f"UTF-16 {label}", offset)

    wide_extended_path = _find_wide_extended_windows_private_path(snapshot.data)
    if wide_extended_path is not None:
        label, offset = wide_extended_path
        raise finding(f"UTF-16 {label}", offset)

    return ScanResult(
        path=snapshot.path,
        bytes=snapshot.size,
        sha256=snapshot.sha256,
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", type=pathlib.Path)
    parser.add_argument("--redact-paths", action="store_true",
                        help="report only file indices, hashes and finding categories/offsets")
    parser.add_argument(
        "--forbid-text",
        action="append",
        default=[],
        help="additional exact text forbidden in UTF-8, UTF-16LE, and UTF-16BE",
    )
    parser.add_argument(
        "--forbid-windows-path",
        action="append",
        default=[],
        help=(
            "additional absolute ASCII Windows path forbidden case-insensitively "
            "with native, portable, and MSYS drive separators"
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    results = []
    file_index = 0
    try:
        for file_index, path in enumerate(args.files):
            results.append(scan_release_file(
                path,
                forbidden_text=args.forbid_text,
                forbidden_windows_paths=args.forbid_windows_path,
                collect_windows_matches=args.redact_paths,
            ))
    except ReleaseBinaryScanError as exc:
        if args.redact_paths:
            # Labels are scanner-owned categories, never matching byte strings
            # or user-selected paths. Input errors do not expose exception text.
            diagnostic = {"status": "fail", "file_index": file_index,
                          "reason": "scan-input-rejected"}
            if isinstance(exc, ReleaseBinaryFinding):
                diagnostic.update(reason=exc.label, byte_offset=exc.offset, sha256=exc.sha256)
                if exc.windows_path_matches:
                    diagnostic["matched_windows_paths"] = [
                        {"index": index, "byte_offset": offset} for index, offset in exc.windows_path_matches]
                if exc.archive_location is not None:
                    diagnostic["archive_location"] = exc.archive_location
            print(json.dumps(diagnostic, sort_keys=True, separators=(",", ":")), file=sys.stderr)
            return 1
        raise SystemExit(f"error: {exc}") from exc
    print(
        json.dumps(
            {
                "files": [
                    {
                        "bytes": result.bytes,
                        **({"file_index": index} if args.redact_paths else {"path": str(result.path)}),
                        "sha256": result.sha256,
                    }
                    for index, result in enumerate(results)
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
