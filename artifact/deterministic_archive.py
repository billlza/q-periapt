#!/usr/bin/env python3
"""Create, audit, and safely extract deterministic release archives.

The module deliberately supports a small archive dialect instead of accepting
every feature implemented by tar or ZIP readers.  Release archives contain one
explicit top-level directory, ordinary directories, and ordinary files only.
All metadata and container framing are canonical so an archive that audits
successfully has one unambiguous interpretation on POSIX and Windows hosts.
Callers must control the existing parent-directory chain against concurrent
replacement and pass its canonical physical path when the operating system
exposes an alias such as macOS ``/var``.  The implementation rejects every
observed ancestor symlink and uses no-replace commits for the caller-visible
archive or extraction target.
"""

from __future__ import annotations

import argparse
import binascii
import datetime as dt
import hashlib
import io
import os
import pathlib
import re
import shutil
import stat
import struct
import unicodedata
import zipfile
import zlib
from dataclasses import dataclass
from typing import Iterable, Literal, NoReturn

from evidence_io import EvidenceIOError, read_regular_snapshot


_BLOCK_SIZE = 512
_TAR_END = b"\0" * (_BLOCK_SIZE * 2)
_GZIP_HEADER_PREFIX = b"\x1f\x8b\x08\x00"
_GZIP_HEADER_SUFFIX = b"\x02\xff"
_ZIP_EOCD = struct.Struct("<4s4H2LH")
_ZIP_LOCAL = struct.Struct("<4s5H3L2H")
_ZIP_CENTRAL = struct.Struct("<4s6H3L5H2L")
_ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP_LOCAL_SIGNATURE = b"PK\x03\x04"
_ZIP_CENTRAL_SIGNATURE = b"PK\x01\x02"
_DRIVE_PATH = re.compile(r"^[A-Za-z]:")
_WINDOWS_RESERVED = re.compile(
    r"^(?:CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|COM[1-9]|LPT[1-9])"
    r"(?:\..*)?$",
    re.IGNORECASE,
)


class DeterministicArchiveError(ValueError):
    """Archive input or output violates the deterministic release contract."""


@dataclass(frozen=True, slots=True)
class ArchiveLimits:
    """Hard resource bounds applied before extraction writes any bytes."""

    maximum_archive_bytes: int = 128 * 1024 * 1024
    maximum_member_count: int = 8192
    maximum_member_bytes: int = 64 * 1024 * 1024
    maximum_total_bytes: int = 128 * 1024 * 1024

    def validate(self) -> None:
        for name, value in (
            ("maximum_archive_bytes", self.maximum_archive_bytes),
            ("maximum_member_count", self.maximum_member_count),
            ("maximum_member_bytes", self.maximum_member_bytes),
            ("maximum_total_bytes", self.maximum_total_bytes),
        ):
            if type(value) is not int or value <= 0:
                raise DeterministicArchiveError(f"{name} must be a positive integer")


DEFAULT_LIMITS = ArchiveLimits()


@dataclass(frozen=True, slots=True)
class ArchiveEntry:
    """One audited directory or regular file."""

    path: str
    kind: Literal["directory", "file"]
    mode: int
    size: int
    sha256: str | None


@dataclass(frozen=True, slots=True)
class ArchiveAudit:
    """Digest-bound summary of one fully audited archive snapshot."""

    format: Literal["tar.gz", "zip"]
    archive_sha256: str
    archive_bytes: int
    mtime: int
    entries: tuple[ArchiveEntry, ...]


@dataclass(frozen=True, slots=True)
class _MaterializedEntry:
    path: str
    kind: Literal["directory", "file"]
    mode: int
    data: bytes


def _fail(message: str) -> NoReturn:
    raise DeterministicArchiveError(message)


def _validate_limits(limits: ArchiveLimits) -> None:
    if not isinstance(limits, ArchiveLimits):
        _fail("limits must be an ArchiveLimits instance")
    limits.validate()


def _validate_mtime(value: int) -> int:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        _fail("archive mtime must be an unsigned 32-bit integer")
    return value


def _safe_component(component: str, label: str) -> None:
    if not component or component in {".", ".."}:
        _fail(f"{label} contains an empty or traversal component")
    if component[-1:] in {" ", "."}:
        _fail(f"{label} contains a Windows-ambiguous trailing character")
    if any(character in '<>:"|?*' for character in component):
        _fail(f"{label} contains a Windows-invalid character")
    if _WINDOWS_RESERVED.fullmatch(component) is not None:
        _fail(f"{label} contains a Windows reserved name")


def _canonical_archive_path(value: str, label: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{label} must be a non-empty string")
    if value != unicodedata.normalize("NFC", value):
        _fail(f"{label} is not Unicode NFC")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        _fail(f"{label} contains a control character")
    if "\\" in value:
        _fail(f"{label} contains a backslash")
    if value.startswith("/") or value.startswith("//") or _DRIVE_PATH.match(value):
        _fail(f"{label} is absolute, UNC, or drive-qualified")
    if value.endswith("/") or "//" in value:
        _fail(f"{label} is not a canonical POSIX path")
    pure = pathlib.PurePosixPath(value)
    if pure.as_posix() != value:
        _fail(f"{label} is not a canonical POSIX path")
    for component in pure.parts:
        _safe_component(component, label)
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise DeterministicArchiveError(
            f"{label} must use portable ASCII release names"
        ) from exc
    return value


def _validate_root_name(root_name: str) -> str:
    canonical = _canonical_archive_path(root_name, "archive root")
    if "/" in canonical:
        _fail("archive root must be one safe path component")
    return canonical


class _PathRegistry:
    def __init__(self, root_name: str) -> None:
        self.root_name = root_name
        self._portable: dict[str, str] = {}
        self._kinds: dict[str, str] = {}

    def add(self, path: str, kind: Literal["directory", "file"]) -> str:
        canonical = _canonical_archive_path(path, "archive member path")
        parts = pathlib.PurePosixPath(canonical).parts
        if not parts or parts[0] != self.root_name:
            _fail(f"archive member is outside exact root {self.root_name}: {canonical}")
        portable = unicodedata.normalize("NFC", canonical).casefold()
        previous = self._portable.get(portable)
        if previous is not None:
            _fail(
                "archive contains duplicate or normalized-duplicate members: "
                f"{previous}, {canonical}"
            )
        for index in range(1, len(parts)):
            parent = "/".join(parts[:index])
            parent_kind = self._kinds.get(parent)
            if parent_kind != "directory":
                _fail(f"archive member parent is missing or not a directory: {canonical}")
        self._portable[portable] = canonical
        self._kinds[canonical] = kind
        return canonical


def _snapshot_file(path: pathlib.Path, limits: ArchiveLimits, label: str) -> bytes:
    try:
        snapshot = read_regular_snapshot(path, maximum=limits.maximum_member_bytes, label=label)
    except EvidenceIOError as exc:
        raise DeterministicArchiveError(str(exc)) from exc
    return snapshot.data


def _source_entries(
    source_dir: pathlib.Path,
    root_name: str,
    limits: ArchiveLimits,
) -> tuple[_MaterializedEntry, ...]:
    _validate_limits(limits)
    root_name = _validate_root_name(root_name)
    source = pathlib.Path(source_dir)
    try:
        source_metadata = source.lstat()
    except OSError as exc:
        raise DeterministicArchiveError(f"cannot inspect archive source {source}: {exc}") from exc
    if source.is_symlink() or not stat.S_ISDIR(source_metadata.st_mode):
        _fail(f"archive source must be a non-symlink directory: {source}")

    gathered: list[tuple[str, Literal["directory", "file"], pathlib.Path]] = []

    def walk_error(error: OSError) -> NoReturn:
        raise DeterministicArchiveError(
            f"cannot enumerate archive source {source}: {error}"
        ) from error

    try:
        for directory, directory_names, file_names in os.walk(
            source, followlinks=False, onerror=walk_error
        ):
            directory_path = pathlib.Path(directory)
            directory_names.sort()
            file_names.sort()
            for name in directory_names:
                candidate = directory_path / name
                metadata = candidate.lstat()
                if candidate.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                    _fail(
                        "archive source contains a symlink or special directory: "
                        f"{candidate}"
                    )
                relative = candidate.relative_to(source).as_posix()
                _canonical_archive_path(relative, "source relative path")
                gathered.append((relative, "directory", candidate))
                if len(gathered) + 1 > limits.maximum_member_count:
                    _fail("archive source contains too many members")
            for name in file_names:
                candidate = directory_path / name
                metadata = candidate.lstat()
                if candidate.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                    _fail(
                        f"archive source contains a symlink or special file: {candidate}"
                    )
                relative = candidate.relative_to(source).as_posix()
                _canonical_archive_path(relative, "source relative path")
                gathered.append((relative, "file", candidate))
                if len(gathered) + 1 > limits.maximum_member_count:
                    _fail("archive source contains too many members")
    except OSError as exc:
        raise DeterministicArchiveError(
            f"cannot enumerate archive source {source}: {exc}"
        ) from exc

    gathered.sort(key=lambda item: item[0].encode("ascii"))
    if len(gathered) + 1 > limits.maximum_member_count:
        _fail("archive source contains too many members")

    entries = [_MaterializedEntry(root_name, "directory", 0o755, b"")]
    total = 0
    registry = _PathRegistry(root_name)
    registry.add(root_name, "directory")
    for relative, kind, candidate in gathered:
        archive_path = f"{root_name}/{relative}"
        registry.add(archive_path, kind)
        if kind == "file":
            data = _snapshot_file(candidate, limits, f"archive source file {relative}")
            total += len(data)
            if total > limits.maximum_total_bytes:
                _fail("archive source logical contents exceed the total size limit")
            entries.append(_MaterializedEntry(archive_path, kind, 0o644, data))
        else:
            entries.append(_MaterializedEntry(archive_path, kind, 0o755, b""))
    return tuple(entries)


def _validated_output_target(path: pathlib.Path, label: str) -> pathlib.Path:
    raw = pathlib.Path(path)
    if raw.name in {"", ".", ".."} or ".." in raw.parts:
        _fail(f"{label} must be one unambiguous child path")
    absolute = raw if raw.is_absolute() else pathlib.Path.cwd() / raw
    parent = absolute.parent
    if not parent.anchor:
        _fail(f"{label} parent must have an absolute anchor")
    current = pathlib.Path(parent.anchor)
    try:
        for component in parent.parts[1:]:
            if component in {"", ".", ".."}:
                _fail(f"{label} parent contains an ambiguous path component")
            current /= component
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                _fail(
                    f"{label} parent chain must contain only non-symlink "
                    f"directories: {current}"
                )
    except DeterministicArchiveError:
        raise
    except OSError as exc:
        raise DeterministicArchiveError(
            f"{label} parent chain is unavailable at {current}: {exc}"
        ) from exc
    return parent / raw.name


def _write_atomic(path: pathlib.Path, data: bytes) -> None:
    output = _validated_output_target(pathlib.Path(path), "archive output")
    parent = output.parent
    if output.exists() or output.is_symlink():
        _fail(f"archive output already exists: {output}")
    temporary = parent / f".{output.name}.tmp-{os.getpid()}"
    if temporary.exists() or temporary.is_symlink():
        _fail(f"archive temporary output already exists: {temporary}")
    try:
        with temporary.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        # A hard-link commit is atomic and, unlike os.replace(), never clobbers
        # an output created by another process after the initial check.
        os.link(temporary, output)
        temporary.unlink()
    except OSError as exc:
        cleanup_error: OSError | None = None
        try:
            temporary.unlink(missing_ok=True)
        except OSError as cleanup_exc:
            cleanup_error = cleanup_exc
        suffix = f"; temporary-file cleanup also failed: {cleanup_error}" if cleanup_error else ""
        raise DeterministicArchiveError(
            f"cannot create archive {output}: {exc}{suffix}"
        ) from exc


def _octal(value: int, length: int) -> bytes:
    if value < 0:
        _fail("tar numeric fields cannot be negative")
    encoded = f"{value:0{length - 1}o}".encode("ascii")
    if len(encoded) != length - 1:
        _fail("tar numeric field exceeds USTAR range")
    return encoded + b"\0"


def _ustar_name(path: str) -> tuple[bytes, bytes]:
    encoded = path.encode("ascii")
    # Our canonical parser requires the USTAR name and prefix fields to be
    # NUL-terminated.  Reserve one byte in each field instead of emitting the
    # ambiguous full-width form accepted by some tar implementations.
    if len(encoded) <= 99:
        return encoded, b""
    slash_positions = [index for index, byte in enumerate(encoded) if byte == ord("/")]
    for index in reversed(slash_positions):
        prefix = encoded[:index]
        name = encoded[index + 1 :]
        if name and len(name) <= 99 and len(prefix) <= 154:
            return name, prefix
    _fail(f"archive path exceeds deterministic USTAR limits: {path}")


def _tar_header(entry: _MaterializedEntry, mtime: int) -> bytes:
    name, prefix = _ustar_name(entry.path)
    header = bytearray(_BLOCK_SIZE)
    header[0 : len(name)] = name
    header[100:108] = _octal(entry.mode, 8)
    header[108:116] = _octal(0, 8)
    header[116:124] = _octal(0, 8)
    header[124:136] = _octal(len(entry.data), 12)
    header[136:148] = _octal(mtime, 12)
    header[148:156] = b"        "
    header[156:157] = b"5" if entry.kind == "directory" else b"0"
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    header[329:337] = _octal(0, 8)
    header[337:345] = _octal(0, 8)
    header[345 : 345 + len(prefix)] = prefix
    checksum = sum(header)
    checksum_bytes = f"{checksum:06o}\0 ".encode("ascii")
    if len(checksum_bytes) != 8:
        _fail("tar checksum exceeds USTAR range")
    header[148:156] = checksum_bytes
    return bytes(header)


def _tar_bytes(entries: Iterable[_MaterializedEntry], mtime: int) -> bytes:
    output = io.BytesIO()
    for entry in entries:
        output.write(_tar_header(entry, mtime))
        if entry.kind == "file":
            output.write(entry.data)
            padding = (-len(entry.data)) % _BLOCK_SIZE
            if padding:
                output.write(b"\0" * padding)
    output.write(_TAR_END)
    return output.getvalue()


def _gzip_bytes(payload: bytes, mtime: int) -> bytes:
    compressor = zlib.compressobj(level=9, wbits=-zlib.MAX_WBITS)
    compressed = compressor.compress(payload) + compressor.flush(zlib.Z_FINISH)
    header = _GZIP_HEADER_PREFIX + struct.pack("<L", mtime) + _GZIP_HEADER_SUFFIX
    trailer = struct.pack("<LL", binascii.crc32(payload) & 0xFFFFFFFF, len(payload) & 0xFFFFFFFF)
    return header + compressed + trailer


def create_tar_gz(
    source_dir: pathlib.Path,
    output: pathlib.Path,
    *,
    root_name: str,
    mtime: int,
    limits: ArchiveLimits = DEFAULT_LIMITS,
) -> ArchiveAudit:
    """Create one deterministic USTAR-in-gzip archive and audit final bytes."""

    mtime = _validate_mtime(mtime)
    entries = _source_entries(source_dir, root_name, limits)
    archive_data = _gzip_bytes(_tar_bytes(entries, mtime), mtime)
    if len(archive_data) > limits.maximum_archive_bytes:
        _fail("created tar.gz exceeds the archive size limit")
    audit = _audit_tar_snapshot(archive_data, root_name, mtime, limits)
    _write_atomic(pathlib.Path(output), archive_data)
    return audit


def _decode_null_field(field: bytes, label: str) -> bytes:
    try:
        end = field.index(0)
    except ValueError as exc:
        raise DeterministicArchiveError(f"tar {label} is not NUL terminated") from exc
    if any(field[end + 1 :]):
        _fail(f"tar {label} has nonzero padding")
    return field[:end]


def _parse_octal(field: bytes, label: str) -> int:
    if (
        not field.endswith(b"\0")
        or not field[:-1]
        or any(byte not in b"01234567" for byte in field[:-1])
    ):
        _fail(f"tar {label} is not canonical NUL-terminated octal")
    return int(field[:-1], 8)


def _parse_tar(
    payload: bytes,
    root_name: str,
    expected_mtime: int | None,
    limits: ArchiveLimits,
) -> tuple[int, tuple[_MaterializedEntry, ...]]:
    if len(payload) < len(_TAR_END) or len(payload) % _BLOCK_SIZE:
        _fail("tar payload is truncated or not block aligned")
    entries: list[_MaterializedEntry] = []
    registry = _PathRegistry(root_name)
    offset = 0
    total = 0
    common_mtime: int | None = None
    while offset < len(payload):
        header = payload[offset : offset + _BLOCK_SIZE]
        if header == b"\0" * _BLOCK_SIZE:
            if payload[offset:] != _TAR_END:
                _fail("tar must end with exactly two zero blocks and no trailing data")
            offset = len(payload)
            break
        if len(entries) >= limits.maximum_member_count:
            _fail("tar contains too many members")
        if header[257:263] != b"ustar\0" or header[263:265] != b"00":
            _fail("tar member is not canonical USTAR")
        if any(header[157:257]) or any(header[265:329]) or any(header[500:512]):
            _fail("tar member contains unsupported link, owner, or extension metadata")
        if header[329:337] != _octal(0, 8) or header[337:345] != _octal(0, 8):
            _fail("tar device fields are not canonical zero values")
        stored_checksum = header[148:156]
        checksum_header = bytearray(header)
        checksum_header[148:156] = b"        "
        expected_checksum = f"{sum(checksum_header):06o}\0 ".encode("ascii")
        if stored_checksum != expected_checksum:
            _fail("tar header checksum is invalid or noncanonical")
        name = _decode_null_field(header[0:100], "name")
        prefix = _decode_null_field(header[345:500], "prefix")
        if not name:
            _fail("tar member name is empty")
        raw_path = prefix + (b"/" if prefix else b"") + name
        try:
            path = raw_path.decode("ascii")
        except UnicodeDecodeError as exc:
            raise DeterministicArchiveError("tar member path is not portable ASCII") from exc
        expected_name, expected_prefix = _ustar_name(path)
        if name != expected_name or prefix != expected_prefix:
            _fail("tar member path fields do not use the canonical USTAR split")
        typeflag = header[156:157]
        if typeflag == b"5":
            kind: Literal["directory", "file"] = "directory"
            mode = 0o755
        elif typeflag == b"0":
            kind = "file"
            mode = 0o644
        else:
            _fail("tar contains a symlink, hardlink, sparse, or special member")
        if header[100:108] != _octal(mode, 8):
            _fail(f"tar {kind} mode is not canonical")
        if header[108:116] != _octal(0, 8) or header[116:124] != _octal(0, 8):
            _fail("tar uid/gid are not canonical zero values")
        size = _parse_octal(header[124:136], "size")
        member_mtime = _parse_octal(header[136:148], "mtime")
        if header[124:136] != _octal(size, 12) or header[136:148] != _octal(member_mtime, 12):
            _fail("tar numeric metadata is not canonically padded")
        if expected_mtime is not None and member_mtime != expected_mtime:
            _fail("tar member mtime differs from the expected source epoch")
        if common_mtime is None:
            common_mtime = member_mtime
        elif member_mtime != common_mtime:
            _fail("tar member mtimes are inconsistent")
        if kind == "directory" and size != 0:
            _fail("tar directory has a nonzero payload")
        if size > limits.maximum_member_bytes:
            _fail(f"tar member exceeds the per-member size limit: {path}")
        offset += _BLOCK_SIZE
        end = offset + size
        padded_end = end + ((-size) % _BLOCK_SIZE)
        if padded_end > len(payload):
            _fail(f"tar member payload is truncated: {path}")
        data = payload[offset:end]
        if any(payload[end:padded_end]):
            _fail(f"tar member padding is nonzero: {path}")
        registry.add(path, kind)
        total += size
        if total > limits.maximum_total_bytes:
            _fail("tar logical contents exceed the total size limit")
        entries.append(_MaterializedEntry(path, kind, mode, data))
        offset = padded_end
    if offset != len(payload) or not entries:
        _fail("tar is empty or lacks its canonical end marker")
    names = [entry.path for entry in entries]
    expected_names = [root_name, *sorted(names[1:], key=lambda value: value.encode("ascii"))]
    if names != expected_names or entries[0].path != root_name or entries[0].kind != "directory":
        _fail("tar root or member ordering is not canonical")
    if common_mtime is None:
        _fail("tar contains no timestamped members")
    return common_mtime, tuple(entries)


def _audit_entries(entries: tuple[_MaterializedEntry, ...]) -> tuple[ArchiveEntry, ...]:
    return tuple(
        ArchiveEntry(
            path=entry.path,
            kind=entry.kind,
            mode=entry.mode,
            size=len(entry.data),
            sha256=hashlib.sha256(entry.data).hexdigest() if entry.kind == "file" else None,
        )
        for entry in entries
    )


def _audit_tar_snapshot(
    data: bytes,
    root_name: str,
    expected_mtime: int | None,
    limits: ArchiveLimits,
) -> ArchiveAudit:
    _validate_limits(limits)
    root_name = _validate_root_name(root_name)
    if len(data) > limits.maximum_archive_bytes:
        _fail("tar.gz exceeds the archive size limit")
    if len(data) < 18 or data[:4] != _GZIP_HEADER_PREFIX or data[8:10] != _GZIP_HEADER_SUFFIX:
        _fail("gzip header is not the canonical no-filename release header")
    mtime = struct.unpack("<L", data[4:8])[0]
    if expected_mtime is not None and mtime != _validate_mtime(expected_mtime):
        _fail("gzip mtime differs from the expected source epoch")
    raw_limit = limits.maximum_total_bytes + limits.maximum_member_count * 1024 + len(_TAR_END)
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        payload = decoder.decompress(data, raw_limit + 1)
    except zlib.error as exc:
        raise DeterministicArchiveError(f"gzip stream is invalid: {exc}") from exc
    if len(payload) > raw_limit or decoder.unconsumed_tail:
        _fail("gzip decompressed tar exceeds the structural size limit")
    if not decoder.eof:
        _fail("gzip stream is truncated")
    if decoder.unused_data:
        _fail("gzip contains trailing data or a concatenated member")
    try:
        flushed = decoder.flush()
    except zlib.error as exc:
        raise DeterministicArchiveError(f"gzip stream cannot be finalized: {exc}") from exc
    if flushed:
        payload += flushed
        if len(payload) > raw_limit:
            _fail("gzip decompressed tar exceeds the structural size limit")
    tar_mtime, entries = _parse_tar(payload, root_name, expected_mtime, limits)
    if tar_mtime != mtime:
        _fail("gzip and tar mtimes differ")
    return ArchiveAudit(
        format="tar.gz",
        archive_sha256=hashlib.sha256(data).hexdigest(),
        archive_bytes=len(data),
        mtime=mtime,
        entries=_audit_entries(entries),
    )


def _archive_snapshot(path: pathlib.Path, limits: ArchiveLimits, label: str) -> bytes:
    _validate_limits(limits)
    try:
        return read_regular_snapshot(path, maximum=limits.maximum_archive_bytes, label=label).data
    except EvidenceIOError as exc:
        raise DeterministicArchiveError(str(exc)) from exc


def _require_snapshot_sha256(data: bytes, expected_sha256: str | None) -> None:
    if expected_sha256 is None:
        return
    if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        _fail("expected archive SHA-256 must be one lowercase hexadecimal digest")
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_sha256:
        _fail(f"archive SHA-256 differs: {actual} != {expected_sha256}")


def audit_tar_gz(
    archive: pathlib.Path,
    *,
    root_name: str,
    mtime: int | None = None,
    expected_sha256: str | None = None,
    limits: ArchiveLimits = DEFAULT_LIMITS,
) -> ArchiveAudit:
    """Audit one tar.gz snapshot without extracting it."""

    data = _archive_snapshot(pathlib.Path(archive), limits, "deterministic tar.gz")
    _require_snapshot_sha256(data, expected_sha256)
    return _audit_tar_snapshot(data, root_name, mtime, limits)


def _zip_datetime(mtime: int) -> tuple[int, int, int, int, int, int]:
    value = dt.datetime.fromtimestamp(_validate_mtime(mtime), tz=dt.timezone.utc)
    if not 1980 <= value.year <= 2107:
        _fail("ZIP mtime must be representable between 1980 and 2107")
    return (
        value.year,
        value.month,
        value.day,
        value.hour,
        value.minute,
        value.second - value.second % 2,
    )


def _zip_dos_fields(date_time: tuple[int, int, int, int, int, int]) -> tuple[int, int]:
    year, month, day, hour, minute, second = date_time
    dos_time = (hour << 11) | (minute << 5) | (second // 2)
    dos_date = ((year - 1980) << 9) | (month << 5) | day
    return dos_time, dos_date


def create_zip(
    source_dir: pathlib.Path,
    output: pathlib.Path,
    *,
    root_name: str,
    mtime: int,
    limits: ArchiveLimits = DEFAULT_LIMITS,
) -> ArchiveAudit:
    """Create one deterministic, non-ZIP64 release ZIP and audit final bytes."""

    entries = _source_entries(source_dir, root_name, limits)
    timestamp = _zip_datetime(mtime)
    buffer = io.BytesIO()
    with zipfile.ZipFile(
        buffer,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        allowZip64=False,
    ) as archive:
        archive.comment = b""
        for entry in entries:
            name = entry.path + ("/" if entry.kind == "directory" else "")
            info = zipfile.ZipInfo(name, timestamp)
            info.create_system = 3
            info.extract_version = 20
            info.create_version = 20
            info.compress_type = (
                zipfile.ZIP_STORED
                if entry.kind == "directory"
                else zipfile.ZIP_DEFLATED
            )
            unix_mode = (
                stat.S_IFDIR | 0o755
                if entry.kind == "directory"
                else stat.S_IFREG | 0o644
            )
            info.external_attr = unix_mode << 16
            info.extra = b""
            info.comment = b""
            archive.writestr(info, entry.data, compress_type=info.compress_type, compresslevel=9)
    data = buffer.getvalue()
    if len(data) > limits.maximum_archive_bytes:
        _fail("created ZIP exceeds the archive size limit")
    audit = _audit_zip_snapshot(data, root_name, mtime, limits)
    _write_atomic(pathlib.Path(output), data)
    return audit


def _zip_eocd(data: bytes) -> tuple[int, int, int]:
    if len(data) < _ZIP_EOCD.size:
        _fail("ZIP is truncated")
    offset = len(data) - _ZIP_EOCD.size
    fields = _ZIP_EOCD.unpack_from(data, offset)
    (
        signature,
        disk,
        central_disk,
        disk_entries,
        total_entries,
        central_size,
        central_offset,
        comment_size,
    ) = fields
    if signature != _ZIP_EOCD_SIGNATURE or data.rfind(_ZIP_EOCD_SIGNATURE) != offset:
        _fail("ZIP EOCD is missing, prefixed, or not at the exact end")
    if disk != 0 or central_disk != 0 or disk_entries != total_entries:
        _fail("multi-disk ZIP archives are unsupported")
    if comment_size != 0:
        _fail("ZIP archive comment is not canonical")
    if total_entries in {0, 0xFFFF} or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
        _fail("empty or ZIP64 archives are unsupported")
    if central_offset + central_size != offset:
        _fail("ZIP central directory has a gap, overlap, or trailing prefix")
    return total_entries, central_offset, central_size


def _decode_zip_name(raw: bytes, flags: int) -> str:
    if flags != 0:
        _fail("ZIP member uses noncanonical flags")
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise DeterministicArchiveError("ZIP member path encoding is invalid") from exc


def _audit_zip_snapshot(
    data: bytes,
    root_name: str,
    expected_mtime: int | None,
    limits: ArchiveLimits,
) -> ArchiveAudit:
    _validate_limits(limits)
    root_name = _validate_root_name(root_name)
    if len(data) > limits.maximum_archive_bytes:
        _fail("ZIP exceeds the archive size limit")
    total_entries, central_offset, central_size = _zip_eocd(data)
    if total_entries > limits.maximum_member_count:
        _fail("ZIP contains too many members")
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r", allowZip64=False) as archive:
            if archive.comment:
                _fail("ZIP archive comment is not canonical")
            infos = archive.infolist()
            if len(infos) != total_entries:
                _fail("ZIP central entry count differs from EOCD")
            registry = _PathRegistry(root_name)
            materialized: list[_MaterializedEntry] = []
            local_end = 0
            total = 0
            common_mtime: int | None = None
            for index, info in enumerate(infos):
                if info.header_offset != local_end:
                    _fail(
                        "ZIP local records contain a prefix, gap, overlap, or "
                        "noncanonical order"
                    )
                if info.extra or info.comment:
                    _fail("ZIP member contains an extra field or comment")
                if (
                    info.create_system != 3
                    or info.create_version != 20
                    or info.extract_version != 20
                ):
                    _fail("ZIP creator or extraction version is not canonical")
                if info.flag_bits != 0:
                    _fail("ZIP member uses noncanonical flags")
                if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                    _fail("ZIP member uses unsupported compression")
                if info.internal_attr != 0:
                    _fail("ZIP member internal attributes are not canonical")
                local = _ZIP_LOCAL.unpack_from(data, info.header_offset)
                (
                    signature,
                    extract_version,
                    flags,
                    method,
                    mod_time,
                    mod_date,
                    crc,
                    compressed_size,
                    size,
                    name_len,
                    extra_len,
                ) = local
                if signature != _ZIP_LOCAL_SIGNATURE or extra_len != 0:
                    _fail("ZIP local header is invalid or contains an extra field")
                name_start = info.header_offset + _ZIP_LOCAL.size
                name_end = name_start + name_len
                data_start = name_end
                data_end = data_start + compressed_size
                if data_end > central_offset:
                    _fail("ZIP local payload overlaps the central directory")
                local_name = _decode_zip_name(data[name_start:name_end], flags)
                expected_dos_time, expected_dos_date = _zip_dos_fields(info.date_time)
                if (
                    local_name != info.filename
                    or extract_version != info.extract_version
                    or flags != info.flag_bits
                    or method != info.compress_type
                    or crc != info.CRC
                    or compressed_size != info.compress_size
                    or size != info.file_size
                    or mod_time != expected_dos_time
                    or mod_date != expected_dos_date
                ):
                    _fail("ZIP local and central metadata differ")
                is_directory = info.filename.endswith("/")
                canonical_name = info.filename[:-1] if is_directory else info.filename
                kind: Literal["directory", "file"] = "directory" if is_directory else "file"
                registry.add(canonical_name, kind)
                expected_mode = (stat.S_IFDIR | 0o755) if is_directory else (stat.S_IFREG | 0o644)
                if info.external_attr != expected_mode << 16:
                    _fail("ZIP member mode or file type is not canonical")
                if is_directory and (
                    info.file_size != 0
                    or info.compress_size != 0
                    or info.compress_type != zipfile.ZIP_STORED
                ):
                    _fail("ZIP directory has payload or noncanonical compression")
                if not is_directory and info.compress_type != zipfile.ZIP_DEFLATED:
                    _fail("ZIP file compression is not canonical DEFLATE")
                if info.file_size > limits.maximum_member_bytes:
                    _fail(f"ZIP member exceeds the per-member size limit: {canonical_name}")
                if total + info.file_size > limits.maximum_total_bytes:
                    _fail("ZIP logical contents exceed the total size limit")
                date_time = info.date_time
                member_datetime = dt.datetime(*date_time, tzinfo=dt.timezone.utc)
                member_mtime = int(member_datetime.timestamp())
                if expected_mtime is not None and date_time != _zip_datetime(expected_mtime):
                    _fail("ZIP member mtime differs from the expected source epoch")
                if common_mtime is None:
                    common_mtime = member_mtime
                elif member_mtime != common_mtime:
                    _fail("ZIP member mtimes are inconsistent")
                if is_directory:
                    content = b""
                else:
                    decoder = zlib.decompressobj(-zlib.MAX_WBITS)
                    try:
                        content = decoder.decompress(
                            data[data_start:data_end],
                            limits.maximum_member_bytes + 1,
                        )
                    except zlib.error as exc:
                        raise DeterministicArchiveError(
                            f"ZIP member DEFLATE stream is invalid: {canonical_name}: {exc}"
                        ) from exc
                    if (
                        decoder.unused_data
                        or decoder.unconsumed_tail
                        or len(content) > limits.maximum_member_bytes
                    ):
                        _fail(
                            "ZIP member DEFLATE stream is truncated, oversized, or has "
                            f"trailing data: {canonical_name}"
                        )
                    try:
                        content += decoder.flush()
                    except zlib.error as exc:
                        raise DeterministicArchiveError(
                            f"ZIP member DEFLATE stream cannot be finalized: {canonical_name}: {exc}"
                        ) from exc
                    if not decoder.eof or len(content) > limits.maximum_member_bytes:
                        _fail(
                            "ZIP member DEFLATE stream is truncated or oversized: "
                            f"{canonical_name}"
                        )
                if len(content) != info.file_size:
                    _fail(f"ZIP member decompressed size differs: {canonical_name}")
                if binascii.crc32(content) & 0xFFFFFFFF != info.CRC:
                    _fail(f"ZIP member CRC check failed: {canonical_name}")
                total += len(content)
                if total > limits.maximum_total_bytes:
                    _fail("ZIP logical contents exceed the total size limit")
                materialized.append(
                    _MaterializedEntry(
                        canonical_name,
                        kind,
                        0o755 if is_directory else 0o644,
                        content,
                    )
                )
                local_end = data_end
            if local_end != central_offset:
                _fail("ZIP local records do not end exactly at the central directory")
            names = [entry.path for entry in materialized]
            expected_names = [
                root_name,
                *sorted(names[1:], key=lambda value: value.encode("ascii")),
            ]
            if (
                names != expected_names
                or materialized[0].path != root_name
                or materialized[0].kind != "directory"
            ):
                _fail("ZIP root or member ordering is not canonical")
    except (EOFError, OSError, RuntimeError, struct.error, zipfile.BadZipFile, zlib.error) as exc:
        raise DeterministicArchiveError(f"ZIP is invalid: {exc}") from exc

    # Parse every central record independently so local/central name bytes,
    # comments, extras, disk fields, and ordering cannot be hidden by zipfile.
    cursor = central_offset
    for index, info in enumerate(infos):
        if cursor + _ZIP_CENTRAL.size > central_offset + central_size:
            _fail("ZIP central directory is truncated")
        fields = _ZIP_CENTRAL.unpack_from(data, cursor)
        (
            signature,
            create_version,
            extract_version,
            flags,
            method,
            mod_time,
            mod_date,
            crc,
            compressed_size,
            size,
            name_len,
            extra_len,
            comment_len,
            disk_start,
            internal_attr,
            external_attr,
            local_offset,
        ) = fields
        if signature != _ZIP_CENTRAL_SIGNATURE or extra_len or comment_len or disk_start:
            _fail("ZIP central record is invalid or noncanonical")
        name_start = cursor + _ZIP_CENTRAL.size
        name_end = name_start + name_len
        if name_end > central_offset + central_size:
            _fail("ZIP central member name is truncated")
        central_name = _decode_zip_name(data[name_start:name_end], flags)
        expected_dos_time, expected_dos_date = _zip_dos_fields(info.date_time)
        if (
            central_name != info.filename
            or create_version != (3 << 8) | 20
            or extract_version != info.extract_version
            or flags != info.flag_bits
            or method != info.compress_type
            or crc != info.CRC
            or compressed_size != info.compress_size
            or size != info.file_size
            or mod_time != expected_dos_time
            or mod_date != expected_dos_date
            or internal_attr != info.internal_attr
            or external_attr != info.external_attr
            or local_offset != info.header_offset
        ):
            _fail("ZIP central metadata differs from the audited member")
        cursor = name_end
    if cursor != central_offset + central_size:
        _fail("ZIP central directory length is noncanonical")
    if common_mtime is None:
        _fail("ZIP contains no timestamped members")
    return ArchiveAudit(
        format="zip",
        archive_sha256=hashlib.sha256(data).hexdigest(),
        archive_bytes=len(data),
        mtime=common_mtime,
        entries=_audit_entries(tuple(materialized)),
    )


def audit_zip(
    archive: pathlib.Path,
    *,
    root_name: str,
    mtime: int | None = None,
    expected_sha256: str | None = None,
    limits: ArchiveLimits = DEFAULT_LIMITS,
) -> ArchiveAudit:
    """Audit one ZIP snapshot without extracting it."""

    data = _archive_snapshot(pathlib.Path(archive), limits, "deterministic ZIP")
    _require_snapshot_sha256(data, expected_sha256)
    return _audit_zip_snapshot(data, root_name, mtime, limits)


def _entries_from_tar_snapshot(
    data: bytes,
    root_name: str,
    mtime: int | None,
    limits: ArchiveLimits,
) -> tuple[ArchiveAudit, tuple[_MaterializedEntry, ...]]:
    audit = _audit_tar_snapshot(data, root_name, mtime, limits)
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    payload = decoder.decompress(data)
    _, entries = _parse_tar(payload, root_name, mtime, limits)
    return audit, entries


def _entries_from_zip_snapshot(
    data: bytes,
    root_name: str,
    mtime: int | None,
    limits: ArchiveLimits,
) -> tuple[ArchiveAudit, tuple[_MaterializedEntry, ...]]:
    audit = _audit_zip_snapshot(data, root_name, mtime, limits)
    with zipfile.ZipFile(io.BytesIO(data), "r", allowZip64=False) as archive:
        entries = tuple(
            _MaterializedEntry(
                info.filename[:-1] if info.is_dir() else info.filename,
                "directory" if info.is_dir() else "file",
                0o755 if info.is_dir() else 0o644,
                b"" if info.is_dir() else archive.read(info),
            )
            for info in archive.infolist()
        )
    return audit, entries


def _extract_entries(
    entries: tuple[_MaterializedEntry, ...], destination: pathlib.Path, mtime: int
) -> None:
    target = _validated_output_target(
        pathlib.Path(destination), "extraction destination"
    )
    parent = target.parent
    if target.exists() or target.is_symlink():
        _fail(f"extraction destination must not already exist: {target}")
    staging = parent / f".{target.name}.tmp-{os.getpid()}"
    if staging.exists() or staging.is_symlink():
        _fail(f"extraction staging path already exists: {staging}")
    target_claimed = False
    published_root: pathlib.Path | None = None
    root_published = False
    try:
        staging.mkdir(mode=0o700)
        for entry in entries:
            relative = pathlib.PurePosixPath(entry.path)
            output = staging.joinpath(*relative.parts)
            if entry.kind == "directory":
                output.mkdir(mode=0o755)
            else:
                with output.open("xb") as handle:
                    handle.write(entry.data)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(output, 0o644)
                os.utime(output, (mtime, mtime), follow_symlinks=False)
        for entry in reversed(entries):
            if entry.kind == "directory":
                output = staging.joinpath(*pathlib.PurePosixPath(entry.path).parts)
                os.chmod(output, 0o755)
                os.utime(output, (mtime, mtime), follow_symlinks=False)
        # Claim the caller-visible destination atomically without replacing a
        # path created after the initial check.  The fully populated archive
        # root is then renamed into that empty wrapper in one operation.
        target.mkdir(mode=0o755)
        target_claimed = True
        archive_root = pathlib.PurePosixPath(entries[0].path)
        published_root = target.joinpath(*archive_root.parts)
        os.rename(
            staging.joinpath(*archive_root.parts),
            published_root,
        )
        root_published = True
        staging.rmdir()
    except OSError as exc:
        cleanup_errors: list[str] = []
        try:
            shutil.rmtree(staging)
        except FileNotFoundError:
            pass
        except OSError as cleanup_exc:
            cleanup_errors.append(f"staging cleanup failed: {cleanup_exc}")
        if target_claimed:
            if root_published and published_root is not None:
                try:
                    shutil.rmtree(published_root)
                except FileNotFoundError:
                    pass
                except OSError as cleanup_exc:
                    cleanup_errors.append(
                        f"published-root cleanup failed: {cleanup_exc}"
                    )
            try:
                target.rmdir()
            except FileNotFoundError:
                pass
            except OSError as cleanup_exc:
                cleanup_errors.append(f"destination cleanup failed: {cleanup_exc}")
        suffix = f"; {'; '.join(cleanup_errors)}" if cleanup_errors else ""
        raise DeterministicArchiveError(
            f"cannot extract archive to {target}: {exc}{suffix}"
        ) from exc


def extract_tar_gz(
    archive: pathlib.Path,
    destination: pathlib.Path,
    *,
    root_name: str,
    mtime: int | None = None,
    expected_sha256: str | None = None,
    limits: ArchiveLimits = DEFAULT_LIMITS,
) -> ArchiveAudit:
    """Audit a single tar.gz snapshot completely, then extract it transactionally."""

    data = _archive_snapshot(pathlib.Path(archive), limits, "deterministic tar.gz")
    _require_snapshot_sha256(data, expected_sha256)
    audit, entries = _entries_from_tar_snapshot(data, root_name, mtime, limits)
    _extract_entries(entries, pathlib.Path(destination), audit.mtime)
    return audit


def extract_zip(
    archive: pathlib.Path,
    destination: pathlib.Path,
    *,
    root_name: str,
    mtime: int | None = None,
    expected_sha256: str | None = None,
    limits: ArchiveLimits = DEFAULT_LIMITS,
) -> ArchiveAudit:
    """Audit a single ZIP snapshot completely, then extract it transactionally."""

    data = _archive_snapshot(pathlib.Path(archive), limits, "deterministic ZIP")
    _require_snapshot_sha256(data, expected_sha256)
    audit, entries = _entries_from_zip_snapshot(data, root_name, mtime, limits)
    _extract_entries(entries, pathlib.Path(destination), audit.mtime)
    return audit


def _emit_audit(audit: ArchiveAudit) -> None:
    print(
        f"DETERMINISTIC_ARCHIVE_PASS format={audit.format} "
        f"bytes={audit.archive_bytes} members={len(audit.entries)} "
        f"sha256={audit.archive_sha256}"
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for archive_format in ("tar-gz", "zip"):
        create = subparsers.add_parser(f"create-{archive_format}")
        create.add_argument("--source", type=pathlib.Path, required=True)
        create.add_argument("--output", type=pathlib.Path, required=True)
        create.add_argument("--root", required=True)
        create.add_argument("--mtime", type=int, required=True)
        audit = subparsers.add_parser(f"audit-{archive_format}")
        audit.add_argument("--archive", type=pathlib.Path, required=True)
        audit.add_argument("--root", required=True)
        audit.add_argument("--mtime", type=int)
        audit.add_argument("--sha256")
        extract = subparsers.add_parser(f"extract-{archive_format}")
        extract.add_argument("--archive", type=pathlib.Path, required=True)
        extract.add_argument("--destination", type=pathlib.Path, required=True)
        extract.add_argument("--root", required=True)
        extract.add_argument("--mtime", type=int)
        extract.add_argument("--sha256")
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "create-tar-gz":
            result = create_tar_gz(args.source, args.output, root_name=args.root, mtime=args.mtime)
        elif args.command == "audit-tar-gz":
            result = audit_tar_gz(
                args.archive,
                root_name=args.root,
                mtime=args.mtime,
                expected_sha256=args.sha256,
            )
        elif args.command == "extract-tar-gz":
            result = extract_tar_gz(
                args.archive,
                args.destination,
                root_name=args.root,
                mtime=args.mtime,
                expected_sha256=args.sha256,
            )
        elif args.command == "create-zip":
            result = create_zip(args.source, args.output, root_name=args.root, mtime=args.mtime)
        elif args.command == "audit-zip":
            result = audit_zip(
                args.archive,
                root_name=args.root,
                mtime=args.mtime,
                expected_sha256=args.sha256,
            )
        elif args.command == "extract-zip":
            result = extract_zip(
                args.archive,
                args.destination,
                root_name=args.root,
                mtime=args.mtime,
                expected_sha256=args.sha256,
            )
        else:  # argparse makes this unreachable, retain a fail-closed boundary.
            _fail(f"unsupported archive command: {args.command}")
    except DeterministicArchiveError as exc:
        raise SystemExit(f"error: {exc}") from exc
    _emit_audit(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
