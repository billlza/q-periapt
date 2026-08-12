#!/usr/bin/env python3
"""Strictly extract the repository's fixed GitHub workflow-artifact shapes.

GitHub's download action is used only as a byte transport.  It writes each
official artifact container as a ZIP under the fixed ``target/workflow-artifact/raw``
staging root; this module validates that outer ZIP and publishes the expected
payload to one profile-owned destination.  Neither source paths, destination
paths, artifact names, nor member names are caller-configurable.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import io
import os
import pathlib
import secrets
import stat
import struct
import sys
import unicodedata
import zipfile
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import NoReturn, Sequence

from evidence_io import EvidenceIOError, FileSnapshot, read_regular_snapshot


REPOSITORY_ROOT = pathlib.Path(__file__).resolve(strict=True).parent.parent
RAW_ROOT = pathlib.PurePosixPath("target/workflow-artifact/raw")

_ZIP_EOCD = struct.Struct("<4s4H2LH")
_ZIP_LOCAL = struct.Struct("<4s5H3L2H")
_ZIP_CENTRAL = struct.Struct("<4s6H3L5H2L")
_ZIP_DATA_DESCRIPTOR = struct.Struct("<3L")
_ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP_LOCAL_SIGNATURE = b"PK\x03\x04"
_ZIP_CENTRAL_SIGNATURE = b"PK\x01\x02"
_ZIP_DATA_DESCRIPTOR_SIGNATURE = b"PK\x07\x08"
_ZIP_FLAG_ENCRYPTED = 0x0001
_ZIP_FLAG_DATA_DESCRIPTOR = 0x0008
_ZIP_FLAG_UTF8 = 0x0800
_ZIP_ALLOWED_FLAGS = _ZIP_FLAG_DATA_DESCRIPTOR | _ZIP_FLAG_UTF8
_ZIP_SUPPORTED_COMPRESSION = frozenset(
    (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
)
_READ_CHUNK_BYTES = 1024 * 1024
_MAX_RAW_ROOT_ENTRIES = 8
_MAX_CONTAINER_BYTES = 128 * 1024 * 1024
_MAX_PAYLOAD_BYTES = 64 * 1024 * 1024
_MAX_METADATA_BYTES = 1024 * 1024
_MAX_CHECKSUM_BYTES = 64 * 1024
_RENAME_EXCL = 0x00000004
_RENAME_NOREPLACE = 0x00000001
_DIRECTORY_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_SUPPORTS_OPENAT = os.open in os.supports_dir_fd

FileIdentity = tuple[int, int]


class WorkflowArtifactError(ValueError):
    """A raw workflow artifact does not match its fixed local contract."""


@dataclass(frozen=True, slots=True)
class MemberSpec:
    """One fixed outer-ZIP member and its fixed published leaf."""

    archive_name: str
    destination_name: str
    maximum_bytes: int


@dataclass(frozen=True, slots=True)
class ContainerSpec:
    """One fixed GitHub artifact container."""

    artifact_name: str
    members: tuple[MemberSpec, ...]
    maximum_archive_bytes: int = _MAX_CONTAINER_BYTES


@dataclass(frozen=True, slots=True)
class ProfileSpec:
    """A complete fixed raw-container and publication shape."""

    name: str
    destination: pathlib.PurePosixPath
    nested_raw_containers: bool
    containers: tuple[ContainerSpec, ...]


@dataclass(frozen=True, slots=True)
class StagedFileRecord:
    """Creation identity plus the completed output contract, when available."""

    identity: FileIdentity
    expected_size: int | None = None
    expected_mode: int | None = None


_ANDROID_VERSION = "0.1.0-alpha.2"
_ANDROID_PACKAGE = f"q-periapt-android-{_ANDROID_VERSION}"
_ANDROID_AAR = f"{_ANDROID_PACKAGE}.aar"

ANDROID_AAR_PROFILE = ProfileSpec(
    name="android-aar",
    destination=pathlib.PurePosixPath(
        f"target/qperiapt-android-aar/{_ANDROID_PACKAGE}"
    ),
    nested_raw_containers=False,
    containers=(
        ContainerSpec(
            artifact_name="abi2-android-aar",
            members=(
                MemberSpec(_ANDROID_AAR, _ANDROID_AAR, _MAX_PAYLOAD_BYTES),
                MemberSpec("MANIFEST.json", "MANIFEST.json", _MAX_METADATA_BYTES),
                MemberSpec("SHA256SUMS", "SHA256SUMS", _MAX_CHECKSUM_BYTES),
            ),
        ),
    ),
)

_LINUX_X86_PACKAGE = (
    "q-periapt-c-abi2-0.1.0-alpha.2-x86_64-unknown-linux-gnu.tar.gz"
)
_LINUX_ARM_PACKAGE = (
    "q-periapt-c-abi2-0.1.0-alpha.2-aarch64-unknown-linux-gnu.tar.gz"
)
_WINDOWS_PACKAGE = (
    "q-periapt-c-abi2-0.1.0-alpha.2-x86_64-pc-windows-msvc.zip"
)
_CANDIDATE_ANDROID_MANIFEST = f"{_ANDROID_PACKAGE}-MANIFEST.json"

PLATFORM_CANDIDATE_PROFILE = ProfileSpec(
    name="platform-candidate",
    destination=pathlib.PurePosixPath("candidate"),
    nested_raw_containers=True,
    containers=(
        ContainerSpec(
            artifact_name="abi2-candidate-linux-x86_64-unknown-linux-gnu",
            members=(
                MemberSpec(
                    _LINUX_X86_PACKAGE,
                    _LINUX_X86_PACKAGE,
                    _MAX_PAYLOAD_BYTES,
                ),
            ),
        ),
        ContainerSpec(
            artifact_name="abi2-candidate-linux-aarch64-unknown-linux-gnu",
            members=(
                MemberSpec(
                    _LINUX_ARM_PACKAGE,
                    _LINUX_ARM_PACKAGE,
                    _MAX_PAYLOAD_BYTES,
                ),
            ),
        ),
        ContainerSpec(
            artifact_name="abi2-candidate-windows-x86_64-msvc",
            members=(
                MemberSpec(
                    _WINDOWS_PACKAGE,
                    _WINDOWS_PACKAGE,
                    _MAX_PAYLOAD_BYTES,
                ),
            ),
        ),
        ContainerSpec(
            artifact_name="abi2-candidate-android",
            members=(
                MemberSpec(_ANDROID_AAR, _ANDROID_AAR, _MAX_PAYLOAD_BYTES),
                MemberSpec(
                    _CANDIDATE_ANDROID_MANIFEST,
                    _CANDIDATE_ANDROID_MANIFEST,
                    _MAX_METADATA_BYTES,
                ),
            ),
        ),
    ),
)

PROFILES = {
    ANDROID_AAR_PROFILE.name: ANDROID_AAR_PROFILE,
    PLATFORM_CANDIDATE_PROFILE.name: PLATFORM_CANDIDATE_PROFILE,
}


def _fail(message: str) -> NoReturn:
    raise WorkflowArtifactError(message)


def _repository_path(relative: pathlib.PurePosixPath) -> pathlib.Path:
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        _fail(f"internal workflow-artifact path is invalid: {relative}")
    return REPOSITORY_ROOT.joinpath(*relative.parts)


def _validate_member_path(name: str, *, label: str) -> None:
    if not name or name.startswith(("/", "\\")) or "\\" in name:
        _fail(f"{label} is absolute or contains a backslash: {name!r}")
    if len(name) >= 2 and name[0].isalpha() and name[1] == ":":
        _fail(f"{label} is a Windows drive path: {name!r}")
    if "\x00" in name or any(
        unicodedata.category(character) in {"Cc", "Cs"} for character in name
    ):
        _fail(f"{label} contains a control character")
    if unicodedata.normalize("NFC", name) != name:
        _fail(f"{label} is not Unicode NFC: {name!r}")
    components = name.split("/")
    if any(component in {"", ".", ".."} for component in components):
        _fail(f"{label} contains an empty or traversal component: {name!r}")


def _bounded_directory_inventory(
    directory: pathlib.Path,
    *,
    maximum_entries: int,
    label: str,
) -> dict[str, os.DirEntry[str]]:
    try:
        metadata = directory.lstat()
    except OSError as exc:
        raise WorkflowArtifactError(f"cannot inspect {label} {directory}: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        _fail(f"{label} is not a non-symlink directory: {directory}")

    entries: dict[str, os.DirEntry[str]] = {}
    casefolded: dict[str, str] = {}
    try:
        with os.scandir(directory) as iterator:
            for entry in iterator:
                if len(entries) >= maximum_entries:
                    _fail(f"{label} exceeds its {maximum_entries}-entry limit")
                _validate_member_path(entry.name, label=f"{label} entry")
                folded = entry.name.casefold()
                previous = casefolded.get(folded)
                if previous is not None:
                    _fail(
                        f"{label} contains a case-insensitive collision: "
                        f"{previous!r} and {entry.name!r}"
                    )
                casefolded[folded] = entry.name
                entries[entry.name] = entry
    except WorkflowArtifactError:
        raise
    except OSError as exc:
        raise WorkflowArtifactError(f"cannot enumerate {label} {directory}: {exc}") from exc
    return entries


def _raw_container_paths(profile: ProfileSpec) -> tuple[pathlib.Path, ...]:
    raw_root = _repository_path(RAW_ROOT)
    root_entries = _bounded_directory_inventory(
        raw_root,
        maximum_entries=_MAX_RAW_ROOT_ENTRIES,
        label=f"{profile.name} raw root",
    )
    expected_names = {container.artifact_name for container in profile.containers}
    if profile.nested_raw_containers:
        if set(root_entries) != expected_names:
            _fail(
                f"{profile.name} raw artifact directories differ: "
                f"expected={sorted(expected_names)}, got={sorted(root_entries)}"
            )
        paths: list[pathlib.Path] = []
        for container in profile.containers:
            entry = root_entries[container.artifact_name]
            if not entry.is_dir(follow_symlinks=False):
                _fail(
                    f"raw artifact wrapper is not a non-symlink directory: "
                    f"{container.artifact_name}"
                )
            wrapper = raw_root / container.artifact_name
            wrapper_entries = _bounded_directory_inventory(
                wrapper,
                maximum_entries=2,
                label=f"raw artifact wrapper {container.artifact_name}",
            )
            leaf = f"{container.artifact_name}.zip"
            if set(wrapper_entries) != {leaf}:
                _fail(
                    f"raw artifact wrapper {container.artifact_name} must contain "
                    f"only {leaf!r}: got={sorted(wrapper_entries)}"
                )
            if not wrapper_entries[leaf].is_file(follow_symlinks=False):
                _fail(f"raw artifact container is not a regular file: {wrapper / leaf}")
            paths.append(wrapper / leaf)
        return tuple(paths)

    expected_leaves = {f"{name}.zip" for name in expected_names}
    if set(root_entries) != expected_leaves:
        _fail(
            f"{profile.name} raw artifact files differ: "
            f"expected={sorted(expected_leaves)}, got={sorted(root_entries)}"
        )
    paths = []
    for container in profile.containers:
        leaf = f"{container.artifact_name}.zip"
        if not root_entries[leaf].is_file(follow_symlinks=False):
            _fail(f"raw artifact container is not a regular file: {raw_root / leaf}")
        paths.append(raw_root / leaf)
    return tuple(paths)


def _decode_zip_name(raw: bytes, flags: int, *, label: str) -> str:
    encoding = "utf-8" if flags & _ZIP_FLAG_UTF8 else "cp437"
    try:
        return raw.decode(encoding, errors="strict")
    except UnicodeError as exc:
        raise WorkflowArtifactError(f"{label} is not valid {encoding}: {exc}") from exc


def _validate_eocd(
    data: bytes,
    *,
    expected_entries: int,
) -> tuple[int, int]:
    if len(data) < _ZIP_EOCD.size:
        _fail("workflow artifact ZIP is shorter than its end record")
    eocd_offset = len(data) - _ZIP_EOCD.size
    (
        signature,
        disk_number,
        central_disk,
        disk_entries,
        total_entries,
        central_size,
        central_offset,
        comment_length,
    ) = _ZIP_EOCD.unpack_from(data, eocd_offset)
    if signature != _ZIP_EOCD_SIGNATURE:
        _fail("workflow artifact ZIP has trailing bytes or no canonical end record")
    if comment_length != 0:
        _fail("workflow artifact ZIP archive comments are forbidden")
    if disk_number != 0 or central_disk != 0 or disk_entries != total_entries:
        _fail("workflow artifact ZIP must not use multiple disks")
    if total_entries != expected_entries:
        _fail("workflow artifact ZIP end-record entry count differs")
    if central_offset + central_size != eocd_offset:
        _fail("workflow artifact ZIP central-directory framing is noncanonical")
    return central_offset, central_size


def _validate_central_directory(
    data: bytes,
    infos: Sequence[zipfile.ZipInfo],
    *,
    central_offset: int,
    central_size: int,
) -> dict[int, tuple[int, int]]:
    cursor = central_offset
    central_end = central_offset + central_size
    timestamps: dict[int, tuple[int, int]] = {}
    for info in infos:
        if cursor + _ZIP_CENTRAL.size > central_end:
            _fail("workflow artifact ZIP central directory is truncated")
        fields = _ZIP_CENTRAL.unpack_from(data, cursor)
        (
            signature,
            create_version,
            extract_version,
            flags,
            compression,
            modified_time,
            modified_date,
            crc,
            compressed_size,
            file_size,
            name_length,
            extra_length,
            comment_length,
            disk_start,
            internal_attr,
            external_attr,
            local_offset,
        ) = fields
        if signature != _ZIP_CENTRAL_SIGNATURE:
            _fail("workflow artifact ZIP central record signature is invalid")
        name_start = cursor + _ZIP_CENTRAL.size
        name_end = name_start + name_length
        record_end = name_end + extra_length + comment_length
        if record_end > central_end:
            _fail("workflow artifact ZIP central record is truncated")
        central_name = _decode_zip_name(
            data[name_start:name_end], flags, label="ZIP central member name"
        )
        if extra_length != 0 or comment_length != 0:
            _fail("workflow artifact ZIP member extras and comments are forbidden")
        if disk_start != 0:
            _fail("workflow artifact ZIP member starts on another disk")
        if (
            central_name != info.filename
            or create_version != (info.create_system << 8) | info.create_version
            or extract_version != info.extract_version
            or flags != info.flag_bits
            or compression != info.compress_type
            or crc != info.CRC
            or compressed_size != info.compress_size
            or file_size != info.file_size
            or internal_attr != info.internal_attr
            or external_attr != info.external_attr
            or local_offset != info.header_offset
        ):
            _fail("workflow artifact ZIP central metadata is inconsistent")
        timestamps[local_offset] = (modified_time, modified_date)
        cursor = record_end
    if cursor != central_end:
        _fail("workflow artifact ZIP central directory contains hidden records")
    return timestamps


def _validate_compressed_payload(raw: bytes, info: zipfile.ZipInfo) -> None:
    """Validate one already-framed member without trusting ZipExtFile semantics."""

    if len(raw) != info.compress_size:
        _fail(f"workflow artifact ZIP compressed size differs: {info.filename}")

    if info.compress_type == zipfile.ZIP_STORED:
        if info.compress_size != info.file_size:
            _fail(f"workflow artifact ZIP stored sizes differ: {info.filename}")
        payload = raw
    elif info.compress_type == zipfile.ZIP_DEFLATED:
        decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
        try:
            payload = decompressor.decompress(raw, info.file_size + 1)
        except zlib.error as exc:
            raise WorkflowArtifactError(
                f"workflow artifact ZIP deflate stream is invalid: {info.filename}: {exc}"
            ) from exc
        if len(payload) > info.file_size:
            _fail(
                "workflow artifact ZIP deflate stream exceeds its declared size: "
                f"{info.filename}"
            )
        if not decompressor.eof:
            _fail(
                "workflow artifact ZIP deflate stream is truncated or exceeds its "
                f"declared size: {info.filename}"
            )
        if decompressor.unused_data or decompressor.unconsumed_tail:
            _fail(
                "workflow artifact ZIP deflate stream has unconsumed trailing bytes: "
                f"{info.filename}"
            )
    else:  # The caller rejects unsupported methods before raw payload validation.
        _fail(f"workflow artifact ZIP compression method changed: {info.filename}")

    if len(payload) != info.file_size:
        _fail(f"workflow artifact ZIP uncompressed size differs: {info.filename}")
    if (zlib.crc32(payload) & 0xFFFFFFFF) != info.CRC:
        _fail(f"workflow artifact ZIP CRC differs: {info.filename}")


def _validate_local_records(
    data: bytes,
    infos: Sequence[zipfile.ZipInfo],
    central_offset: int,
    timestamps: dict[int, tuple[int, int]],
) -> None:
    ordered = sorted(infos, key=lambda info: info.header_offset)
    if not ordered or ordered[0].header_offset != 0:
        _fail("workflow artifact ZIP has a prefix before its first local record")
    if len({info.header_offset for info in ordered}) != len(ordered):
        _fail("workflow artifact ZIP reuses a local-header offset")

    for index, info in enumerate(ordered):
        offset = info.header_offset
        boundary = (
            ordered[index + 1].header_offset
            if index + 1 < len(ordered)
            else central_offset
        )
        if offset < 0 or offset + _ZIP_LOCAL.size > boundary:
            _fail("workflow artifact ZIP local record is truncated")
        (
            signature,
            extract_version,
            flags,
            compression,
            modified_time,
            modified_date,
            crc,
            compressed_size,
            file_size,
            name_length,
            extra_length,
        ) = _ZIP_LOCAL.unpack_from(data, offset)
        if signature != _ZIP_LOCAL_SIGNATURE:
            _fail("workflow artifact ZIP local record signature is invalid")
        name_start = offset + _ZIP_LOCAL.size
        name_end = name_start + name_length
        data_start = name_end + extra_length
        data_end = data_start + info.compress_size
        if data_end > boundary:
            _fail("workflow artifact ZIP member payload overlaps another record")
        local_name = _decode_zip_name(
            data[name_start:name_end], flags, label="ZIP local member name"
        )
        if extra_length != 0:
            _fail("workflow artifact ZIP local member extras are forbidden")
        if (
            local_name != info.filename
            or extract_version != info.extract_version
            or flags != info.flag_bits
            or compression != info.compress_type
            or (modified_time, modified_date) != timestamps.get(info.header_offset)
        ):
            _fail("workflow artifact ZIP local and central metadata differ")

        local_sizes = (crc, compressed_size, file_size)
        central_sizes = (info.CRC, info.compress_size, info.file_size)
        if flags & _ZIP_FLAG_DATA_DESCRIPTOR:
            if local_sizes not in ((0, 0, 0), central_sizes):
                _fail("workflow artifact ZIP local deferred sizes are inconsistent")
            descriptor = data[data_end:boundary]
            if descriptor.startswith(_ZIP_DATA_DESCRIPTOR_SIGNATURE):
                descriptor = descriptor[len(_ZIP_DATA_DESCRIPTOR_SIGNATURE) :]
            if len(descriptor) != _ZIP_DATA_DESCRIPTOR.size:
                _fail("workflow artifact ZIP data descriptor is noncanonical")
            if _ZIP_DATA_DESCRIPTOR.unpack(descriptor) != central_sizes:
                _fail("workflow artifact ZIP data descriptor differs from metadata")
        else:
            if local_sizes != central_sizes or data_end != boundary:
                _fail("workflow artifact ZIP local sizes or framing differ")
        _validate_compressed_payload(data[data_start:data_end], info)


def _audited_infos(
    snapshot: FileSnapshot,
    archive: zipfile.ZipFile,
    container: ContainerSpec,
) -> dict[str, zipfile.ZipInfo]:
    infos = archive.infolist()
    if archive.comment:
        _fail("workflow artifact ZIP archive comments are forbidden")
    expected = {member.archive_name: member for member in container.members}
    maximum_entries = len(container.members)
    if len(infos) > maximum_entries:
        _fail(
            f"workflow artifact {container.artifact_name} exceeds its "
            f"{maximum_entries}-entry limit"
        )

    observed: dict[str, zipfile.ZipInfo] = {}
    casefolded: dict[str, str] = {}
    total_size = 0
    maximum_total = sum(member.maximum_bytes for member in container.members)
    for info in infos:
        _validate_member_path(info.filename, label="workflow artifact ZIP member")
        folded = info.filename.casefold()
        previous = casefolded.get(folded)
        if previous is not None:
            _fail(
                "workflow artifact ZIP contains a duplicate or case-insensitive "
                f"collision: {previous!r} and {info.filename!r}"
            )
        casefolded[folded] = info.filename
        if info.filename in observed:
            _fail(f"workflow artifact ZIP contains a duplicate: {info.filename!r}")
        observed[info.filename] = info

        if info.flag_bits & _ZIP_FLAG_ENCRYPTED:
            _fail(f"workflow artifact ZIP member is encrypted: {info.filename}")
        if info.flag_bits & ~_ZIP_ALLOWED_FLAGS:
            _fail(f"workflow artifact ZIP member uses unsupported flags: {info.filename}")
        if info.compress_type not in _ZIP_SUPPORTED_COMPRESSION:
            _fail(
                f"workflow artifact ZIP member uses unsupported compression: "
                f"{info.filename}"
            )
        if info.extra or info.comment:
            _fail("workflow artifact ZIP member extras and comments are forbidden")
        unix_mode = (info.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(unix_mode)
        if (
            info.is_dir()
            or info.filename.endswith("/")
            or info.external_attr & 0x10
            or file_type not in (0, stat.S_IFREG)
        ):
            _fail(
                "workflow artifact ZIP directories, symlinks, and special files "
                f"are forbidden: {info.filename}"
            )
        member = expected.get(info.filename)
        if member is not None and info.file_size > member.maximum_bytes:
            _fail(
                f"workflow artifact ZIP member exceeds {member.maximum_bytes} bytes: "
                f"{info.filename}"
            )
        total_size += info.file_size
        if total_size > maximum_total:
            _fail("workflow artifact ZIP logical contents exceed their total size limit")

    if set(observed) != set(expected):
        _fail(
            f"workflow artifact {container.artifact_name} members differ: "
            f"expected={sorted(expected)}, got={sorted(observed)}"
        )
    central_offset, central_size = _validate_eocd(
        snapshot.data, expected_entries=len(infos)
    )
    timestamps = _validate_central_directory(
        snapshot.data,
        infos,
        central_offset=central_offset,
        central_size=central_size,
    )
    _validate_local_records(snapshot.data, infos, central_offset, timestamps)
    return observed


def _write_all(descriptor: int, data: bytes) -> None:
    remaining = memoryview(data)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError(errno.EIO, "short write while extracting workflow artifact")
        remaining = remaining[written:]


def _close_with_primary(
    close: Callable[[], object],
    *,
    label: str,
    primary: BaseException | None,
) -> None:
    try:
        close()
    except BaseException as cleanup_error:
        if primary is not None:
            primary.add_note(f"closing {label} also failed: {cleanup_error}")
        else:
            raise


def _extract_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    member: MemberSpec,
    staging_fd: int,
    staged_files: dict[str, StagedFileRecord],
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(member.destination_name, flags, 0o600, dir_fd=staging_fd)
    source: zipfile.ZipExtFile | None = None
    primary: BaseException | None = None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            _fail(
                "new workflow-artifact output is not one private regular file: "
                f"{member.destination_name}"
            )
        creation_identity = (metadata.st_dev, metadata.st_ino)
        staged_files[member.destination_name] = StagedFileRecord(
            identity=creation_identity,
        )
        source = archive.open(info, "r")
        total = 0
        while True:
            chunk = source.read(_READ_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > member.maximum_bytes:
                _fail(
                    f"workflow artifact ZIP member exceeds {member.maximum_bytes} bytes "
                    f"while reading: {member.archive_name}"
                )
            _write_all(descriptor, chunk)
        if total != info.file_size:
            _fail(
                f"workflow artifact ZIP member size differs after CRC-checked read: "
                f"{member.archive_name}"
            )
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
        final_metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(final_metadata.st_mode)
            or final_metadata.st_nlink != 1
            or (final_metadata.st_dev, final_metadata.st_ino) != creation_identity
            or final_metadata.st_size != info.file_size
            or stat.S_IMODE(final_metadata.st_mode) != 0o644
        ):
            _fail(
                "workflow-artifact output contract changed after extraction: "
                f"{member.destination_name}"
            )
        staged_files[member.destination_name] = StagedFileRecord(
            identity=creation_identity,
            expected_size=info.file_size,
            expected_mode=0o644,
        )
    except BaseException as exc:
        primary = exc
        raise
    finally:
        if source is not None:
            _close_with_primary(source.close, label="ZIP member reader", primary=primary)
        _close_with_primary(
            lambda: os.close(descriptor),
            label="workflow artifact output descriptor",
            primary=primary,
        )


def _extract_container(
    path: pathlib.Path,
    container: ContainerSpec,
    staging_fd: int,
    staged_files: dict[str, StagedFileRecord],
) -> None:
    try:
        snapshot = read_regular_snapshot(
            path,
            maximum=container.maximum_archive_bytes,
            label=f"raw workflow artifact {container.artifact_name}",
        )
    except EvidenceIOError as exc:
        raise WorkflowArtifactError(str(exc)) from exc
    try:
        with zipfile.ZipFile(io.BytesIO(snapshot.data), "r", allowZip64=False) as archive:
            infos = _audited_infos(snapshot, archive, container)
            for member in container.members:
                _extract_member(
                    archive,
                    infos[member.archive_name],
                    member,
                    staging_fd,
                    staged_files,
                )
    except WorkflowArtifactError:
        raise
    except (EOFError, OSError, RuntimeError, struct.error, zipfile.BadZipFile) as exc:
        raise WorkflowArtifactError(
            f"workflow artifact {container.artifact_name} ZIP is invalid: {exc}"
        ) from exc


def _validate_profile_contract(profile: ProfileSpec) -> None:
    artifact_names: set[str] = set()
    artifact_casefolds: set[str] = set()
    destination_names: set[str] = set()
    destination_casefolds: set[str] = set()
    for container in profile.containers:
        _validate_member_path(container.artifact_name, label="internal artifact name")
        if "/" in container.artifact_name or container.artifact_name.endswith(".zip"):
            _fail(
                "internal artifact name must be one extension-free leaf: "
                f"{container.artifact_name}"
            )
        if (
            container.artifact_name in artifact_names
            or container.artifact_name.casefold() in artifact_casefolds
        ):
            _fail(f"internal profile repeats an artifact name: {container.artifact_name}")
        artifact_names.add(container.artifact_name)
        artifact_casefolds.add(container.artifact_name.casefold())
        if container.maximum_archive_bytes <= 0:
            _fail("internal workflow-artifact archive bound must be positive")
        archive_names: set[str] = set()
        archive_casefolds: set[str] = set()
        for member in container.members:
            for name, label in (
                (member.archive_name, "internal archive member"),
                (member.destination_name, "internal destination member"),
            ):
                _validate_member_path(name, label=label)
                if "/" in name:
                    _fail(f"{label} must be one leaf: {name}")
            if member.maximum_bytes <= 0:
                _fail("internal workflow-artifact member bound must be positive")
            if (
                member.archive_name in archive_names
                or member.archive_name.casefold() in archive_casefolds
            ):
                _fail(
                    f"internal archive members collide in {container.artifact_name}: "
                    f"{member.archive_name}"
                )
            archive_names.add(member.archive_name)
            archive_casefolds.add(member.archive_name.casefold())
            if (
                member.destination_name in destination_names
                or member.destination_name.casefold() in destination_casefolds
            ):
                _fail(
                    "internal workflow-artifact destinations collide: "
                    f"{member.destination_name}"
                )
            destination_names.add(member.destination_name)
            destination_casefolds.add(member.destination_name.casefold())


def _open_repository_root() -> int:
    """Open the canonical repository without following any path component."""

    if (
        os.name != "posix"
        or not _SUPPORTS_OPENAT
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
    ):
        _fail("workflow-artifact publication requires POSIX openat no-follow APIs")
    absolute = pathlib.Path(os.path.abspath(REPOSITORY_ROOT))
    if not absolute.is_absolute() or ".." in absolute.parts:
        _fail(f"repository root is not one canonical absolute path: {absolute}")
    try:
        descriptor = os.open(absolute.anchor, _DIRECTORY_OPEN_FLAGS)
    except OSError as exc:
        raise WorkflowArtifactError(
            f"cannot safely open repository filesystem root: {exc}"
        ) from exc
    try:
        for component in absolute.parts[1:]:
            _validate_member_path(component, label="repository root component")
            try:
                next_descriptor = os.open(
                    component,
                    _DIRECTORY_OPEN_FLAGS,
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise WorkflowArtifactError(
                    f"cannot safely open repository root component {component!r}: {exc}"
                ) from exc
            previous_descriptor = descriptor
            descriptor = next_descriptor
            os.close(previous_descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            _fail(f"repository root is not a directory: {absolute}")
        return descriptor
    except BaseException as primary:
        _close_with_primary(
            lambda: os.close(descriptor),
            label="repository root descriptor",
            primary=primary,
        )
        raise


def _open_output_parent(
    relative: pathlib.PurePosixPath,
) -> tuple[pathlib.Path, int]:
    """Create and open each fixed output-parent component with mkdirat/openat."""

    if relative.is_absolute() or ".." in relative.parts:
        _fail(f"internal output parent is invalid: {relative}")
    parent = REPOSITORY_ROOT.joinpath(*relative.parts)
    descriptor = _open_repository_root()
    try:
        for component in relative.parts:
            _validate_member_path(component, label="internal output parent component")
            if "/" in component:
                _fail(f"internal output parent component is not one leaf: {component}")
            try:
                os.mkdir(component, mode=0o755, dir_fd=descriptor)
            except FileExistsError:
                pass
            except OSError as exc:
                raise WorkflowArtifactError(
                    f"cannot create output parent component {component!r}: {exc}"
                ) from exc
            try:
                next_descriptor = os.open(
                    component,
                    _DIRECTORY_OPEN_FLAGS,
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise WorkflowArtifactError(
                    f"cannot safely open output parent component {component!r}: {exc}"
                ) from exc
            previous_descriptor = descriptor
            descriptor = next_descriptor
            os.close(previous_descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            _fail(f"workflow-artifact output parent is not a directory: {parent}")
        return parent, descriptor
    except BaseException as primary:
        _close_with_primary(
            lambda: os.close(descriptor),
            label="workflow-artifact output parent descriptor",
            primary=primary,
        )
        raise


def _create_staging_directory(
    parent_fd: int,
    destination_name: str,
) -> tuple[str, int, FileIdentity]:
    for _attempt in range(8):
        name = f".{destination_name}.workflow-artifact-{secrets.token_hex(16)}"
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        except OSError as exc:
            raise WorkflowArtifactError(
                f"cannot create private workflow-artifact staging directory: {exc}"
            ) from exc
        try:
            descriptor = os.open(
                name,
                _DIRECTORY_OPEN_FLAGS,
                dir_fd=parent_fd,
            )
        except OSError as exc:
            raise WorkflowArtifactError(
                "cannot safely open the newly created workflow-artifact staging "
                f"directory; it is intentionally preserved: {exc}"
            ) from exc
        try:
            os.fchmod(descriptor, 0o700)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                _fail(
                    "new workflow-artifact staging path is not one owned private "
                    f"directory: {name}"
                )
            return name, descriptor, (metadata.st_dev, metadata.st_ino)
        except BaseException as primary:
            _close_with_primary(
                lambda: os.close(descriptor),
                label="invalid workflow-artifact staging descriptor",
                primary=primary,
            )
            raise
    _fail("cannot allocate a unique workflow-artifact staging directory")


def _rename_noreplace(
    parent_fd: int,
    staging_name: str,
    destination_name: str,
) -> None:
    try:
        library = ctypes.CDLL(None, use_errno=True)
    except OSError as exc:
        raise WorkflowArtifactError(f"cannot load atomic no-replace API: {exc}") from exc
    if sys.platform == "darwin":
        symbol_name = "renameatx_np"
        flags = _RENAME_EXCL
    elif sys.platform.startswith("linux"):
        symbol_name = "renameat2"
        flags = _RENAME_NOREPLACE
    else:
        _fail("workflow-artifact publication requires native atomic no-replace rename")
    try:
        rename = getattr(library, symbol_name)
    except AttributeError:
        _fail(f"workflow-artifact publication cannot load {symbol_name}")
    rename.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    rename.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = rename(
        parent_fd,
        os.fsencode(staging_name),
        parent_fd,
        os.fsencode(destination_name),
        flags,
    )
    if result == 0:
        return
    observed_errno = ctypes.get_errno()
    if observed_errno == errno.EEXIST:
        _fail(f"workflow-artifact destination already exists: {destination_name}")
    unsupported = {
        errno.EINVAL,
        errno.ENOSYS,
        getattr(errno, "ENOTSUP", errno.EINVAL),
        getattr(errno, "EOPNOTSUPP", errno.EINVAL),
    }
    if observed_errno in unsupported:
        _fail(
            f"{symbol_name} does not provide atomic no-replace publication on "
            f"this filesystem: {os.strerror(observed_errno)}"
        )
    if observed_errno == 0:
        _fail(f"{symbol_name} failed without reporting errno")
    _fail(
        f"cannot publish workflow artifact with {symbol_name}: "
        f"{os.strerror(observed_errno)} (errno {observed_errno})"
    )


def _validate_staging_directory(
    *,
    parent_fd: int,
    staging_name: str,
    staging_fd: int,
    staging_identity: FileIdentity,
    required_leaves: frozenset[str],
    staged_files: dict[str, StagedFileRecord],
    allowed_directory_modes: frozenset[int],
    require_complete_files: bool,
) -> tuple[str, ...]:
    """Validate the named staging directory against its open descriptors."""

    try:
        descriptor_metadata = os.fstat(staging_fd)
        named_metadata = os.stat(
            staging_name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise WorkflowArtifactError(
            f"cannot revalidate workflow-artifact staging before cleanup: {exc}"
        ) from exc
    descriptor_identity = (
        descriptor_metadata.st_dev,
        descriptor_metadata.st_ino,
    )
    named_identity = (named_metadata.st_dev, named_metadata.st_ino)
    if (
        not stat.S_ISDIR(descriptor_metadata.st_mode)
        or not stat.S_ISDIR(named_metadata.st_mode)
        or descriptor_metadata.st_uid != os.geteuid()
        or named_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(descriptor_metadata.st_mode) not in allowed_directory_modes
        or stat.S_IMODE(named_metadata.st_mode) not in allowed_directory_modes
        or descriptor_identity != staging_identity
        or named_identity != staging_identity
    ):
        _fail(
            "workflow-artifact staging identity, owner, or mode changed: "
            f"{staging_name}"
        )

    observed: dict[str, os.stat_result] = {}
    try:
        with os.scandir(staging_fd) as entries:
            for entry in entries:
                if len(observed) >= len(required_leaves):
                    _fail("workflow-artifact staging exceeds its fixed leaf limit")
                name = entry.name
                if name not in required_leaves:
                    _fail(
                        "workflow-artifact staging contains an unexpected leaf; "
                        f"refusing publication or cleanup: {name!r}"
                    )
                metadata = os.stat(
                    name,
                    dir_fd=staging_fd,
                    follow_symlinks=False,
                )
                record = staged_files.get(name)
                if (
                    record is None
                    or not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or (metadata.st_dev, metadata.st_ino) != record.identity
                ):
                    _fail(
                        "workflow-artifact staging leaf identity changed: "
                        f"{name}"
                    )
                if require_complete_files and (
                    record.expected_size is None
                    or record.expected_mode is None
                    or metadata.st_size != record.expected_size
                    or stat.S_IMODE(metadata.st_mode) != record.expected_mode
                ):
                    _fail(
                        "workflow-artifact staging leaf size or mode changed: "
                        f"{name}"
                    )
                observed[name] = metadata
    except WorkflowArtifactError:
        raise
    except OSError as exc:
        raise WorkflowArtifactError(
            f"cannot enumerate workflow-artifact staging: {exc}"
        ) from exc
    if set(observed) != required_leaves or set(staged_files) != required_leaves:
        _fail(
            "workflow-artifact staging leaf set differs from its fixed contract: "
            f"{staging_name}"
        )
    return tuple(sorted(observed))


def _cleanup_staging_directory(
    *,
    parent_fd: int,
    staging_name: str,
    staging_fd: int,
    staging_identity: FileIdentity,
    staged_files: dict[str, StagedFileRecord],
) -> None:
    """Remove only the descriptor-bound staging directory and created leaves."""

    observed = _validate_staging_directory(
        parent_fd=parent_fd,
        staging_name=staging_name,
        staging_fd=staging_fd,
        staging_identity=staging_identity,
        required_leaves=frozenset(staged_files),
        staged_files=staged_files,
        allowed_directory_modes=frozenset((0o700, 0o755)),
        require_complete_files=False,
    )

    try:
        for name in sorted(observed):
            os.unlink(name, dir_fd=staging_fd)
        os.fsync(staging_fd)
        final_metadata = os.stat(
            staging_name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(final_metadata.st_mode)
            or (final_metadata.st_dev, final_metadata.st_ino) != staging_identity
        ):
            _fail(
                "workflow-artifact staging identity changed during cleanup; "
                f"refusing to remove {staging_name}"
            )
        os.rmdir(staging_name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except WorkflowArtifactError:
        raise
    except OSError as exc:
        raise WorkflowArtifactError(
            f"cannot remove descriptor-bound workflow-artifact staging: {exc}"
        ) from exc


def extract_profile(profile_name: str) -> pathlib.Path:
    """Extract one code-owned profile and atomically publish its fixed output."""

    profile = PROFILES.get(profile_name)
    if profile is None:
        _fail(f"unknown workflow-artifact profile: {profile_name}")
    _validate_profile_contract(profile)
    container_paths = _raw_container_paths(profile)
    destination = _repository_path(profile.destination)
    parent_relative = pathlib.PurePosixPath(*profile.destination.parts[:-1])
    _parent, parent_fd = _open_output_parent(parent_relative)
    staging_name: str | None = None
    staging_fd: int | None = None
    staging_identity: FileIdentity | None = None
    staged_files: dict[str, StagedFileRecord] = {}
    expected_leaves = frozenset(
        member.destination_name
        for container in profile.containers
        for member in container.members
    )
    primary: BaseException | None = None
    published = False
    try:
        destination_name = profile.destination.name
        staging_name, staging_fd, staging_identity = _create_staging_directory(
            parent_fd,
            destination_name,
        )
        for path, container in zip(container_paths, profile.containers, strict=True):
            _extract_container(
                path,
                container,
                staging_fd,
                staged_files,
            )
        os.fchmod(staging_fd, 0o755)
        os.fsync(staging_fd)
        _validate_staging_directory(
            parent_fd=parent_fd,
            staging_name=staging_name,
            staging_fd=staging_fd,
            staging_identity=staging_identity,
            required_leaves=expected_leaves,
            staged_files=staged_files,
            allowed_directory_modes=frozenset((0o755,)),
            require_complete_files=True,
        )
        _rename_noreplace(parent_fd, staging_name, destination_name)
        published = True
        os.fsync(parent_fd)
        return destination
    except BaseException as exc:
        primary = exc
        raise
    finally:
        finalization_errors: list[tuple[str, BaseException]] = []
        if (
            staging_name is not None
            and staging_fd is not None
            and staging_identity is not None
            and not published
        ):
            try:
                _cleanup_staging_directory(
                    parent_fd=parent_fd,
                    staging_name=staging_name,
                    staging_fd=staging_fd,
                    staging_identity=staging_identity,
                    staged_files=staged_files,
                )
            except BaseException as cleanup_error:
                finalization_errors.append(
                    ("workflow-artifact staging cleanup", cleanup_error)
                )
        if staging_fd is not None:
            try:
                os.close(staging_fd)
            except BaseException as cleanup_error:
                finalization_errors.append(
                    ("closing workflow-artifact staging descriptor", cleanup_error)
                )
        try:
            os.close(parent_fd)
        except BaseException as cleanup_error:
            finalization_errors.append(
                ("closing workflow-artifact output parent descriptor", cleanup_error)
            )
        if primary is not None:
            for label, cleanup_error in finalization_errors:
                primary.add_note(f"{label} also failed: {cleanup_error}")
        elif finalization_errors:
            label, finalization_error = finalization_errors[0]
            finalization_error.add_note(f"while {label}")
            for later_label, later_error in finalization_errors[1:]:
                finalization_error.add_note(
                    f"{later_label} also failed: {later_error}"
                )
            raise finalization_error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", choices=tuple(PROFILES))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        destination = extract_profile(arguments.profile)
    except (WorkflowArtifactError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    profile = PROFILES[arguments.profile]
    member_count = sum(len(container.members) for container in profile.containers)
    relative_destination = destination.relative_to(REPOSITORY_ROOT).as_posix()
    print(
        "WORKFLOW_ARTIFACT_EXTRACT_PASS "
        f"profile={profile.name} containers={len(profile.containers)} "
        f"files={member_count} destination={relative_destination}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
