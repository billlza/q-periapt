#!/usr/bin/env python3
"""Strict fixed-root I/O for publication receipts and results candidates.

This module owns only filesystem and JSON mechanics.  Domain receipt shape and
state transitions remain in the publication-contract modules.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import pathlib
import stat
import sys
from dataclasses import dataclass
from typing import Any, Never

from evidence_io import (
    EvidenceIOError,
    FileSnapshot,
    consume_regular_snapshot_at,
    parse_strict_json_bytes,
)


DEFAULT_RECEIPT_MAX_BYTES = 16 * 1024 * 1024
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
PUBLIC_FILE_MODE = 0o644
_DARWIN_RENAME_EXCL = 0x00000004
_LINUX_RENAME_NOREPLACE = 0x00000001


class PublicationReceiptIOError(ValueError):
    """A publication receipt path, file, or JSON value is unsafe."""


class PublicationReceiptCommittedError(PublicationReceiptIOError):
    """The final leaf exists, but its parent durability check failed."""


@dataclass(frozen=True, slots=True)
class StrictJsonSnapshot:
    """One strict JSON object and the exact stable bytes that produced it."""

    file: FileSnapshot
    value: dict[str, Any]


def _fail(message: str) -> Never:
    raise PublicationReceiptIOError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _effective_uid() -> int:
    getter = getattr(os, "geteuid", None)
    if getter is None:
        _fail("publication receipt I/O requires POSIX owner metadata")
    return int(getter())


def _directory_metadata(
    metadata: os.stat_result,
    *,
    required_mode: int,
    label: str,
) -> None:
    _require(
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == _effective_uid()
        and stat.S_IMODE(metadata.st_mode) == required_mode,
        f"{label} must be an owned mode-{required_mode:04o} directory",
    )


def normalize_safe_root(
    root: pathlib.Path,
    *,
    label: str,
    required_mode: int = PRIVATE_DIRECTORY_MODE,
) -> pathlib.Path:
    """Return one canonical, owned, non-symlink fixed root."""

    _require(root.is_absolute(), f"{label} must be absolute")
    absolute = os.path.abspath(os.fspath(root))
    resolved = os.path.realpath(os.fspath(root))
    _require(absolute == resolved, f"{label} must be canonical and symlink-free")
    normalized = pathlib.Path(resolved)
    try:
        metadata = normalized.lstat()
    except OSError as exc:
        raise PublicationReceiptIOError(f"cannot inspect {label}") from exc
    _require(not normalized.is_symlink(), f"{label} must not be a symlink")
    _directory_metadata(metadata, required_mode=required_mode, label=label)
    return normalized


def _open_or_create_private_safe_root(
    root: pathlib.Path,
    *,
    label: str,
    create: bool,
    sync_parent: bool = False,
) -> tuple[pathlib.Path, int]:
    """Open one fixed private root through a pinned parent descriptor."""

    _require(root.is_absolute(), f"{label} must be absolute")
    _require(
        all(part not in {"", ".", ".."} for part in root.parts[1:]),
        f"{label} must be canonically spelled",
    )
    parent = root.parent
    _require(
        os.path.realpath(os.fspath(parent)) == os.path.abspath(os.fspath(parent)),
        f"{label} parent must be canonical and symlink-free",
    )
    try:
        parent_metadata = parent.lstat()
    except OSError as exc:
        raise PublicationReceiptIOError(f"cannot inspect {label} parent") from exc
    _require(
        stat.S_ISDIR(parent_metadata.st_mode)
        and not parent.is_symlink()
        and parent_metadata.st_uid == _effective_uid()
        and stat.S_IMODE(parent_metadata.st_mode) & 0o002 == 0,
        f"{label} parent must be an owned non-world-writable directory",
    )
    parent_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        parent_fd = os.open(parent, parent_flags)
    except OSError as exc:
        raise PublicationReceiptIOError(f"cannot open {label} parent") from exc
    root_fd = -1
    primary_error: BaseException | None = None
    try:
        opened_parent = os.fstat(parent_fd)
        _require(
            stat.S_ISDIR(opened_parent.st_mode)
            and opened_parent.st_uid == _effective_uid()
            and stat.S_IMODE(opened_parent.st_mode) & 0o002 == 0
            and opened_parent.st_dev == parent_metadata.st_dev
            and opened_parent.st_ino == parent_metadata.st_ino,
            f"{label} parent identity changed while opening",
        )
        if create:
            try:
                os.mkdir(root.name, PRIVATE_DIRECTORY_MODE, dir_fd=parent_fd)
            except FileExistsError:
                pass
            except OSError as exc:
                raise PublicationReceiptIOError(f"cannot create {label}") from exc
        if create or sync_parent:
            try:
                os.fsync(parent_fd)
            except OSError as exc:
                raise PublicationReceiptIOError(
                    f"cannot sync {label} parent"
                ) from exc
        root_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            root_fd = os.open(root.name, root_flags, dir_fd=parent_fd)
        except OSError as exc:
            raise PublicationReceiptIOError(f"cannot open {label}") from exc
        opened_root = os.fstat(root_fd)
        named_root = os.stat(root.name, dir_fd=parent_fd, follow_symlinks=False)
        _directory_metadata(
            opened_root,
            required_mode=PRIVATE_DIRECTORY_MODE,
            label=label,
        )
        _require(
            named_root.st_dev == opened_root.st_dev
            and named_root.st_ino == opened_root.st_ino
            and os.path.realpath(os.fspath(root)) == os.path.abspath(os.fspath(root)),
            f"{label} identity changed while opening",
        )
    except BaseException as exc:
        primary_error = exc
        if root_fd >= 0:
            try:
                os.close(root_fd)
            except OSError as close_error:
                exc.add_note(f"cannot close failed {label}: {close_error}")
        raise
    finally:
        try:
            os.close(parent_fd)
        except OSError as exc:
            detail = f"cannot close {label} parent"
            if primary_error is not None:
                primary_error.add_note(detail)
            else:
                if root_fd >= 0:
                    try:
                        os.close(root_fd)
                    except OSError as root_close_error:
                        exc.add_note(
                            f"cannot also close opened {label}: {root_close_error}"
                        )
                raise PublicationReceiptIOError(detail) from exc
    return root, root_fd


def ensure_private_safe_root(
    root: pathlib.Path,
    *,
    label: str,
) -> pathlib.Path:
    """Create one fixed private root if absent, then return it normalized."""

    normalized, descriptor = _open_or_create_private_safe_root(
        root,
        label=label,
        create=True,
    )
    try:
        os.close(descriptor)
    except OSError as exc:
        raise PublicationReceiptIOError(f"cannot close {label}") from exc
    return normalized


def _open_directory(
    path: pathlib.Path,
    *,
    label: str,
    required_mode: int,
) -> int:
    """Open and identity-check one already-normalized directory."""

    try:
        before = path.lstat()
    except OSError as exc:
        raise PublicationReceiptIOError(f"cannot inspect {label}") from exc
    _require(not path.is_symlink(), f"{label} must not be a symlink")
    _directory_metadata(before, required_mode=required_mode, label=label)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PublicationReceiptIOError(f"cannot open {label}") from exc
    after = os.fstat(descriptor)
    if (
        after.st_dev != before.st_dev
        or after.st_ino != before.st_ino
        or not stat.S_ISDIR(after.st_mode)
        or after.st_uid != _effective_uid()
        or stat.S_IMODE(after.st_mode) != required_mode
    ):
        os.close(descriptor)
        _fail(f"{label} identity changed while opening")
    return descriptor


def open_private_directory(path: pathlib.Path, *, label: str) -> int:
    """Open one caller-prevalidated private directory and pin its identity."""

    return _open_directory(
        path,
        label=label,
        required_mode=PRIVATE_DIRECTORY_MODE,
    )


def verify_private_direct_child_and_sync_parent(
    *,
    safe_root: pathlib.Path,
    direct_child_name: str,
    label: str,
) -> pathlib.Path:
    """Pin one private direct child and durably commit its directory entry."""

    _require(
        direct_child_name not in {"", ".", ".."}
        and "/" not in direct_child_name
        and "\\" not in direct_child_name,
        f"{label} directory leaf is unsafe",
    )
    root, root_fd = _open_or_create_private_safe_root(
        safe_root,
        label=f"{label} safe root",
        create=False,
        sync_parent=True,
    )
    child = root / direct_child_name
    child_fd = -1
    primary_error: BaseException | None = None
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        try:
            child_fd = os.open(direct_child_name, flags, dir_fd=root_fd)
        except OSError as exc:
            raise PublicationReceiptIOError(
                f"cannot open {label} directory"
            ) from exc
        opened_child = os.fstat(child_fd)
        named_child = os.stat(
            direct_child_name,
            dir_fd=root_fd,
            follow_symlinks=False,
        )
        _directory_metadata(
            opened_child,
            required_mode=PRIVATE_DIRECTORY_MODE,
            label=f"{label} directory",
        )
        _require(
            named_child.st_dev == opened_child.st_dev
            and named_child.st_ino == opened_child.st_ino,
            f"{label} directory identity changed while opening",
        )
        try:
            os.fsync(root_fd)
        except OSError as exc:
            raise PublicationReceiptIOError(
                f"cannot durably commit {label} directory entry"
            ) from exc
        current_root = safe_root.lstat()
        current_child = child.lstat()
        opened_root = os.fstat(root_fd)
        _require(
            current_root.st_dev == opened_root.st_dev
            and current_root.st_ino == opened_root.st_ino
            and current_child.st_dev == opened_child.st_dev
            and current_child.st_ino == opened_child.st_ino,
            f"{label} root/directory identity changed while syncing",
        )
    except OSError as exc:
        wrapped = PublicationReceiptIOError(
            f"cannot validate {label} directory durability"
        )
        primary_error = wrapped
        raise wrapped from exc
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        cleanup_errors: list[OSError] = []
        if child_fd >= 0:
            try:
                os.close(child_fd)
            except OSError as exc:
                cleanup_errors.append(exc)
        try:
            os.close(root_fd)
        except OSError as exc:
            cleanup_errors.append(exc)
        if cleanup_errors:
            detail = f"cannot close {label} directory descriptor(s)"
            if primary_error is not None:
                primary_error.add_note(detail)
            else:
                raise PublicationReceiptIOError(detail) from cleanup_errors[0]
    return child


def _open_fixed_parent(
    path: pathlib.Path,
    *,
    safe_root: pathlib.Path,
    expected_leaf: str,
    label: str,
    parent_depth: int,
    root_mode: int,
    parent_mode: int,
) -> tuple[pathlib.Path, int, int, bool]:
    """Pin the safe root and exact parent while a fixed leaf is consumed."""

    _require(parent_depth in {0, 1}, f"{label} parent depth is unsupported")
    _require(path.is_absolute(), f"{label} must be absolute")
    _require(path.name == expected_leaf, f"{label} leaf differs")
    _require(
        all(part not in {"", ".", ".."} for part in path.parts[1:]),
        f"{label} must be canonically spelled",
    )
    root = normalize_safe_root(
        safe_root,
        label=f"{label} safe root",
        required_mode=root_mode,
    )
    parent = path.parent
    _require(
        os.path.abspath(os.fspath(parent)) == os.path.realpath(os.fspath(parent)),
        f"{label} parent must be canonical and symlink-free",
    )
    actual_root = parent if parent_depth == 0 else parent.parent
    _require(actual_root == root, f"{label} is outside its fixed root/depth")
    normalized = parent / expected_leaf
    _require(
        os.path.abspath(os.fspath(path)) == os.fspath(normalized),
        f"{label} path is not canonically spelled",
    )
    root_fd = _open_directory(
        root,
        label=f"{label} safe root",
        required_mode=root_mode,
    )
    if parent_depth == 0:
        return normalized, root_fd, root_fd, True
    _require(
        parent.name not in {"", ".", ".."}
        and "/" not in parent.name
        and "\\" not in parent.name,
        f"{label} parent leaf is unsafe",
    )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    parent_fd = -1
    try:
        parent_fd = os.open(parent.name, flags, dir_fd=root_fd)
        opened = os.fstat(parent_fd)
        named = os.stat(parent.name, dir_fd=root_fd, follow_symlinks=False)
        _directory_metadata(opened, required_mode=parent_mode, label=f"{label} parent")
        _require(
            opened.st_dev == named.st_dev and opened.st_ino == named.st_ino,
            f"{label} parent identity changed while opening",
        )
    except BaseException as exc:
        cleanup_errors: list[tuple[str, OSError]] = []
        if parent_fd >= 0:
            try:
                os.close(parent_fd)
            except OSError as close_error:
                cleanup_errors.append(("parent", close_error))
        try:
            os.close(root_fd)
        except OSError as close_error:
            cleanup_errors.append(("safe root", close_error))
        for resource, close_error in cleanup_errors:
            exc.add_note(
                f"cannot close failed {label} {resource}: {close_error}"
            )
        raise
    return normalized, root_fd, parent_fd, False


def _verify_fixed_parent_identity(
    *,
    safe_root: pathlib.Path,
    parent: pathlib.Path,
    root_fd: int,
    parent_fd: int,
    label: str,
) -> None:
    try:
        current_root = safe_root.lstat()
        current_parent = parent.lstat()
    except OSError as exc:
        raise PublicationReceiptIOError(
            f"{label} root/parent changed while reading"
        ) from exc
    opened_root = os.fstat(root_fd)
    opened_parent = os.fstat(parent_fd)
    _require(
        current_root.st_dev == opened_root.st_dev
        and current_root.st_ino == opened_root.st_ino
        and current_parent.st_dev == opened_parent.st_dev
        and current_parent.st_ino == opened_parent.st_ino,
        f"{label} root/parent identity changed while reading",
    )


def _close_fixed_parent_descriptors(
    *,
    root_fd: int,
    parent_fd: int,
    shared: bool,
    label: str,
    primary_error: BaseException | None,
) -> None:
    cleanup_errors: list[OSError] = []
    if not shared:
        try:
            os.close(parent_fd)
        except OSError as exc:
            cleanup_errors.append(exc)
    try:
        os.close(root_fd)
    except OSError as exc:
        cleanup_errors.append(exc)
    if cleanup_errors:
        detail = f"cannot close {label} fixed-root descriptor(s)"
        if primary_error is not None:
            primary_error.add_note(detail)
        else:
            raise PublicationReceiptIOError(detail) from cleanup_errors[0]


def _regular_metadata_validator(
    *,
    required_mode: int,
    label: str,
):
    def validate(metadata: os.stat_result) -> None:
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != _effective_uid()
            or stat.S_IMODE(metadata.st_mode) != required_mode
            or metadata.st_nlink != 1
        ):
            raise EvidenceIOError(
                f"{label} must be an owned mode-{required_mode:04o} "
                "single-link regular file"
            )

    return validate


def read_fixed_file_snapshot(
    path: pathlib.Path,
    *,
    safe_root: pathlib.Path,
    expected_leaf: str,
    label: str,
    parent_depth: int,
    maximum: int,
    file_mode: int,
    root_mode: int = PRIVATE_DIRECTORY_MODE,
    parent_mode: int = PRIVATE_DIRECTORY_MODE,
) -> FileSnapshot:
    """Read one bounded stable fixed-root regular file with exact metadata."""

    normalized, root_fd, parent_fd, shared = _open_fixed_parent(
        path,
        safe_root=safe_root,
        expected_leaf=expected_leaf,
        label=label,
        parent_depth=parent_depth,
        root_mode=root_mode,
        parent_mode=parent_mode,
    )
    primary_error: BaseException | None = None
    try:
        chunks: list[bytes] = []
        digest = consume_regular_snapshot_at(
            parent_fd,
            expected_leaf,
            display_path=normalized,
            maximum=maximum,
            label=label,
            consume=chunks.append,
            validate_metadata=_regular_metadata_validator(
                required_mode=file_mode,
                label=label,
            ),
        )
        data = b"".join(chunks)
        _require(
            len(data) == digest.size,
            f"{label} consumer byte count changed unexpectedly",
        )
        _verify_fixed_parent_identity(
            safe_root=safe_root,
            parent=normalized.parent,
            root_fd=root_fd,
            parent_fd=parent_fd,
            label=label,
        )
        return FileSnapshot(
            path=digest.path,
            data=data,
            size=digest.size,
            sha256=digest.sha256,
        )
    except EvidenceIOError as exc:
        wrapped = PublicationReceiptIOError(f"cannot safely read {label}")
        primary_error = wrapped
        raise wrapped from exc
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        _close_fixed_parent_descriptors(
            root_fd=root_fd,
            parent_fd=parent_fd,
            shared=shared,
            label=label,
            primary_error=primary_error,
        )


def read_fixed_json_snapshot(
    path: pathlib.Path,
    *,
    safe_root: pathlib.Path,
    expected_leaf: str,
    label: str,
    parent_depth: int,
    maximum: int = DEFAULT_RECEIPT_MAX_BYTES,
    file_mode: int = PRIVATE_FILE_MODE,
    root_mode: int = PRIVATE_DIRECTORY_MODE,
    parent_mode: int = PRIVATE_DIRECTORY_MODE,
) -> StrictJsonSnapshot:
    """Strict-parse a fixed-root JSON object from one stable byte snapshot."""

    snapshot = read_fixed_file_snapshot(
        path,
        safe_root=safe_root,
        expected_leaf=expected_leaf,
        label=label,
        parent_depth=parent_depth,
        maximum=maximum,
        file_mode=file_mode,
        root_mode=root_mode,
        parent_mode=parent_mode,
    )
    try:
        value = parse_strict_json_bytes(snapshot.data, label=label)
    except EvidenceIOError as exc:
        raise PublicationReceiptIOError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict) or any(
        not isinstance(key, str) for key in value
    ):
        _fail(f"{label} root must be a JSON object with string keys")
    return StrictJsonSnapshot(file=snapshot, value=value)


def _require_absent_at(directory_fd: int, leaf: str, label: str) -> None:
    try:
        os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise PublicationReceiptIOError(f"cannot inspect {label}") from exc
    _fail(f"{label} already exists")


def _write_all(descriptor: int, payload: bytes, *, label: str) -> None:
    offset = 0
    while offset < len(payload):
        try:
            written = os.write(descriptor, payload[offset:])
        except OSError as exc:
            raise PublicationReceiptIOError(f"cannot write {label}") from exc
        _require(written > 0, f"{label} write made no progress")
        offset += written


def _rename_noreplace(
    directory_fd: int,
    source_leaf: str,
    destination_leaf: str,
) -> None:
    """Atomically rename one sibling without ever replacing the destination."""

    library = ctypes.CDLL(None, use_errno=True)
    encoded_source = os.fsencode(source_leaf)
    encoded_destination = os.fsencode(destination_leaf)
    if sys.platform == "darwin":
        rename = getattr(library, "renameatx_np", None)
        flag = _DARWIN_RENAME_EXCL
    elif sys.platform.startswith("linux"):
        rename = getattr(library, "renameat2", None)
        flag = _LINUX_RENAME_NOREPLACE
    else:
        rename = None
        flag = 0
    if rename is None:
        _fail("atomic no-replace publication is unsupported on this host")
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
        directory_fd,
        encoded_source,
        directory_fd,
        encoded_destination,
        flag,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number == errno.EEXIST:
        _fail("publication receipt output already exists")
    if error_number == 0:
        _fail("atomic no-replace publication failed without errno")
    raise PublicationReceiptIOError(
        "cannot atomically publish publication receipt output"
    ) from OSError(error_number, os.strerror(error_number))


def canonical_json_bytes(value: object) -> bytes:
    """Encode one bounded, deterministic, ASCII-only results/receipt document."""

    try:
        payload = (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise PublicationReceiptIOError(
            "publication receipt output is not finite JSON"
        ) from exc
    _require(
        len(payload) <= DEFAULT_RECEIPT_MAX_BYTES,
        "publication receipt output exceeds the bounded size",
    )
    return payload


def write_private_bytes_noreplace_at(
    directory_fd: int,
    expected_leaf: str,
    payload: bytes,
    *,
    label: str,
    maximum: int = DEFAULT_RECEIPT_MAX_BYTES,
) -> str:
    """Publish bounded bytes below an already-owned private directory fd."""

    directory_metadata = os.fstat(directory_fd)
    _directory_metadata(
        directory_metadata,
        required_mode=PRIVATE_DIRECTORY_MODE,
        label=f"{label} parent",
    )
    _require(
        expected_leaf not in {"", ".", ".."}
        and "/" not in expected_leaf
        and "\\" not in expected_leaf,
        f"{label} leaf is unsafe",
    )
    _require(type(payload) is bytes, f"{label} payload must be exact bytes")
    _require(len(payload) <= maximum, f"{label} exceeds the bounded size")
    descriptor = -1
    staging_leaf = f".{expected_leaf}.pending-{os.getpid()}"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    published = False
    staging_created = False
    primary_error: BaseException | None = None
    try:
        _require_absent_at(directory_fd, expected_leaf, label)
        _require_absent_at(directory_fd, staging_leaf, f"{label} staging file")
        try:
            descriptor = os.open(
                staging_leaf,
                flags,
                PRIVATE_FILE_MODE,
                dir_fd=directory_fd,
            )
            staging_created = True
        except OSError as exc:
            raise PublicationReceiptIOError(
                f"cannot create {label} staging file"
            ) from exc
        _write_all(descriptor, payload, label=label)
        os.fchmod(descriptor, PRIVATE_FILE_MODE)
        metadata = os.fstat(descriptor)
        _regular_metadata_validator(
            required_mode=PRIVATE_FILE_MODE,
            label=label,
        )(metadata)
        try:
            os.fsync(descriptor)
        except OSError as exc:
            raise PublicationReceiptIOError(f"cannot sync {label}") from exc
        os.close(descriptor)
        descriptor = -1
        _rename_noreplace(directory_fd, staging_leaf, expected_leaf)
        published = True
        try:
            final_metadata = os.stat(
                expected_leaf,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            _regular_metadata_validator(
                required_mode=PRIVATE_FILE_MODE,
                label=label,
            )(final_metadata)
            os.fsync(directory_fd)
        except (EvidenceIOError, OSError) as exc:
            raise PublicationReceiptCommittedError(
                f"{label} was atomically published but its parent "
                "durability verification failed"
            ) from exc
    except OSError as exc:
        wrapped = PublicationReceiptIOError(f"cannot publish {label}")
        primary_error = wrapped
        raise wrapped from exc
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        cleanup_errors: list[OSError] = []
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as exc:
                cleanup_errors.append(exc)
        if staging_created and not published:
            try:
                os.unlink(staging_leaf, dir_fd=directory_fd)
            except OSError as exc:
                cleanup_errors.append(exc)
        if cleanup_errors:
            detail = (
                f"{label} cleanup failed for {len(cleanup_errors)} "
                "private staging resource(s)"
            )
            if primary_error is not None:
                primary_error.add_note(detail)
            else:
                raise PublicationReceiptIOError(detail) from cleanup_errors[0]
    return hashlib.sha256(payload).hexdigest()


def write_private_json_noreplace_at(
    directory_fd: int,
    expected_leaf: str,
    value: object,
    *,
    label: str,
    maximum: int = DEFAULT_RECEIPT_MAX_BYTES,
) -> str:
    """Publish deterministic strict JSON below a pinned private directory."""

    payload = canonical_json_bytes(value)
    return write_private_bytes_noreplace_at(
        directory_fd,
        expected_leaf,
        payload,
        label=label,
        maximum=maximum,
    )


def create_private_transaction_json(
    *,
    safe_root: pathlib.Path,
    transaction_prefix: str,
    expected_leaf: str,
    value: object,
    label: str,
    maximum: int = DEFAULT_RECEIPT_MAX_BYTES,
) -> tuple[pathlib.Path, str]:
    """Create a private transaction directory and one fixed receipt leaf."""

    _require(
        transaction_prefix
        and all(character.isascii() and (character.isalnum() or character in "-_.")
                for character in transaction_prefix),
        f"{label} transaction prefix is unsafe",
    )
    root, root_fd = _open_or_create_private_safe_root(
        safe_root,
        label=f"{label} safe root",
        create=True,
    )
    descriptor = -1
    primary_error: BaseException | None = None
    try:
        transaction_name = ""
        for attempt in range(1000):
            candidate = f"{transaction_prefix}{os.getpid()}-{attempt}"
            try:
                os.mkdir(candidate, PRIVATE_DIRECTORY_MODE, dir_fd=root_fd)
                os.fsync(root_fd)
                transaction_name = candidate
                break
            except FileExistsError:
                continue
            except OSError as exc:
                raise PublicationReceiptIOError(
                    f"cannot create {label} transaction directory"
                ) from exc
        _require(
            bool(transaction_name),
            f"cannot allocate {label} transaction directory",
        )
        transaction = root / transaction_name
        transaction_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            descriptor = os.open(
                transaction_name,
                transaction_flags,
                dir_fd=root_fd,
            )
        except OSError as exc:
            raise PublicationReceiptIOError(
                f"cannot open {label} transaction directory"
            ) from exc
        transaction_metadata = os.fstat(descriptor)
        named_transaction = os.stat(
            transaction_name,
            dir_fd=root_fd,
            follow_symlinks=False,
        )
        _directory_metadata(
            transaction_metadata,
            required_mode=PRIVATE_DIRECTORY_MODE,
            label=f"{label} transaction directory",
        )
        _require(
            named_transaction.st_dev == transaction_metadata.st_dev
            and named_transaction.st_ino == transaction_metadata.st_ino,
            f"{label} transaction directory identity changed",
        )
        digest = write_private_json_noreplace_at(
            descriptor,
            expected_leaf,
            value,
            label=label,
            maximum=maximum,
        )
        try:
            current_root = safe_root.lstat()
            current_transaction = transaction.lstat()
        except OSError as exc:
            raise PublicationReceiptIOError(
                f"{label} output root identity changed during publication"
            ) from exc
        opened_root = os.fstat(root_fd)
        opened_transaction = os.fstat(descriptor)
        _require(
            current_root.st_dev == opened_root.st_dev
            and current_root.st_ino == opened_root.st_ino
            and current_transaction.st_dev == opened_transaction.st_dev
            and current_transaction.st_ino == opened_transaction.st_ino,
            f"{label} output root identity changed during publication",
        )
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        cleanup_errors: list[OSError] = []
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as exc:
                cleanup_errors.append(exc)
        try:
            os.close(root_fd)
        except OSError as exc:
            cleanup_errors.append(exc)
        if cleanup_errors:
            detail = f"cannot close {label} publication descriptor(s)"
            if primary_error is not None:
                primary_error.add_note(detail)
            else:
                raise PublicationReceiptIOError(detail) from cleanup_errors[0]
    return transaction / expected_leaf, digest


def write_fixed_private_json(
    *,
    safe_root: pathlib.Path,
    expected_leaf: str,
    value: object,
    label: str,
    maximum: int = DEFAULT_RECEIPT_MAX_BYTES,
) -> tuple[pathlib.Path, str]:
    """Write one fixed leaf directly below a module-owned private root."""

    root, descriptor = _open_or_create_private_safe_root(
        safe_root,
        label=f"{label} safe root",
        create=False,
    )
    primary_error: BaseException | None = None
    try:
        digest = write_private_json_noreplace_at(
            descriptor,
            expected_leaf,
            value,
            label=label,
            maximum=maximum,
        )
        try:
            current_root = safe_root.lstat()
        except OSError as exc:
            raise PublicationReceiptIOError(
                f"{label} safe root identity changed during publication"
            ) from exc
        opened_root = os.fstat(descriptor)
        _require(
            current_root.st_dev == opened_root.st_dev
            and current_root.st_ino == opened_root.st_ino,
            f"{label} safe root identity changed during publication",
        )
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        cleanup_errors: list[OSError] = []
        try:
            os.close(descriptor)
        except OSError as exc:
            cleanup_errors.append(exc)
        if cleanup_errors:
            detail = f"cannot close {label} safe root"
            if primary_error is not None:
                primary_error.add_note(detail)
            else:
                raise PublicationReceiptIOError(detail) from cleanup_errors[0]
    return root / expected_leaf, digest
