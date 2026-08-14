#!/usr/bin/env python3
"""Strict fixed-root I/O for publication receipts and results candidates.

This module owns only filesystem and JSON mechanics.  Domain receipt shape and
state transitions remain in the publication-contract modules.
"""

from __future__ import annotations

import contextlib
import ctypes
import errno
import hashlib
import json
import os
import pathlib
import stat
import sys
from dataclasses import dataclass
from collections.abc import Iterator
from typing import Any, Literal, Never

from evidence_io import (
    EvidenceIOError,
    FileSnapshot,
    consume_regular_snapshot_at,
    parse_strict_json_bytes,
)


DEFAULT_RECEIPT_MAX_BYTES = 16 * 1024 * 1024
MAX_FIXED_DIRECTORY_ENTRIES = 256
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
PUBLIC_FILE_MODE = 0o644
_DARWIN_RENAME_EXCL = 0x00000004
_LINUX_RENAME_NOREPLACE = 0x00000001


class PublicationReceiptIOError(ValueError):
    """A publication receipt path, file, or JSON value is unsafe."""


PublicationVisibility = Literal["committed", "indeterminate"]
_InterruptedVisibility = Literal["exact", "precommit", "indeterminate"]


class PublicationReceiptCommittedError(PublicationReceiptIOError):
    """A final leaf is committed or visibility is unsafe to classify."""

    def __init__(
        self,
        message: str,
        *,
        leaf: str | None = None,
        digest: str | None = None,
        visibility: PublicationVisibility = "committed",
    ) -> None:
        if visibility not in {"committed", "indeterminate"}:
            raise ValueError("publication visibility state is invalid")
        super().__init__(message)
        self.leaf = leaf
        self.digest = digest
        self.visibility = visibility


@dataclass(frozen=True, slots=True)
class StrictJsonSnapshot:
    """One strict JSON object and the exact stable bytes that produced it."""

    file: FileSnapshot
    value: dict[str, Any]


@dataclass(slots=True)
class PrivateDirectoryHandle:
    """One canonical private directory pinned below an already-open parent."""

    path: pathlib.Path
    descriptor: int
    parent_descriptor: int
    name: str
    device: int
    inode: int
    mode: int
    ancestor_descriptor: int | None = None
    ancestor_path: pathlib.Path | None = None
    ancestor_device: int | None = None
    ancestor_inode: int | None = None
    committed_publication: tuple[str, str] | None = None

    @property
    def committed_leaf(self) -> str | None:
        return (
            None
            if self.committed_publication is None
            else self.committed_publication[0]
        )

    @property
    def committed_sha256(self) -> str | None:
        return (
            None
            if self.committed_publication is None
            else self.committed_publication[1]
        )


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


def _safe_leaf(value: object, *, label: str) -> str:
    _require(
        type(value) is str
        and value not in {"", ".", ".."}
        and "/" not in value
        and "\\" not in value
        and "\x00" not in value,
        f"{label} must be one safe basename",
    )
    return value


def _normalized_descendant(
    path: pathlib.Path,
    *,
    safe_root: pathlib.Path,
    label: str,
) -> pathlib.Path:
    """Normalize one path and prove its separator-bounded fixed-root ancestry."""

    _require(path.is_absolute(), f"{label} must be absolute")
    _require(
        all(part not in {"", ".", ".."} for part in path.parts[1:]),
        f"{label} must be canonically spelled",
    )
    supplied = os.fspath(path)
    absolute = os.path.abspath(supplied)
    normalized_text = os.path.realpath(supplied)
    root_prefix = os.fspath(safe_root) + os.sep
    if not normalized_text.startswith(root_prefix):
        raise PublicationReceiptIOError(f"{label} is outside its fixed root")
    _require(
        normalized_text == absolute,
        f"{label} must be canonical and symlink-free",
    )
    return pathlib.Path(normalized_text)


def _validated_directory_inventory(
    expected_entries: frozenset[str],
    *,
    label: str,
) -> frozenset[str]:
    _require(
        type(expected_entries) is frozenset
        and len(expected_entries) <= MAX_FIXED_DIRECTORY_ENTRIES,
        f"{label} expected entry set is invalid or too large",
    )
    for entry in expected_entries:
        _safe_leaf(entry, label=f"{label} expected entry")
    return expected_entries


def verify_exact_directory_inventory_at(
    directory_fd: int,
    expected_entries: frozenset[str],
    *,
    label: str,
) -> frozenset[str]:
    """Boundedly inventory one pinned directory and require an exact leaf set."""

    expected = _validated_directory_inventory(expected_entries, label=label)
    try:
        metadata = os.fstat(directory_fd)
        _require(stat.S_ISDIR(metadata.st_mode), f"{label} descriptor is not a directory")
        actual: set[str] = set()
        with os.scandir(directory_fd) as iterator:
            for entry in iterator:
                name = _safe_leaf(entry.name, label=f"{label} observed entry")
                _require(name not in actual, f"{label} contains a duplicate entry")
                actual.add(name)
                _require(
                    len(actual) <= len(expected),
                    f"{label} entry set differs",
                )
    except PublicationReceiptIOError:
        raise
    except OSError as exc:
        raise PublicationReceiptIOError(f"cannot inventory {label}") from exc
    observed = frozenset(actual)
    _require(observed == expected, f"{label} entry set differs")
    return observed


def require_absent_leaf_at(directory_fd: int, leaf: str, *, label: str) -> None:
    """Require one safe leaf to be absent below a pinned directory."""

    leaf = _safe_leaf(leaf, label=f"{label} leaf")
    try:
        os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise PublicationReceiptIOError(f"cannot inspect {label}") from exc
    _fail(f"{label} already exists")


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
    retain_parent: bool = False,
) -> tuple[pathlib.Path, int, int | None]:
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
        failure: BaseException = exc
        if isinstance(exc, OSError):
            failure = PublicationReceiptIOError(f"cannot inspect {label}")
            failure.__cause__ = exc
        primary_error = failure
        if root_fd >= 0:
            try:
                os.close(root_fd)
            except OSError as close_error:
                failure.add_note(f"cannot close failed {label}")
        if failure is exc:
            raise
        raise failure
    finally:
        if primary_error is not None or not retain_parent:
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
                                f"cannot also close opened {label}"
                            )
                    raise PublicationReceiptIOError(detail) from exc
    return root, root_fd, parent_fd if retain_parent else None


def _require_released_safe_root_parent(
    parent_descriptor: int | None,
    *,
    opened_descriptors: tuple[int, ...],
    label: str,
) -> None:
    """Fail closed and close every fd if a non-retaining open kept its parent."""

    if parent_descriptor is None:
        return
    cleanup_errors: list[OSError] = []
    for descriptor in (*opened_descriptors, parent_descriptor):
        try:
            os.close(descriptor)
        except OSError as exc:
            cleanup_errors.append(exc)
    error = PublicationReceiptIOError(
        f"{label} unexpectedly retained its safe-root parent descriptor"
    )
    if cleanup_errors:
        raise error from cleanup_errors[0]
    raise error


def ensure_private_safe_root(
    root: pathlib.Path,
    *,
    label: str,
) -> pathlib.Path:
    """Create one fixed private root if absent, then return it normalized."""

    normalized, descriptor, parent_descriptor = _open_or_create_private_safe_root(
        root,
        label=label,
        create=True,
    )
    _require_released_safe_root_parent(
        parent_descriptor,
        opened_descriptors=(descriptor,),
        label=label,
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
    try:
        after = os.fstat(descriptor)
    except OSError as exc:
        try:
            os.close(descriptor)
        except OSError as close_error:
            exc.add_note(f"cannot close failed {label}")
        raise PublicationReceiptIOError(f"cannot inspect opened {label}") from exc
    if (
        after.st_dev != before.st_dev
        or after.st_ino != before.st_ino
        or not stat.S_ISDIR(after.st_mode)
        or after.st_uid != _effective_uid()
        or stat.S_IMODE(after.st_mode) != required_mode
    ):
        try:
            os.close(descriptor)
        except OSError as exc:
            raise PublicationReceiptIOError(
                f"cannot close changed {label}"
            ) from exc
        _fail(f"{label} identity changed while opening")
    return descriptor


def open_private_directory(path: pathlib.Path, *, label: str) -> int:
    """Open one caller-prevalidated private directory and pin its identity."""

    return _open_directory(
        path,
        label=label,
        required_mode=PRIVATE_DIRECTORY_MODE,
    )


def verify_private_directory_handle_identity(
    handle: PrivateDirectoryHandle,
    *,
    label: str,
) -> None:
    """Revalidate the named/open identity of one still-pinned directory."""

    try:
        opened = os.fstat(handle.descriptor)
        named = os.stat(
            handle.name,
            dir_fd=handle.parent_descriptor,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise PublicationReceiptIOError(
            f"cannot resample {label} identity"
        ) from exc
    _directory_metadata(
        opened,
        required_mode=handle.mode,
        label=label,
    )
    _require(
        opened.st_dev == handle.device
        and opened.st_ino == handle.inode
        and named.st_dev == handle.device
        and named.st_ino == handle.inode,
        f"{label} identity changed while pinned",
    )


def verify_private_directory_handle_parent_identity(
    handle: PrivateDirectoryHandle,
    *,
    label: str,
) -> None:
    """Revalidate the owned private parent of one still-pinned directory."""

    _require(
        handle.parent_descriptor >= 0,
        f"{label} parent descriptor is unavailable",
    )
    try:
        opened = os.fstat(handle.parent_descriptor)
        named = handle.path.parent.lstat()
    except OSError as exc:
        raise PublicationReceiptIOError(
            f"cannot resample {label} parent identity"
        ) from exc
    _directory_metadata(
        opened,
        required_mode=PRIVATE_DIRECTORY_MODE,
        label=f"{label} parent",
    )
    _directory_metadata(
        named,
        required_mode=PRIVATE_DIRECTORY_MODE,
        label=f"{label} parent",
    )
    _require(
        opened.st_dev == named.st_dev and opened.st_ino == named.st_ino,
        f"{label} parent identity changed while pinned",
    )


def _verify_private_directory_handle_ancestor_identity(
    handle: PrivateDirectoryHandle,
    *,
    label: str,
) -> None:
    descriptor = handle.ancestor_descriptor
    path = handle.ancestor_path
    expected_device = handle.ancestor_device
    expected_inode = handle.ancestor_inode
    if descriptor is None:
        return
    _require(
        path is not None
        and expected_device is not None
        and expected_inode is not None,
        f"{label} safe-root parent state is incomplete",
    )
    try:
        opened = os.fstat(descriptor)
        named = path.lstat()
    except OSError as exc:
        raise PublicationReceiptIOError(
            f"cannot resample {label} safe-root parent identity"
        ) from exc
    _require(
        stat.S_ISDIR(opened.st_mode)
        and stat.S_ISDIR(named.st_mode)
        and opened.st_uid == _effective_uid()
        and named.st_uid == _effective_uid()
        and stat.S_IMODE(opened.st_mode) & 0o002 == 0
        and stat.S_IMODE(named.st_mode) & 0o002 == 0
        and opened.st_dev == expected_device
        and opened.st_ino == expected_inode
        and named.st_dev == expected_device
        and named.st_ino == expected_inode,
        f"{label} safe-root parent identity changed while pinned",
    )


def _committed_resource_error(
    handle: PrivateDirectoryHandle,
    *,
    label: str,
    detail: str,
    cause: OSError,
) -> PublicationReceiptCommittedError:
    leaf = handle.committed_leaf
    digest = handle.committed_sha256
    _require(
        leaf is not None and digest is not None,
        f"{label} committed publication state is incomplete",
    )
    error = PublicationReceiptCommittedError(
        f"{label} committed leaf={leaf} sha256={digest}; {detail}",
        leaf=leaf,
        digest=digest,
    )
    error.__cause__ = cause
    return error


def _committed_publication_error(
    *,
    label: str,
    leaf: str,
    digest: str,
    detail: str,
    cause: BaseException,
    visibility: PublicationVisibility = "committed",
) -> PublicationReceiptCommittedError:
    state = "committed" if visibility == "committed" else "visibility indeterminate"
    error = PublicationReceiptCommittedError(
        f"{label} {state} leaf={leaf} sha256={digest}; {detail}",
        leaf=leaf,
        digest=digest,
        visibility=visibility,
    )
    error.__cause__ = cause
    return error


def sync_private_directory_parent(
    handle: PrivateDirectoryHandle,
    *,
    label: str,
) -> None:
    """Durably sync and revalidate one held private directory entry."""

    verify_private_directory_handle_identity(handle, label=label)
    verify_private_directory_handle_parent_identity(handle, label=label)
    try:
        os.fsync(handle.parent_descriptor)
    except OSError as exc:
        raise PublicationReceiptIOError(
            f"cannot durably sync {label} parent"
        ) from exc
    verify_private_directory_handle_parent_identity(handle, label=label)
    verify_private_directory_handle_identity(handle, label=label)


@contextlib.contextmanager
def open_private_directory_at(
    *,
    parent: PrivateDirectoryHandle,
    direct_child_name: str,
    label: str,
    required_mode: int = PRIVATE_DIRECTORY_MODE,
) -> Iterator[PrivateDirectoryHandle]:
    """Open and retain one fixed private direct child below a pinned parent."""

    child_name = _safe_leaf(
        direct_child_name,
        label=f"{label} directory leaf",
    )
    child_path = _normalized_descendant(
        parent.path / child_name,
        safe_root=parent.path,
        label=label,
    )
    _require(
        child_path.parent == parent.path and child_path.name == child_name,
        f"{label} is not one direct child",
    )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(child_name, flags, dir_fd=parent.descriptor)
        opened = os.fstat(descriptor)
        named = os.stat(
            child_name,
            dir_fd=parent.descriptor,
            follow_symlinks=False,
        )
        _directory_metadata(opened, required_mode=required_mode, label=label)
        _require(
            named.st_dev == opened.st_dev and named.st_ino == opened.st_ino,
            f"{label} identity changed while opening",
        )
    except BaseException as exc:
        failure: BaseException = exc
        if isinstance(exc, OSError):
            failure = PublicationReceiptIOError(f"cannot open {label}")
            failure.__cause__ = exc
        if "descriptor" in locals():
            try:
                os.close(descriptor)
            except OSError as close_error:
                failure.add_note(f"cannot close failed {label}")
        if failure is exc:
            raise
        raise failure
    handle = PrivateDirectoryHandle(
        path=child_path,
        descriptor=descriptor,
        parent_descriptor=parent.descriptor,
        name=child_name,
        device=opened.st_dev,
        inode=opened.st_ino,
        mode=required_mode,
    )
    primary_error: BaseException | None = None
    try:
        yield handle
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        if handle.committed_leaf is None:
            try:
                verify_private_directory_handle_identity(handle, label=label)
            except BaseException as exc:
                if primary_error is not None:
                    primary_error.add_note(
                        f"cannot revalidate pinned {label}: {exc}"
                    )
                else:
                    primary_error = exc
        try:
            os.close(handle.descriptor)
        except OSError as exc:
            if primary_error is not None:
                primary_error.add_note(f"cannot close pinned {label}")
            elif handle.committed_leaf is not None:
                primary_error = _committed_resource_error(
                    handle,
                    label=label,
                    detail="cannot close committed directory descriptor",
                    cause=exc,
                )
            else:
                primary_error = PublicationReceiptIOError(
                    f"cannot close pinned {label}"
                )
                primary_error.__cause__ = exc
        if primary_error is not None and sys.exception() is None:
            raise primary_error


@contextlib.contextmanager
def _private_direct_child_handle(
    *,
    safe_root: pathlib.Path,
    direct_child_name: str,
    label: str,
    create: bool,
    sync_safe_root_parent: bool,
) -> Iterator[PrivateDirectoryHandle]:
    child_name = _safe_leaf(
        direct_child_name,
        label=f"{label} directory leaf",
    )
    root, root_fd, safe_root_parent_fd = _open_or_create_private_safe_root(
        safe_root,
        label=f"{label} safe root",
        create=False,
        sync_parent=create or sync_safe_root_parent,
        retain_parent=sync_safe_root_parent,
    )
    try:
        root_metadata = os.fstat(root_fd)
    except OSError as exc:
        try:
            os.close(root_fd)
        except OSError as close_error:
            exc.add_note(f"cannot close failed {label} safe root")
        if safe_root_parent_fd is not None:
            try:
                os.close(safe_root_parent_fd)
            except OSError as close_error:
                exc.add_note(f"cannot close failed {label} safe-root parent")
        raise PublicationReceiptIOError(
            f"cannot inspect {label} safe root"
        ) from exc
    root_handle = PrivateDirectoryHandle(
        path=root,
        descriptor=root_fd,
        parent_descriptor=-1,
        name=root.name,
        device=root_metadata.st_dev,
        inode=root_metadata.st_ino,
        mode=PRIVATE_DIRECTORY_MODE,
    )
    created = False
    primary_error: BaseException | None = None
    try:
        if create:
            try:
                os.mkdir(child_name, PRIVATE_DIRECTORY_MODE, dir_fd=root_fd)
                created = True
            except FileExistsError as exc:
                raise PublicationReceiptIOError(
                    f"{label} already exists"
                ) from exc
            except OSError as exc:
                raise PublicationReceiptIOError(f"cannot create {label}") from exc
            try:
                os.fsync(root_fd)
            except OSError as exc:
                raise PublicationReceiptIOError(
                    f"cannot durably create {label}"
                ) from exc
        with open_private_directory_at(
            parent=root_handle,
            direct_child_name=child_name,
            label=label,
        ) as child:
            if safe_root_parent_fd is not None:
                try:
                    ancestor_metadata = os.fstat(safe_root_parent_fd)
                except OSError as exc:
                    raise PublicationReceiptIOError(
                        f"cannot inspect {label} safe-root parent"
                    ) from exc
                child.ancestor_descriptor = safe_root_parent_fd
                child.ancestor_path = root.parent
                child.ancestor_device = ancestor_metadata.st_dev
                child.ancestor_inode = ancestor_metadata.st_ino
            yield child
    except BaseException as exc:
        primary_error = exc
        if created and "child" not in locals():
            try:
                os.rmdir(child_name, dir_fd=root_fd)
                os.fsync(root_fd)
            except OSError as cleanup_error:
                exc.add_note(f"cannot clean failed {label}: {cleanup_error}")
        raise
    finally:
        child_handle = locals().get("child")
        committed = (
            isinstance(child_handle, PrivateDirectoryHandle)
            and child_handle.committed_leaf is not None
        )
        if not committed:
            try:
                current_root = root.lstat()
                opened_root = os.fstat(root_fd)
                _directory_metadata(
                    current_root,
                    required_mode=PRIVATE_DIRECTORY_MODE,
                    label=f"{label} safe root",
                )
                _directory_metadata(
                    opened_root,
                    required_mode=PRIVATE_DIRECTORY_MODE,
                    label=f"{label} safe root",
                )
                _require(
                    current_root.st_dev == root_handle.device
                    and current_root.st_ino == root_handle.inode
                    and opened_root.st_dev == root_handle.device
                    and opened_root.st_ino == root_handle.inode,
                    f"{label} safe-root identity changed while pinned",
                )
                if isinstance(child_handle, PrivateDirectoryHandle):
                    _verify_private_directory_handle_ancestor_identity(
                        child_handle,
                        label=label,
                    )
            except OSError as exc:
                failure = PublicationReceiptIOError(
                    f"cannot revalidate {label} safe root"
                )
                failure.__cause__ = exc
                if primary_error is not None:
                    primary_error.add_note(str(failure))
                else:
                    primary_error = failure
            except BaseException as exc:
                if primary_error is not None:
                    primary_error.add_note(
                        f"cannot revalidate {label} safe root: {exc}"
                    )
                else:
                    primary_error = exc
        try:
            os.close(root_fd)
        except OSError as exc:
            if primary_error is not None:
                primary_error.add_note(f"cannot close {label} safe root")
            elif committed:
                if isinstance(child_handle, PrivateDirectoryHandle):
                    primary_error = _committed_resource_error(
                        child_handle,
                        label=label,
                        detail="cannot close committed safe-root descriptor",
                        cause=exc,
                    )
                else:
                    primary_error = PublicationReceiptIOError(
                        f"{label} committed handle state is invalid"
                    )
                    primary_error.__cause__ = exc
            else:
                primary_error = PublicationReceiptIOError(
                    f"cannot close {label} safe root"
                )
                primary_error.__cause__ = exc
        if safe_root_parent_fd is not None:
            try:
                os.close(safe_root_parent_fd)
            except OSError as exc:
                if primary_error is not None:
                    primary_error.add_note(
                        f"cannot close {label} safe-root parent"
                    )
                elif committed:
                    if isinstance(child_handle, PrivateDirectoryHandle):
                        primary_error = _committed_resource_error(
                            child_handle,
                            label=label,
                            detail=(
                                "cannot close committed safe-root parent descriptor"
                            ),
                            cause=exc,
                        )
                    else:
                        primary_error = PublicationReceiptIOError(
                            f"{label} committed handle state is invalid"
                        )
                        primary_error.__cause__ = exc
                else:
                    primary_error = PublicationReceiptIOError(
                        f"cannot close {label} safe-root parent"
                    )
                    primary_error.__cause__ = exc
        if primary_error is not None and sys.exception() is None:
            raise primary_error


def open_private_direct_child_handle(
    *,
    safe_root: pathlib.Path,
    direct_child_name: str,
    label: str,
    sync_safe_root_parent: bool = False,
) -> contextlib.AbstractContextManager[PrivateDirectoryHandle]:
    """Retain one existing fixed-root private direct child."""

    return _private_direct_child_handle(
        safe_root=safe_root,
        direct_child_name=direct_child_name,
        label=label,
        create=False,
        sync_safe_root_parent=sync_safe_root_parent,
    )


def create_private_direct_child_handle(
    *,
    safe_root: pathlib.Path,
    direct_child_name: str,
    label: str,
) -> contextlib.AbstractContextManager[PrivateDirectoryHandle]:
    """Atomically create and retain one fixed-root private direct child."""

    return _private_direct_child_handle(
        safe_root=safe_root,
        direct_child_name=direct_child_name,
        label=label,
        create=True,
        sync_safe_root_parent=True,
    )


def verify_private_direct_child_and_sync_parent(
    *,
    safe_root: pathlib.Path,
    direct_child_name: str,
    label: str,
) -> pathlib.Path:
    """Pin one private direct child and durably commit its directory entry."""

    with open_private_direct_child_handle(
        safe_root=safe_root,
        direct_child_name=direct_child_name,
        label=label,
    ) as handle:
        try:
            os.fsync(handle.parent_descriptor)
        except OSError as exc:
            raise PublicationReceiptIOError(
                f"cannot durably commit {label} directory entry"
            ) from exc
        return handle.path


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
    expected_leaf = _safe_leaf(expected_leaf, label=f"{label} expected leaf")
    root = normalize_safe_root(
        safe_root,
        label=f"{label} safe root",
        required_mode=root_mode,
    )
    normalized = _normalized_descendant(
        path,
        safe_root=root,
        label=label,
    )
    _require(normalized.name == expected_leaf, f"{label} leaf differs")
    parent = normalized.parent
    actual_root = parent if parent_depth == 0 else parent.parent
    _require(actual_root == root, f"{label} is outside its fixed root/depth")
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
        failure: BaseException = exc
        if isinstance(exc, OSError):
            failure = PublicationReceiptIOError(
                f"cannot open {label} fixed parent"
            )
            failure.__cause__ = exc
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
            failure.add_note(f"cannot close failed {label} {resource}")
        if failure is exc:
            raise
        raise failure
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
    try:
        opened_root = os.fstat(root_fd)
        opened_parent = os.fstat(parent_fd)
    except OSError as exc:
        raise PublicationReceiptIOError(
            f"cannot resample {label} root/parent descriptors"
        ) from exc
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


def _verify_named_private_file_identity_at(
    directory_fd: int,
    leaf: str,
    *,
    device: int,
    inode: int,
    label: str,
) -> None:
    try:
        metadata = os.stat(
            leaf,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise EvidenceIOError(f"cannot resample named {label}") from exc
    _regular_metadata_validator(
        required_mode=PRIVATE_FILE_MODE,
        label=label,
    )(metadata)
    if metadata.st_dev != device or metadata.st_ino != inode:
        raise EvidenceIOError(f"named {label} identity changed")


def _matches_exact_private_file_at(
    directory_fd: int,
    leaf: str,
    *,
    device: int,
    inode: int,
    size: int,
    digest: str,
    label: str,
) -> bool:
    """Return whether one named leaf is the exact stable prepared file."""

    def validate(metadata: os.stat_result) -> None:
        _regular_metadata_validator(
            required_mode=PRIVATE_FILE_MODE,
            label=label,
        )(metadata)
        if metadata.st_dev != device or metadata.st_ino != inode:
            raise EvidenceIOError(f"{label} identity changed")

    try:
        snapshot = consume_regular_snapshot_at(
            directory_fd,
            leaf,
            display_path=pathlib.Path(leaf),
            maximum=max(1, size),
            label=label,
            consume=lambda _chunk: None,
            validate_metadata=validate,
        )
        _verify_named_private_file_identity_at(
            directory_fd,
            leaf,
            device=device,
            inode=inode,
            label=label,
        )
    except EvidenceIOError:
        return False
    return snapshot.size == size and snapshot.sha256 == digest


_VISIBILITY_EXACT = "exact"
_VISIBILITY_PRECOMMIT = "precommit"
_VISIBILITY_INDETERMINATE = "indeterminate"


def _classify_interrupted_visibility_at(
    directory_fd: int,
    *,
    destination_leaf: str,
    staging_leaf: str,
    device: int,
    inode: int,
    size: int,
    digest: str,
    label: str,
) -> _InterruptedVisibility:
    """Classify an interrupted rename without treating uncertainty as absence."""

    if _matches_exact_private_file_at(
        directory_fd,
        destination_leaf,
        device=device,
        inode=inode,
        size=size,
        digest=digest,
        label=f"{label} visible destination",
    ):
        return _VISIBILITY_EXACT
    if _matches_exact_private_file_at(
        directory_fd,
        staging_leaf,
        device=device,
        inode=inode,
        size=size,
        digest=digest,
        label=f"{label} retained staging file",
    ):
        return _VISIBILITY_PRECOMMIT
    return _VISIBILITY_INDETERMINATE


def _classify_interrupted_visibility_conservatively(
    directory_fd: int,
    *,
    destination_leaf: str,
    staging_leaf: str,
    device: int,
    inode: int,
    size: int,
    digest: str,
    label: str,
    interruption: BaseException,
) -> _InterruptedVisibility:
    try:
        return _classify_interrupted_visibility_at(
            directory_fd,
            destination_leaf=destination_leaf,
            staging_leaf=staging_leaf,
            device=device,
            inode=inode,
            size=size,
            digest=digest,
            label=label,
        )
    except BaseException as classification_error:
        interruption.add_note(
            "visibility classification also failed: "
            f"{type(classification_error).__name__}"
        )
        return _VISIBILITY_INDETERMINATE


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
    expected_parent_entries: frozenset[str] | None = None,
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
        if expected_parent_entries is not None:
            expected_parent_entries = _validated_directory_inventory(
                expected_parent_entries,
                label=f"{label} parent",
            )
            _require(
                expected_leaf in expected_parent_entries,
                f"{label} expected leaf is absent from its parent inventory",
            )
            verify_exact_directory_inventory_at(
                parent_fd,
                expected_parent_entries,
                label=f"{label} parent before snapshot",
            )
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
        if expected_parent_entries is not None:
            verify_exact_directory_inventory_at(
                parent_fd,
                expected_parent_entries,
                label=f"{label} parent after snapshot",
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
    expected_parent_entries: frozenset[str] | None = None,
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
        expected_parent_entries=expected_parent_entries,
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


@dataclass(slots=True)
class PreparedPrivateJsonPublication:
    """One durable staging file awaiting its single no-replace visibility point."""

    directory: PrivateDirectoryHandle
    expected_leaf: str
    staging_leaf: str
    digest: str
    size: int
    device: int
    inode: int
    label: str

    @property
    def published(self) -> bool:
        return self.directory.committed_publication == (
            self.expected_leaf,
            self.digest,
        )

    def _mark_published(self) -> None:
        self.directory.committed_publication = (
            self.expected_leaf,
            self.digest,
        )

    def _validate_file_identity(self, metadata: os.stat_result) -> None:
        _regular_metadata_validator(
            required_mode=PRIVATE_FILE_MODE,
            label=f"{self.label} prepared file",
        )(metadata)
        if metadata.st_dev != self.device or metadata.st_ino != self.inode:
            raise EvidenceIOError(
                f"{self.label} prepared file identity changed"
            )

    def commit_after_revalidation(self) -> str:
        """Revalidate held ancestry, then atomically make the receipt visible."""

        _require(not self.published, f"{self.label} is already committed")
        _require(
            self.directory.committed_leaf is None,
            f"{self.label} directory already contains a committed publication",
        )
        try:
            staging = consume_regular_snapshot_at(
                self.directory.descriptor,
                self.staging_leaf,
                display_path=pathlib.Path(self.staging_leaf),
                maximum=max(1, self.size),
                label=f"{self.label} staging file",
                consume=lambda _chunk: None,
                validate_metadata=self._validate_file_identity,
            )
        except EvidenceIOError as exc:
            raise PublicationReceiptIOError(
                f"cannot safely resample {self.label} staging file"
            ) from exc
        _require(
            staging.size == self.size and staging.sha256 == self.digest,
            f"{self.label} staging bytes changed before commit",
        )
        verify_private_directory_handle_identity(
            self.directory,
            label=f"{self.label} parent",
        )
        verify_private_directory_handle_parent_identity(
            self.directory,
            label=f"{self.label} parent",
        )
        _verify_private_directory_handle_ancestor_identity(
            self.directory,
            label=f"{self.label} parent",
        )
        try:
            os.fsync(self.directory.descriptor)
            os.fsync(self.directory.parent_descriptor)
            if self.directory.ancestor_descriptor is not None:
                os.fsync(self.directory.ancestor_descriptor)
        except OSError as exc:
            raise PublicationReceiptIOError(
                f"cannot durably prepare {self.label} ancestry"
            ) from exc
        verify_private_directory_handle_parent_identity(
            self.directory,
            label=f"{self.label} parent",
        )
        verify_private_directory_handle_identity(
            self.directory,
            label=f"{self.label} parent",
        )
        _verify_private_directory_handle_ancestor_identity(
            self.directory,
            label=f"{self.label} parent",
        )
        try:
            _rename_noreplace(
                self.directory.descriptor,
                self.staging_leaf,
                self.expected_leaf,
            )
        except PublicationReceiptIOError:
            raise
        except BaseException as exc:
            visibility = _classify_interrupted_visibility_conservatively(
                self.directory.descriptor,
                destination_leaf=self.expected_leaf,
                staging_leaf=self.staging_leaf,
                device=self.device,
                inode=self.inode,
                size=self.size,
                digest=self.digest,
                label=f"{self.label} interrupted visibility point",
                interruption=exc,
            )
            if visibility == _VISIBILITY_PRECOMMIT:
                raise
            self._mark_published()
            if visibility == _VISIBILITY_EXACT:
                raise _committed_publication_error(
                    label=self.label,
                    leaf=self.expected_leaf,
                    digest=self.digest,
                    detail="visibility point completed before interruption",
                    cause=exc,
                )
            else:
                raise _committed_publication_error(
                    label=self.label,
                    leaf=self.expected_leaf,
                    digest=self.digest,
                    detail="visibility could not be safely classified",
                    cause=exc,
                    visibility="indeterminate",
                )
        self._mark_published()
        try:
            final_snapshot = consume_regular_snapshot_at(
                self.directory.descriptor,
                self.expected_leaf,
                display_path=pathlib.Path(self.expected_leaf),
                maximum=max(1, self.size),
                label=f"{self.label} committed file",
                consume=lambda _chunk: None,
                validate_metadata=self._validate_file_identity,
            )
            _require(
                final_snapshot.size == self.size
                and final_snapshot.sha256 == self.digest,
                f"{self.label} committed bytes differ from staging",
            )
            _verify_named_private_file_identity_at(
                self.directory.descriptor,
                self.expected_leaf,
                device=self.device,
                inode=self.inode,
                label=f"{self.label} committed file",
            )
            os.fsync(self.directory.descriptor)
            _verify_named_private_file_identity_at(
                self.directory.descriptor,
                self.expected_leaf,
                device=self.device,
                inode=self.inode,
                label=f"{self.label} committed file",
            )
            verify_private_directory_handle_identity(
                self.directory,
                label=f"{self.label} parent",
            )
            verify_private_directory_handle_parent_identity(
                self.directory,
                label=f"{self.label} parent",
            )
            _verify_private_directory_handle_ancestor_identity(
                self.directory,
                label=f"{self.label} parent",
            )
        except (EvidenceIOError, OSError, PublicationReceiptIOError) as exc:
            raise PublicationReceiptCommittedError(
                f"{self.label} committed leaf={self.expected_leaf} "
                f"sha256={self.digest}; final durability verification failed",
                leaf=self.expected_leaf,
                digest=self.digest,
            ) from exc
        return self.digest


@contextlib.contextmanager
def prepare_private_json_noreplace_at(
    directory: PrivateDirectoryHandle,
    expected_leaf: str,
    value: object,
    *,
    label: str,
    maximum: int = DEFAULT_RECEIPT_MAX_BYTES,
) -> Iterator[PreparedPrivateJsonPublication]:
    """Durably stage JSON below a held directory for a later validated commit."""

    expected_leaf = _safe_leaf(expected_leaf, label=f"{label} leaf")
    payload = canonical_json_bytes(value)
    _require(len(payload) <= maximum, f"{label} exceeds the bounded size")
    verify_private_directory_handle_identity(
        directory,
        label=f"{label} parent",
    )
    staging_leaf = f".{expected_leaf}.pending-{os.getpid()}"
    _safe_leaf(staging_leaf, label=f"{label} staging leaf")
    descriptor = -1
    staging_created = False
    prepared: PreparedPrivateJsonPublication | None = None
    primary_error: BaseException | None = None
    try:
        require_absent_leaf_at(directory.descriptor, expected_leaf, label=label)
        require_absent_leaf_at(
            directory.descriptor,
            staging_leaf,
            label=f"{label} staging file",
        )
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            descriptor = os.open(
                staging_leaf,
                flags,
                PRIVATE_FILE_MODE,
                dir_fd=directory.descriptor,
            )
            staging_created = True
        except OSError as exc:
            raise PublicationReceiptIOError(
                f"cannot create {label} staging file"
            ) from exc
        _write_all(descriptor, payload, label=label)
        try:
            os.fchmod(descriptor, PRIVATE_FILE_MODE)
            metadata = os.fstat(descriptor)
            _regular_metadata_validator(
                required_mode=PRIVATE_FILE_MODE,
                label=label,
            )(metadata)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
        except EvidenceIOError as exc:
            raise PublicationReceiptIOError(
                f"cannot validate {label} staging file"
            ) from exc
        except OSError as exc:
            raise PublicationReceiptIOError(
                f"cannot durably stage {label}"
            ) from exc
        prepared = PreparedPrivateJsonPublication(
            directory=directory,
            expected_leaf=expected_leaf,
            staging_leaf=staging_leaf,
            digest=hashlib.sha256(payload).hexdigest(),
            size=len(payload),
            device=metadata.st_dev,
            inode=metadata.st_ino,
            label=label,
        )
        yield prepared
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
        if staging_created and (prepared is None or not prepared.published):
            try:
                os.unlink(staging_leaf, dir_fd=directory.descriptor)
                os.fsync(directory.descriptor)
            except OSError as exc:
                cleanup_errors.append(exc)
        if cleanup_errors:
            detail = f"{label} staging cleanup failed"
            if primary_error is not None:
                primary_error.add_note(detail)
            else:
                raise PublicationReceiptIOError(detail) from cleanup_errors[0]


def write_private_bytes_noreplace_at(
    directory_fd: int,
    expected_leaf: str,
    payload: bytes,
    *,
    label: str,
    maximum: int = DEFAULT_RECEIPT_MAX_BYTES,
) -> str:
    """Publish bounded bytes below an already-owned private directory fd."""

    try:
        directory_metadata = os.fstat(directory_fd)
    except OSError as exc:
        raise PublicationReceiptIOError(
            f"cannot inspect {label} parent"
        ) from exc
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
        require_absent_leaf_at(directory_fd, expected_leaf, label=label)
        require_absent_leaf_at(
            directory_fd,
            staging_leaf,
            label=f"{label} staging file",
        )
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
        expected_digest = hashlib.sha256(payload).hexdigest()
        try:
            _rename_noreplace(directory_fd, staging_leaf, expected_leaf)
        except PublicationReceiptIOError:
            raise
        except BaseException as exc:
            visibility = _classify_interrupted_visibility_conservatively(
                directory_fd,
                destination_leaf=expected_leaf,
                staging_leaf=staging_leaf,
                device=metadata.st_dev,
                inode=metadata.st_ino,
                size=len(payload),
                digest=expected_digest,
                label=f"{label} interrupted visibility point",
                interruption=exc,
            )
            if visibility == _VISIBILITY_PRECOMMIT:
                raise
            published = True
            if visibility == _VISIBILITY_EXACT:
                raise _committed_publication_error(
                    label=label,
                    leaf=expected_leaf,
                    digest=expected_digest,
                    detail="visibility point completed before interruption",
                    cause=exc,
                )
            raise _committed_publication_error(
                label=label,
                leaf=expected_leaf,
                digest=expected_digest,
                detail="visibility could not be safely classified",
                cause=exc,
                visibility="indeterminate",
            )
        published = True
        try:
            def validate_final_metadata(final_metadata: os.stat_result) -> None:
                _regular_metadata_validator(
                    required_mode=PRIVATE_FILE_MODE,
                    label=label,
                )(final_metadata)
                if (
                    final_metadata.st_dev != metadata.st_dev
                    or final_metadata.st_ino != metadata.st_ino
                ):
                    raise EvidenceIOError(
                        f"{label} published file identity changed"
                    )

            final_snapshot = consume_regular_snapshot_at(
                directory_fd,
                expected_leaf,
                display_path=pathlib.Path(expected_leaf),
                maximum=max(1, len(payload)),
                label=f"{label} published file",
                consume=lambda _chunk: None,
                validate_metadata=validate_final_metadata,
            )
            _require(
                final_snapshot.size == len(payload)
                and final_snapshot.sha256 == expected_digest,
                f"{label} published bytes differ from staging",
            )
            _verify_named_private_file_identity_at(
                directory_fd,
                expected_leaf,
                device=metadata.st_dev,
                inode=metadata.st_ino,
                label=f"{label} published file",
            )
            os.fsync(directory_fd)
            _verify_named_private_file_identity_at(
                directory_fd,
                expected_leaf,
                device=metadata.st_dev,
                inode=metadata.st_ino,
                label=f"{label} published file",
            )
        except (EvidenceIOError, OSError, PublicationReceiptIOError) as exc:
            digest = hashlib.sha256(payload).hexdigest()
            raise PublicationReceiptCommittedError(
                f"{label} was atomically published but its parent "
                "durability verification failed",
                leaf=expected_leaf,
                digest=digest,
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
    root, root_fd, parent_descriptor = _open_or_create_private_safe_root(
        safe_root,
        label=f"{label} safe root",
        create=True,
    )
    _require_released_safe_root_parent(
        parent_descriptor,
        opened_descriptors=(root_fd,),
        label=f"{label} safe root",
    )
    descriptor = -1
    digest = ""
    published = False
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
        try:
            transaction_metadata = os.fstat(descriptor)
            named_transaction = os.stat(
                transaction_name,
                dir_fd=root_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise PublicationReceiptIOError(
                f"cannot inspect {label} transaction directory"
            ) from exc
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
        published = True
        try:
            current_root = safe_root.lstat()
            current_transaction = transaction.lstat()
            opened_root = os.fstat(root_fd)
            opened_transaction = os.fstat(descriptor)
            for metadata, metadata_label in (
                (current_root, f"{label} safe root"),
                (opened_root, f"{label} safe root"),
                (current_transaction, f"{label} transaction directory"),
                (opened_transaction, f"{label} transaction directory"),
            ):
                _directory_metadata(
                    metadata,
                    required_mode=PRIVATE_DIRECTORY_MODE,
                    label=metadata_label,
                )
            _require(
                current_root.st_dev == opened_root.st_dev
                and current_root.st_ino == opened_root.st_ino
                and current_transaction.st_dev == opened_transaction.st_dev
                and current_transaction.st_ino == opened_transaction.st_ino,
                f"{label} output root identity changed during publication",
            )
        except (OSError, PublicationReceiptIOError) as exc:
            raise _committed_publication_error(
                label=label,
                leaf=expected_leaf,
                digest=digest,
                detail="output identity verification failed",
                cause=exc,
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
            elif published:
                raise _committed_publication_error(
                    label=label,
                    leaf=expected_leaf,
                    digest=digest,
                    detail=detail,
                    cause=cleanup_errors[0],
                )
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

    root, descriptor, parent_descriptor = _open_or_create_private_safe_root(
        safe_root,
        label=f"{label} safe root",
        create=False,
    )
    _require_released_safe_root_parent(
        parent_descriptor,
        opened_descriptors=(descriptor,),
        label=f"{label} safe root",
    )
    digest = ""
    published = False
    primary_error: BaseException | None = None
    try:
        digest = write_private_json_noreplace_at(
            descriptor,
            expected_leaf,
            value,
            label=label,
            maximum=maximum,
        )
        published = True
        try:
            current_root = safe_root.lstat()
            opened_root = os.fstat(descriptor)
            _directory_metadata(
                current_root,
                required_mode=PRIVATE_DIRECTORY_MODE,
                label=f"{label} safe root",
            )
            _directory_metadata(
                opened_root,
                required_mode=PRIVATE_DIRECTORY_MODE,
                label=f"{label} safe root",
            )
            _require(
                current_root.st_dev == opened_root.st_dev
                and current_root.st_ino == opened_root.st_ino,
                f"{label} safe root identity changed during publication",
            )
        except (OSError, PublicationReceiptIOError) as exc:
            raise _committed_publication_error(
                label=label,
                leaf=expected_leaf,
                digest=digest,
                detail="safe-root identity verification failed",
                cause=exc,
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
            elif published:
                raise _committed_publication_error(
                    label=label,
                    leaf=expected_leaf,
                    digest=digest,
                    detail=detail,
                    cause=cleanup_errors[0],
                )
            else:
                raise PublicationReceiptIOError(detail) from cleanup_errors[0]
    return root / expected_leaf, digest
