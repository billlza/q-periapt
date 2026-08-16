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
import re
import stat
import sys
from dataclasses import dataclass, field
from collections.abc import Callable, Iterator
from typing import Any, Literal, Never

try:
    import fcntl
except ImportError:
    fcntl = None

from evidence_io import (
    EvidenceIOError,
    FileSnapshot,
    OwnedFileDescriptorLease,
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


class PublicationLockHeldError(PublicationReceiptIOError):
    """A persistent publication lock is already held by another process."""


@dataclass(frozen=True, slots=True)
class BoundaryFailureContext:
    type_name: str | None
    error_kind: str | None
    returncode: int | None
    signal_number: int | None
    cleanup_ambiguous: bool

    @classmethod
    def from_exception(
        cls, error: BaseException | None
    ) -> "BoundaryFailureContext":
        type_name = None if error is None else type(error).__name__
        error_kind: object = None
        returncode: object = None
        signal_number: object = None
        cleanup_ambiguous: object = False
        current = error
        visited: set[int] = set()
        for _ in range(8):
            if current is None or id(current) in visited:
                break
            visited.add(id(current))
            current_error_kind = getattr(current, "error_kind", None)
            if current_error_kind is None:
                current_error_kind = getattr(current, "kind", None)
            current_returncode = getattr(current, "returncode", None)
            current_signal = getattr(current, "signal_number", None)
            current_cleanup = getattr(current, "cleanup_ambiguous", False)
            if error_kind is None and isinstance(current_error_kind, str):
                error_kind = current_error_kind
            if returncode is None and type(current_returncode) is int:
                returncode = current_returncode
            if signal_number is None and type(current_signal) is int:
                signal_number = current_signal
            if type(current_cleanup) is bool and current_cleanup:
                cleanup_ambiguous = True
            next_error = current.__cause__
            if next_error is None:
                next_error = current.__context__
            current = next_error
        return cls(
            type_name=type_name,
            error_kind=error_kind if isinstance(error_kind, str) else None,
            returncode=returncode if type(returncode) is int else None,
            signal_number=(
                signal_number if type(signal_number) is int else None
            ),
            cleanup_ambiguous=(
                cleanup_ambiguous
                if type(cleanup_ambiguous) is bool
                else False
            ),
        )


class PublicationBoundaryIntegrityError(PublicationReceiptIOError):
    """A pinned publication resource changed or could not be closed safely."""

    def __init__(
        self,
        message: str,
        *,
        preceding_type: str | None = None,
        preceding_error: BaseException | None = None,
        cleanup_ambiguous: bool = False,
    ) -> None:
        super().__init__(message)
        context = BoundaryFailureContext.from_exception(preceding_error)
        if preceding_error is None and preceding_type is not None:
            context = BoundaryFailureContext(
                type_name=preceding_type,
                error_kind=None,
                returncode=None,
                signal_number=None,
                cleanup_ambiguous=False,
            )
        self.preceding_context = context
        self.preceding_type = context.type_name
        self.error_kind = context.error_kind
        self.returncode = context.returncode
        self.signal_number = context.signal_number
        self.cleanup_ambiguous = (
            context.cleanup_ambiguous or cleanup_ambiguous
        )


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
        path: pathlib.Path | None = None,
    ) -> None:
        if visibility not in {"committed", "indeterminate"}:
            raise ValueError("publication visibility state is invalid")
        if path is not None and not isinstance(path, pathlib.Path):
            raise ValueError("publication attempt path must be a pathlib.Path")
        super().__init__(message)
        self.leaf = leaf
        self.digest = digest
        self.visibility = visibility
        self.path = path


@dataclass(frozen=True, slots=True)
class _PrivateDirectoryPublicationState:
    """One monotonic publication fact retained by a pinned directory handle."""

    leaf: str
    digest: str
    visibility: PublicationVisibility

    def __post_init__(self) -> None:
        if (
            not isinstance(self.leaf, str)
            or not self.leaf
            or self.leaf in {".", ".."}
            or "/" in self.leaf
            or "\\" in self.leaf
            or "\x00" in self.leaf
        ):
            raise ValueError("committed publication leaf is invalid")
        if (
            not isinstance(self.digest, str)
            or len(self.digest) != 64
            or any(character not in "0123456789abcdef" for character in self.digest)
        ):
            raise ValueError("committed publication digest is invalid")
        if (
            not isinstance(self.visibility, str)
            or self.visibility not in {"committed", "indeterminate"}
        ):
            raise ValueError("committed publication visibility is invalid")


@dataclass(frozen=True, slots=True)
class StrictJsonSnapshot:
    """One strict JSON object and the exact stable bytes that produced it."""

    file: FileSnapshot
    value: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _OpenPrivateFileSnapshot:
    """Stable metadata and bytes read through one already-open staging fd."""

    metadata: os.stat_result
    size: int
    sha256: str


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
    _committed_publication: _PrivateDirectoryPublicationState | None = field(
        default=None,
        init=False,
        repr=False,
    )

    @property
    def committed_publication(self) -> _PrivateDirectoryPublicationState | None:
        return self._committed_publication

    def mark_publication(
        self,
        *,
        leaf: str,
        digest: str,
        visibility: PublicationVisibility,
    ) -> None:
        """Record one publication monotonically without upgrading uncertainty."""

        observed = _PrivateDirectoryPublicationState(
            leaf=leaf,
            digest=digest,
            visibility=visibility,
        )
        current = self._committed_publication
        if current is not None:
            if current.leaf != observed.leaf or current.digest != observed.digest:
                raise PublicationReceiptIOError(
                    "committed publication identity cannot change"
                )
            if current.visibility == "indeterminate":
                return
            if observed.visibility == "committed":
                return
        self._committed_publication = observed

    @property
    def committed_leaf(self) -> str | None:
        return (
            None
            if self._committed_publication is None
            else self._committed_publication.leaf
        )

    @property
    def committed_sha256(self) -> str | None:
        return (
            None
            if self._committed_publication is None
            else self._committed_publication.digest
        )

    @property
    def committed_visibility(self) -> PublicationVisibility | None:
        return (
            None
            if self._committed_publication is None
            else self._committed_publication.visibility
        )


@dataclass(frozen=True, slots=True)
class PrivateSafeRootCreatedIdentity:
    """Level-1 identity of a private root atomically created by this call."""

    device: int
    inode: int


@dataclass(frozen=True, slots=True)
class PrivateFileLockHandle:
    root: pathlib.Path
    root_descriptor: int
    lock_leaf: str
    lock_descriptor: int
    root_device: int
    root_inode: int
    lock_device: int
    lock_inode: int


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
) -> tuple[pathlib.Path, int, int | None, bool]:
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
    created = False
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
                created = True
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
    return root, root_fd, parent_fd if retain_parent else None, created


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

    normalized, _created = ensure_private_safe_root_with_creation(
        root,
        label=label,
    )
    return normalized


def ensure_private_safe_root_with_creation(
    root: pathlib.Path,
    *,
    label: str,
) -> tuple[pathlib.Path, PrivateSafeRootCreatedIdentity | None]:
    """Create/open a fixed private root and report its created-root identity."""

    normalized, descriptor, parent_descriptor, created = (
        _open_or_create_private_safe_root(
            root,
            label=label,
            create=True,
        )
    )
    _require_released_safe_root_parent(
        parent_descriptor,
        opened_descriptors=(descriptor,),
        label=label,
    )
    inspect_error: OSError | None = None
    close_error: OSError | None = None
    metadata: os.stat_result | None = None
    try:
        metadata = os.fstat(descriptor)
    except OSError as exc:
        inspect_error = exc
    try:
        os.close(descriptor)
    except OSError as exc:
        close_error = exc
    if inspect_error is not None or close_error is not None:
        boundary = PublicationBoundaryIntegrityError(
            f"cannot verify or close {label}",
            preceding_error=inspect_error,
            cleanup_ambiguous=close_error is not None,
        )
        if inspect_error is not None and close_error is not None:
            boundary.add_note("descriptor cleanup is indeterminate")
        raise boundary from (
            close_error if close_error is not None else inspect_error
        )
    if metadata is None:
        raise PublicationBoundaryIntegrityError(
            f"cannot verify {label} metadata"
        )
    identity = PrivateSafeRootCreatedIdentity(
        metadata.st_dev,
        metadata.st_ino,
    ) if created else None
    return normalized, identity


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


@contextlib.contextmanager
def exclusive_private_file_lock(
    safe_root: pathlib.Path,
    lock_leaf: str,
    *,
    label: str,
    allow_create: bool,
    created_root_identity: PrivateSafeRootCreatedIdentity | None = None,
) -> Iterator[PrivateFileLockHandle]:
    """Hold one persistent-inode, crash-released cross-worktree lock.

    The lock file is retained permanently. Replacing or removing it would split
    the lock authority between processes holding different inodes.
    """

    _require(
        os.name == "posix" and fcntl is not None,
        f"{label} requires POSIX flock",
    )
    lock_api = fcntl
    if lock_api is None:
        _fail(f"{label} requires POSIX flock")
    lock_leaf = _safe_leaf(lock_leaf, label=f"{label} leaf")
    root = normalize_safe_root(safe_root, label=f"{label} root")
    root_descriptor = open_private_directory(root, label=f"{label} root")
    lock_descriptor = -1
    acquired = False
    primary_error: BaseException | None = None
    try:
        _require(type(allow_create) is bool, f"{label} creation policy is malformed")
        if allow_create:
            if not isinstance(
                created_root_identity,
                PrivateSafeRootCreatedIdentity,
            ):
                _fail(f"{label} created-root identity is malformed")
            try:
                root_metadata = os.fstat(root_descriptor)
            except OSError as exc:
                raise PublicationBoundaryIntegrityError(
                    f"cannot inspect {label} created-root identity"
                ) from exc
            _require(
                root_metadata.st_dev == created_root_identity.device
                and root_metadata.st_ino == created_root_identity.inode,
                f"{label} created-root identity differs from the fixed root",
            )
        else:
            _require(
                created_root_identity is None,
                f"{label} created-root identity is malformed",
            )
        try:
            initial_entries = sorted(os.listdir(root_descriptor))
        except OSError as exc:
            raise PublicationBoundaryIntegrityError(
                f"cannot inventory {label} root"
            ) from exc
        exists = lock_leaf in initial_entries
        needs_creation_sync = False
        flags = (
            os.O_RDWR
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        if not exists:
            if not allow_create:
                raise PublicationBoundaryIntegrityError(
                    f"persistent {label} is absent"
                )
            if initial_entries:
                raise PublicationBoundaryIntegrityError(
                    f"persistent {label} cannot be created beside existing state"
                )
            try:
                lock_descriptor = os.open(
                    lock_leaf,
                    flags | os.O_CREAT | os.O_EXCL,
                    PRIVATE_FILE_MODE,
                    dir_fd=root_descriptor,
                )
                needs_creation_sync = True
            except FileExistsError:
                try:
                    lock_descriptor = os.open(
                        lock_leaf,
                        flags,
                        dir_fd=root_descriptor,
                    )
                except OSError as exc:
                    raise PublicationBoundaryIntegrityError(
                        f"cannot open concurrently created persistent {label}"
                    ) from exc
                _require(
                    sorted(os.listdir(root_descriptor)) == [lock_leaf],
                    f"persistent {label} root changed during creation",
                )
                needs_creation_sync = True
            except OSError as exc:
                raise PublicationBoundaryIntegrityError(
                    f"cannot create persistent {label}"
                ) from exc
        else:
            try:
                lock_descriptor = os.open(
                    lock_leaf,
                    flags,
                    dir_fd=root_descriptor,
                )
            except OSError as exc:
                raise PublicationBoundaryIntegrityError(
                    f"cannot open existing persistent {label}"
                ) from exc
        try:
            opened = os.fstat(lock_descriptor)
            named = os.stat(
                lock_leaf,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise PublicationReceiptIOError(
                f"cannot open persistent {label}"
            ) from exc
        _require(
            stat.S_ISREG(opened.st_mode)
            and opened.st_uid == _effective_uid()
            and opened.st_nlink == 1
            and stat.S_IMODE(opened.st_mode) == PRIVATE_FILE_MODE
            and opened.st_size == 0,
            f"{label} must be an owned empty mode-0600 single-link file",
        )
        _require(
            named.st_dev == opened.st_dev and named.st_ino == opened.st_ino,
            f"{label} path identity differs",
        )
        try:
            if needs_creation_sync:
                os.fsync(lock_descriptor)
                os.fsync(root_descriptor)
                _require(
                    sorted(os.listdir(root_descriptor)) == [lock_leaf],
                    f"persistent {label} root changed after creation",
                )
            lock_api.flock(lock_descriptor, lock_api.LOCK_EX | lock_api.LOCK_NB)
            acquired = True
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                raise PublicationLockHeldError(f"{label} is already held") from None
            raise PublicationReceiptIOError(f"cannot acquire {label}") from exc
        locked = os.fstat(lock_descriptor)
        named_locked = os.stat(
            lock_leaf,
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        root_opened = os.fstat(root_descriptor)
        root_named = root.lstat()
        _require(
            locked.st_dev == opened.st_dev
            and locked.st_ino == opened.st_ino
            and named_locked.st_dev == opened.st_dev
            and named_locked.st_ino == opened.st_ino
            and root_opened.st_dev == root_named.st_dev
            and root_opened.st_ino == root_named.st_ino,
            f"{label} identity changed during acquisition",
        )
        handle = PrivateFileLockHandle(
            root=root,
            root_descriptor=root_descriptor,
            lock_leaf=lock_leaf,
            lock_descriptor=lock_descriptor,
            root_device=root_opened.st_dev,
            root_inode=root_opened.st_ino,
            lock_device=locked.st_dev,
            lock_inode=locked.st_ino,
        )
        yield_error: BaseException | None = None
        try:
            yield handle
        except BaseException as exc:
            yield_error = exc
        post_error: BaseException | None = None
        try:
            verify_private_file_lock(handle, label=label)
        except BaseException as exc:
            post_error = exc
        if yield_error is not None:
            if post_error is not None:
                raise PublicationBoundaryIntegrityError(
                    f"{label} lock integrity changed across a failed operation",
                    preceding_error=yield_error,
                ) from post_error
            raise yield_error
        if post_error is not None:
            raise PublicationBoundaryIntegrityError(
                f"{label} lock integrity changed after the operation"
            ) from post_error
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        cleanup_errors: list[BaseException] = []
        if acquired and lock_descriptor >= 0:
            try:
                lock_api.flock(lock_descriptor, lock_api.LOCK_UN)
            except BaseException as exc:
                cleanup_errors.append(exc)
        cleanup_errors.extend(
            _close_descriptors_once((lock_descriptor, root_descriptor))
        )
        if cleanup_errors:
            if primary_error is not None:
                cleanup = PublicationBoundaryIntegrityError(
                    f"cannot fully release {label} after an operation failure",
                    preceding_error=primary_error,
                )
                raise cleanup from cleanup_errors[0]
            elif isinstance(cleanup_errors[0], Exception):
                raise PublicationBoundaryIntegrityError(
                    f"cannot fully release {label}"
                ) from cleanup_errors[0]
            else:
                raise cleanup_errors[0]


def verify_private_file_lock(
    handle: PrivateFileLockHandle,
    *,
    label: str,
) -> None:
    """Revalidate a held lock before every subsequent mutation boundary."""

    _require(
        isinstance(handle, PrivateFileLockHandle),
        f"{label} handle is malformed",
    )
    try:
        root_opened = os.fstat(handle.root_descriptor)
        root_named = handle.root.lstat()
        lock_opened = os.fstat(handle.lock_descriptor)
        lock_named = os.stat(
            handle.lock_leaf,
            dir_fd=handle.root_descriptor,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise PublicationBoundaryIntegrityError(
            f"cannot revalidate {label}"
        ) from exc
    try:
        _directory_metadata(
            root_opened,
            required_mode=PRIVATE_DIRECTORY_MODE,
            label=f"{label} root",
        )
        _directory_metadata(
            root_named,
            required_mode=PRIVATE_DIRECTORY_MODE,
            label=f"{label} root",
        )
        _private_regular_file_metadata(lock_opened, label=label)
        _private_regular_file_metadata(lock_named, label=label)
        _require(
            root_opened.st_dev == handle.root_device
            and root_opened.st_ino == handle.root_inode
            and root_named.st_dev == handle.root_device
            and root_named.st_ino == handle.root_inode
            and lock_opened.st_dev == handle.lock_device
            and lock_opened.st_ino == handle.lock_inode
            and lock_named.st_dev == handle.lock_device
            and lock_named.st_ino == handle.lock_inode
            and lock_opened.st_size == 0
            and lock_named.st_size == 0,
            f"{label} identity changed while held",
        )
    except PublicationReceiptIOError as exc:
        raise PublicationBoundaryIntegrityError(
            f"{label} integrity changed while held"
        ) from exc


def _private_regular_file_metadata(
    metadata: os.stat_result,
    *,
    label: str,
) -> None:
    _require(
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == _effective_uid()
        and metadata.st_nlink == 1
        and stat.S_IMODE(metadata.st_mode) == PRIVATE_FILE_MODE,
        f"{label} must be an owned mode-0600 single-link regular file",
    )


@contextlib.contextmanager
def open_pinned_private_file_at(
    directory_fd: int,
    leaf: str,
    *,
    expected_size: int,
    expected_sha256: str,
    maximum: int,
    label: str,
) -> Iterator[int]:
    """Yield one mode-0600 file descriptor whose bytes are pinned twice."""

    leaf = _safe_leaf(leaf, label=f"{label} leaf")
    _require(
        type(expected_size) is int and 0 < expected_size <= maximum,
        f"{label} size is invalid",
    )
    _require(
        isinstance(expected_sha256, str)
        and len(expected_sha256) == 64
        and all(character in "0123456789abcdef" for character in expected_sha256),
        f"{label} SHA-256 is malformed",
    )
    descriptor = -1
    primary_error: BaseException | None = None

    def snapshot() -> os.stat_result:
        metadata = os.fstat(descriptor)
        named = os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
        _private_regular_file_metadata(metadata, label=label)
        _private_regular_file_metadata(named, label=label)
        _require(
            metadata.st_dev == named.st_dev
            and metadata.st_ino == named.st_ino
            and metadata.st_size == expected_size,
            f"{label} identity or size differs",
        )
        digest = hashlib.sha256()
        offset = 0
        try:
            while offset < expected_size:
                chunk = os.pread(
                    descriptor,
                    min(1024 * 1024, expected_size - offset),
                    offset,
                )
                _require(chunk, f"{label} ended before its declared size")
                digest.update(chunk)
                offset += len(chunk)
            trailing = os.pread(descriptor, 1, expected_size)
        except OSError as exc:
            raise PublicationReceiptIOError(f"cannot read {label}") from exc
        _require(
            offset == expected_size
            and trailing == b""
            and digest.hexdigest() == expected_sha256,
            f"{label} bytes differ",
        )
        return metadata

    try:
        descriptor = os.open(
            leaf,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory_fd,
        )
        before = snapshot()
        os.lseek(descriptor, 0, os.SEEK_SET)
        _require(
            os.lseek(descriptor, 0, os.SEEK_CUR) == 0,
            f"{label} offset is not zero",
        )
        yield_error: BaseException | None = None
        try:
            yield descriptor
        except BaseException as exc:
            yield_error = exc
        post_error: BaseException | None = None
        try:
            after = snapshot()
            _require(
                after.st_dev == before.st_dev
                and after.st_ino == before.st_ino
                and after.st_mtime_ns == before.st_mtime_ns
                and after.st_ctime_ns == before.st_ctime_ns,
                f"{label} metadata changed while pinned",
            )
            if yield_error is None:
                _require(
                    os.lseek(descriptor, 0, os.SEEK_CUR) == expected_size,
                    f"{label} was not consumed at its exact declared length",
                )
        except BaseException as exc:
            post_error = exc
        if yield_error is not None:
            if post_error is not None:
                integrity = PublicationBoundaryIntegrityError(
                    f"{label} integrity changed across a failed operation",
                    preceding_error=yield_error,
                )
                raise integrity from post_error
            raise yield_error
        if post_error is not None:
            raise PublicationBoundaryIntegrityError(
                f"{label} integrity changed after the operation"
            ) from post_error
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as exc:
                if primary_error is not None:
                    cleanup = PublicationBoundaryIntegrityError(
                        f"cannot close {label} after an operation failure",
                        preceding_error=primary_error,
                    )
                    raise cleanup from exc
                else:
                    raise PublicationBoundaryIntegrityError(
                        f"cannot close {label}"
                    ) from exc


def source_digest_from_fd(
    descriptor: int,
    *,
    expected_size: int,
    label: str,
) -> str:
    """Hash exactly one declared regular-file extent through ``pread``."""

    digest = hashlib.sha256()
    offset = 0
    while offset < expected_size:
        try:
            chunk = os.pread(
                descriptor,
                min(1024 * 1024, expected_size - offset),
                offset,
            )
        except OSError as exc:
            raise PublicationReceiptIOError(f"cannot read {label}") from exc
        _require(chunk, f"{label} ended before its declared size")
        digest.update(chunk)
        offset += len(chunk)
    try:
        trailing = os.pread(descriptor, 1, expected_size)
    except OSError as exc:
        raise PublicationReceiptIOError(f"cannot read {label}") from exc
    _require(trailing == b"", f"{label} exceeds its declared size")
    return digest.hexdigest()


def stage_private_file_from_fd_noreplace_at(
    source_fd: int,
    destination_directory_fd: int,
    destination_leaf: str,
    *,
    expected_size: int,
    expected_sha256: str,
    maximum: int,
    label: str,
    allow_existing_exact: bool = False,
) -> str:
    """Stream one pinned source fd into a durable mode-0600 no-replace leaf."""

    destination_leaf = _safe_leaf(
        destination_leaf, label=f"{label} destination leaf"
    )
    _require(
        type(expected_size) is int and 0 < expected_size <= maximum,
        f"{label} expected size is invalid",
    )
    _require(
        isinstance(expected_sha256, str)
        and len(expected_sha256) == 64
        and all(character in "0123456789abcdef" for character in expected_sha256),
        f"{label} expected SHA-256 is malformed",
    )
    try:
        destination_metadata = os.fstat(destination_directory_fd)
        source_before = os.fstat(source_fd)
    except OSError as exc:
        raise PublicationReceiptIOError(f"cannot inspect {label}") from exc
    _directory_metadata(
        destination_metadata,
        required_mode=PRIVATE_DIRECTORY_MODE,
        label=f"{label} destination directory",
    )
    _require(
        stat.S_ISREG(source_before.st_mode)
        and source_before.st_uid == _effective_uid()
        and source_before.st_nlink == 1
        and source_before.st_size == expected_size,
        f"{label} source metadata differs",
    )
    try:
        existing_metadata = os.stat(
            destination_leaf,
            dir_fd=destination_directory_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        existing_metadata = None
    except OSError as exc:
        raise PublicationReceiptIOError(
            f"cannot inspect {label} destination"
        ) from exc
    if existing_metadata is not None:
        _require(
            allow_existing_exact is True,
            f"existing {label} lacks same-plan recovery authority",
        )
        _private_regular_file_metadata(existing_metadata, label=label)
        existing = consume_regular_snapshot_at(
            destination_directory_fd,
            destination_leaf,
            display_path=pathlib.Path(destination_leaf),
            maximum=maximum,
            label=f"existing {label}",
            validate_metadata=lambda metadata: _private_regular_file_metadata(
                metadata, label=label
            ),
        )
        _require(
            existing.size == expected_size
            and existing.sha256 == expected_sha256,
            f"existing {label} destination bytes differ",
        )
        return existing.sha256
    temporary_fd = -1
    temporary_leaf = ""
    committed = False
    cleanup_safe = True
    primary_error: BaseException | None = None

    def source_digest() -> str:
        return source_digest_from_fd(
            source_fd,
            expected_size=expected_size,
            label=f"{label} source",
        )

    try:
        for attempt in range(1000):
            candidate = f".{destination_leaf}.pending-{os.getpid()}-{attempt}"
            try:
                temporary_fd = os.open(
                    candidate,
                    os.O_RDWR
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    PRIVATE_FILE_MODE,
                    dir_fd=destination_directory_fd,
                )
            except FileExistsError:
                continue
            except OSError as exc:
                raise PublicationReceiptIOError(
                    f"cannot create {label} staging leaf"
                ) from exc
            temporary_leaf = candidate
            break
        _require(temporary_fd >= 0, f"cannot allocate {label} staging leaf")
        digest = hashlib.sha256()
        offset = 0
        while offset < expected_size:
            try:
                chunk = os.pread(
                    source_fd,
                    min(1024 * 1024, expected_size - offset),
                    offset,
                )
            except OSError as exc:
                raise PublicationReceiptIOError(f"cannot read {label} source") from exc
            _require(chunk, f"{label} source ended before its declared size")
            _write_all(temporary_fd, chunk, label=label)
            digest.update(chunk)
            offset += len(chunk)
        _require(
            digest.hexdigest() == expected_sha256,
            f"{label} source digest differs",
        )
        os.fsync(temporary_fd)
        temporary_metadata = os.fstat(temporary_fd)
        named_temporary = os.stat(
            temporary_leaf,
            dir_fd=destination_directory_fd,
            follow_symlinks=False,
        )
        _private_regular_file_metadata(temporary_metadata, label=label)
        _require(
            temporary_metadata.st_size == expected_size
            and named_temporary.st_dev == temporary_metadata.st_dev
            and named_temporary.st_ino == temporary_metadata.st_ino
            and source_digest_from_fd(
                temporary_fd,
                expected_size=expected_size,
                label=f"{label} staged file",
            )
            == expected_sha256,
            f"{label} staged size differs",
        )
        source_after = os.fstat(source_fd)
        _require(
            source_after.st_dev == source_before.st_dev
            and source_after.st_ino == source_before.st_ino
            and source_after.st_mtime_ns == source_before.st_mtime_ns
            and source_after.st_ctime_ns == source_before.st_ctime_ns
            and source_digest() == expected_sha256,
            f"{label} source changed during staging",
        )
        cleanup_safe = False
        try:
            _rename_noreplace(
                temporary_leaf,
                destination_leaf,
                source_directory_fd=destination_directory_fd,
                destination_directory_fd=destination_directory_fd,
            )
            committed = True
        except BaseException as exc:
            destination_identity: os.stat_result | None = None
            temporary_identity: os.stat_result | None = None
            try:
                destination_identity = os.stat(
                    destination_leaf,
                    dir_fd=destination_directory_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            try:
                temporary_identity = os.stat(
                    temporary_leaf,
                    dir_fd=destination_directory_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            if (
                destination_identity is not None
                and destination_identity.st_dev == temporary_metadata.st_dev
                and destination_identity.st_ino == temporary_metadata.st_ino
                and temporary_identity is None
            ):
                committed = True
                raise PublicationReceiptCommittedError(
                    f"{label} committed before an interrupted return",
                    leaf=destination_leaf,
                    digest=expected_sha256,
                ) from exc
            if (
                destination_identity is None
                and temporary_identity is not None
                and temporary_identity.st_dev == temporary_metadata.st_dev
                and temporary_identity.st_ino == temporary_metadata.st_ino
            ):
                cleanup_safe = True
                raise
            raise PublicationBoundaryIntegrityError(
                f"{label} rename visibility is indeterminate"
            ) from exc
        os.fsync(destination_directory_fd)
        named_destination = os.stat(
            destination_leaf,
            dir_fd=destination_directory_fd,
            follow_symlinks=False,
        )
        held_after = os.fstat(temporary_fd)
        _require(
            named_destination.st_dev == temporary_metadata.st_dev
            and named_destination.st_ino == temporary_metadata.st_ino
            and held_after.st_dev == temporary_metadata.st_dev
            and held_after.st_ino == temporary_metadata.st_ino,
            f"{label} destination identity changed after commit",
        )
        snapshot = consume_regular_snapshot_at(
            destination_directory_fd,
            destination_leaf,
            display_path=pathlib.Path(destination_leaf),
            maximum=maximum,
            label=label,
            validate_metadata=lambda metadata: _private_regular_file_metadata(
                metadata, label=label
            ),
        )
        _require(
            snapshot.size == expected_size
            and snapshot.sha256 == expected_sha256,
            f"{label} staged bytes differ",
        )
        return snapshot.sha256
    except PublicationReceiptCommittedError:
        raise
    except BaseException as exc:
        primary_error = exc
        if committed:
            raise PublicationReceiptCommittedError(
                f"{label} committed but post-publication validation failed",
                leaf=destination_leaf,
                digest=expected_sha256,
            ) from exc
        raise
    finally:
        cleanup_error: BaseException | None = None
        if temporary_fd >= 0:
            try:
                os.close(temporary_fd)
            except BaseException as exc:
                cleanup_error = exc
        if temporary_leaf and not committed and cleanup_safe:
            try:
                os.unlink(temporary_leaf, dir_fd=destination_directory_fd)
            except FileNotFoundError:
                pass
            except BaseException as exc:
                cleanup_error = cleanup_error or exc
        if cleanup_error is not None:
            if committed:
                raise PublicationReceiptCommittedError(
                    f"{label} committed but staging cleanup failed",
                    leaf=destination_leaf,
                    digest=expected_sha256,
                ) from cleanup_error
            boundary = PublicationBoundaryIntegrityError(
                f"cannot clean {label} staging resources",
                preceding_error=primary_error,
            )
            raise boundary from cleanup_error


def recover_private_staging_residues_at(
    directory_fd: int,
    allowed_final_entries: frozenset[str],
    *,
    label: str,
    recoverable_final_leaves: frozenset[str] | None = None,
) -> tuple[str, ...]:
    """Remove only crash-left precommit files for a held private transaction.

    The caller's cross-worktree lock proves that no live transaction can own
    these names. Final leaves are never removed or replaced.
    """

    finals = _validated_directory_inventory(allowed_final_entries, label=label)
    recoverable = (
        finals
        if recoverable_final_leaves is None
        else _validated_directory_inventory(
            recoverable_final_leaves,
            label=f"{label} recoverable leaves",
        )
    )
    _require(
        recoverable <= finals,
        f"{label} recoverable leaves differ from allowed final entries",
    )
    try:
        directory_metadata = os.fstat(directory_fd)
        entries_before = sorted(os.listdir(directory_fd))
    except OSError as exc:
        raise PublicationReceiptIOError(f"cannot inventory {label}") from exc
    _directory_metadata(
        directory_metadata,
        required_mode=PRIVATE_DIRECTORY_MODE,
        label=label,
    )
    _require(
        len(entries_before) <= MAX_FIXED_DIRECTORY_ENTRIES,
        f"{label} exceeds its bounded inventory",
    )
    pending_pattern = re.compile(
        r"^\.(?P<final>[0-9A-Za-z][0-9A-Za-z._-]*)\.pending-"
        r"[1-9][0-9]*(?:-[0-9]+)?$"
    )
    residues: list[str] = []
    residue_targets: set[str] = set()
    for entry in entries_before:
        if entry in finals:
            continue
        match = pending_pattern.fullmatch(entry)
        _require(
            match is not None and match.group("final") in recoverable,
            f"{label} contains an unexpected entry",
        )
        _require(
            match.group("final") not in entries_before,
            f"{label} contains both a final leaf and its pending residue",
        )
        _require(
            match.group("final") not in residue_targets,
            f"{label} contains multiple residues for one final leaf",
        )
        residue_targets.add(match.group("final"))
        try:
            metadata = os.stat(entry, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise PublicationReceiptIOError(
                f"cannot inspect {label} residue"
            ) from exc
        _private_regular_file_metadata(metadata, label=f"{label} residue")
        residues.append(entry)
    entries_resampled = sorted(os.listdir(directory_fd))
    _require(
        entries_resampled == entries_before,
        f"{label} changed before residue recovery",
    )
    for entry in residues:
        try:
            os.unlink(entry, dir_fd=directory_fd)
        except OSError as exc:
            raise PublicationBoundaryIntegrityError(
                f"cannot remove {label} precommit residue"
            ) from exc
    if residues:
        try:
            os.fsync(directory_fd)
        except OSError as exc:
            raise PublicationBoundaryIntegrityError(
                f"cannot durably recover {label} precommit residues"
            ) from exc
    final_entries = sorted(os.listdir(directory_fd))
    _require(
        final_entries == sorted(set(entries_before) - set(residues)),
        f"{label} changed during residue recovery",
    )
    return tuple(residues)


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
    cause: BaseException,
) -> PublicationReceiptCommittedError:
    publication = handle.committed_publication
    _require(
        publication is not None,
        f"{label} committed publication state is incomplete",
    )
    return _committed_publication_error(
        label=label,
        leaf=publication.leaf,
        digest=publication.digest,
        detail=detail,
        cause=cause,
        visibility=publication.visibility,
    )


def _committed_publication_error(
    *,
    label: str,
    leaf: str,
    digest: str,
    detail: str,
    cause: BaseException,
    visibility: PublicationVisibility = "committed",
    path: pathlib.Path | None = None,
) -> PublicationReceiptCommittedError:
    state = "committed" if visibility == "committed" else "visibility indeterminate"
    error = PublicationReceiptCommittedError(
        f"{label} {state} leaf={leaf} sha256={digest}; {detail}",
        leaf=leaf,
        digest=digest,
        visibility=visibility,
        path=path,
    )
    error.__cause__ = cause
    return error


def _directory_context_committed_error(
    handle: PrivateDirectoryHandle | None,
    *,
    label: str,
    preceding_error: BaseException | None,
) -> PublicationReceiptCommittedError | None:
    """Retain or derive committed state after a directory-context body fails."""

    publication = (
        None if handle is None else handle.committed_publication
    )
    if isinstance(preceding_error, PublicationReceiptCommittedError):
        if (
            publication is not None
            and publication.visibility == "indeterminate"
            and (
                preceding_error.visibility != "indeterminate"
                or preceding_error.path is not None
                or preceding_error.leaf != publication.leaf
                or preceding_error.digest != publication.digest
            )
        ):
            return _committed_publication_error(
                label=label,
                leaf=publication.leaf,
                digest=publication.digest,
                detail=(
                    "directory state retained indeterminate publication visibility"
                ),
                cause=preceding_error,
                visibility="indeterminate",
                path=None,
            )
        return preceding_error
    if publication is None:
        return None
    if preceding_error is None:
        if publication.visibility == "committed":
            return None
        return PublicationReceiptCommittedError(
            f"{label} retained indeterminate publication visibility",
            leaf=publication.leaf,
            digest=publication.digest,
            visibility="indeterminate",
            path=None,
        )
    return _committed_publication_error(
        label=label,
        leaf=publication.leaf,
        digest=publication.digest,
        detail="committed publication was followed by an operation failure",
        cause=preceding_error,
        visibility=publication.visibility,
        path=None,
    )


def _directory_context_identity_outcome(
    handle: PrivateDirectoryHandle | None,
    *,
    label: str,
    detail: str,
    preceding_error: BaseException | None,
    cause: BaseException,
) -> tuple[
    PublicationReceiptCommittedError | None,
    PublicationBoundaryIntegrityError | None,
]:
    """Classify identity failure while retaining any committed state."""

    committed = _directory_context_committed_error(
        handle,
        label=label,
        preceding_error=preceding_error,
    )
    boundary = PublicationBoundaryIntegrityError(
        detail,
        preceding_error=(
            committed if committed is not None else preceding_error
        ),
    )
    boundary.__cause__ = cause
    if committed is None:
        return None, boundary
    error = PublicationReceiptCommittedError(
        f"{label} committed publication visibility is indeterminate; {detail}",
        leaf=committed.leaf,
        digest=committed.digest,
        visibility="indeterminate",
        path=None,
    )
    error.__cause__ = boundary
    return error, None


def _retain_committed_cleanup_failure(
    error: BaseException | None,
    *,
    detail: str,
) -> bool:
    """Attach pure descriptor-cleanup failure to an existing committed error."""

    if not isinstance(error, PublicationReceiptCommittedError):
        return False
    error.add_note(detail)
    return True


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
    replacement_error: PublicationReceiptCommittedError | None = None
    boundary_error: PublicationBoundaryIntegrityError | None = None
    try:
        yield handle
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        replacement_error = _directory_context_committed_error(
            handle,
            label=label,
            preceding_error=primary_error,
        )
        effective_error: BaseException | None = (
            replacement_error if replacement_error is not None else primary_error
        )
        if handle.committed_leaf is None or effective_error is not None:
            try:
                verify_private_directory_handle_identity(handle, label=label)
            except BaseException as exc:
                detail = (
                    f"{label} identity changed while pinned after an operation failure"
                    if effective_error is not None
                    else f"{label} identity changed while pinned after the operation"
                )
                committed_boundary, classified_boundary = (
                    _directory_context_identity_outcome(
                        handle,
                        label=label,
                        detail=detail,
                        preceding_error=effective_error,
                        cause=exc,
                    )
                )
                if committed_boundary is not None:
                    replacement_error = committed_boundary
                    effective_error = committed_boundary
                else:
                    boundary_error = classified_boundary
        try:
            os.close(handle.descriptor)
        except BaseException as exc:
            effective_error = (
                replacement_error
                if replacement_error is not None
                else primary_error
            )
            detail = f"cannot close pinned {label}"
            if _retain_committed_cleanup_failure(
                effective_error,
                detail=detail,
            ):
                pass
            elif primary_error is not None:
                boundary_error = PublicationBoundaryIntegrityError(
                    f"cannot close pinned {label} after an operation failure",
                    preceding_error=primary_error,
                )
                boundary_error.__cause__ = exc
            elif handle.committed_leaf is not None:
                primary_error = _committed_resource_error(
                    handle,
                    label=label,
                    detail="cannot close committed directory descriptor",
                    cause=exc,
                )
                replacement_error = primary_error
            else:
                boundary_error = PublicationBoundaryIntegrityError(
                    f"cannot close pinned {label}"
                )
                boundary_error.__cause__ = exc
        if replacement_error is not None:
            if (
                replacement_error is not primary_error
                or sys.exception() is None
            ):
                raise replacement_error
        elif boundary_error is not None:
            raise boundary_error
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
    root, root_fd, safe_root_parent_fd, _created = (
        _open_or_create_private_safe_root(
            safe_root,
            label=f"{label} safe root",
            create=False,
            sync_parent=create or sync_safe_root_parent,
            retain_parent=sync_safe_root_parent,
        )
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
    replacement_error: PublicationReceiptCommittedError | None = None
    boundary_error: PublicationBoundaryIntegrityError | None = None
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
        replacement_error = _directory_context_committed_error(
            child_handle if isinstance(child_handle, PrivateDirectoryHandle) else None,
            label=label,
            preceding_error=primary_error,
        )
        effective_error: BaseException | None = (
            replacement_error if replacement_error is not None else primary_error
        )
        if not committed or effective_error is not None:
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
            except BaseException as exc:
                detail = (
                    f"{label} safe root changed after an operation failure"
                    if effective_error is not None
                    else str(exc)
                )
                committed_boundary, classified_boundary = (
                    _directory_context_identity_outcome(
                        child_handle
                        if isinstance(child_handle, PrivateDirectoryHandle)
                        else None,
                        label=label,
                        detail=detail,
                        preceding_error=effective_error,
                        cause=exc,
                    )
                )
                if committed_boundary is not None:
                    replacement_error = committed_boundary
                    effective_error = committed_boundary
                else:
                    boundary_error = classified_boundary
        try:
            os.close(root_fd)
        except BaseException as exc:
            effective_error = (
                replacement_error
                if replacement_error is not None
                else primary_error
            )
            detail = f"cannot close {label} safe root"
            if _retain_committed_cleanup_failure(
                effective_error,
                detail=detail,
            ):
                pass
            elif primary_error is not None:
                boundary_error = PublicationBoundaryIntegrityError(
                    f"cannot close {label} safe root after an operation failure",
                    preceding_error=primary_error,
                )
                boundary_error.__cause__ = exc
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
                if isinstance(
                    primary_error,
                    PublicationReceiptCommittedError,
                ):
                    replacement_error = primary_error
            else:
                boundary_error = PublicationBoundaryIntegrityError(
                    f"cannot close {label} safe root"
                )
                boundary_error.__cause__ = exc
        if safe_root_parent_fd is not None:
            try:
                os.close(safe_root_parent_fd)
            except BaseException as exc:
                effective_error = (
                    replacement_error
                    if replacement_error is not None
                    else primary_error
                )
                detail = f"cannot close {label} safe-root parent"
                if _retain_committed_cleanup_failure(
                    effective_error,
                    detail=detail,
                ):
                    pass
                elif primary_error is not None:
                    boundary_error = PublicationBoundaryIntegrityError(
                        f"cannot close {label} safe-root parent after an operation failure",
                        preceding_error=primary_error,
                    )
                    boundary_error.__cause__ = exc
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
                    if isinstance(
                        primary_error,
                        PublicationReceiptCommittedError,
                    ):
                        replacement_error = primary_error
                else:
                    boundary_error = PublicationBoundaryIntegrityError(
                        f"cannot close {label} safe-root parent"
                    )
                    boundary_error.__cause__ = exc
        if replacement_error is not None:
            if (
                replacement_error is not primary_error
                or sys.exception() is None
            ):
                raise replacement_error
        elif boundary_error is not None:
            raise boundary_error
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


def _private_file_mutation_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Return portable metadata that must remain stable during one file read."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _snapshot_open_private_file(
    descriptor: int,
    *,
    maximum: int,
    label: str,
    expected_device: int | None = None,
    expected_inode: int | None = None,
) -> _OpenPrivateFileSnapshot:
    """Hash bounded bytes with pread while one staging inode stays pinned open."""

    if type(maximum) is not int or maximum <= 0:
        raise EvidenceIOError(f"{label} maximum must be a positive integer")

    validate = _regular_metadata_validator(
        required_mode=PRIVATE_FILE_MODE,
        label=label,
    )
    try:
        before = os.fstat(descriptor)
        validate(before)
        if (
            expected_device is not None
            and before.st_dev != expected_device
        ) or (
            expected_inode is not None
            and before.st_ino != expected_inode
        ):
            raise EvidenceIOError(f"{label} identity changed")
        if before.st_size > maximum:
            raise EvidenceIOError(f"{label} exceeds {maximum} bytes")

        digest = hashlib.sha256()
        offset = 0
        remaining = maximum + 1
        while remaining:
            chunk = os.pread(
                descriptor,
                min(1024 * 1024, remaining),
                offset,
            )
            if not chunk:
                break
            offset += len(chunk)
            remaining -= len(chunk)
            if offset > maximum:
                raise EvidenceIOError(f"{label} exceeds {maximum} bytes")
            digest.update(chunk)

        after = os.fstat(descriptor)
        validate(after)
        if (
            _private_file_mutation_identity(before)
            != _private_file_mutation_identity(after)
            or offset != before.st_size
            or offset != after.st_size
        ):
            raise EvidenceIOError(f"{label} changed while it was read")
    except EvidenceIOError:
        raise
    except OSError as exc:
        raise EvidenceIOError(f"cannot read {label}") from exc

    return _OpenPrivateFileSnapshot(
        metadata=after,
        size=offset,
        sha256=digest.hexdigest(),
    )


def _verify_named_private_file_matches_open_at(
    directory_fd: int,
    leaf: str,
    *,
    descriptor: int,
    size: int,
    digest: str,
    label: str,
    expected_device: int | None = None,
    expected_inode: int | None = None,
) -> None:
    """Require a named leaf to remain the exact bytes pinned by an open fd."""

    held_before = _snapshot_open_private_file(
        descriptor,
        maximum=max(1, size),
        label=f"{label} held file",
        expected_device=expected_device,
        expected_inode=expected_inode,
    )
    if held_before.size != size or held_before.sha256 != digest:
        raise EvidenceIOError(f"{label} held bytes changed")

    def validate_named(metadata: os.stat_result) -> None:
        _regular_metadata_validator(
            required_mode=PRIVATE_FILE_MODE,
            label=label,
        )(metadata)
        if (
            _private_file_mutation_identity(metadata)
            != _private_file_mutation_identity(held_before.metadata)
        ):
            raise EvidenceIOError(f"named {label} differs from held file")

    named = consume_regular_snapshot_at(
        directory_fd,
        leaf,
        display_path=pathlib.Path(leaf),
        maximum=max(1, size),
        label=label,
        consume=lambda _chunk: None,
        validate_metadata=validate_named,
    )
    if named.size != size or named.sha256 != digest:
        raise EvidenceIOError(f"{label} bytes differ from held file")

    held_after = _snapshot_open_private_file(
        descriptor,
        maximum=max(1, size),
        label=f"{label} held file",
        expected_device=held_before.metadata.st_dev,
        expected_inode=held_before.metadata.st_ino,
    )
    if (
        _private_file_mutation_identity(held_after.metadata)
        != _private_file_mutation_identity(held_before.metadata)
        or held_after.size != size
        or held_after.sha256 != digest
    ):
        raise EvidenceIOError(f"{label} held file changed during named verification")

    try:
        named_after = os.stat(
            leaf,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        validate_named(named_after)
    except EvidenceIOError:
        raise
    except OSError as exc:
        raise EvidenceIOError(f"cannot resample named {label}") from exc


def _matches_exact_private_file_at(
    directory_fd: int,
    leaf: str,
    *,
    descriptor: int,
    size: int,
    digest: str,
    label: str,
) -> bool:
    """Return whether one named leaf is the exact stable prepared file."""

    try:
        _verify_named_private_file_matches_open_at(
            directory_fd,
            leaf,
            descriptor=descriptor,
            size=size,
            digest=digest,
            label=label,
        )
    except EvidenceIOError:
        return False
    return True


_VISIBILITY_EXACT = "exact"
_VISIBILITY_PRECOMMIT = "precommit"
_VISIBILITY_INDETERMINATE = "indeterminate"


@dataclass(slots=True)
class _PrivateFilePublicationState:
    """Conservative cleanup ownership for one no-replace visibility attempt."""

    visibility: _InterruptedVisibility = _VISIBILITY_PRECOMMIT

    @property
    def cleanup_is_safe(self) -> bool:
        return self.visibility == _VISIBILITY_PRECOMMIT

    @property
    def committed_error_visibility(self) -> PublicationVisibility:
        _require(
            not self.cleanup_is_safe,
            "precommit publication has no committed error visibility",
        )
        return (
            "committed"
            if self.visibility == _VISIBILITY_EXACT
            else "indeterminate"
        )


def _classify_interrupted_visibility_at(
    directory_fd: int,
    *,
    destination_leaf: str,
    staging_leaf: str,
    descriptor: int,
    size: int,
    digest: str,
    label: str,
) -> _InterruptedVisibility:
    """Classify an interrupted rename without treating uncertainty as absence."""

    if _matches_exact_private_file_at(
        directory_fd,
        destination_leaf,
        descriptor=descriptor,
        size=size,
        digest=digest,
        label=f"{label} visible destination",
    ):
        return _VISIBILITY_EXACT
    if _matches_exact_private_file_at(
        directory_fd,
        staging_leaf,
        descriptor=descriptor,
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
    descriptor: int,
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
            descriptor=descriptor,
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


def _raise_for_private_file_publication_visibility(
    state: _PrivateFilePublicationState,
    *,
    directory_fd: int,
    destination_leaf: str,
    staging_leaf: str,
    descriptor: int,
    size: int,
    digest: str,
    label: str,
    interruption: BaseException,
    record_visible: Callable[[], None] | None,
) -> Never:
    """Classify one interrupted visibility attempt and raise its domain error."""

    if state.visibility == _VISIBILITY_EXACT:
        # A normally returned no-replace rename is a stronger fact than any
        # later path observation, so post-rename failures cannot demote it.
        visibility = _VISIBILITY_EXACT
    elif isinstance(interruption, PublicationReceiptCommittedError):
        visibility = (
            _VISIBILITY_EXACT
            if interruption.visibility == "committed"
            else _VISIBILITY_INDETERMINATE
        )
        state.visibility = visibility
    else:
        visibility = _classify_interrupted_visibility_conservatively(
            directory_fd,
            destination_leaf=destination_leaf,
            staging_leaf=staging_leaf,
            descriptor=descriptor,
            size=size,
            digest=digest,
            label=f"{label} interrupted visibility point",
            interruption=interruption,
        )
        state.visibility = visibility
    if visibility == _VISIBILITY_PRECOMMIT:
        raise interruption
    if record_visible is not None:
        record_visible()
    if isinstance(interruption, PublicationReceiptCommittedError):
        raise interruption
    if visibility == _VISIBILITY_EXACT:
        raise _committed_publication_error(
            label=label,
            leaf=destination_leaf,
            digest=digest,
            detail="was atomically published but operation did not return normally",
            cause=interruption,
        )
    raise _committed_publication_error(
        label=label,
        leaf=destination_leaf,
        digest=digest,
        detail="visibility could not be safely classified",
        cause=interruption,
        visibility="indeterminate",
    )


def _publish_private_file_noreplace_at(
    state: _PrivateFilePublicationState,
    *,
    directory_fd: int,
    destination_leaf: str,
    staging_leaf: str,
    descriptor: int,
    size: int,
    digest: str,
    label: str,
    record_visible: Callable[[], None] | None,
    verify_visible: Callable[[], None],
    release_held: Callable[[], None],
) -> None:
    """Own rename, visibility state, recovery, and post-rename verification."""

    try:
        try:
            # From here onward cleanup must preserve both names unless a held-fd
            # classification later proves that staging is still exact.
            state.visibility = _VISIBILITY_INDETERMINATE
            _rename_noreplace(directory_fd, staging_leaf, destination_leaf)
            state.visibility = _VISIBILITY_EXACT
            if record_visible is not None:
                record_visible()
            verify_visible()
            release_held()
            return
        except BaseException as interruption:
            _raise_for_private_file_publication_visibility(
                state,
                directory_fd=directory_fd,
                destination_leaf=destination_leaf,
                staging_leaf=staging_leaf,
                descriptor=descriptor,
                size=size,
                digest=digest,
                label=label,
                interruption=interruption,
                record_visible=record_visible,
            )
    except PublicationReceiptCommittedError:
        raise
    except BaseException as recovery_interruption:
        # A second asynchronous exception can land after classification returns
        # but before its state/callback is recorded.  The conservative state was
        # already installed before rename, so reclassification cannot mis-clean.
        _raise_for_private_file_publication_visibility(
            state,
            directory_fd=directory_fd,
            destination_leaf=destination_leaf,
            staging_leaf=staging_leaf,
            descriptor=descriptor,
            size=size,
            digest=digest,
            label=label,
            interruption=recovery_interruption,
            record_visible=record_visible,
        )


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
    held_file: OwnedFileDescriptorLease
    publication_state: _PrivateFilePublicationState

    @property
    def descriptor(self) -> int:
        return self.held_file.descriptor

    @property
    def published(self) -> bool:
        publication = self.directory.committed_publication
        return (
            publication is not None
            and publication.leaf == self.expected_leaf
            and publication.digest == self.digest
        )

    def _mark_published(self) -> None:
        self.directory.mark_publication(
            leaf=self.expected_leaf,
            digest=self.digest,
            visibility=self.publication_state.committed_error_visibility,
        )

    def _close_descriptor(self, *, primary_error: BaseException | None) -> None:
        if not self.held_file.is_owned:
            return
        try:
            self.held_file.close()
        except BaseException as exc:
            if primary_error is not None:
                primary_error.add_note(
                    f"cannot close {self.label} held staging descriptor"
                )
                return
            if not self.publication_state.cleanup_is_safe:
                raise _committed_publication_error(
                    label=self.label,
                    leaf=self.expected_leaf,
                    digest=self.digest,
                    detail="committed staging descriptor could not be closed",
                    cause=exc,
                    visibility=(
                        self.publication_state.committed_error_visibility
                    ),
                )
            if isinstance(exc, Exception):
                raise PublicationReceiptIOError(
                    f"cannot close {self.label} held staging descriptor"
                ) from exc
            raise

    def commit_after_revalidation(self) -> str:
        """Commit with an outer boundary covering the helper-to-caller return."""

        try:
            return self._commit_after_revalidation()
        except PublicationReceiptCommittedError:
            raise
        except BaseException as boundary_interruption:
            if self.publication_state.cleanup_is_safe:
                raise
            _raise_for_private_file_publication_visibility(
                self.publication_state,
                directory_fd=self.directory.descriptor,
                destination_leaf=self.expected_leaf,
                staging_leaf=self.staging_leaf,
                descriptor=self.descriptor,
                size=self.size,
                digest=self.digest,
                label=self.label,
                interruption=boundary_interruption,
                record_visible=self._mark_published,
            )

    def _commit_after_revalidation(self) -> str:
        """Revalidate held ancestry, then atomically make the receipt visible."""

        primary_error: BaseException | None = None
        try:
            _require(not self.published, f"{self.label} is already committed")
            _require(
                self.descriptor >= 0,
                f"{self.label} held staging descriptor is closed",
            )
            _require(
                self.directory.committed_leaf is None,
                f"{self.label} directory already contains a committed publication",
            )
            try:
                _verify_named_private_file_matches_open_at(
                    self.directory.descriptor,
                    self.staging_leaf,
                    descriptor=self.descriptor,
                    size=self.size,
                    digest=self.digest,
                    label=f"{self.label} staging file",
                    expected_device=self.device,
                    expected_inode=self.inode,
                )
            except EvidenceIOError as exc:
                raise PublicationReceiptIOError(
                    f"cannot safely resample {self.label} staging file"
                ) from exc
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

            def verify_visible() -> None:
                _verify_named_private_file_matches_open_at(
                    self.directory.descriptor,
                    self.expected_leaf,
                    descriptor=self.descriptor,
                    size=self.size,
                    digest=self.digest,
                    label=f"{self.label} committed file",
                    expected_device=self.device,
                    expected_inode=self.inode,
                )
                os.fsync(self.directory.descriptor)
                _verify_named_private_file_matches_open_at(
                    self.directory.descriptor,
                    self.expected_leaf,
                    descriptor=self.descriptor,
                    size=self.size,
                    digest=self.digest,
                    label=f"{self.label} committed file",
                    expected_device=self.device,
                    expected_inode=self.inode,
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

            def release_held() -> None:
                self._close_descriptor(primary_error=None)

            _publish_private_file_noreplace_at(
                self.publication_state,
                directory_fd=self.directory.descriptor,
                destination_leaf=self.expected_leaf,
                staging_leaf=self.staging_leaf,
                descriptor=self.descriptor,
                size=self.size,
                digest=self.digest,
                label=self.label,
                record_visible=self._mark_published,
                verify_visible=verify_visible,
                release_held=release_held,
            )
            return self.digest
        except BaseException as exc:
            primary_error = exc
            raise
        finally:
            if not self.publication_state.cleanup_is_safe:
                self._close_descriptor(primary_error=primary_error)


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
    held_file: OwnedFileDescriptorLease | None = None
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
            os.O_RDWR
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
        try:
            opened_metadata = os.fstat(descriptor)
        except OSError as exc:
            raise PublicationReceiptIOError(
                f"cannot inspect {label} staging file"
            ) from exc
        held_file = OwnedFileDescriptorLease.acquire(
            descriptor,
            label=f"{label} staging file",
        )
        descriptor = -1
        _write_all(held_file.descriptor, payload, label=label)
        try:
            os.fchmod(held_file.descriptor, PRIVATE_FILE_MODE)
            metadata = os.fstat(held_file.descriptor)
            _regular_metadata_validator(
                required_mode=PRIVATE_FILE_MODE,
                label=label,
            )(metadata)
            os.fsync(held_file.descriptor)
            staged = _snapshot_open_private_file(
                held_file.descriptor,
                maximum=max(1, len(payload)),
                label=f"{label} staging file",
                expected_device=metadata.st_dev,
                expected_inode=metadata.st_ino,
            )
            _require(
                staged.size == len(payload)
                and staged.sha256 == hashlib.sha256(payload).hexdigest(),
                f"{label} staging bytes changed while preparing",
            )
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
            held_file=held_file,
            publication_state=_PrivateFilePublicationState(),
        )
        held_file = None
        yield prepared
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        cleanup_errors: list[BaseException] = []
        if staging_created and (
            prepared is None or prepared.publication_state.cleanup_is_safe
        ):
            try:
                os.unlink(staging_leaf, dir_fd=directory.descriptor)
                os.fsync(directory.descriptor)
            except BaseException as exc:
                cleanup_errors.append(exc)
        owned_file = prepared.held_file if prepared is not None else held_file
        if owned_file is not None and owned_file.is_owned:
            try:
                owned_file.close()
            except BaseException as exc:
                cleanup_errors.append(exc)
        elif descriptor >= 0:
            try:
                os.close(descriptor)
            except BaseException as exc:
                cleanup_errors.append(exc)
        if cleanup_errors:
            detail = f"{label} staging cleanup failed"
            if primary_error is not None:
                primary_error.add_note(detail)
            elif (
                prepared is not None
                and not prepared.publication_state.cleanup_is_safe
            ):
                raise _committed_publication_error(
                    label=label,
                    leaf=expected_leaf,
                    digest=prepared.digest,
                    detail="committed staging cleanup failed",
                    cause=cleanup_errors[0],
                    visibility=(
                        prepared.publication_state.committed_error_visibility
                    ),
                )
            elif isinstance(cleanup_errors[0], Exception):
                raise PublicationReceiptIOError(detail) from cleanup_errors[0]
            else:
                raise cleanup_errors[0]


def write_private_bytes_noreplace_at(
    directory_fd: int,
    expected_leaf: str,
    payload: bytes,
    *,
    label: str,
    maximum: int = DEFAULT_RECEIPT_MAX_BYTES,
) -> str:
    """Publish bytes with an outer helper-to-caller interruption boundary."""

    publication_state = _PrivateFilePublicationState()
    try:
        return _write_private_bytes_noreplace_at(
            directory_fd,
            expected_leaf,
            payload,
            label=label,
            maximum=maximum,
            publication_state=publication_state,
        )
    except PublicationReceiptCommittedError:
        raise
    except BaseException as boundary_interruption:
        if publication_state.cleanup_is_safe:
            raise
        _raise_for_private_file_publication_visibility(
            publication_state,
            directory_fd=directory_fd,
            destination_leaf=expected_leaf,
            staging_leaf=f".{expected_leaf}.pending-{os.getpid()}",
            descriptor=-1,
            size=len(payload),
            digest=hashlib.sha256(payload).hexdigest(),
            label=label,
            interruption=boundary_interruption,
            record_visible=None,
        )


def _write_private_bytes_noreplace_at(
    directory_fd: int,
    expected_leaf: str,
    payload: bytes,
    *,
    label: str,
    maximum: int,
    publication_state: _PrivateFilePublicationState,
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
    held_file: OwnedFileDescriptorLease | None = None
    staging_leaf = f".{expected_leaf}.pending-{os.getpid()}"
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    expected_digest = hashlib.sha256(payload).hexdigest()
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
        try:
            opened_metadata = os.fstat(descriptor)
        except OSError as exc:
            raise PublicationReceiptIOError(
                f"cannot inspect {label} staging file"
            ) from exc
        held_file = OwnedFileDescriptorLease.acquire(
            descriptor,
            label=f"{label} staging file",
        )
        descriptor = -1
        _write_all(held_file.descriptor, payload, label=label)
        os.fchmod(held_file.descriptor, PRIVATE_FILE_MODE)
        metadata = os.fstat(held_file.descriptor)
        _regular_metadata_validator(
            required_mode=PRIVATE_FILE_MODE,
            label=label,
        )(metadata)
        try:
            os.fsync(held_file.descriptor)
        except OSError as exc:
            raise PublicationReceiptIOError(f"cannot sync {label}") from exc
        try:
            _verify_named_private_file_matches_open_at(
                directory_fd,
                staging_leaf,
                descriptor=held_file.descriptor,
                size=len(payload),
                digest=expected_digest,
                label=f"{label} staging file",
                expected_device=metadata.st_dev,
                expected_inode=metadata.st_ino,
            )
        except EvidenceIOError as exc:
            raise PublicationReceiptIOError(
                f"cannot safely resample {label} staging file"
            ) from exc

        def verify_visible() -> None:
            _verify_named_private_file_matches_open_at(
                directory_fd,
                expected_leaf,
                descriptor=held_file.descriptor,
                size=len(payload),
                digest=expected_digest,
                label=f"{label} published file",
                expected_device=metadata.st_dev,
                expected_inode=metadata.st_ino,
            )
            os.fsync(directory_fd)
            _verify_named_private_file_matches_open_at(
                directory_fd,
                expected_leaf,
                descriptor=held_file.descriptor,
                size=len(payload),
                digest=expected_digest,
                label=f"{label} published file",
                expected_device=metadata.st_dev,
                expected_inode=metadata.st_ino,
            )

        def release_held() -> None:
            _require(held_file is not None, f"{label} held file is absent")
            held_file.close()

        _publish_private_file_noreplace_at(
            publication_state,
            directory_fd=directory_fd,
            destination_leaf=expected_leaf,
            staging_leaf=staging_leaf,
            descriptor=held_file.descriptor,
            size=len(payload),
            digest=expected_digest,
            label=label,
            record_visible=None,
            verify_visible=verify_visible,
            release_held=release_held,
        )
    except OSError as exc:
        wrapped = PublicationReceiptIOError(f"cannot publish {label}")
        primary_error = wrapped
        raise wrapped from exc
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        cleanup_errors: list[BaseException] = []
        if staging_created and publication_state.cleanup_is_safe:
            try:
                os.unlink(staging_leaf, dir_fd=directory_fd)
                os.fsync(directory_fd)
            except BaseException as exc:
                cleanup_errors.append(exc)
        if held_file is not None and held_file.is_owned:
            try:
                held_file.close()
            except BaseException as exc:
                cleanup_errors.append(exc)
        elif descriptor >= 0:
            try:
                os.close(descriptor)
            except BaseException as exc:
                cleanup_errors.append(exc)
        if cleanup_errors:
            detail = (
                f"{label} cleanup failed for {len(cleanup_errors)} "
                "private staging resource(s)"
            )
            if primary_error is not None:
                primary_error.add_note(detail)
            elif not publication_state.cleanup_is_safe:
                raise _committed_publication_error(
                    label=label,
                    leaf=expected_leaf,
                    digest=expected_digest,
                    detail="committed staging cleanup failed",
                    cause=cleanup_errors[0],
                    visibility=publication_state.committed_error_visibility,
                )
            elif isinstance(cleanup_errors[0], Exception):
                raise PublicationReceiptIOError(detail) from cleanup_errors[0]
            else:
                raise cleanup_errors[0]
    return expected_digest


def write_private_json_noreplace_at(
    directory_fd: int,
    expected_leaf: str,
    value: object,
    *,
    label: str,
    maximum: int = DEFAULT_RECEIPT_MAX_BYTES,
) -> str:
    """Publish strict JSON with a boundary covering the bytes-writer return."""

    payload = canonical_json_bytes(value)
    publication_state = _PrivateFilePublicationState()
    try:
        digest = _write_private_bytes_noreplace_at(
            directory_fd,
            expected_leaf,
            payload,
            label=label,
            maximum=maximum,
            publication_state=publication_state,
        )
        return digest
    except PublicationReceiptCommittedError:
        raise
    except BaseException as boundary_interruption:
        if publication_state.cleanup_is_safe:
            raise
        _raise_for_private_file_publication_visibility(
            publication_state,
            directory_fd=directory_fd,
            destination_leaf=expected_leaf,
            staging_leaf=f".{expected_leaf}.pending-{os.getpid()}",
            descriptor=-1,
            size=len(payload),
            digest=hashlib.sha256(payload).hexdigest(),
            label=label,
            interruption=boundary_interruption,
            record_visible=None,
        )


def _close_descriptors_once(
    descriptors: tuple[int, ...],
) -> list[BaseException]:
    """Close every distinct descriptor once and retain every cleanup failure."""

    errors: list[BaseException] = []
    closed: set[int] = set()
    for descriptor in descriptors:
        if descriptor < 0 or descriptor in closed:
            continue
        closed.add(descriptor)
        try:
            os.close(descriptor)
        except BaseException as exc:
            errors.append(exc)
    return errors


def _remove_owned_empty_transaction_at(
    root_fd: int,
    transaction_name: str,
    *,
    descriptor: int,
    expected_device: int,
    expected_inode: int,
    label: str,
) -> None:
    """Remove only the still-named, empty directory created by this attempt."""

    cleanup_descriptor = descriptor
    close_cleanup_descriptor = False
    primary_error: BaseException | None = None
    try:
        if cleanup_descriptor < 0:
            flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            cleanup_descriptor = os.open(
                transaction_name,
                flags,
                dir_fd=root_fd,
            )
            close_cleanup_descriptor = True
        opened = os.fstat(cleanup_descriptor)
        named = os.stat(
            transaction_name,
            dir_fd=root_fd,
            follow_symlinks=False,
        )
        _directory_metadata(
            opened,
            required_mode=PRIVATE_DIRECTORY_MODE,
            label=f"{label} failed transaction directory",
        )
        _directory_metadata(
            named,
            required_mode=PRIVATE_DIRECTORY_MODE,
            label=f"{label} failed transaction directory",
        )
        _require(
            opened.st_dev == expected_device
            and opened.st_ino == expected_inode
            and named.st_dev == expected_device
            and named.st_ino == expected_inode,
            f"{label} failed transaction directory identity changed",
        )
        entries = os.listdir(cleanup_descriptor)
        _require(
            not entries,
            f"{label} failed transaction directory is not empty",
        )
        os.rmdir(transaction_name, dir_fd=root_fd)
        os.fsync(root_fd)
    except OSError as exc:
        error = PublicationReceiptIOError(
            f"cannot remove empty {label} failed transaction directory"
        )
        error.__cause__ = exc
        primary_error = error
        raise error
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        if close_cleanup_descriptor:
            close_errors = _close_descriptors_once((cleanup_descriptor,))
            if close_errors:
                detail = (
                    f"cannot close {label} failed transaction cleanup descriptor"
                )
                if primary_error is not None:
                    primary_error.add_note(detail)
                elif isinstance(close_errors[0], Exception):
                    raise PublicationReceiptIOError(detail) from close_errors[0]
                else:
                    raise close_errors[0]


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
    payload = canonical_json_bytes(value)
    _require(len(payload) <= maximum, f"{label} exceeds the bounded size")
    expected_digest = hashlib.sha256(payload).hexdigest()
    root, root_fd, parent_descriptor, _created = (
        _open_or_create_private_safe_root(
            safe_root,
            label=f"{label} safe root",
            create=True,
        )
    )
    _require_released_safe_root_parent(
        parent_descriptor,
        opened_descriptors=(root_fd,),
        label=f"{label} safe root",
    )
    descriptor = -1
    transaction_name = ""
    transaction_created = False
    transaction_device = -1
    transaction_inode = -1
    transaction_path: pathlib.Path | None = None
    digest = expected_digest
    published = False
    publication_attempted = False
    publication_state = _PrivateFilePublicationState()
    primary_error: BaseException | None = None
    try:
        for attempt in range(1000):
            candidate = f"{transaction_prefix}{os.getpid()}-{attempt}"
            try:
                os.mkdir(candidate, PRIVATE_DIRECTORY_MODE, dir_fd=root_fd)
            except FileExistsError:
                continue
            except OSError as exc:
                raise PublicationReceiptIOError(
                    f"cannot create {label} transaction directory"
                ) from exc
            transaction_name = candidate
            transaction_created = True
            try:
                created_metadata = os.stat(
                    transaction_name,
                    dir_fd=root_fd,
                    follow_symlinks=False,
                )
                transaction_device = created_metadata.st_dev
                transaction_inode = created_metadata.st_ino
                _directory_metadata(
                    created_metadata,
                    required_mode=PRIVATE_DIRECTORY_MODE,
                    label=f"{label} transaction directory",
                )
                os.fsync(root_fd)
            except OSError as exc:
                raise PublicationReceiptIOError(
                    f"cannot durably create {label} transaction directory"
                ) from exc
            break
        _require(
            bool(transaction_name),
            f"cannot allocate {label} transaction directory",
        )
        transaction = root / transaction_name
        transaction_path = transaction / expected_leaf
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
        _require(
            transaction_metadata.st_dev == transaction_device
            and transaction_metadata.st_ino == transaction_inode,
            f"{label} transaction directory differs from the created identity",
        )
        publication_attempted = True
        digest = _write_private_bytes_noreplace_at(
            descriptor,
            expected_leaf,
            payload,
            label=label,
            maximum=maximum,
            publication_state=publication_state,
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
        except PublicationReceiptCommittedError:
            raise
        except BaseException as exc:
            raise _committed_publication_error(
                label=label,
                leaf=expected_leaf,
                digest=digest,
                detail="output identity verification failed",
                cause=exc,
                path=transaction_path,
            )
    except PublicationReceiptCommittedError as exc:
        if exc.path is None:
            exc.path = transaction_path
        published = True
        primary_error = exc
        raise
    except BaseException as exc:
        primary_error = exc
        if publication_attempted and not publication_state.cleanup_is_safe:
            try:
                _raise_for_private_file_publication_visibility(
                    publication_state,
                    directory_fd=descriptor,
                    destination_leaf=expected_leaf,
                    staging_leaf=f".{expected_leaf}.pending-{os.getpid()}",
                    descriptor=-1,
                    size=len(payload),
                    digest=expected_digest,
                    label=label,
                    interruption=exc,
                    record_visible=None,
                )
            except BaseException as classified_error:
                primary_error = classified_error
                if isinstance(
                    classified_error,
                    PublicationReceiptCommittedError,
                ):
                    if classified_error.path is None:
                        classified_error.path = transaction_path
                    published = True
                raise
        raise
    finally:
        cleanup_errors: list[BaseException] = []
        if transaction_created and not published:
            if transaction_device >= 0 and transaction_inode >= 0:
                try:
                    _remove_owned_empty_transaction_at(
                        root_fd,
                        transaction_name,
                        descriptor=descriptor,
                        expected_device=transaction_device,
                        expected_inode=transaction_inode,
                        label=label,
                    )
                except BaseException as exc:
                    cleanup_errors.append(exc)
            else:
                cleanup_errors.append(
                    PublicationReceiptIOError(
                        f"cannot identify {label} failed transaction directory for cleanup"
                    )
                )
        cleanup_errors.extend(
            _close_descriptors_once((descriptor, root_fd))
        )
        if cleanup_errors:
            detail = (
                f"{label} cleanup failed for {len(cleanup_errors)} "
                "publication resource(s)"
            )
            if primary_error is not None:
                primary_error.add_note(detail)
                for cleanup_error in cleanup_errors:
                    primary_error.add_note(
                        f"publication cleanup error: {type(cleanup_error).__name__}"
                    )
            elif published:
                raise _committed_publication_error(
                    label=label,
                    leaf=expected_leaf,
                    digest=digest,
                    detail=detail,
                    cause=cleanup_errors[0],
                    path=transaction_path,
                )
            elif isinstance(cleanup_errors[0], Exception):
                raise PublicationReceiptIOError(detail) from cleanup_errors[0]
            else:
                raise cleanup_errors[0]
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

    payload = canonical_json_bytes(value)
    _require(len(payload) <= maximum, f"{label} exceeds the bounded size")
    expected_digest = hashlib.sha256(payload).hexdigest()
    root, descriptor, parent_descriptor, _created = (
        _open_or_create_private_safe_root(
            safe_root,
            label=f"{label} safe root",
            create=False,
        )
    )
    _require_released_safe_root_parent(
        parent_descriptor,
        opened_descriptors=(descriptor,),
        label=f"{label} safe root",
    )
    digest = expected_digest
    published = False
    publication_attempted = False
    publication_state = _PrivateFilePublicationState()
    primary_error: BaseException | None = None
    try:
        publication_attempted = True
        digest = _write_private_bytes_noreplace_at(
            descriptor,
            expected_leaf,
            payload,
            label=label,
            maximum=maximum,
            publication_state=publication_state,
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
        except PublicationReceiptCommittedError:
            raise
        except BaseException as exc:
            raise _committed_publication_error(
                label=label,
                leaf=expected_leaf,
                digest=digest,
                detail="safe-root identity verification failed",
                cause=exc,
            )
    except PublicationReceiptCommittedError as exc:
        published = True
        primary_error = exc
        raise
    except BaseException as exc:
        primary_error = exc
        if publication_attempted and not publication_state.cleanup_is_safe:
            try:
                _raise_for_private_file_publication_visibility(
                    publication_state,
                    directory_fd=descriptor,
                    destination_leaf=expected_leaf,
                    staging_leaf=f".{expected_leaf}.pending-{os.getpid()}",
                    descriptor=-1,
                    size=len(payload),
                    digest=expected_digest,
                    label=label,
                    interruption=exc,
                    record_visible=None,
                )
            except BaseException as classified_error:
                primary_error = classified_error
                if isinstance(
                    classified_error,
                    PublicationReceiptCommittedError,
                ):
                    published = True
                raise
        raise
    finally:
        cleanup_errors = _close_descriptors_once((descriptor,))
        if cleanup_errors:
            detail = f"cannot close {label} safe root"
            if primary_error is not None:
                primary_error.add_note(detail)
                for cleanup_error in cleanup_errors:
                    primary_error.add_note(
                        f"publication cleanup error: {type(cleanup_error).__name__}"
                    )
            elif published:
                raise _committed_publication_error(
                    label=label,
                    leaf=expected_leaf,
                    digest=digest,
                    detail=detail,
                    cause=cleanup_errors[0],
                )
            elif isinstance(cleanup_errors[0], Exception):
                raise PublicationReceiptIOError(detail) from cleanup_errors[0]
            else:
                raise cleanup_errors[0]
    return root / expected_leaf, digest
