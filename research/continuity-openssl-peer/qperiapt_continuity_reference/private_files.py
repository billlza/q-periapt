"""Private POSIX directory lease and bounded, staged durable file publication."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from __future__ import annotations

import fcntl
import os
from pathlib import Path
import stat
import sys

from .wire import require
from .storage_budget import MAX_STATE, MAX_POLICY_STATE

MAX_FILE = MAX_STATE + 4096
MAX_DIRECTORY_BYTES = 64 * 1024 * 1024


class DirectoryBusy(BlockingIOError):
    """The existing directory lease is held; no content was read or changed."""


def open_directory(path: Path) -> int:
    require(path.is_absolute() and ".." not in path.parts, "absolute canonical directory required")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        value = os.fstat(fd)
        require(value.st_uid == os.getuid() and stat.S_IMODE(value.st_mode) == 0o700,
                "store directory must be owned and mode 0700")
        return fd
    except BaseException:
        os.close(fd)
        raise


def private_regular(value: os.stat_result) -> None:
    require(stat.S_ISREG(value.st_mode) and value.st_uid == os.getuid()
            and stat.S_IMODE(value.st_mode) == 0o600 and value.st_nlink == 1,
            "store file must be private, regular and singly linked")


def sync_file(fd: int) -> None:
    os.fsync(fd)
    if sys.platform == "darwin":
        # No weaker fallback if the requested Apple barrier is unavailable.
        fcntl.fcntl(fd, fcntl.F_FULLFSYNC)


class PrivateDirectory:
    def __init__(self, path: Path, observer=None, *, max_file=MAX_FILE):
        require(sys.platform in ("darwin", "linux"), "independent store requires POSIX")
        require(type(max_file) is int and MAX_FILE <= max_file <= MAX_POLICY_STATE + 4096,
                "private file bound")
        self.max_file = max_file
        self.path, self.observer = path, observer
        self.fd = open_directory(path)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            self.close()
            raise DirectoryBusy(*error.args) from error
        except BaseException:
            self.close()
            raise

    def check(self) -> None:
        require(self.fd is not None, "closed store directory")
        fresh = open_directory(self.path)
        try:
            current, original = os.fstat(fresh), os.fstat(self.fd)
            require((current.st_dev, current.st_ino) == (original.st_dev, original.st_ino),
                    "store directory replaced")
        finally:
            os.close(fresh)

    def observe(self, stage: str) -> None:
        if self.observer is not None:
            self.observer(stage)
        # Do not let reentrant close turn dir_fd=None into an implicit cwd path.
        require(self.fd is not None, "closed store directory")

    def read(self, name: str) -> bytes | None:
        require(name in ("head", "intent", "authority"), "unknown formal record")
        return self._read(name)

    def read_initial_intent(self) -> bytes | None:
        # One reserved original-creation slot, never a directory/orphan search.
        return self._read(".stage-initial-intent")

    def _read(self, name: str) -> bytes | None:
        require(self.fd is not None, "closed store directory")
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        except FileNotFoundError:
            return None
        try:
            before = os.fstat(fd)
            private_regular(before)
            require(0 < before.st_size <= self.max_file, "store file capacity")
            result = bytearray()
            while len(result) < before.st_size:
                part = os.read(fd, min(65536, before.st_size - len(result)))
                require(bool(part), "truncated store file")
                result.extend(part)
            require(not os.read(fd, 1), "store file grew while reading")
            after = os.fstat(fd)
            current = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            private_regular(after)
            require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                    == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                    and (current.st_dev, current.st_ino) == (after.st_dev, after.st_ino),
                    "store file changed while reading")
            return bytes(result)
        finally:
            os.close(fd)

    def quota(self, incoming: int, files: int = 1) -> None:
        require(self.fd is not None, "closed store directory")
        total, count = 0, 0
        with os.scandir(self.fd) as entries:
            for entry in entries:
                count += 1
                require(count + files <= 128, "store file count capacity")
                require(entry.name in ("head", "intent", "authority") or entry.name.startswith(".stage-"),
                        "unknown store file")
                value = entry.stat(follow_symlinks=False)
                private_regular(value)
                total += value.st_size
                require(total + incoming <= MAX_DIRECTORY_BYTES, "store disk capacity")

    def publish(self, name: str, value: bytes, *, fixed_slot: str | None = None) -> None:
        require(name in ("head", "intent", "authority") and 0 < len(value) <= self.max_file, "publication shape")
        if name == "head":
            require(fixed_slot is None, "head publication owns its reserved slot")
            self._publish_fixed(name, ".stage-head", value)
            return
        if fixed_slot is not None:
            require((name == "authority" and fixed_slot in (tuple("authority-" + str(i) for i in range(6))
                    + tuple("authority-r-" + str(i) for i in range(1, 6))))
                    or (name == "intent" and fixed_slot == "initial-intent"),
                    "unknown reserved publication slot")
            self._publish_fixed(name, ".stage-" + fixed_slot, value)
            return
        self.check()
        self.quota(len(value))
        temporary = ".stage-" + os.urandom(16).hex()
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.fd)
        try:
            remaining = memoryview(value)
            while remaining:
                count = os.write(fd, remaining)
                require(count > 0, "zero-length store write")
                remaining = remaining[count:]
            sync_file(fd)
            self.observe("stage-synced:" + name)
            # The lifetime directory lease and authenticated prior comparison
            # serialize writers. Hostile same-UID mutation is outside this lane.
            os.replace(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            self.observe("published:" + name)
            os.fsync(self.fd)
            sync_file(fd)
            self.observe("committed:" + name)
        finally:
            os.close(fd)

    def _publish_fixed(self, name: str, temporary: str, value: bytes) -> None:
        # The caller supplies the complete authenticated intent target. This
        # reserved output slot never supplies state or authority on its own.
        # Repeated interrupted recovery must not allocate another orphan each
        # time and exhaust the very quota reserved by the original commit.
        self.check()
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            fd = os.open(temporary, flags, dir_fd=self.fd)
        except FileNotFoundError:
            self.quota(len(value))
            fd = os.open(temporary, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=self.fd)
        try:
            before = os.fstat(fd)
            private_regular(before)
            require(before.st_size <= len(value), "staged head exceeds original target")
            self.quota(len(value) - before.st_size, 0)
            offset = 0
            while offset < before.st_size:
                part = os.read(fd, min(65536, before.st_size - offset))
                require(bool(part) and part == value[offset:offset + len(part)],
                        "staged head differs from original target")
                offset += len(part)
            require(not os.read(fd, 1), "staged head grew during recovery")
            remaining = memoryview(value)[offset:]
            while remaining:
                count = os.write(fd, remaining)
                require(count > 0, "zero-length staged head write")
                remaining = remaining[count:]
            sync_file(fd)
            self.observe("stage-synced:" + name)
            current = os.stat(temporary, dir_fd=self.fd, follow_symlinks=False)
            private_regular(current)
            require((current.st_dev, current.st_ino) == (before.st_dev, before.st_ino),
                    "staged head replaced")
            os.replace(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            self.observe("published:" + name)
            os.fsync(self.fd)
            sync_file(fd)
            self.observe("committed:" + name)
        finally:
            os.close(fd)

    def remove_intent(self) -> None:
        self.check()
        os.unlink("intent", dir_fd=self.fd)
        self.observe("removed:intent")
        os.fsync(self.fd)
        # Flush the directory publication before acknowledging the transition.
        fd = os.open("head", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        try:
            private_regular(os.fstat(fd))
            sync_file(fd)
        finally:
            os.close(fd)
        self.observe("committed:removal")

    def close(self) -> None:
        if self.fd is not None:
            fd, self.fd = self.fd, None
            os.close(fd)
