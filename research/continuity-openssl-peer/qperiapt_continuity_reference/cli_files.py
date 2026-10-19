"""Bounded local CLI input and explicit no-overwrite public exports."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import base64
import os
import stat


def read_file(path, maximum, *, private=False, allow_empty=False):
    from .private_files import open_directory, private_regular
    from .wire import require
    require(path.is_absolute() and '..' not in path.parts, 'absolute input path required')
    parent = open_directory(path.parent) if private else None
    fd = None
    try:
        fd = os.open(path.name if private else path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=parent)
        before = os.fstat(fd)
        if private: private_regular(before)
        require(stat.S_ISREG(before.st_mode) and (0 if allow_empty else 1) <= before.st_size <= maximum, 'input type or size')
        value = bytearray()
        while len(value) < before.st_size:
            part = os.read(fd, before.st_size - len(value))
            require(bool(part), 'input truncated'); value.extend(part)
        require(not os.read(fd, 1), 'input grew')
        after = os.fstat(fd)
        require((before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'input changed')
        return bytes(value)
    finally:
        if fd is not None: os.close(fd)
        if parent is not None: os.close(parent)


def export_request(path, value):
    from .private_files import open_directory, sync_file
    from .wire import require
    parent = open_directory(path.parent)
    fd = None
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        remaining = memoryview(value)
        while remaining:
            count = os.write(fd, remaining); require(count > 0, 'request export zero-length write')
            remaining = remaining[count:]
        sync_file(fd); os.fsync(parent); sync_file(fd)
    finally:
        if fd is not None: os.close(fd)
        os.close(parent)


def public(value):
    if type(value) is bytes: return base64.urlsafe_b64encode(value).rstrip(b'=').decode()
    raise TypeError('unsupported public result')
