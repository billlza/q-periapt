#!/usr/bin/env python3
"""Fail-closed byte snapshots and strict JSON parsing for evidence files."""

from __future__ import annotations

import hashlib
import json
import math
import os
import pathlib
import stat
import sys
from dataclasses import dataclass
from typing import Any, NoReturn


DEFAULT_JSON_MAX_BYTES = 16 * 1024 * 1024


class EvidenceIOError(ValueError):
    """An evidence file cannot be read as one stable, strict snapshot."""


@dataclass(frozen=True, slots=True)
class FileSnapshot:
    """The exact bytes and digest read from one open regular-file description."""

    path: pathlib.Path
    data: bytes
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class JsonObjectSnapshot:
    """A strict JSON object parsed from the same bytes used for its digest."""

    file: FileSnapshot
    value: dict[str, Any]


def _open_regular_no_symlinks(path: pathlib.Path) -> int:
    """Open every path component with O_NOFOLLOW and return the final descriptor."""

    if os.open not in os.supports_dir_fd:
        raise EvidenceIOError("this platform lacks dir_fd-safe evidence opening")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise EvidenceIOError("this platform lacks no-follow evidence opening")

    lexical = pathlib.Path(path)
    if ".." in lexical.parts:
        raise EvidenceIOError(f"evidence path must not contain '..': {path}")
    absolute = pathlib.Path(os.path.abspath(lexical))
    # macOS exposes three fixed root aliases.  Permit only these operating-system
    # aliases; every caller-controlled component is still walked with O_NOFOLLOW.
    if sys.platform == "darwin" and len(absolute.parts) >= 2:
        alias = absolute.parts[1]
        expected = {"etc": "private/etc", "tmp": "private/tmp", "var": "private/var"}.get(alias)
        if expected is not None:
            alias_path = pathlib.Path(absolute.anchor) / alias
            try:
                target = os.readlink(alias_path)
            except OSError:
                target = ""
            if target.lstrip("/") == expected:
                absolute = pathlib.Path("/private") / alias / pathlib.Path(*absolute.parts[2:])
    parts = absolute.parts
    if not parts or parts[0] != absolute.anchor or len(parts) < 2:
        raise EvidenceIOError(f"evidence path must name a file: {path}")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    file_flags = (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    directory_fd = os.open(absolute.anchor, directory_flags)
    try:
        for component in parts[1:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        return os.open(parts[-1], file_flags, dir_fd=directory_fd)
    except OSError as exc:
        raise EvidenceIOError(f"cannot safely open evidence file {path}: {exc}") from exc
    finally:
        os.close(directory_fd)


def read_regular_snapshot(
    path: pathlib.Path,
    *,
    maximum: int,
    label: str,
) -> FileSnapshot:
    """Read one bounded regular file and hash exactly the bytes returned."""

    if type(maximum) is not int or maximum <= 0:
        raise EvidenceIOError(f"{label} maximum must be a positive integer")
    descriptor = _open_regular_no_symlinks(path)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise EvidenceIOError(f"{label} is not a regular file: {path}")
        if before.st_size > maximum:
            raise EvidenceIOError(f"{label} exceeds {maximum} bytes: {path}")

        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > maximum:
            raise EvidenceIOError(f"{label} exceeds {maximum} bytes: {path}")

        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after or len(data) != before.st_size:
            raise EvidenceIOError(f"{label} changed while it was read: {path}")

        return FileSnapshot(
            path=pathlib.Path(os.path.abspath(path)),
            data=data,
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
        )
    except OSError as exc:
        raise EvidenceIOError(f"cannot read {label} {path}: {exc}") from exc
    finally:
        os.close(descriptor)


def parse_strict_json_bytes(data: bytes, *, label: str) -> Any:
    """Parse RFC JSON while rejecting duplicate keys and non-finite constants."""

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise EvidenceIOError(f"{label} contains duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> NoReturn:
        raise EvidenceIOError(f"{label} contains non-finite JSON number: {value}")

    def parse_finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise EvidenceIOError(f"{label} contains non-finite JSON number: {value}")
        return parsed

    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
            parse_float=parse_finite_float,
        )
    except EvidenceIOError:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise EvidenceIOError(f"{label} is not strict UTF-8 JSON: {exc}") from exc


def load_json_object_snapshot(
    path: pathlib.Path,
    *,
    maximum: int = DEFAULT_JSON_MAX_BYTES,
    label: str,
) -> JsonObjectSnapshot:
    """Read, hash, and parse one JSON object without reopening its path."""

    file_snapshot = read_regular_snapshot(path, maximum=maximum, label=label)
    value = parse_strict_json_bytes(file_snapshot.data, label=label)
    if not isinstance(value, dict):
        raise EvidenceIOError(f"{label} root must be a JSON object")
    return JsonObjectSnapshot(file=file_snapshot, value=value)
