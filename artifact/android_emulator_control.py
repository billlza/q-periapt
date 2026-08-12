#!/usr/bin/env python3
"""Fixed Android emulator executable rules and pure listener parsing."""

from __future__ import annotations

import os
import pathlib
import platform
import stat
import sys
from typing import Literal


class AndroidEmulatorControlError(ValueError):
    """The fixed emulator layout or an owned listener snapshot is invalid."""


EmulatorAbi = Literal["arm64-v8a", "x86_64"]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AndroidEmulatorControlError(message)


def canonical_emulator_abi(value: object) -> EmulatorAbi:
    """Return one of the two ABIs supported by the owned headless lane."""

    if value == "arm64-v8a":
        return "arm64-v8a"
    if value == "x86_64":
        return "x86_64"
    raise AndroidEmulatorControlError(
        "script-owned Android AVDs require arm64-v8a or x86_64"
    )


def _resolve_executable(path: pathlib.Path, label: str) -> pathlib.Path:
    requested = pathlib.Path(path)
    try:
        requested_metadata = requested.lstat()
        resolved = requested.resolve(strict=True)
        resolved_metadata = resolved.lstat()
    except (OSError, RuntimeError) as exc:
        raise AndroidEmulatorControlError(
            f"cannot inspect {label} {requested}: {exc}"
        ) from exc
    _require(
        not stat.S_ISLNK(requested_metadata.st_mode),
        f"{label} must not be a symlink: {requested}",
    )
    _require(
        stat.S_ISREG(requested_metadata.st_mode),
        f"{label} must be a regular file: {requested}",
    )
    _require(
        stat.S_ISREG(resolved_metadata.st_mode)
        and (requested_metadata.st_dev, requested_metadata.st_ino)
        == (resolved_metadata.st_dev, resolved_metadata.st_ino),
        f"{label} changed while its canonical path was resolved",
    )
    _require(os.access(resolved, os.X_OK), f"{label} is not executable: {requested}")
    return resolved


def fixed_headless_backend_path(
    launcher_path: pathlib.Path,
    device_abi: object,
    *,
    host_platform: str | None = None,
    host_machine: str | None = None,
) -> pathlib.Path:
    """Resolve the sole headless QEMU backend allowed by the SDK launcher."""

    launcher = _resolve_executable(
        pathlib.Path(launcher_path), "Android emulator launcher"
    )
    _require(
        launcher.name == "emulator",
        "Android emulator launcher filename differs",
    )
    canonical_abi = canonical_emulator_abi(device_abi)
    selected_platform = sys.platform if host_platform is None else host_platform
    selected_machine = (
        platform.machine() if host_machine is None else host_machine
    ).lower()
    host_directory = {
        ("darwin", "arm64"): "darwin-aarch64",
        ("darwin", "aarch64"): "darwin-aarch64",
        ("darwin", "x86_64"): "darwin-x86_64",
        ("linux", "arm64"): "linux-aarch64",
        ("linux", "aarch64"): "linux-aarch64",
        ("linux", "x86_64"): "linux-x86_64",
    }.get((selected_platform, selected_machine))
    _require(
        host_directory is not None,
        f"Android emulator host is unsupported: {selected_platform}/{selected_machine}",
    )
    qemu_architecture = {
        "arm64-v8a": "aarch64",
        "x86_64": "x86_64",
    }[canonical_abi]
    if selected_machine in {"arm64", "aarch64"}:
        _require(
            qemu_architecture == "aarch64",
            "an arm64 Android emulator host requires an arm64-v8a AVD",
        )
    else:
        _require(
            qemu_architecture == "x86_64",
            "an x86_64 Android emulator host requires an x86_64 AVD",
        )
    backend = (
        launcher.parent
        / "qemu"
        / host_directory
        / f"qemu-system-{qemu_architecture}-headless"
    )
    resolved_backend = _resolve_executable(
        backend, "Android emulator headless backend"
    )
    try:
        resolved_backend.relative_to(launcher.parent)
    except ValueError as exc:
        raise AndroidEmulatorControlError(
            "Android emulator backend escapes the selected emulator installation"
        ) from exc
    return resolved_backend


def _canonical_decimal(value: str, label: str) -> int:
    _require(
        value.isascii()
        and value.isdigit()
        and len(value) <= 20
        and str(int(value)) == value,
        f"malformed emulator listener {label}: {value!r}",
    )
    return int(value)


def parse_owned_single_listener(
    text: str,
    *,
    expected_pid: int,
    expected_uid: int,
    expected_endpoint: str,
) -> int:
    """Parse one exact owned single-endpoint ``lsof -Fpun`` listener."""

    _require(type(text) is str, "owned single listener inspection is not text")
    _require(
        type(expected_pid) is int and expected_pid > 1,
        "owned single listener pid is invalid",
    )
    _require(
        type(expected_uid) is int and expected_uid >= 0,
        "owned single listener uid is invalid",
    )
    _require(
        type(expected_endpoint) is str
        and 1 <= len(expected_endpoint) <= 4096
        and expected_endpoint.isascii()
        and all(character not in expected_endpoint for character in "\x00\r\n"),
        "owned single listener endpoint is invalid",
    )
    observed_pid: int | None = None
    observed_uid: int | None = None
    observed_fd: int | None = None
    observed_endpoint: str | None = None
    for line in text.splitlines():
        _require(bool(line), "empty field in owned single listener inspection")
        prefix, value = line[0], line[1:]
        if prefix == "p":
            _require(
                observed_pid is None
                and observed_uid is None
                and observed_fd is None,
                f"malformed owned single listener pid: {value!r}",
            )
            observed_pid = _canonical_decimal(value, "pid")
        elif prefix == "u":
            _require(
                observed_pid is not None
                and observed_uid is None
                and observed_fd is None,
                f"malformed owned single listener uid: {value!r}",
            )
            observed_uid = _canonical_decimal(value, "uid")
        elif prefix == "f":
            _require(
                observed_pid is not None
                and observed_uid is not None
                and observed_fd is None,
                f"malformed owned single listener descriptor: {value!r}",
            )
            observed_fd = _canonical_decimal(value, "descriptor")
        elif prefix == "n":
            _require(
                observed_fd is not None
                and observed_endpoint is None
                and bool(value),
                f"malformed owned single listener endpoint: {value!r}",
            )
            observed_endpoint = value
        else:
            raise AndroidEmulatorControlError(
                f"unexpected owned single listener field: {line!r}"
            )
    _require(
        observed_pid == expected_pid,
        "owned listener differs from the owned child pid",
    )
    _require(
        observed_uid == expected_uid,
        "owned listener is not owned by the expected account",
    )
    _require(observed_fd is not None, "owned listener lacks its descriptor")
    _require(
        observed_endpoint == expected_endpoint,
        "owned single listener endpoint differs",
    )
    return observed_uid


def parse_owned_lsof_listeners(
    text: str,
    *,
    expected_pid: int,
    expected_uid: int,
    console_port: int,
    adb_port: int,
) -> int:
    """Parse one exact ``lsof -Fpun`` snapshot without performing I/O."""

    _require(type(text) is str, "owned emulator listener inspection is not text")
    _require(
        type(expected_pid) is int and expected_pid > 1,
        "owned emulator pid is invalid",
    )
    _require(
        type(expected_uid) is int and expected_uid >= 0,
        "owned emulator uid is invalid",
    )
    _require(
        type(console_port) is int
        and type(adb_port) is int
        and 5554 <= console_port <= 5584
        and console_port % 2 == 0
        and adb_port == console_port + 1,
        "owned emulator ports are invalid",
    )

    observed_pid: int | None = None
    observed_uid: int | None = None
    endpoints: set[str] = set()
    descriptors: set[int] = set()
    current_fd: int | None = None
    fd_has_endpoint = False
    for line in text.splitlines():
        _require(bool(line), "empty field in emulator listener inspection")
        prefix, value = line[0], line[1:]
        if prefix == "p":
            _require(
                observed_pid is None
                and observed_uid is None
                and current_fd is None,
                f"malformed emulator listener pid: {value!r}",
            )
            observed_pid = _canonical_decimal(value, "pid")
        elif prefix == "u":
            _require(
                observed_pid is not None
                and observed_uid is None
                and current_fd is None,
                f"malformed emulator listener uid: {value!r}",
            )
            observed_uid = _canonical_decimal(value, "uid")
        elif prefix == "f":
            _require(
                observed_pid is not None
                and observed_uid is not None
                and (current_fd is None or fd_has_endpoint),
                f"malformed emulator listener descriptor: {value!r}",
            )
            current_fd = _canonical_decimal(value, "descriptor")
            _require(
                current_fd not in descriptors,
                f"duplicate emulator listener descriptor: {value!r}",
            )
            descriptors.add(current_fd)
            fd_has_endpoint = False
        elif prefix == "n":
            _require(
                observed_pid is not None
                and observed_uid is not None
                and current_fd is not None
                and not fd_has_endpoint
                and bool(value)
                and value not in endpoints,
                f"malformed emulator listener endpoint: {value!r}",
            )
            endpoints.add(value)
            fd_has_endpoint = True
        else:
            raise AndroidEmulatorControlError(
                f"unexpected emulator listener field: {line!r}"
            )

    _require(
        current_fd is None or fd_has_endpoint,
        "emulator listener descriptor lacks an endpoint",
    )
    _require(
        len(descriptors) == 2,
        "emulator listener inspection must contain two descriptors",
    )
    _require(
        observed_pid == expected_pid,
        "emulator listeners differ from the owned child pid",
    )
    _require(
        observed_uid == expected_uid,
        "emulator listeners are not owned by the expected account",
    )
    expected_endpoints = {
        f"127.0.0.1:{console_port}",
        f"127.0.0.1:{adb_port}",
    }
    _require(
        endpoints == expected_endpoints,
        "owned emulator listener endpoints differ",
    )
    return observed_uid
