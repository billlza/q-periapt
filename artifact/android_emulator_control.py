#!/usr/bin/env python3
"""Fixed Android emulator rules, listener parsing, and bounded loopback probes."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import pathlib
import platform
import re
import socket
import stat
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Literal

from evidence_io import EvidenceIOError, parse_strict_json_bytes


class AndroidEmulatorControlError(ValueError):
    """The fixed emulator layout or an owned listener snapshot is invalid."""


EmulatorAbi = Literal["arm64-v8a", "x86_64"]

DEFAULT_ADB_SERVER_PORT = 5037
NATIVE_ADB_NOTIFIER_PORT = 5586
NATIVE_ADB_NOTIFIER_MODE = "closed_loopback"
ADB_ISOLATION_RECEIPT_SCHEMA_VERSION = 1
ADB_ISOLATION_RECEIPT_KIND = "qperiapt.android_adb_loopback_absence"
EMULATOR_ROUTING_RECEIPT_SCHEMA_VERSION = 1
EMULATOR_ROUTING_RECEIPT_KIND = "qperiapt.android_emulator_routing"
EMULATOR_ROUTING_RECEIPT_LEAF = "emulator-routing.json"
EMULATOR_ROUTING_MODE = "private_unix_external_adb_closed_native_notifier"
EMULATOR_ROUTING_PRIVATE_ADB_FIELDS = frozenset(
    {
        "identity_sha256",
        "server_status_sha256",
        "listener_snapshot_sha256",
    }
)
EMULATOR_ROUTING_ENVIRONMENT_FIELDS = frozenset(
    {
        "HOME",
        "PATH",
        "TMPDIR",
        "LC_ALL",
        "LANG",
        "ANDROID_HOME",
        "ANDROID_SDK_ROOT",
        "ANDROID_AVD_HOME",
        "ADB_SERVER_SOCKET",
        "ADB_VENDOR_KEYS",
        "ADB_MDNS",
        "ADB_MDNS_AUTO_CONNECT",
        "ADB_LOCAL_TRANSPORT_MAX_PORT",
        "ADB_USB",
        "ADB_EMU",
        "ANDROID_ADB_SERVER_PORT",
    }
)

_SHA256 = re.compile(r"[0-9a-f]{64}")
_RUN_ID = re.compile(r"[0-9a-f]{32}")


class AdbIsolationCheckpoint(str, Enum):
    EMULATOR_PRE_EXEC = "emulator_pre_exec"
    EMULATOR_POST_REGISTRATION = "emulator_post_registration"
    RUNTIME_PRE_CLEANUP = "runtime_pre_cleanup"
    RUNTIME_POST_CLEANUP = "runtime_post_cleanup"


ADB_ISOLATION_CHECKPOINT_LEAVES = MappingProxyType(
    {
        AdbIsolationCheckpoint.EMULATOR_PRE_EXEC: "adb-isolation-emulator-pre-exec.json",
        AdbIsolationCheckpoint.EMULATOR_POST_REGISTRATION: "adb-isolation-emulator-post-registration.json",
        AdbIsolationCheckpoint.RUNTIME_PRE_CLEANUP: "adb-isolation-runtime-pre-cleanup.json",
        AdbIsolationCheckpoint.RUNTIME_POST_CLEANUP: "adb-isolation-runtime-post-cleanup.json",
    }
)


@dataclass(frozen=True, slots=True)
class AdbIsolationObservation:
    """One bounded fixed-order sequence observing both ports on v4 and v6."""

    default_ipv4: Literal["connection_refused"] = "connection_refused"
    default_ipv6: Literal["connection_refused"] = "connection_refused"
    notifier_ipv4: Literal["connection_refused"] = "connection_refused"
    notifier_ipv6: Literal["connection_refused"] = "connection_refused"

    def ports_payload(self) -> dict[str, dict[str, str]]:
        return {
            str(DEFAULT_ADB_SERVER_PORT): {
                "ipv4": self.default_ipv4,
                "ipv6": self.default_ipv6,
            },
            str(NATIVE_ADB_NOTIFIER_PORT): {
                "ipv4": self.notifier_ipv4,
                "ipv6": self.notifier_ipv6,
            },
        }


def emulator_routing_transport_binding_sha256(
    adb_snapshot_sha256: str,
    routing_environment_sha256: str,
    private_adb: Mapping[str, str],
) -> str:
    """Commit the exact external-adb routing projection used by proof parsing."""

    _require(
        _SHA256.fullmatch(adb_snapshot_sha256) is not None,
        "emulator routing adb snapshot digest is invalid",
    )
    _require(
        _SHA256.fullmatch(routing_environment_sha256) is not None,
        "emulator routing environment digest is invalid",
    )
    _require(
        isinstance(private_adb, Mapping)
        and set(private_adb) == EMULATOR_ROUTING_PRIVATE_ADB_FIELDS,
        "emulator routing private adb fields changed",
    )
    for name in EMULATOR_ROUTING_PRIVATE_ADB_FIELDS:
        _require(
            type(private_adb[name]) is str
            and _SHA256.fullmatch(private_adb[name]) is not None,
            f"emulator routing private adb digest is invalid: {name}",
        )
    payload = {
        "mode": EMULATOR_ROUTING_MODE,
        "adb_snapshot_sha256": adb_snapshot_sha256,
        "routing_environment_sha256": routing_environment_sha256,
        "native_notifier_port": NATIVE_ADB_NOTIFIER_PORT,
        "private_adb": dict(private_adb),
    }
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def emulator_routing_environment_sha256(environment: Mapping[str, str]) -> str:
    """Hash the exact, finite emulator routing environment projection."""

    _require(
        isinstance(environment, Mapping)
        and set(environment) == EMULATOR_ROUTING_ENVIRONMENT_FIELDS,
        "emulator routing environment fields changed",
    )
    canonical: dict[str, str] = {}
    for name in sorted(EMULATOR_ROUTING_ENVIRONMENT_FIELDS):
        value = environment[name]
        _require(
            type(value) is str
            and value
            and "\0" not in value
            and "\r" not in value
            and "\n" not in value,
            f"emulator routing environment value is invalid: {name}",
        )
        canonical[name] = value
    encoded = (json.dumps(canonical, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def parse_emulator_routing_receipt(
    payload: object,
    *,
    run_id: str,
) -> Mapping[str, object]:
    """Validate the exact canonical routing receipt object shared by runtime/proof."""

    fields = {
        "schema",
        "kind",
        "run_id",
        "mode",
        "adb_snapshot_sha256",
        "routing_environment_sha256",
        "transport_binding_sha256",
        "private_adb",
        "native_notifier_port",
        "private_socket_kind",
        "raw_paths_recorded",
    }
    _require(
        type(payload) is dict and set(payload) == fields,
        "emulator routing receipt fields changed",
    )
    _require(
        type(run_id) is str and _RUN_ID.fullmatch(run_id) is not None,
        "emulator routing run id is invalid",
    )
    _require(
        type(payload["schema"]) is int
        and payload["schema"] == EMULATOR_ROUTING_RECEIPT_SCHEMA_VERSION
        and payload["kind"] == EMULATOR_ROUTING_RECEIPT_KIND
        and payload["run_id"] == run_id
        and payload["mode"] == EMULATOR_ROUTING_MODE
        and type(payload["native_notifier_port"]) is int
        and payload["native_notifier_port"] == NATIVE_ADB_NOTIFIER_PORT
        and payload["private_socket_kind"] == "localfilesystem"
        and payload["raw_paths_recorded"] is False,
        "emulator routing receipt contract differs",
    )
    adb_snapshot_sha256 = payload["adb_snapshot_sha256"]
    routing_environment_sha256 = payload["routing_environment_sha256"]
    transport_binding_sha256 = payload["transport_binding_sha256"]
    private_adb = payload["private_adb"]
    _require(
        type(adb_snapshot_sha256) is str
        and _SHA256.fullmatch(adb_snapshot_sha256) is not None
        and type(routing_environment_sha256) is str
        and _SHA256.fullmatch(routing_environment_sha256) is not None
        and type(transport_binding_sha256) is str
        and _SHA256.fullmatch(transport_binding_sha256) is not None
        and type(private_adb) is dict,
        "emulator routing receipt digest shape differs",
    )
    expected_transport_binding = emulator_routing_transport_binding_sha256(
        adb_snapshot_sha256,
        routing_environment_sha256,
        private_adb,
    )
    _require(
        transport_binding_sha256 == expected_transport_binding,
        "emulator routing transport binding differs",
    )
    return MappingProxyType(dict(payload))


def _strict_json_value(raw: str, *, label: str) -> object:
    try:
        return parse_strict_json_bytes(raw.encode("utf-8"), label=label)
    except (EvidenceIOError, UnicodeError) as exc:
        raise AndroidEmulatorControlError(f"malformed {label} JSON value") from exc


def parse_owned_adb_server_status(text: str) -> Mapping[str, object]:
    """Parse bounded adb server-status text without accepting duplicate fields."""

    _require(
        type(text) is str and 1 <= len(text.encode("utf-8")) <= 65536,
        "adb server-status output is outside its fixed bound",
    )
    fields: dict[str, object] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([a-z][a-z0-9_]*): (.+)", line)
        _require(match is not None, f"malformed adb server-status line: {line!r}")
        key, raw_value = match.groups()
        _require(key not in fields, f"duplicate adb server-status field: {key}")
        if re.fullmatch(r"[A-Z][A-Z0-9_]*", raw_value) is not None:
            fields[key] = raw_value
        else:
            fields[key] = _strict_json_value(
                raw_value,
                label=f"adb server-status {key}",
            )
    required = {"executable_absolute_path", "keystore_path", "mdns_enabled"}
    _require(
        required <= fields.keys(),
        "adb server-status omits required fields: "
        + ", ".join(sorted(required - fields.keys())),
    )
    return MappingProxyType(fields)


def probe_adb_loopback_absence() -> AdbIsolationObservation:
    """Require exact connection refusal on both fixed ports and IP families."""

    endpoints = (
        (socket.AF_INET, ("127.0.0.1", DEFAULT_ADB_SERVER_PORT), "IPv4 adb server"),
        (
            socket.AF_INET6,
            ("::1", DEFAULT_ADB_SERVER_PORT, 0, 0),
            "IPv6 adb server",
        ),
        (
            socket.AF_INET,
            ("127.0.0.1", NATIVE_ADB_NOTIFIER_PORT),
            "IPv4 native adb notifier",
        ),
        (
            socket.AF_INET6,
            ("::1", NATIVE_ADB_NOTIFIER_PORT, 0, 0),
            "IPv6 native adb notifier",
        ),
    )
    for family, address, label in endpoints:
        try:
            probe = socket.socket(family, socket.SOCK_STREAM)
        except OSError as exc:
            raise AndroidEmulatorControlError(
                f"cannot create the {label} absence probe: {exc}"
            ) from exc
        try:
            probe.settimeout(1.0)
            try:
                result = probe.connect_ex(address)
            except OSError as exc:
                raise AndroidEmulatorControlError(
                    f"cannot inspect the {label} endpoint: {exc}"
                ) from exc
        finally:
            probe.close()
        _require(
            result == errno.ECONNREFUSED,
            f"{label} endpoint did not refuse its loopback connection (errno={result})",
        )
    return AdbIsolationObservation()


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
