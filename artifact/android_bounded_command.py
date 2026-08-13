#!/usr/bin/env python3
"""Run the Android evidence lane's finite adb/lsof operation set."""

from __future__ import annotations

import argparse
import dataclasses
import enum
import errno
import hashlib
import os
import pathlib
import re
import resource
import signal
import socket
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Literal, NoReturn

import android_runtime_state as runtime_state
from android_emulator_control import (
    EMULATOR_ROUTING_PRIVATE_ADB_FIELDS,
    NATIVE_ADB_NOTIFIER_PORT,
    AdbIsolationCheckpoint,
    AndroidEmulatorControlError,
    OwnedUnixListenerObservation,
    emulator_routing_environment_sha256,
    fixed_headless_backend_path,
    parse_owned_adb_server_status,
    parse_owned_lsof_listeners,
    parse_owned_single_listener,
    probe_adb_loopback_absence,
)
from bounded_process import (
    BoundedProcessError,
    BoundedResult,
    capture_stdout,
    run,
    write_stdout_at,
)
from evidence_io import (
    EvidenceIOError,
    consume_regular_snapshot,
    consume_regular_snapshot_at,
    load_json_object_snapshot,
    load_json_object_snapshot_at,
    read_regular_snapshot,
)
from process_identity import (
    ProcessExecutionSnapshot,
    ProcessIdentity,
    ProcessIdentityError,
    execution_snapshot,
    host_boot_identity,
)
from process_identity import (
    snapshot as process_snapshot,
)

PACKAGE = "dev.qperiapt.androidsmoke"
INSTALLED_APK_COPY_LEAF = "installed-smoke-base.apk"
RESULT_TEXT_REMOTE = "files/qperiapt-android-device-result.txt"
RESULT_JSON_REMOTE = "files/qperiapt-android-device-result.json"
REMOTE_BASE_APK = re.compile("/[A-Za-z0-9_./+=~:-]+/base\\.apk")
DEVICE_EPOCH = re.compile("[1-9][0-9]{9,12}\\.[0-9]{3}")
_REMOTE_PATH_CHARACTERS = frozenset(
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_./+=~:-"
)
_EPOCH_CHARACTERS = frozenset("0123456789.")
EXACT_CLIENT_ENVIRONMENT = MappingProxyType(
    {
        "ADB_MDNS": "0",
        "ADB_MDNS_AUTO_CONNECT": "0",
        "ADB_LOCAL_TRANSPORT_MAX_PORT": "5585",
        "ADB_USB": "0",
        "ADB_EMU": "0",
    }
)
FORBIDDEN_CLIENT_ENVIRONMENT = frozenset(
    {
        "ANDROID_ADB_SERVER_ADDRESS",
        "ANDROID_ADB_SERVER_PORT",
        "ADB_MDNS_OPENSCREEN",
        "ADB_REJECT_KILL_SERVER",
        "ADB_OSX_USB_CLEAR_ENDPOINTS",
        "ANDROID_ADB_LOG_PATH",
        "ADB_TRACE",
        "ADB_INSTALL_DEFAULT_INCREMENTAL",
        "ADB_LIBUSB",
        "ADB_LIBUSB_START_DETACHED",
    }
)
FORBIDDEN_EMULATOR_AVD_SELECTOR_ENVIRONMENT = frozenset(
    {
        "ANDROID_EMULATOR_HOME",
        "ANDROID_PREFS_ROOT",
        "ANDROID_SDK_HOME",
        "ANDROID_USER_HOME",
    }
)
EMULATOR_CONSOLE_AUTHENTICATED_MARKER = (
    b"\nOK\nAndroid Console: type 'help' for a list of commands\nOK\n"
)
EMULATOR_CONSOLE_AUTHENTICATION_BANNER_PREFIX = (
    b"Android Console: Authentication required\n"
    b"Android Console: type 'auth <auth_token>' to authenticate\n"
    b"Android Console: you can find your <auth_token> in \n'"
)
EMULATOR_CONSOLE_AUTH_TOKEN_LEAF = ".emulator_console_auth_token"
EMULATOR_CONSOLE_RESPONSE_TIMEOUT_SECONDS = 5


class AndroidCommandError(RuntimeError):
    """The private Android command capability or requested operation is invalid."""


class InstalledApkRetryReason(str, enum.Enum):
    """Safe shell-facing reasons for an inconclusive installed-APK observation."""

    PACKAGE_UNAVAILABLE = "package-unavailable"
    PULL_FAILED = "pull-failed"
    PATH_CHANGED = "path-changed"
    BYTES_MISMATCH = "bytes-mismatch"
    DEADLINE_EXHAUSTED = "deadline-exhausted"


class PackageState(str, enum.Enum):
    """Safe shell-facing package-state observations."""

    ABSENT = "absent"
    PRESENT = "present"
    QUERY_NONZERO = "retryable:query-nonzero"
    QUERY_TIMEOUT = "retryable:query-timeout"


class AndroidOperation(str, enum.Enum):
    REGISTER_EMULATOR = "register-emulator"
    LIST_DEVICES = "list-devices"
    LSOF_INITIAL = "lsof-initial"
    LSOF_BEFORE = "lsof-before"
    LSOF_REGISTERED = "lsof-registered"
    LSOF_AFTER = "lsof-after"
    SERVER_STATUS_BEFORE = "server-status-before"
    SERVER_STATUS_REGISTERED = "server-status-registered"
    SERVER_STATUS_AFTER = "server-status-after"
    DEVICE_STATE = "device-state"
    BOOT_COMPLETED = "boot-completed"
    QEMU_KIND = "qemu-kind"
    DEVICE_ABI = "device-abi"
    PAGE_SIZE = "page-size"
    DEVICE_SDK = "device-sdk"
    DEVICE_DEVPATH = "device-devpath"
    DEVICE_MANUFACTURER = "device-manufacturer"
    DEVICE_MODEL = "device-model"
    DEVICE_RELEASE = "device-release"
    DEVICE_FINGERPRINT = "device-fingerprint"
    ADB_VERSION = "adb-version"
    PACKAGE_STATE = "package-state"
    OBSERVE_INSTALLED_APK = "observe-installed-apk"
    INSTALL_APK = "install-apk"
    UNINSTALL_APP = "uninstall-app"
    DEVICE_TIME = "device-time"
    FORCE_STOP = "force-stop"
    START_APP = "start-app"
    READ_RESULT_TEXT = "read-result-text"
    READ_RESULT_JSON = "read-result-json"
    CAPTURE_LOGCAT = "capture-logcat"


class OutputRoot(str, enum.Enum):
    WORK = "work"
    PROOF = "proof"


@dataclasses.dataclass(frozen=True, slots=True)
class OutputSpec:
    root: OutputRoot
    leaf: str
    maximum_bytes: int


@dataclasses.dataclass(frozen=True, slots=True)
class OperationSpec:
    mode: Literal[
        "run",
        "capture",
        "write",
        "package-state",
        "observe-apk",
        "logcat",
        "register-emulator",
    ]
    timeout_seconds: int
    timeout_maximum: int
    output: OutputSpec | None
    build_argv: Callable[[runtime_state.AndroidAdbCapability], tuple[str, ...]]
    requires_private_server: bool = True
    stderr_to_stdout: bool = False


@dataclasses.dataclass(frozen=True, slots=True)
class RecoveryContext:
    """Protocol-layer recovery inputs reconstructed from durable state."""

    layout: runtime_state.AndroidRunLayout
    capability: runtime_state.AndroidAdbCapability
    launcher: pathlib.Path | None
    backend: pathlib.Path | None
    current_boot: bool


def _fail(message: str) -> NoReturn:
    raise AndroidCommandError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _close_nonstandard_descriptors(*, preserve_lane_lock: bool = False) -> None:
    """Close every inherited descriptor other than stdin/stdout/stderr."""
    try:
        soft_limit, _hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    except (OSError, ValueError) as exc:
        raise AndroidCommandError(
            f"cannot determine inherited descriptor limit: {exc}"
        ) from exc
    if soft_limit == resource.RLIM_INFINITY:
        soft_limit = 1048576
    _require(
        type(soft_limit) is int and 3 <= soft_limit <= 1048576,
        "inherited descriptor limit is outside the supported bound",
    )
    if preserve_lane_lock:
        _require(
            not os.get_inheritable(runtime_state.LANE_LOCK_FD),
            "preserved Android lane lock is not close-on-exec",
        )
    try:
        if preserve_lane_lock:
            os.closerange(3, runtime_state.LANE_LOCK_FD)
            os.closerange(runtime_state.LANE_LOCK_FD + 1, soft_limit)
        else:
            os.closerange(3, soft_limit)
    except OSError as exc:
        raise AndroidCommandError(
            f"cannot close inherited descriptors before long-lived exec: {exc}"
        ) from exc


def create_capability_with_deferred_signals(
    *,
    adb_profile: str,
    socket_nonce: str,
    device_kind: str,
    expected_serial: str,
    run_id: str,
    signed_apk_size: int,
    signed_apk_sha256: str,
) -> None:
    managed_signals = tuple(
        (
            getattr(signal, name)
            for name in ("SIGHUP", "SIGINT", "SIGTERM")
            if hasattr(signal, name)
        )
    )
    _require(
        bool(managed_signals) and hasattr(signal, "pthread_sigmask"),
        "Android capability signal handoff requires POSIX signal masks",
    )
    received_signal = 0
    original_handlers: dict[signal.Signals, object] = {}

    def record_signal(signum: int, _frame: object) -> None:
        nonlocal received_signal
        if received_signal == 0:
            received_signal = signum

    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, managed_signals)
    setup_primary: BaseException | None = None
    installed_signals: list[signal.Signals] = []
    try:
        for managed_signal in managed_signals:
            original_handlers[managed_signal] = signal.getsignal(managed_signal)
            signal.signal(managed_signal, record_signal)
            installed_signals.append(managed_signal)
    except BaseException as exc:
        setup_primary = exc
        for installed_signal in reversed(installed_signals):
            try:
                signal.signal(installed_signal, original_handlers[installed_signal])
            except BaseException as cleanup_error:
                setup_primary.add_note(
                    f"restoring a partially installed signal handler also failed: {cleanup_error}"
                )
        raise
    finally:
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        except BaseException as cleanup_error:
            if setup_primary is not None:
                setup_primary.add_note(
                    f"restoring the signal mask after handler setup also failed: {cleanup_error}"
                )
            else:
                raise
    capability_created = False
    capability_cleanup_attempted = False
    create_primary: BaseException | None = None
    try:
        runtime_state.create_capability(
            adb_profile=adb_profile,
            socket_nonce=socket_nonce,
            device_kind=device_kind,
            expected_serial=expected_serial,
            run_id=run_id,
            signed_apk_size=signed_apk_size,
            signed_apk_sha256=signed_apk_sha256,
        )
        capability_created = True
    except BaseException as exc:
        create_primary = exc
        raise
    finally:
        handoff_errors: list[BaseException] = []

        def remove_interrupted_capability() -> None:
            nonlocal capability_cleanup_attempted
            if (
                capability_created
                and received_signal != 0
                and (not capability_cleanup_attempted)
            ):
                capability_cleanup_attempted = True
                runtime_state.destroy_capability(
                    run_id=runtime_state.canonical_run_id(run_id), missing_ok=True
                )

        try:
            remove_interrupted_capability()
        except BaseException as cleanup_error:
            handoff_errors.append(cleanup_error)
        for managed_signal, original_handler in original_handlers.items():
            try:
                signal.signal(managed_signal, original_handler)
            except BaseException as restore_error:
                handoff_errors.append(restore_error)
            try:
                remove_interrupted_capability()
            except BaseException as cleanup_error:
                handoff_errors.append(cleanup_error)
        if handoff_errors:
            if create_primary is not None:
                for handoff_error in handoff_errors:
                    create_primary.add_note(
                        f"Android capability signal handoff also failed: {handoff_error}"
                    )
            else:
                handoff_primary = handoff_errors[0]
                for handoff_error in handoff_errors[1:]:
                    handoff_primary.add_note(
                        f"an additional Android capability handoff step failed: {handoff_error}"
                    )
                raise handoff_primary
    if received_signal != 0:
        raise SystemExit(128 + received_signal)


def _lsof_path() -> str:
    for candidate in (pathlib.Path("/usr/sbin/lsof"), pathlib.Path("/usr/bin/lsof")):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    _fail("fixed-system lsof is unavailable")


def capture_owned_emulator_listeners(
    *, run_id: str, timeout_seconds: int
) -> str:
    """Capture the receipt-owned emulator's listeners and return its identity."""
    runtime_state.validate_lane_lock_descriptor()
    layout = runtime_state.AndroidRunLayout.from_run_id(run_id)
    receipt = runtime_state.load_owned_runtime_receipt()
    _require(
        receipt is not None
        and receipt.run_id == layout.run_id
        and receipt.phase is runtime_state.RuntimePhase.EMULATOR_CHILD_REGISTERED
        and receipt.pid is not None
        and receipt.process_identity is not None,
        "emulator listener capture lacks this run's registered child receipt",
    )
    context = _validate_recovery_receipt(receipt)
    _require(
        context.layout == layout,
        "emulator listener receipt belongs to a different repository run",
    )
    capability = context.capability
    _validate_client_environment(capability)
    before = _same_receipt_process(receipt)
    _require(
        before is not None
        and context.backend is not None
        and before.executable == context.backend,
        "owned emulator is not its receipt-bound live backend",
    )
    result = _capture_owned_emulator_listeners(
        layout=layout,
        capability=capability,
        emulator_pid=receipt.pid,
        timeout_seconds=timeout_seconds,
    )
    current = runtime_state.load_owned_runtime_receipt()
    _require(
        current is not None and current.snapshot_sha256 == receipt.snapshot_sha256,
        "owned emulator receipt changed during listener capture",
    )
    confirmed_context = _validate_recovery_receipt(current)
    _require(
        confirmed_context.layout == layout
        and confirmed_context.backend == context.backend,
        "owned emulator backend changed during listener capture",
    )
    after = _same_receipt_process(current)
    _require(
        after is not None
        and after.token == before.token
        and after.executable == before.executable,
        "owned emulator identity changed during listener capture",
    )
    _require(result.returncode == 0, "owned emulator listener inspection failed")
    return after.token


def _capture_owned_emulator_listeners(
    *,
    layout: runtime_state.AndroidRunLayout,
    capability: runtime_state.AndroidAdbCapability,
    emulator_pid: int,
    timeout_seconds: int,
) -> BoundedResult:
    _require(
        type(emulator_pid) is int and emulator_pid > 1, "owned emulator pid is invalid"
    )
    _require(
        type(timeout_seconds) is int and 1 <= timeout_seconds <= 5,
        "owned emulator listener timeout must be 1 through 5 seconds",
    )
    console_port, adb_port = _owned_emulator_ports(capability)
    directory_fd = runtime_state.open_private_directory(layout.work, "Android work")
    primary: BaseException | None = None
    try:
        result = write_stdout_at(
            (
                _lsof_path(),
                "-nP",
                "-a",
                "-p",
                str(emulator_pid),
                f"-iTCP:{console_port}",
                f"-iTCP:{adb_port}",
                "-sTCP:LISTEN",
                "-Fpufn",
            ),
            output_directory_fd=directory_fd,
            output_name="emulator-listeners.txt.pending",
            timeout_seconds=timeout_seconds,
            maximum_bytes=65536,
            environment={
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "LC_ALL": "C",
                "LANG": "C",
            },
        )
    except BaseException as exc:
        primary = exc
        raise
    finally:
        runtime_state.close_descriptor(
            directory_fd, label="the Android work directory", primary=primary
        )
    return result


def _adb(
    capability: runtime_state.AndroidAdbCapability, *arguments: str
) -> tuple[str, ...]:
    return (
        str(capability.adb_snapshot_path),
        "-L",
        capability.server_socket,
        *arguments,
    )


def _device(
    capability: runtime_state.AndroidAdbCapability, *arguments: str
) -> tuple[str, ...]:
    return _adb(capability, "-s", capability.expected_serial, *arguments)


def _owned_emulator_ports(
    capability: runtime_state.AndroidAdbCapability,
) -> tuple[int, int]:
    _require(
        capability.device_kind == "emulator",
        "emulator registration requires an emulator capability",
    )
    match = re.fullmatch("emulator-([0-9]{4})", capability.expected_serial)
    _require(match is not None, "emulator registration serial is invalid")
    console_port = int(match.group(1))
    _require(
        5554 <= console_port <= 5584 and console_port % 2 == 0,
        "emulator registration port is outside the owned AVD range",
    )
    return (console_port, console_port + 1)


def _emulator_registration_target(
    capability: runtime_state.AndroidAdbCapability,
) -> str:
    console_port, adb_port = _owned_emulator_ports(capability)
    return f"emu:{console_port},{adb_port}"


def _operation_specs() -> Mapping[AndroidOperation, OperationSpec]:
    proof = OutputRoot.PROOF
    work = OutputRoot.WORK
    specs = {
        AndroidOperation.REGISTER_EMULATOR: OperationSpec(
            "register-emulator",
            10,
            10,
            None,
            lambda cap: _adb(cap, "connect", _emulator_registration_target(cap)),
        ),
        AndroidOperation.LIST_DEVICES: OperationSpec(
            "capture", 15, 15, None, lambda cap: _adb(cap, "devices")
        ),
        AndroidOperation.LSOF_INITIAL: OperationSpec(
            "write",
            15,
            15,
            OutputSpec(proof, "adb-listener-initial.txt", 65536),
            lambda cap: (
                _lsof_path(),
                "-nP",
                "-a",
                "-U",
                "-Ts",
                "-FpufnT",
                cap.socket_path,
            ),
            False,
        ),
        AndroidOperation.LSOF_BEFORE: OperationSpec(
            "write",
            15,
            15,
            OutputSpec(proof, "adb-listener-before.txt", 65536),
            lambda cap: (
                _lsof_path(),
                "-nP",
                "-a",
                "-U",
                "-Ts",
                "-FpufnT",
                cap.socket_path,
            ),
            False,
        ),
        AndroidOperation.LSOF_REGISTERED: OperationSpec(
            "write",
            15,
            15,
            OutputSpec(proof, "adb-listener-registered.txt", 65536),
            lambda cap: (
                _lsof_path(),
                "-nP",
                "-a",
                "-U",
                "-Ts",
                "-FpufnT",
                cap.socket_path,
            ),
            False,
        ),
        AndroidOperation.LSOF_AFTER: OperationSpec(
            "write",
            15,
            15,
            OutputSpec(proof, "adb-listener-after.txt", 65536),
            lambda cap: (
                _lsof_path(),
                "-nP",
                "-a",
                "-U",
                "-Ts",
                "-FpufnT",
                cap.socket_path,
            ),
            False,
        ),
        AndroidOperation.SERVER_STATUS_BEFORE: OperationSpec(
            "write",
            15,
            15,
            OutputSpec(proof, "adb-server-status-before.txt", 65536),
            lambda cap: _adb(cap, "server-status"),
        ),
        AndroidOperation.SERVER_STATUS_REGISTERED: OperationSpec(
            "write",
            15,
            15,
            OutputSpec(proof, "adb-server-status-registered.txt", 65536),
            lambda cap: _adb(cap, "server-status"),
        ),
        AndroidOperation.SERVER_STATUS_AFTER: OperationSpec(
            "write",
            15,
            15,
            OutputSpec(proof, "adb-server-status-after.txt", 65536),
            lambda cap: _adb(cap, "server-status"),
        ),
        AndroidOperation.DEVICE_STATE: OperationSpec(
            "capture", 15, 15, None, lambda cap: _device(cap, "get-state")
        ),
        AndroidOperation.BOOT_COMPLETED: OperationSpec(
            "capture",
            15,
            15,
            None,
            lambda cap: _device(cap, "shell", "getprop", "sys.boot_completed"),
        ),
        AndroidOperation.QEMU_KIND: OperationSpec(
            "capture",
            15,
            15,
            None,
            lambda cap: _device(cap, "shell", "getprop", "ro.kernel.qemu"),
        ),
        AndroidOperation.DEVICE_ABI: OperationSpec(
            "capture",
            15,
            15,
            None,
            lambda cap: _device(cap, "shell", "getprop", "ro.product.cpu.abi"),
        ),
        AndroidOperation.PAGE_SIZE: OperationSpec(
            "capture",
            15,
            15,
            None,
            lambda cap: _device(cap, "shell", "getconf", "PAGE_SIZE"),
        ),
        AndroidOperation.DEVICE_SDK: OperationSpec(
            "capture",
            15,
            15,
            None,
            lambda cap: _device(cap, "shell", "getprop", "ro.build.version.sdk"),
        ),
        AndroidOperation.DEVICE_DEVPATH: OperationSpec(
            "write",
            15,
            15,
            OutputSpec(proof, "adb-device-devpath.txt", 4096),
            lambda cap: _device(cap, "get-devpath"),
        ),
        AndroidOperation.DEVICE_MANUFACTURER: OperationSpec(
            "capture",
            15,
            15,
            None,
            lambda cap: _device(cap, "shell", "getprop", "ro.product.manufacturer"),
        ),
        AndroidOperation.DEVICE_MODEL: OperationSpec(
            "capture",
            15,
            15,
            None,
            lambda cap: _device(cap, "shell", "getprop", "ro.product.model"),
        ),
        AndroidOperation.DEVICE_RELEASE: OperationSpec(
            "capture",
            15,
            15,
            None,
            lambda cap: _device(cap, "shell", "getprop", "ro.build.version.release"),
        ),
        AndroidOperation.DEVICE_FINGERPRINT: OperationSpec(
            "capture",
            15,
            15,
            None,
            lambda cap: _device(cap, "shell", "getprop", "ro.build.fingerprint"),
        ),
        AndroidOperation.ADB_VERSION: OperationSpec(
            "capture", 15, 15, None, lambda cap: _adb(cap, "version")
        ),
        AndroidOperation.PACKAGE_STATE: OperationSpec(
            "package-state",
            15,
            15,
            None,
            lambda cap: _device(
                cap, "shell", "cmd", "package", "list", "packages", "-u", PACKAGE
            ),
            requires_private_server=True,
            stderr_to_stdout=True,
        ),
        AndroidOperation.OBSERVE_INSTALLED_APK: OperationSpec(
            "observe-apk",
            45,
            60,
            None,
            lambda cap: (),
        ),
        AndroidOperation.INSTALL_APK: OperationSpec(
            "run",
            120,
            120,
            None,
            lambda cap: _device(
                cap,
                "install",
                "--no-incremental",
                str(runtime_state.AndroidRunLayout.from_run_id(cap.run_id).signed_apk),
            ),
        ),
        AndroidOperation.UNINSTALL_APP: OperationSpec(
            "run", 60, 60, None, lambda cap: _device(cap, "uninstall", PACKAGE)
        ),
        AndroidOperation.DEVICE_TIME: OperationSpec(
            "write",
            15,
            15,
            OutputSpec(proof, "adb-device-time.txt", 4096),
            lambda cap: _device(cap, "shell", "date", "+%s.%3N"),
        ),
        AndroidOperation.FORCE_STOP: OperationSpec(
            "capture",
            15,
            15,
            None,
            lambda cap: _device(cap, "shell", "am", "force-stop", PACKAGE),
            stderr_to_stdout=True,
        ),
        AndroidOperation.START_APP: OperationSpec(
            "capture",
            30,
            30,
            None,
            lambda cap: _device(
                cap,
                "shell",
                "am",
                "start",
                "-W",
                "-n",
                f"{PACKAGE}/.QPeriaptSmokeActivity",
                "--es",
                "qperiapt_run_id",
                cap.run_id,
            ),
            stderr_to_stdout=True,
        ),
        AndroidOperation.READ_RESULT_TEXT: OperationSpec(
            "write",
            15,
            15,
            OutputSpec(proof, "qperiapt-android-device-result.txt.tmp", 1048576),
            lambda cap: _device(
                cap, "exec-out", "run-as", PACKAGE, "cat", RESULT_TEXT_REMOTE
            ),
        ),
        AndroidOperation.READ_RESULT_JSON: OperationSpec(
            "write",
            15,
            15,
            OutputSpec(proof, "qperiapt-android-device-result.json", 4194304),
            lambda cap: _device(
                cap, "exec-out", "run-as", PACKAGE, "cat", RESULT_JSON_REMOTE
            ),
        ),
        AndroidOperation.CAPTURE_LOGCAT: OperationSpec(
            "logcat",
            30,
            30,
            OutputSpec(proof, "logcat-raw.txt", 16777216),
            lambda cap: (),
        ),
    }
    return MappingProxyType(specs)


OPERATION_SPECS = _operation_specs()


def _validate_client_environment(
    capability: runtime_state.AndroidAdbCapability,
) -> None:
    exact = {
        **EXACT_CLIENT_ENVIRONMENT,
        "ADB_SERVER_SOCKET": capability.server_socket,
        "ADB_VENDOR_KEYS": str(capability.vendor_key),
    }
    for name, expected in exact.items():
        _require(
            os.environ.get(name) == expected,
            f"Android command environment changed: {name}",
        )
    for name in FORBIDDEN_CLIENT_ENVIRONMENT:
        _require(
            name not in os.environ, f"unsupported Android command environment: {name}"
        )


def _base_environment(capability: runtime_state.AndroidAdbCapability) -> dict[str, str]:
    return {
        "HOME": str(runtime_state.ACCOUNT_HOME),
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "TMPDIR": "/tmp",
        "LC_ALL": "C",
        "LANG": "C",
        "ADB_MDNS": "0",
        "ADB_MDNS_AUTO_CONNECT": "0",
        "ADB_LOCAL_TRANSPORT_MAX_PORT": "5585",
        "ADB_SERVER_SOCKET": capability.server_socket,
        "ADB_VENDOR_KEYS": str(capability.vendor_key),
    }


def _client_environment(
    capability: runtime_state.AndroidAdbCapability,
) -> dict[str, str]:
    return {**_base_environment(capability), "ADB_USB": "0", "ADB_EMU": "0"}


def _server_environment(
    capability: runtime_state.AndroidAdbCapability,
) -> dict[str, str]:
    return {
        **_base_environment(capability),
        "ADB_USB": "1" if capability.device_kind == "physical" else "0",
        "ADB_EMU": "0",
    }


def _validate_server_environment(
    capability: runtime_state.AndroidAdbCapability,
) -> None:
    server_transport = {
        "ADB_USB": "1" if capability.device_kind == "physical" else "0",
        "ADB_EMU": "0",
    }
    exact = {
        "ADB_MDNS": "0",
        "ADB_MDNS_AUTO_CONNECT": "0",
        "ADB_LOCAL_TRANSPORT_MAX_PORT": "5585",
        "ADB_SERVER_SOCKET": capability.server_socket,
        "ADB_VENDOR_KEYS": str(capability.vendor_key),
        **server_transport,
    }
    for name, expected in exact.items():
        _require(
            os.environ.get(name) == expected,
            f"Android server environment changed: {name}",
        )
    for name in FORBIDDEN_CLIENT_ENVIRONMENT:
        _require(
            name not in os.environ, f"unsupported Android server environment: {name}"
        )


def _validate_adb_at(
    directory_fd: int, capability: runtime_state.AndroidAdbCapability
) -> None:
    observed = consume_regular_snapshot_at(
        directory_fd,
        runtime_state.adb_snapshot_leaf(capability.run_id),
        display_path=capability.adb_snapshot_path,
        maximum=runtime_state.MAX_TOOL_BYTES,
        label="Android adb snapshot",
        validate_metadata=runtime_state.private_executable_metadata,
    )
    _require(
        observed.size == capability.adb_size
        and observed.sha256 == capability.adb_sha256,
        "Android adb snapshot changed after capability creation",
    )


def _validate_adb(
    layout: runtime_state.AndroidRunLayout,
    capability: runtime_state.AndroidAdbCapability,
) -> None:
    directory_fd = runtime_state.open_private_directory(layout.work, "Android work")
    primary: BaseException | None = None
    try:
        _validate_adb_at(directory_fd, capability)
    except BaseException as exc:
        primary = exc
        raise
    finally:
        runtime_state.close_descriptor(
            directory_fd, label="the Android work directory", primary=primary
        )


def _load_capability_for_layout(
    layout: runtime_state.AndroidRunLayout,
) -> runtime_state.AndroidCommandCapability:
    snapshot = load_json_object_snapshot(
        layout.capability,
        maximum=runtime_state.MAX_CAPABILITY_BYTES,
        label="Android command capability",
        validate_metadata=runtime_state.private_file_metadata,
    )
    capability = runtime_state.load_capability_snapshot_for_layout(
        snapshot, layout=layout
    )
    _validate_adb(layout, capability)
    return capability


def _validate_tool_and_apk(
    layout: runtime_state.AndroidRunLayout,
    capability: runtime_state.AndroidCommandCapability,
    operation: AndroidOperation,
) -> None:
    _validate_adb(layout, capability)
    if operation in {
        AndroidOperation.INSTALL_APK,
        AndroidOperation.OBSERVE_INSTALLED_APK,
    }:
        observed = consume_regular_snapshot(
            layout.signed_apk,
            maximum=runtime_state.MAX_APK_BYTES,
            label="signed Android smoke APK",
        )
        _require(
            observed.size == capability.signed_apk_size
            and observed.sha256 == capability.signed_apk_sha256,
            "signed Android smoke APK changed after capability creation",
        )


def _emulator_environment(
    capability: runtime_state.AndroidAdbCapability,
) -> dict[str, str]:
    sdk_root = runtime_state.ADB_PROFILE_PATHS[capability.adb_profile].parent.parent
    return {
        **_client_environment(capability),
        "ANDROID_HOME": str(sdk_root),
        "ANDROID_SDK_ROOT": str(sdk_root),
        "ANDROID_AVD_HOME": str(runtime_state.avd_home_directory()),
        "ANDROID_ADB_SERVER_PORT": str(NATIVE_ADB_NOTIFIER_PORT),
    }


def _fixed_emulator_paths(
    capability: runtime_state.AndroidAdbCapability,
    device_abi: str,
) -> tuple[pathlib.Path, pathlib.Path]:
    _require(
        capability.device_kind == "emulator",
        "owned emulator execution requires an emulator capability",
    )
    source_adb = runtime_state.ADB_PROFILE_PATHS[capability.adb_profile]
    _require(
        source_adb.parent.name == "platform-tools" and source_adb.name == "adb",
        "fixed Android SDK adb layout changed",
    )
    launcher = source_adb.parent.parent / "emulator" / "emulator"
    try:
        backend = fixed_headless_backend_path(launcher, device_abi)
        return launcher.resolve(strict=True), backend.resolve(strict=True)
    except (AndroidEmulatorControlError, OSError) as exc:
        raise AndroidCommandError(
            f"cannot resolve the fixed Android emulator executables: {exc}"
        ) from exc


def _executable_file_identity(path: pathlib.Path, label: str) -> tuple[int, int]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise AndroidCommandError(f"cannot inspect {label}: {exc}") from exc
    _require(
        stat.S_ISREG(metadata.st_mode)
        and not path.is_symlink()
        and metadata.st_mode & 0o111 != 0,
        f"{label} must be a non-symlink executable regular file",
    )
    return metadata.st_dev, metadata.st_ino


def exec_emulator(run_id: str, device_abi: str) -> NoReturn:
    """Persist recovery identity, drop the lane lock, and exec one fixed AVD."""
    runtime_state.validate_lane_lock_descriptor()
    layout = runtime_state.AndroidRunLayout.from_run_id(run_id)
    prior_receipt = runtime_state.load_owned_runtime_receipt()
    _require(prior_receipt is not None, "runtime recovery receipt is missing")
    _require(
        prior_receipt.run_id == layout.run_id
        and prior_receipt.adb_server_started
        and prior_receipt.adb_socket_directory_sealed
        and (not prior_receipt.emulator_started),
        "runtime recovery receipt is not awaiting this emulator",
    )
    capability = runtime_state.load_capability(layout.run_id)
    _validate_adb(layout, capability)
    _validate_owned_adb_server_for_client(capability)
    canonical_abi = runtime_state.canonical_runtime_emulator_abi(device_abi)
    selection = runtime_state.validate_runtime_avd_selection(
        capability.adb_profile,
        canonical_abi,
    )
    canonical_avd = selection.name
    launcher, backend = _fixed_emulator_paths(capability, canonical_abi)
    try:
        identity = process_snapshot(os.getpid())
    except ProcessIdentityError as exc:
        raise AndroidCommandError(
            f"cannot identify the emulator exec process: {exc}"
        ) from exc
    token, token_identity = _emulator_console_auth_token()
    del token
    launcher_device, launcher_inode = _executable_file_identity(
        launcher, "Android emulator launcher"
    )
    backend_device, backend_inode = _executable_file_identity(
        backend, "Android emulator backend"
    )
    backend_snapshot = consume_regular_snapshot(
        backend,
        maximum=runtime_state.MAX_TOOL_BYTES,
        label="Android emulator backend",
        validate_metadata=runtime_state.executable_metadata,
    )
    confirmed_token, confirmed_token_identity = _emulator_console_auth_token(
        token_identity
    )
    del confirmed_token
    console_port, _adb_port = _owned_emulator_ports(capability)
    confirmed_selection = runtime_state.validate_runtime_avd_selection(
        capability.adb_profile,
        canonical_abi,
    )
    _require(
        confirmed_selection == selection,
        "fixed Android AVD selection changed before emulator registration",
    )
    receipt = runtime_state.register_emulator_child(
        receipt=prior_receipt,
        registration=runtime_state.EmulatorChildRegistration(
            process=identity,
            avd_name=canonical_avd,
            device_abi=canonical_abi,
            console_port=console_port,
            native_adb_notifier_port=NATIVE_ADB_NOTIFIER_PORT,
            console_auth_token=confirmed_token_identity,
            launcher_path=launcher,
            launcher_device=launcher_device,
            launcher_inode=launcher_inode,
            backend_path=backend,
            backend_device=backend_device,
            backend_inode=backend_inode,
            backend_sha256=backend_snapshot.sha256,
        ),
    )
    _validate_adb(layout, capability)
    _validate_owned_adb_server_for_client(capability)
    emulator_environment = _emulator_environment(capability)
    argv = [
        str(launcher),
        "-avd",
        canonical_avd,
        "-port",
        str(receipt.console_port),
        "-no-snapshot",
        "-read-only",
        "-no-window",
        "-no-audio",
        "-no-boot-anim",
        "-no-direct-adb",
        "-adb-path",
        str(capability.adb_snapshot_path),
        "-gpu",
        "swiftshader_indirect",
    ]
    runtime_state.record_pre_exec_adb_isolation_checkpoint(layout.run_id)
    try:
        runtime_state.arm_lane_lock_close_on_exec()
        _close_nonstandard_descriptors(preserve_lane_lock=True)
        os.execve(str(launcher), argv, emulator_environment)
    except BaseException as primary:
        if isinstance(primary, OSError):
            raise AndroidCommandError(
                f"cannot start the owned Android emulator: {primary}"
            ) from primary
        raise


def _same_receipt_process(
    receipt: runtime_state.OwnedRuntimeReceipt,
) -> ProcessIdentity | None:
    _require(
        receipt.emulator_started
        and receipt.pid is not None
        and (receipt.process_identity is not None),
        "pending runtime receipt has no emulator process identity",
    )
    try:
        observed = process_snapshot(receipt.pid)
    except ProcessIdentityError as exc:
        try:
            os.kill(receipt.pid, 0)
        except ProcessLookupError:
            return None
        except PermissionError as permission_error:
            raise AndroidCommandError(
                "cannot inspect the owned emulator process under the current account"
            ) from permission_error
        except OSError as probe_error:
            if probe_error.errno == errno.ESRCH:
                return None
            raise AndroidCommandError(
                f"cannot determine whether the owned emulator still exists: {probe_error}"
            ) from probe_error
        raise AndroidCommandError(
            f"owned emulator still exists but its identity cannot be read: {exc}"
        ) from exc
    if observed.token != receipt.process_identity:
        return None
    return observed


def _same_receipt_adb_server_process(
    receipt: runtime_state.OwnedRuntimeReceipt,
) -> ProcessIdentity | None:
    _require(
        receipt.adb_server_started
        and receipt.adb_server_pid is not None
        and (receipt.adb_server_process_identity is not None),
        "pending runtime receipt has no adb server process identity",
    )
    try:
        observed = process_snapshot(receipt.adb_server_pid)
    except ProcessIdentityError as exc:
        try:
            os.kill(receipt.adb_server_pid, 0)
        except ProcessLookupError:
            return None
        except PermissionError as permission_error:
            raise AndroidCommandError(
                "cannot inspect the owned adb server process under the current account"
            ) from permission_error
        except OSError as probe_error:
            if probe_error.errno == errno.ESRCH:
                return None
            raise AndroidCommandError(
                f"cannot determine whether the owned adb server still exists: {probe_error}"
            ) from probe_error
        raise AndroidCommandError(
            f"owned adb server still exists but its identity cannot be read: {exc}"
        ) from exc
    if observed.token != receipt.adb_server_process_identity:
        return None
    return observed


def _validate_receipt_adb_server_executable(
    receipt: runtime_state.OwnedRuntimeReceipt,
    capability: runtime_state.AndroidAdbCapability,
    observed: ProcessIdentity,
) -> None:
    _require(
        receipt.adb_server_initial_executable is not None
        and receipt.adb_server_initial_executable_device is not None
        and (receipt.adb_server_initial_executable_inode is not None)
        and (receipt.adb_snapshot_device is not None)
        and (receipt.adb_snapshot_inode is not None),
        "owned adb server receipt lacks executable identity",
    )
    if observed.executable == receipt.adb_server_initial_executable:
        identity = _executable_file_identity(
            observed.executable, "adb server initial executable"
        )
        _require(
            identity
            == (
                receipt.adb_server_initial_executable_device,
                receipt.adb_server_initial_executable_inode,
            ),
            "owned adb server initial executable identity changed",
        )
        return
    _require(
        observed.executable == capability.adb_snapshot_path,
        "owned adb server execed an unexpected executable",
    )
    identity = _executable_file_identity(
        capability.adb_snapshot_path, "Android adb snapshot"
    )
    _require(
        identity == (receipt.adb_snapshot_device, receipt.adb_snapshot_inode),
        "owned adb server snapshot identity changed",
    )


def _capture_recovery_adb_listener(
    capability: runtime_state.AndroidAdbCapability,
    receipt: runtime_state.OwnedRuntimeReceipt,
) -> OwnedUnixListenerObservation | None:
    result = capture_stdout(
        (
            _lsof_path(),
            "-nP",
            "-a",
            "-U",
            "-Ts",
            "-FpufnT",
            capability.socket_path,
        ),
        timeout_seconds=5,
        maximum_bytes=65536,
        environment={
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LC_ALL": "C",
            "LANG": "C",
        },
    )
    if result.returncode == 1 and result.stdout == b"":
        return None
    _require(result.returncode == 0, "owned adb server listener inspection failed")
    try:
        text = result.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AndroidCommandError(
            "owned adb server listener output is not UTF-8"
        ) from exc
    try:
        observation = parse_owned_single_listener(
            text,
            expected_pid=receipt.adb_server_pid,
            expected_uid=receipt.uid,
            expected_endpoint=capability.socket_path,
            dialect=runtime_state.owned_unix_listener_dialect(
                receipt.adb_profile
            ),
            expected_listener_descriptor=receipt.adb_listener_descriptor,
        )
    except AndroidEmulatorControlError as exc:
        raise AndroidCommandError(str(exc)) from exc
    return observation


def _wait_for_recovery_adb_server(
    receipt: runtime_state.OwnedRuntimeReceipt,
    capability: runtime_state.AndroidAdbCapability,
) -> ProcessIdentity | None:
    """Observe only the receipt-bound Python-to-adb exec transition."""
    deadline = time.monotonic() + 5
    socket_path = pathlib.Path(capability.socket_path)
    while True:
        observed = _same_receipt_adb_server_process(receipt)
        if observed is None:
            return None
        _validate_receipt_adb_server_executable(receipt, capability, observed)
        socket_present = os.path.lexists(socket_path)
        if observed.executable == capability.adb_snapshot_path and socket_present:
            return observed
        _require(
            not socket_present,
            "owned adb socket appeared before the receipt-bound adb exec",
        )
        remaining = deadline - time.monotonic()
        _require(
            remaining > 0,
            "owned adb server is live but its private socket is not ready",
        )
        time.sleep(min(0.05, remaining))


def _wait_for_recovered_adb_server_exit(
    receipt: runtime_state.OwnedRuntimeReceipt,
) -> None:
    deadline = time.monotonic() + 15
    while True:
        if _same_receipt_adb_server_process(receipt) is None:
            return
        remaining = deadline - time.monotonic()
        _require(remaining > 0, "owned adb server did not exit after protocol shutdown")
        time.sleep(min(0.1, remaining))


def _validate_owned_adb_server_for_client(
    capability: runtime_state.AndroidCommandCapability,
) -> None:
    """Prevent adb clients from auto-starting an unowned replacement server."""
    runtime_state.validate_lane_lock_descriptor()
    receipt = runtime_state.load_owned_runtime_receipt()
    _require(
        receipt is not None
        and receipt.run_id == capability.run_id
        and receipt.adb_server_started,
        "Android client lacks this run's started adb server receipt",
    )
    try:
        current_host_boot = host_boot_identity()
    except ProcessIdentityError as exc:
        raise AndroidCommandError(
            f"cannot verify adb client runtime host: {exc}"
        ) from exc
    _require(
        receipt.uid == os.geteuid()
        and receipt.host_identity == current_host_boot.host
        and (receipt.boot_identity == current_host_boot.boot),
        "Android client adb server receipt belongs to another runtime",
    )
    observed = _wait_for_recovery_adb_server(receipt, capability)
    _require(observed is not None, "owned adb server exited before client operation")
    receipt = _reconcile_live_adb_seal(capability, receipt, observed)
    _require(
        os.path.lexists(capability.socket_path),
        "owned adb server socket disappeared before client operation",
    )
    _require(
        _capture_recovery_adb_listener(capability, receipt),
        "owned adb server listener disappeared before client operation",
    )


def _socket_directory_metadata(
    capability: runtime_state.AndroidAdbCapability,
    receipt: runtime_state.OwnedRuntimeReceipt,
    *,
    allowed_modes: frozenset[int],
) -> os.stat_result:
    directory = pathlib.Path(capability.socket_path).parent
    try:
        metadata = directory.lstat()
    except OSError as exc:
        raise AndroidCommandError(
            f"cannot inspect private adb socket directory: {exc}"
        ) from exc
    _require(
        stat.S_ISDIR(metadata.st_mode)
        and (not directory.is_symlink())
        and (metadata.st_uid == os.geteuid())
        and (
            (metadata.st_dev, metadata.st_ino)
            == (receipt.adb_socket_directory_device, receipt.adb_socket_directory_inode)
        )
        and (stat.S_IMODE(metadata.st_mode) in allowed_modes),
        "private adb socket directory identity or mode changed",
    )
    return metadata


def _reconcile_live_adb_seal(
    capability: runtime_state.AndroidAdbCapability,
    receipt: runtime_state.OwnedRuntimeReceipt,
    observed: ProcessIdentity,
) -> runtime_state.OwnedRuntimeReceipt:
    """Make phase and directory mode durably safe before any adb client."""

    _validate_receipt_adb_server_executable(receipt, capability, observed)
    _require(
        observed.executable == capability.adb_snapshot_path,
        "cannot reconcile adb sealing before the exact adb exec",
    )
    observation = _capture_recovery_adb_listener(capability, receipt)
    _require(
        observation is not None,
        "cannot reconcile adb sealing without the exact live listener",
    )
    directory = pathlib.Path(capability.socket_path).parent
    phase = receipt.phase
    if phase is runtime_state.RuntimePhase.ADB_CHILD_REGISTERED:
        _socket_directory_metadata(
            capability, receipt, allowed_modes=frozenset({0o700})
        )
        receipt = runtime_state.begin_adb_seal(
            receipt,
            observation.listener_descriptor,
        )
        rebound = _capture_recovery_adb_listener(capability, receipt)
        _require(
            rebound is not None,
            "bound adb listener changed before socket-directory sealing",
        )
        phase = receipt.phase
    if phase is runtime_state.RuntimePhase.ADB_SEALING:
        metadata = _socket_directory_metadata(
            capability, receipt, allowed_modes=frozenset({0o500, 0o700})
        )
        if stat.S_IMODE(metadata.st_mode) == 0o700:
            directory.chmod(0o500)
        _socket_directory_metadata(
            capability, receipt, allowed_modes=frozenset({0o500})
        )
        receipt = runtime_state.complete_adb_seal(receipt)
        phase = receipt.phase
    _require(
        phase
        in {
            runtime_state.RuntimePhase.ADB_SEALED,
            runtime_state.RuntimePhase.EMULATOR_CHILD_REGISTERED,
        },
        "live adb server receipt cannot reach a client-safe phase",
    )
    metadata = _socket_directory_metadata(
        capability, receipt, allowed_modes=frozenset({0o500, 0o700})
    )
    if stat.S_IMODE(metadata.st_mode) == 0o700:
        directory.chmod(0o500)
    _socket_directory_metadata(capability, receipt, allowed_modes=frozenset({0o500}))
    return receipt


def seal_private_adb_directory(run_id: str) -> None:
    """Seal the exact live server directory before any adb client can auto-start."""
    runtime_state.validate_lane_lock_descriptor()
    capability = runtime_state.load_capability(run_id)
    receipt = runtime_state.load_owned_runtime_receipt()
    _require(
        receipt is not None
        and receipt.run_id == capability.run_id
        and receipt.phase is runtime_state.RuntimePhase.ADB_CHILD_REGISTERED,
        "private adb directory is not awaiting this run's seal",
    )
    observed = _wait_for_recovery_adb_server(receipt, capability)
    _require(
        observed is not None and observed.executable == capability.adb_snapshot_path,
        "cannot seal a private adb directory without its exact live server",
    )
    _require(
        _capture_recovery_adb_listener(capability, receipt),
        "cannot seal a private adb directory without its exact listener",
    )
    try:
        _reconcile_live_adb_seal(capability, receipt, observed)
    except OSError as exc:
        raise AndroidCommandError(f"cannot seal private adb directory: {exc}") from exc


def _recovery_adb_capability(
    layout: runtime_state.AndroidRunLayout, receipt: runtime_state.OwnedRuntimeReceipt
) -> runtime_state.AndroidAdbCapability:
    server_socket, socket_path = runtime_state.server_socket_identity(
        receipt.socket_nonce
    )
    return runtime_state.AndroidAdbCapability(
        adb_profile=receipt.adb_profile,
        adb_snapshot_path=layout.work / runtime_state.adb_snapshot_leaf(receipt.run_id),
        adb_size=receipt.adb_size,
        adb_sha256=receipt.adb_sha256,
        socket_nonce=receipt.socket_nonce,
        native_adb_notifier_port=receipt.native_adb_notifier_port,
        server_socket=server_socket,
        socket_path=socket_path,
        vendor_key=runtime_state.ACCOUNT_HOME / ".android/adbkey",
        device_kind=receipt.device_kind,
        expected_serial=receipt.expected_serial,
        run_id=receipt.run_id,
    )


def _load_recovery_adb_capability(
    layout: runtime_state.AndroidRunLayout, receipt: runtime_state.OwnedRuntimeReceipt
) -> runtime_state.AndroidAdbCapability:
    """Validate whichever capability bytes remain and reconstruct cleanup identity."""
    recovery = _recovery_adb_capability(layout, receipt)
    directory_fd = runtime_state.open_private_directory(
        layout.work, "Android recovery work"
    )
    primary: BaseException | None = None
    try:
        capability_present = True
        try:
            snapshot = load_json_object_snapshot_at(
                directory_fd,
                runtime_state.CAPABILITY_LEAF,
                display_path=layout.capability,
                maximum=runtime_state.MAX_CAPABILITY_BYTES,
                label="Android command capability",
                validate_metadata=runtime_state.private_file_metadata,
            )
        except EvidenceIOError:
            try:
                os.stat(
                    runtime_state.CAPABILITY_LEAF,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                capability_present = False
            else:
                raise
        if capability_present:
            capability = runtime_state.load_capability_snapshot_for_layout(
                snapshot, layout=layout
            )
            _require(
                capability.adb_profile == recovery.adb_profile
                and capability.adb_size == recovery.adb_size
                and (capability.adb_sha256 == recovery.adb_sha256)
                and (capability.socket_nonce == recovery.socket_nonce)
                and (capability.device_kind == recovery.device_kind)
                and (capability.expected_serial == recovery.expected_serial),
                "runtime recovery receipt differs from its run capability",
            )
        adb_present = True
        try:
            adb_snapshot = consume_regular_snapshot_at(
                directory_fd,
                runtime_state.adb_snapshot_leaf(receipt.run_id),
                display_path=recovery.adb_snapshot_path,
                maximum=runtime_state.MAX_TOOL_BYTES,
                label="Android adb snapshot",
                validate_metadata=runtime_state.private_executable_metadata,
            )
        except EvidenceIOError:
            try:
                os.stat(
                    runtime_state.adb_snapshot_leaf(receipt.run_id),
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                adb_present = False
            else:
                raise
        if adb_present:
            _require(
                adb_snapshot.size == recovery.adb_size
                and adb_snapshot.sha256 == recovery.adb_sha256,
                "runtime recovery adb snapshot differs from its receipt",
            )
        return recovery
    except BaseException as exc:
        primary = exc
        raise
    finally:
        runtime_state.close_descriptor(
            directory_fd, label="the Android recovery work directory", primary=primary
        )


def _validate_recovery_receipt(
    receipt: runtime_state.OwnedRuntimeReceipt, *, validate_active_emulator: bool = True
) -> RecoveryContext:
    _require(
        receipt.uid == os.geteuid(),
        "owned runtime receipt belongs to a different account",
    )
    try:
        current_host_boot = host_boot_identity()
    except ProcessIdentityError as exc:
        raise AndroidCommandError(
            f"cannot verify runtime recovery host: {exc}"
        ) from exc
    _require(
        receipt.host_identity == current_host_boot.host,
        "owned runtime receipt belongs to a different host",
    )
    current_boot = receipt.boot_identity == current_host_boot.boot
    _require(
        current_boot, "current-boot recovery validation received a prior-boot receipt"
    )
    try:
        repository_metadata = receipt.repository_root.lstat()
    except OSError as exc:
        raise AndroidCommandError(
            f"cannot inspect the recovery repository root: {exc}"
        ) from exc
    _require(
        stat.S_ISDIR(repository_metadata.st_mode)
        and (not receipt.repository_root.is_symlink()),
        "owned runtime recovery repository root changed type",
    )
    run_root = (
        receipt.repository_root
        / "target"
        / runtime_state.RUNS_ROOT_LEAF
        / receipt.run_id
    )
    try:
        run_root_metadata = run_root.lstat()
    except OSError as exc:
        raise AndroidCommandError(
            f"cannot inspect the recovery run root: {exc}"
        ) from exc
    _require(
        stat.S_ISDIR(run_root_metadata.st_mode)
        and (not run_root.is_symlink())
        and (run_root_metadata.st_uid == os.geteuid())
        and (stat.S_IMODE(run_root_metadata.st_mode) == 448)
        and (
            (run_root_metadata.st_dev, run_root_metadata.st_ino)
            == (receipt.run_root_device, receipt.run_root_inode)
        ),
        "owned runtime recovery run-root identity changed",
    )
    layout = runtime_state.AndroidRunLayout(
        run_id=receipt.run_id,
        root=run_root,
        work=run_root / "work",
        proof=run_root / "proof",
        capability=run_root / "work" / runtime_state.CAPABILITY_LEAF,
        signed_apk=run_root / "proof" / runtime_state.SIGNED_APK_LEAF,
    )
    capability = _load_recovery_adb_capability(layout, receipt)
    if not receipt.emulator_started or not validate_active_emulator:
        return RecoveryContext(
            layout=layout,
            capability=capability,
            launcher=None,
            backend=None,
            current_boot=current_boot,
        )
    launcher, backend = _fixed_emulator_paths(capability, receipt.device_abi)
    _require(
        launcher == receipt.launcher_path and backend == receipt.backend_path,
        "owned emulator executable paths changed after launch",
    )
    launcher_identity = _executable_file_identity(launcher, "Android emulator launcher")
    backend_identity = _executable_file_identity(backend, "Android emulator backend")
    backend_snapshot = consume_regular_snapshot(
        backend,
        maximum=runtime_state.MAX_TOOL_BYTES,
        label="Android emulator backend",
        validate_metadata=runtime_state.executable_metadata,
    )
    _require(
        launcher_identity == (receipt.launcher_device, receipt.launcher_inode)
        and backend_identity == (receipt.backend_device, receipt.backend_inode),
        "owned emulator executable identity changed after launch",
    )
    _require(
        backend_snapshot.sha256 == receipt.backend_sha256,
        "owned emulator backend bytes changed after launch",
    )
    return RecoveryContext(
        layout=layout,
        capability=capability,
        launcher=launcher,
        backend=backend,
        current_boot=current_boot,
    )


def _wait_for_recovery_backend(
    receipt: runtime_state.OwnedRuntimeReceipt,
    launcher: pathlib.Path,
    backend: pathlib.Path,
) -> ProcessIdentity | None:
    deadline = time.monotonic() + 10
    while True:
        observed = _same_receipt_process(receipt)
        if observed is None:
            return None
        if observed.executable == backend:
            return observed
        _require(
            observed.executable == launcher,
            "owned emulator execed an unexpected executable",
        )
        remaining = deadline - time.monotonic()
        _require(
            remaining > 0, "owned emulator launcher did not become its fixed backend"
        )
        time.sleep(min(0.05, remaining))


def _verify_recovery_listeners(
    *,
    layout: runtime_state.AndroidRunLayout,
    capability: runtime_state.AndroidAdbCapability,
    receipt: runtime_state.OwnedRuntimeReceipt,
) -> None:
    _capture_owned_emulator_listeners(
        layout=layout,
        capability=capability,
        emulator_pid=receipt.pid,
        timeout_seconds=5,
    )
    pending = layout.work / "emulator-listeners.txt.pending"
    snapshot = read_regular_snapshot(
        pending,
        maximum=65536,
        label="owned emulator recovery listeners",
        validate_metadata=runtime_state.private_file_metadata,
    )
    try:
        text = snapshot.data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AndroidCommandError(
            "owned emulator recovery listeners are not UTF-8"
        ) from exc
    try:
        parse_owned_lsof_listeners(
            text,
            expected_pid=receipt.pid,
            expected_uid=receipt.uid,
            console_port=receipt.console_port,
            adb_port=receipt.console_port + 1,
        )
    except AndroidEmulatorControlError as exc:
        raise AndroidCommandError(str(exc)) from exc


def _register_owned_emulator(
    capability: runtime_state.AndroidAdbCapability, *, timeout_seconds: int
) -> BoundedResult:
    console_port, adb_port = _owned_emulator_ports(capability)
    result = capture_stdout(
        OPERATION_SPECS[AndroidOperation.REGISTER_EMULATOR].build_argv(capability),
        timeout_seconds=timeout_seconds,
        maximum_bytes=512,
        stderr=subprocess.STDOUT,
        environment=_client_environment(capability),
    )
    accepted = {
        f"Connected to emulator on ports {console_port},{adb_port}\n".encode("ascii"),
        f"Emulator already registered on port {adb_port}\n".encode("ascii"),
    }
    _require(
        result.returncode == 0 and result.stdout in accepted,
        f"owned emulator registration was not an exact success (returncode={result.returncode}, response_hex={result.stdout.hex()})",
    )
    return result


def _emulator_console_auth_token_path() -> pathlib.Path:
    """Return the account-bound path shared by token I/O and banner parsing."""

    return runtime_state.ACCOUNT_HOME / EMULATOR_CONSOLE_AUTH_TOKEN_LEAF


def _emulator_console_auth_token(
    expected: runtime_state.ConsoleAuthTokenIdentity | None = None,
) -> tuple[bytes, runtime_state.ConsoleAuthTokenIdentity]:
    """Read and identify the private console token without logging its bytes."""
    token_path = _emulator_console_auth_token_path()
    try:
        descriptor = os.open(
            token_path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        )
    except OSError as exc:
        raise AndroidCommandError(
            f"cannot open the Android emulator console authentication token: {exc}"
        ) from exc
    primary: BaseException | None = None
    try:
        metadata = os.fstat(descriptor)
        _require(
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and (metadata.st_nlink == 1)
            and (stat.S_IMODE(metadata.st_mode) == 384),
            "Android emulator console authentication token must be one private regular file",
        )
        runtime_state.reject_macos_allow_acl(
            descriptor, "Android emulator console authentication token"
        )
        chunks: list[bytes] = []
        remaining = 4097
        while remaining:
            chunk = os.read(descriptor, min(remaining, 4096))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        _require(
            1 <= len(raw) <= 4096,
            "Android emulator console authentication token size is invalid",
        )
        token = raw.rstrip(b"\r\n")
        _require(
            token
            and len(token) <= 4094
            and all((33 <= value <= 126 and value != 32 for value in token)),
            "Android emulator console authentication token bytes are invalid",
        )
        identity = runtime_state.ConsoleAuthTokenIdentity(
            device=metadata.st_dev,
            inode=metadata.st_ino,
            sha256=hashlib.sha256(raw).hexdigest(),
        )
        _require(
            expected is None or identity == expected,
            "Android emulator console authentication token changed after emulator launch",
        )
        return token, identity
    except BaseException as exc:
        primary = exc
        raise
    finally:
        runtime_state.close_descriptor(
            descriptor,
            label="the Android emulator console authentication token",
            primary=primary,
        )


def _normalize_emulator_console_response(response: bytes) -> bytes:
    return response.replace(b"\r\n", b"\n")


def _receive_emulator_console(
    sock: socket.socket,
    *,
    expected_responses: tuple[bytes, ...],
    maximum: int = 16384,
) -> bytes:
    """Read one exact terminal frame without requiring socket EOF.

    The fixed console protocol is line-delimited. Bytes received after the
    terminal line belong to no command response and are not interpreted.
    """
    _require(
        type(expected_responses) is tuple
        and expected_responses
        and type(maximum) is int
        and 1 <= maximum <= 16384
        and len(set(expected_responses)) == len(expected_responses)
        and all(
            type(expected) is bytes
            and expected
            and b"\r" not in expected
            and len(expected) < maximum
            for expected in expected_responses
        ),
        "owned emulator console response contract is invalid",
    )
    _require(
        all(
            not left.startswith(right)
            for left in expected_responses
            for right in expected_responses
            if left != right
        ),
        "owned emulator console terminal frames must not overlap",
    )
    deadline = time.monotonic() + EMULATOR_CONSOLE_RESPONSE_TIMEOUT_SECONDS
    response = bytearray()
    while len(response) < maximum:
        remaining = deadline - time.monotonic()
        _require(
            remaining > 0,
            "owned emulator console response timed out",
        )
        try:
            sock.settimeout(remaining)
            chunk = sock.recv(min(4096, maximum - len(response)))
        except TimeoutError as exc:
            raise AndroidCommandError(
                "owned emulator console response timed out"
            ) from exc
        except OSError as exc:
            if response and exc.errno in {errno.ECONNRESET, errno.EPIPE}:
                break
            raise AndroidCommandError(
                f"cannot read the owned emulator console response: {exc}"
            ) from exc
        if not chunk:
            break
        response.extend(chunk)
        _require(
            len(response) <= maximum,
            "owned emulator console response exceeded its fixed bound",
        )
        normalized = _normalize_emulator_console_response(bytes(response))
        for expected in expected_responses:
            if normalized.startswith(expected):
                return expected
        prefix = normalized[:-1] if normalized.endswith(b"\r") else normalized
        _require(
            any(expected.startswith(prefix) for expected in expected_responses),
            "owned emulator console response was outside its exact grammar",
        )
    normalized = _normalize_emulator_console_response(bytes(response))
    _require(
        normalized in expected_responses,
        "owned emulator console response ended before its terminal frame",
    )
    return normalized


def _expected_emulator_console_responses(
    receipt: runtime_state.OwnedRuntimeReceipt,
    command: bytes,
) -> tuple[bytes, ...]:
    authenticated_prefix = _emulator_console_authenticated_prefix()
    if command == b"avd name\nquit\n":
        _require(
            receipt.avd_name is not None,
            "owned emulator console name response lacks its receipt AVD name",
        )
        return (
            authenticated_prefix
            + receipt.avd_name.encode("ascii")
            + b"\nOK\n",
        )
    _require(
        command == b"kill\n",
        "owned emulator console response command is outside the fixed set",
    )
    return (
        authenticated_prefix + b"OK: killing emulator, bye bye\n",
    )


def _emulator_console_authenticated_prefix() -> bytes:
    """Return the exact account-bound banner through successful authentication."""

    token_path = os.fsencode(_emulator_console_auth_token_path())
    _require(
        token_path.startswith(b"/")
        and len(token_path) <= 4096
        and b"\0" not in token_path
        and b"\r" not in token_path
        and b"\n" not in token_path
        and b"'" not in token_path,
        "Android emulator console authentication token path bytes are invalid",
    )
    return (
        EMULATOR_CONSOLE_AUTHENTICATION_BANNER_PREFIX
        + token_path
        + b"'"
        + EMULATOR_CONSOLE_AUTHENTICATED_MARKER
    )


def _emulator_console_exchange(
    context: RecoveryContext, receipt: runtime_state.OwnedRuntimeReceipt, command: bytes
) -> bytes:
    _require(
        receipt.emulator_started
        and receipt.console_port is not None
        and (receipt.avd_name is not None),
        "owned emulator console shutdown lacks its receipt identity",
    )
    _require(
        command in {b"avd name\nquit\n", b"kill\n"},
        "owned emulator console command is outside the fixed set",
    )
    try:
        with socket.create_connection(
            ("127.0.0.1", receipt.console_port),
            timeout=EMULATOR_CONSOLE_RESPONSE_TIMEOUT_SECONDS,
        ) as console:
            fresh = _same_receipt_process(receipt)
            _require(
                context.backend is not None
                and fresh is not None
                and (fresh.executable == context.backend),
                "owned emulator identity changed after console connection",
            )
            _verify_recovery_listeners(
                layout=context.layout, capability=context.capability, receipt=receipt
            )
            expected_token = receipt.console_auth_token_identity
            _require(
                expected_token is not None,
                "owned emulator receipt lacks its console token identity",
            )
            token, _identity = _emulator_console_auth_token(expected_token)
            request = b"auth " + token + b"\n" + command
            console.sendall(request)
            response = _receive_emulator_console(
                console,
                expected_responses=_expected_emulator_console_responses(
                    receipt,
                    command,
                ),
            )
    except AndroidCommandError:
        raise
    except OSError as exc:
        raise AndroidCommandError(
            f"cannot connect to the owned Android emulator console: {exc}"
        ) from exc
    return _authenticated_emulator_console_payload(response)


def _authenticated_emulator_console_payload(response: bytes) -> bytes:
    """Return the exact command payload after the authenticated console banner."""

    authenticated_prefix = _emulator_console_authenticated_prefix()
    _require(
        type(response) is bytes
        and response.startswith(authenticated_prefix)
        and response.count(EMULATOR_CONSOLE_AUTHENTICATED_MARKER) == 1,
        "owned emulator console authentication response was not exact",
    )
    return response[len(authenticated_prefix) :]


def _verify_owned_emulator_console_name(
    context: RecoveryContext, receipt: runtime_state.OwnedRuntimeReceipt
) -> None:
    payload = _emulator_console_exchange(context, receipt, b"avd name\nquit\n")
    _require(
        payload == receipt.avd_name.encode("ascii") + b"\nOK\n",
        "owned emulator console AVD name was not an exact match",
    )


def _request_owned_emulator_console_shutdown(
    context: RecoveryContext, receipt: runtime_state.OwnedRuntimeReceipt
) -> None:
    payload = _emulator_console_exchange(context, receipt, b"kill\n")
    _require(
        payload == b"OK: killing emulator, bye bye\n",
        "owned emulator console rejected its authenticated shutdown request",
    )


def _wait_for_recovered_emulator_exit(
    receipt: runtime_state.OwnedRuntimeReceipt,
) -> None:
    deadline = time.monotonic() + 20
    while True:
        if _same_receipt_process(receipt) is None:
            return
        remaining = deadline - time.monotonic()
        _require(
            remaining > 0,
            "owned emulator did not exit after its authenticated console shutdown",
        )
        time.sleep(min(0.2, remaining))


def _request_verified_owned_emulator_stop(
    context: RecoveryContext, receipt: runtime_state.OwnedRuntimeReceipt
) -> None:
    """Use only the authenticated receipt-bound console to request shutdown."""
    _require(
        context.launcher is not None and context.backend is not None,
        "active emulator shutdown lacks its executable identity",
    )
    _require(
        receipt.native_adb_notifier_port == NATIVE_ADB_NOTIFIER_PORT,
        "active emulator shutdown lacks its native adb notifier isolation",
    )
    probe_adb_loopback_absence()
    observed = _wait_for_recovery_backend(receipt, context.launcher, context.backend)
    _require(observed is not None, "owned emulator exited before protocol shutdown")
    _verify_recovery_listeners(
        layout=context.layout, capability=context.capability, receipt=receipt
    )
    _verify_owned_emulator_console_name(context, receipt)
    fresh = _same_receipt_process(receipt)
    _require(
        fresh is not None and fresh.executable == context.backend,
        "owned emulator identity changed before protocol shutdown",
    )
    _verify_recovery_listeners(
        layout=context.layout, capability=context.capability, receipt=receipt
    )
    _request_owned_emulator_console_shutdown(context, receipt)


def request_normal_owned_emulator_stop(run_id: str) -> None:
    runtime_state.validate_lane_lock_descriptor()
    receipt = runtime_state.load_owned_runtime_receipt()
    _require(
        receipt is not None
        and receipt.run_id == runtime_state.canonical_run_id(run_id)
        and receipt.emulator_started,
        "owned emulator stop request lacks this run's active receipt",
    )
    _require(
        _same_receipt_process(receipt) is not None,
        "owned emulator exited before its normal protocol shutdown",
    )
    context = _validate_recovery_receipt(receipt, validate_active_emulator=True)
    _request_verified_owned_emulator_stop(context, receipt)


def request_owned_adb_stop(
    layout: runtime_state.AndroidRunLayout,
    capability: runtime_state.AndroidAdbCapability,
    receipt: runtime_state.OwnedRuntimeReceipt,
) -> bool:
    socket_path = pathlib.Path(capability.socket_path)
    observed = (
        _wait_for_recovery_adb_server(receipt, capability)
        if receipt.adb_server_started
        else None
    )
    if not os.path.lexists(socket_path):
        _require(
            observed is None,
            "owned adb server is live but its private socket is not ready",
        )
        return False
    try:
        socket_metadata = socket_path.lstat()
    except OSError as exc:
        raise AndroidCommandError(
            f"cannot inspect private adb recovery socket: {exc}"
        ) from exc
    _require(
        stat.S_ISSOCK(socket_metadata.st_mode)
        and socket_metadata.st_uid == os.geteuid(),
        "private adb recovery endpoint changed type or owner",
    )
    _socket_directory_metadata(capability, receipt, allowed_modes=frozenset({320, 448}))
    if observed is None:
        _require(
            receipt.adb_server_started,
            "private adb recovery socket lacks its started server receipt",
        )
        listener_present = _capture_recovery_adb_listener(capability, receipt)
        _require(
            not listener_present,
            "private adb recovery socket lacks its live owned server process",
        )
        pathlib.Path(capability.socket_path).parent.chmod(448)
        socket_path.unlink()
        return False
    listener_present = _capture_recovery_adb_listener(capability, receipt)
    _require(
        receipt.adb_server_started and listener_present,
        "private adb recovery socket lacks its live owned server process",
    )
    receipt = _reconcile_live_adb_seal(capability, receipt, observed)
    _validate_adb(layout, capability)
    result = run(
        _adb(capability, "kill-server"),
        timeout_seconds=15,
        environment=_client_environment(capability),
    )
    _require(result.returncode == 0, "private adb server rejected protocol shutdown")
    return True


def finalize_owned_adb_stop(
    capability: runtime_state.AndroidAdbCapability,
    receipt: runtime_state.OwnedRuntimeReceipt,
) -> None:
    """Finalize only after the receipt-bound server process is confirmed gone."""
    if receipt.adb_server_started:
        _require(
            _same_receipt_adb_server_process(receipt) is None,
            "cannot finalize private adb cleanup while its server is live",
        )
    socket_path = pathlib.Path(capability.socket_path)
    socket_directory = socket_path.parent
    if not os.path.lexists(socket_directory):
        return
    _socket_directory_metadata(capability, receipt, allowed_modes=frozenset({320, 448}))
    try:
        socket_directory.chmod(448)
        if os.path.lexists(socket_path):
            metadata = socket_path.lstat()
            _require(
                stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == os.geteuid(),
                "private adb endpoint changed before final cleanup",
            )
            socket_path.unlink()
        socket_directory.rmdir()
    except OSError as exc:
        raise AndroidCommandError(
            f"cannot finalize private adb cleanup: {exc}"
        ) from exc


def request_normal_owned_adb_stop(run_id: str) -> None:
    runtime_state.validate_lane_lock_descriptor()
    receipt = runtime_state.load_owned_runtime_receipt()
    _require(receipt is not None, "owned runtime receipt is missing")
    layout = runtime_state.AndroidRunLayout.from_run_id(run_id)
    _require(
        receipt.run_id == layout.run_id, "owned runtime receipt belongs to another run"
    )
    capability = _load_recovery_adb_capability(layout, receipt)
    _require(
        request_owned_adb_stop(layout, capability, receipt),
        "owned adb server exited before its normal protocol shutdown",
    )


def finalize_normal_owned_adb_stop(run_id: str) -> None:
    runtime_state.validate_lane_lock_descriptor()
    receipt = runtime_state.load_owned_runtime_receipt()
    _require(receipt is not None, "owned runtime receipt is missing")
    layout = runtime_state.AndroidRunLayout.from_run_id(run_id)
    _require(
        receipt.run_id == layout.run_id, "owned runtime receipt belongs to another run"
    )
    capability = _load_recovery_adb_capability(layout, receipt)
    finalize_owned_adb_stop(capability, receipt)


def _finish_recovery_resources(
    layout: runtime_state.AndroidRunLayout,
    capability: runtime_state.AndroidAdbCapability,
    receipt: runtime_state.OwnedRuntimeReceipt,
) -> None:
    """Stop and remove the exact prior run's private adb recovery resources."""
    requested = request_owned_adb_stop(layout, capability, receipt)
    if requested:
        _wait_for_recovered_adb_server_exit(receipt)
    finalize_owned_adb_stop(capability, receipt)
    runtime_state.retire_recovery_capability(layout, receipt)


def _finish_previous_boot_resources(receipt: runtime_state.OwnedRuntimeReceipt) -> None:
    """Retire only offline files after a confirmed reboot; never signal a PID."""
    _server_socket, socket_path_text = runtime_state.server_socket_identity(
        receipt.socket_nonce
    )
    socket_directory = pathlib.Path(socket_path_text).parent
    try:
        directory_metadata = socket_directory.lstat()
    except FileNotFoundError:
        directory_metadata = None
    except OSError as exc:
        raise AndroidCommandError(
            f"cannot inspect prior-boot adb directory: {exc}"
        ) from exc
    if directory_metadata is not None:
        _require(
            stat.S_ISDIR(directory_metadata.st_mode)
            and (not socket_directory.is_symlink())
            and (directory_metadata.st_uid == os.geteuid())
            and (
                (directory_metadata.st_dev, directory_metadata.st_ino)
                == (
                    receipt.adb_socket_directory_device,
                    receipt.adb_socket_directory_inode,
                )
            )
            and (stat.S_IMODE(directory_metadata.st_mode) in {320, 448}),
            "prior-boot adb directory identity changed",
        )
        socket_directory.chmod(448)
        socket_path = pathlib.Path(socket_path_text)
        try:
            socket_metadata = socket_path.lstat()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise AndroidCommandError(
                f"cannot inspect prior-boot adb socket: {exc}"
            ) from exc
        else:
            _require(
                stat.S_ISSOCK(socket_metadata.st_mode)
                and socket_metadata.st_uid == os.geteuid(),
                "prior-boot adb endpoint changed type or owner",
            )
            socket_path.unlink()
        socket_directory.rmdir()
    try:
        repository_metadata = receipt.repository_root.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise AndroidCommandError(
            f"cannot inspect the prior-boot recovery repository root: {exc}"
        ) from exc
    if not (
        stat.S_ISDIR(repository_metadata.st_mode)
        and (not receipt.repository_root.is_symlink())
    ):
        return
    run_root = (
        receipt.repository_root
        / "target"
        / runtime_state.RUNS_ROOT_LEAF
        / receipt.run_id
    )
    try:
        run_root_metadata = run_root.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise AndroidCommandError(
            f"cannot inspect the prior-boot recovery run root: {exc}"
        ) from exc
    if not (
        stat.S_ISDIR(run_root_metadata.st_mode)
        and (not run_root.is_symlink())
        and (run_root_metadata.st_uid == os.geteuid())
        and (stat.S_IMODE(run_root_metadata.st_mode) == 448)
        and (
            (run_root_metadata.st_dev, run_root_metadata.st_ino)
            == (receipt.run_root_device, receipt.run_root_inode)
        )
    ):
        return
    layout = runtime_state.AndroidRunLayout(
        run_id=receipt.run_id,
        root=run_root,
        work=run_root / "work",
        proof=run_root / "proof",
        capability=run_root / "work" / runtime_state.CAPABILITY_LEAF,
        signed_apk=run_root / "proof" / runtime_state.SIGNED_APK_LEAF,
    )
    runtime_state.retire_recovery_capability(layout, receipt)


def _current_boot_origin_is_missing(receipt: runtime_state.OwnedRuntimeReceipt) -> bool:
    """Distinguish an absent checkout/run from a changed existing identity."""
    try:
        repository_metadata = receipt.repository_root.lstat()
    except FileNotFoundError:
        return True
    except OSError as exc:
        raise AndroidCommandError(
            f"cannot inspect the recovery repository root: {exc}"
        ) from exc
    _require(
        stat.S_ISDIR(repository_metadata.st_mode)
        and (not receipt.repository_root.is_symlink()),
        "owned runtime recovery repository root changed type",
    )
    run_root = (
        receipt.repository_root
        / "target"
        / runtime_state.RUNS_ROOT_LEAF
        / receipt.run_id
    )
    try:
        run_metadata = run_root.lstat()
    except FileNotFoundError:
        return True
    except OSError as exc:
        raise AndroidCommandError(
            f"cannot inspect the recovery run root: {exc}"
        ) from exc
    _require(
        stat.S_ISDIR(run_metadata.st_mode)
        and (not run_root.is_symlink())
        and (run_metadata.st_uid == os.geteuid())
        and (stat.S_IMODE(run_metadata.st_mode) == 448)
        and (
            (run_metadata.st_dev, run_metadata.st_ino)
            == (receipt.run_root_device, receipt.run_root_inode)
        ),
        "owned runtime recovery run-root identity changed",
    )
    return False


def _finish_missing_origin_current_boot(
    receipt: runtime_state.OwnedRuntimeReceipt,
) -> None:
    """Narrowly retire account/socket state without protocol or PID signalling."""
    if receipt.emulator_started:
        _require(
            _same_receipt_process(receipt) is None,
            "cannot retire a missing-origin receipt while its emulator is live",
        )
    if receipt.adb_server_started:
        _require(
            _same_receipt_adb_server_process(receipt) is None,
            "cannot retire a missing-origin receipt while its adb server is live",
        )
    run_root = (
        receipt.repository_root
        / "target"
        / runtime_state.RUNS_ROOT_LEAF
        / receipt.run_id
    )
    layout = runtime_state.AndroidRunLayout(
        run_id=receipt.run_id,
        root=run_root,
        work=run_root / "work",
        proof=run_root / "proof",
        capability=run_root / "work" / runtime_state.CAPABILITY_LEAF,
        signed_apk=run_root / "proof" / runtime_state.SIGNED_APK_LEAF,
    )
    capability = _recovery_adb_capability(layout, receipt)
    _require(
        not request_owned_adb_stop(layout, capability, receipt),
        "missing-origin cleanup unexpectedly requested an adb protocol stop",
    )
    finalize_owned_adb_stop(capability, receipt)


def recover_owned_runtime() -> Literal["none", "stale-retired", "recovered"]:
    """Recover one prior SIGKILL orphan under the caller's stable lane lock."""
    runtime_state.validate_lane_lock_descriptor()
    runtime_state.cleanup_owned_runtime_receipt_staging_files()
    receipt = runtime_state.load_owned_runtime_receipt(missing_ok=True)
    if receipt is None:
        return "none"
    _require(
        receipt.uid == os.geteuid(),
        "owned runtime receipt belongs to a different account",
    )
    try:
        current_host_boot = host_boot_identity()
    except ProcessIdentityError as exc:
        raise AndroidCommandError(
            f"cannot verify runtime recovery host: {exc}"
        ) from exc
    _require(
        receipt.host_identity == current_host_boot.host,
        "owned runtime receipt belongs to a different host",
    )
    if receipt.boot_identity != current_host_boot.boot:
        _finish_previous_boot_resources(receipt)
        runtime_state.retire_owned_runtime_receipt(receipt)
        return "stale-retired"
    if _current_boot_origin_is_missing(receipt):
        _finish_missing_origin_current_boot(receipt)
        runtime_state.retire_owned_runtime_receipt(receipt)
        return "stale-retired"
    context = _validate_recovery_receipt(receipt, validate_active_emulator=False)
    layout = context.layout
    capability = context.capability
    if not receipt.emulator_started:
        _finish_recovery_resources(layout, capability, receipt)
        runtime_state.retire_owned_runtime_receipt(receipt)
        return "stale-retired"
    observed = _same_receipt_process(receipt)
    if observed is None:
        _finish_recovery_resources(layout, capability, receipt)
        runtime_state.retire_owned_runtime_receipt(receipt)
        return "stale-retired"
    active_context = _validate_recovery_receipt(receipt, validate_active_emulator=True)
    _request_verified_owned_emulator_stop(active_context, receipt)
    _wait_for_recovered_emulator_exit(receipt)
    _finish_recovery_resources(layout, capability, receipt)
    runtime_state.retire_owned_runtime_receipt(receipt)
    return "recovered"


def _stopped_owned_runtime_receipt(run_id: str) -> runtime_state.OwnedRuntimeReceipt:
    """Return the exact receipt only after every owned runtime resource is gone."""

    runtime_state.validate_lane_lock_descriptor()
    receipt = runtime_state.load_owned_runtime_receipt()
    _require(receipt is not None, "owned runtime receipt is missing")
    _require(
        receipt.run_id == runtime_state.canonical_run_id(run_id),
        "owned runtime receipt belongs to a different run",
    )
    context = _validate_recovery_receipt(receipt, validate_active_emulator=False)
    _require(
        context.current_boot,
        "runtime retirement cannot retire a prior-boot receipt",
    )
    if receipt.emulator_started:
        _require(
            _same_receipt_process(receipt) is None,
            "cannot retire an owned runtime receipt while its process is still live",
        )
    if receipt.adb_server_started:
        _require(
            _same_receipt_adb_server_process(receipt) is None,
            "cannot retire an owned runtime receipt while its adb server is still live",
        )
    socket_path = pathlib.Path(context.capability.socket_path)
    _require(
        not os.path.lexists(socket_path)
        and (not os.path.lexists(context.layout.capability))
        and (not os.path.lexists(context.capability.adb_snapshot_path)),
        "cannot retire an owned runtime receipt while private adb resources remain",
    )
    socket_directory = socket_path.parent
    _require(
        not os.path.lexists(socket_directory),
        "cannot retire an owned runtime receipt while its private adb directory remains",
    )
    return receipt


def retire_stopped_owned_runtime(run_id: str) -> None:
    """Retire a successful normal-run receipt with complete cleanup evidence."""

    receipt = _stopped_owned_runtime_receipt(run_id)
    if receipt.device_kind == "emulator":
        runtime_state.record_post_cleanup_adb_isolation_checkpoint(receipt)
    runtime_state.retire_owned_runtime_receipt(receipt)


def retire_failed_stopped_owned_runtime(
    run_id: str,
    primary_exit_status: int,
) -> None:
    """Retire a failed run without manufacturing successful cleanup checkpoints."""

    _require(
        type(primary_exit_status) is int and 1 <= primary_exit_status <= 255,
        "failed runtime retirement requires a nonzero primary exit status",
    )
    receipt = _stopped_owned_runtime_receipt(run_id)
    runtime_state.retire_owned_runtime_receipt(receipt)


def owned_emulator_backend_identity(run_id: str) -> str:
    """Return the pre-exec backend inode and digest bound by this run's receipt."""
    runtime_state.validate_lane_lock_descriptor()
    receipt = runtime_state.load_owned_runtime_receipt()
    _require(receipt is not None, "owned runtime receipt is missing")
    _require(
        receipt.run_id == runtime_state.canonical_run_id(run_id),
        "owned runtime receipt belongs to a different run",
    )
    return f"{receipt.backend_device}:{receipt.backend_inode}:{receipt.backend_sha256}"


def record_adb_isolation_checkpoint(
    run_id: str, checkpoint: AdbIsolationCheckpoint
) -> pathlib.Path:
    """Durably record one admitted non-final isolation checkpoint."""

    _require(
        checkpoint
        in {
            AdbIsolationCheckpoint.EMULATOR_POST_REGISTRATION,
            AdbIsolationCheckpoint.RUNTIME_PRE_CLEANUP,
        },
        "checkpoint is not exposed by the bounded isolation action",
    )
    return runtime_state.record_adb_isolation_checkpoint(run_id, checkpoint)


def _registered_private_adb_evidence(
    layout: runtime_state.AndroidRunLayout,
    capability: runtime_state.AndroidCommandCapability,
    receipt: runtime_state.OwnedRuntimeReceipt,
) -> dict[str, str]:
    status = read_regular_snapshot(
        layout.proof / "adb-server-status-registered.txt",
        maximum=65536,
        label="registered private adb server status",
        validate_metadata=runtime_state.private_file_metadata,
    )
    listener = read_regular_snapshot(
        layout.proof / "adb-listener-registered.txt",
        maximum=65536,
        label="registered private adb listener snapshot",
        validate_metadata=runtime_state.private_file_metadata,
    )
    try:
        status_fields = parse_owned_adb_server_status(status.data.decode("utf-8"))
        listener_text = listener.data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AndroidCommandError(
            "registered private adb evidence is not UTF-8"
        ) from exc
    _require(
        status_fields["executable_absolute_path"] == str(capability.adb_snapshot_path)
        and status_fields["keystore_path"] == str(capability.vendor_key)
        and status_fields["mdns_enabled"] is False,
        "registered private adb server status differs from this run",
    )
    try:
        observation = parse_owned_single_listener(
            listener_text,
            expected_pid=receipt.adb_server_pid,
            expected_uid=receipt.uid,
            expected_endpoint=capability.socket_path,
            dialect=runtime_state.owned_unix_listener_dialect(
                receipt.adb_profile
            ),
            expected_listener_descriptor=receipt.adb_listener_descriptor,
        )
    except AndroidEmulatorControlError as exc:
        raise AndroidCommandError(str(exc)) from exc
    _require(
        receipt.adb_server_process_identity is not None
        and receipt.adb_listener_descriptor is not None
        and observation.listener_descriptor == receipt.adb_listener_descriptor,
        "registered private adb receipt lacks its bound listener identity",
    )
    return {
        "identity_sha256": hashlib.sha256(
            receipt.adb_server_process_identity.encode("ascii")
        ).hexdigest(),
        "server_status_sha256": status.sha256,
        "listener_snapshot_sha256": listener.sha256,
        "listener_descriptor_sha256": hashlib.sha256(
            str(receipt.adb_listener_descriptor).encode("ascii")
        ).hexdigest(),
        "adb_profile": receipt.adb_profile,
    }


def _validate_emulator_execution_routing(
    execution: ProcessExecutionSnapshot,
    *,
    receipt: runtime_state.OwnedRuntimeReceipt,
    capability: runtime_state.AndroidCommandCapability,
) -> str:
    _require(
        execution.identity.token == receipt.process_identity
        and execution.identity.pid == receipt.pid
        and execution.identity.uid == receipt.uid,
        "owned emulator process identity changed before routing receipt",
    )
    _require(
        execution.identity.executable == receipt.backend_path,
        "owned emulator has not reached its receipt-bound backend",
    )
    expected_environment = _emulator_environment(capability)
    _require(
        all(
            execution.environment.get(name) == value
            for name, value in expected_environment.items()
        ),
        "owned emulator routing environment projection differs",
    )
    forbidden_routing_names = sorted(
        name
        for name in execution.environment
        if (
            name.startswith("ADB_") or name.startswith("ANDROID_ADB_")
        )
        and name not in expected_environment
    )
    _require(
        not forbidden_routing_names,
        "owned emulator inherited forbidden adb routing variables: "
        + ", ".join(forbidden_routing_names),
    )
    forbidden_avd_selector_names = sorted(
        FORBIDDEN_EMULATOR_AVD_SELECTOR_ENVIRONMENT
        & execution.environment.keys()
    )
    _require(
        not forbidden_avd_selector_names,
        "owned emulator inherited forbidden AVD selector variables: "
        + ", ".join(forbidden_avd_selector_names),
    )
    _require(
        execution.argv.count("-no-direct-adb") == 1,
        "owned emulator lacks native direct-adb suppression",
    )
    try:
        adb_path_index = execution.argv.index("-adb-path")
    except ValueError as exc:
        raise AndroidCommandError(
            "owned emulator lacks its external adb path"
        ) from exc
    _require(
        execution.argv.count("-adb-path") == 1
        and execution.argv.index("-no-direct-adb") < adb_path_index
        and adb_path_index + 1 < len(execution.argv)
        and execution.argv[adb_path_index + 1] == str(capability.adb_snapshot_path),
        "owned emulator external adb route differs",
    )
    return emulator_routing_environment_sha256(expected_environment)


def record_owned_emulator_routing(run_id: str) -> pathlib.Path:
    """Verify the live child and publish its raw-value-omitting route receipt."""

    runtime_state.validate_lane_lock_descriptor()
    layout = runtime_state.AndroidRunLayout.from_run_id(run_id)
    capability = runtime_state.load_capability(layout.run_id)
    receipt = runtime_state.load_owned_runtime_receipt()
    _require(
        receipt is not None
        and receipt.run_id == layout.run_id
        and receipt.phase is runtime_state.RuntimePhase.EMULATOR_CHILD_REGISTERED
        and receipt.native_adb_notifier_port == NATIVE_ADB_NOTIFIER_PORT,
        "emulator routing lacks this run's registered child receipt",
    )
    _require(
        capability.device_kind == "emulator"
        and capability.native_adb_notifier_port == NATIVE_ADB_NOTIFIER_PORT,
        "emulator routing lacks its capability",
    )
    _validate_adb(layout, capability)
    _validate_owned_adb_server_for_client(capability)
    _require(receipt.pid is not None, "emulator routing receipt lacks its child pid")
    try:
        before = execution_snapshot(receipt.pid)
    except ProcessIdentityError as exc:
        raise AndroidCommandError(
            f"cannot inspect owned emulator routing: {exc}"
        ) from exc
    environment_sha256 = _validate_emulator_execution_routing(
        before,
        receipt=receipt,
        capability=capability,
    )
    private_adb = _registered_private_adb_evidence(
        layout,
        capability,
        receipt,
    )
    _require(
        set(private_adb) == EMULATOR_ROUTING_PRIVATE_ADB_FIELDS,
        "emulator routing private adb fields changed",
    )
    try:
        after = execution_snapshot(receipt.pid)
    except ProcessIdentityError as exc:
        raise AndroidCommandError(
            f"cannot recheck owned emulator routing: {exc}"
        ) from exc
    _require(
        after == before,
        "owned emulator routing changed while its receipt was created",
    )
    _validate_owned_adb_server_for_client(capability)
    return runtime_state.record_emulator_routing_receipt(
        layout.run_id,
        adb_snapshot_sha256=capability.adb_sha256,
        routing_environment_sha256=environment_sha256,
        private_adb=private_adb,
    )


def exec_server(run_id: str) -> NoReturn:
    runtime_state.validate_lane_lock_descriptor()
    layout = runtime_state.AndroidRunLayout.from_run_id(run_id)
    prior_receipt = runtime_state.load_owned_runtime_receipt()
    _require(prior_receipt is not None, "runtime recovery receipt is missing")
    capability = runtime_state.load_capability(layout.run_id)
    _validate_server_environment(capability)
    _validate_adb(layout, capability)
    try:
        identity = process_snapshot(os.getpid())
    except ProcessIdentityError as exc:
        raise AndroidCommandError(
            f"cannot identify the adb server exec process: {exc}"
        ) from exc
    initial_device, initial_inode = _executable_file_identity(
        identity.executable, "adb server initial executable"
    )
    adb_device, adb_inode = _executable_file_identity(
        capability.adb_snapshot_path, "Android adb snapshot"
    )
    runtime_state.register_adb_child(
        prior_receipt,
        runtime_state.AdbChildRegistration(
            process=identity,
            initial_executable_device=initial_device,
            initial_executable_inode=initial_inode,
            adb_snapshot_device=adb_device,
            adb_snapshot_inode=adb_inode,
        ),
    )
    argv = [str(capability.adb_snapshot_path), "-L", capability.server_socket]
    if capability.device_kind == "physical":
        argv.extend(("--one-device", capability.expected_serial))
    argv.extend(("server", "nodaemon"))
    try:
        runtime_state.arm_lane_lock_close_on_exec()
        _close_nonstandard_descriptors(preserve_lane_lock=True)
        os.execve(
            str(capability.adb_snapshot_path), argv, _server_environment(capability)
        )
    except OSError as exc:
        raise AndroidCommandError(f"cannot start the owned adb server: {exc}") from exc


def wait_owned_emulator_backend(*, run_id: str, timeout_seconds: int) -> str:
    """Wait for this run's registered emulator child to reach its fixed backend."""
    runtime_state.validate_lane_lock_descriptor()
    layout = runtime_state.AndroidRunLayout.from_run_id(run_id)
    _require(
        type(timeout_seconds) is int and 1 <= timeout_seconds <= 30,
        "owned emulator backend timeout must be 1 through 30 seconds",
    )
    try:
        controller = process_snapshot(os.getpid())
    except ProcessIdentityError as exc:
        raise AndroidCommandError(
            f"cannot identify the Android control interpreter: {exc}"
        ) from exc
    deadline = time.monotonic() + timeout_seconds
    observed_stage = -1
    while True:
        receipt = runtime_state.load_owned_runtime_receipt()
        _require(receipt is not None, "runtime recovery receipt is missing")
        _require(
            receipt.run_id == layout.run_id,
            "runtime recovery receipt belongs to another emulator spawn",
        )
        if receipt.phase is runtime_state.RuntimePhase.ADB_SEALED:
            remaining = deadline - time.monotonic()
            _require(
                remaining > 0,
                "spawned emulator child did not advance its recovery receipt",
            )
            time.sleep(min(0.02, remaining))
            continue
        _require(
            receipt.phase is runtime_state.RuntimePhase.EMULATOR_CHILD_REGISTERED
            and receipt.pid is not None
            and receipt.process_identity is not None,
            "runtime receipt is not this run's registered emulator child",
        )
        context = _validate_recovery_receipt(receipt)
        _require(
            context.layout == layout
            and receipt.launcher_path is not None
            and receipt.backend_path is not None,
            "emulator backend receipt belongs to a different repository run",
        )
        stages = (controller.executable, receipt.launcher_path, receipt.backend_path)
        _require(
            len(set(stages)) == len(stages),
            "emulator control interpreter, launcher, and backend must differ",
        )
        observed = _same_receipt_process(receipt)
        _require(observed is not None, "spawned emulator child exited before backend exec")
        try:
            current_stage = stages.index(observed.executable)
        except ValueError as exc:
            raise AndroidCommandError(
                "spawned emulator child execed an unexpected executable"
            ) from exc
        _require(
            current_stage >= observed_stage,
            "spawned emulator executable regressed during backend transition",
        )
        observed_stage = current_stage
        if observed.executable == receipt.backend_path:
            current = runtime_state.load_owned_runtime_receipt()
            _require(
                current is not None
                and current.snapshot_sha256 == receipt.snapshot_sha256,
                "emulator receipt changed during backend transition",
            )
            confirmed_context = _validate_recovery_receipt(current)
            _require(
                confirmed_context.layout == layout
                and confirmed_context.backend == receipt.backend_path,
                "emulator backend identity changed during backend transition",
            )
            confirmed = _same_receipt_process(current)
            _require(
                confirmed is not None
                and confirmed.token == observed.token
                and confirmed.executable == receipt.backend_path,
                "emulator identity changed at the backend transition",
            )
            _require(
                time.monotonic() <= deadline,
                "spawned emulator child reached its fixed backend after the deadline",
            )
            return confirmed.token
        remaining = deadline - time.monotonic()
        _require(
            remaining > 0,
            "spawned emulator child did not reach its fixed backend",
        )
        time.sleep(min(0.05, remaining))


def wait_owned_adb_server_start(*, run_id: str, timeout_seconds: int) -> str:
    """Wait until this run's exact adb child durably advances its receipt."""
    runtime_state.validate_lane_lock_descriptor()
    layout = runtime_state.AndroidRunLayout.from_run_id(run_id)
    _require(
        type(timeout_seconds) is int and 1 <= timeout_seconds <= 15,
        "owned adb startup handshake timeout must be 1 through 15 seconds",
    )
    deadline = time.monotonic() + timeout_seconds
    while True:
        receipt = runtime_state.load_owned_runtime_receipt()
        _require(receipt is not None, "runtime recovery receipt is missing")
        _require(
            receipt.run_id == layout.run_id,
            "runtime recovery receipt belongs to another server spawn",
        )
        if receipt.adb_server_started:
            context = _validate_recovery_receipt(
                receipt, validate_active_emulator=False
            )
            _require(
                context.layout == layout,
                "adb server receipt belongs to a different repository run",
            )
            observed = _same_receipt_adb_server_process(receipt)
            _require(
                observed is not None,
                "spawned adb server child exited after its receipt advance",
            )
            capability = context.capability
            _validate_receipt_adb_server_executable(receipt, capability, observed)
            current = runtime_state.load_owned_runtime_receipt()
            _require(
                current is not None
                and current.snapshot_sha256 == receipt.snapshot_sha256,
                "adb server receipt changed during startup handoff",
            )
            confirmed_context = _validate_recovery_receipt(
                current, validate_active_emulator=False
            )
            _require(
                confirmed_context.layout == layout,
                "adb server recovery context changed during startup handoff",
            )
            confirmed = _same_receipt_adb_server_process(current)
            _require(
                confirmed is not None
                and confirmed.token == observed.token
                and confirmed.executable == observed.executable,
                "adb server identity changed during startup handoff",
            )
            _validate_receipt_adb_server_executable(
                current, confirmed_context.capability, confirmed
            )
            _require(
                time.monotonic() <= deadline,
                "spawned adb server child advanced its recovery receipt after the deadline",
            )
            return confirmed.token
        remaining = deadline - time.monotonic()
        _require(
            remaining > 0,
            "spawned adb server child did not advance its recovery receipt",
        )
        time.sleep(min(0.02, remaining))


def _output_directory(layout: runtime_state.AndroidRunLayout, root: OutputRoot) -> int:
    return runtime_state.open_private_directory(
        layout.work if root is OutputRoot.WORK else layout.proof,
        f"Android {root.value}",
    )


def _write_operation(
    layout: runtime_state.AndroidRunLayout,
    capability: runtime_state.AndroidCommandCapability,
    spec: OperationSpec,
    argv: tuple[str, ...],
    timeout_seconds: int,
) -> BoundedResult:
    output = spec.output
    if output is None:
        _fail("Android write operation lacks a fixed output")
    directory_fd = _output_directory(layout, output.root)
    primary: BaseException | None = None
    try:
        return write_stdout_at(
            argv,
            output_directory_fd=directory_fd,
            output_name=output.leaf,
            timeout_seconds=timeout_seconds,
            maximum_bytes=output.maximum_bytes,
            environment=_client_environment(capability),
        )
    except BaseException as exc:
        primary = exc
        raise
    finally:
        runtime_state.close_descriptor(
            directory_fd, label="the Android output directory", primary=primary
        )


def _parse_remote_base_apk_output(output: bytes) -> str:
    try:
        text = output.decode("utf-8").replace("\r", "")
    except UnicodeDecodeError as exc:
        raise AndroidCommandError(
            f"installed Android package path is not UTF-8: {exc}"
        ) from exc
    lines = text.splitlines()
    _require(
        len(lines) == 1 and lines[0].startswith("package:"),
        "installed Android package path is ambiguous",
    )
    remote = runtime_state.canonical_ascii_atom(
        lines[0][len("package:") :],
        characters=_REMOTE_PATH_CHARACTERS,
        minimum=len("/a/base.apk"),
        maximum=4096,
        label="installed Android base APK path",
    )
    _require(
        REMOTE_BASE_APK.fullmatch(remote) is not None,
        "installed Android base APK path is unsafe",
    )
    _require(
        all(part not in {".", ".."} for part in pathlib.PurePosixPath(remote).parts),
        "installed Android base APK path is non-canonical",
    )
    return remote


def _remaining_observation_timeout(deadline: float) -> int | None:
    remaining = deadline - time.monotonic()
    if remaining < 1:
        return None
    return min(15, int(remaining))


def _remove_installed_apk_copy(layout: runtime_state.AndroidRunLayout) -> None:
    directory_fd = _output_directory(layout, OutputRoot.WORK)
    primary: BaseException | None = None
    try:
        try:
            metadata = os.stat(
                INSTALLED_APK_COPY_LEAF,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return
        _require(
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and metadata.st_nlink == 1
            and stat.S_IMODE(metadata.st_mode) == 0o600,
            "installed Android smoke APK copy is not one private regular file",
        )
        os.unlink(INSTALLED_APK_COPY_LEAF, dir_fd=directory_fd)
        os.fsync(directory_fd)
    except BaseException as exc:
        primary = exc
        raise
    finally:
        runtime_state.close_descriptor(
            directory_fd, label="the Android work directory", primary=primary
        )


def _capture_installed_apk_path(
    capability: runtime_state.AndroidCommandCapability,
    *,
    timeout_seconds: int,
) -> tuple[BoundedResult, str | None]:
    try:
        result = capture_stdout(
            _device(capability, "shell", "pm", "path", PACKAGE),
            timeout_seconds=timeout_seconds,
            maximum_bytes=65536,
            stderr=subprocess.STDOUT,
            environment=_client_environment(capability),
        )
    except BoundedProcessError as exc:
        if exc.kind != "timeout":
            raise
        return BoundedResult(1), None
    if result.returncode != 0 or not result.stdout:
        return result, None
    return result, _parse_remote_base_apk_output(result.stdout)


def _observe_installed_apk(
    layout: runtime_state.AndroidRunLayout,
    capability: runtime_state.AndroidCommandCapability,
    *,
    timeout_seconds: int,
) -> BoundedResult:
    """Observe one path-stable installed APK without accepting non-exact bytes."""

    deadline = time.monotonic() + timeout_seconds
    _remove_installed_apk_copy(layout)

    before_timeout = _remaining_observation_timeout(deadline)
    if before_timeout is None:
        return BoundedResult(
            0,
            f"retryable:{InstalledApkRetryReason.DEADLINE_EXHAUSTED.value}\n".encode(
                "ascii"
            ),
        )
    before_result, before_path = _capture_installed_apk_path(
        capability, timeout_seconds=before_timeout
    )
    if before_result.returncode != 0 or before_path is None:
        return BoundedResult(
            0,
            f"retryable:{InstalledApkRetryReason.PACKAGE_UNAVAILABLE.value}\n".encode(
                "ascii"
            ),
        )

    pull_timeout = _remaining_observation_timeout(deadline)
    if pull_timeout is None:
        return BoundedResult(
            0,
            f"retryable:{InstalledApkRetryReason.DEADLINE_EXHAUSTED.value}\n".encode(
                "ascii"
            ),
        )
    pull_spec = OperationSpec(
        "write",
        pull_timeout,
        pull_timeout,
        OutputSpec(
            OutputRoot.WORK,
            INSTALLED_APK_COPY_LEAF,
            capability.signed_apk_size,
        ),
        lambda cap: (),
    )
    try:
        pull_result = _write_operation(
            layout,
            capability,
            pull_spec,
            _device(capability, "exec-out", "cat", before_path),
            pull_timeout,
        )
    except BoundedProcessError as exc:
        if exc.kind != "timeout":
            raise
        _remove_installed_apk_copy(layout)
        return BoundedResult(
            0,
            f"retryable:{InstalledApkRetryReason.PULL_FAILED.value}\n".encode("ascii"),
        )
    if pull_result.returncode != 0:
        _remove_installed_apk_copy(layout)
        return BoundedResult(
            0,
            f"retryable:{InstalledApkRetryReason.PULL_FAILED.value}\n".encode("ascii"),
        )

    after_timeout = _remaining_observation_timeout(deadline)
    if after_timeout is None:
        _remove_installed_apk_copy(layout)
        return BoundedResult(
            0,
            f"retryable:{InstalledApkRetryReason.DEADLINE_EXHAUSTED.value}\n".encode(
                "ascii"
            ),
        )
    after_result, after_path = _capture_installed_apk_path(
        capability, timeout_seconds=after_timeout
    )
    if after_result.returncode != 0 or after_path is None:
        _remove_installed_apk_copy(layout)
        return BoundedResult(
            0,
            f"retryable:{InstalledApkRetryReason.PACKAGE_UNAVAILABLE.value}\n".encode(
                "ascii"
            ),
        )
    if after_path != before_path:
        _remove_installed_apk_copy(layout)
        return BoundedResult(
            0,
            f"retryable:{InstalledApkRetryReason.PATH_CHANGED.value}\n".encode("ascii"),
        )

    observed = consume_regular_snapshot(
        layout.work / INSTALLED_APK_COPY_LEAF,
        maximum=runtime_state.MAX_APK_BYTES,
        label="installed Android smoke APK copy",
        validate_metadata=runtime_state.private_file_metadata,
    )
    if not (
        observed.size == capability.signed_apk_size
        and observed.sha256 == capability.signed_apk_sha256
    ):
        _remove_installed_apk_copy(layout)
        return BoundedResult(
            0,
            f"retryable:{InstalledApkRetryReason.BYTES_MISMATCH.value}\n".encode(
                "ascii"
            ),
        )
    path_sha256 = hashlib.sha256(before_path.encode("ascii")).hexdigest()
    if _remaining_observation_timeout(deadline) is None:
        _remove_installed_apk_copy(layout)
        return BoundedResult(
            0,
            f"retryable:{InstalledApkRetryReason.DEADLINE_EXHAUSTED.value}\n".encode(
                "ascii"
            ),
        )
    return BoundedResult(0, f"exact:{path_sha256}\n".encode("ascii"))


def _invoke_installed_apk_observation(
    layout: runtime_state.AndroidRunLayout,
    capability: runtime_state.AndroidCommandCapability,
    *,
    timeout_seconds: int,
) -> BoundedResult:
    """Run the composite observation and preserve both primary and cleanup failures."""

    result: BoundedResult | None = None
    primary: BaseException | None = None
    try:
        result = _observe_installed_apk(
            layout, capability, timeout_seconds=timeout_seconds
        )
    except BaseException as exc:
        primary = exc
    try:
        _validate_owned_adb_server_for_client(capability)
    except BaseException as postcheck_error:
        if primary is None:
            primary = postcheck_error
        else:
            primary.add_note(
                "owned adb server post-observation validation also failed: "
                f"{postcheck_error}"
            )

    keep_copy = (
        primary is None
        and result is not None
        and re.fullmatch(b"exact:[0-9a-f]{64}\n", result.stdout) is not None
    )
    if not keep_copy:
        try:
            _remove_installed_apk_copy(layout)
        except BaseException as cleanup_error:
            if primary is None:
                primary = cleanup_error
            else:
                primary.add_note(
                    "removing the rejected installed-APK copy also failed: "
                    f"{cleanup_error}"
                )
    if primary is not None:
        raise primary
    _require(result is not None, "installed Android APK observation produced no result")
    return result


def _observe_package_state(
    capability: runtime_state.AndroidCommandCapability,
    spec: OperationSpec,
    *,
    timeout_seconds: int,
) -> BoundedResult:
    """Map the fixed raw package query to one exact, non-diagnostic token."""

    try:
        raw = capture_stdout(
            spec.build_argv(capability),
            timeout_seconds=timeout_seconds,
            maximum_bytes=65536,
            stderr=subprocess.STDOUT,
            environment=_client_environment(capability),
        )
    except BoundedProcessError as exc:
        if exc.kind != "timeout" or getattr(exc, "__notes__", None):
            raise
        return BoundedResult(0, f"{PackageState.QUERY_TIMEOUT.value}\n".encode("ascii"))
    if raw.returncode != 0:
        return BoundedResult(0, f"{PackageState.QUERY_NONZERO.value}\n".encode("ascii"))
    if b"\x00" in raw.stdout or b"\r" in raw.stdout:
        _fail("Android package-state output contains a forbidden control character")
    try:
        text = raw.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AndroidCommandError(
            f"Android package-state output is not UTF-8: {exc}"
        ) from exc
    if text == "":
        state = PackageState.ABSENT
    elif text == f"package:{PACKAGE}\n":
        state = PackageState.PRESENT
    else:
        _fail("Android package-state output is malformed")
    return BoundedResult(0, f"{state.value}\n".encode("ascii"))


def _invoke_package_state(
    capability: runtime_state.AndroidCommandCapability,
    spec: OperationSpec,
    *,
    timeout_seconds: int,
) -> BoundedResult:
    """Run one typed package query and preserve primary/postcheck attribution."""

    result: BoundedResult | None = None
    primary: BaseException | None = None
    try:
        result = _observe_package_state(
            capability,
            spec,
            timeout_seconds=timeout_seconds,
        )
    except BaseException as exc:
        primary = exc
    try:
        _validate_owned_adb_server_for_client(capability)
    except BaseException as postcheck_error:
        if primary is None:
            primary = postcheck_error
        else:
            primary.add_note(
                "owned adb server post-package-state validation also failed: "
                f"{postcheck_error}"
            )
    if primary is not None:
        raise primary
    _require(result is not None, "Android package-state observation produced no result")
    return result


def _device_epoch(layout: runtime_state.AndroidRunLayout) -> str:
    snapshot = read_regular_snapshot(
        layout.proof / "adb-device-time.txt",
        maximum=4096,
        label="Android logcat start time",
        validate_metadata=runtime_state.private_file_metadata,
    )
    try:
        raw_value = snapshot.data.decode("ascii").replace("\r", "").strip()
    except UnicodeDecodeError as exc:
        raise AndroidCommandError(
            f"Android logcat start time is not ASCII: {exc}"
        ) from exc
    value = runtime_state.canonical_ascii_atom(
        raw_value,
        characters=_EPOCH_CHARACTERS,
        minimum=14,
        maximum=17,
        label="Android logcat start time",
    )
    _require(
        DEVICE_EPOCH.fullmatch(value) is not None,
        "Android logcat start time is non-canonical",
    )
    return value


def invoke_operation(
    operation: AndroidOperation, *, run_id: str, timeout_seconds: int | None = None
) -> BoundedResult:
    layout = runtime_state.AndroidRunLayout.from_run_id(run_id)
    capability = runtime_state.load_capability(layout.run_id)
    _validate_client_environment(capability)
    _validate_tool_and_apk(layout, capability, operation)
    spec = OPERATION_SPECS[operation]
    if spec.requires_private_server:
        _validate_owned_adb_server_for_client(capability)
    timeout = spec.timeout_seconds if timeout_seconds is None else timeout_seconds
    _require(
        type(timeout) is int and 1 <= timeout <= spec.timeout_maximum,
        f"{operation.value} timeout must be 1 through {spec.timeout_maximum} seconds",
    )
    if spec.mode == "observe-apk":
        return _invoke_installed_apk_observation(
            layout, capability, timeout_seconds=timeout
        )
    if spec.mode == "package-state":
        return _invoke_package_state(
            capability,
            spec,
            timeout_seconds=timeout,
        )
    if spec.mode == "logcat":
        argv = _device(
            capability,
            "logcat",
            "-d",
            "-v",
            "tag",
            "-T",
            _device_epoch(layout),
            "-s",
            "QPeriaptSmoke:*",
            "*:S",
        )
        result = _write_operation(layout, capability, spec, argv, timeout)
        if spec.requires_private_server:
            _validate_owned_adb_server_for_client(capability)
        return result
    if spec.mode == "register-emulator":
        result = _register_owned_emulator(capability, timeout_seconds=timeout)
        _validate_owned_adb_server_for_client(capability)
        return result
    argv = spec.build_argv(capability)
    if spec.mode == "run":
        result = run(
            argv, timeout_seconds=timeout, environment=_client_environment(capability)
        )
        _validate_owned_adb_server_for_client(capability)
        return result
    if spec.mode == "capture":
        result = capture_stdout(
            argv,
            timeout_seconds=timeout,
            maximum_bytes=65536,
            stderr=subprocess.STDOUT if spec.stderr_to_stdout else None,
            environment=_client_environment(capability),
        )
        _validate_owned_adb_server_for_client(capability)
        return result
    if spec.mode == "write":
        result = _write_operation(layout, capability, spec, argv, timeout)
        if spec.requires_private_server:
            _validate_owned_adb_server_for_client(capability)
        return result
    _fail(f"unsupported Android command mode: {spec.mode}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    create = sub.add_parser("create-capability")
    create.add_argument(
        "--adb-profile",
        choices=["auto", *runtime_state.ADB_PROFILE_PATHS],
        default="auto",
    )
    create.add_argument("--socket-nonce", required=True)
    create.add_argument(
        "--device-kind", choices=["physical", "emulator"], required=True
    )
    create.add_argument("--expected-serial", required=True)
    create.add_argument("--run-id", required=True)
    create.add_argument("--signed-apk-size", required=True, type=int)
    create.add_argument("--signed-apk-sha256", required=True)
    invoke = sub.add_parser("invoke")
    invoke.add_argument(
        "operation", choices=[operation.value for operation in AndroidOperation]
    )
    invoke.add_argument("--run-id", required=True)
    invoke.add_argument("--timeout-seconds", type=int)
    emulator_listeners = sub.add_parser("capture-emulator-listeners")
    emulator_listeners.add_argument("--run-id", required=True)
    emulator_listeners.add_argument(
        "--timeout-seconds", required=True, type=int, choices=range(1, 6)
    )
    create_run = sub.add_parser("create-run")
    create_run.add_argument("--run-id", required=True)
    create_recovery = sub.add_parser("create-runtime-recovery")
    create_recovery.add_argument("--run-id", required=True)
    path = sub.add_parser("adb-path")
    path.add_argument(
        "--adb-profile",
        choices=["auto", *runtime_state.ADB_PROFILE_PATHS],
        default="auto",
    )
    capability_path = sub.add_parser("capability-adb-path")
    capability_path.add_argument("--run-id", required=True)
    server = sub.add_parser("server-nodaemon")
    server.add_argument("--run-id", required=True)
    wait_server = sub.add_parser("wait-owned-adb-server-start")
    wait_server.add_argument("--run-id", required=True)
    wait_server.add_argument(
        "--timeout-seconds", required=True, type=int, choices=range(1, 16)
    )
    wait_emulator = sub.add_parser("wait-owned-emulator-backend")
    wait_emulator.add_argument("--run-id", required=True)
    wait_emulator.add_argument(
        "--timeout-seconds", required=True, type=int, choices=range(1, 31)
    )
    emulator = sub.add_parser("emulator-nodaemon")
    emulator.add_argument("--run-id", required=True)
    emulator.add_argument(
        "--device-abi", required=True, choices=["arm64-v8a", "x86_64"]
    )
    runtime_avd = sub.add_parser("runtime-avd-name")
    runtime_avd.add_argument(
        "--adb-profile",
        choices=[*runtime_state.ADB_PROFILE_PATHS],
        required=True,
    )
    runtime_avd.add_argument(
        "--device-abi", required=True, choices=["arm64-v8a", "x86_64"]
    )
    sub.add_parser("avd-home-path")
    isolation = sub.add_parser("record-adb-isolation-checkpoint")
    isolation.add_argument("--run-id", required=True)
    isolation.add_argument(
        "--checkpoint",
        required=True,
        choices=[
            AdbIsolationCheckpoint.EMULATOR_POST_REGISTRATION.value,
            AdbIsolationCheckpoint.RUNTIME_PRE_CLEANUP.value,
        ],
    )
    routing = sub.add_parser("record-owned-emulator-routing")
    routing.add_argument("--run-id", required=True)
    sub.add_parser("lane-lock-path")
    sub.add_parser("recover-owned-runtime")
    seal_adb = sub.add_parser("seal-private-adb-directory")
    seal_adb.add_argument("--run-id", required=True)
    request_adb_stop = sub.add_parser("request-owned-adb-stop")
    request_adb_stop.add_argument("--run-id", required=True)
    request_emulator_stop = sub.add_parser("request-owned-emulator-stop")
    request_emulator_stop.add_argument("--run-id", required=True)
    finalize_adb_stop = sub.add_parser("finalize-owned-adb-stop")
    finalize_adb_stop.add_argument("--run-id", required=True)
    retire_runtime = sub.add_parser("retire-stopped-runtime")
    retire_runtime.add_argument("--run-id", required=True)
    retire_failed_runtime = sub.add_parser("retire-failed-runtime")
    retire_failed_runtime.add_argument("--run-id", required=True)
    retire_failed_runtime.add_argument(
        "--primary-exit-status",
        required=True,
        type=int,
        choices=range(1, 256),
    )
    backend_identity = sub.add_parser("owned-emulator-backend-identity")
    backend_identity.add_argument("--run-id", required=True)
    destroy = sub.add_parser("destroy-capability")
    destroy.add_argument("--run-id", required=True)
    destroy.add_argument("--missing-ok", action="store_true")
    return parser


def main(argv: list[str]) -> int:
    args = _build_parser().parse_args(argv)
    if args.action == "create-capability":
        create_capability_with_deferred_signals(
            adb_profile=args.adb_profile,
            socket_nonce=args.socket_nonce,
            device_kind=args.device_kind,
            expected_serial=args.expected_serial,
            run_id=args.run_id,
            signed_apk_size=args.signed_apk_size,
            signed_apk_sha256=args.signed_apk_sha256,
        )
        return 0
    if args.action == "create-run":
        layout = runtime_state.create_run_layout(args.run_id)
        print(layout.root)
        return 0
    if args.action == "create-runtime-recovery":
        runtime_state.create_runtime_recovery_receipt(args.run_id)
        print("ANDROID_RUNTIME_RECOVERY_RECEIPT_CREATED")
        return 0
    if args.action == "capture-emulator-listeners":
        identity = capture_owned_emulator_listeners(
            run_id=args.run_id,
            timeout_seconds=args.timeout_seconds,
        )
        print(identity)
        return 0
    if args.action == "adb-path":
        print(runtime_state.resolve_adb_profile(args.adb_profile))
        return 0
    if args.action == "lane-lock-path":
        runtime_state.ensure_account_state()
        print(runtime_state.lane_lock_path())
        return 0
    if args.action == "avd-home-path":
        runtime_state.ensure_account_state()
        print(runtime_state.avd_home_directory())
        return 0
    if args.action == "runtime-avd-name":
        print(runtime_state.runtime_avd_name(args.adb_profile, args.device_abi))
        return 0
    if args.action == "capability-adb-path":
        layout = runtime_state.AndroidRunLayout.from_run_id(args.run_id)
        capability = runtime_state.load_capability(layout.run_id)
        _validate_adb(layout, capability)
        print(capability.adb_snapshot_path)
        return 0
    if args.action == "destroy-capability":
        runtime_state.destroy_capability(run_id=args.run_id, missing_ok=args.missing_ok)
        return 0
    if args.action == "server-nodaemon":
        exec_server(args.run_id)
    if args.action == "wait-owned-adb-server-start":
        identity = wait_owned_adb_server_start(
            run_id=args.run_id,
            timeout_seconds=args.timeout_seconds,
        )
        print(identity)
        return 0
    if args.action == "wait-owned-emulator-backend":
        identity = wait_owned_emulator_backend(
            run_id=args.run_id,
            timeout_seconds=args.timeout_seconds,
        )
        print(identity)
        return 0
    if args.action == "emulator-nodaemon":
        exec_emulator(args.run_id, args.device_abi)
    if args.action == "record-adb-isolation-checkpoint":
        checkpoint = AdbIsolationCheckpoint(args.checkpoint)
        record_adb_isolation_checkpoint(args.run_id, checkpoint)
        print(
            "ANDROID_ADB_ISOLATION_CHECKPOINT_RECORDED "
            f"checkpoint={checkpoint.value}"
        )
        return 0
    if args.action == "record-owned-emulator-routing":
        record_owned_emulator_routing(args.run_id)
        print("ANDROID_OWNED_EMULATOR_ROUTING_RECORDED")
        return 0
    if args.action == "recover-owned-runtime":
        status = recover_owned_runtime().upper().replace("-", "_")
        print(f"ANDROID_OWNED_RUNTIME_RECOVERY_{status}")
        return 0
    if args.action == "seal-private-adb-directory":
        seal_private_adb_directory(args.run_id)
        print("ANDROID_PRIVATE_ADB_DIRECTORY_SEALED")
        return 0
    if args.action == "request-owned-adb-stop":
        request_normal_owned_adb_stop(args.run_id)
        print("ANDROID_OWNED_ADB_STOP_REQUESTED")
        return 0
    if args.action == "request-owned-emulator-stop":
        request_normal_owned_emulator_stop(args.run_id)
        print("ANDROID_OWNED_EMULATOR_STOP_REQUESTED")
        return 0
    if args.action == "finalize-owned-adb-stop":
        finalize_normal_owned_adb_stop(args.run_id)
        print("ANDROID_OWNED_ADB_STOP_FINALIZED")
        return 0
    if args.action == "retire-stopped-runtime":
        retire_stopped_owned_runtime(args.run_id)
        print("ANDROID_OWNED_RUNTIME_RECEIPT_RETIRED")
        return 0
    if args.action == "retire-failed-runtime":
        retire_failed_stopped_owned_runtime(
            args.run_id,
            args.primary_exit_status,
        )
        print(
            "ANDROID_FAILED_RUNTIME_RECEIPT_RETIRED "
            f"primary_exit_status={args.primary_exit_status}"
        )
        return 0
    if args.action == "owned-emulator-backend-identity":
        print(owned_emulator_backend_identity(args.run_id))
        return 0
    if args.action == "invoke":
        operation = AndroidOperation(args.operation)
        result = invoke_operation(
            operation, run_id=args.run_id, timeout_seconds=args.timeout_seconds
        )
        if result.stdout:
            view = memoryview(result.stdout)
            while view:
                written = os.write(sys.stdout.fileno(), view)
                view = view[written:]
        return result.returncode
    _fail(f"unsupported Android command action: {args.action}")


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (
        AndroidCommandError,
        runtime_state.AndroidRuntimeStateError,
        AndroidEmulatorControlError,
        BoundedProcessError,
        EvidenceIOError,
    ) as exc:
        print(f"error: Android bounded command: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
