#!/usr/bin/env python3
"""Run the Android evidence lane's finite adb/lsof operation set."""

from __future__ import annotations

import argparse
import dataclasses
import enum
import json
import os
import pathlib
import pwd
import re
import signal
import stat
import sys
from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Literal, NoReturn

from bounded_process import (
    BoundedProcessError,
    BoundedResult,
    capture_stdout,
    run,
    write_stdout_at,
)
from evidence_io import (
    EvidenceIOError,
    JsonObjectSnapshot,
    consume_regular_snapshot,
    load_json_object_snapshot,
    load_json_object_snapshot_at,
    read_regular_snapshot,
)


SCHEMA_VERSION = 2
KIND = "qperiapt.android_command_capability"
MAX_CAPABILITY_BYTES = 16 * 1024
MAX_TOOL_BYTES = 128 * 1024 * 1024
MAX_APK_BYTES = 512 * 1024 * 1024
PACKAGE = "dev.qperiapt.androidsmoke"
RESULT_TEXT_REMOTE = "files/qperiapt-android-device-result.txt"
RESULT_JSON_REMOTE = "files/qperiapt-android-device-result.json"

REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parent.parent
OUTPUT_ROOT = REPOSITORY_ROOT / "target" / "qperiapt-android-device-smoke"
WORK_ROOT = OUTPUT_ROOT / "work"
PROOF_ROOT = OUTPUT_ROOT / "proof"
CAPABILITY_LEAF = "android-command-capability.json"
CAPABILITY_PATH = WORK_ROOT / CAPABILITY_LEAF
SIGNED_APK_PATH = PROOF_ROOT / "qperiapt-android-smoke.apk"

HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
RUN_ID = re.compile(r"[0-9a-f]{32}")
SERIAL = re.compile(r"[A-Za-z0-9._:-]{1,128}")
SOCKET_NONCE = re.compile(r"[A-Za-z0-9]{8}")
REMOTE_BASE_APK = re.compile(r"/[A-Za-z0-9_./+=~:-]+/base\.apk")
DEVICE_EPOCH = re.compile(r"[1-9][0-9]{9,12}\.[0-9]{3}")

_CANONICAL_ASCII = MappingProxyType(
    {character: character for character in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._:/+=~-"}
)
_NONCE_CHARACTERS = frozenset("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_SERIAL_CHARACTERS = frozenset("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._:-")
_RUN_ID_CHARACTERS = frozenset("0123456789abcdef")
_REMOTE_PATH_CHARACTERS = frozenset(
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_./+=~:-"
)
_EPOCH_CHARACTERS = frozenset("0123456789.")

CAPABILITY_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "adb_profile",
        "adb_size",
        "adb_sha256",
        "socket_nonce",
        "device_kind",
        "expected_serial",
        "run_id",
        "signed_apk_size",
        "signed_apk_sha256",
    }
)

ACCOUNT_HOME = pathlib.Path(pwd.getpwuid(os.geteuid()).pw_dir)
ADB_PROFILE_PATHS: Mapping[str, pathlib.Path] = MappingProxyType(
    {
        "macos-account": ACCOUNT_HOME / "Library/Android/sdk/platform-tools/adb",
        "linux-account": ACCOUNT_HOME / "Android/Sdk/platform-tools/adb",
        "linux-system": pathlib.Path("/usr/local/lib/android/sdk/platform-tools/adb"),
        "linux-opt": pathlib.Path("/opt/android-sdk/platform-tools/adb"),
    }
)

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


class AndroidCommandError(RuntimeError):
    """The private Android command capability or requested operation is invalid."""


class AndroidOperation(str, enum.Enum):
    KILL_SERVER = "kill-server"
    LIST_DEVICES = "list-devices"
    LSOF_INITIAL = "lsof-initial"
    LSOF_BEFORE = "lsof-before"
    LSOF_AFTER = "lsof-after"
    SERVER_STATUS_BEFORE = "server-status-before"
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
    PACKAGE_LIST = "package-list"
    PACKAGE_PATH = "package-path"
    PULL_INSTALLED_APK = "pull-installed-apk"
    INSTALL_APK = "install-apk"
    UNINSTALL_APP = "uninstall-app"
    EMULATOR_KILL = "emulator-kill"
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
class AndroidCommandCapability:
    adb_profile: str
    adb_path: pathlib.Path
    adb_size: int
    adb_sha256: str
    socket_nonce: str
    server_socket: str
    socket_path: str
    vendor_key: pathlib.Path
    device_kind: Literal["physical", "emulator"]
    expected_serial: str
    run_id: str
    signed_apk_size: int
    signed_apk_sha256: str


@dataclasses.dataclass(frozen=True, slots=True)
class OutputSpec:
    root: OutputRoot
    leaf: str
    maximum_bytes: int


@dataclasses.dataclass(frozen=True, slots=True)
class OperationSpec:
    mode: Literal["run", "capture", "write", "pull-apk", "logcat"]
    timeout_seconds: int
    timeout_maximum: int
    output: OutputSpec | None
    build_argv: Callable[[AndroidCommandCapability], tuple[str, ...]]


def _fail(message: str) -> NoReturn:
    raise AndroidCommandError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _canonical_ascii_atom(
    value: object,
    *,
    characters: frozenset[str],
    minimum: int,
    maximum: int,
    label: str,
) -> str:
    """Rebuild an input from code-owned ASCII values after a finite allowlist."""

    _require(
        isinstance(value, str) and minimum <= len(value) <= maximum,
        f"{label} is malformed",
    )
    rebuilt: list[str] = []
    for character in value:
        canonical = _CANONICAL_ASCII.get(character)
        _require(
            canonical is not None and canonical in characters,
            f"{label} contains an unsupported character",
        )
        rebuilt.append(canonical)
    return "".join(rebuilt)


def _canonical_device_kind(value: object) -> Literal["physical", "emulator"]:
    if value == "physical":
        return "physical"
    if value == "emulator":
        return "emulator"
    _fail("Android device kind is invalid")


def _canonical_run_id(value: object) -> str:
    rebuilt = _canonical_ascii_atom(
        value,
        characters=_RUN_ID_CHARACTERS,
        minimum=32,
        maximum=32,
        label="Android run id",
    )
    _require(RUN_ID.fullmatch(rebuilt) is not None, "Android run id is invalid")
    return rebuilt


def _canonical_socket_nonce(value: object) -> str:
    rebuilt = _canonical_ascii_atom(
        value,
        characters=_NONCE_CHARACTERS,
        minimum=8,
        maximum=8,
        label="private adb socket nonce",
    )
    _require(
        SOCKET_NONCE.fullmatch(rebuilt) is not None,
        "private adb socket nonce is invalid",
    )
    return rebuilt


def _server_socket_identity(nonce: str) -> tuple[str, str]:
    socket_path = f"/tmp/qperiapt-adb.{nonce}/adb.sock"
    return f"localfilesystem:{socket_path}", socket_path


def _private_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise EvidenceIOError(
            "Android command capability must be one current-user-owned regular file with mode 0600"
        )


def _canonical_expected_serial(value: object, device_kind: str) -> str:
    rebuilt = _canonical_ascii_atom(
        value,
        characters=_SERIAL_CHARACTERS,
        minimum=1,
        maximum=128,
        label="Android serial",
    )
    _require(
        SERIAL.fullmatch(rebuilt) is not None and not rebuilt.startswith("-"),
        "Android serial is invalid",
    )
    if device_kind == "emulator":
        match = re.fullmatch(r"emulator-([0-9]{4})", rebuilt)
        _require(match is not None, "Android emulator serial is invalid")
        port = int(match.group(1))
        _require(
            5554 <= port <= 5584 and port % 2 == 0,
            "Android emulator serial is outside the owned AVD port range",
        )
    return rebuilt


def _executable_metadata(metadata: os.stat_result) -> None:
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o111 == 0:
        raise EvidenceIOError("Android command tool must be an executable regular file")


def _close_owned_descriptor(
    descriptor: int,
    *,
    label: str,
    primary: BaseException | None = None,
) -> None:
    try:
        os.close(descriptor)
    except BaseException as cleanup_error:
        if primary is not None:
            primary.add_note(f"closing {label} also failed: {cleanup_error}")
        elif isinstance(cleanup_error, Exception):
            raise AndroidCommandError(
                f"cannot close {label}: {cleanup_error}"
            ) from cleanup_error
        else:
            raise


def _canonical_concrete_adb_profile(profile: object) -> str:
    if profile == "macos-account":
        return "macos-account"
    if profile == "linux-account":
        return "linux-account"
    if profile == "linux-system":
        return "linux-system"
    if profile == "linux-opt":
        return "linux-opt"
    _fail("Android adb profile is unsupported")


def canonical_adb_profile(profile: object) -> str:
    if profile == "auto":
        available = [
            (name, path)
            for name, path in ADB_PROFILE_PATHS.items()
            if os.path.lexists(path) and os.access(path, os.X_OK)
        ]
        _require(
            len(available) == 1,
            "automatic Android adb selection requires exactly one fixed profile",
        )
        profile = available[0][0]
    return _canonical_concrete_adb_profile(profile)


def resolve_adb_profile(profile: object) -> pathlib.Path:
    return ADB_PROFILE_PATHS[canonical_adb_profile(profile)]


def _open_private_directory(path: pathlib.Path, label: str) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AndroidCommandError(f"cannot open {label} directory {path}: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        _require(
            stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and stat.S_IMODE(metadata.st_mode) == 0o700,
            f"{label} directory must be current-user-owned with mode 0700",
        )
    except BaseException as primary:
        _close_owned_descriptor(
            descriptor,
            label=f"rejected {label} directory",
            primary=primary,
        )
        raise
    return descriptor


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise AndroidCommandError("short write while creating Android command capability")
        view = view[written:]


def create_capability(
    *,
    adb_profile: str,
    socket_nonce: str,
    device_kind: str,
    expected_serial: str,
    run_id: str,
    signed_apk_size: int,
    signed_apk_sha256: str,
) -> None:
    validated_adb_profile = canonical_adb_profile(adb_profile)
    validated_adb_path = ADB_PROFILE_PATHS[validated_adb_profile]
    validated_socket_nonce = _canonical_socket_nonce(socket_nonce)
    validated_device_kind = _canonical_device_kind(device_kind)
    validated_serial = _canonical_expected_serial(
        expected_serial, validated_device_kind
    )
    validated_run_id = _canonical_run_id(run_id)
    _require(
        type(signed_apk_size) is int and 0 < signed_apk_size <= MAX_APK_BYTES,
        "signed Android APK size is invalid",
    )
    _require(
        HEX_SHA256.fullmatch(signed_apk_sha256) is not None,
        "signed Android APK digest is invalid",
    )
    adb_snapshot = consume_regular_snapshot(
        validated_adb_path,
        maximum=MAX_TOOL_BYTES,
        label="adb executable",
        validate_metadata=_executable_metadata,
    )
    apk_snapshot = consume_regular_snapshot(
        SIGNED_APK_PATH,
        maximum=MAX_APK_BYTES,
        label="signed Android smoke APK",
    )
    _require(
        apk_snapshot.size == signed_apk_size
        and apk_snapshot.sha256 == signed_apk_sha256,
        "signed Android APK identity differs at capability creation",
    )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "adb_profile": validated_adb_profile,
        "adb_size": adb_snapshot.size,
        "adb_sha256": adb_snapshot.sha256,
        "socket_nonce": validated_socket_nonce,
        "device_kind": validated_device_kind,
        "expected_serial": validated_serial,
        "run_id": validated_run_id,
        "signed_apk_size": signed_apk_size,
        "signed_apk_sha256": signed_apk_sha256,
    }
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _require(len(encoded) <= MAX_CAPABILITY_BYTES, "Android command capability is oversized")
    directory_fd = _open_private_directory(WORK_ROOT, "Android work")
    descriptor = -1
    created = False
    primary: BaseException | None = None
    try:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = os.open(CAPABILITY_LEAF, flags, 0o600, dir_fd=directory_fd)
        created = True
        os.fchmod(descriptor, 0o600)
        _private_metadata(os.fstat(descriptor))
        _write_all(descriptor, encoded)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.fsync(directory_fd)
    except BaseException as exc:
        primary = exc
        if descriptor >= 0:
            _close_owned_descriptor(
                descriptor,
                label="the incomplete Android capability",
                primary=primary,
            )
        if created:
            try:
                os.unlink(CAPABILITY_LEAF, dir_fd=directory_fd)
            except BaseException as cleanup_error:
                primary.add_note(
                    f"removing the incomplete Android capability also failed: {cleanup_error}"
                )
        raise
    finally:
        _close_owned_descriptor(
            directory_fd,
            label="the Android work directory",
            primary=primary,
        )


def destroy_capability(
    *,
    expected_run_id: str | None = None,
    missing_ok: bool = False,
) -> None:
    canonical_expected_run_id = (
        _canonical_run_id(expected_run_id)
        if expected_run_id is not None
        else None
    )
    directory_fd = _open_private_directory(WORK_ROOT, "Android work")
    primary: BaseException | None = None
    try:
        try:
            snapshot = load_json_object_snapshot_at(
                directory_fd,
                CAPABILITY_LEAF,
                display_path=CAPABILITY_PATH,
                maximum=MAX_CAPABILITY_BYTES,
                label="Android command capability",
                validate_metadata=_private_metadata,
            )
        except EvidenceIOError as exc:
            if missing_ok:
                try:
                    os.stat(
                        CAPABILITY_LEAF,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    return
            raise AndroidCommandError(
                f"cannot load Android command capability for removal: {exc}"
            ) from exc
        capability = _capability_from_snapshot(snapshot)
        if canonical_expected_run_id is not None:
            _require(
                capability.run_id == canonical_expected_run_id,
                "Android command capability belongs to a different run",
            )
        os.unlink(CAPABILITY_LEAF, dir_fd=directory_fd)
        os.fsync(directory_fd)
    except OSError as exc:
        primary = AndroidCommandError(
            f"cannot remove Android command capability: {exc}"
        )
        raise primary from exc
    except BaseException as exc:
        primary = exc
        raise
    finally:
        _close_owned_descriptor(
            directory_fd,
            label="the Android work directory",
            primary=primary,
        )


def _capability_from_snapshot(snapshot: JsonObjectSnapshot) -> AndroidCommandCapability:
    value = snapshot.value
    _require(set(value) == CAPABILITY_FIELDS, "Android command capability fields changed")
    _require(
        type(value.get("schema_version")) is int
        and value.get("schema_version") == SCHEMA_VERSION,
        "Android command schema changed",
    )
    _require(value.get("kind") == KIND, "Android command capability kind changed")
    adb_profile = _canonical_concrete_adb_profile(value.get("adb_profile"))
    adb_path = ADB_PROFILE_PATHS[adb_profile]
    adb_size = value.get("adb_size")
    _require(
        type(adb_size) is int and 0 < adb_size <= MAX_TOOL_BYTES,
        "adb executable size changed shape",
    )
    adb_sha256 = value.get("adb_sha256")
    _require(
        isinstance(adb_sha256, str) and HEX_SHA256.fullmatch(adb_sha256) is not None,
        "adb executable digest changed shape",
    )
    vendor_key = ACCOUNT_HOME / ".android/adbkey"
    socket_nonce = _canonical_socket_nonce(value.get("socket_nonce"))
    server_socket, socket_path = _server_socket_identity(socket_nonce)
    device_kind = _canonical_device_kind(value.get("device_kind"))
    expected_serial = _canonical_expected_serial(
        value.get("expected_serial"), device_kind
    )
    run_id = _canonical_run_id(value.get("run_id"))
    signed_apk_size = value.get("signed_apk_size")
    _require(
        type(signed_apk_size) is int and 0 < signed_apk_size <= MAX_APK_BYTES,
        "signed APK size changed",
    )
    signed_apk_sha256 = value.get("signed_apk_sha256")
    _require(
        isinstance(signed_apk_sha256, str)
        and HEX_SHA256.fullmatch(signed_apk_sha256) is not None,
        "signed APK digest changed",
    )
    return AndroidCommandCapability(
        adb_profile=adb_profile,
        adb_path=adb_path,
        adb_size=adb_size,
        adb_sha256=adb_sha256,
        socket_nonce=socket_nonce,
        server_socket=server_socket,
        socket_path=socket_path,
        vendor_key=vendor_key,
        device_kind=device_kind,
        expected_serial=expected_serial,
        run_id=run_id,
        signed_apk_size=signed_apk_size,
        signed_apk_sha256=signed_apk_sha256,
    )


def load_capability() -> AndroidCommandCapability:
    snapshot = load_json_object_snapshot(
        CAPABILITY_PATH,
        maximum=MAX_CAPABILITY_BYTES,
        label="Android command capability",
        validate_metadata=_private_metadata,
    )
    return _capability_from_snapshot(snapshot)


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
        getattr(signal, name)
        for name in ("SIGHUP", "SIGINT", "SIGTERM")
        if hasattr(signal, name)
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
                signal.signal(
                    installed_signal,
                    original_handlers[installed_signal],
                )
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
        create_capability(
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
                and not capability_cleanup_attempted
            ):
                capability_cleanup_attempted = True
                destroy_capability(
                    expected_run_id=_canonical_run_id(run_id),
                    missing_ok=True,
                )

        try:
            remove_interrupted_capability()
        except BaseException as cleanup_error:
            handoff_errors.append(cleanup_error)

        # Keep each temporary handler installed until signal.signal atomically
        # transfers that signal back to its original owner.  A signal delivered
        # before its transfer records the interruption and is cleaned below;
        # one delivered after the transfer follows the caller's original signal
        # semantics.  Taking a sigpending() snapshot before unmasking cannot
        # establish this boundary because a signal can become pending between
        # those two operations.
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


def _adb(capability: AndroidCommandCapability, *arguments: str) -> tuple[str, ...]:
    return (str(capability.adb_path), "-L", capability.server_socket, *arguments)


def _device(capability: AndroidCommandCapability, *arguments: str) -> tuple[str, ...]:
    return _adb(capability, "-s", capability.expected_serial, *arguments)


def _operation_specs() -> Mapping[AndroidOperation, OperationSpec]:
    proof = OutputRoot.PROOF
    work = OutputRoot.WORK
    specs = {
        AndroidOperation.KILL_SERVER: OperationSpec(
            "run", 15, 15, None, lambda cap: _adb(cap, "kill-server")
        ),
        AndroidOperation.LIST_DEVICES: OperationSpec(
            "capture", 15, 15, None, lambda cap: _adb(cap, "devices")
        ),
        AndroidOperation.LSOF_INITIAL: OperationSpec(
            "write",
            15,
            15,
            OutputSpec(proof, "adb-listener-initial.txt", 65_536),
            lambda cap: (
                _lsof_path(),
                "-nP",
                "-a",
                "-U",
                "-Fpun",
                cap.socket_path,
            ),
        ),
        AndroidOperation.LSOF_BEFORE: OperationSpec(
            "write",
            15,
            15,
            OutputSpec(proof, "adb-listener-before.txt", 65_536),
            lambda cap: (
                _lsof_path(),
                "-nP",
                "-a",
                "-U",
                "-Fpun",
                cap.socket_path,
            ),
        ),
        AndroidOperation.LSOF_AFTER: OperationSpec(
            "write",
            15,
            15,
            OutputSpec(proof, "adb-listener-after.txt", 65_536),
            lambda cap: (
                _lsof_path(),
                "-nP",
                "-a",
                "-U",
                "-Fpun",
                cap.socket_path,
            ),
        ),
        AndroidOperation.SERVER_STATUS_BEFORE: OperationSpec(
            "write",
            15,
            15,
            OutputSpec(proof, "adb-server-status-before.txt", 65_536),
            lambda cap: _adb(cap, "server-status"),
        ),
        AndroidOperation.SERVER_STATUS_AFTER: OperationSpec(
            "write",
            15,
            15,
            OutputSpec(proof, "adb-server-status-after.txt", 65_536),
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
            OutputSpec(proof, "adb-device-devpath.txt", 4_096),
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
        AndroidOperation.PACKAGE_LIST: OperationSpec(
            "write",
            15,
            15,
            OutputSpec(proof, "adb-package-query.txt", 65_536),
            lambda cap: _device(
                cap,
                "shell",
                "cmd",
                "package",
                "list",
                "packages",
                "-u",
                PACKAGE,
            ),
        ),
        AndroidOperation.PACKAGE_PATH: OperationSpec(
            "write",
            15,
            15,
            OutputSpec(proof, "adb-package-path.txt", 65_536),
            lambda cap: _device(cap, "shell", "pm", "path", PACKAGE),
        ),
        AndroidOperation.PULL_INSTALLED_APK: OperationSpec(
            "pull-apk",
            60,
            60,
            OutputSpec(work, "installed-smoke-base.apk", MAX_APK_BYTES),
            lambda cap: (),
        ),
        AndroidOperation.INSTALL_APK: OperationSpec(
            "run",
            120,
            120,
            None,
            lambda cap: _device(
                cap, "install", "--no-incremental", str(SIGNED_APK_PATH)
            ),
        ),
        AndroidOperation.UNINSTALL_APP: OperationSpec(
            "run", 60, 60, None, lambda cap: _device(cap, "uninstall", PACKAGE)
        ),
        AndroidOperation.EMULATOR_KILL: OperationSpec(
            "run", 15, 15, None, lambda cap: _device(cap, "emu", "kill")
        ),
        AndroidOperation.DEVICE_TIME: OperationSpec(
            "write",
            15,
            15,
            OutputSpec(proof, "adb-device-time.txt", 4_096),
            lambda cap: _device(cap, "shell", "date", "+%s.%3N"),
        ),
        AndroidOperation.FORCE_STOP: OperationSpec(
            "run",
            15,
            15,
            None,
            lambda cap: _device(cap, "shell", "am", "force-stop", PACKAGE),
        ),
        AndroidOperation.START_APP: OperationSpec(
            "run",
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
        ),
        AndroidOperation.READ_RESULT_TEXT: OperationSpec(
            "write",
            15,
            15,
            OutputSpec(
                proof, "qperiapt-android-device-result.txt.tmp", 1_048_576
            ),
            lambda cap: _device(
                cap, "exec-out", "run-as", PACKAGE, "cat", RESULT_TEXT_REMOTE
            ),
        ),
        AndroidOperation.READ_RESULT_JSON: OperationSpec(
            "write",
            15,
            15,
            OutputSpec(
                proof, "qperiapt-android-device-result.json", 4_194_304
            ),
            lambda cap: _device(
                cap, "exec-out", "run-as", PACKAGE, "cat", RESULT_JSON_REMOTE
            ),
        ),
        AndroidOperation.CAPTURE_LOGCAT: OperationSpec(
            "logcat",
            30,
            30,
            OutputSpec(proof, "logcat-raw.txt", 16_777_216),
            lambda cap: (),
        ),
    }
    return MappingProxyType(specs)


OPERATION_SPECS = _operation_specs()


def _validate_client_environment(capability: AndroidCommandCapability) -> None:
    exact = {
        **EXACT_CLIENT_ENVIRONMENT,
        "ADB_SERVER_SOCKET": capability.server_socket,
        "ADB_VENDOR_KEYS": str(capability.vendor_key),
    }
    for name, expected in exact.items():
        _require(os.environ.get(name) == expected, f"Android command environment changed: {name}")
    for name in FORBIDDEN_CLIENT_ENVIRONMENT:
        _require(name not in os.environ, f"unsupported Android command environment: {name}")


def _base_environment(capability: AndroidCommandCapability) -> dict[str, str]:
    return {
        "HOME": str(ACCOUNT_HOME),
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


def _client_environment(capability: AndroidCommandCapability) -> dict[str, str]:
    return {
        **_base_environment(capability),
        "ADB_USB": "0",
        "ADB_EMU": "0",
    }


def _server_environment(capability: AndroidCommandCapability) -> dict[str, str]:
    return {
        **_base_environment(capability),
        "ADB_USB": "1" if capability.device_kind == "physical" else "0",
        "ADB_EMU": "0" if capability.device_kind == "physical" else "1",
    }


def _validate_server_environment(capability: AndroidCommandCapability) -> None:
    server_transport = (
        {"ADB_USB": "1", "ADB_EMU": "0"}
        if capability.device_kind == "physical"
        else {"ADB_USB": "0", "ADB_EMU": "1"}
    )
    exact = {
        "ADB_MDNS": "0",
        "ADB_MDNS_AUTO_CONNECT": "0",
        "ADB_LOCAL_TRANSPORT_MAX_PORT": "5585",
        "ADB_SERVER_SOCKET": capability.server_socket,
        "ADB_VENDOR_KEYS": str(capability.vendor_key),
        **server_transport,
    }
    for name, expected in exact.items():
        _require(os.environ.get(name) == expected, f"Android server environment changed: {name}")
    for name in FORBIDDEN_CLIENT_ENVIRONMENT:
        _require(name not in os.environ, f"unsupported Android server environment: {name}")


def _validate_adb(capability: AndroidCommandCapability) -> None:
    observed = consume_regular_snapshot(
        capability.adb_path,
        maximum=MAX_TOOL_BYTES,
        label="adb executable",
        validate_metadata=_executable_metadata,
    )
    _require(
        observed.size == capability.adb_size
        and observed.sha256 == capability.adb_sha256,
        "adb executable changed after capability creation",
    )


def _validate_tool_and_apk(capability: AndroidCommandCapability, operation: AndroidOperation) -> None:
    _validate_adb(capability)
    if operation in {AndroidOperation.INSTALL_APK, AndroidOperation.PULL_INSTALLED_APK}:
        observed = consume_regular_snapshot(
            SIGNED_APK_PATH,
            maximum=MAX_APK_BYTES,
            label="signed Android smoke APK",
        )
        _require(
            observed.size == capability.signed_apk_size
            and observed.sha256 == capability.signed_apk_sha256,
            "signed Android smoke APK changed after capability creation",
        )


def exec_server() -> NoReturn:
    capability = load_capability()
    _validate_server_environment(capability)
    _validate_adb(capability)
    argv = [str(capability.adb_path), "-L", capability.server_socket]
    if capability.device_kind == "physical":
        argv.extend(("--one-device", capability.expected_serial))
    argv.extend(("server", "nodaemon"))
    try:
        os.execve(str(capability.adb_path), argv, _server_environment(capability))
    except OSError as exc:
        raise AndroidCommandError(f"cannot start the owned adb server: {exc}") from exc


def _output_directory(root: OutputRoot) -> int:
    return _open_private_directory(
        WORK_ROOT if root is OutputRoot.WORK else PROOF_ROOT,
        f"Android {root.value}",
    )


def _write_operation(
    capability: AndroidCommandCapability,
    spec: OperationSpec,
    argv: tuple[str, ...],
    timeout_seconds: int,
) -> BoundedResult:
    output = spec.output
    if output is None:
        _fail("Android write operation lacks a fixed output")
    directory_fd = _output_directory(output.root)
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
        _close_owned_descriptor(
            directory_fd,
            label="the Android output directory",
            primary=primary,
        )


def _remote_base_apk() -> str:
    snapshot = read_regular_snapshot(
        PROOF_ROOT / "adb-package-path.txt",
        maximum=65536,
        label="installed Android package path",
        validate_metadata=_private_metadata,
    )
    try:
        text = snapshot.data.decode("utf-8").replace("\r", "")
    except UnicodeDecodeError as exc:
        raise AndroidCommandError(f"installed Android package path is not UTF-8: {exc}") from exc
    lines = text.splitlines()
    _require(len(lines) == 1 and lines[0].startswith("package:"), "installed Android package path is ambiguous")
    remote = _canonical_ascii_atom(
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


def _device_epoch() -> str:
    snapshot = read_regular_snapshot(
        PROOF_ROOT / "adb-device-time.txt",
        maximum=4096,
        label="Android logcat start time",
        validate_metadata=_private_metadata,
    )
    try:
        raw_value = snapshot.data.decode("ascii").replace("\r", "").strip()
    except UnicodeDecodeError as exc:
        raise AndroidCommandError(f"Android logcat start time is not ASCII: {exc}") from exc
    value = _canonical_ascii_atom(
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
    operation: AndroidOperation, *, timeout_seconds: int | None = None
) -> BoundedResult:
    capability = load_capability()
    _validate_client_environment(capability)
    _validate_tool_and_apk(capability, operation)
    spec = OPERATION_SPECS[operation]
    timeout = spec.timeout_seconds if timeout_seconds is None else timeout_seconds
    _require(
        type(timeout) is int and 1 <= timeout <= spec.timeout_maximum,
        f"{operation.value} timeout must be 1 through {spec.timeout_maximum} seconds",
    )

    if spec.mode == "pull-apk":
        argv = _device(capability, "exec-out", "cat", _remote_base_apk())
        dynamic_spec = dataclasses.replace(
            spec,
            output=OutputSpec(OutputRoot.WORK, "installed-smoke-base.apk", capability.signed_apk_size),
        )
        result = _write_operation(capability, dynamic_spec, argv, timeout)
        if result.returncode == 0:
            observed = consume_regular_snapshot(
                WORK_ROOT / "installed-smoke-base.apk",
                maximum=MAX_APK_BYTES,
                label="installed Android smoke APK copy",
                validate_metadata=_private_metadata,
            )
            _require(
                observed.size == capability.signed_apk_size
                and observed.sha256 == capability.signed_apk_sha256,
                "installed Android smoke APK differs from this run's signed bytes",
            )
        return result
    if spec.mode == "logcat":
        argv = _device(
            capability,
            "logcat",
            "-d",
            "-v",
            "tag",
            "-T",
            _device_epoch(),
            "-s",
            "QPeriaptSmoke:*",
            "*:S",
        )
        return _write_operation(capability, spec, argv, timeout)

    argv = spec.build_argv(capability)
    if spec.mode == "run":
        return run(
            argv,
            timeout_seconds=timeout,
            environment=_client_environment(capability),
        )
    if spec.mode == "capture":
        return capture_stdout(
            argv,
            timeout_seconds=timeout,
            maximum_bytes=65536,
            environment=_client_environment(capability),
        )
    if spec.mode == "write":
        return _write_operation(capability, spec, argv, timeout)
    _fail(f"unsupported Android command mode: {spec.mode}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)

    create = sub.add_parser("create-capability")
    create.add_argument(
        "--adb-profile",
        choices=["auto", *ADB_PROFILE_PATHS],
        default="auto",
    )
    create.add_argument("--socket-nonce", required=True)
    create.add_argument("--device-kind", choices=["physical", "emulator"], required=True)
    create.add_argument("--expected-serial", required=True)
    create.add_argument("--run-id", required=True)
    create.add_argument("--signed-apk-size", required=True, type=int)
    create.add_argument("--signed-apk-sha256", required=True)

    invoke = sub.add_parser("invoke")
    invoke.add_argument("operation", choices=[operation.value for operation in AndroidOperation])
    invoke.add_argument("--timeout-seconds", type=int)

    path = sub.add_parser("adb-path")
    path.add_argument(
        "--adb-profile",
        choices=["auto", *ADB_PROFILE_PATHS],
        default="auto",
    )
    sub.add_parser("server-nodaemon")
    destroy = sub.add_parser("destroy-capability")
    destroy.add_argument("--expected-run-id")
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
    if args.action == "adb-path":
        print(resolve_adb_profile(args.adb_profile))
        return 0
    if args.action == "destroy-capability":
        destroy_capability(
            expected_run_id=args.expected_run_id,
            missing_ok=args.missing_ok,
        )
        return 0
    if args.action == "server-nodaemon":
        exec_server()
    if args.action == "invoke":
        operation = AndroidOperation(args.operation)
        result = invoke_operation(operation, timeout_seconds=args.timeout_seconds)
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
    except (AndroidCommandError, BoundedProcessError, EvidenceIOError) as exc:
        print(f"error: Android bounded command: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
