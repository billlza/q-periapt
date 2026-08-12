#!/usr/bin/env python3
"""Durable host/account state for the bounded Android release runtime."""

from __future__ import annotations

import ctypes
import dataclasses
import enum
import errno
import fcntl
import hashlib
import json
import os
import pathlib
import pwd
import re
import stat
import sys
from collections.abc import Mapping
from types import MappingProxyType
from typing import Literal, NoReturn

from android_emulator_control import (
    ADB_ISOLATION_CHECKPOINT_LEAVES,
    ADB_ISOLATION_RECEIPT_KIND,
    ADB_ISOLATION_RECEIPT_SCHEMA_VERSION,
    EMULATOR_ROUTING_MODE,
    EMULATOR_ROUTING_PRIVATE_ADB_FIELDS,
    EMULATOR_ROUTING_RECEIPT_KIND,
    EMULATOR_ROUTING_RECEIPT_LEAF,
    EMULATOR_ROUTING_RECEIPT_SCHEMA_VERSION,
    NATIVE_ADB_NOTIFIER_PORT,
    AdbIsolationCheckpoint,
    AdbIsolationObservation,
    AndroidEmulatorControlError,
    canonical_emulator_abi,
    emulator_routing_transport_binding_sha256,
    parse_emulator_routing_receipt,
    probe_adb_loopback_absence,
)
from evidence_io import (
    EvidenceIOError,
    FileDigestSnapshot,
    FileSnapshot,
    JsonObjectSnapshot,
    consume_regular_snapshot,
    consume_regular_snapshot_at,
    load_json_object_snapshot,
    load_json_object_snapshot_at,
)
from process_identity import (
    ProcessIdentity,
    ProcessIdentityError,
    host_boot_identity,
)
from process_identity import (
    parse_token as parse_process_identity_token,
)
from process_identity import (
    render_token as render_process_identity_token,
)

SCHEMA_VERSION = 3
KIND = "qperiapt.android_command_capability"
MAX_CAPABILITY_BYTES = 16 * 1024
MAX_TOOL_BYTES = 128 * 1024 * 1024
MAX_APK_BYTES = 512 * 1024 * 1024

REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parent.parent
TARGET_ROOT = REPOSITORY_ROOT / "target"
RUNS_ROOT_LEAF = "qperiapt-android-device-smoke-runs"
RUNS_ROOT = TARGET_ROOT / RUNS_ROOT_LEAF
CAPABILITY_LEAF = "android-command-capability.json"
ADB_SNAPSHOT_PREFIX = "adb-"
SIGNED_APK_LEAF = "qperiapt-android-smoke.apk"
ACCOUNT_STATE_LEAF = "dev.qperiapt.android-device-smoke"
LANE_LOCK_LEAF = "lane.lock"
OWNED_RUNTIME_RECEIPT_LEAF = "owned-runtime.json"
OWNED_RUNTIME_RECEIPT_KIND = "qperiapt.android_owned_runtime"
OWNED_RUNTIME_RECEIPT_SCHEMA_VERSION = 4
MAX_OWNED_RUNTIME_RECEIPT_BYTES = 16 * 1024
LANE_LOCK_FD = 9
RENAME_EXCL = 0x00000004
RENAME_NOREPLACE = 0x00000001

HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
RUN_ID = re.compile(r"[0-9a-f]{32}")
SERIAL = re.compile(r"[A-Za-z0-9._:-]{1,128}")
SOCKET_NONCE = re.compile(r"[A-Za-z0-9]{8}")
AVD_NAME = re.compile(r"[A-Za-z0-9._-]{1,128}")

_CANONICAL_ASCII = MappingProxyType(
    {
        character: character
        for character in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._:/+=~-"
    }
)
_NONCE_CHARACTERS = frozenset(
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)
_SERIAL_CHARACTERS = frozenset(
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._:-"
)
_RUN_ID_CHARACTERS = frozenset("0123456789abcdef")
_AVD_NAME_CHARACTERS = frozenset(
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._-"
)

CAPABILITY_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "adb_profile",
        "adb_size",
        "adb_sha256",
        "socket_nonce",
        "native_adb_notifier_port",
        "device_kind",
        "expected_serial",
        "run_id",
        "signed_apk_size",
        "signed_apk_sha256",
    }
)

OWNED_RUNTIME_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "phase",
        "run_id",
        "host_identity",
        "boot_identity",
        "repository_root",
        "run_root_device",
        "run_root_inode",
        "pid",
        "uid",
        "started_at",
        "started_subsecond",
        "process_identity",
        "adb_profile",
        "adb_size",
        "adb_sha256",
        "socket_nonce",
        "native_adb_notifier_port",
        "device_kind",
        "adb_server_pid",
        "adb_server_started_at",
        "adb_server_started_subsecond",
        "adb_server_process_identity",
        "adb_server_initial_executable",
        "adb_server_initial_executable_device",
        "adb_server_initial_executable_inode",
        "adb_snapshot_device",
        "adb_snapshot_inode",
        "adb_socket_directory_device",
        "adb_socket_directory_inode",
        "avd_name",
        "device_abi",
        "expected_serial",
        "console_port",
        "console_auth_token_device",
        "console_auth_token_inode",
        "console_auth_token_sha256",
        "launcher_path",
        "launcher_device",
        "launcher_inode",
        "backend_path",
        "backend_device",
        "backend_inode",
        "backend_sha256",
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


class AndroidRuntimeStateError(RuntimeError):
    """Durable Android runtime state is missing, malformed, or inconsistent."""


class RuntimePhase(str, enum.Enum):
    """Monotonic durable phases for one adapter-owned Android runtime."""

    PREPARED = "prepared"
    ADB_CHILD_REGISTERED = "adb_child_registered"
    ADB_SEALING = "adb_sealing"
    ADB_SEALED = "adb_sealed"
    EMULATOR_CHILD_REGISTERED = "emulator_child_registered"


@dataclasses.dataclass(frozen=True, slots=True)
class ConsoleAuthTokenIdentity:
    """Non-secret identity of the console token admitted before emulator exec."""

    device: int
    inode: int
    sha256: str


@dataclasses.dataclass(frozen=True, slots=True)
class AdbChildRegistration:
    """Adapter-validated identity required to durably register the adb child."""

    process: ProcessIdentity
    initial_executable_device: int
    initial_executable_inode: int
    adb_snapshot_device: int
    adb_snapshot_inode: int


@dataclasses.dataclass(frozen=True, slots=True)
class EmulatorChildRegistration:
    """Adapter-validated non-secret identity required before emulator exec."""

    process: ProcessIdentity
    avd_name: str
    device_abi: Literal["arm64-v8a", "x86_64"]
    console_port: int
    native_adb_notifier_port: int
    console_auth_token: ConsoleAuthTokenIdentity
    launcher_path: pathlib.Path
    launcher_device: int
    launcher_inode: int
    backend_path: pathlib.Path
    backend_device: int
    backend_inode: int
    backend_sha256: str


@dataclasses.dataclass(frozen=True, slots=True)
class AndroidRunLayout:
    """Fixed repository paths derived from one canonical Android run id."""

    run_id: str
    root: pathlib.Path
    work: pathlib.Path
    proof: pathlib.Path
    capability: pathlib.Path
    signed_apk: pathlib.Path

    @classmethod
    def from_run_id(cls, value: object) -> AndroidRunLayout:
        run_id = _canonical_run_id(value)
        root = RUNS_ROOT / run_id
        work = root / "work"
        proof = root / "proof"
        return cls(
            run_id=run_id,
            root=root,
            work=work,
            proof=proof,
            capability=work / CAPABILITY_LEAF,
            signed_apk=proof / SIGNED_APK_LEAF,
        )


@dataclasses.dataclass(frozen=True, slots=True)
class AndroidAdbCapability:
    """Recovery-relevant identity shared by normal and crash-cleanup commands."""

    adb_profile: str
    adb_snapshot_path: pathlib.Path
    adb_size: int
    adb_sha256: str
    socket_nonce: str
    native_adb_notifier_port: int | None
    server_socket: str
    socket_path: str
    vendor_key: pathlib.Path
    device_kind: Literal["physical", "emulator"]
    expected_serial: str
    run_id: str


@dataclasses.dataclass(frozen=True, slots=True)
class AndroidCommandCapability(AndroidAdbCapability):
    signed_apk_size: int
    signed_apk_sha256: str


@dataclasses.dataclass(frozen=True, slots=True)
class OwnedRuntimeReceipt:
    """Private crash-recovery identity for one adapter-owned runtime."""

    run_id: str
    host_identity: str
    boot_identity: str
    repository_root: pathlib.Path
    run_root_device: int
    run_root_inode: int
    phase: RuntimePhase
    pid: int | None
    uid: int
    started_at: int | None
    started_subsecond: int | None
    process_identity: str | None
    adb_profile: str
    adb_size: int
    adb_sha256: str
    socket_nonce: str
    native_adb_notifier_port: int | None
    device_kind: Literal["physical", "emulator"]
    expected_serial: str
    adb_server_pid: int | None
    adb_server_started_at: int | None
    adb_server_started_subsecond: int | None
    adb_server_process_identity: str | None
    adb_server_initial_executable: pathlib.Path | None
    adb_server_initial_executable_device: int | None
    adb_server_initial_executable_inode: int | None
    adb_snapshot_device: int | None
    adb_snapshot_inode: int | None
    adb_socket_directory_device: int
    adb_socket_directory_inode: int
    avd_name: str | None
    device_abi: Literal["arm64-v8a", "x86_64"] | None
    console_port: int | None
    console_auth_token_device: int | None
    console_auth_token_inode: int | None
    console_auth_token_sha256: str | None
    launcher_path: pathlib.Path | None
    launcher_device: int | None
    launcher_inode: int | None
    backend_path: pathlib.Path | None
    backend_device: int | None
    backend_inode: int | None
    backend_sha256: str | None
    snapshot_sha256: str

    @property
    def adb_server_started(self) -> bool:
        return self.phase is not RuntimePhase.PREPARED

    @property
    def adb_socket_directory_sealed(self) -> bool:
        return self.phase in {
            RuntimePhase.ADB_SEALED,
            RuntimePhase.EMULATOR_CHILD_REGISTERED,
        }

    @property
    def emulator_started(self) -> bool:
        return self.phase is RuntimePhase.EMULATOR_CHILD_REGISTERED

    @property
    def console_auth_token_identity(self) -> ConsoleAuthTokenIdentity | None:
        if self.console_auth_token_device is None:
            return None
        return ConsoleAuthTokenIdentity(
            device=self.console_auth_token_device,
            inode=self.console_auth_token_inode,
            sha256=self.console_auth_token_sha256,
        )


def _fail(message: str) -> NoReturn:
    raise AndroidRuntimeStateError(message)


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


def canonical_ascii_atom(
    value: object,
    *,
    characters: frozenset[str],
    minimum: int,
    maximum: int,
    label: str,
) -> str:
    return _canonical_ascii_atom(
        value,
        characters=characters,
        minimum=minimum,
        maximum=maximum,
        label=label,
    )


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


def canonical_run_id(value: object) -> str:
    return _canonical_run_id(value)


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


def canonical_socket_nonce(value: object) -> str:
    return _canonical_socket_nonce(value)


def _server_socket_identity(nonce: str) -> tuple[str, str]:
    socket_path = f"/tmp/qperiapt-adb.{nonce}/adb.sock"
    return f"localfilesystem:{socket_path}", socket_path


def server_socket_identity(nonce: str) -> tuple[str, str]:
    return _server_socket_identity(_canonical_socket_nonce(nonce))


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


def canonical_expected_serial(value: object, device_kind: str) -> str:
    return _canonical_expected_serial(value, device_kind)


def _executable_metadata(metadata: os.stat_result) -> None:
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o111 == 0:
        raise EvidenceIOError("Android command tool must be an executable regular file")


def _private_executable_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o500
    ):
        raise EvidenceIOError(
            "Android adb snapshot must be one current-user-owned regular file with mode 0500"
        )


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
            raise AndroidRuntimeStateError(
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
        raise AndroidRuntimeStateError(
            f"cannot open {label} directory {path}: {exc}"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        _require(
            stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and stat.S_IMODE(metadata.st_mode) == 0o700,
            f"{label} directory must be current-user-owned with mode 0700",
        )
        _reject_macos_allow_acl(descriptor, label)
    except BaseException as primary:
        _close_owned_descriptor(
            descriptor,
            label=f"rejected {label} directory",
            primary=primary,
        )
        raise
    return descriptor


def _open_owned_directory(path: pathlib.Path, label: str) -> int:
    """Open one current-user-owned directory without following its leaf."""

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AndroidRuntimeStateError(
            f"cannot open {label} directory {path}: {exc}"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        _require(
            stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.geteuid(),
            f"{label} directory must be owned by the current user",
        )
        _reject_macos_allow_acl(descriptor, label)
    except BaseException as primary:
        _close_owned_descriptor(
            descriptor,
            label=f"rejected {label} directory",
            primary=primary,
        )
        raise
    return descriptor


def _open_private_directory_at(
    parent_fd: int,
    leaf: str,
    *,
    display_path: pathlib.Path,
    label: str,
) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(leaf, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise AndroidRuntimeStateError(
            f"cannot open {label} directory {display_path}: {exc}"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        _require(
            stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and stat.S_IMODE(metadata.st_mode) == 0o700,
            f"{label} directory must be current-user-owned with mode 0700",
        )
        _reject_macos_allow_acl(descriptor, label)
    except BaseException as primary:
        _close_owned_descriptor(
            descriptor,
            label=f"rejected {label} directory",
            primary=primary,
        )
        raise
    return descriptor


def _account_state_parent() -> pathlib.Path:
    if sys.platform == "darwin":
        return ACCOUNT_HOME / "Library" / "Application Support"
    if sys.platform == "linux":
        return ACCOUNT_HOME / ".local" / "state"
    _fail(f"Android account control state is unsupported on {sys.platform}")


def account_state_directory() -> pathlib.Path:
    """Return the fixed host/account-scoped control-state directory."""

    return _account_state_parent() / ACCOUNT_STATE_LEAF


def lane_lock_path() -> pathlib.Path:
    return account_state_directory() / LANE_LOCK_LEAF


def owned_runtime_receipt_path() -> pathlib.Path:
    return account_state_directory() / OWNED_RUNTIME_RECEIPT_LEAF


def _open_protected_parent(path: pathlib.Path, label: str) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AndroidRuntimeStateError(
            f"cannot open {label} directory {path}: {exc}"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        _require(
            stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and metadata.st_mode & 0o022 == 0,
            f"{label} directory must be current-user-owned and not group/other writable",
        )
        _reject_macos_allow_acl(descriptor, label)
    except BaseException as primary:
        _close_owned_descriptor(
            descriptor,
            label=f"rejected {label} directory",
            primary=primary,
        )
        raise
    return descriptor


def _private_control_file_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise EvidenceIOError(
            "Android account control file must be one current-user-owned regular file with mode 0600"
        )


def _verify_private_control_descriptor(descriptor: int, label: str) -> None:
    _private_control_file_metadata(os.fstat(descriptor))
    _reject_macos_allow_acl(descriptor, label)


def _open_protected_child_directory(
    parent_fd: int,
    leaf: str,
    *,
    label: str,
    create: bool,
) -> int:
    if create:
        try:
            os.mkdir(leaf, 0o700, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except FileExistsError:
            pass
        except OSError as exc:
            raise AndroidRuntimeStateError(
                f"cannot create {label} directory: {exc}"
            ) from exc
    descriptor = os.open(
        leaf,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        dir_fd=parent_fd,
    )
    try:
        metadata = os.fstat(descriptor)
        _require(
            stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and metadata.st_mode & 0o022 == 0,
            f"{label} directory must be current-user-owned and not group/other writable",
        )
        _reject_macos_allow_acl(descriptor, label)
    except BaseException as primary:
        _close_owned_descriptor(
            descriptor,
            label=f"rejected {label} directory",
            primary=primary,
        )
        raise
    return descriptor


def _reject_macos_allow_acl(descriptor: int, label: str) -> None:
    if sys.platform == "linux":
        return
    _require(
        sys.platform == "darwin",
        f"unsupported account-state ACL host: {sys.platform}",
    )
    acl_type_extended = 0x00000100
    acl_first_entry = 0
    acl_next_entry = -1
    acl_extended_allow = 1
    acl_extended_deny = 2
    libc = ctypes.CDLL(None, use_errno=True)
    acl_get_fd_np = libc.acl_get_fd_np
    acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_uint]
    acl_get_fd_np.restype = ctypes.c_void_p
    acl_get_entry = libc.acl_get_entry
    acl_get_entry.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    acl_get_entry.restype = ctypes.c_int
    acl_get_tag_type = libc.acl_get_tag_type
    acl_get_tag_type.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    acl_get_tag_type.restype = ctypes.c_int
    acl_free = libc.acl_free
    acl_free.argtypes = [ctypes.c_void_p]
    acl_free.restype = ctypes.c_int
    ctypes.set_errno(0)
    acl = acl_get_fd_np(descriptor, acl_type_extended)
    if not acl:
        error_number = ctypes.get_errno()
        if error_number == errno.ENOENT:
            return
        detail = (
            os.strerror(error_number) if error_number else "unknown ACL query error"
        )
        _fail(f"cannot inspect macOS ACL for {label}: {detail}")
    allow_entry = False
    error: str | None = None
    selector = acl_first_entry
    while error is None:
        entry = ctypes.c_void_p()
        ctypes.set_errno(0)
        result = acl_get_entry(acl, selector, ctypes.byref(entry))
        if result != 0:
            error_number = ctypes.get_errno()
            if error_number == errno.EINVAL and selector == acl_next_entry:
                break
            detail = (
                os.strerror(error_number) if error_number else "unknown ACL entry error"
            )
            error = f"cannot enumerate macOS ACL for {label}: {detail}"
            break
        tag_type = ctypes.c_int()
        if acl_get_tag_type(entry, ctypes.byref(tag_type)) != 0:
            error_number = ctypes.get_errno()
            detail = (
                os.strerror(error_number) if error_number else "unknown ACL tag error"
            )
            error = f"cannot inspect macOS ACL tag for {label}: {detail}"
            break
        if tag_type.value == acl_extended_allow:
            allow_entry = True
        elif tag_type.value != acl_extended_deny:
            error = f"macOS ACL for {label} contains an unsupported tag"
            break
        selector = acl_next_entry
    if acl_free(acl) != 0 and error is None:
        error_number = ctypes.get_errno()
        detail = os.strerror(error_number) if error_number else "unknown ACL free error"
        error = f"cannot release macOS ACL for {label}: {detail}"
    _require(error is None, error or "account-state ACL inspection failed")
    _require(not allow_entry, f"macOS allow ACL is forbidden for {label}")


def reject_macos_allow_acl(descriptor: int, label: str) -> None:
    _reject_macos_allow_acl(descriptor, label)


def _rename_sibling_noreplace(
    directory_fd: int,
    source_leaf: str,
    destination_leaf: str,
) -> None:
    """Atomically publish one sibling control file without replacement."""

    for value, label in (
        (source_leaf, "control staging leaf"),
        (destination_leaf, "control destination leaf"),
    ):
        _require(
            isinstance(value, str)
            and 0 < len(os.fsencode(value)) <= 255
            and value not in {".", ".."}
            and "/" not in value
            and "\\" not in value
            and "\x00" not in value,
            f"{label} is invalid",
        )
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        rename = library.renameatx_np
        flags = RENAME_EXCL
    elif sys.platform.startswith("linux"):
        rename = library.renameat2
        flags = RENAME_NOREPLACE
    else:
        _fail("atomic control-file publication is unsupported on this host")
    rename.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    rename.restype = ctypes.c_int
    ctypes.set_errno(0)
    if (
        rename(
            directory_fd,
            os.fsencode(source_leaf),
            directory_fd,
            os.fsencode(destination_leaf),
            flags,
        )
        == 0
    ):
        return
    observed_errno = ctypes.get_errno()
    if observed_errno == errno.EEXIST:
        _fail("an owned runtime recovery receipt already exists")
    if observed_errno == 0:
        _fail("atomic control-file publication failed without errno")
    raise AndroidRuntimeStateError(
        "cannot atomically publish owned runtime receipt: "
        f"{os.strerror(observed_errno)} (errno {observed_errno})"
    )


def _open_or_create_lane_lock(state_fd: int) -> None:
    descriptor = -1
    primary: BaseException | None = None
    flags = os.O_RDWR | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        try:
            descriptor = os.open(
                LANE_LOCK_LEAF,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=state_fd,
            )
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            os.fsync(state_fd)
        except FileExistsError:
            descriptor = os.open(LANE_LOCK_LEAF, flags, dir_fd=state_fd)
        _verify_private_control_descriptor(descriptor, "Android lane lock")
    except BaseException as exc:
        primary = exc
        if descriptor >= 0:
            _close_owned_descriptor(
                descriptor,
                label="the Android lane lock",
                primary=primary,
            )
            descriptor = -1
        # A newly visible lock inode is deliberately never removed. Another
        # checkout may already have opened it; recreating the leaf would split
        # the host/account lock into two independent open descriptions.
        raise
    finally:
        if descriptor >= 0:
            _close_owned_descriptor(
                descriptor,
                label="the Android lane lock",
                primary=primary,
            )


def _open_validated_account_state() -> int:
    """Return the state dirfd from one protected descriptor walk."""

    home_fd = _open_protected_parent(ACCOUNT_HOME, "account home")
    ancestor_fds: list[int] = []
    parent_fd = -1
    state_fd = -1
    primary: BaseException | None = None
    try:
        current_fd = home_fd
        components = (
            (
                ("Library", False),
                ("Application Support", False),
            )
            if sys.platform == "darwin"
            else (
                (".local", True),
                ("state", True),
            )
        )
        for leaf, create in components:
            child_fd = _open_protected_child_directory(
                current_fd,
                leaf,
                label=f"Android account-state ancestor {leaf}",
                create=create,
            )
            ancestor_fds.append(child_fd)
            current_fd = child_fd
        parent_fd = current_fd
        created = False
        try:
            os.mkdir(ACCOUNT_STATE_LEAF, 0o700, dir_fd=parent_fd)
            created = True
        except FileExistsError:
            pass
        if created:
            os.fsync(parent_fd)
        state_fd = _open_private_directory_at(
            parent_fd,
            ACCOUNT_STATE_LEAF,
            display_path=account_state_directory(),
            label="Android account state",
        )
        _open_or_create_lane_lock(state_fd)
        result = state_fd
        state_fd = -1
        return result
    except BaseException as exc:
        primary = exc
        raise
    finally:
        if state_fd >= 0:
            _close_owned_descriptor(
                state_fd,
                label="the Android account-state directory",
                primary=primary,
            )
        for descriptor in reversed(ancestor_fds):
            _close_owned_descriptor(
                descriptor,
                label="an Android account-state ancestor directory",
                primary=primary,
            )
        _close_owned_descriptor(
            home_fd,
            label="the Android account home directory",
            primary=primary,
        )


def ensure_account_state() -> pathlib.Path:
    """Create and validate the fixed private state directory and stable lock inode."""

    state_fd = _open_validated_account_state()
    _close_owned_descriptor(state_fd, label="the Android account-state directory")
    return account_state_directory()


def _open_account_state() -> int:
    return _open_validated_account_state()


def validate_lane_lock_descriptor(descriptor: int = LANE_LOCK_FD) -> None:
    """Bind the inherited lane lock descriptor to the fixed stable lock inode."""

    _require(
        type(descriptor) is int and descriptor == LANE_LOCK_FD,
        f"Android lane lock must use descriptor {LANE_LOCK_FD}",
    )
    state_fd = _open_account_state()
    lock_fd = -1
    primary: BaseException | None = None
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        lock_fd = os.open(LANE_LOCK_LEAF, flags, dir_fd=state_fd)
        fixed = os.fstat(lock_fd)
        inherited = os.fstat(descriptor)
        _verify_private_control_descriptor(lock_fd, "fixed Android lane lock")
        _verify_private_control_descriptor(descriptor, "inherited Android lane lock")
        _require(
            (fixed.st_dev, fixed.st_ino) == (inherited.st_dev, inherited.st_ino),
            "inherited Android lane lock differs from the fixed account lock",
        )
        import fcntl

        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            _fail("inherited Android lane lock is not held")
        # On an OFD-flock host, re-locking the inherited descriptor itself is
        # idempotent.  Combined with the independently blocked descriptor above,
        # success proves that fd9 is the open description holding the lock.
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise AndroidRuntimeStateError(
                "inherited Android lane descriptor does not hold its lock"
            ) from exc
    except OSError as exc:
        primary = AndroidRuntimeStateError(
            f"cannot validate the Android lane lock: {exc}"
        )
        raise primary from exc
    except BaseException as exc:
        primary = exc
        raise
    finally:
        if lock_fd >= 0:
            _close_owned_descriptor(
                lock_fd,
                label="the Android lane lock validation descriptor",
                primary=primary,
            )
        _close_owned_descriptor(
            state_fd,
            label="the Android account-state directory",
            primary=primary,
        )


def _arm_lane_lock_close_on_exec() -> None:
    """Hold the lane through the exec boundary and let the kernel release it."""

    validate_lane_lock_descriptor()
    try:
        os.set_inheritable(LANE_LOCK_FD, False)
    except OSError as exc:
        raise AndroidRuntimeStateError(
            f"cannot make the Android lane lock close-on-exec: {exc}"
        ) from exc
    _require(
        not os.get_inheritable(LANE_LOCK_FD),
        "Android lane lock did not become close-on-exec",
    )


def arm_lane_lock_close_on_exec() -> None:
    _arm_lane_lock_close_on_exec()


def create_run_layout(run_id: str) -> AndroidRunLayout:
    """Create one append-only private run root without replacing an older run."""

    layout = AndroidRunLayout.from_run_id(run_id)
    _require(
        RUNS_ROOT.parent == TARGET_ROOT and RUNS_ROOT.name == RUNS_ROOT_LEAF,
        "Android run root configuration changed",
    )
    target_fd = _open_owned_directory(TARGET_ROOT, "repository target")
    runs_fd = -1
    run_fd = -1
    primary: BaseException | None = None
    try:
        runs_created = False
        try:
            os.mkdir(RUNS_ROOT_LEAF, 0o700, dir_fd=target_fd)
            runs_created = True
        except FileExistsError:
            pass
        if runs_created:
            os.fsync(target_fd)
        runs_fd = _open_private_directory_at(
            target_fd,
            RUNS_ROOT_LEAF,
            display_path=RUNS_ROOT,
            label="Android runs",
        )
        try:
            os.mkdir(layout.run_id, 0o700, dir_fd=runs_fd)
        except FileExistsError as exc:
            raise AndroidRuntimeStateError(
                f"Android run output already exists: {layout.root}"
            ) from exc
        os.fsync(runs_fd)
        run_fd = _open_private_directory_at(
            runs_fd,
            layout.run_id,
            display_path=layout.root,
            label="Android run",
        )
        for leaf in ("work", "proof"):
            try:
                os.mkdir(leaf, 0o700, dir_fd=run_fd)
            except OSError as exc:
                raise AndroidRuntimeStateError(
                    f"cannot create Android run {leaf} directory: {exc}"
                ) from exc
        os.fsync(run_fd)
        _close_owned_descriptor(run_fd, label="the Android run directory")
        run_fd = -1
        _close_owned_descriptor(runs_fd, label="the Android runs directory")
        runs_fd = -1
        return layout
    except BaseException as exc:
        primary = exc
        raise
    finally:
        if run_fd >= 0:
            _close_owned_descriptor(
                run_fd,
                label="the Android run directory",
                primary=primary,
            )
        if runs_fd >= 0:
            _close_owned_descriptor(
                runs_fd,
                label="the Android runs directory",
                primary=primary,
            )
        _close_owned_descriptor(
            target_fd,
            label="the repository target directory",
            primary=primary,
        )


def _write_all(descriptor: int, data: bytes, *, label: str) -> None:
    view = memoryview(data)
    while view:
        try:
            written = os.write(descriptor, view)
        except OSError as exc:
            raise AndroidRuntimeStateError(f"cannot write {label}: {exc}") from exc
        if written <= 0:
            raise AndroidRuntimeStateError(f"short write while creating {label}")
        view = view[written:]


def _adb_snapshot_leaf(run_id: str) -> str:
    return f"{ADB_SNAPSHOT_PREFIX}{_canonical_run_id(run_id)}"


def _create_adb_snapshot(
    directory_fd: int,
    source_path: pathlib.Path,
    run_id: str,
) -> FileDigestSnapshot:
    """Copy and hash one SDK adb stream into this run's private executable."""

    leaf = _adb_snapshot_leaf(run_id)
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
        descriptor = os.open(leaf, flags, 0o600, dir_fd=directory_fd)
        created = True
        snapshot = consume_regular_snapshot(
            source_path,
            maximum=MAX_TOOL_BYTES,
            label="adb executable",
            validate_metadata=_executable_metadata,
            consume=lambda chunk: _write_all(
                descriptor,
                chunk,
                label="Android adb snapshot",
            ),
        )
        os.fchmod(descriptor, 0o500)
        metadata = os.fstat(descriptor)
        _private_executable_metadata(metadata)
        _require(
            metadata.st_size == snapshot.size,
            "Android adb snapshot size differs from the consumed SDK executable",
        )
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.fsync(directory_fd)
        return snapshot
    except BaseException as exc:
        primary = exc
        if descriptor >= 0:
            _close_owned_descriptor(
                descriptor,
                label="the incomplete Android adb snapshot",
                primary=primary,
            )
        if created:
            try:
                os.unlink(leaf, dir_fd=directory_fd)
                os.fsync(directory_fd)
            except BaseException as cleanup_error:
                primary.add_note(
                    f"removing the incomplete Android adb snapshot also failed: {cleanup_error}"
                )
        raise


def _remove_adb_snapshot(
    directory_fd: int,
    run_id: str,
    *,
    missing_ok: bool,
) -> None:
    leaf = _adb_snapshot_leaf(run_id)
    try:
        metadata = os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        if missing_ok:
            return
        raise AndroidRuntimeStateError("Android adb snapshot is missing") from None
    except OSError as exc:
        raise AndroidRuntimeStateError(
            f"cannot inspect Android adb snapshot: {exc}"
        ) from exc
    try:
        _private_executable_metadata(metadata)
    except EvidenceIOError as exc:
        raise AndroidRuntimeStateError(str(exc)) from exc
    try:
        os.unlink(leaf, dir_fd=directory_fd)
    except OSError as exc:
        raise AndroidRuntimeStateError(
            f"cannot remove Android adb snapshot: {exc}"
        ) from exc


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
    layout = AndroidRunLayout.from_run_id(run_id)
    validated_adb_profile = canonical_adb_profile(adb_profile)
    validated_adb_path = ADB_PROFILE_PATHS[validated_adb_profile]
    validated_socket_nonce = _canonical_socket_nonce(socket_nonce)
    validated_device_kind = _canonical_device_kind(device_kind)
    native_adb_notifier_port = (
        NATIVE_ADB_NOTIFIER_PORT if validated_device_kind == "emulator" else None
    )
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
    apk_snapshot = consume_regular_snapshot(
        layout.signed_apk,
        maximum=MAX_APK_BYTES,
        label="signed Android smoke APK",
    )
    _require(
        apk_snapshot.size == signed_apk_size
        and apk_snapshot.sha256 == signed_apk_sha256,
        "signed Android APK identity differs at capability creation",
    )
    directory_fd = _open_private_directory(layout.work, "Android work")
    descriptor = -1
    capability_created = False
    snapshot_created = False
    primary: BaseException | None = None
    try:
        adb_snapshot = _create_adb_snapshot(
            directory_fd,
            validated_adb_path,
            validated_run_id,
        )
        snapshot_created = True
        payload = {
            "schema_version": SCHEMA_VERSION,
            "kind": KIND,
            "adb_profile": validated_adb_profile,
            "adb_size": adb_snapshot.size,
            "adb_sha256": adb_snapshot.sha256,
            "socket_nonce": validated_socket_nonce,
            "native_adb_notifier_port": native_adb_notifier_port,
            "device_kind": validated_device_kind,
            "expected_serial": validated_serial,
            "run_id": validated_run_id,
            "signed_apk_size": signed_apk_size,
            "signed_apk_sha256": signed_apk_sha256,
        }
        encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        _require(
            len(encoded) <= MAX_CAPABILITY_BYTES,
            "Android command capability is oversized",
        )
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = os.open(CAPABILITY_LEAF, flags, 0o600, dir_fd=directory_fd)
        capability_created = True
        os.fchmod(descriptor, 0o600)
        _private_metadata(os.fstat(descriptor))
        _write_all(
            descriptor,
            encoded,
            label="Android command capability",
        )
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
        if capability_created:
            try:
                os.unlink(CAPABILITY_LEAF, dir_fd=directory_fd)
            except BaseException as cleanup_error:
                primary.add_note(
                    f"removing the incomplete Android capability also failed: {cleanup_error}"
                )
        if snapshot_created:
            try:
                _remove_adb_snapshot(
                    directory_fd,
                    validated_run_id,
                    missing_ok=True,
                )
                os.fsync(directory_fd)
            except BaseException as cleanup_error:
                primary.add_note(
                    f"removing the uncommitted Android adb snapshot also failed: {cleanup_error}"
                )
        raise
    finally:
        _close_owned_descriptor(
            directory_fd,
            label="the Android work directory",
            primary=primary,
        )


def _destroy_capability_for_layout(
    layout: AndroidRunLayout,
    *,
    missing_ok: bool,
) -> None:
    directory_fd = _open_private_directory(layout.work, "Android work")
    primary: BaseException | None = None
    try:
        try:
            snapshot = load_json_object_snapshot_at(
                directory_fd,
                CAPABILITY_LEAF,
                display_path=layout.capability,
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
                    _remove_adb_snapshot(
                        directory_fd,
                        layout.run_id,
                        missing_ok=True,
                    )
                    os.fsync(directory_fd)
                    return
            raise AndroidRuntimeStateError(
                f"cannot load Android command capability for removal: {exc}"
            ) from exc
        capability = _capability_from_snapshot_for_layout(snapshot, layout=layout)
        _require(
            capability.run_id == layout.run_id,
            "Android command capability belongs to a different run",
        )
        observed = consume_regular_snapshot_at(
            directory_fd,
            _adb_snapshot_leaf(capability.run_id),
            display_path=capability.adb_snapshot_path,
            maximum=MAX_TOOL_BYTES,
            label="Android adb snapshot",
            validate_metadata=_private_executable_metadata,
        )
        _require(
            observed.size == capability.adb_size
            and observed.sha256 == capability.adb_sha256,
            "Android adb snapshot changed after capability creation",
        )
        _remove_adb_snapshot(
            directory_fd,
            capability.run_id,
            missing_ok=False,
        )
        os.unlink(CAPABILITY_LEAF, dir_fd=directory_fd)
        os.fsync(directory_fd)
    except OSError as exc:
        primary = AndroidRuntimeStateError(
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


def destroy_capability(
    *,
    run_id: str,
    missing_ok: bool = False,
) -> None:
    _destroy_capability_for_layout(
        AndroidRunLayout.from_run_id(run_id),
        missing_ok=missing_ok,
    )


def _retire_recovery_capability_from_receipt(
    layout: AndroidRunLayout,
    receipt: OwnedRuntimeReceipt,
) -> None:
    """Idempotently remove only bytes already bound by the recovery receipt."""

    directory_fd = _open_private_directory(layout.work, "Android work")
    primary: BaseException | None = None
    try:
        capability_present = True
        try:
            snapshot = load_json_object_snapshot_at(
                directory_fd,
                CAPABILITY_LEAF,
                display_path=layout.capability,
                maximum=MAX_CAPABILITY_BYTES,
                label="Android command capability",
                validate_metadata=_private_metadata,
            )
        except EvidenceIOError:
            try:
                os.stat(
                    CAPABILITY_LEAF,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                capability_present = False
            else:
                raise
        if capability_present:
            capability = _capability_from_snapshot_for_layout(snapshot, layout=layout)
            _require(
                capability.adb_profile == receipt.adb_profile
                and capability.adb_size == receipt.adb_size
                and capability.adb_sha256 == receipt.adb_sha256
                and capability.socket_nonce == receipt.socket_nonce
                and capability.native_adb_notifier_port
                == receipt.native_adb_notifier_port
                and capability.device_kind == receipt.device_kind
                and capability.expected_serial == receipt.expected_serial,
                "recovery capability differs from the owned runtime receipt",
            )
        adb_leaf = _adb_snapshot_leaf(layout.run_id)
        adb_present = True
        try:
            adb_snapshot = consume_regular_snapshot_at(
                directory_fd,
                adb_leaf,
                display_path=layout.work / adb_leaf,
                maximum=MAX_TOOL_BYTES,
                label="Android adb snapshot",
                validate_metadata=_private_executable_metadata,
            )
        except EvidenceIOError:
            try:
                os.stat(adb_leaf, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                adb_present = False
            else:
                raise
        if adb_present:
            _require(
                adb_snapshot.size == receipt.adb_size
                and adb_snapshot.sha256 == receipt.adb_sha256,
                "recovery adb snapshot differs from the owned runtime receipt",
            )
            os.unlink(adb_leaf, dir_fd=directory_fd)
            os.fsync(directory_fd)
        if capability_present:
            os.unlink(CAPABILITY_LEAF, dir_fd=directory_fd)
            os.fsync(directory_fd)
    except OSError as exc:
        primary = AndroidRuntimeStateError(
            f"cannot retire Android recovery capability: {exc}"
        )
        raise primary from exc
    except BaseException as exc:
        primary = exc
        raise
    finally:
        _close_owned_descriptor(
            directory_fd,
            label="the Android recovery work directory",
            primary=primary,
        )


def retire_recovery_capability(
    layout: AndroidRunLayout,
    receipt: OwnedRuntimeReceipt,
) -> None:
    _retire_recovery_capability_from_receipt(layout, receipt)


def _capability_from_snapshot(
    snapshot: JsonObjectSnapshot,
    *,
    expected_run_id: str,
) -> AndroidCommandCapability:
    return _capability_from_snapshot_for_layout(
        snapshot,
        layout=AndroidRunLayout.from_run_id(expected_run_id),
    )


def _capability_from_snapshot_for_layout(
    snapshot: JsonObjectSnapshot,
    *,
    layout: AndroidRunLayout,
) -> AndroidCommandCapability:
    value = snapshot.value
    _require(
        set(value) == CAPABILITY_FIELDS, "Android command capability fields changed"
    )
    _require(
        type(value.get("schema_version")) is int
        and value.get("schema_version") == SCHEMA_VERSION,
        "Android command schema changed",
    )
    _require(value.get("kind") == KIND, "Android command capability kind changed")
    adb_profile = _canonical_concrete_adb_profile(value.get("adb_profile"))
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
    native_adb_notifier_port = value.get("native_adb_notifier_port")
    server_socket, socket_path = _server_socket_identity(socket_nonce)
    device_kind = _canonical_device_kind(value.get("device_kind"))
    _require(
        (
            device_kind == "emulator"
            and type(native_adb_notifier_port) is int
            and native_adb_notifier_port == NATIVE_ADB_NOTIFIER_PORT
        )
        or (device_kind == "physical" and native_adb_notifier_port is None),
        "native adb notifier port changed shape",
    )
    expected_serial = _canonical_expected_serial(
        value.get("expected_serial"), device_kind
    )
    run_id = _canonical_run_id(value.get("run_id"))
    _require(
        run_id == layout.run_id,
        "Android command capability belongs to a different run",
    )
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
        adb_snapshot_path=layout.work / _adb_snapshot_leaf(run_id),
        adb_size=adb_size,
        adb_sha256=adb_sha256,
        socket_nonce=socket_nonce,
        native_adb_notifier_port=native_adb_notifier_port,
        server_socket=server_socket,
        socket_path=socket_path,
        vendor_key=vendor_key,
        device_kind=device_kind,
        expected_serial=expected_serial,
        run_id=run_id,
        signed_apk_size=signed_apk_size,
        signed_apk_sha256=signed_apk_sha256,
    )


def load_capability(run_id: str) -> AndroidCommandCapability:
    layout = AndroidRunLayout.from_run_id(run_id)
    snapshot = load_json_object_snapshot(
        layout.capability,
        maximum=MAX_CAPABILITY_BYTES,
        label="Android command capability",
        validate_metadata=_private_metadata,
    )
    return _capability_from_snapshot(snapshot, expected_run_id=layout.run_id)


def adb_snapshot_leaf(run_id: object) -> str:
    return _adb_snapshot_leaf(_canonical_run_id(run_id))


def open_private_directory(path: pathlib.Path, label: str) -> int:
    return _open_private_directory(path, label)


def close_descriptor(
    descriptor: int,
    *,
    label: str,
    primary: BaseException | None = None,
) -> None:
    _close_owned_descriptor(descriptor, label=label, primary=primary)


def private_file_metadata(metadata: os.stat_result) -> None:
    _private_metadata(metadata)


def private_executable_metadata(metadata: os.stat_result) -> None:
    _private_executable_metadata(metadata)


def executable_metadata(metadata: os.stat_result) -> None:
    _executable_metadata(metadata)


def load_capability_snapshot_for_layout(
    snapshot: JsonObjectSnapshot,
    *,
    layout: AndroidRunLayout,
) -> AndroidCommandCapability:
    return _capability_from_snapshot_for_layout(snapshot, layout=layout)


def canonical_avd_name(value: object) -> str:
    return _canonical_avd_name(value)


def canonical_runtime_emulator_abi(
    value: object,
) -> Literal["arm64-v8a", "x86_64"]:
    return _canonical_emulator_abi(value)


def _canonical_avd_name(value: object) -> str:
    rebuilt = _canonical_ascii_atom(
        value,
        characters=_AVD_NAME_CHARACTERS,
        minimum=1,
        maximum=128,
        label="Android AVD name",
    )
    _require(AVD_NAME.fullmatch(rebuilt) is not None, "Android AVD name is invalid")
    return rebuilt


def _canonical_emulator_abi(value: object) -> Literal["arm64-v8a", "x86_64"]:
    try:
        return canonical_emulator_abi(value)
    except AndroidEmulatorControlError as exc:
        raise AndroidRuntimeStateError(str(exc)) from exc


def _executable_file_identity(path: pathlib.Path, label: str) -> tuple[int, int]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise AndroidRuntimeStateError(f"cannot inspect {label}: {exc}") from exc
    _require(
        stat.S_ISREG(metadata.st_mode)
        and not path.is_symlink()
        and metadata.st_mode & 0o111 != 0,
        f"{label} must be a non-symlink executable regular file",
    )
    return metadata.st_dev, metadata.st_ino


def _runtime_recovery_payload(
    capability: AndroidCommandCapability,
) -> dict[str, object]:
    """Build durable recovery state before the private adb server can start."""

    repository_root = REPOSITORY_ROOT.resolve(strict=True)
    layout = AndroidRunLayout.from_run_id(capability.run_id)
    run_root_metadata = layout.root.lstat()
    _server_socket, socket_path = _server_socket_identity(capability.socket_nonce)
    socket_directory = pathlib.Path(socket_path).parent
    try:
        socket_directory_metadata = socket_directory.lstat()
    except OSError as exc:
        raise AndroidRuntimeStateError(
            f"cannot bind private adb socket directory for recovery: {exc}"
        ) from exc
    try:
        host_boot = host_boot_identity()
    except ProcessIdentityError as exc:
        raise AndroidRuntimeStateError(
            f"cannot bind runtime recovery host: {exc}"
        ) from exc
    _require(
        stat.S_ISDIR(run_root_metadata.st_mode)
        and not layout.root.is_symlink()
        and run_root_metadata.st_uid == os.geteuid()
        and stat.S_IMODE(run_root_metadata.st_mode) == 0o700,
        "runtime recovery run root is not one private current-user directory",
    )
    _require(
        stat.S_ISDIR(socket_directory_metadata.st_mode)
        and not socket_directory.is_symlink()
        and socket_directory_metadata.st_uid == os.geteuid()
        and stat.S_IMODE(socket_directory_metadata.st_mode) == 0o700,
        "private adb socket directory is not one private current-user directory",
    )
    return {
        "schema_version": OWNED_RUNTIME_RECEIPT_SCHEMA_VERSION,
        "kind": OWNED_RUNTIME_RECEIPT_KIND,
        "phase": RuntimePhase.PREPARED.value,
        "run_id": capability.run_id,
        "host_identity": host_boot.host,
        "boot_identity": host_boot.boot,
        "repository_root": str(repository_root),
        "run_root_device": run_root_metadata.st_dev,
        "run_root_inode": run_root_metadata.st_ino,
        "pid": None,
        "uid": os.geteuid(),
        "started_at": None,
        "started_subsecond": None,
        "process_identity": None,
        "adb_profile": capability.adb_profile,
        "adb_size": capability.adb_size,
        "adb_sha256": capability.adb_sha256,
        "socket_nonce": capability.socket_nonce,
        "native_adb_notifier_port": capability.native_adb_notifier_port,
        "device_kind": capability.device_kind,
        "adb_server_pid": None,
        "adb_server_started_at": None,
        "adb_server_started_subsecond": None,
        "adb_server_process_identity": None,
        "adb_server_initial_executable": None,
        "adb_server_initial_executable_device": None,
        "adb_server_initial_executable_inode": None,
        "adb_snapshot_device": None,
        "adb_snapshot_inode": None,
        "adb_socket_directory_device": socket_directory_metadata.st_dev,
        "adb_socket_directory_inode": socket_directory_metadata.st_ino,
        "avd_name": None,
        "device_abi": None,
        "expected_serial": capability.expected_serial,
        "console_port": None,
        "console_auth_token_device": None,
        "console_auth_token_inode": None,
        "console_auth_token_sha256": None,
        "launcher_path": None,
        "launcher_device": None,
        "launcher_inode": None,
        "backend_path": None,
        "backend_device": None,
        "backend_inode": None,
        "backend_sha256": None,
    }


def _runtime_receipt_payload(receipt: OwnedRuntimeReceipt) -> dict[str, object]:
    """Serialize one already-validated runtime receipt without its file digest."""

    return {
        "schema_version": OWNED_RUNTIME_RECEIPT_SCHEMA_VERSION,
        "kind": OWNED_RUNTIME_RECEIPT_KIND,
        "phase": receipt.phase.value,
        "run_id": receipt.run_id,
        "host_identity": receipt.host_identity,
        "boot_identity": receipt.boot_identity,
        "repository_root": str(receipt.repository_root),
        "run_root_device": receipt.run_root_device,
        "run_root_inode": receipt.run_root_inode,
        "pid": receipt.pid,
        "uid": receipt.uid,
        "started_at": receipt.started_at,
        "started_subsecond": receipt.started_subsecond,
        "process_identity": receipt.process_identity,
        "adb_profile": receipt.adb_profile,
        "adb_size": receipt.adb_size,
        "adb_sha256": receipt.adb_sha256,
        "socket_nonce": receipt.socket_nonce,
        "native_adb_notifier_port": receipt.native_adb_notifier_port,
        "device_kind": receipt.device_kind,
        "expected_serial": receipt.expected_serial,
        "adb_server_pid": receipt.adb_server_pid,
        "adb_server_started_at": receipt.adb_server_started_at,
        "adb_server_started_subsecond": receipt.adb_server_started_subsecond,
        "adb_server_process_identity": receipt.adb_server_process_identity,
        "adb_server_initial_executable": (
            str(receipt.adb_server_initial_executable)
            if receipt.adb_server_initial_executable is not None
            else None
        ),
        "adb_server_initial_executable_device": (
            receipt.adb_server_initial_executable_device
        ),
        "adb_server_initial_executable_inode": (
            receipt.adb_server_initial_executable_inode
        ),
        "adb_snapshot_device": receipt.adb_snapshot_device,
        "adb_snapshot_inode": receipt.adb_snapshot_inode,
        "adb_socket_directory_device": receipt.adb_socket_directory_device,
        "adb_socket_directory_inode": receipt.adb_socket_directory_inode,
        "avd_name": receipt.avd_name,
        "device_abi": receipt.device_abi,
        "console_port": receipt.console_port,
        "console_auth_token_device": receipt.console_auth_token_device,
        "console_auth_token_inode": receipt.console_auth_token_inode,
        "console_auth_token_sha256": receipt.console_auth_token_sha256,
        "launcher_path": (
            str(receipt.launcher_path) if receipt.launcher_path is not None else None
        ),
        "launcher_device": receipt.launcher_device,
        "launcher_inode": receipt.launcher_inode,
        "backend_path": (
            str(receipt.backend_path) if receipt.backend_path is not None else None
        ),
        "backend_device": receipt.backend_device,
        "backend_inode": receipt.backend_inode,
        "backend_sha256": receipt.backend_sha256,
    }


def _cleanup_owned_runtime_receipt_staging_files() -> None:
    """Remove only abandoned receipt stages while the stable lane lock is held."""

    state_fd = _open_account_state()
    primary: BaseException | None = None
    try:
        pending_prefix = f".{OWNED_RUNTIME_RECEIPT_LEAF}.pending-"
        replace_prefix = f".{OWNED_RUNTIME_RECEIPT_LEAF}.replace-"
        exact = re.compile(
            rf"\.{re.escape(OWNED_RUNTIME_RECEIPT_LEAF)}\."
            r"(?:pending|replace)-[1-9][0-9]{0,19}"
        )
        candidates: list[str] = []
        for leaf in os.listdir(state_fd):
            if not (leaf.startswith(pending_prefix) or leaf.startswith(replace_prefix)):
                continue
            _require(
                exact.fullmatch(leaf) is not None,
                "owned runtime receipt staging filename is malformed",
            )
            candidates.append(leaf)
        _require(
            len(candidates) <= 64,
            "owned runtime receipt staging inventory exceeds its fixed bound",
        )
        for leaf in sorted(candidates):
            descriptor = -1
            file_primary: BaseException | None = None
            try:
                descriptor = os.open(
                    leaf,
                    os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=state_fd,
                )
                _verify_private_control_descriptor(
                    descriptor, "abandoned owned runtime receipt staging file"
                )
                opened = os.fstat(descriptor)
                named = os.stat(leaf, dir_fd=state_fd, follow_symlinks=False)
                _require(
                    (opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino),
                    "owned runtime receipt staging identity changed before cleanup",
                )
                os.unlink(leaf, dir_fd=state_fd)
                os.fsync(state_fd)
            except OSError as exc:
                file_primary = AndroidRuntimeStateError(
                    f"cannot clean abandoned owned runtime receipt staging file: {exc}"
                )
                raise file_primary from exc
            except BaseException as exc:
                file_primary = exc
                raise
            finally:
                if descriptor >= 0:
                    _close_owned_descriptor(
                        descriptor,
                        label="the abandoned owned runtime receipt staging file",
                        primary=file_primary,
                    )
    except BaseException as exc:
        primary = exc
        raise
    finally:
        _close_owned_descriptor(
            state_fd,
            label="the Android account-state directory",
            primary=primary,
        )


def cleanup_owned_runtime_receipt_staging_files() -> None:
    validate_lane_lock_descriptor()
    _cleanup_owned_runtime_receipt_staging_files()


def create_runtime_recovery_receipt(run_id: str) -> None:
    validate_lane_lock_descriptor()
    _cleanup_owned_runtime_receipt_staging_files()
    capability = load_capability(run_id)
    _write_owned_runtime_receipt(_runtime_recovery_payload(capability))


def _record_adb_isolation_checkpoint(
    run_id: str,
    checkpoint: AdbIsolationCheckpoint,
    *,
    internal_pre_exec: bool,
) -> pathlib.Path:
    """Admit, observe, and durably publish one fixed isolation checkpoint."""

    validate_lane_lock_descriptor()
    canonical_run = _canonical_run_id(run_id)
    _require(
        type(checkpoint) is AdbIsolationCheckpoint,
        "Android adb isolation checkpoint is invalid",
    )
    _require(
        (
            internal_pre_exec
            and checkpoint is AdbIsolationCheckpoint.EMULATOR_PRE_EXEC
        )
        or (
            not internal_pre_exec
            and checkpoint
            in {
                AdbIsolationCheckpoint.EMULATOR_POST_REGISTRATION,
                AdbIsolationCheckpoint.RUNTIME_PRE_CLEANUP,
            }
        ),
        "Android adb isolation checkpoint is not admitted by this API",
    )
    layout = AndroidRunLayout.from_run_id(canonical_run)
    checkpoint_order = tuple(AdbIsolationCheckpoint)
    checkpoint_index = checkpoint_order.index(checkpoint)
    for prior_checkpoint in checkpoint_order[:checkpoint_index]:
        prior_leaf = ADB_ISOLATION_CHECKPOINT_LEAVES[prior_checkpoint]
        try:
            prior_snapshot = load_json_object_snapshot(
                layout.proof / prior_leaf,
                maximum=4096,
                label=f"Android adb isolation {prior_checkpoint.value} checkpoint",
                validate_metadata=_private_metadata,
            )
        except EvidenceIOError as exc:
            raise AndroidRuntimeStateError(
                f"cannot load prior Android adb isolation checkpoint: {exc}"
            ) from exc
        expected_prior = {
            "schema": ADB_ISOLATION_RECEIPT_SCHEMA_VERSION,
            "kind": ADB_ISOLATION_RECEIPT_KIND,
            "run_id": canonical_run,
            "checkpoint": prior_checkpoint.value,
            "ports": AdbIsolationObservation().ports_payload(),
        }
        expected_bytes = (
            json.dumps(expected_prior, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        _require(
            prior_snapshot.value == expected_prior
            and prior_snapshot.file.data == expected_bytes,
            "prior Android adb isolation checkpoint changed",
        )
    receipt = load_owned_runtime_receipt()
    _require(
        receipt is not None
        and receipt.run_id == canonical_run
        and receipt.phase is RuntimePhase.EMULATOR_CHILD_REGISTERED
        and receipt.native_adb_notifier_port == NATIVE_ADB_NOTIFIER_PORT,
        "adb isolation checkpoint lacks this run's active emulator receipt",
    )
    capability = load_capability(canonical_run)
    _require(
        capability.device_kind == "emulator"
        and capability.native_adb_notifier_port == NATIVE_ADB_NOTIFIER_PORT,
        "adb isolation checkpoint lacks its emulator capability",
    )
    snapshot = consume_regular_snapshot(
        capability.adb_snapshot_path,
        maximum=MAX_TOOL_BYTES,
        label="Android adb snapshot",
        validate_metadata=_private_executable_metadata,
    )
    _require(
        snapshot.size == capability.adb_size
        and snapshot.sha256 == capability.adb_sha256,
        "adb isolation checkpoint adb snapshot identity changed",
    )
    _server_socket, socket_path = _server_socket_identity(receipt.socket_nonce)
    socket_directory = pathlib.Path(socket_path).parent
    metadata = socket_directory.lstat()
    _require(
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and stat.S_IMODE(metadata.st_mode) == 0o500
        and (metadata.st_dev, metadata.st_ino)
        == (
            receipt.adb_socket_directory_device,
            receipt.adb_socket_directory_inode,
        ),
        "adb isolation checkpoint private adb directory is not sealed",
    )
    if checkpoint is AdbIsolationCheckpoint.EMULATOR_POST_REGISTRATION:
        try:
            routing_snapshot = load_json_object_snapshot(
                layout.proof / EMULATOR_ROUTING_RECEIPT_LEAF,
                maximum=16 * 1024,
                label="Android emulator routing receipt",
                validate_metadata=_private_metadata,
            )
        except EvidenceIOError as exc:
            raise AndroidRuntimeStateError(
                f"cannot load Android emulator routing receipt: {exc}"
            ) from exc
        try:
            parse_emulator_routing_receipt(
                routing_snapshot.value,
                run_id=canonical_run,
            )
        except AndroidEmulatorControlError as exc:
            raise AndroidRuntimeStateError(str(exc)) from exc
        expected_routing_bytes = (
            json.dumps(routing_snapshot.value, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        _require(
            routing_snapshot.file.data == expected_routing_bytes,
            "Android emulator routing receipt is not canonical",
        )
    try:
        observation = probe_adb_loopback_absence()
    except AndroidEmulatorControlError as exc:
        raise AndroidRuntimeStateError(str(exc)) from exc
    leaf = ADB_ISOLATION_CHECKPOINT_LEAVES[checkpoint]
    proof_fd = _open_private_directory(layout.proof, "Android proof")
    descriptor = -1
    created = False
    primary: BaseException | None = None
    try:
        payload = {
            "schema": ADB_ISOLATION_RECEIPT_SCHEMA_VERSION,
            "kind": ADB_ISOLATION_RECEIPT_KIND,
            "run_id": canonical_run,
            "checkpoint": checkpoint.value,
            "ports": observation.ports_payload(),
        }
        encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
        descriptor = os.open(
            leaf,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=proof_fd,
        )
        created = True
        os.fchmod(descriptor, 0o600)
        _private_metadata(os.fstat(descriptor))
        _write_all(descriptor, encoded, label="Android adb isolation checkpoint")
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.fsync(proof_fd)
        return layout.proof / leaf
    except BaseException as exc:
        primary = exc
        if descriptor >= 0:
            _close_owned_descriptor(
                descriptor,
                label="the incomplete Android adb isolation checkpoint",
                primary=primary,
            )
            descriptor = -1
        if created:
            try:
                os.unlink(leaf, dir_fd=proof_fd)
                os.fsync(proof_fd)
            except BaseException as cleanup_error:
                primary.add_note(
                    "removing the incomplete Android adb isolation checkpoint "
                    f"also failed: {cleanup_error}"
                )
        raise
    finally:
        _close_owned_descriptor(
            proof_fd, label="the Android proof directory", primary=primary
        )


def record_pre_exec_adb_isolation_checkpoint(run_id: str) -> pathlib.Path:
    """Internal emulator-exec-only admission for the pre-exec checkpoint."""

    return _record_adb_isolation_checkpoint(
        run_id,
        AdbIsolationCheckpoint.EMULATOR_PRE_EXEC,
        internal_pre_exec=True,
    )


def record_adb_isolation_checkpoint(
    run_id: str,
    checkpoint: AdbIsolationCheckpoint,
) -> pathlib.Path:
    """Record one shell-admitted post-registration or pre-cleanup checkpoint."""

    return _record_adb_isolation_checkpoint(
        run_id,
        checkpoint,
        internal_pre_exec=False,
    )


def record_post_cleanup_adb_isolation_checkpoint(
    receipt: OwnedRuntimeReceipt,
) -> pathlib.Path:
    """Durably stage post-cleanup evidence before exact receipt retirement."""

    validate_lane_lock_descriptor()
    current_receipt = load_owned_runtime_receipt()
    _require(
        current_receipt is not None
        and current_receipt.snapshot_sha256 == receipt.snapshot_sha256
        and current_receipt.run_id == receipt.run_id
        and receipt.device_kind == "emulator",
        "post-cleanup adb isolation requires the exact emulator runtime receipt",
    )
    canonical_run = _canonical_run_id(receipt.run_id)
    layout = AndroidRunLayout.from_run_id(canonical_run)
    _require(
        not os.path.lexists(layout.capability)
        and not os.path.lexists(layout.work / _adb_snapshot_leaf(canonical_run)),
        "post-cleanup adb isolation requires capability resources to be retired",
    )
    checkpoint = AdbIsolationCheckpoint.RUNTIME_POST_CLEANUP
    checkpoint_order = tuple(AdbIsolationCheckpoint)
    for prior_checkpoint in checkpoint_order[:-1]:
        try:
            prior_snapshot = load_json_object_snapshot(
                layout.proof / ADB_ISOLATION_CHECKPOINT_LEAVES[prior_checkpoint],
                maximum=4096,
                label=f"Android adb isolation {prior_checkpoint.value} checkpoint",
                validate_metadata=_private_metadata,
            )
        except EvidenceIOError as exc:
            raise AndroidRuntimeStateError(
                f"cannot load prior Android adb isolation checkpoint: {exc}"
            ) from exc
        expected_prior = {
            "schema": ADB_ISOLATION_RECEIPT_SCHEMA_VERSION,
            "kind": ADB_ISOLATION_RECEIPT_KIND,
            "run_id": canonical_run,
            "checkpoint": prior_checkpoint.value,
            "ports": AdbIsolationObservation().ports_payload(),
        }
        expected_bytes = (
            json.dumps(expected_prior, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        _require(
            prior_snapshot.value == expected_prior
            and prior_snapshot.file.data == expected_bytes,
            "prior Android adb isolation checkpoint changed",
        )
    try:
        observation = probe_adb_loopback_absence()
    except AndroidEmulatorControlError as exc:
        raise AndroidRuntimeStateError(str(exc)) from exc
    leaf = ADB_ISOLATION_CHECKPOINT_LEAVES[checkpoint]
    proof_fd = _open_private_directory(layout.proof, "Android proof")
    descriptor = -1
    created = False
    primary: BaseException | None = None
    try:
        payload = {
            "schema": ADB_ISOLATION_RECEIPT_SCHEMA_VERSION,
            "kind": ADB_ISOLATION_RECEIPT_KIND,
            "run_id": canonical_run,
            "checkpoint": checkpoint.value,
            "ports": observation.ports_payload(),
        }
        encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
        current_receipt = load_owned_runtime_receipt()
        _require(
            current_receipt is not None
            and current_receipt.snapshot_sha256 == receipt.snapshot_sha256,
            "owned runtime receipt changed during post-cleanup observation",
        )
        try:
            existing = load_json_object_snapshot_at(
                proof_fd,
                leaf,
                display_path=layout.proof / leaf,
                maximum=4096,
                label="Android post-cleanup adb isolation checkpoint",
                validate_metadata=_private_metadata,
            )
        except EvidenceIOError as exc:
            try:
                os.stat(leaf, dir_fd=proof_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise AndroidRuntimeStateError(
                    f"cannot load existing post-cleanup adb isolation checkpoint: {exc}"
                ) from exc
        else:
            _require(
                existing.value == payload and existing.file.data == encoded,
                "existing post-cleanup adb isolation checkpoint changed",
            )
            os.fsync(proof_fd)
            current_receipt = load_owned_runtime_receipt()
            _require(
                current_receipt is not None
                and current_receipt.snapshot_sha256 == receipt.snapshot_sha256,
                "owned runtime receipt changed while confirming post-cleanup evidence",
            )
            return layout.proof / leaf
        descriptor = os.open(
            leaf,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=proof_fd,
        )
        created = True
        os.fchmod(descriptor, 0o600)
        _private_metadata(os.fstat(descriptor))
        _write_all(
            descriptor,
            encoded,
            label="Android post-cleanup adb isolation checkpoint",
        )
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.fsync(proof_fd)
        current_receipt = load_owned_runtime_receipt()
        _require(
            current_receipt is not None
            and current_receipt.snapshot_sha256 == receipt.snapshot_sha256,
            "owned runtime receipt changed while publishing post-cleanup evidence",
        )
        return layout.proof / leaf
    except BaseException as exc:
        primary = exc
        if descriptor >= 0:
            _close_owned_descriptor(
                descriptor,
                label="the incomplete Android post-cleanup isolation checkpoint",
                primary=primary,
            )
            descriptor = -1
        if created:
            try:
                os.unlink(leaf, dir_fd=proof_fd)
                os.fsync(proof_fd)
            except BaseException as cleanup_error:
                primary.add_note(
                    "removing the incomplete Android post-cleanup isolation "
                    f"checkpoint also failed: {cleanup_error}"
                )
        raise
    finally:
        _close_owned_descriptor(
            proof_fd, label="the Android proof directory", primary=primary
        )


def record_emulator_routing_receipt(
    run_id: str,
    *,
    adb_snapshot_sha256: str,
    routing_environment_sha256: str,
    private_adb: Mapping[str, str],
) -> pathlib.Path:
    """Durably publish the exact adapter-derived emulator routing projection."""

    validate_lane_lock_descriptor()
    canonical_run = _canonical_run_id(run_id)
    _require(
        isinstance(adb_snapshot_sha256, str)
        and HEX_SHA256.fullmatch(adb_snapshot_sha256) is not None,
        "emulator routing adb snapshot digest is invalid",
    )
    _require(
        isinstance(routing_environment_sha256, str)
        and HEX_SHA256.fullmatch(routing_environment_sha256) is not None,
        "emulator routing environment digest is invalid",
    )
    _require(
        isinstance(private_adb, Mapping)
        and set(private_adb) == EMULATOR_ROUTING_PRIVATE_ADB_FIELDS,
        "emulator routing private adb fields changed",
    )
    canonical_private_adb = dict(private_adb)
    for name, digest in canonical_private_adb.items():
        _require(
            isinstance(digest, str) and HEX_SHA256.fullmatch(digest) is not None,
            f"emulator routing private adb digest is invalid: {name}",
        )
    layout = AndroidRunLayout.from_run_id(canonical_run)
    receipt = load_owned_runtime_receipt()
    _require(
        receipt is not None
        and receipt.run_id == canonical_run
        and receipt.phase is RuntimePhase.EMULATOR_CHILD_REGISTERED
        and receipt.native_adb_notifier_port == NATIVE_ADB_NOTIFIER_PORT,
        "emulator routing lacks this run's registered child receipt",
    )
    capability = load_capability(canonical_run)
    _require(
        capability.device_kind == "emulator"
        and capability.adb_sha256 == adb_snapshot_sha256
        and capability.native_adb_notifier_port == NATIVE_ADB_NOTIFIER_PORT,
        "emulator routing capability differs",
    )
    transport_binding_sha256 = emulator_routing_transport_binding_sha256(
        adb_snapshot_sha256,
        routing_environment_sha256,
        canonical_private_adb,
    )
    payload = {
        "schema": EMULATOR_ROUTING_RECEIPT_SCHEMA_VERSION,
        "kind": EMULATOR_ROUTING_RECEIPT_KIND,
        "run_id": canonical_run,
        "mode": EMULATOR_ROUTING_MODE,
        "adb_snapshot_sha256": adb_snapshot_sha256,
        "routing_environment_sha256": routing_environment_sha256,
        "transport_binding_sha256": transport_binding_sha256,
        "private_adb": canonical_private_adb,
        "native_notifier_port": NATIVE_ADB_NOTIFIER_PORT,
        "private_socket_kind": "localfilesystem",
        "raw_paths_recorded": False,
    }
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    proof_fd = _open_private_directory(layout.proof, "Android proof")
    descriptor = -1
    created = False
    primary: BaseException | None = None
    try:
        descriptor = os.open(
            EMULATOR_ROUTING_RECEIPT_LEAF,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=proof_fd,
        )
        created = True
        os.fchmod(descriptor, 0o600)
        _private_metadata(os.fstat(descriptor))
        _write_all(descriptor, encoded, label="Android emulator routing receipt")
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.fsync(proof_fd)
        return layout.proof / EMULATOR_ROUTING_RECEIPT_LEAF
    except BaseException as exc:
        primary = exc
        if descriptor >= 0:
            _close_owned_descriptor(
                descriptor,
                label="the incomplete Android emulator routing receipt",
                primary=primary,
            )
            descriptor = -1
        if created:
            try:
                os.unlink(EMULATOR_ROUTING_RECEIPT_LEAF, dir_fd=proof_fd)
                os.fsync(proof_fd)
            except BaseException as cleanup_error:
                primary.add_note(
                    "removing the incomplete Android emulator routing receipt "
                    f"also failed: {cleanup_error}"
                )
        raise
    finally:
        _close_owned_descriptor(
            proof_fd, label="the Android proof directory", primary=primary
        )


def _write_owned_runtime_receipt(payload: Mapping[str, object]) -> str:
    state_fd = _open_account_state()
    descriptor = -1
    temporary_leaf = f".{OWNED_RUNTIME_RECEIPT_LEAF}.pending-{os.getpid()}"
    temporary_created = False
    published = False
    primary: BaseException | None = None
    try:
        encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        _require(
            len(encoded) <= MAX_OWNED_RUNTIME_RECEIPT_BYTES,
            "owned runtime receipt is oversized",
        )
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            os.stat(
                OWNED_RUNTIME_RECEIPT_LEAF,
                dir_fd=state_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise AndroidRuntimeStateError(
                "an owned runtime recovery receipt already exists"
            )
        descriptor = os.open(
            temporary_leaf,
            flags,
            0o600,
            dir_fd=state_fd,
        )
        temporary_created = True
        os.fchmod(descriptor, 0o600)
        _verify_private_control_descriptor(descriptor, "owned runtime receipt")
        _write_all(descriptor, encoded, label="owned runtime receipt")
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        _rename_sibling_noreplace(
            state_fd,
            temporary_leaf,
            OWNED_RUNTIME_RECEIPT_LEAF,
        )
        published = True
        temporary_created = False
        os.fsync(state_fd)
        return hashlib.sha256(encoded).hexdigest()
    except BaseException as exc:
        primary = exc
        if descriptor >= 0:
            _close_owned_descriptor(
                descriptor,
                label="the incomplete owned runtime receipt",
                primary=primary,
            )
        if temporary_created:
            try:
                os.unlink(temporary_leaf, dir_fd=state_fd)
                os.fsync(state_fd)
            except BaseException as cleanup_error:
                primary.add_note(
                    f"removing the incomplete owned runtime receipt staging file also failed: {cleanup_error}"
                )
        if published:
            primary.add_note(
                "owned runtime receipt was durably published before a later cleanup failure"
            )
        raise
    finally:
        _close_owned_descriptor(
            state_fd,
            label="the Android account-state directory",
            primary=primary,
        )


def _replace_owned_runtime_receipt(
    prior: OwnedRuntimeReceipt,
    payload: Mapping[str, object],
) -> OwnedRuntimeReceipt:
    """Atomically advance the exact current recovery receipt."""

    state_fd = _open_account_state()
    temporary_leaf = f".{OWNED_RUNTIME_RECEIPT_LEAF}.replace-{os.getpid()}"
    descriptor = -1
    receipt_fd = -1
    primary: BaseException | None = None
    try:
        receipt_fd = _open_owned_runtime_receipt_for_mutation(state_fd)
        _lock_account_state_for_receipt_mutation(state_fd)
        _require_locked_receipt_is_current(
            state_fd,
            receipt_fd,
            prior.snapshot_sha256,
            action="lifecycle advance",
        )
        encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        _require(
            len(encoded) <= MAX_OWNED_RUNTIME_RECEIPT_BYTES,
            "owned runtime receipt is oversized",
        )
        next_snapshot = JsonObjectSnapshot(
            file=FileSnapshot(
                path=owned_runtime_receipt_path(),
                data=encoded,
                size=len(encoded),
                sha256=hashlib.sha256(encoded).hexdigest(),
            ),
            value=dict(payload),
        )
        next_receipt = _owned_runtime_from_snapshot(next_snapshot)
        descriptor = os.open(
            temporary_leaf,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=state_fd,
        )
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, encoded, label="owned runtime receipt replacement")
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(
            temporary_leaf,
            OWNED_RUNTIME_RECEIPT_LEAF,
            src_dir_fd=state_fd,
            dst_dir_fd=state_fd,
        )
        os.fsync(state_fd)
        return next_receipt
    except BaseException as exc:
        primary = exc
        if descriptor >= 0:
            _close_owned_descriptor(
                descriptor,
                label="the owned runtime receipt replacement",
                primary=primary,
            )
        try:
            os.unlink(temporary_leaf, dir_fd=state_fd)
        except FileNotFoundError:
            pass
        except BaseException as cleanup_error:
            primary.add_note(
                f"removing the receipt replacement staging file also failed: {cleanup_error}"
            )
        raise
    finally:
        if receipt_fd >= 0:
            _close_owned_descriptor(
                receipt_fd,
                label="the lifecycle-locked owned runtime receipt",
                primary=primary,
            )
        _close_owned_descriptor(
            state_fd,
            label="the Android account-state directory",
            primary=primary,
        )


def _open_owned_runtime_receipt_for_mutation(state_fd: int) -> int:
    """Open and validate the named receipt before the mutation lock."""

    try:
        descriptor = os.open(
            OWNED_RUNTIME_RECEIPT_LEAF,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=state_fd,
        )
    except OSError as exc:
        raise AndroidRuntimeStateError(
            f"cannot open owned runtime receipt for lifecycle mutation: {exc}"
        ) from exc
    try:
        _verify_private_control_descriptor(
            descriptor, "owned runtime receipt lifecycle mutation"
        )
        return descriptor
    except BaseException as primary:
        _close_owned_descriptor(
            descriptor,
            label="the rejected owned runtime receipt lifecycle mutation",
            primary=primary,
        )
        raise


def _lock_account_state_for_receipt_mutation(state_fd: int) -> None:
    """Serialize receipt mutation on the stable account-state directory inode."""

    try:
        fcntl.flock(state_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        _fail("owned runtime receipt has a concurrent lifecycle mutation")
    except OSError as exc:
        raise AndroidRuntimeStateError(
            f"cannot lock Android account state for lifecycle mutation: {exc}"
        ) from exc


def _require_locked_receipt_is_current(
    state_fd: int,
    receipt_fd: int,
    expected_sha256: str,
    *,
    action: str,
) -> JsonObjectSnapshot:
    """Bind the locked inode to the named receipt and expected prior bytes."""

    locked = os.fstat(receipt_fd)
    named = os.stat(
        OWNED_RUNTIME_RECEIPT_LEAF,
        dir_fd=state_fd,
        follow_symlinks=False,
    )
    _require(
        (locked.st_dev, locked.st_ino) == (named.st_dev, named.st_ino),
        f"owned runtime receipt changed before {action}",
    )
    current = load_json_object_snapshot_at(
        state_fd,
        OWNED_RUNTIME_RECEIPT_LEAF,
        display_path=owned_runtime_receipt_path(),
        maximum=MAX_OWNED_RUNTIME_RECEIPT_BYTES,
        label="owned runtime receipt",
        validate_metadata=_private_control_file_metadata,
    )
    _require(
        current.file.sha256 == expected_sha256,
        f"owned runtime receipt changed before {action}",
    )
    return current


def register_adb_child(
    receipt: OwnedRuntimeReceipt,
    registration: AdbChildRegistration,
) -> OwnedRuntimeReceipt:
    """CAS PREPARED to ADB_CHILD_REGISTERED with the exact child identity."""

    validate_lane_lock_descriptor()
    _require(
        receipt.phase is RuntimePhase.PREPARED,
        "runtime recovery receipt is not awaiting an adb child",
    )
    identity = registration.process
    _require(
        identity.pid == os.getpid()
        and identity.uid == os.geteuid()
        and registration.initial_executable_device >= 0
        and registration.initial_executable_inode > 0
        and registration.adb_snapshot_device >= 0
        and registration.adb_snapshot_inode > 0,
        "adb child registration identity is invalid",
    )
    payload = _runtime_receipt_payload(receipt)
    payload.update(
        {
            "phase": RuntimePhase.ADB_CHILD_REGISTERED.value,
            "adb_server_pid": identity.pid,
            "adb_server_started_at": identity.started_at,
            "adb_server_started_subsecond": identity.started_subsecond,
            "adb_server_process_identity": identity.token,
            "adb_server_initial_executable": str(identity.executable),
            "adb_server_initial_executable_device": registration.initial_executable_device,
            "adb_server_initial_executable_inode": registration.initial_executable_inode,
            "adb_snapshot_device": registration.adb_snapshot_device,
            "adb_snapshot_inode": registration.adb_snapshot_inode,
        }
    )
    return _replace_owned_runtime_receipt(receipt, payload)


def begin_adb_seal(receipt: OwnedRuntimeReceipt) -> OwnedRuntimeReceipt:
    """Durably record seal intent before changing the socket-directory mode."""

    validate_lane_lock_descriptor()
    _require(
        receipt.phase is RuntimePhase.ADB_CHILD_REGISTERED,
        "runtime recovery receipt is not awaiting adb sealing",
    )
    payload = _runtime_receipt_payload(receipt)
    payload["phase"] = RuntimePhase.ADB_SEALING.value
    return _replace_owned_runtime_receipt(receipt, payload)


def complete_adb_seal(receipt: OwnedRuntimeReceipt) -> OwnedRuntimeReceipt:
    """CAS ADB_SEALING to ADB_SEALED after the caller verifies mode 0500."""

    validate_lane_lock_descriptor()
    _require(
        receipt.phase is RuntimePhase.ADB_SEALING,
        "runtime recovery receipt has no in-progress adb seal",
    )
    payload = _runtime_receipt_payload(receipt)
    payload["phase"] = RuntimePhase.ADB_SEALED.value
    return _replace_owned_runtime_receipt(receipt, payload)


def register_emulator_child(
    *,
    receipt: OwnedRuntimeReceipt,
    registration: EmulatorChildRegistration,
) -> OwnedRuntimeReceipt:
    """CAS ADB_SEALED to the terminal active-emulator phase."""

    validate_lane_lock_descriptor()
    _require(
        receipt.phase is RuntimePhase.ADB_SEALED,
        "runtime recovery receipt is not awaiting an emulator child",
    )
    process = registration.process
    token = registration.console_auth_token
    _require(
        process.pid == os.getpid()
        and process.uid == os.geteuid()
        and receipt.device_kind == "emulator"
        and registration.console_port >= 5554
        and registration.console_port <= 5584
        and registration.console_port % 2 == 0
        and receipt.expected_serial == f"emulator-{registration.console_port}"
        and receipt.native_adb_notifier_port == NATIVE_ADB_NOTIFIER_PORT
        and registration.native_adb_notifier_port
        == receipt.native_adb_notifier_port
        and token.device >= 0
        and token.inode > 0
        and HEX_SHA256.fullmatch(token.sha256) is not None
        and registration.launcher_path.is_absolute()
        and registration.launcher_device >= 0
        and registration.launcher_inode > 0
        and registration.backend_path.is_absolute()
        and registration.backend_device >= 0
        and registration.backend_inode > 0
        and HEX_SHA256.fullmatch(registration.backend_sha256) is not None,
        "emulator child registration identity is invalid",
    )
    payload = _runtime_receipt_payload(receipt)
    payload.update(
        {
            "phase": RuntimePhase.EMULATOR_CHILD_REGISTERED.value,
            "pid": process.pid,
            "started_at": process.started_at,
            "started_subsecond": process.started_subsecond,
            "process_identity": process.token,
            "avd_name": _canonical_avd_name(registration.avd_name),
            "device_abi": _canonical_emulator_abi(registration.device_abi),
            "console_port": registration.console_port,
            "console_auth_token_device": token.device,
            "console_auth_token_inode": token.inode,
            "console_auth_token_sha256": token.sha256,
            "launcher_path": str(registration.launcher_path),
            "launcher_device": registration.launcher_device,
            "launcher_inode": registration.launcher_inode,
            "backend_path": str(registration.backend_path),
            "backend_device": registration.backend_device,
            "backend_inode": registration.backend_inode,
            "backend_sha256": registration.backend_sha256,
        }
    )
    return _replace_owned_runtime_receipt(receipt, payload)


def _positive_int(value: object, label: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    _require(
        type(value) is int and value >= minimum,
        f"owned runtime receipt {label} is invalid",
    )
    return value


def _absolute_receipt_path(value: object, label: str) -> pathlib.Path:
    _require(
        isinstance(value, str) and "\x00" not in value,
        f"owned runtime receipt {label} is invalid",
    )
    path = pathlib.Path(value)
    _require(
        path.is_absolute()
        and str(path) == value
        and all(part not in {".", ".."} for part in path.parts),
        f"owned runtime receipt {label} is non-canonical",
    )
    return path


def _owned_runtime_from_snapshot(snapshot: JsonObjectSnapshot) -> OwnedRuntimeReceipt:
    value = snapshot.value
    _require(
        set(value) == OWNED_RUNTIME_RECEIPT_FIELDS,
        "owned runtime receipt fields changed",
    )
    _require(
        value.get("schema_version") == OWNED_RUNTIME_RECEIPT_SCHEMA_VERSION
        and type(value.get("schema_version")) is int,
        "owned runtime receipt schema changed",
    )
    _require(
        value.get("kind") == OWNED_RUNTIME_RECEIPT_KIND,
        "owned runtime receipt kind changed",
    )
    try:
        phase = RuntimePhase(value.get("phase"))
    except (TypeError, ValueError) as exc:
        raise AndroidRuntimeStateError(
            "owned runtime receipt phase is invalid"
        ) from exc
    run_id = _canonical_run_id(value.get("run_id"))
    host_identity = value.get("host_identity")
    boot_identity = value.get("boot_identity")
    _require(
        type(host_identity) is str
        and 1 <= len(host_identity) <= 128
        and host_identity.isascii()
        and type(boot_identity) is str
        and 1 <= len(boot_identity) <= 128
        and boot_identity.isascii(),
        "owned runtime receipt host/boot identity is invalid",
    )
    repository_root = _absolute_receipt_path(
        value.get("repository_root"), "repository root"
    )
    run_root_device = _positive_int(
        value.get("run_root_device"), "run root device", allow_zero=True
    )
    run_root_inode = _positive_int(value.get("run_root_inode"), "run root inode")
    uid = _positive_int(value.get("uid"), "uid", allow_zero=True)
    adb_profile = _canonical_concrete_adb_profile(value.get("adb_profile"))
    adb_size = _positive_int(value.get("adb_size"), "adb size")
    _require(adb_size <= MAX_TOOL_BYTES, "owned runtime receipt adb size changed")
    adb_sha256 = value.get("adb_sha256")
    _require(
        type(adb_sha256) is str and HEX_SHA256.fullmatch(adb_sha256) is not None,
        "owned runtime receipt adb digest is invalid",
    )
    socket_nonce = _canonical_socket_nonce(value.get("socket_nonce"))
    native_adb_notifier_port = value.get("native_adb_notifier_port")
    adb_socket_directory_device = _positive_int(
        value.get("adb_socket_directory_device"),
        "adb socket directory device",
        allow_zero=True,
    )
    adb_socket_directory_inode = _positive_int(
        value.get("adb_socket_directory_inode"), "adb socket directory inode"
    )
    device_kind = _canonical_device_kind(value.get("device_kind"))
    _require(
        (
            device_kind == "emulator"
            and type(native_adb_notifier_port) is int
            and native_adb_notifier_port == NATIVE_ADB_NOTIFIER_PORT
        )
        or (device_kind == "physical" and native_adb_notifier_port is None),
        "owned runtime receipt native adb notifier port is invalid",
    )
    expected_serial = _canonical_expected_serial(
        value.get("expected_serial"), device_kind
    )

    adb_server_fields = (
        "adb_server_pid",
        "adb_server_started_at",
        "adb_server_started_subsecond",
        "adb_server_process_identity",
        "adb_server_initial_executable",
        "adb_server_initial_executable_device",
        "adb_server_initial_executable_inode",
        "adb_snapshot_device",
        "adb_snapshot_inode",
    )
    if phase is not RuntimePhase.PREPARED:
        adb_server_pid = _positive_int(value.get("adb_server_pid"), "adb server pid")
        adb_server_started_at = _positive_int(
            value.get("adb_server_started_at"), "adb server start time"
        )
        adb_server_started_subsecond = _positive_int(
            value.get("adb_server_started_subsecond"),
            "adb server start subsecond",
            allow_zero=True,
        )
        try:
            adb_server_identity = parse_process_identity_token(
                value.get("adb_server_process_identity")
            )
            expected_adb_server_identity = render_process_identity_token(
                adb_server_pid,
                uid,
                adb_server_started_at,
                adb_server_started_subsecond,
            )
        except ProcessIdentityError as exc:
            raise AndroidRuntimeStateError(
                f"owned runtime receipt adb server identity is invalid: {exc}"
            ) from exc
        _require(
            adb_server_identity.token == expected_adb_server_identity,
            "owned runtime receipt adb server identity changed",
        )
        adb_server_initial_executable = _absolute_receipt_path(
            value.get("adb_server_initial_executable"),
            "adb server initial executable",
        )
        adb_server_initial_executable_device = _positive_int(
            value.get("adb_server_initial_executable_device"),
            "adb server initial executable device",
            allow_zero=True,
        )
        adb_server_initial_executable_inode = _positive_int(
            value.get("adb_server_initial_executable_inode"),
            "adb server initial executable inode",
        )
        adb_snapshot_device = _positive_int(
            value.get("adb_snapshot_device"), "adb snapshot device", allow_zero=True
        )
        adb_snapshot_inode = _positive_int(
            value.get("adb_snapshot_inode"), "adb snapshot inode"
        )
    else:
        _require(
            all(value.get(field) is None for field in adb_server_fields),
            "prepared runtime receipt contains adb server identity fields",
        )
        adb_server_pid = None
        adb_server_started_at = None
        adb_server_started_subsecond = None
        expected_adb_server_identity = None
        adb_server_initial_executable = None
        adb_server_initial_executable_device = None
        adb_server_initial_executable_inode = None
        adb_snapshot_device = None
        adb_snapshot_inode = None

    emulator_fields = (
        "pid",
        "started_at",
        "started_subsecond",
        "process_identity",
        "avd_name",
        "device_abi",
        "console_port",
        "console_auth_token_device",
        "console_auth_token_inode",
        "console_auth_token_sha256",
        "launcher_path",
        "launcher_device",
        "launcher_inode",
        "backend_path",
        "backend_device",
        "backend_inode",
        "backend_sha256",
    )
    if phase is RuntimePhase.EMULATOR_CHILD_REGISTERED:
        _require(
            device_kind == "emulator",
            "active emulator receipt has a non-emulator device kind",
        )
        pid = _positive_int(value.get("pid"), "pid")
        started_at = _positive_int(value.get("started_at"), "start time")
        started_subsecond = _positive_int(
            value.get("started_subsecond"), "start subsecond", allow_zero=True
        )
        try:
            expected_identity = render_process_identity_token(
                pid, uid, started_at, started_subsecond
            )
            parsed_identity = parse_process_identity_token(
                value.get("process_identity")
            )
        except ProcessIdentityError as exc:
            raise AndroidRuntimeStateError(
                f"owned runtime receipt process identity is invalid: {exc}"
            ) from exc
        _require(
            parsed_identity.token == expected_identity,
            "owned runtime receipt process identity changed",
        )
        avd_name = _canonical_avd_name(value.get("avd_name"))
        device_abi = _canonical_emulator_abi(value.get("device_abi"))
        console_port = _positive_int(value.get("console_port"), "console port")
        _require(
            expected_serial == f"emulator-{console_port}"
            and 5554 <= console_port <= 5584
            and console_port % 2 == 0,
            "owned runtime receipt port identity changed",
        )
        console_auth_token_device = _positive_int(
            value.get("console_auth_token_device"),
            "console authentication token device",
            allow_zero=True,
        )
        console_auth_token_inode = _positive_int(
            value.get("console_auth_token_inode"),
            "console authentication token inode",
        )
        console_auth_token_sha256 = value.get("console_auth_token_sha256")
        _require(
            type(console_auth_token_sha256) is str
            and HEX_SHA256.fullmatch(console_auth_token_sha256) is not None,
            "owned runtime receipt console authentication token digest is invalid",
        )
        launcher_path = _absolute_receipt_path(
            value.get("launcher_path"), "launcher path"
        )
        launcher_device = _positive_int(
            value.get("launcher_device"), "launcher device", allow_zero=True
        )
        launcher_inode = _positive_int(value.get("launcher_inode"), "launcher inode")
        backend_path = _absolute_receipt_path(value.get("backend_path"), "backend path")
        backend_device = _positive_int(
            value.get("backend_device"), "backend device", allow_zero=True
        )
        backend_inode = _positive_int(value.get("backend_inode"), "backend inode")
        backend_sha256 = value.get("backend_sha256")
        _require(
            type(backend_sha256) is str
            and HEX_SHA256.fullmatch(backend_sha256) is not None,
            "owned runtime receipt backend digest is invalid",
        )
    else:
        _require(
            all(value.get(field) is None for field in emulator_fields),
            "non-emulator runtime phase contains emulator identity fields",
        )
        pid = None
        started_at = None
        started_subsecond = None
        expected_identity = None
        avd_name = None
        device_abi = None
        console_port = None
        console_auth_token_device = None
        console_auth_token_inode = None
        console_auth_token_sha256 = None
        launcher_path = None
        launcher_device = None
        launcher_inode = None
        backend_path = None
        backend_device = None
        backend_inode = None
        backend_sha256 = None

    return OwnedRuntimeReceipt(
        run_id=run_id,
        host_identity=host_identity,
        boot_identity=boot_identity,
        repository_root=repository_root,
        run_root_device=run_root_device,
        run_root_inode=run_root_inode,
        phase=phase,
        pid=pid,
        uid=uid,
        started_at=started_at,
        started_subsecond=started_subsecond,
        process_identity=expected_identity,
        adb_profile=adb_profile,
        adb_size=adb_size,
        adb_sha256=adb_sha256,
        socket_nonce=socket_nonce,
        native_adb_notifier_port=native_adb_notifier_port,
        device_kind=device_kind,
        expected_serial=expected_serial,
        adb_server_pid=adb_server_pid,
        adb_server_started_at=adb_server_started_at,
        adb_server_started_subsecond=adb_server_started_subsecond,
        adb_server_process_identity=expected_adb_server_identity,
        adb_server_initial_executable=adb_server_initial_executable,
        adb_server_initial_executable_device=adb_server_initial_executable_device,
        adb_server_initial_executable_inode=adb_server_initial_executable_inode,
        adb_snapshot_device=adb_snapshot_device,
        adb_snapshot_inode=adb_snapshot_inode,
        adb_socket_directory_device=adb_socket_directory_device,
        adb_socket_directory_inode=adb_socket_directory_inode,
        avd_name=avd_name,
        device_abi=device_abi,
        console_port=console_port,
        console_auth_token_device=console_auth_token_device,
        console_auth_token_inode=console_auth_token_inode,
        console_auth_token_sha256=console_auth_token_sha256,
        launcher_path=launcher_path,
        launcher_device=launcher_device,
        launcher_inode=launcher_inode,
        backend_path=backend_path,
        backend_device=backend_device,
        backend_inode=backend_inode,
        backend_sha256=backend_sha256,
        snapshot_sha256=snapshot.file.sha256,
    )


def load_owned_runtime_receipt(
    *, missing_ok: bool = False
) -> OwnedRuntimeReceipt | None:
    state_fd = _open_account_state()
    receipt_fd = -1
    primary: BaseException | None = None
    try:
        try:
            receipt_fd = os.open(
                OWNED_RUNTIME_RECEIPT_LEAF,
                os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                dir_fd=state_fd,
            )
        except FileNotFoundError:
            if missing_ok:
                return None
            raise AndroidRuntimeStateError("owned runtime receipt is missing") from None
        except OSError as exc:
            raise AndroidRuntimeStateError(
                f"cannot open owned runtime receipt: {exc}"
            ) from exc
        try:
            _verify_private_control_descriptor(receipt_fd, "owned runtime receipt")
        except EvidenceIOError as exc:
            raise AndroidRuntimeStateError(
                f"cannot load owned runtime receipt: {exc}"
            ) from exc
        try:
            snapshot = load_json_object_snapshot_at(
                state_fd,
                OWNED_RUNTIME_RECEIPT_LEAF,
                display_path=owned_runtime_receipt_path(),
                maximum=MAX_OWNED_RUNTIME_RECEIPT_BYTES,
                label="owned runtime receipt",
                validate_metadata=_private_control_file_metadata,
            )
        except EvidenceIOError as exc:
            if missing_ok:
                try:
                    os.stat(
                        OWNED_RUNTIME_RECEIPT_LEAF,
                        dir_fd=state_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    return None
            raise AndroidRuntimeStateError(
                f"cannot load owned runtime receipt: {exc}"
            ) from exc
        return _owned_runtime_from_snapshot(snapshot)
    except BaseException as exc:
        primary = exc
        raise
    finally:
        if receipt_fd >= 0:
            _close_owned_descriptor(
                receipt_fd,
                label="the owned runtime receipt",
                primary=primary,
            )
        _close_owned_descriptor(
            state_fd,
            label="the Android account-state directory",
            primary=primary,
        )


def retire_owned_runtime_receipt(receipt: OwnedRuntimeReceipt) -> None:
    """Remove only the exact receipt snapshot the caller already validated."""

    validate_lane_lock_descriptor()
    state_fd = _open_account_state()
    receipt_fd = -1
    primary: BaseException | None = None
    try:
        receipt_fd = _open_owned_runtime_receipt_for_mutation(state_fd)
        _lock_account_state_for_receipt_mutation(state_fd)
        current = _require_locked_receipt_is_current(
            state_fd,
            receipt_fd,
            receipt.snapshot_sha256,
            action="retirement",
        )
        _owned_runtime_from_snapshot(current)
        os.unlink(OWNED_RUNTIME_RECEIPT_LEAF, dir_fd=state_fd)
        os.fsync(state_fd)
    except OSError as exc:
        primary = AndroidRuntimeStateError(
            f"cannot retire owned runtime receipt: {exc}"
        )
        raise primary from exc
    except BaseException as exc:
        primary = exc
        raise
    finally:
        if receipt_fd >= 0:
            _close_owned_descriptor(
                receipt_fd,
                label="the owned runtime receipt",
                primary=primary,
            )
        _close_owned_descriptor(
            state_fd,
            label="the Android account-state directory",
            primary=primary,
        )
