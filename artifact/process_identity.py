#!/usr/bin/env python3
"""Read stable, non-environment process identities on supported release hosts."""

from __future__ import annotations

import ctypes
import dataclasses
import os
import pathlib
import stat
import sys
import uuid
from collections.abc import Mapping
from types import MappingProxyType


class ProcessIdentityError(RuntimeError):
    """A process identity could not be read or was internally inconsistent."""


@dataclasses.dataclass(frozen=True, slots=True)
class HostBootIdentity:
    host: str
    boot: str


def host_boot_identity() -> HostBootIdentity:
    """Return the fixed host and boot-session identities for recovery receipts."""

    if sys.platform == "darwin":
        gethostuuid = ctypes.CDLL(None, use_errno=True).gethostuuid

        class Timespec(ctypes.Structure):
            _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]

        class Timeval(ctypes.Structure):
            _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_int)]

        gethostuuid.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(Timespec),
        ]
        gethostuuid.restype = ctypes.c_int
        raw_uuid = (ctypes.c_ubyte * 16)()
        timeout = Timespec(5, 0)
        if gethostuuid(raw_uuid, ctypes.byref(timeout)) != 0:
            error_number = ctypes.get_errno()
            detail = os.strerror(error_number) if error_number else "unknown host UUID error"
            raise ProcessIdentityError(f"cannot read host identity: {detail}")
        host = str(uuid.UUID(bytes=bytes(raw_uuid)))
        mib = (ctypes.c_int * 2)(1, 21)
        boot_time = Timeval()
        size = ctypes.c_size_t(ctypes.sizeof(boot_time))
        sysctl = ctypes.CDLL(None, use_errno=True).sysctl
        sysctl.argtypes = [
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_uint,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        sysctl.restype = ctypes.c_int
        if sysctl(mib, 2, ctypes.byref(boot_time), ctypes.byref(size), None, 0) != 0:
            error_number = ctypes.get_errno()
            detail = os.strerror(error_number) if error_number else "unknown boot-time error"
            raise ProcessIdentityError(f"cannot read boot identity: {detail}")
        if boot_time.tv_sec <= 0 or not 0 <= boot_time.tv_usec < 1_000_000:
            raise ProcessIdentityError("boot identity fields are invalid")
        boot = f"{boot_time.tv_sec}:{boot_time.tv_usec}"
    elif sys.platform == "linux":
        try:
            host = pathlib.Path("/etc/machine-id").read_text(encoding="ascii").strip()
            boot = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text(
                encoding="ascii"
            ).strip()
        except OSError as exc:
            raise ProcessIdentityError(f"cannot read host/boot identity: {exc}") from exc
        try:
            host = str(uuid.UUID(host))
            boot = str(uuid.UUID(boot))
        except ValueError as exc:
            raise ProcessIdentityError("host/boot identity is malformed") from exc
    else:
        raise ProcessIdentityError(
            f"host/boot identity is unsupported on {sys.platform}"
        )
    return HostBootIdentity(host=host, boot=boot)


_MAX_PID = (1 << 31) - 1
_MAX_UID = (1 << 32) - 1
_MAX_STARTED_AT = (1 << 64) - 1
_MAX_STARTED_SUBSECOND = 999_999
_MAX_TOKEN_LENGTH = 64
_MAX_EXECUTION_BYTES = 16 * 1024 * 1024
_MAX_EXECUTION_ENTRIES = 4096


def _identity_fields(
    pid: object,
    uid: object,
    started_at: object,
    started_subsecond: object,
) -> tuple[int, int, int, int]:
    fields = (
        (pid, 2, _MAX_PID, "pid"),
        (uid, 0, _MAX_UID, "uid"),
        (started_at, 1, _MAX_STARTED_AT, "start time"),
        (
            started_subsecond,
            0,
            _MAX_STARTED_SUBSECOND,
            "start subsecond",
        ),
    )
    canonical: list[int] = []
    for value, minimum, maximum, label in fields:
        if type(value) is not int or not minimum <= value <= maximum:
            raise ProcessIdentityError(f"process identity {label} is invalid")
        canonical.append(value)
    return canonical[0], canonical[1], canonical[2], canonical[3]


def render_token(
    pid: object,
    uid: object,
    started_at: object,
    started_subsecond: object,
) -> str:
    """Render validated process identity fields in their sole canonical form."""

    canonical = _identity_fields(pid, uid, started_at, started_subsecond)
    return ":".join(str(component) for component in canonical)


@dataclasses.dataclass(frozen=True, slots=True)
class ProcessIdentityToken:
    pid: int
    uid: int
    started_at: int
    started_subsecond: int

    def __post_init__(self) -> None:
        _identity_fields(
            self.pid,
            self.uid,
            self.started_at,
            self.started_subsecond,
        )

    @property
    def token(self) -> str:
        return render_token(
            self.pid,
            self.uid,
            self.started_at,
            self.started_subsecond,
        )


def parse_token(value: object) -> ProcessIdentityToken:
    """Parse an exact canonical PID/UID/start token without normalization."""

    if type(value) is not str or not 7 <= len(value) <= _MAX_TOKEN_LENGTH:
        raise ProcessIdentityError("process identity token is malformed")
    components = value.split(":")
    if len(components) != 4:
        raise ProcessIdentityError("process identity token is malformed")
    numbers: list[int] = []
    for component in components:
        if (
            not component
            or len(component) > 20
            or not component.isascii()
            or not component.isdigit()
            or (len(component) > 1 and component.startswith("0"))
        ):
            raise ProcessIdentityError("process identity token is not canonical")
        numbers.append(int(component))
    parsed = ProcessIdentityToken(*numbers)
    if parsed.token != value:
        raise ProcessIdentityError("process identity token is not canonical")
    return parsed


@dataclasses.dataclass(frozen=True, slots=True)
class ProcessIdentity:
    pid: int
    uid: int
    started_at: int
    started_subsecond: int
    executable: pathlib.Path

    def __post_init__(self) -> None:
        _identity_fields(
            self.pid,
            self.uid,
            self.started_at,
            self.started_subsecond,
        )

    @property
    def token(self) -> str:
        return render_token(
            self.pid,
            self.uid,
            self.started_at,
            self.started_subsecond,
        )


@dataclasses.dataclass(frozen=True, slots=True)
class ProcessExecutionSnapshot:
    """One identity-stable argv/environment snapshot for a live process."""

    identity: ProcessIdentity
    argv: tuple[str, ...]
    environment: Mapping[str, str]

    def __post_init__(self) -> None:
        if not self.argv or len(self.argv) > _MAX_EXECUTION_ENTRIES:
            raise ProcessIdentityError("process argument count is invalid")
        if any(type(argument) is not str or "\0" in argument for argument in self.argv):
            raise ProcessIdentityError("process argument is invalid")
        if not 0 < len(self.environment) <= _MAX_EXECUTION_ENTRIES:
            raise ProcessIdentityError("process environment count is invalid")
        for name, value in self.environment.items():
            if (
                type(name) is not str
                or not name
                or "=" in name
                or "\0" in name
                or type(value) is not str
                or "\0" in value
            ):
                raise ProcessIdentityError("process environment entry is invalid")
        object.__setattr__(self, "environment", MappingProxyType(dict(self.environment)))


def _require_pid(pid: object) -> int:
    return _identity_fields(pid, 0, 1, 0)[0]


def _resolved_executable(
    raw_path: bytes | str | os.PathLike[str], *, pid: int
) -> pathlib.Path:
    try:
        path = pathlib.Path(os.fsdecode(raw_path)).resolve(strict=True)
        metadata = path.stat()
    except (OSError, RuntimeError) as exc:
        raise ProcessIdentityError(
            f"cannot resolve process {pid} executable: {exc}"
        ) from exc
    if not path.is_absolute() or not stat.S_ISREG(metadata.st_mode):
        raise ProcessIdentityError(f"process {pid} executable is invalid")
    return path


def _darwin_snapshot(pid: int) -> ProcessIdentity:
    class ProcBsdInfo(ctypes.Structure):
        _fields_ = [
            ("pbi_flags", ctypes.c_uint32),
            ("pbi_status", ctypes.c_uint32),
            ("pbi_xstatus", ctypes.c_uint32),
            ("pbi_pid", ctypes.c_uint32),
            ("pbi_ppid", ctypes.c_uint32),
            ("pbi_uid", ctypes.c_uint32),
            ("pbi_gid", ctypes.c_uint32),
            ("pbi_ruid", ctypes.c_uint32),
            ("pbi_rgid", ctypes.c_uint32),
            ("pbi_svuid", ctypes.c_uint32),
            ("pbi_svgid", ctypes.c_uint32),
            ("rfu_1", ctypes.c_uint32),
            ("pbi_comm", ctypes.c_char * 16),
            ("pbi_name", ctypes.c_char * 32),
            ("pbi_nfiles", ctypes.c_uint32),
            ("pbi_pgid", ctypes.c_uint32),
            ("pbi_pjobc", ctypes.c_uint32),
            ("e_tdev", ctypes.c_uint32),
            ("e_tpgid", ctypes.c_uint32),
            ("pbi_nice", ctypes.c_int32),
            ("pbi_start_tvsec", ctypes.c_uint64),
            ("pbi_start_tvusec", ctypes.c_uint64),
        ]

    libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    proc_pidinfo = libproc.proc_pidinfo
    proc_pidinfo.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_uint64,
        ctypes.c_void_p,
        ctypes.c_int,
    ]
    proc_pidinfo.restype = ctypes.c_int
    info = ProcBsdInfo()
    ctypes.set_errno(0)
    result = proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
    if result != ctypes.sizeof(info) or info.pbi_pid != pid:
        error_number = ctypes.get_errno()
        detail = os.strerror(error_number) if error_number else "process disappeared"
        raise ProcessIdentityError(f"cannot inspect process {pid}: {detail}")

    proc_pidpath = libproc.proc_pidpath
    proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    proc_pidpath.restype = ctypes.c_int
    path_buffer = ctypes.create_string_buffer(4096)
    ctypes.set_errno(0)
    path_length = proc_pidpath(pid, path_buffer, len(path_buffer))
    if path_length <= 0:
        error_number = ctypes.get_errno()
        detail = os.strerror(error_number) if error_number else "empty process path"
        raise ProcessIdentityError(
            f"cannot inspect process {pid} executable: {detail}"
        )
    return ProcessIdentity(
        pid=pid,
        uid=int(info.pbi_uid),
        started_at=int(info.pbi_start_tvsec),
        started_subsecond=int(info.pbi_start_tvusec),
        executable=_resolved_executable(path_buffer.value, pid=pid),
    )


def _linux_snapshot(pid: int) -> ProcessIdentity:
    process_root = pathlib.Path("/proc") / str(pid)
    try:
        metadata = process_root.stat()
        executable = (process_root / "exe").resolve(strict=True)
        stat_text = (process_root / "stat").read_text(encoding="utf-8")
    except OSError as exc:
        raise ProcessIdentityError(f"cannot inspect process {pid}: {exc}") from exc
    command_end = stat_text.rfind(")")
    if command_end < 0 or not stat_text.startswith(f"{pid} ("):
        raise ProcessIdentityError("malformed Linux process identity")
    fields = stat_text[command_end + 1 :].split()
    if len(fields) < 20 or not fields[19].isdigit():
        raise ProcessIdentityError("malformed Linux process start identity")
    return ProcessIdentity(
        pid=pid,
        uid=metadata.st_uid,
        started_at=int(fields[19]),
        started_subsecond=0,
        executable=_resolved_executable(executable, pid=pid),
    )


def _decode_execution_entry(raw: bytes, *, label: str) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProcessIdentityError(f"process {label} is not UTF-8") from exc


def _execution_from_parts(
    identity: ProcessIdentity,
    raw_argv: tuple[bytes, ...],
    raw_environment: tuple[bytes, ...],
) -> ProcessExecutionSnapshot:
    if not raw_argv or len(raw_argv) > _MAX_EXECUTION_ENTRIES:
        raise ProcessIdentityError("process argument count is invalid")
    argv = tuple(
        _decode_execution_entry(argument, label="argument") for argument in raw_argv
    )
    environment: dict[str, str] = {}
    if not raw_environment or len(raw_environment) > _MAX_EXECUTION_ENTRIES:
        raise ProcessIdentityError("process environment count is invalid")
    for raw_entry in raw_environment:
        entry = _decode_execution_entry(raw_entry, label="environment")
        if "=" not in entry:
            raise ProcessIdentityError("malformed process environment entry")
        name, value = entry.split("=", 1)
        if not name or name in environment:
            raise ProcessIdentityError("duplicate or empty process environment name")
        environment[name] = value
    return ProcessExecutionSnapshot(
        identity=identity,
        argv=argv,
        environment=environment,
    )


def _darwin_execution_snapshot(pid: int) -> ProcessExecutionSnapshot:
    identity_before = _darwin_snapshot(pid)
    libc = ctypes.CDLL(None, use_errno=True)
    sysctl = libc.sysctl
    sysctl.argtypes = [
        ctypes.POINTER(ctypes.c_int),
        ctypes.c_uint,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    sysctl.restype = ctypes.c_int
    mib = (ctypes.c_int * 3)(1, 49, pid)
    size = ctypes.c_size_t()
    ctypes.set_errno(0)
    if sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0 or size.value < 8:
        error_number = ctypes.get_errno()
        detail = os.strerror(error_number) if error_number else "invalid arguments size"
        raise ProcessIdentityError(
            f"cannot size process {pid} arguments and environment: {detail}"
        )
    if size.value > _MAX_EXECUTION_BYTES:
        raise ProcessIdentityError(
            f"process {pid} arguments and environment exceed the fixed bound"
        )
    buffer = ctypes.create_string_buffer(size.value)
    ctypes.set_errno(0)
    if sysctl(mib, 3, buffer, ctypes.byref(size), None, 0) != 0:
        error_number = ctypes.get_errno()
        detail = os.strerror(error_number) if error_number else "unknown sysctl error"
        raise ProcessIdentityError(
            f"cannot read process {pid} arguments and environment: {detail}"
        )
    data = bytes(buffer.raw[: size.value])
    argc = int.from_bytes(data[:4], sys.byteorder, signed=True)
    if not 1 <= argc <= _MAX_EXECUTION_ENTRIES:
        raise ProcessIdentityError("process argument count is invalid")
    offset = 4
    executable_end = data.find(b"\0", offset)
    if executable_end < 0:
        raise ProcessIdentityError("process executable terminator is missing")
    offset = executable_end + 1
    while offset < len(data) and data[offset] == 0:
        offset += 1
    raw_argv: list[bytes] = []
    for _ in range(argc):
        argument_end = data.find(b"\0", offset)
        if argument_end < 0:
            raise ProcessIdentityError("process arguments are truncated")
        raw_argv.append(data[offset:argument_end])
        offset = argument_end + 1
    raw_environment: list[bytes] = []
    while offset < len(data):
        entry_end = data.find(b"\0", offset)
        if entry_end < 0:
            raise ProcessIdentityError("process environment is truncated")
        raw_entry = data[offset:entry_end]
        offset = entry_end + 1
        if not raw_entry:
            break
        raw_environment.append(raw_entry)
        if len(raw_environment) > _MAX_EXECUTION_ENTRIES:
            raise ProcessIdentityError("process environment count is invalid")
    execution = _execution_from_parts(
        identity_before, tuple(raw_argv), tuple(raw_environment)
    )
    identity_after = _darwin_snapshot(pid)
    if identity_after.token != identity_before.token:
        raise ProcessIdentityError("process identity changed during execution snapshot")
    if identity_after.executable != identity_before.executable:
        raise ProcessIdentityError("process executable changed during execution snapshot")
    return execution


def _linux_execution_snapshot(pid: int) -> ProcessExecutionSnapshot:
    identity_before = _linux_snapshot(pid)
    process_root = pathlib.Path("/proc") / str(pid)
    try:
        argv_bytes = (process_root / "cmdline").read_bytes()
        environment_bytes = (process_root / "environ").read_bytes()
    except OSError as exc:
        raise ProcessIdentityError(
            f"cannot read process {pid} arguments and environment: {exc}"
        ) from exc
    if (
        len(argv_bytes) > _MAX_EXECUTION_BYTES
        or len(environment_bytes) > _MAX_EXECUTION_BYTES
    ):
        raise ProcessIdentityError(
            f"process {pid} arguments or environment exceed the fixed bound"
        )
    raw_argv = tuple(entry for entry in argv_bytes.split(b"\0") if entry)
    raw_environment = tuple(entry for entry in environment_bytes.split(b"\0") if entry)
    execution = _execution_from_parts(identity_before, raw_argv, raw_environment)
    identity_after = _linux_snapshot(pid)
    if identity_after.token != identity_before.token:
        raise ProcessIdentityError("process identity changed during execution snapshot")
    if identity_after.executable != identity_before.executable:
        raise ProcessIdentityError("process executable changed during execution snapshot")
    return execution


def snapshot(pid: int) -> ProcessIdentity:
    """Return PID-reuse-resistant identity fields without reading its environment."""

    canonical_pid = _require_pid(pid)
    if sys.platform == "darwin":
        identity = _darwin_snapshot(canonical_pid)
    elif sys.platform == "linux":
        identity = _linux_snapshot(canonical_pid)
    else:
        raise ProcessIdentityError(
            f"process identity verification is unsupported on {sys.platform}"
        )
    return identity


def execution_snapshot(pid: int) -> ProcessExecutionSnapshot:
    """Return identity-bound argv and exact environment for a live process."""

    canonical_pid = _require_pid(pid)
    if sys.platform == "darwin":
        return _darwin_execution_snapshot(canonical_pid)
    if sys.platform == "linux":
        return _linux_execution_snapshot(canonical_pid)
    raise ProcessIdentityError(
        f"process execution verification is unsupported on {sys.platform}"
    )
