#!/usr/bin/env python3
"""Run argv-only subprocesses with deadlines and bounded standard output."""

from __future__ import annotations

import dataclasses
import os
import pathlib
import re
import secrets
import signal
import stat
import subprocess
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from typing import BinaryIO, Literal, Never


MAX_TIMEOUT_SECONDS = 300
MAX_OUTPUT_BYTES = 512 * 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024
REAP_TIMEOUT_SECONDS = 5
MAX_OUTPUT_NAME_BYTES = 128
_OUTPUT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")

ErrorKind = Literal[
    "arguments",
    "start",
    "timeout",
    "output_limit",
    "io",
    "reap",
    "output_path",
]

_INTERRUPTION_SIGNALS = (
    signal.SIGINT,
    signal.SIGHUP,
    signal.SIGTERM,
)
_MAX_ADDITIONAL_SIGNAL_COUNT = 255


class BoundedProcessError(RuntimeError):
    """A typed failure at the subprocess resource boundary."""

    def __init__(self, kind: ErrorKind, message: str) -> None:
        super().__init__(message)
        self.kind = kind


class _TerminationSignal(SystemExit):
    def __init__(self, signal_number: int) -> None:
        self.signal_number = signal_number
        super().__init__(128 + signal_number)


class _SignalCoordinator:
    """Turn process termination signals into synchronous ownership checks."""

    def __init__(self) -> None:
        self._previous_handlers: dict[signal.Signals, object] = {}
        self._requested_signal: int | None = None
        self._additional_signal_counts = {
            int(signal_number): 0 for signal_number in _INTERRUPTION_SIGNALS
        }

    def _record_signal(self, signal_number: int, _frame: object) -> None:
        if self._requested_signal is None:
            self._requested_signal = signal_number
        else:
            current_count = self._additional_signal_counts[signal_number]
            if current_count < _MAX_ADDITIONAL_SIGNAL_COUNT:
                self._additional_signal_counts[signal_number] = current_count + 1

    def __enter__(self) -> _SignalCoordinator:
        if threading.current_thread() is not threading.main_thread():
            raise BoundedProcessError(
                "start", "bounded process operations must run on the main thread"
            )
        installed: list[signal.Signals] = []
        try:
            for signal_number in _INTERRUPTION_SIGNALS:
                previous = signal.getsignal(signal_number)
                signal.signal(signal_number, self._record_signal)
                self._previous_handlers[signal_number] = previous
                installed.append(signal_number)
        except BaseException as exc:
            restoration_failures: list[str] = []
            for signal_number in reversed(installed):
                try:
                    signal.signal(
                        signal_number, self._previous_handlers[signal_number]
                    )
                except BaseException as restore_exc:
                    restoration_failures.append(
                        f"{signal_number.name}: {restore_exc}"
                    )
            failure = BoundedProcessError(
                "start", f"cannot install bounded process signal handlers: {exc}"
            )
            failure.__cause__ = exc
            if restoration_failures:
                failure.add_note(
                    "signal handler restoration failures: "
                    + "; ".join(restoration_failures)
                )
            raise failure
        return self

    def __exit__(
        self,
        _exception_type: object,
        exception: BaseException | None,
        _traceback: object,
    ) -> bool:
        restoration_failures: list[str] = []
        for signal_number in reversed(_INTERRUPTION_SIGNALS):
            try:
                signal.signal(signal_number, self._previous_handlers[signal_number])
            except BaseException as exc:
                restoration_failures.append(f"{signal_number.name}: {exc}")

        signal_note: str | None = None
        if self._requested_signal is not None:
            signal_note = (
                "bounded operation received "
                f"{signal.Signals(self._requested_signal).name}"
            )
            additional_signals = tuple(
                (signal_number, count)
                for signal_number, count in self._additional_signal_counts.items()
                if count > 0
            )
            if additional_signals:
                signal_note += (
                    "; additional signals="
                    + ",".join(
                        f"{signal.Signals(signal_number).name}x{count}"
                        + (
                            "+"
                            if count == _MAX_ADDITIONAL_SIGNAL_COUNT
                            else ""
                        )
                        for signal_number, count in additional_signals
                    )
                )

        if exception is not None:
            if signal_note is not None and not isinstance(
                exception, _TerminationSignal
            ):
                exception.add_note(signal_note)
            if restoration_failures:
                exception.add_note(
                    "signal handler restoration failures: "
                    + "; ".join(restoration_failures)
                )
            return False

        if self._requested_signal is not None:
            termination = _TerminationSignal(self._requested_signal)
            if restoration_failures:
                termination.add_note(
                    "signal handler restoration failures: "
                    + "; ".join(restoration_failures)
                )
            raise termination
        if restoration_failures:
            raise BoundedProcessError(
                "reap",
                "cannot restore bounded process signal handlers: "
                + "; ".join(restoration_failures),
            )
        return False

    def raise_if_requested(self) -> None:
        if self._requested_signal is not None:
            raise _TerminationSignal(self._requested_signal)


@dataclasses.dataclass(frozen=True)
class BoundedResult:
    returncode: int
    stdout: bytes = b""


def _validated_argv(argv: Sequence[str]) -> list[str]:
    if not argv or any(not isinstance(value, str) or not value for value in argv):
        raise BoundedProcessError(
            "arguments", "command must contain one or more non-empty argv strings"
        )
    if any("\x00" in value for value in argv):
        raise BoundedProcessError("arguments", "command argv contains a NUL byte")
    return list(argv)


def _validated_timeout(timeout_seconds: int) -> int:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int)
        or not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS
    ):
        raise BoundedProcessError(
            "arguments",
            f"timeout must be an integer from 1 through {MAX_TIMEOUT_SECONDS}",
        )
    return timeout_seconds


def _validated_maximum(maximum_bytes: int) -> int:
    if (
        isinstance(maximum_bytes, bool)
        or not isinstance(maximum_bytes, int)
        or not 1 <= maximum_bytes <= MAX_OUTPUT_BYTES
    ):
        raise BoundedProcessError(
            "arguments",
            f"output limit must be an integer from 1 through {MAX_OUTPUT_BYTES}",
        )
    return maximum_bytes


def _validated_environment(
    environment: Mapping[str, str] | None,
) -> dict[str, str] | None:
    if environment is None:
        return None
    if not isinstance(environment, Mapping):
        raise BoundedProcessError("arguments", "process environment must be a mapping")
    validated: dict[str, str] = {}
    for name, value in environment.items():
        if (
            not isinstance(name, str)
            or not name
            or "=" in name
            or "\x00" in name
            or not isinstance(value, str)
            or "\x00" in value
        ):
            raise BoundedProcessError(
                "arguments", "process environment contains a malformed entry"
            )
        validated[name] = value
    return validated


def _start_process(
    argv: Sequence[str],
    *,
    stdout: int | None,
    stderr: int | None,
    environment: Mapping[str, str] | None,
) -> subprocess.Popen[bytes]:
    command = _validated_argv(argv)
    child_environment = _validated_environment(environment)
    if os.name != "posix":
        raise BoundedProcessError(
            "start", "bounded process groups require a POSIX host"
        )
    required_waitid_api = ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT")
    if any(not hasattr(os, name) for name in required_waitid_api):
        raise BoundedProcessError(
            "start", "bounded process ownership requires POSIX waitid with WNOWAIT"
        )
    if stderr == subprocess.PIPE:
        raise BoundedProcessError(
            "arguments", "stderr=PIPE is unsupported because it cannot be drained safely"
        )
    try:
        return subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            env=child_environment,
            bufsize=0,
            start_new_session=True,
        )
    except OSError as exc:
        raise BoundedProcessError(
            "start", f"cannot start {pathlib.Path(command[0]).name}: {exc}"
        ) from exc


def _remaining(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())


def _wait_for_process_exit(
    process: subprocess.Popen[bytes],
    *,
    deadline: float,
    coordinator: _SignalCoordinator,
) -> int | None:
    """Observe without reaping until success can be committed synchronously."""

    while True:
        coordinator.raise_if_requested()
        try:
            status = os.waitid(
                os.P_PID,
                process.pid,
                os.WEXITED | os.WNOHANG | os.WNOWAIT,
            )
        except ChildProcessError as exc:
            if process.returncode is not None:
                return process.returncode
            raise BoundedProcessError(
                "reap", "bounded subprocess stopped being an owned child while waiting"
            ) from exc
        except OSError as exc:
            raise BoundedProcessError(
                "reap", f"cannot observe bounded subprocess exit: {exc}"
            ) from exc
        if status is not None:
            coordinator.raise_if_requested()
            try:
                return process.wait(timeout=_remaining(deadline))
            except subprocess.TimeoutExpired:
                return None
        remaining = _remaining(deadline)
        if remaining <= 0:
            return None
        time.sleep(min(remaining, 0.05))


def _kill_and_reap(
    process: subprocess.Popen[bytes], *, deadline: float | None = None
) -> None:
    """Kill the unreaped session leader's whole process group, then reap it."""

    cleanup_deadline = deadline or time.monotonic() + REAP_TIMEOUT_SECONDS
    if process.returncode is not None:
        raise BoundedProcessError(
            "reap",
            "bounded subprocess leader was already reaped; refusing unsafe process-group signal",
        )
    try:
        os.waitid(
            os.P_PID,
            process.pid,
            os.WEXITED | os.WNOHANG | os.WNOWAIT,
        )
    except ChildProcessError as exc:
        raise BoundedProcessError(
            "reap",
            "bounded subprocess is no longer an unreaped child; refusing unsafe process-group signal",
        ) from exc
    except OSError as exc:
        raise BoundedProcessError(
            "reap", f"cannot confirm bounded subprocess ownership before termination: {exc}"
        ) from exc

    group_failure: BoundedProcessError | None = None
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as exc:
        group_failure = BoundedProcessError(
            "reap", f"cannot terminate bounded process group: {exc}"
        )
        # The unreaped leader still owns its PID, so a direct signal cannot hit
        # an unrelated process. This does not claim that descendants were
        # cleaned up; the process-group failure remains the reported error.
        try:
            os.kill(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as direct_exc:
            group_failure.add_note(
                f"direct leader termination also failed: {direct_exc}"
            )
    try:
        process.wait(timeout=_remaining(cleanup_deadline))
    except subprocess.TimeoutExpired as exc:
        reap_failure = BoundedProcessError(
            "reap", "bounded subprocess did not exit after termination"
        )
        if group_failure is not None:
            reap_failure.add_note(str(group_failure))
        raise reap_failure from exc
    except OSError as exc:
        reap_failure = BoundedProcessError(
            "reap", f"cannot reap bounded subprocess: {exc}"
        )
        if group_failure is not None:
            reap_failure.add_note(str(group_failure))
        raise reap_failure from exc
    if group_failure is not None:
        raise group_failure


def _cleanup_process(
    process: subprocess.Popen[bytes], *, deadline: float | None = None
) -> BoundedProcessError | None:
    try:
        _kill_and_reap(process, deadline=deadline)
    except BoundedProcessError as exc:
        return exc
    except BaseException as exc:
        failure = BoundedProcessError(
            "reap", f"unexpected failure while cleaning bounded process: {exc}"
        )
        failure.__cause__ = exc
        return failure
    return None


def _close_stdout(stdout_pipe: BinaryIO) -> BoundedProcessError | None:
    try:
        stdout_pipe.close()
    except OSError as exc:
        failure = BoundedProcessError(
            "io", f"cannot close bounded subprocess stdout: {exc}"
        )
        failure.__cause__ = exc
        return failure
    return None


def _cleanup_stream_impl(
    process: subprocess.Popen[bytes],
    stdout_pipe: BinaryIO,
    reader: threading.Thread | None,
    *,
    reader_started: bool,
    terminate_process: bool,
    stdout_closed: bool,
) -> BoundedProcessError | None:
    cleanup_failures: list[BoundedProcessError] = []
    cleanup_deadline: float | None = None
    try:
        cleanup_deadline = time.monotonic() + REAP_TIMEOUT_SECONDS
    except BaseException as exc:
        failure = BoundedProcessError(
            "reap", f"cannot establish bounded stream cleanup deadline: {exc}"
        )
        failure.__cause__ = exc
        cleanup_failures.append(failure)

    if terminate_process:
        process_failure = _cleanup_process(process, deadline=cleanup_deadline)
        if process_failure is not None:
            cleanup_failures.append(process_failure)

    reader_alive = False
    if reader_started and reader is not None:
        try:
            join_timeout = (
                _remaining(cleanup_deadline)
                if cleanup_deadline is not None
                else REAP_TIMEOUT_SECONDS
            )
            reader.join(timeout=join_timeout)
        except BaseException as exc:
            join_failure = BoundedProcessError(
                "reap", f"cannot join bounded subprocess stdout reader: {exc}"
            )
            join_failure.__cause__ = exc
            cleanup_failures.append(join_failure)
        try:
            reader_alive = reader.is_alive()
        except BaseException as exc:
            state_failure = BoundedProcessError(
                "reap", f"cannot inspect bounded subprocess stdout reader: {exc}"
            )
            state_failure.__cause__ = exc
            cleanup_failures.append(state_failure)
            reader_alive = True
        if reader_alive:
            reader_failure = BoundedProcessError(
                "reap", "bounded subprocess stdout reader did not terminate"
            )
            cleanup_failures.append(reader_failure)
            # Closing a descriptor while another thread is blocked in read can
            # deadlock on BufferedReader locks or race fd reuse. The process
            # group has already been killed; leave this daemon reader isolated
            # and report the cleanup failure explicitly.
    if not stdout_closed and not reader_alive:
        close_failure = _close_stdout(stdout_pipe)
        if close_failure is not None:
            cleanup_failures.append(close_failure)

    if not cleanup_failures:
        return None
    primary_cleanup_failure = cleanup_failures[0]
    for additional_failure in cleanup_failures[1:]:
        primary_cleanup_failure.add_note(str(additional_failure))
    return primary_cleanup_failure


def _cleanup_stream(
    process: subprocess.Popen[bytes],
    stdout_pipe: BinaryIO,
    reader: threading.Thread | None,
    *,
    reader_started: bool,
    terminate_process: bool,
    stdout_closed: bool,
) -> BoundedProcessError | None:
    """Best-effort cleanup that never replaces the operation's primary error."""

    try:
        return _cleanup_stream_impl(
            process,
            stdout_pipe,
            reader,
            reader_started=reader_started,
            terminate_process=terminate_process,
            stdout_closed=stdout_closed,
        )
    except BaseException as exc:
        failure = BoundedProcessError(
            "reap", f"unexpected bounded stream cleanup failure: {exc}"
        )
        failure.__cause__ = exc
        return failure


def _raise_with_cleanup_note(
    primary: BaseException, cleanup_failure: BoundedProcessError | None
) -> Never:
    if cleanup_failure is not None:
        primary.add_note(f"bounded process cleanup failure: {cleanup_failure}")
    raise primary


def _raise_pending(primary: BaseException) -> Never:
    raise primary


def run(
    argv: Sequence[str],
    *,
    timeout_seconds: int,
    stderr: int | None = None,
    environment: Mapping[str, str] | None = None,
) -> BoundedResult:
    """Run with inherited stdout, DEVNULL stdin, and a hard wall-clock deadline."""

    timeout = _validated_timeout(timeout_seconds)
    process: subprocess.Popen[bytes] | None = None
    pending_failure: BaseException | None = None
    with _SignalCoordinator() as coordinator:
        try:
            coordinator.raise_if_requested()
            process = _start_process(
                argv,
                stdout=None,
                stderr=stderr,
                environment=environment,
            )
            coordinator.raise_if_requested()
            deadline = time.monotonic() + timeout
            returncode = _wait_for_process_exit(
                process, deadline=deadline, coordinator=coordinator
            )
            if returncode is None:
                pending_failure = BoundedProcessError(
                    "timeout", f"command timed out after {timeout} seconds"
                )
                _raise_pending(pending_failure)
            return BoundedResult(returncode=returncode)
        except BaseException as exc:
            primary = pending_failure or exc
            if pending_failure is not None and exc is not pending_failure:
                primary.add_note(
                    f"secondary exception while handling bounded process failure: {exc}"
                )
            cleanup_failure = (
                _cleanup_process(process) if process is not None else None
            )
            _raise_with_cleanup_note(primary, cleanup_failure)


def _stream_stdout(
    argv: Sequence[str],
    *,
    timeout_seconds: int,
    maximum_bytes: int,
    write_chunk: Callable[[bytes], None],
    stderr: int | None,
    environment: Mapping[str, str] | None = None,
    coordinator: _SignalCoordinator | None = None,
) -> BoundedResult:
    if coordinator is None:
        with _SignalCoordinator() as owned_coordinator:
            return _stream_stdout(
                argv,
                timeout_seconds=timeout_seconds,
                maximum_bytes=maximum_bytes,
                write_chunk=write_chunk,
                stderr=stderr,
                environment=environment,
                coordinator=owned_coordinator,
            )
    timeout = _validated_timeout(timeout_seconds)
    maximum = _validated_maximum(maximum_bytes)
    process: subprocess.Popen[bytes] | None = None
    stdout_pipe: BinaryIO | None = None
    reader: threading.Thread | None = None
    reader_started = False
    leader_reaped = False
    stdout_closed = False
    pending_failure: BaseException | None = None
    try:
        coordinator.raise_if_requested()
        process = _start_process(
            argv,
            stdout=subprocess.PIPE,
            stderr=stderr,
            environment=environment,
        )
        stdout_pipe = process.stdout
        coordinator.raise_if_requested()
        if stdout_pipe is None:
            pending_failure = BoundedProcessError(
                "io", "bounded subprocess did not expose stdout"
            )
            _raise_pending(pending_failure)

        state_lock = threading.Lock()
        reader_done = threading.Event()
        reader_failure: BaseException | None = None
        total = 0

        def read_stdout() -> None:
            nonlocal reader_failure, total
            try:
                while True:
                    chunk = stdout_pipe.read(READ_CHUNK_BYTES)
                    if not chunk:
                        break
                    with state_lock:
                        next_total = total + len(chunk)
                        if next_total > maximum:
                            reader_failure = BoundedProcessError(
                                "output_limit",
                                f"command output exceeds {maximum} bytes",
                            )
                            break
                        total = next_total
                    write_chunk(chunk)
            except (KeyboardInterrupt, SystemExit) as exc:
                with state_lock:
                    reader_failure = exc
            except BaseException as exc:
                failure = BoundedProcessError(
                    "io", f"cannot read or store bounded command output: {exc}"
                )
                failure.__cause__ = exc
                with state_lock:
                    reader_failure = failure
            finally:
                reader_done.set()

        reader = threading.Thread(
            target=read_stdout,
            name="bounded-process-stdout",
            daemon=True,
        )
        # Thread.start() may be interrupted after the OS thread exists but
        # before start() returns from its internal readiness wait. Mark cleanup
        # ownership before the call; a normal RuntimeError below can safely
        # narrow it back when no thread identity was ever assigned.
        reader_started = True
        try:
            reader.start()
        except RuntimeError as exc:
            pending_failure = BoundedProcessError(
                "start", f"cannot start bounded stdout reader: {exc}"
            )
            pending_failure.__cause__ = exc
            try:
                reader_started = reader.ident is not None
            except BaseException as state_exc:
                reader_started = True
                pending_failure.add_note(
                    f"cannot inspect reader start state: {state_exc}"
                )
            _raise_pending(pending_failure)
        deadline = time.monotonic() + timeout
        while True:
            coordinator.raise_if_requested()
            remaining = _remaining(deadline)
            if remaining <= 0:
                pending_failure = BoundedProcessError(
                    "timeout", f"command timed out after {timeout} seconds"
                )
                _raise_pending(pending_failure)
            if reader_done.wait(timeout=min(remaining, 0.05)):
                break
        coordinator.raise_if_requested()
        with state_lock:
            pending_failure = reader_failure
        if pending_failure is not None:
            _raise_pending(pending_failure)

        returncode = _wait_for_process_exit(
            process, deadline=deadline, coordinator=coordinator
        )
        if returncode is None:
            pending_failure = BoundedProcessError(
                "timeout", f"command timed out after {timeout} seconds"
            )
            _raise_pending(pending_failure)
        leader_reaped = True

        reader.join(timeout=REAP_TIMEOUT_SECONDS)
        if reader.is_alive():
            pending_failure = BoundedProcessError(
                "reap", "bounded subprocess stdout reader did not terminate"
            )
            _raise_pending(pending_failure)
        close_failure = _close_stdout(stdout_pipe)
        if close_failure is not None:
            pending_failure = close_failure
            _raise_pending(pending_failure)
        stdout_closed = True
        if returncode is None:
            pending_failure = BoundedProcessError(
                "reap", "bounded subprocess lacks an exit status"
            )
            _raise_pending(pending_failure)
        return BoundedResult(returncode=returncode)
    except BaseException as exc:
        primary = pending_failure or exc
        if pending_failure is not None and exc is not pending_failure:
            primary.add_note(
                f"secondary exception while handling bounded process failure: {exc}"
            )
        if process is None:
            cleanup_failure = None
        elif stdout_pipe is None:
            cleanup_failure = _cleanup_process(process)
        else:
            cleanup_failure = _cleanup_stream(
                process,
                stdout_pipe,
                reader,
                reader_started=reader_started,
                terminate_process=not leader_reaped,
                stdout_closed=stdout_closed,
            )
        _raise_with_cleanup_note(primary, cleanup_failure)


def capture_stdout(
    argv: Sequence[str],
    *,
    timeout_seconds: int,
    maximum_bytes: int,
    stderr: int | None = None,
    environment: Mapping[str, str] | None = None,
) -> BoundedResult:
    """Capture stdout without allowing the producer to exceed the byte limit."""

    chunks: list[bytes] = []
    result = _stream_stdout(
        argv,
        timeout_seconds=timeout_seconds,
        maximum_bytes=maximum_bytes,
        write_chunk=chunks.append,
        stderr=stderr,
        environment=environment,
    )
    return dataclasses.replace(result, stdout=b"".join(chunks))


def _validated_output_name(output_name: str) -> str:
    if not isinstance(output_name, str) or _OUTPUT_NAME.fullmatch(output_name) is None:
        raise BoundedProcessError(
            "output_path",
            "bounded-output name must be one canonical ASCII file leaf",
        )
    try:
        encoded = output_name.encode("ascii")
    except UnicodeEncodeError as exc:
        raise BoundedProcessError(
            "output_path", "bounded-output name must be ASCII"
        ) from exc
    if len(encoded) > MAX_OUTPUT_NAME_BYTES:
        raise BoundedProcessError(
            "output_path",
            f"bounded-output name exceeds {MAX_OUTPUT_NAME_BYTES} bytes",
        )
    return output_name


def _owned_private_directory_fd(directory_fd: int) -> int:
    try:
        owned_fd = os.dup(directory_fd)
    except OSError as exc:
        raise BoundedProcessError(
            "output_path", f"cannot duplicate bounded-output directory: {exc}"
        ) from exc
    try:
        metadata = os.fstat(owned_fd)
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or mode != 0o700
        ):
            raise BoundedProcessError(
                "output_path",
                "bounded-output directory must be current-user-owned with mode 0700",
            )
    except BaseException as primary:
        try:
            os.close(owned_fd)
        except BaseException as cleanup_error:
            primary.add_note(
                f"closing the rejected bounded-output directory also failed: {cleanup_error}"
            )
        raise
    return owned_fd


def _require_safe_output_target_at(directory_fd: int, output_name: str) -> None:
    try:
        metadata = os.stat(output_name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise BoundedProcessError(
            "output_path", f"cannot inspect bounded-output target {output_name}: {exc}"
        ) from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise BoundedProcessError(
            "output_path",
            "bounded-output target must be one current-user-owned regular file with mode 0600",
        )


def _create_temporary_output(directory_fd: int, output_name: str) -> tuple[int, str]:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    for _ in range(32):
        temporary_name = f".{output_name}.bounded-{secrets.token_hex(16)}"
        try:
            descriptor = os.open(
                temporary_name,
                flags,
                0o600,
                dir_fd=directory_fd,
            )
        except FileExistsError:
            continue
        except OSError as exc:
            raise BoundedProcessError(
                "io", f"cannot create bounded temporary output for {output_name}: {exc}"
            ) from exc
        try:
            os.fchmod(descriptor, 0o600)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise BoundedProcessError(
                    "io", "bounded temporary output lacks its private regular-file identity"
                )
        except BaseException as primary:
            try:
                os.close(descriptor)
            except BaseException as cleanup_error:
                primary.add_note(
                    f"closing rejected bounded temporary output also failed: {cleanup_error}"
                )
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except BaseException as cleanup_error:
                primary.add_note(
                    f"removing rejected bounded temporary output also failed: {cleanup_error}"
                )
            raise
        return descriptor, temporary_name
    raise BoundedProcessError(
        "io", "cannot allocate a unique bounded temporary output name"
    )


def _write_stdout_impl(
    argv: Sequence[str],
    *,
    output_directory_fd: int,
    output_name: str,
    timeout_seconds: int,
    maximum_bytes: int,
    stderr: int | None = None,
    environment: Mapping[str, str] | None = None,
    coordinator: _SignalCoordinator,
) -> BoundedResult:
    """Atomically replace output only after a bounded command exits successfully."""

    target_name = _validated_output_name(output_name)
    directory_fd = _owned_private_directory_fd(output_directory_fd)
    temporary_fd = -1
    temporary_name = ""
    replaced = False
    primary_failure: BaseException | None = None
    try:
        try:
            _require_safe_output_target_at(directory_fd, target_name)
            temporary_fd, temporary_name = _create_temporary_output(
                directory_fd, target_name
            )

            def write_chunk(chunk: bytes) -> None:
                view = memoryview(chunk)
                while view:
                    written = os.write(temporary_fd, view)
                    view = view[written:]

            result = _stream_stdout(
                argv,
                timeout_seconds=timeout_seconds,
                maximum_bytes=maximum_bytes,
                write_chunk=write_chunk,
                stderr=stderr,
                environment=environment,
                coordinator=coordinator,
            )
            coordinator.raise_if_requested()
            if result.returncode != 0:
                return result
            os.fsync(temporary_fd)
            os.close(temporary_fd)
            temporary_fd = -1
            commit_mask = signal.pthread_sigmask(
                signal.SIG_BLOCK, set(_INTERRUPTION_SIGNALS)
            )
            try:
                coordinator.raise_if_requested()
                _require_safe_output_target_at(directory_fd, target_name)
                # os.replace is the output transaction's linearization point.
                # A signal pending inside this child-free critical section is
                # ordered after the committed replacement.
                os.replace(
                    temporary_name,
                    target_name,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                )
                replaced = True
                os.fsync(directory_fd)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, commit_mask)
            return result
        except OSError as exc:
            raise BoundedProcessError(
                "io", f"cannot store bounded command output at {target_name}: {exc}"
            ) from exc
    except BaseException as exc:
        primary_failure = exc
        raise
    finally:
        cleanup_failures: list[tuple[str, BaseException]] = []
        if temporary_fd >= 0:
            try:
                os.close(temporary_fd)
            except BaseException as exc:
                cleanup_failures.append(("close temporary output", exc))
        if temporary_name and not replaced:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            except BaseException as exc:
                cleanup_failures.append(("remove temporary output", exc))
        try:
            os.close(directory_fd)
        except BaseException as exc:
            cleanup_failures.append(("close output directory", exc))
        if cleanup_failures:
            details = "; ".join(
                f"{operation}: {failure}"
                for operation, failure in cleanup_failures
            )
            if primary_failure is not None:
                primary_failure.add_note(f"bounded output cleanup failure: {details}")
            else:
                cleanup_failure = BoundedProcessError(
                    "io", f"cannot clean bounded output at {target_name}: {details}"
                )
                cleanup_failure.__cause__ = cleanup_failures[0][1]
                raise cleanup_failure


def write_stdout_at(
    argv: Sequence[str],
    *,
    output_directory_fd: int,
    output_name: str,
    timeout_seconds: int,
    maximum_bytes: int,
    stderr: int | None = None,
    environment: Mapping[str, str] | None = None,
) -> BoundedResult:
    """Atomically replace output only after a bounded command exits successfully."""

    with _SignalCoordinator() as coordinator:
        return _write_stdout_impl(
            argv,
            output_directory_fd=output_directory_fd,
            output_name=output_name,
            timeout_seconds=timeout_seconds,
            maximum_bytes=maximum_bytes,
            stderr=stderr,
            environment=environment,
            coordinator=coordinator,
        )
