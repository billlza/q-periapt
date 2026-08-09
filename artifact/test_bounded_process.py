#!/usr/bin/env python3

from __future__ import annotations

import os
import pathlib
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from collections.abc import Sequence
from typing import BinaryIO
from unittest import mock

import bounded_process


class BoundedProcessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    @staticmethod
    def python(source: str) -> list[str]:
        return [sys.executable, "-c", source]

    def descendant_command(
        self,
        name: str,
        *,
        descendant_action: str,
        leader_action: str,
    ) -> tuple[list[str], pathlib.Path]:
        pid_path = self.root / f"{name}.pids"
        ready_path = self.root / f"{name}.ready"
        descendant_source = "\n".join(
            (
                "import os, pathlib, signal, sys, time",
                "ready = pathlib.Path(sys.argv[1])",
                "while not ready.exists():",
                "    time.sleep(0.01)",
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)",
                descendant_action,
            )
        )
        leader_source = "\n".join(
            (
                "import os, pathlib, subprocess, sys, time",
                f"pid_path = pathlib.Path({str(pid_path)!r})",
                f"ready_path = pathlib.Path({str(ready_path)!r})",
                "descendant = subprocess.Popen(",
                "    [sys.executable, '-c', "
                f"{descendant_source!r}, str(ready_path)],",
                "    stdin=subprocess.DEVNULL,",
                "    stdout=sys.stdout,",
                "    stderr=subprocess.DEVNULL,",
                ")",
                "pid_path.write_text(",
                "    f'{os.getpid()} {os.getpgrp()} {os.getsid(0)} '",
                "    f'{descendant.pid} {os.getpgid(descendant.pid)} '",
                "    f'{os.getsid(descendant.pid)}\\n',",
                "    encoding='ascii',",
                ")",
                "ready_path.write_text('ready\\n', encoding='ascii')",
                leader_action,
            )
        )
        return self.python(leader_source), pid_path

    @staticmethod
    def read_complete_integer_record(
        path: pathlib.Path, expected_fields: int
    ) -> tuple[int, ...] | None:
        try:
            fields = path.read_text(encoding="ascii").split()
        except FileNotFoundError:
            return None
        if len(fields) != expected_fields:
            return None
        try:
            return tuple(int(field) for field in fields)
        except ValueError:
            return None

    def read_process_identity(
        self, pid_path: pathlib.Path
    ) -> tuple[int, int, int, int, int, int]:
        for _ in range(200):
            values = self.read_complete_integer_record(pid_path, 6)
            if values is None:
                time.sleep(0.01)
                continue
            leader_pid, leader_pgid, leader_sid, child_pid, child_pgid, child_sid = (
                values
            )
            return (
                leader_pid,
                leader_pgid,
                leader_sid,
                child_pid,
                child_pgid,
                child_sid,
            )
        self.fail(f"process fixture did not publish identity: {pid_path}")

    def assert_process_group_identity(
        self, identity: tuple[int, int, int, int, int, int]
    ) -> int:
        leader_pid, leader_pgid, leader_sid, _, child_pgid, child_sid = identity
        self.assertEqual(leader_pid, leader_pgid)
        self.assertEqual(leader_pid, leader_sid)
        self.assertEqual(child_pgid, leader_pgid)
        self.assertEqual(child_sid, leader_sid)
        self.assertNotEqual(leader_pgid, os.getpgrp())
        return leader_pgid

    @staticmethod
    def process_group_exists(process_group: int) -> bool:
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    def assert_process_group_gone(self, process_group: int) -> None:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if not self.process_group_exists(process_group):
                return
            time.sleep(0.02)
        self.fail(f"bounded process group {process_group} survived cleanup")

    def cleanup_process_group(self, process_group: int | None) -> None:
        if (
            process_group is None
            or process_group <= 1
            or process_group == os.getpgrp()
        ):
            return
        try:
            os.killpg(process_group, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def test_capture_accepts_exact_limit_and_large_pipe_output(self) -> None:
        payload_size = bounded_process.READ_CHUNK_BYTES * 3
        result = bounded_process.capture_stdout(
            self.python(f"import sys; sys.stdout.buffer.write(b'x' * {payload_size})"),
            timeout_seconds=5,
            maximum_bytes=payload_size,
            stderr=subprocess.DEVNULL,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"x" * payload_size)

    def test_capture_rejects_one_byte_over_limit(self) -> None:
        with self.assertRaisesRegex(
            bounded_process.BoundedProcessError, "exceeds 32 bytes"
        ) as raised:
            bounded_process.capture_stdout(
                self.python("import sys; sys.stdout.buffer.write(b'x' * 33)"),
                timeout_seconds=5,
                maximum_bytes=32,
                stderr=subprocess.DEVNULL,
            )
        self.assertEqual(raised.exception.kind, "output_limit")

    def test_capture_preserves_nonzero_status_and_output(self) -> None:
        result = bounded_process.capture_stdout(
            self.python("import sys; print('diagnostic'); raise SystemExit(7)"),
            timeout_seconds=5,
            maximum_bytes=1024,
            stderr=subprocess.DEVNULL,
        )
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout, b"diagnostic\n")

    def test_timeout_terminates_promptly(self) -> None:
        started = time.monotonic()
        with self.assertRaisesRegex(
            bounded_process.BoundedProcessError, "timed out after 1 seconds"
        ) as raised:
            bounded_process.capture_stdout(
                self.python("import time; time.sleep(60)"),
                timeout_seconds=1,
                maximum_bytes=1024,
                stderr=subprocess.DEVNULL,
            )
        self.assertEqual(raised.exception.kind, "timeout")
        self.assertLess(time.monotonic() - started, 5)

    def test_timeout_kills_stdout_inheriting_descendant_after_leader_exit(
        self,
    ) -> None:
        command, pid_path = self.descendant_command(
            "leader-exit",
            descendant_action="time.sleep(60)",
            leader_action="raise SystemExit(0)",
        )
        process_group: int | None = None
        started = time.monotonic()
        try:
            with self.assertRaises(bounded_process.BoundedProcessError) as raised:
                bounded_process.capture_stdout(
                    command,
                    timeout_seconds=1,
                    maximum_bytes=1024,
                    stderr=subprocess.DEVNULL,
                )
            self.assertEqual(raised.exception.kind, "timeout")
            identity = self.read_process_identity(pid_path)
            process_group = self.assert_process_group_identity(identity)
            self.assert_process_group_gone(process_group)
            self.assertLess(time.monotonic() - started, 5)
        finally:
            self.cleanup_process_group(process_group)

    def test_run_timeout_kills_descendant_process_group(self) -> None:
        command, pid_path = self.descendant_command(
            "run-timeout",
            descendant_action="time.sleep(60)",
            leader_action="time.sleep(60)",
        )
        process_group: int | None = None
        try:
            with self.assertRaises(bounded_process.BoundedProcessError) as raised:
                bounded_process.run(
                    command,
                    timeout_seconds=1,
                    stderr=subprocess.DEVNULL,
                )
            self.assertEqual(raised.exception.kind, "timeout")
            identity = self.read_process_identity(pid_path)
            process_group = self.assert_process_group_identity(identity)
            self.assert_process_group_gone(process_group)
        finally:
            self.cleanup_process_group(process_group)

    def test_output_limit_kills_descendant_process_group(self) -> None:
        command, pid_path = self.descendant_command(
            "overflow",
            descendant_action="os.write(1, b'x' * 65); time.sleep(60)",
            leader_action="time.sleep(60)",
        )
        process_group: int | None = None
        try:
            with self.assertRaises(bounded_process.BoundedProcessError) as raised:
                bounded_process.capture_stdout(
                    command,
                    timeout_seconds=5,
                    maximum_bytes=64,
                    stderr=subprocess.DEVNULL,
                )
            self.assertEqual(raised.exception.kind, "output_limit")
            identity = self.read_process_identity(pid_path)
            process_group = self.assert_process_group_identity(identity)
            self.assert_process_group_gone(process_group)
        finally:
            self.cleanup_process_group(process_group)

    def test_main_keyboard_interrupt_cleans_descendant_process_group(self) -> None:
        command, pid_path = self.descendant_command(
            "keyboard-interrupt",
            descendant_action="time.sleep(60)",
            leader_action="time.sleep(60)",
        )
        original_start = bounded_process._start_process
        original_monotonic = time.monotonic
        monotonic_calls = 0

        def wait_for_fixture(
            argv: Sequence[str],
            *,
            stdout: int | None,
            stderr: int | None,
        ) -> subprocess.Popen[bytes]:
            process = original_start(argv, stdout=stdout, stderr=stderr)
            for _ in range(200):
                if self.read_complete_integer_record(pid_path, 6) is not None:
                    return process
                time.sleep(0.01)
            self.fail("process fixture was not ready before injected interrupt")

        def interrupt_second_monotonic_call() -> float:
            nonlocal monotonic_calls
            monotonic_calls += 1
            if monotonic_calls == 2:
                raise KeyboardInterrupt
            return original_monotonic()

        process_group: int | None = None
        try:
            with (
                mock.patch.object(
                    bounded_process, "_start_process", side_effect=wait_for_fixture
                ),
                mock.patch.object(
                    bounded_process.time,
                    "monotonic",
                    side_effect=interrupt_second_monotonic_call,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                bounded_process.capture_stdout(
                    command,
                    timeout_seconds=5,
                    maximum_bytes=1024,
                    stderr=subprocess.DEVNULL,
                )
            identity = self.read_process_identity(pid_path)
            process_group = self.assert_process_group_identity(identity)
            self.assert_process_group_gone(process_group)
        finally:
            self.cleanup_process_group(process_group)

    def test_deadline_construction_interrupt_cleans_descendant_process_group(
        self,
    ) -> None:
        command, pid_path = self.descendant_command(
            "deadline-interrupt",
            descendant_action="time.sleep(60)",
            leader_action="time.sleep(60)",
        )
        original_start = bounded_process._start_process
        original_monotonic = time.monotonic
        monotonic_calls = 0

        def wait_for_fixture(
            argv: Sequence[str],
            *,
            stdout: int | None,
            stderr: int | None,
        ) -> subprocess.Popen[bytes]:
            process = original_start(argv, stdout=stdout, stderr=stderr)
            for _ in range(200):
                if self.read_complete_integer_record(pid_path, 6) is not None:
                    return process
                time.sleep(0.01)
            self.fail("process fixture was not ready before deadline interrupt")

        def interrupt_first_monotonic_call() -> float:
            nonlocal monotonic_calls
            monotonic_calls += 1
            if monotonic_calls == 1:
                raise KeyboardInterrupt
            return original_monotonic()

        process_group: int | None = None
        try:
            with (
                mock.patch.object(
                    bounded_process, "_start_process", side_effect=wait_for_fixture
                ),
                mock.patch.object(
                    bounded_process.time,
                    "monotonic",
                    side_effect=interrupt_first_monotonic_call,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                bounded_process.capture_stdout(
                    command,
                    timeout_seconds=5,
                    maximum_bytes=1024,
                    stderr=subprocess.DEVNULL,
                )
            identity = self.read_process_identity(pid_path)
            process_group = self.assert_process_group_identity(identity)
            self.assert_process_group_gone(process_group)
        finally:
            self.cleanup_process_group(process_group)

    def test_reaped_then_interrupted_wait_never_signals_reused_group(self) -> None:
        process = mock.Mock(spec=subprocess.Popen)
        process.pid = 424_242
        process.returncode = None

        def reap_then_interrupt(
            candidate: subprocess.Popen[bytes],
            *,
            deadline: float,
            coordinator: object,
        ) -> int:
            self.assertIs(candidate, process)
            self.assertGreater(deadline, time.monotonic())
            self.assertIsNotNone(coordinator)
            process.returncode = 0
            raise KeyboardInterrupt

        with (
            mock.patch.object(bounded_process, "_start_process", return_value=process),
            mock.patch.object(
                bounded_process,
                "_wait_for_process_exit",
                side_effect=reap_then_interrupt,
            ),
            mock.patch.object(bounded_process.os, "killpg") as kill_group,
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            bounded_process.run(
                ["synthetic-command"],
                timeout_seconds=5,
                stderr=subprocess.DEVNULL,
            )
        kill_group.assert_not_called()
        notes = getattr(raised.exception, "__notes__", ())
        self.assertTrue(
            any("leader was already reaped" in note for note in notes),
            notes,
        )

    def test_secondary_interrupt_cannot_replace_pending_timeout(self) -> None:
        command, pid_path = self.descendant_command(
            "pending-timeout",
            descendant_action="time.sleep(60)",
            leader_action="time.sleep(60)",
        )
        process_group: int | None = None
        try:
            with (
                mock.patch.object(
                    bounded_process, "_raise_pending", side_effect=KeyboardInterrupt
                ),
                self.assertRaises(bounded_process.BoundedProcessError) as raised,
            ):
                bounded_process.capture_stdout(
                    command,
                    timeout_seconds=1,
                    maximum_bytes=1024,
                    stderr=subprocess.DEVNULL,
                )
            self.assertEqual(raised.exception.kind, "timeout")
            notes = getattr(raised.exception, "__notes__", ())
            self.assertTrue(
                any("secondary exception" in note for note in notes), notes
            )
            identity = self.read_process_identity(pid_path)
            process_group = self.assert_process_group_identity(identity)
            self.assert_process_group_gone(process_group)
        finally:
            self.cleanup_process_group(process_group)

    def test_cleanup_deadline_interrupt_cannot_replace_timeout(self) -> None:
        process = mock.Mock(spec=subprocess.Popen)
        stdout_pipe = mock.Mock()
        primary = bounded_process.BoundedProcessError(
            "timeout", "sentinel command timeout"
        )
        with (
            mock.patch.object(bounded_process.time, "monotonic", side_effect=KeyboardInterrupt),
            mock.patch.object(bounded_process, "_cleanup_process", return_value=None),
        ):
            cleanup_failure = bounded_process._cleanup_stream(
                process,
                stdout_pipe,
                None,
                reader_started=False,
                terminate_process=True,
                stdout_closed=True,
            )
        self.assertIsNotNone(cleanup_failure)
        with self.assertRaises(bounded_process.BoundedProcessError) as raised:
            bounded_process._raise_with_cleanup_note(primary, cleanup_failure)
        self.assertIs(raised.exception, primary)
        self.assertEqual(raised.exception.kind, "timeout")
        notes = getattr(raised.exception, "__notes__", ())
        self.assertTrue(
            any("cleanup deadline" in note for note in notes),
            notes,
        )

    def test_cleanup_close_interrupt_cannot_replace_timeout(self) -> None:
        original_close = bounded_process._close_stdout

        def close_then_interrupt(stdout_pipe: BinaryIO) -> None:
            close_failure = original_close(stdout_pipe)
            self.assertIsNone(close_failure)
            raise KeyboardInterrupt

        with (
            mock.patch.object(
                bounded_process, "_close_stdout", side_effect=close_then_interrupt
            ),
            self.assertRaises(bounded_process.BoundedProcessError) as raised,
        ):
            bounded_process.capture_stdout(
                self.python("import time; time.sleep(60)"),
                timeout_seconds=1,
                maximum_bytes=1024,
                stderr=subprocess.DEVNULL,
            )
        self.assertEqual(raised.exception.kind, "timeout")
        notes = getattr(raised.exception, "__notes__", ())
        self.assertTrue(
            any("unexpected bounded stream cleanup failure" in note for note in notes),
            notes,
        )

    def test_reader_sink_failure_is_reported_and_cleans_process_group(self) -> None:
        command, pid_path = self.descendant_command(
            "sink-failure",
            descendant_action="os.write(1, b'x'); time.sleep(60)",
            leader_action="time.sleep(60)",
        )

        def fail_write(_: bytes) -> None:
            raise RuntimeError("sentinel write failure")

        process_group: int | None = None
        try:
            with self.assertRaises(bounded_process.BoundedProcessError) as raised:
                bounded_process._stream_stdout(
                    command,
                    timeout_seconds=5,
                    maximum_bytes=1024,
                    write_chunk=fail_write,
                    stderr=subprocess.DEVNULL,
                )
            self.assertEqual(raised.exception.kind, "io")
            self.assertIsInstance(raised.exception.__cause__, RuntimeError)
            identity = self.read_process_identity(pid_path)
            process_group = self.assert_process_group_identity(identity)
            self.assert_process_group_gone(process_group)
        finally:
            self.cleanup_process_group(process_group)

    def test_reader_keyboard_interrupt_is_preserved_and_cleans_process_group(
        self,
    ) -> None:
        command, pid_path = self.descendant_command(
            "reader-interrupt",
            descendant_action="os.write(1, b'x'); time.sleep(60)",
            leader_action="time.sleep(60)",
        )

        def interrupt_write(_: bytes) -> None:
            raise KeyboardInterrupt

        process_group: int | None = None
        try:
            with self.assertRaises(KeyboardInterrupt):
                bounded_process._stream_stdout(
                    command,
                    timeout_seconds=5,
                    maximum_bytes=1024,
                    write_chunk=interrupt_write,
                    stderr=subprocess.DEVNULL,
                )
            identity = self.read_process_identity(pid_path)
            process_group = self.assert_process_group_identity(identity)
            self.assert_process_group_gone(process_group)
        finally:
            self.cleanup_process_group(process_group)

    def test_success_does_not_kill_stdout_closing_descendant(self) -> None:
        command, pid_path = self.descendant_command(
            "successful-daemon",
            descendant_action="os.close(1); time.sleep(60)",
            leader_action="raise SystemExit(0)",
        )
        process_group: int | None = None
        try:
            result = bounded_process.capture_stdout(
                command,
                timeout_seconds=5,
                maximum_bytes=1024,
                stderr=subprocess.DEVNULL,
            )
            self.assertEqual(result, bounded_process.BoundedResult(0, b""))
            identity = self.read_process_identity(pid_path)
            process_group = self.assert_process_group_identity(identity)
            self.assertTrue(self.process_group_exists(process_group))
        finally:
            self.cleanup_process_group(process_group)

    def test_pending_sigint_after_process_creation_cleans_owned_group(self) -> None:
        command, pid_path = self.descendant_command(
            "pending-sigint",
            descendant_action="time.sleep(60)",
            leader_action="time.sleep(60)",
        )
        original_start = bounded_process._start_process

        def signal_after_start(
            argv: Sequence[str],
            *,
            stdout: int | None,
            stderr: int | None,
        ) -> subprocess.Popen[bytes]:
            process = original_start(argv, stdout=stdout, stderr=stderr)
            for _ in range(200):
                if self.read_complete_integer_record(pid_path, 6) is not None:
                    os.kill(os.getpid(), signal.SIGINT)
                    return process
                time.sleep(0.01)
            self.fail("process fixture was not ready before pending SIGINT")

        process_group: int | None = None
        try:
            with (
                mock.patch.object(
                    bounded_process, "_start_process", side_effect=signal_after_start
                ),
                self.assertRaises(SystemExit) as raised,
            ):
                bounded_process.capture_stdout(
                    command,
                    timeout_seconds=5,
                    maximum_bytes=1024,
                    stderr=subprocess.DEVNULL,
                )
            self.assertEqual(raised.exception.code, 128 + signal.SIGINT)
            identity = self.read_process_identity(pid_path)
            process_group = self.assert_process_group_identity(identity)
            self.assert_process_group_gone(process_group)
        finally:
            self.cleanup_process_group(process_group)

    def test_child_inherits_caller_mask_without_added_control_signals(self) -> None:
        caller_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        result = bounded_process.capture_stdout(
            self.python(
                "import signal; "
                "blocked = signal.pthread_sigmask(signal.SIG_BLOCK, set()); "
                "print(','.join(str(int(value)) for value in sorted(blocked)))"
            ),
            timeout_seconds=5,
            maximum_bytes=1024,
            stderr=subprocess.DEVNULL,
        )
        expected = ",".join(str(int(value)) for value in sorted(caller_mask))
        self.assertEqual(result.stdout.decode("ascii").strip(), expected)
        for control_signal in (signal.SIGINT, signal.SIGHUP, signal.SIGTERM):
            if control_signal not in caller_mask:
                self.assertNotIn(
                    str(int(control_signal)),
                    result.stdout.decode("ascii").strip().split(","),
                )

    def test_sigterm_and_sighup_cli_cleanup_owned_process_group(self) -> None:
        script = pathlib.Path(bounded_process.__file__).resolve()
        for termination_signal in (signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signal=termination_signal.name):
                pid_path = self.root / f"cli-{termination_signal.name}.pids"
                target_source = "\n".join(
                    (
                        "import os, pathlib, sys, time",
                        "pathlib.Path(sys.argv[1]).write_text(",
                        "    f'{os.getpid()} {os.getpgrp()}\\n',",
                        "    encoding='ascii',",
                        ")",
                        "time.sleep(60)",
                    )
                )
                helper = subprocess.Popen(
                    [
                        sys.executable,
                        str(script),
                        "capture",
                        "--timeout-seconds",
                        "30",
                        "--maximum-bytes",
                        "1024",
                        "--",
                        sys.executable,
                        "-c",
                        target_source,
                        str(pid_path),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
                process_group: int | None = None
                try:
                    identity: tuple[int, int] | None = None
                    for _ in range(300):
                        values = self.read_complete_integer_record(pid_path, 2)
                        if values is None:
                            time.sleep(0.01)
                            continue
                        identity = (values[0], values[1])
                        break
                    if identity is None:
                        self.fail("CLI target did not publish its process identity")
                    target_pid, process_group = identity
                    self.assertEqual(target_pid, process_group)
                    os.kill(helper.pid, termination_signal)
                    _, stderr_bytes = helper.communicate(timeout=10)
                    self.assertEqual(
                        helper.returncode, 128 + termination_signal, stderr_bytes
                    )
                    self.assert_process_group_gone(process_group)
                finally:
                    if helper.poll() is None:
                        helper.kill()
                        helper.wait(timeout=5)
                    self.cleanup_process_group(process_group)

    def test_non_main_thread_fails_before_starting_process(self) -> None:
        sentinel = self.root / "worker-started"
        failures: list[BaseException] = []

        def invoke_from_worker() -> None:
            try:
                bounded_process.capture_stdout(
                    self.python(
                        f"import pathlib; pathlib.Path({str(sentinel)!r}).touch()"
                    ),
                    timeout_seconds=5,
                    maximum_bytes=1024,
                    stderr=subprocess.DEVNULL,
                )
            except BaseException as exc:
                failures.append(exc)

        worker = bounded_process.threading.Thread(target=invoke_from_worker)
        worker.start()
        worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], bounded_process.BoundedProcessError)
        self.assertEqual(failures[0].kind, "start")
        self.assertFalse(sentinel.exists())

    def test_signal_diagnostics_use_fixed_saturating_counters(self) -> None:
        coordinator = bounded_process._SignalCoordinator()
        coordinator._record_signal(signal.SIGTERM, None)
        for _ in range(bounded_process._MAX_ADDITIONAL_SIGNAL_COUNT + 20):
            coordinator._record_signal(signal.SIGTERM, None)
        self.assertEqual(
            set(coordinator._additional_signal_counts),
            {int(value) for value in bounded_process._INTERRUPTION_SIGNALS},
        )
        self.assertEqual(
            coordinator._additional_signal_counts[int(signal.SIGTERM)],
            bounded_process._MAX_ADDITIONAL_SIGNAL_COUNT,
        )

    def test_reader_start_failure_reaps_the_started_process(self) -> None:
        command, pid_path = self.descendant_command(
            "reader-start-failure",
            descendant_action="time.sleep(60)",
            leader_action="time.sleep(60)",
        )
        started_processes: list[subprocess.Popen[bytes]] = []
        original_start = bounded_process._start_process

        def record_process(
            argv: Sequence[str],
            *,
            stdout: int | None,
            stderr: int | None,
        ) -> subprocess.Popen[bytes]:
            process = original_start(argv, stdout=stdout, stderr=stderr)
            started_processes.append(process)
            for _ in range(200):
                if self.read_complete_integer_record(pid_path, 6) is not None:
                    return process
                time.sleep(0.01)
            self.fail("process fixture was not ready before reader start failure")

        process_group: int | None = None
        try:
            with (
                mock.patch.object(
                    bounded_process, "_start_process", side_effect=record_process
                ),
                mock.patch.object(
                    bounded_process.threading.Thread,
                    "start",
                    side_effect=RuntimeError("thread unavailable"),
                ),
                self.assertRaisesRegex(
                    bounded_process.BoundedProcessError,
                    "cannot start bounded stdout reader",
                ) as raised,
            ):
                bounded_process.capture_stdout(
                    command,
                    timeout_seconds=5,
                    maximum_bytes=1024,
                    stderr=subprocess.DEVNULL,
                )
            self.assertEqual(raised.exception.kind, "start")
            self.assertEqual(len(started_processes), 1)
            self.assertIsNotNone(started_processes[0].poll())
            identity = self.read_process_identity(pid_path)
            process_group = self.assert_process_group_identity(identity)
            self.assert_process_group_gone(process_group)
        finally:
            self.cleanup_process_group(process_group)

    def test_interrupt_after_reader_thread_start_joins_and_cleans_group(self) -> None:
        command, pid_path = self.descendant_command(
            "reader-start-interrupt",
            descendant_action="time.sleep(60)",
            leader_action="time.sleep(60)",
        )
        original_process_start = bounded_process._start_process
        original_thread_start = bounded_process.threading.Thread.start

        def wait_for_fixture(
            argv: Sequence[str],
            *,
            stdout: int | None,
            stderr: int | None,
        ) -> subprocess.Popen[bytes]:
            process = original_process_start(argv, stdout=stdout, stderr=stderr)
            for _ in range(200):
                if self.read_complete_integer_record(pid_path, 6) is not None:
                    return process
                time.sleep(0.01)
            self.fail("process fixture was not ready before reader start interrupt")

        def start_then_interrupt(reader: bounded_process.threading.Thread) -> None:
            original_thread_start(reader)
            raise KeyboardInterrupt

        process_group: int | None = None
        try:
            with (
                mock.patch.object(
                    bounded_process, "_start_process", side_effect=wait_for_fixture
                ),
                mock.patch.object(
                    bounded_process.threading.Thread,
                    "start",
                    autospec=True,
                    side_effect=start_then_interrupt,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                bounded_process.capture_stdout(
                    command,
                    timeout_seconds=5,
                    maximum_bytes=1024,
                    stderr=subprocess.DEVNULL,
                )
            identity = self.read_process_identity(pid_path)
            process_group = self.assert_process_group_identity(identity)
            self.assert_process_group_gone(process_group)
            self.assertFalse(
                any(
                    thread.name == "bounded-process-stdout" and thread.is_alive()
                    for thread in bounded_process.threading.enumerate()
                )
            )
        finally:
            self.cleanup_process_group(process_group)

    def test_write_is_private_and_atomic_on_success(self) -> None:
        output = self.root / "output.bin"
        result = bounded_process.write_stdout(
            self.python("import sys; sys.stdout.buffer.write(b'complete')"),
            output_path=output,
            timeout_seconds=5,
            maximum_bytes=8,
            stderr=subprocess.DEVNULL,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(output.read_bytes(), b"complete")
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_nonzero_overflow_and_timeout_preserve_existing_output(self) -> None:
        cases = (
            (
                "nonzero",
                self.python("import sys; sys.stdout.write('partial'); raise SystemExit(9)"),
                5,
                1024,
                None,
                9,
            ),
            (
                "overflow",
                self.python("import sys; sys.stdout.buffer.write(b'x' * 65)"),
                5,
                64,
                "output_limit",
                None,
            ),
            (
                "timeout",
                self.python("import time; time.sleep(60)"),
                1,
                64,
                "timeout",
                None,
            ),
        )
        for name, command, timeout, maximum, error_kind, returncode in cases:
            with self.subTest(case=name):
                output = self.root / f"{name}.bin"
                output.write_bytes(b"original")
                output.chmod(0o600)
                if error_kind is None:
                    result = bounded_process.write_stdout(
                        command,
                        output_path=output,
                        timeout_seconds=timeout,
                        maximum_bytes=maximum,
                        stderr=subprocess.DEVNULL,
                    )
                    self.assertEqual(result.returncode, returncode)
                else:
                    with self.assertRaises(bounded_process.BoundedProcessError) as raised:
                        bounded_process.write_stdout(
                            command,
                            output_path=output,
                            timeout_seconds=timeout,
                            maximum_bytes=maximum,
                            stderr=subprocess.DEVNULL,
                        )
                    self.assertEqual(raised.exception.kind, error_kind)
                self.assertEqual(output.read_bytes(), b"original")
                self.assertEqual(list(self.root.glob(f".{name}.bin.bounded-*")), [])

    def test_output_cleanup_failures_do_not_mask_primary_error(self) -> None:
        output = self.root / "cleanup-primary.bin"
        primary = bounded_process.BoundedProcessError(
            "timeout", "sentinel command timeout"
        )
        real_close = os.close
        real_unlink = pathlib.Path.unlink

        def close_then_fail(file_descriptor: int) -> None:
            real_close(file_descriptor)
            raise OSError("sentinel close failure")

        def unlink_then_fail(path: pathlib.Path, *, missing_ok: bool = False) -> None:
            real_unlink(path, missing_ok=missing_ok)
            raise OSError("sentinel unlink failure")

        with (
            mock.patch.object(bounded_process, "_stream_stdout", side_effect=primary),
            mock.patch.object(bounded_process.os, "close", side_effect=close_then_fail),
            mock.patch.object(
                bounded_process.pathlib.Path,
                "unlink",
                autospec=True,
                side_effect=unlink_then_fail,
            ),
            self.assertRaises(bounded_process.BoundedProcessError) as raised,
        ):
            bounded_process.write_stdout(
                self.python("raise SystemExit(0)"),
                output_path=output,
                timeout_seconds=5,
                maximum_bytes=1024,
                stderr=subprocess.DEVNULL,
            )
        self.assertIs(raised.exception, primary)
        self.assertEqual(raised.exception.kind, "timeout")
        notes = getattr(raised.exception, "__notes__", ())
        self.assertTrue(any("sentinel close failure" in note for note in notes), notes)
        self.assertTrue(any("sentinel unlink failure" in note for note in notes), notes)
        self.assertEqual(list(self.root.glob(".cleanup-primary.bin.bounded-*")), [])

    def test_signal_after_stream_success_preserves_existing_output(self) -> None:
        output = self.root / "signal-before-commit.bin"
        output.write_bytes(b"original")
        output.chmod(0o600)

        def signal_after_stream(
            _argv: Sequence[str],
            **arguments: object,
        ) -> bounded_process.BoundedResult:
            write_chunk = arguments["write_chunk"]
            if not callable(write_chunk):
                self.fail("write_chunk was not callable")
            write_chunk(b"replacement")
            os.kill(os.getpid(), signal.SIGTERM)
            return bounded_process.BoundedResult(0)

        with (
            mock.patch.object(
                bounded_process,
                "_stream_stdout",
                side_effect=signal_after_stream,
            ),
            self.assertRaises(SystemExit) as raised,
        ):
            bounded_process.write_stdout(
                self.python("raise SystemExit(0)"),
                output_path=output,
                timeout_seconds=5,
                maximum_bytes=1024,
                stderr=subprocess.DEVNULL,
            )
        self.assertEqual(raised.exception.code, 128 + signal.SIGTERM)
        self.assertEqual(output.read_bytes(), b"original")
        self.assertEqual(
            list(self.root.glob(".signal-before-commit.bin.bounded-*")), []
        )

    def test_symlink_output_is_rejected_without_touching_target(self) -> None:
        target = self.root / "target.bin"
        target.write_bytes(b"protected")
        link = self.root / "output.bin"
        try:
            link.symlink_to(target)
        except OSError as exc:
            self.skipTest(f"platform cannot create symlink: {exc}")
        with self.assertRaises(bounded_process.BoundedProcessError) as raised:
            bounded_process.write_stdout(
                self.python("print('replacement')"),
                output_path=link,
                timeout_seconds=5,
                maximum_bytes=1024,
                stderr=subprocess.DEVNULL,
            )
        self.assertEqual(raised.exception.kind, "output_path")
        self.assertEqual(target.read_bytes(), b"protected")

    def test_stderr_volume_does_not_deadlock_stdout_capture(self) -> None:
        result = bounded_process.capture_stdout(
            self.python(
                "import sys; "
                "sys.stderr.buffer.write(b'e' * 262144); "
                "sys.stdout.buffer.write(b'ok')"
            ),
            timeout_seconds=5,
            maximum_bytes=2,
            stderr=subprocess.DEVNULL,
        )
        self.assertEqual(result, bounded_process.BoundedResult(0, b"ok"))

    def test_run_inherits_stdout_and_propagates_nonzero(self) -> None:
        result = bounded_process.run(
            self.python("raise SystemExit(11)"),
            timeout_seconds=5,
            stderr=subprocess.DEVNULL,
        )
        self.assertEqual(result.returncode, 11)
        self.assertEqual(result.stdout, b"")

    def test_cli_capture_and_write_match_library_contract(self) -> None:
        script = pathlib.Path(bounded_process.__file__).resolve()
        capture = subprocess.run(
            [
                sys.executable,
                str(script),
                "capture",
                "--timeout-seconds",
                "5",
                "--maximum-bytes",
                "4",
                "--",
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(b'data')",
            ],
            check=False,
            capture_output=True,
        )
        self.assertEqual(capture.returncode, 0, capture.stderr.decode())
        self.assertEqual(capture.stdout, b"data")

        output = self.root / "cli-output.bin"
        write = subprocess.run(
            [
                sys.executable,
                str(script),
                "write",
                "--timeout-seconds",
                "5",
                "--maximum-bytes",
                "4",
                "--output",
                str(output),
                "--",
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(b'data')",
            ],
            check=False,
            capture_output=True,
        )
        self.assertEqual(write.returncode, 0, write.stderr.decode())
        self.assertEqual(output.read_bytes(), b"data")

    def test_argument_boundaries_fail_fast(self) -> None:
        invalid_calls = (
            lambda: bounded_process.capture_stdout(
                [], timeout_seconds=1, maximum_bytes=1
            ),
            lambda: bounded_process.capture_stdout(
                ["command"], timeout_seconds=0, maximum_bytes=1
            ),
            lambda: bounded_process.capture_stdout(
                ["command"], timeout_seconds=1, maximum_bytes=0
            ),
            lambda: bounded_process.capture_stdout(
                ["bad\x00command"], timeout_seconds=1, maximum_bytes=1
            ),
            lambda: bounded_process.capture_stdout(
                ["command"],
                timeout_seconds=1,
                maximum_bytes=1,
                stderr=subprocess.PIPE,
            ),
        )
        for call in invalid_calls:
            with self.subTest(call=call):
                with self.assertRaises(bounded_process.BoundedProcessError) as raised:
                    call()
                self.assertEqual(raised.exception.kind, "arguments")


if __name__ == "__main__":
    unittest.main()
