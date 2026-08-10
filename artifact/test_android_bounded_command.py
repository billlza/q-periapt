from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import pathlib
import shlex
import signal
import stat
import tempfile
import unittest
from unittest import mock

import android_bounded_command as commands
from bounded_process import BoundedResult


class AndroidBoundedCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name).resolve()
        self.work = self.root / "work"
        self.proof = self.root / "proof"
        self.work.mkdir(mode=0o700)
        self.proof.mkdir(mode=0o700)
        self.adb = self.root / "adb"
        self.adb.write_bytes(b"fixture adb")
        self.adb.chmod(0o700)
        self.vendor_key = self.root / ".android/adbkey"
        self.vendor_key.parent.mkdir(mode=0o700)
        self.vendor_key.write_bytes(b"fixture key")
        self.vendor_key.chmod(0o600)
        self.apk = self.proof / "qperiapt-android-smoke.apk"
        self.apk.write_bytes(b"signed apk fixture")
        self.apk.chmod(0o600)
        self.state = self.work / commands.CAPABILITY_LEAF
        self.snapshot = self.work / f"{commands.ADB_SNAPSHOT_PREFIX}{'a' * 32}"
        self.constants = (
            mock.patch.object(commands, "WORK_ROOT", self.work),
            mock.patch.object(commands, "PROOF_ROOT", self.proof),
            mock.patch.object(commands, "CAPABILITY_PATH", self.state),
            mock.patch.object(commands, "SIGNED_APK_PATH", self.apk),
            mock.patch.object(commands, "ACCOUNT_HOME", self.root),
            mock.patch.object(
                commands, "ADB_PROFILE_PATHS", {"macos-account": self.adb}
            ),
        )
        for patcher in self.constants:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.environment = {
            "ADB_SERVER_SOCKET": "localfilesystem:/tmp/qperiapt-adb.ABCDEFGH/adb.sock",
            "ADB_VENDOR_KEYS": str(self.vendor_key),
            **commands.EXACT_CLIENT_ENVIRONMENT,
        }
        self.environment_patch = mock.patch.dict(os.environ, self.environment, clear=True)
        self.environment_patch.start()
        self.addCleanup(self.environment_patch.stop)
        self.create_capability()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def capability_values(self, **overrides: object) -> dict[str, object]:
        values: dict[str, object] = {
            "adb_profile": "macos-account",
            "socket_nonce": "ABCDEFGH",
            "device_kind": "physical",
            "expected_serial": "SERIAL123",
            "run_id": "a" * 32,
            "signed_apk_size": self.apk.stat().st_size,
            "signed_apk_sha256": hashlib.sha256(self.apk.read_bytes()).hexdigest(),
        }
        values.update(overrides)
        return values

    def create_capability(self, **overrides: object) -> None:
        values = self.capability_values(**overrides)
        self.remove_capability_files()
        commands.create_capability(**values)  # type: ignore[arg-type]

    def remove_capability_files(self) -> None:
        self.state.unlink(missing_ok=True)
        for snapshot in self.work.glob(f"{commands.ADB_SNAPSHOT_PREFIX}*"):
            snapshot.unlink()

    def test_capability_is_private_exact_and_destroyed_explicitly(self) -> None:
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o600)
        capability = commands.load_capability()
        self.assertEqual(capability.expected_serial, "SERIAL123")
        self.assertEqual(capability.adb_profile, "macos-account")
        self.assertEqual(capability.adb_snapshot_path, self.snapshot)
        self.assertEqual(capability.run_id, "a" * 32)
        snapshot_metadata = self.snapshot.stat()
        self.assertEqual(stat.S_IMODE(snapshot_metadata.st_mode), 0o500)
        self.assertEqual(snapshot_metadata.st_uid, os.geteuid())
        self.assertEqual(snapshot_metadata.st_nlink, 1)
        self.assertEqual(self.snapshot.read_bytes(), self.adb.read_bytes())
        state = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(set(state), commands.CAPABILITY_FIELDS)
        for redundant_path in ("adb_path", "vendor_key", "server_socket"):
            self.assertNotIn(redundant_path, state)
        commands.destroy_capability()
        self.assertFalse(self.state.exists())
        self.assertFalse(self.snapshot.exists())
        with self.assertRaises(commands.AndroidCommandError):
            commands.destroy_capability()

    def test_snapshot_write_failures_are_attributed_and_leave_no_partial_state(self) -> None:
        def fail_write(_descriptor: int, _data: object) -> int:
            raise OSError("injected snapshot write failure")

        def short_write(_descriptor: int, _data: object) -> int:
            return 0

        for writer, message in (
            (fail_write, "cannot write Android adb snapshot"),
            (short_write, "short write while creating Android adb snapshot"),
        ):
            with self.subTest(message=message):
                self.remove_capability_files()
                with (
                    mock.patch.object(commands.os, "write", new=writer),
                    self.assertRaisesRegex(commands.AndroidCommandError, message),
                ):
                    commands.create_capability(  # type: ignore[arg-type]
                        **self.capability_values()
                    )
                self.assertFalse(self.state.exists())
                self.assertFalse(self.snapshot.exists())

    def test_capability_collision_removes_only_the_uncommitted_snapshot(self) -> None:
        self.remove_capability_files()
        self.state.write_bytes(b"existing capability\n")
        self.state.chmod(0o600)
        with self.assertRaises(FileExistsError):
            commands.create_capability(  # type: ignore[arg-type]
                **self.capability_values()
            )
        self.assertEqual(self.state.read_bytes(), b"existing capability\n")
        self.assertFalse(self.snapshot.exists())

    def test_capability_fsync_failure_removes_capability_and_snapshot(self) -> None:
        self.remove_capability_files()
        original_fsync = os.fsync
        calls = 0

        def fail_capability_fsync(descriptor: int) -> None:
            nonlocal calls
            calls += 1
            if calls == 3:
                raise OSError("injected capability fsync failure")
            original_fsync(descriptor)

        with (
            mock.patch.object(commands.os, "fsync", side_effect=fail_capability_fsync),
            self.assertRaisesRegex(OSError, "capability fsync failure"),
        ):
            commands.create_capability(  # type: ignore[arg-type]
                **self.capability_values()
            )
        self.assertGreaterEqual(calls, 4)
        self.assertFalse(self.state.exists())
        self.assertFalse(self.snapshot.exists())

    def test_destroy_is_missing_safe_and_never_removes_another_run(self) -> None:
        commands.destroy_capability(
            expected_run_id="a" * 32,
            missing_ok=True,
        )
        self.assertFalse(self.state.exists())
        self.assertFalse(self.snapshot.exists())
        commands.destroy_capability(
            expected_run_id="a" * 32,
            missing_ok=True,
        )

        self.create_capability(run_id="b" * 32)
        with self.assertRaisesRegex(
            commands.AndroidCommandError,
            "different run",
        ):
            commands.destroy_capability(
                expected_run_id="a" * 32,
                missing_ok=True,
            )
        self.assertTrue(self.state.exists())
        self.assertTrue(
            (self.work / f"{commands.ADB_SNAPSHOT_PREFIX}{'b' * 32}").exists()
        )

    @unittest.skipUnless(os.name == "posix", "dirfd cleanup requires POSIX")
    def test_destroy_remains_bound_to_the_open_work_directory(self) -> None:
        old_work = self.root / "work-owned-by-run-a"
        original_loader = commands.load_json_object_snapshot_at
        root_replaced = False

        def replace_root_after_snapshot(*args: object, **kwargs: object):
            nonlocal root_replaced
            snapshot = original_loader(*args, **kwargs)
            if not root_replaced:
                root_replaced = True
                self.work.rename(old_work)
                self.work.mkdir(mode=0o700)
                self.create_capability(run_id="b" * 32)
            return snapshot

        with mock.patch.object(
            commands,
            "load_json_object_snapshot_at",
            side_effect=replace_root_after_snapshot,
        ):
            commands.destroy_capability(expected_run_id="a" * 32)

        self.assertTrue(root_replaced)
        self.assertFalse((old_work / commands.CAPABILITY_LEAF).exists())
        self.assertFalse(
            (old_work / f"{commands.ADB_SNAPSHOT_PREFIX}{'a' * 32}").exists()
        )
        self.assertTrue(self.state.exists())
        self.assertTrue(
            (self.work / f"{commands.ADB_SNAPSHOT_PREFIX}{'b' * 32}").exists()
        )
        self.assertEqual(commands.load_capability().run_id, "b" * 32)

    def test_capability_rejects_mode_schema_and_extra_fields(self) -> None:
        original = json.loads(self.state.read_text(encoding="utf-8"))
        cases = (
            ("mode", None),
            ("schema", {**original, "schema_version": 1}),
            ("schema-bool", {**original, "schema_version": True}),
            ("schema-float", {**original, "schema_version": 2.0}),
            ("unresolved-profile", {**original, "adb_profile": "auto"}),
            ("extra", {**original, "argv": ["/bin/sh"]}),
        )
        for name, value in cases:
            with self.subTest(case=name):
                self.state.write_text(
                    json.dumps(original if value is None else value) + "\n",
                    encoding="utf-8",
                )
                self.state.chmod(0o644 if name == "mode" else 0o600)
                with self.assertRaises((commands.AndroidCommandError, ValueError)):
                    commands.load_capability()
        self.state.write_text(json.dumps(original) + "\n", encoding="utf-8")
        self.state.chmod(0o600)

    def test_control_signal_after_capability_creation_removes_the_owned_file(self) -> None:
        values = {
            "adb_profile": "macos-account",
            "socket_nonce": "ABCDEFGH",
            "device_kind": "physical",
            "expected_serial": "SERIAL123",
            "run_id": "a" * 32,
            "signed_apk_size": self.apk.stat().st_size,
            "signed_apk_sha256": hashlib.sha256(self.apk.read_bytes()).hexdigest(),
        }
        for control_signal in (signal.SIGHUP, signal.SIGTERM):
            with self.subTest(signal=control_signal):
                self.remove_capability_files()
                original_fsync = os.fsync
                signal_sent = False

                def interrupt_after_write(descriptor: int) -> None:
                    nonlocal signal_sent
                    original_fsync(descriptor)
                    if not signal_sent:
                        signal_sent = True
                        os.kill(os.getpid(), control_signal)

                with mock.patch.object(os, "fsync", side_effect=interrupt_after_write):
                    with self.assertRaises(SystemExit) as raised:
                        commands.create_capability_with_deferred_signals(**values)
                self.assertEqual(raised.exception.code, 128 + control_signal)
                self.assertFalse(self.state.exists())
                self.assertFalse(self.snapshot.exists())

    @unittest.skipUnless(
        hasattr(signal, "pthread_sigmask"),
        "signal handoff requires POSIX signal masks",
    )
    def test_control_signal_during_handler_restore_cannot_be_lost(self) -> None:
        self.remove_capability_files()
        values = {
            "adb_profile": "macos-account",
            "socket_nonce": "ABCDEFGH",
            "device_kind": "physical",
            "expected_serial": "SERIAL123",
            "run_id": "a" * 32,
            "signed_apk_size": self.apk.stat().st_size,
            "signed_apk_sha256": hashlib.sha256(self.apk.read_bytes()).hexdigest(),
        }
        original_signal = signal.signal
        managed_count = len(
            [
                name
                for name in ("SIGHUP", "SIGINT", "SIGTERM")
                if hasattr(signal, name)
            ]
        )
        signal_calls = 0

        def signal_with_restore_interrupt(signum: int, handler: object):
            nonlocal signal_calls
            signal_calls += 1
            if signal_calls == managed_count + 1:
                os.kill(os.getpid(), signal.SIGTERM)
            return original_signal(signum, handler)

        with mock.patch.object(
            signal,
            "signal",
            side_effect=signal_with_restore_interrupt,
        ):
            with self.assertRaises(SystemExit) as raised:
                commands.create_capability_with_deferred_signals(**values)
        self.assertEqual(raised.exception.code, 128 + signal.SIGTERM)
        self.assertFalse(self.state.exists())
        self.assertFalse(self.snapshot.exists())

    @unittest.skipUnless(
        hasattr(signal, "pthread_sigmask"),
        "signal handoff requires POSIX signal masks",
    )
    def test_signal_immediately_before_final_handler_handoff_is_not_lost(self) -> None:
        self.remove_capability_files()
        values = {
            "adb_profile": "macos-account",
            "socket_nonce": "ABCDEFGH",
            "device_kind": "physical",
            "expected_serial": "SERIAL123",
            "run_id": "a" * 32,
            "signed_apk_size": self.apk.stat().st_size,
            "signed_apk_sha256": hashlib.sha256(self.apk.read_bytes()).hexdigest(),
        }
        managed = tuple(
            getattr(signal, name)
            for name in ("SIGHUP", "SIGINT", "SIGTERM")
            if hasattr(signal, name)
        )
        original_handlers = {
            managed_signal: signal.getsignal(managed_signal)
            for managed_signal in managed
        }
        original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        original_signal = signal.signal
        signal_calls = 0

        def signal_at_final_handoff(signum: int, handler: object):
            nonlocal signal_calls
            signal_calls += 1
            if signal_calls == len(managed) * 2:
                os.kill(os.getpid(), signal.SIGTERM)
            return original_signal(signum, handler)

        with (
            mock.patch.object(
                signal,
                "signal",
                side_effect=signal_at_final_handoff,
            ),
            mock.patch.object(
                signal,
                "sigpending",
                side_effect=AssertionError(
                    "a pending-signal snapshot cannot linearize handler handoff"
                ),
            ),
        ):
            with self.assertRaises(SystemExit) as raised:
                commands.create_capability_with_deferred_signals(**values)

        self.assertEqual(raised.exception.code, 128 + signal.SIGTERM)
        self.assertFalse(self.state.exists())
        self.assertFalse(self.snapshot.exists())
        self.assertEqual(
            {
                managed_signal: signal.getsignal(managed_signal)
                for managed_signal in managed
            },
            original_handlers,
        )
        self.assertEqual(
            signal.pthread_sigmask(signal.SIG_BLOCK, set()),
            original_mask,
        )

    @unittest.skipUnless(
        hasattr(signal, "pthread_sigmask"),
        "signal setup cleanup requires POSIX signal masks",
    )
    def test_partial_signal_handler_setup_is_fully_restored(self) -> None:
        self.state.unlink(missing_ok=True)
        managed = tuple(
            getattr(signal, name)
            for name in ("SIGHUP", "SIGINT", "SIGTERM")
            if hasattr(signal, name)
        )
        original_handlers = {
            managed_signal: signal.getsignal(managed_signal)
            for managed_signal in managed
        }
        original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        original_signal = signal.signal
        signal_calls = 0

        def fail_second_install(signum: int, handler: object):
            nonlocal signal_calls
            signal_calls += 1
            if signal_calls == 2:
                raise OSError("injected handler installation failure")
            return original_signal(signum, handler)

        with mock.patch.object(
            signal,
            "signal",
            side_effect=fail_second_install,
        ):
            with self.assertRaisesRegex(OSError, "handler installation failure"):
                commands.create_capability_with_deferred_signals(
                    adb_profile="macos-account",
                    socket_nonce="ABCDEFGH",
                    device_kind="physical",
                    expected_serial="SERIAL123",
                    run_id="a" * 32,
                    signed_apk_size=self.apk.stat().st_size,
                    signed_apk_sha256=hashlib.sha256(
                        self.apk.read_bytes()
                    ).hexdigest(),
                )

        self.assertEqual(
            {
                managed_signal: signal.getsignal(managed_signal)
                for managed_signal in managed
            },
            original_handlers,
        )
        self.assertEqual(
            signal.pthread_sigmask(signal.SIG_BLOCK, set()),
            original_mask,
        )
        self.assertFalse(self.state.exists())

    def test_create_rejects_unsafe_serial_socket_and_run_id(self) -> None:
        invalid = (
            {"adb_profile": "unknown"},
            {"expected_serial": "../../device"},
            {"socket_nonce": "../../bad"},
            {"run_id": "not-a-run-id"},
            {"signed_apk_size": 0},
        )
        for values in invalid:
            with self.subTest(values=values), self.assertRaises(
                commands.AndroidCommandError
            ):
                self.create_capability(**values)
        self.create_capability()

    def test_auto_profile_is_persisted_as_one_fixed_profile(self) -> None:
        self.create_capability(adb_profile="auto")
        state = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(state["adb_profile"], "macos-account")

    def test_dynamic_command_atoms_are_rebuilt_from_code_owned_ascii(self) -> None:
        class InputString(str):
            pass

        raw_serial = InputString("SERIAL123")
        raw_run_id = InputString("a" * 32)
        raw_nonce = InputString("ABCDEFGH")
        serial = commands._canonical_expected_serial(raw_serial, "physical")
        run_id = commands._canonical_run_id(raw_run_id)
        nonce = commands._canonical_socket_nonce(raw_nonce)
        self.assertEqual(serial, raw_serial)
        self.assertEqual(run_id, raw_run_id)
        self.assertEqual(nonce, raw_nonce)
        self.assertIsNot(serial, raw_serial)
        self.assertIsNot(run_id, raw_run_id)
        self.assertIsNot(nonce, raw_nonce)

    def test_tampered_capability_never_reaches_a_process_boundary(self) -> None:
        original = json.loads(self.state.read_text(encoding="utf-8"))
        cases = (
            {**original, "adb_profile": "/bin/sh"},
            {**original, "socket_nonce": "AAAA/../"},
            {**original, "expected_serial": "--one-device"},
            {**original, "run_id": "a" * 31 + ";"},
            {**original, "adb_path": "/bin/sh"},
        )
        for value in cases:
            with self.subTest(value=value):
                self.state.write_text(json.dumps(value) + "\n", encoding="utf-8")
                self.state.chmod(0o600)
                with (
                    mock.patch.object(commands, "run") as run,
                    mock.patch.object(commands, "capture_stdout") as capture,
                    mock.patch.object(commands, "write_stdout_at") as write,
                    self.assertRaises(commands.AndroidCommandError),
                ):
                    commands.invoke_operation(commands.AndroidOperation.KILL_SERVER)
                run.assert_not_called()
                capture.assert_not_called()
                write.assert_not_called()
        self.state.write_text(json.dumps(original) + "\n", encoding="utf-8")
        self.state.chmod(0o600)

    def test_operation_table_has_only_fixed_modes_and_outputs(self) -> None:
        self.assertEqual(set(commands.OPERATION_SPECS), set(commands.AndroidOperation))
        output_pairs: set[tuple[commands.OutputRoot, str]] = set()
        for operation, spec in commands.OPERATION_SPECS.items():
            with self.subTest(operation=operation.value):
                self.assertIn(spec.mode, {"run", "capture", "write", "pull-apk", "logcat"})
                self.assertGreaterEqual(spec.timeout_maximum, spec.timeout_seconds)
                if spec.output is not None:
                    pair = (spec.output.root, spec.output.leaf)
                    self.assertNotIn(pair, output_pairs)
                    output_pairs.add(pair)
                    self.assertNotIn("/", spec.output.leaf)
        source = pathlib.Path(commands.__file__).read_text(encoding="utf-8")
        self.assertNotIn("argparse.REMAINDER", source)
        self.assertNotIn("--output", source)
        self.assertNotIn('"argv"', source)
        self.assertNotIn('create.add_argument("--adb",', source)
        self.assertNotIn('create.add_argument("--vendor-key",', source)
        self.assertNotIn('create.add_argument("--server-socket",', source)
        self.assertIn('"--adb-profile"', source)

    def test_fixed_adb_operations_construct_exact_argv(self) -> None:
        capability = commands.load_capability()
        expected = {
            commands.AndroidOperation.KILL_SERVER: (
                str(self.snapshot),
                "-L",
                self.environment["ADB_SERVER_SOCKET"],
                "kill-server",
            ),
            commands.AndroidOperation.DEVICE_ABI: (
                str(self.snapshot),
                "-L",
                self.environment["ADB_SERVER_SOCKET"],
                "-s",
                "SERIAL123",
                "shell",
                "getprop",
                "ro.product.cpu.abi",
            ),
            commands.AndroidOperation.START_APP: (
                str(self.snapshot),
                "-L",
                self.environment["ADB_SERVER_SOCKET"],
                "-s",
                "SERIAL123",
                "shell",
                "am",
                "start",
                "-W",
                "-n",
                "dev.qperiapt.androidsmoke/.QPeriaptSmokeActivity",
                "--es",
                "qperiapt_run_id",
                "a" * 32,
            ),
        }
        for operation, argv in expected.items():
            with self.subTest(operation=operation.value):
                self.assertEqual(commands.OPERATION_SPECS[operation].build_argv(capability), argv)

    def test_capture_run_and_write_dispatch_preserve_fixed_limits(self) -> None:
        with (
            mock.patch.object(commands, "run", return_value=BoundedResult(0)) as run,
            mock.patch.object(
                commands,
                "capture_stdout",
                return_value=BoundedResult(0, b"device\n"),
            ) as capture,
            mock.patch.object(
                commands,
                "write_stdout_at",
                return_value=BoundedResult(0),
            ) as write,
            mock.patch.object(commands, "_lsof_path", return_value="/usr/sbin/lsof"),
        ):
            capture_result = commands.invoke_operation(commands.AndroidOperation.DEVICE_STATE)
            self.assertEqual(capture_result.stdout, b"device\n")
            capture.assert_called_once()
            commands.invoke_operation(commands.AndroidOperation.FORCE_STOP)
            run.assert_called_once()
            commands.invoke_operation(commands.AndroidOperation.LSOF_INITIAL)
            write.assert_called_once()
            write_arguments = write.call_args.kwargs
            self.assertEqual(write_arguments["output_name"], "adb-listener-initial.txt")
            self.assertEqual(write_arguments["maximum_bytes"], 65536)
            self.assertEqual(write_arguments["timeout_seconds"], 15)

    def test_timeout_cannot_exceed_operation_profile(self) -> None:
        with mock.patch.object(commands, "capture_stdout") as capture:
            with self.assertRaisesRegex(commands.AndroidCommandError, "1 through 15"):
                commands.invoke_operation(
                    commands.AndroidOperation.DEVICE_STATE, timeout_seconds=16
                )
            capture.assert_not_called()

    def test_environment_poisoning_fails_before_process_start(self) -> None:
        with (
            mock.patch.dict(os.environ, {**self.environment, "ADB_TRACE": "all"}, clear=True),
            mock.patch.object(commands, "run") as run,
            self.assertRaisesRegex(commands.AndroidCommandError, "ADB_TRACE"),
        ):
            commands.invoke_operation(commands.AndroidOperation.KILL_SERVER)
        run.assert_not_called()

    def test_dynamic_loader_and_path_environment_never_reaches_tools(self) -> None:
        hostile = {
            **self.environment,
            "PATH": str(self.root),
            "LD_PRELOAD": str(self.root / "inject.so"),
            "DYLD_INSERT_LIBRARIES": str(self.root / "inject.dylib"),
        }
        with (
            mock.patch.dict(os.environ, hostile, clear=True),
            mock.patch.object(
                commands, "run", return_value=BoundedResult(0)
            ) as run,
        ):
            commands.invoke_operation(commands.AndroidOperation.KILL_SERVER)
        child_environment = run.call_args.kwargs["environment"]
        self.assertEqual(child_environment["PATH"], "/usr/bin:/bin:/usr/sbin:/sbin")
        self.assertNotIn("LD_PRELOAD", child_environment)
        self.assertNotIn("DYLD_INSERT_LIBRARIES", child_environment)

    def test_server_exec_uses_only_capability_owned_identity(self) -> None:
        server_environment = {
            **self.environment,
            "ADB_USB": "1",
            "ADB_EMU": "0",
        }
        with (
            mock.patch.dict(os.environ, server_environment, clear=True),
            mock.patch.object(os, "execve", side_effect=RuntimeError("exec boundary")) as execve,
            self.assertRaisesRegex(RuntimeError, "exec boundary"),
        ):
            commands.exec_server()
        argv = execve.call_args.args[1]
        child_environment = execve.call_args.args[2]
        self.assertEqual(
            argv,
            [
                str(self.snapshot),
                "-L",
                self.environment["ADB_SERVER_SOCKET"],
                "--one-device",
                "SERIAL123",
                "server",
                "nodaemon",
            ],
        )
        self.assertEqual(child_environment["HOME"], str(self.root))
        self.assertNotIn("LD_PRELOAD", child_environment)

    def test_sdk_directory_replacement_executes_only_the_run_snapshot(self) -> None:
        sdk = self.root / "sdk"
        source_adb = sdk / "platform-tools/adb"
        source_adb.parent.mkdir(parents=True, mode=0o700)
        original_marker = self.root / "original-adb-ran"
        replacement_marker = self.root / "replacement-adb-ran"
        source_adb.write_text(
            "#!/bin/sh\n"
            f"printf original > {shlex.quote(str(original_marker))}\n",
            encoding="utf-8",
        )
        source_adb.chmod(0o700)
        with mock.patch.object(
            commands,
            "ADB_PROFILE_PATHS",
            {"macos-account": source_adb},
        ):
            self.create_capability()
            sdk.rename(self.root / "sdk-owned-by-source")
            source_adb.parent.mkdir(parents=True, mode=0o700)
            source_adb.write_text(
                "#!/bin/sh\n"
                f"printf replacement > {shlex.quote(str(replacement_marker))}\n",
                encoding="utf-8",
            )
            source_adb.chmod(0o700)
            result = commands.invoke_operation(commands.AndroidOperation.KILL_SERVER)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(original_marker.read_text(encoding="ascii"), "original")
        self.assertFalse(replacement_marker.exists())

    def test_changed_adb_snapshot_is_rejected_before_operation_start(self) -> None:
        self.snapshot.chmod(0o700)
        self.snapshot.write_bytes(b"replaced snapshot")
        self.snapshot.chmod(0o500)
        with (
            mock.patch.object(commands, "run") as run,
            self.assertRaisesRegex(commands.AndroidCommandError, "snapshot changed"),
        ):
            commands.invoke_operation(commands.AndroidOperation.KILL_SERVER)
        run.assert_not_called()

    def test_snapshot_mode_link_and_symlink_replacements_are_rejected(self) -> None:
        cases = ("mode", "hardlink", "symlink")
        for case in cases:
            with self.subTest(case=case):
                self.create_capability()
                if case == "mode":
                    self.snapshot.chmod(0o700)
                elif case == "hardlink":
                    os.link(self.snapshot, self.work / "snapshot-link")
                else:
                    replacement = self.work / "snapshot-replacement"
                    replacement.write_bytes(self.snapshot.read_bytes())
                    replacement.chmod(0o500)
                    self.snapshot.unlink()
                    self.snapshot.symlink_to(replacement)
                with (
                    mock.patch.object(commands, "run") as run,
                    self.assertRaises(commands.EvidenceIOError),
                ):
                    commands.invoke_operation(commands.AndroidOperation.KILL_SERVER)
                run.assert_not_called()
                (self.work / "snapshot-link").unlink(missing_ok=True)
                (self.work / "snapshot-replacement").unlink(missing_ok=True)

    def test_capability_adb_path_action_returns_only_the_validated_snapshot(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(commands.main(["capability-adb-path"]), 0)
        self.assertEqual(output.getvalue().strip(), str(self.snapshot))

    def test_remote_apk_path_is_validated_before_it_enters_argv(self) -> None:
        package_path = self.proof / "adb-package-path.txt"
        package_path.write_text("package:/data/app/run/base.apk\n", encoding="utf-8")
        package_path.chmod(0o600)

        def write_fixture(argv: tuple[str, ...], **arguments: object) -> BoundedResult:
            output_name = arguments["output_name"]
            self.assertEqual(output_name, "installed-smoke-base.apk")
            output = self.work / str(output_name)
            output.write_bytes(self.apk.read_bytes())
            output.chmod(0o600)
            self.assertEqual(
                argv[-3:], ("exec-out", "cat", "/data/app/run/base.apk")
            )
            return BoundedResult(0)

        with mock.patch.object(commands, "write_stdout_at", side_effect=write_fixture):
            commands.invoke_operation(commands.AndroidOperation.PULL_INSTALLED_APK)

        for hostile in (
            "package:--help\n",
            "package:/data/app/../other/base.apk\n",
            "package:/data/app/run/base.apk\npackage:/data/app/other/base.apk\n",
            "package:/data/app/run/base.apk;sh\n",
        ):
            package_path.write_text(hostile, encoding="utf-8")
            package_path.chmod(0o600)
            with (
                mock.patch.object(commands, "write_stdout_at") as write,
                self.assertRaises(commands.AndroidCommandError),
            ):
                commands.invoke_operation(commands.AndroidOperation.PULL_INSTALLED_APK)
            write.assert_not_called()

    def test_logcat_epoch_is_validated_before_it_enters_argv(self) -> None:
        epoch_path = self.proof / "adb-device-time.txt"
        epoch_path.write_text("1786240000.123\n", encoding="ascii")
        epoch_path.chmod(0o600)
        with mock.patch.object(
            commands, "write_stdout_at", return_value=BoundedResult(0)
        ) as write:
            commands.invoke_operation(commands.AndroidOperation.CAPTURE_LOGCAT)
        argv = write.call_args.args[0]
        self.assertIn("1786240000.123", argv)

        epoch_path.write_text("1786240000.123 --help\n", encoding="ascii")
        epoch_path.chmod(0o600)
        with (
            mock.patch.object(commands, "write_stdout_at") as write,
            self.assertRaises(commands.AndroidCommandError),
        ):
            commands.invoke_operation(commands.AndroidOperation.CAPTURE_LOGCAT)
        write.assert_not_called()

    def test_parser_rejects_unknown_operation_and_extra_arguments(self) -> None:
        diagnostics = io.StringIO()
        with contextlib.redirect_stderr(diagnostics), self.assertRaises(
            SystemExit
        ) as unknown:
            commands.main(["invoke", "shell"])
        self.assertEqual(unknown.exception.code, 2)
        with contextlib.redirect_stderr(diagnostics), self.assertRaises(
            SystemExit
        ) as extra:
            commands.main(["invoke", "device-state", "--", "/bin/sh"])
        self.assertEqual(extra.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
