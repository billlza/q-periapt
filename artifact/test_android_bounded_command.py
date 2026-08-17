from __future__ import annotations

import contextlib
import errno
import hashlib
import io
import json
import os
import pathlib
import shlex
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

import android_bounded_command as commands
import android_emulator_control as emulator_control
import android_runtime_state as state
import process_identity
from android_emulator_control import (
    OwnedUnixListenerDescriptor,
    OwnedUnixListenerDialect,
    OwnedUnixListenerObservation,
)
from bounded_process import BoundedResult
from process_identity import ProcessExecutionSnapshot
from process_identity import parse_token as parse_process_identity_token


class AndroidBoundedCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name).resolve()
        self.target = self.root / "target"
        self.target.mkdir(mode=0o700)
        self.runs = self.target / state.RUNS_ROOT_LEAF
        self.run_id = "a" * 32
        self.adb = self.root / "adb"
        self.adb.write_bytes(b"fixture adb")
        self.adb.chmod(0o700)
        self.vendor_key = self.root / ".android/adbkey"
        self.vendor_key.parent.mkdir(mode=0o700)
        self.vendor_key.write_bytes(b"fixture key")
        self.vendor_key.chmod(0o600)
        self.console_token = self.root / ".emulator_console_auth_token"
        self.console_token.write_bytes(b"private-token\n")
        self.console_token.chmod(0o600)
        self.private_adb_directory = self.root / "qperiapt-adb.ABCDEFGH"
        self.private_adb_directory.mkdir(mode=0o700)
        self.private_adb_socket = self.private_adb_directory / "adb.sock"
        if sys.platform == "darwin":
            self.account_state_parent = self.root / "Library" / "Application Support"
        else:
            self.account_state_parent = self.root / ".local" / "state"
        self.account_state_parent.mkdir(parents=True, mode=0o700)
        self.constants = (
            mock.patch.object(state, "REPOSITORY_ROOT", self.root),
            mock.patch.object(state, "TARGET_ROOT", self.target),
            mock.patch.object(state, "RUNS_ROOT", self.runs),
            mock.patch.object(state, "ACCOUNT_HOME", self.root),
            mock.patch.object(state, "ADB_PROFILE_PATHS", {"macos-account": self.adb}),
            mock.patch.object(
                state,
                "_server_socket_identity",
                lambda nonce: (
                    f"localfilesystem:{self.root}/qperiapt-adb.{nonce}/adb.sock",
                    f"{self.root}/qperiapt-adb.{nonce}/adb.sock",
                ),
            ),
        )
        for patcher in self.constants:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.layout = state.create_run_layout(self.run_id)
        self.work = self.layout.work
        self.proof = self.layout.proof
        self.apk = self.layout.signed_apk
        self.apk.write_bytes(b"signed apk fixture")
        self.apk.chmod(0o600)
        self.state = self.layout.capability
        self.snapshot = self.work / f"{state.ADB_SNAPSHOT_PREFIX}{self.run_id}"
        self.environment = {
            "ADB_SERVER_SOCKET": f"localfilesystem:{self.private_adb_socket}",
            "ADB_VENDOR_KEYS": str(self.vendor_key),
            **commands.EXACT_CLIENT_ENVIRONMENT,
        }
        self.environment_patch = mock.patch.dict(
            os.environ, self.environment, clear=True
        )
        self.environment_patch.start()
        self.addCleanup(self.environment_patch.stop)
        self.create_capability()
        state.ensure_account_state()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_shared_adb_profile_policy_rejects_non_text_and_unknown_values(
        self,
    ) -> None:
        for value in ([], True, "unknown"):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(
                    emulator_control.AndroidEmulatorControlError,
                    "owned adb profile is unsupported",
                ),
            ):
                emulator_control.canonical_owned_adb_profile(value)

    def test_listener_parser_rejects_out_of_range_bound_descriptor(self) -> None:
        with self.assertRaisesRegex(
            emulator_control.AndroidEmulatorControlError,
            "bound descriptor is invalid",
        ):
            emulator_control.parse_owned_single_listener(
                "p123\nu501\nf7\n/tmp/qperiapt-adb.ABCDEFGH/adb.sock\n",
                expected_pid=123,
                expected_uid=501,
                expected_endpoint="/tmp/qperiapt-adb.ABCDEFGH/adb.sock",
                dialect=emulator_control.OwnedUnixListenerDialect.DARWIN,
                expected_listener_descriptor=(
                    emulator_control.MAX_OWNED_LISTENER_DESCRIPTOR + 1
                ),
            )

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
        if not self.private_adb_directory.exists():
            self.private_adb_directory.mkdir(mode=0o700)
        else:
            self.private_adb_directory.chmod(0o700)
        values = self.capability_values(**overrides)
        run_id = str(values["run_id"])
        layout = state.AndroidRunLayout.from_run_id(run_id)
        if not layout.root.exists():
            state.create_run_layout(run_id)
            layout.signed_apk.write_bytes(self.apk.read_bytes())
            layout.signed_apk.chmod(0o600)
        self.layout = layout
        self.work = layout.work
        self.proof = layout.proof
        self.apk = layout.signed_apk
        self.state = layout.capability
        self.snapshot = layout.work / f"{state.ADB_SNAPSHOT_PREFIX}{run_id}"
        self.remove_capability_files()
        if "signed_apk_size" not in overrides:
            values["signed_apk_size"] = self.apk.stat().st_size
        if "signed_apk_sha256" not in overrides:
            values["signed_apk_sha256"] = hashlib.sha256(
                self.apk.read_bytes()
            ).hexdigest()
        state.create_capability(**values)  # type: ignore[arg-type]

    def create_avd_fixture(self, name: str = "QPeriapt_Release_16K_API_35_V1") -> pathlib.Path:
        home = state.avd_home_directory()
        home.mkdir(mode=0o700, exist_ok=False)
        directory = home / f"{name}.avd"
        directory.mkdir(mode=0o700)
        config = directory / "config.ini"
        config.write_text("hw.cpu.arch=arm64\n", encoding="utf-8")
        config.chmod(0o600)
        ini = home / f"{name}.ini"
        ini.write_text(f"path={directory}\ntarget=android-35\n", encoding="utf-8")
        ini.chmod(0o600)
        return directory

    def remove_capability_files(self) -> None:
        self.state.unlink(missing_ok=True)
        for snapshot in self.work.glob(f"{state.ADB_SNAPSHOT_PREFIX}*"):
            snapshot.unlink()

    def create_active_emulator_runtime_receipt(
        self, **overrides: object
    ) -> state.OwnedRuntimeReceipt:
        self.create_capability(
            device_kind="emulator",
            expected_serial="emulator-5584",
        )
        launcher = self.root / "emulator"
        backend = self.root / "qemu-system-aarch64-headless"
        for executable in (launcher, backend):
            executable.write_bytes(b"fixture executable")
            executable.chmod(0o700)
        identity = commands.ProcessIdentity(
            pid=os.getpid(),
            uid=os.geteuid(),
            started_at=123456,
            started_subsecond=789,
            executable=pathlib.Path(sys.executable).resolve(),
        )
        state._write_owned_runtime_receipt(
            state._runtime_recovery_payload(self.load_capability())
        )
        pending = state.load_owned_runtime_receipt()
        self.assertIsNotNone(pending)
        server_identity = commands.ProcessIdentity(
            pid=os.getpid(),
            uid=os.geteuid(),
            started_at=123455,
            started_subsecond=788,
            executable=pathlib.Path(sys.executable).resolve(),
        )
        executable_metadata = server_identity.executable.stat()
        snapshot_metadata = self.snapshot.stat()
        with mock.patch.object(state, "validate_lane_lock_descriptor"):
            runtime_receipt = state.register_adb_child(
                pending,  # type: ignore[arg-type]
                state.AdbChildRegistration(
                    process=server_identity,
                    initial_executable_device=executable_metadata.st_dev,
                    initial_executable_inode=executable_metadata.st_ino,
                    adb_snapshot_device=snapshot_metadata.st_dev,
                    adb_snapshot_inode=snapshot_metadata.st_ino,
                ),
            )
        self.private_adb_directory.chmod(0o500)
        with mock.patch.object(state, "validate_lane_lock_descriptor"):
            sealing = state.begin_adb_seal(runtime_receipt, 7)
            runtime_receipt = state.complete_adb_seal(sealing)
            launcher_metadata = launcher.stat()
            backend_metadata = backend.stat()
            runtime_receipt = state.register_emulator_child(
                receipt=runtime_receipt,
                registration=state.EmulatorChildRegistration(
                    process=identity,
                    avd_name="QPeriapt_Release_16K_API_35_V1",
                    device_abi="arm64-v8a",
                    console_port=5584,
                    native_adb_notifier_port=state.NATIVE_ADB_NOTIFIER_PORT,
                    console_auth_token=state.ConsoleAuthTokenIdentity(
                        device=self.console_token.stat().st_dev,
                        inode=self.console_token.stat().st_ino,
                        sha256=hashlib.sha256(
                            self.console_token.read_bytes()
                        ).hexdigest(),
                    ),
                    launcher_path=launcher,
                    launcher_device=launcher_metadata.st_dev,
                    launcher_inode=launcher_metadata.st_ino,
                    backend_path=backend,
                    backend_device=backend_metadata.st_dev,
                    backend_inode=backend_metadata.st_ino,
                    backend_sha256=hashlib.sha256(backend.read_bytes()).hexdigest(),
                ),
            )
        payload = state._runtime_receipt_payload(runtime_receipt)
        payload.update(overrides)
        if (
            any(
                field in overrides
                for field in ("pid", "uid", "started_at", "started_subsecond")
            )
            and "process_identity" not in overrides
        ):
            payload["process_identity"] = (
                f"{payload['pid']}:{payload['uid']}:"
                f"{payload['started_at']}:{payload['started_subsecond']}"
            )
        if overrides:
            state._replace_owned_runtime_receipt(runtime_receipt, payload)
        receipt = state.load_owned_runtime_receipt()
        self.assertIsNotNone(receipt)
        return receipt  # type: ignore[return-value]

    def test_run_layout_is_fixed_private_and_append_only(self) -> None:
        self.assertEqual(self.layout.root, self.runs / self.run_id)
        self.assertEqual(self.layout.work, self.layout.root / "work")
        self.assertEqual(self.layout.proof, self.layout.root / "proof")
        self.assertEqual(
            self.layout.capability, self.layout.work / state.CAPABILITY_LEAF
        )
        self.assertEqual(
            self.layout.signed_apk, self.layout.proof / state.SIGNED_APK_LEAF
        )
        for path in (self.runs, self.layout.root, self.layout.work, self.layout.proof):
            metadata = path.lstat()
            self.assertTrue(stat.S_ISDIR(metadata.st_mode))
            self.assertEqual(metadata.st_uid, os.geteuid())
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o700)

        marker = self.layout.root / "marker"
        marker.write_bytes(b"selected evidence stays untouched")
        identity = (self.layout.root.stat().st_dev, self.layout.root.stat().st_ino)
        with self.assertRaisesRegex(
            (commands.AndroidCommandError, state.AndroidRuntimeStateError),
            "already exists",
        ):
            state.create_run_layout(self.run_id)
        self.assertEqual(marker.read_bytes(), b"selected evidence stays untouched")
        self.assertEqual(
            (self.layout.root.stat().st_dev, self.layout.root.stat().st_ino), identity
        )

    def test_run_layout_rejects_noncanonical_run_ids_and_collisions(self) -> None:
        invalid = (
            "",
            "a" * 31,
            "a" * 33,
            "A" * 32,
            "../" + "a" * 29,
            "g" * 32,
            "\0" + "a" * 31,
            "é" * 32,
        )
        for value in invalid:
            with (
                self.subTest(value=value),
                self.assertRaises(
                    (commands.AndroidCommandError, state.AndroidRuntimeStateError)
                ),
            ):
                state.AndroidRunLayout.from_run_id(value)

        for kind in ("file", "symlink"):
            run_id = ("b" if kind == "file" else "c") * 32
            occupied = self.runs / run_id
            if kind == "file":
                occupied.write_bytes(b"occupied")
            else:
                occupied.symlink_to(self.layout.root)
            with (
                self.subTest(kind=kind),
                self.assertRaisesRegex(
                    (commands.AndroidCommandError, state.AndroidRuntimeStateError),
                    "already exists",
                ),
            ):
                state.create_run_layout(run_id)
            self.assertTrue(os.path.lexists(occupied))

    def test_every_stateful_cli_requires_a_run_id(self) -> None:
        for arguments in (
            ["create-run"],
            ["create-capability"],
            ["invoke", "device-state"],
            [
                "capture-emulator-listeners",
                "--timeout-seconds",
                "1",
            ],
            ["capability-adb-path"],
            ["server-nodaemon"],
            [
                "wait-owned-adb-server-start",
                "--timeout-seconds",
                "1",
            ],
            [
                "wait-owned-emulator-backend",
                "--timeout-seconds",
                "1",
            ],
            ["destroy-capability"],
            ["retire-failed-runtime", "--primary-exit-status", "1"],
        ):
            with (
                self.subTest(arguments=arguments),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as raised,
            ):
                commands.main(arguments)
            self.assertEqual(raised.exception.code, 2)

    def test_receipt_owned_cli_rejects_legacy_pid_inputs(self) -> None:
        for arguments in (
            [
                "capture-emulator-listeners",
                "--run-id",
                self.run_id,
                "--emulator-pid",
                "123",
                "--timeout-seconds",
                "1",
            ],
            [
                "wait-owned-adb-server-start",
                "--run-id",
                self.run_id,
                "--expected-pid",
                "123",
                "--timeout-seconds",
                "1",
            ],
        ):
            with (
                self.subTest(arguments=arguments),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as raised,
            ):
                commands.main(arguments)
            self.assertEqual(raised.exception.code, 2)

    def test_receipt_owned_entrypoints_reject_run_id_before_os_inspection(
        self,
    ) -> None:
        entrypoints = (
            lambda: commands.capture_owned_emulator_listeners(
                run_id="../" + ("a" * 29), timeout_seconds=1
            ),
            lambda: commands.wait_owned_adb_server_start(
                run_id="/" + ("a" * 31), timeout_seconds=1
            ),
            lambda: commands.wait_owned_emulator_backend(
                run_id=("A" * 32), timeout_seconds=1
            ),
        )
        for entrypoint in entrypoints:
            with (
                self.subTest(entrypoint=entrypoint),
                mock.patch.object(state, "validate_lane_lock_descriptor"),
                mock.patch.object(state, "load_owned_runtime_receipt") as load,
                mock.patch.object(commands, "process_snapshot") as inspect,
                mock.patch.object(commands, "write_stdout_at") as write,
                self.assertRaises(
                    (commands.AndroidCommandError, state.AndroidRuntimeStateError)
                ),
            ):
                entrypoint()
            load.assert_not_called()
            inspect.assert_not_called()
            write.assert_not_called()

    def load_capability(self) -> state.AndroidCommandCapability:
        return state.load_capability(self.layout.run_id)

    def invoke(
        self,
        operation: commands.AndroidOperation,
        *,
        timeout_seconds: int | None = None,
    ) -> BoundedResult:
        with mock.patch.object(commands, "_validate_owned_adb_server_for_client"):
            return commands.invoke_operation(
                operation,
                run_id=self.layout.run_id,
                timeout_seconds=timeout_seconds,
            )

    def test_client_refuses_to_autostart_after_owned_server_exit(self) -> None:
        receipt, _observed = self.start_physical_adb_server_receipt()
        receipt = self.seal_test_runtime_receipt(receipt)
        self.assertTrue(receipt.adb_server_started)
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands, "_same_receipt_adb_server_process", return_value=None
            ),
            mock.patch.object(
                commands,
                "_fixed_emulator_paths",
                return_value=(receipt.launcher_path, receipt.backend_path),
            ),
            mock.patch.object(commands, "run") as bounded_run,
            mock.patch.object(commands, "capture_stdout") as capture,
            self.assertRaisesRegex(
                (commands.AndroidCommandError, state.AndroidRuntimeStateError),
                "exited before client",
            ),
        ):
            commands.invoke_operation(
                commands.AndroidOperation.DEVICE_STATE,
                run_id=self.run_id,
            )
        bounded_run.assert_not_called()
        capture.assert_not_called()

    def test_capability_is_private_exact_and_destroyed_explicitly(self) -> None:
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o600)
        capability = self.load_capability()
        self.assertEqual(capability.expected_serial, "SERIAL123")
        self.assertEqual(capability.adb_profile, "macos-account")
        self.assertEqual(capability.adb_snapshot_path, self.snapshot)
        self.assertEqual(capability.run_id, "a" * 32)
        snapshot_metadata = self.snapshot.stat()
        self.assertEqual(stat.S_IMODE(snapshot_metadata.st_mode), 0o500)
        self.assertEqual(snapshot_metadata.st_uid, os.geteuid())
        self.assertEqual(snapshot_metadata.st_nlink, 1)
        self.assertEqual(self.snapshot.read_bytes(), self.adb.read_bytes())
        capability_json = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(set(capability_json), state.CAPABILITY_FIELDS)
        for redundant_path in ("adb_path", "vendor_key", "server_socket"):
            self.assertNotIn(redundant_path, capability_json)
        state.destroy_capability(run_id=self.layout.run_id)
        self.assertFalse(self.state.exists())
        self.assertFalse(self.snapshot.exists())
        with self.assertRaises(
            (commands.AndroidCommandError, state.AndroidRuntimeStateError)
        ):
            state.destroy_capability(run_id=self.layout.run_id)

    def test_snapshot_write_failures_are_attributed_and_leave_no_partial_state(
        self,
    ) -> None:
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
                    self.assertRaisesRegex(
                        (commands.AndroidCommandError, state.AndroidRuntimeStateError),
                        message,
                    ),
                ):
                    state.create_capability(  # type: ignore[arg-type]
                        **self.capability_values()
                    )
                self.assertFalse(self.state.exists())
                self.assertFalse(self.snapshot.exists())

    def test_capability_collision_removes_only_the_uncommitted_snapshot(self) -> None:
        self.remove_capability_files()
        self.state.write_bytes(b"existing capability\n")
        self.state.chmod(0o600)
        with self.assertRaises(FileExistsError):
            state.create_capability(  # type: ignore[arg-type]
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
            state.create_capability(  # type: ignore[arg-type]
                **self.capability_values()
            )
        self.assertGreaterEqual(calls, 4)
        self.assertFalse(self.state.exists())
        self.assertFalse(self.snapshot.exists())

    def test_destroy_is_missing_safe_and_never_removes_another_run(self) -> None:
        state.destroy_capability(
            run_id="a" * 32,
            missing_ok=True,
        )
        self.assertFalse(self.state.exists())
        self.assertFalse(self.snapshot.exists())
        state.destroy_capability(
            run_id="a" * 32,
            missing_ok=True,
        )

        self.create_capability(run_id="b" * 32)
        state.destroy_capability(
            run_id="a" * 32,
            missing_ok=True,
        )
        self.assertTrue(self.state.exists())
        self.assertTrue((self.work / f"{state.ADB_SNAPSHOT_PREFIX}{'b' * 32}").exists())

    @unittest.skipUnless(os.name == "posix", "dirfd cleanup requires POSIX")
    def test_destroy_remains_bound_to_the_open_work_directory(self) -> None:
        old_work = self.root / "work-owned-by-run-a"
        original_loader = state.load_json_object_snapshot_at
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
            state,
            "load_json_object_snapshot_at",
            side_effect=replace_root_after_snapshot,
        ):
            state.destroy_capability(run_id="a" * 32)

        self.assertTrue(root_replaced)
        self.assertFalse((old_work / state.CAPABILITY_LEAF).exists())
        self.assertFalse((old_work / f"{state.ADB_SNAPSHOT_PREFIX}{'a' * 32}").exists())
        self.assertTrue(self.state.exists())
        self.assertTrue((self.work / f"{state.ADB_SNAPSHOT_PREFIX}{'b' * 32}").exists())
        self.assertEqual(state.load_capability("b" * 32).run_id, "b" * 32)

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
                with self.assertRaises(
                    (
                        commands.AndroidCommandError,
                        state.AndroidRuntimeStateError,
                        ValueError,
                    )
                ):
                    self.load_capability()
        self.state.write_text(json.dumps(original) + "\n", encoding="utf-8")
        self.state.chmod(0o600)

    def test_control_signal_after_capability_creation_removes_the_owned_file(
        self,
    ) -> None:
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
            [name for name in ("SIGHUP", "SIGINT", "SIGTERM") if hasattr(signal, name)]
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
                    signed_apk_sha256=hashlib.sha256(self.apk.read_bytes()).hexdigest(),
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
            with (
                self.subTest(values=values),
                self.assertRaises(
                    (commands.AndroidCommandError, state.AndroidRuntimeStateError)
                ),
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
        serial = state.canonical_expected_serial(raw_serial, "physical")
        run_id = state.canonical_run_id(raw_run_id)
        nonce = state.canonical_socket_nonce(raw_nonce)
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
                    self.assertRaises(
                        (commands.AndroidCommandError, state.AndroidRuntimeStateError)
                    ),
                ):
                    self.invoke(commands.AndroidOperation.DEVICE_STATE)
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
                self.assertIn(
                    spec.mode,
                    {
                        "run",
                        "capture",
                        "write",
                        "package-state",
                        "recover-emulator",
                        "observe-apk",
                        "logcat",
                        "register-emulator",
                    },
                )
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
        capability = self.load_capability()
        expected = {
            commands.AndroidOperation.DEVICE_STATE: (
                str(self.snapshot),
                "-L",
                self.environment["ADB_SERVER_SOCKET"],
                "-s",
                "SERIAL123",
                "get-state",
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
                self.assertEqual(
                    commands.OPERATION_SPECS[operation].build_argv(capability), argv
                )

        self.create_capability(
            device_kind="emulator",
            expected_serial="emulator-5584",
        )
        emulator_capability = self.load_capability()
        self.assertEqual(
            commands.OPERATION_SPECS[
                commands.AndroidOperation.REGISTER_EMULATOR
            ].build_argv(emulator_capability),
            (
                str(self.snapshot),
                "-L",
                self.environment["ADB_SERVER_SOCKET"],
                "connect",
                "emu:5584,5585",
            ),
        )

    def test_emulator_registration_is_narrow_and_requires_exact_success(self) -> None:
        self.create_capability(
            device_kind="emulator",
            expected_serial="emulator-5584",
        )
        accepted = (
            b"Connected to emulator on ports 5584,5585\n",
            b"Emulator already registered on port 5585\n",
        )
        for response in accepted:
            with (
                self.subTest(response=response),
                mock.patch.object(
                    commands,
                    "capture_stdout",
                    return_value=BoundedResult(0, response),
                ) as capture,
            ):
                result = self.invoke(commands.AndroidOperation.REGISTER_EMULATOR)
                self.assertEqual(result.stdout, response)
                self.assertEqual(capture.call_args.kwargs["maximum_bytes"], 512)
                self.assertEqual(capture.call_args.kwargs["timeout_seconds"], 10)
                self.assertEqual(
                    capture.call_args.kwargs["stderr"], __import__("subprocess").STDOUT
                )
                self.assertEqual(
                    capture.call_args.kwargs["environment"]["ADB_EMU"], "0"
                )

        rejected = (
            BoundedResult(1, b"Connected to emulator on ports 5584,5585\n"),
            BoundedResult(0, b"Could not connect to emulator on ports 5584,5585\n"),
            BoundedResult(0, b"Connected to emulator on ports 5584,5585\nextra\n"),
            BoundedResult(0, b"warning\nConnected to emulator on ports 5584,5585\n"),
            BoundedResult(0, b"Connected to emulator on ports 5584,5585\r\n"),
            BoundedResult(0, b"Connected to emulator on ports 5584,5585"),
            BoundedResult(0, b"\xff\n"),
        )
        for result in rejected:
            with (
                self.subTest(result=result),
                mock.patch.object(
                    commands,
                    "capture_stdout",
                    return_value=result,
                ),
                self.assertRaises(
                    (commands.AndroidCommandError, state.AndroidRuntimeStateError)
                ) as raised,
            ):
                self.invoke(commands.AndroidOperation.REGISTER_EMULATOR)
            self.assertIn(f"response_hex={result.stdout.hex()}", str(raised.exception))
            self.assertNotIn("\x1b", str(raised.exception))

        self.create_capability()
        with (
            mock.patch.object(commands, "capture_stdout") as capture,
            self.assertRaisesRegex(
                commands.AndroidCommandError,
                "requires an emulator capability",
            ),
        ):
            self.invoke(commands.AndroidOperation.REGISTER_EMULATOR)
        capture.assert_not_called()

    def test_emulator_server_disables_automatic_scanning(self) -> None:
        self.create_capability(
            device_kind="emulator",
            expected_serial="emulator-5584",
        )
        server_environment = {
            **self.environment,
            "ADB_USB": "0",
            "ADB_EMU": "0",
        }
        state._write_owned_runtime_receipt(
            state._runtime_recovery_payload(self.load_capability())
        )
        with (
            mock.patch.dict(os.environ, server_environment, clear=True),
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(state, "_arm_lane_lock_close_on_exec") as close_lock,
            mock.patch.object(commands, "_close_nonstandard_descriptors"),
            mock.patch.object(
                os, "execve", side_effect=RuntimeError("exec boundary")
            ) as execve,
            self.assertRaisesRegex(RuntimeError, "exec boundary"),
        ):
            commands.exec_server(self.layout.run_id)
        close_lock.assert_called_once_with()
        child_environment = execve.call_args.args[2]
        self.assertEqual(child_environment["ADB_USB"], "0")
        self.assertEqual(child_environment["ADB_EMU"], "0")

    def test_owned_emulator_listener_capture_is_run_bound_and_bounded(self) -> None:
        receipt = self.create_active_emulator_runtime_receipt()
        capability = self.load_capability()
        context = commands.RecoveryContext(
            layout=self.layout,
            capability=capability,
            launcher=receipt.launcher_path,
            backend=receipt.backend_path,
            current_boot=True,
        )
        identity = commands.ProcessIdentity(
            pid=receipt.pid,  # type: ignore[arg-type]
            uid=receipt.uid,
            started_at=receipt.started_at,  # type: ignore[arg-type]
            started_subsecond=receipt.started_subsecond,  # type: ignore[arg-type]
            executable=receipt.backend_path,  # type: ignore[arg-type]
        )

        def write_fixture(argv: tuple[str, ...], **arguments: object) -> BoundedResult:
            self.assertEqual(
                argv,
                (
                    "/usr/sbin/lsof",
                    "-nP",
                    "-a",
                    "-p",
                    str(receipt.pid),
                    "-iTCP:5584",
                    "-iTCP:5585",
                    "-sTCP:LISTEN",
                    "-Fpufn",
                ),
            )
            self.assertEqual(arguments["output_name"], "emulator-listeners.txt.pending")
            self.assertEqual(arguments["timeout_seconds"], 3)
            self.assertEqual(arguments["maximum_bytes"], 65_536)
            output = self.work / "emulator-listeners.txt.pending"
            output.write_text(
                f"p{receipt.pid}\nu{os.geteuid()}\nf18\n"
                "n127.0.0.1:5584\nf19\nn127.0.0.1:5585\n",
                encoding="ascii",
            )
            output.chmod(0o600)
            return BoundedResult(0)

        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands, "_validate_recovery_receipt", return_value=context
            ),
            mock.patch.object(
                commands,
                "_same_receipt_process",
                side_effect=[identity, identity, identity],
            ),
            mock.patch.object(commands, "_lsof_path", return_value="/usr/sbin/lsof"),
            mock.patch.object(
                commands, "write_stdout_at", side_effect=write_fixture
            ) as write,
        ):
            result = commands.capture_owned_emulator_listeners(
                run_id=self.layout.run_id,
                timeout_seconds=3,
            )
        self.assertEqual(result, identity.token)
        write.assert_called_once()

        for timeout in (0, 6):
            with (
                self.subTest(timeout=timeout),
                mock.patch.object(state, "validate_lane_lock_descriptor"),
                mock.patch.object(
                    commands, "_validate_recovery_receipt", return_value=context
                ),
                mock.patch.object(
                    commands, "_same_receipt_process", return_value=identity
                ),
                mock.patch.object(commands, "write_stdout_at") as write,
                self.assertRaises(
                    (commands.AndroidCommandError, state.AndroidRuntimeStateError)
                ),
            ):
                commands.capture_owned_emulator_listeners(
                    run_id=self.layout.run_id,
                    timeout_seconds=timeout,
                )
            write.assert_not_called()

        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                state, "load_owned_runtime_receipt", return_value=None
            ),
            mock.patch.object(commands, "write_stdout_at") as write,
            self.assertRaisesRegex(
                commands.AndroidCommandError, "lacks this run's registered child"
            ),
        ):
            commands.capture_owned_emulator_listeners(
                run_id=self.layout.run_id,
                timeout_seconds=1,
            )
        write.assert_not_called()

    def test_recovery_listener_parser_binds_receipt_pid_uid_and_ports(self) -> None:
        receipt = self.create_active_emulator_runtime_receipt()
        capability = self.load_capability()
        pending = self.work / "emulator-listeners.txt.pending"
        pending.write_text(
            f"p{receipt.pid}\nu{receipt.uid}\nf18\n"
            f"n127.0.0.1:{receipt.console_port}\nf19\n"
            f"n127.0.0.1:{receipt.console_port + 1}\n",
            encoding="ascii",
        )
        pending.chmod(0o600)
        with mock.patch.object(
            commands,
            "_capture_owned_emulator_listeners",
            return_value=BoundedResult(0),
        ):
            commands._verify_recovery_listeners(
                layout=self.layout,
                capability=capability,
                receipt=receipt,
            )

        with (
            mock.patch.object(
                commands,
                "_capture_owned_emulator_listeners",
                return_value=BoundedResult(17),
            ),
            mock.patch.object(commands, "read_regular_snapshot") as read_snapshot,
            self.assertRaisesRegex(
                commands.AndroidCommandError, "listener inspection failed"
            ),
        ):
            commands._verify_recovery_listeners(
                layout=self.layout,
                capability=capability,
                receipt=receipt,
            )
        read_snapshot.assert_not_called()

        pending.write_text(
            f"p{receipt.pid}\nu{receipt.uid + 1}\nf18\n"
            f"n127.0.0.1:{receipt.console_port}\nf19\n"
            f"n127.0.0.1:{receipt.console_port + 1}\n",
            encoding="ascii",
        )
        pending.chmod(0o600)
        with (
            mock.patch.object(
                commands,
                "_capture_owned_emulator_listeners",
                return_value=BoundedResult(0),
            ),
            self.assertRaisesRegex(
                (commands.AndroidCommandError, state.AndroidRuntimeStateError),
                "expected account",
            ),
        ):
            commands._verify_recovery_listeners(
                layout=self.layout,
                capability=capability,
                receipt=receipt,
            )

    def test_owned_single_listener_parser_is_exact_and_rejects_parallel_identity(
        self,
    ) -> None:
        endpoint = "/tmp/qperiapt-adb.ABCDEFGH/adb.sock"
        darwin = f"p424242\nu{os.geteuid()}\nf17\nn{endpoint}\n"
        self.assertEqual(
            commands.parse_owned_single_listener(
                darwin,
                expected_pid=424242,
                expected_uid=os.geteuid(),
                expected_endpoint=endpoint,
                dialect=OwnedUnixListenerDialect.DARWIN,
                expected_listener_descriptor=None,
            ).uid,
            os.geteuid(),
        )
        linux = (
            f"p424242\nu{os.geteuid()}\n"
            f"f17\nn{endpoint} type=STREAM\nTST=LISTEN\n"
        )
        self.assertEqual(
            commands.parse_owned_single_listener(
                linux,
                expected_pid=424242,
                expected_uid=os.geteuid(),
                expected_endpoint=endpoint,
                dialect=OwnedUnixListenerDialect.LINUX,
                expected_listener_descriptor=None,
            ).listener_descriptor,
            17,
        )
        active_linux = (
            f"p424242\nu{os.geteuid()}\n"
            f"f17\nn{endpoint} type=STREAM\nTST=LISTEN\n"
            f"f18\nn{endpoint} type=STREAM\nTST=CONNECTED\n"
        )
        self.assertEqual(
            commands.parse_owned_single_listener(
                active_linux,
                expected_pid=424242,
                expected_uid=os.geteuid(),
                expected_endpoint=endpoint,
                dialect=OwnedUnixListenerDialect.LINUX,
                expected_listener_descriptor=17,
            ).listener_descriptor,
            17,
        )
        self.assertEqual(
            commands.parse_owned_single_listener(
                active_linux,
                expected_pid=424242,
                expected_uid=os.geteuid(),
                expected_endpoint=endpoint,
                dialect=OwnedUnixListenerDialect.LINUX,
                expected_listener_descriptor=None,
                expected_listener_descriptor_sha256=hashlib.sha256(
                    b"17"
                ).hexdigest(),
            ).listener_descriptor,
            17,
        )
        invalid = (
            active_linux.replace("TST=LISTEN", "TST=CONNECTED"),
            active_linux.replace("TST=CONNECTED", "TST=LISTEN"),
            active_linux.replace("TST=CONNECTED", "TST=UNCONNECTED"),
            active_linux.replace("TST=CONNECTED\n", ""),
            active_linux.replace("f18", "f17"),
            active_linux.replace(endpoint + " type=STREAM", endpoint + ".other type=STREAM", 1),
            active_linux + f"p424243\nu{os.geteuid()}\nf19\nn{endpoint}\n",
        )
        for text in invalid:
            with (
                self.subTest(text=text),
                self.assertRaises(commands.AndroidEmulatorControlError),
            ):
                commands.parse_owned_single_listener(
                    text,
                    expected_pid=424242,
                    expected_uid=os.geteuid(),
                    expected_endpoint=endpoint,
                    dialect=OwnedUnixListenerDialect.LINUX,
                    expected_listener_descriptor=17,
                )

        darwin_active = darwin + f"f18\nn{endpoint}\n"
        commands.parse_owned_single_listener(
            darwin_active,
            expected_pid=424242,
            expected_uid=os.geteuid(),
            expected_endpoint=endpoint,
            dialect=OwnedUnixListenerDialect.DARWIN,
            expected_listener_descriptor=17,
        )
        reordered_darwin_active = (
            f"p424242\nu{os.geteuid()}\nf18\nn{endpoint}\nf17\nn{endpoint}\n"
        )
        self.assertEqual(
            commands.parse_owned_single_listener(
                reordered_darwin_active,
                expected_pid=424242,
                expected_uid=os.geteuid(),
                expected_endpoint=endpoint,
                dialect=OwnedUnixListenerDialect.DARWIN,
                expected_listener_descriptor=17,
            ).listener_descriptor,
            17,
        )
        with self.assertRaisesRegex(
            commands.AndroidEmulatorControlError,
            "bound listening descriptor",
        ):
            commands.parse_owned_single_listener(
                darwin_active.replace("f17", "f19"),
                expected_pid=424242,
                expected_uid=os.geteuid(),
                expected_endpoint=endpoint,
                dialect=OwnedUnixListenerDialect.DARWIN,
                expected_listener_descriptor=17,
            )

    def test_emulator_listener_count_error_reports_only_fixed_endpoint_presence(
        self,
    ) -> None:
        fixture = f"p424242\nu{os.geteuid()}\nf17\nn127.0.0.1:5584\n"
        with self.assertRaisesRegex(
            commands.AndroidEmulatorControlError,
            r"observed=1, console=1, adb=0, unexpected=0",
        ):
            commands.parse_owned_lsof_listeners(
                fixture,
                expected_pid=424242,
                expected_uid=os.geteuid(),
                console_port=5584,
                adb_port=5585,
            )

    def test_emulator_listener_parser_accepts_only_the_exact_optional_ipv6_pair(
        self,
    ) -> None:
        fixture = (
            f"p424242\nu{os.geteuid()}\n"
            "f17\nn127.0.0.1:5584\n"
            "f18\nn[::1]:5584\n"
            "f19\nn127.0.0.1:5585\n"
            "f20\nn[::1]:5585\n"
        )
        self.assertEqual(
            commands.parse_owned_lsof_listeners(
                fixture,
                expected_pid=424242,
                expected_uid=os.geteuid(),
                console_port=5584,
                adb_port=5585,
            ),
            os.geteuid(),
        )
        invalid = (
            fixture.replace("[::1]:5584", "[::]:5584"),
            fixture.replace("[::1]:5585", "[2001:db8::1]:5585"),
            fixture.replace("f18\nn[::1]:5584\n", ""),
            fixture.replace("f20\nn[::1]:5585\n", ""),
            fixture.replace("f17\nn127.0.0.1:5584\n", ""),
            fixture.replace("f19\nn127.0.0.1:5585\n", ""),
            fixture + "f21\nn127.0.0.1:5586\n",
        )
        for candidate in invalid:
            with (
                self.subTest(candidate=candidate),
                self.assertRaises(commands.AndroidEmulatorControlError),
            ):
                commands.parse_owned_lsof_listeners(
                    candidate,
                    expected_pid=424242,
                    expected_uid=os.geteuid(),
                    console_port=5584,
                    adb_port=5585,
                )

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
            capture_result = self.invoke(commands.AndroidOperation.DEVICE_STATE)
            self.assertEqual(capture_result.stdout, b"device\n")
            capture.assert_called_once()
            capture.reset_mock()
            self.invoke(commands.AndroidOperation.FORCE_STOP)
            capture.assert_called_once()
            self.assertEqual(capture.call_args.kwargs["maximum_bytes"], 65536)
            self.assertEqual(capture.call_args.kwargs["stderr"], subprocess.STDOUT)
            self.invoke(commands.AndroidOperation.UNINSTALL_APP)
            run.assert_called_once()
            self.invoke(commands.AndroidOperation.LSOF_INITIAL)
            write.assert_called_once()
            write_arguments = write.call_args.kwargs
            self.assertEqual(write_arguments["output_name"], "adb-listener-initial.txt")
            self.assertEqual(write_arguments["maximum_bytes"], 65536)
            self.assertEqual(write_arguments["timeout_seconds"], 15)

    def test_package_state_maps_exact_absent_present_and_nonzero_results(self) -> None:
        cases = (
            (BoundedResult(0, b""), b"absent\n"),
            (
                BoundedResult(
                    0, b"package:dev.qperiapt.androidsmoke\n"
                ),
                b"present\n",
            ),
            (
                BoundedResult(17, b"raw package service diagnostic\n"),
                b"retryable:query-nonzero\n",
            ),
            (
                BoundedResult(-9, b"raw signal diagnostic\n"),
                b"retryable:query-nonzero\n",
            ),
        )
        capability = self.load_capability()
        expected_argv = commands._device(
            capability,
            "shell",
            "cmd",
            "package",
            "list",
            "packages",
            commands.PACKAGE,
        )
        self.assertNotIn("-u", expected_argv)
        for raw, expected in cases:
            with (
                self.subTest(raw=raw),
                mock.patch.object(
                    commands, "capture_stdout", return_value=raw
                ) as capture,
            ):
                result = self.invoke(
                    commands.AndroidOperation.PACKAGE_STATE,
                    timeout_seconds=5,
                )
            self.assertEqual(result, BoundedResult(0, expected))
            capture.assert_called_once()
            self.assertEqual(capture.call_args.args[0], expected_argv)
            self.assertGreaterEqual(capture.call_args.kwargs["timeout_seconds"], 1)
            self.assertLessEqual(capture.call_args.kwargs["timeout_seconds"], 5)
            self.assertEqual(capture.call_args.kwargs["maximum_bytes"], 65536)
            self.assertEqual(capture.call_args.kwargs["stderr"], subprocess.STDOUT)
            self.assertEqual(
                capture.call_args.kwargs["environment"],
                commands._client_environment(capability),
            )

    def test_package_state_maps_only_bounded_timeout_to_retryable(self) -> None:
        with mock.patch.object(
            commands,
            "capture_stdout",
            side_effect=commands.BoundedProcessError("timeout", "query timed out"),
        ):
            result = self.invoke(commands.AndroidOperation.PACKAGE_STATE)
        self.assertEqual(result, BoundedResult(0, b"retryable:query-timeout\n"))

        timeout_with_cleanup_failure = commands.BoundedProcessError(
            "timeout", "query timed out"
        )
        timeout_with_cleanup_failure.add_note("bounded process cleanup failure: reap")
        with (
            mock.patch.object(
                commands,
                "capture_stdout",
                side_effect=timeout_with_cleanup_failure,
            ),
            self.assertRaisesRegex(
                commands.BoundedProcessError, "query timed out"
            ) as raised,
        ):
            self.invoke(commands.AndroidOperation.PACKAGE_STATE)
        self.assertIn("cleanup failure", raised.exception.__notes__[0])

        for kind in ("arguments", "start", "output_limit", "io", "reap"):
            with (
                self.subTest(kind=kind),
                mock.patch.object(
                    commands,
                    "capture_stdout",
                    side_effect=commands.BoundedProcessError(kind, "structural"),
                ),
                self.assertRaisesRegex(commands.BoundedProcessError, "structural"),
            ):
                self.invoke(commands.AndroidOperation.PACKAGE_STATE)

    def test_expected_transport_table_is_exact_and_private(self) -> None:
        self.create_capability(
            device_kind="emulator", expected_serial="emulator-5584"
        )
        capability = self.load_capability()
        cases = (
            (
                BoundedResult(0, b"List of devices attached\n\n"),
                commands.ExpectedTransportState.ABSENT,
            ),
            (
                BoundedResult(
                    0, b"List of devices attached\nemulator-5584\tdevice\n\n"
                ),
                commands.ExpectedTransportState.DEVICE,
            ),
            (
                BoundedResult(
                    0, b"List of devices attached\nemulator-5584\toffline\n\n"
                ),
                commands.ExpectedTransportState.OTHER,
            ),
            (BoundedResult(17, b"raw diagnostic\n"), commands.ExpectedTransportState.INCONCLUSIVE),
        )
        for raw, expected in cases:
            with (
                self.subTest(raw=raw),
                mock.patch.object(commands, "capture_stdout", return_value=raw) as capture,
            ):
                observed = commands._observe_expected_transport(
                    capability, timeout_seconds=4
                )
            self.assertIs(observed, expected)
            capture.assert_called_once_with(
                commands._adb(capability, "devices"),
                timeout_seconds=4,
                maximum_bytes=65536,
                stderr=subprocess.STDOUT,
                environment=commands._client_environment(capability),
            )

        with mock.patch.object(
            commands,
            "capture_stdout",
            side_effect=commands.BoundedProcessError("timeout", "transport timeout"),
        ):
            self.assertIs(
                commands._observe_expected_transport(capability, timeout_seconds=4),
                commands.ExpectedTransportState.INCONCLUSIVE,
            )

        malformed = (
            b"",
            b"List of devices attached\n",
            b"List of devices attached\r\n\r\n",
            b"List of devices attached\n\v\n",
            b"List of devices attached\n\f\n",
            b"List of devices attached\nSERIAL123\tdevice\n\n",
            b"List of devices attached\nemulator-5584\tdevice\nother\tdevice\n\n",
            b"List of devices attached\nemulator-5584\tno permissions\n\n",
            b"\xff\n",
        )
        for output in malformed:
            with (
                self.subTest(output=output),
                mock.patch.object(
                    commands,
                    "capture_stdout",
                    return_value=BoundedResult(0, output),
                ),
                self.assertRaises(commands.AndroidCommandError),
            ):
                commands._observe_expected_transport(capability, timeout_seconds=4)

    def test_package_state_distinguishes_missing_emulator_transport_only(self) -> None:
        self.create_capability(
            device_kind="emulator", expected_serial="emulator-5584"
        )
        tables = (
            (
                b"List of devices attached\n\n",
                b"retryable:device-unavailable\n",
            ),
            (
                b"List of devices attached\nemulator-5584\tdevice\n\n",
                b"retryable:query-nonzero\n",
            ),
            (
                b"List of devices attached\nemulator-5584\tunauthorized\n\n",
                b"retryable:query-nonzero\n",
            ),
        )
        for table, expected in tables:
            with (
                self.subTest(table=table),
                mock.patch.object(
                    commands,
                    "capture_stdout",
                    side_effect=[
                        BoundedResult(17, b"raw package diagnostic\n"),
                        BoundedResult(0, table),
                    ],
                ) as capture,
            ):
                result = self.invoke(
                    commands.AndroidOperation.PACKAGE_STATE, timeout_seconds=5
                )
            self.assertEqual(result, BoundedResult(0, expected))
            self.assertEqual(capture.call_count, 2)

    def test_emulator_transport_recovery_is_receipt_bound_and_non_publishing(
        self,
    ) -> None:
        receipt = self.create_active_emulator_runtime_receipt()
        capability = self.load_capability()
        context = commands.RecoveryContext(
            layout=self.layout,
            capability=commands._recovery_adb_capability(self.layout, receipt),
            launcher=receipt.launcher_path,
            backend=receipt.backend_path,
            current_boot=True,
        )
        identity = commands.ProcessIdentity(
            pid=receipt.pid,  # type: ignore[arg-type]
            uid=receipt.uid,
            started_at=receipt.started_at,  # type: ignore[arg-type]
            started_subsecond=receipt.started_subsecond,  # type: ignore[arg-type]
            executable=receipt.backend_path,  # type: ignore[arg-type]
        )
        initial_registration = self.proof / "adb-emulator-registration.txt"
        initial_registration.write_bytes(b"initial registration proof\n")
        initial_registration.chmod(0o600)
        accepted = b"Connected to emulator on ports 5584,5585\n"
        with (
            mock.patch.object(
                commands, "_validate_owned_adb_server_for_client"
            ) as server_guard,
            mock.patch.object(
                commands, "_validate_recovery_receipt", return_value=context
            ),
            mock.patch.object(
                commands,
                "_same_receipt_process",
                side_effect=[identity, identity, identity, identity],
            ),
            mock.patch.object(commands, "_verify_recovery_listeners") as listeners,
            mock.patch.object(commands, "_verify_owned_emulator_console_name") as console,
            mock.patch.object(
                commands,
                "_observe_expected_transport",
                side_effect=[
                    commands.ExpectedTransportState.ABSENT,
                    commands.ExpectedTransportState.ABSENT,
                ],
            ) as transport,
            mock.patch.object(
                commands, "_observe_exact_device_state", return_value=True
            ) as device_state,
            mock.patch.object(
                commands,
                "capture_stdout",
                return_value=BoundedResult(0, accepted),
            ) as register,
        ):
            result = commands._recover_owned_emulator_transport(
                self.layout, capability, timeout_seconds=15
            )
        self.assertEqual(result, BoundedResult(0, b"recovered\n"))
        self.assertEqual(server_guard.call_count, 5)
        self.assertEqual(listeners.call_count, 4)
        self.assertEqual(transport.call_count, 2)
        device_state.assert_called_once()
        console.assert_called_once()
        self.assertIn("deadline", console.call_args.kwargs)
        register.assert_called_once()
        self.assertEqual(
            register.call_args.args[0],
            commands.OPERATION_SPECS[
                commands.AndroidOperation.REGISTER_EMULATOR
            ].build_argv(capability),
        )
        self.assertEqual(
            initial_registration.read_bytes(), b"initial registration proof\n"
        )

    def test_emulator_transport_recovery_never_connects_without_exact_absence(
        self,
    ) -> None:
        receipt = self.create_active_emulator_runtime_receipt()
        capability = self.load_capability()
        context = commands.RecoveryContext(
            layout=self.layout,
            capability=commands._recovery_adb_capability(self.layout, receipt),
            launcher=receipt.launcher_path,
            backend=receipt.backend_path,
            current_boot=True,
        )
        identity = commands.ProcessIdentity(
            pid=receipt.pid,  # type: ignore[arg-type]
            uid=receipt.uid,
            started_at=receipt.started_at,  # type: ignore[arg-type]
            started_subsecond=receipt.started_subsecond,  # type: ignore[arg-type]
            executable=receipt.backend_path,  # type: ignore[arg-type]
        )
        for transport_state, expected in (
            (commands.ExpectedTransportState.DEVICE, b"race-device\n"),
            (
                commands.ExpectedTransportState.OTHER,
                b"retryable:transport-inconclusive\n",
            ),
            (
                commands.ExpectedTransportState.INCONCLUSIVE,
                b"retryable:transport-inconclusive\n",
            ),
        ):
            with (
                self.subTest(transport_state=transport_state),
                mock.patch.object(commands, "_validate_owned_adb_server_for_client"),
                mock.patch.object(
                    commands, "_validate_recovery_receipt", return_value=context
                ),
                mock.patch.object(commands, "_same_receipt_process", return_value=identity),
                mock.patch.object(commands, "_verify_recovery_listeners"),
                mock.patch.object(commands, "_verify_owned_emulator_console_name"),
                mock.patch.object(
                    commands,
                    "_observe_expected_transport",
                    return_value=transport_state,
                ),
                mock.patch.object(
                    commands, "_observe_exact_device_state", return_value=True
                ),
                mock.patch.object(commands, "capture_stdout") as register,
            ):
                result = commands._recover_owned_emulator_transport(
                    self.layout, capability, timeout_seconds=15
                )
            self.assertEqual(result, BoundedResult(0, expected))
            register.assert_not_called()

        with (
            mock.patch.object(commands, "_validate_owned_adb_server_for_client") as server_guard,
            mock.patch.object(
                commands, "_validate_recovery_receipt", return_value=context
            ),
            mock.patch.object(commands, "_same_receipt_process", return_value=identity),
            mock.patch.object(commands, "_verify_recovery_listeners") as listeners,
            mock.patch.object(commands, "_verify_owned_emulator_console_name"),
            mock.patch.object(
                commands,
                "_observe_expected_transport",
                side_effect=[
                    commands.ExpectedTransportState.ABSENT,
                    commands.ExpectedTransportState.DEVICE,
                ],
            ),
            mock.patch.object(
                commands, "_observe_exact_device_state", return_value=True
            ) as state_probe,
            mock.patch.object(commands, "capture_stdout") as register,
        ):
            result = commands._recover_owned_emulator_transport(
                self.layout, capability, timeout_seconds=15
            )
        self.assertEqual(result, BoundedResult(0, b"race-device\n"))
        register.assert_not_called()
        state_probe.assert_called_once()
        self.assertEqual(server_guard.call_count, 4)
        self.assertEqual(listeners.call_count, 3)

    def test_emulator_transport_recovery_classifies_connect_and_post_state_failures(
        self,
    ) -> None:
        receipt = self.create_active_emulator_runtime_receipt()
        capability = self.load_capability()
        context = commands.RecoveryContext(
            layout=self.layout,
            capability=commands._recovery_adb_capability(self.layout, receipt),
            launcher=receipt.launcher_path,
            backend=receipt.backend_path,
            current_boot=True,
        )
        identity = commands.ProcessIdentity(
            pid=receipt.pid,  # type: ignore[arg-type]
            uid=receipt.uid,
            started_at=receipt.started_at,  # type: ignore[arg-type]
            started_subsecond=receipt.started_subsecond,  # type: ignore[arg-type]
            executable=receipt.backend_path,  # type: ignore[arg-type]
        )

        for registration in (
            BoundedResult(17, b"raw failure\n"),
            commands.BoundedProcessError("timeout", "registration timeout"),
        ):
            capture_arguments: dict[str, object]
            if isinstance(registration, BaseException):
                capture_arguments = {"side_effect": registration}
            else:
                capture_arguments = {"return_value": registration}
            with (
                self.subTest(registration=registration),
                mock.patch.object(commands, "_validate_owned_adb_server_for_client"),
                mock.patch.object(
                    commands, "_validate_recovery_receipt", return_value=context
                ),
                mock.patch.object(commands, "_same_receipt_process", return_value=identity),
                mock.patch.object(commands, "_verify_recovery_listeners"),
                mock.patch.object(commands, "_verify_owned_emulator_console_name"),
                mock.patch.object(
                    commands,
                    "_observe_expected_transport",
                    side_effect=[
                        commands.ExpectedTransportState.ABSENT,
                        commands.ExpectedTransportState.ABSENT,
                    ],
                ),
                mock.patch.object(commands, "_observe_exact_device_state") as state_probe,
                mock.patch.object(commands, "capture_stdout", **capture_arguments),
            ):
                result = commands._recover_owned_emulator_transport(
                    self.layout, capability, timeout_seconds=15
                )
            self.assertEqual(
                result, BoundedResult(0, b"retryable:registration-failed\n")
            )
            state_probe.assert_not_called()

        accepted = b"Emulator already registered on port 5585\n"
        with (
            mock.patch.object(commands, "_validate_owned_adb_server_for_client"),
            mock.patch.object(
                commands, "_validate_recovery_receipt", return_value=context
            ),
            mock.patch.object(commands, "_same_receipt_process", return_value=identity),
            mock.patch.object(commands, "_verify_recovery_listeners"),
            mock.patch.object(commands, "_verify_owned_emulator_console_name"),
            mock.patch.object(
                commands,
                "_observe_expected_transport",
                side_effect=[
                    commands.ExpectedTransportState.ABSENT,
                    commands.ExpectedTransportState.ABSENT,
                ],
            ),
            mock.patch.object(
                commands, "_observe_exact_device_state", return_value=False
            ),
            mock.patch.object(
                commands,
                "capture_stdout",
                return_value=BoundedResult(0, accepted),
            ),
        ):
            result = commands._recover_owned_emulator_transport(
                self.layout, capability, timeout_seconds=15
            )
        self.assertEqual(
            result, BoundedResult(0, b"retryable:post-state-unavailable\n")
        )

        with (
            mock.patch.object(commands, "_validate_owned_adb_server_for_client"),
            mock.patch.object(
                commands, "_validate_recovery_receipt", return_value=context
            ),
            mock.patch.object(commands, "_same_receipt_process", return_value=identity),
            mock.patch.object(commands, "_verify_recovery_listeners"),
            mock.patch.object(commands, "_verify_owned_emulator_console_name"),
            mock.patch.object(
                commands,
                "_observe_expected_transport",
                side_effect=[
                    commands.ExpectedTransportState.ABSENT,
                    commands.ExpectedTransportState.ABSENT,
                ],
            ),
            mock.patch.object(
                commands,
                "capture_stdout",
                return_value=BoundedResult(0, b"unexpected success\n"),
            ),
            self.assertRaisesRegex(
                commands.AndroidCommandError, "malformed success"
            ) as raised,
        ):
            commands._recover_owned_emulator_transport(
                self.layout, capability, timeout_seconds=15
            )
        self.assertNotIn("unexpected success", str(raised.exception))

    def test_emulator_transport_recovery_identity_gate_precedes_connect(self) -> None:
        receipt = self.create_active_emulator_runtime_receipt()
        capability = self.load_capability()
        context = commands.RecoveryContext(
            layout=self.layout,
            capability=commands._recovery_adb_capability(self.layout, receipt),
            launcher=receipt.launcher_path,
            backend=receipt.backend_path,
            current_boot=True,
        )
        identity = commands.ProcessIdentity(
            pid=receipt.pid,  # type: ignore[arg-type]
            uid=receipt.uid,
            started_at=receipt.started_at,  # type: ignore[arg-type]
            started_subsecond=receipt.started_subsecond,  # type: ignore[arg-type]
            executable=receipt.backend_path,  # type: ignore[arg-type]
        )
        for gate_name in (
            "_verify_recovery_listeners",
            "_verify_owned_emulator_console_name",
        ):
            with (
                self.subTest(gate=gate_name),
                mock.patch.object(commands, "_validate_owned_adb_server_for_client"),
                mock.patch.object(
                    commands, "_validate_recovery_receipt", return_value=context
                ),
                mock.patch.object(commands, "_same_receipt_process", return_value=identity),
                mock.patch.object(commands, "_verify_recovery_listeners") as listeners,
                mock.patch.object(
                    commands, "_verify_owned_emulator_console_name"
                ) as console,
                mock.patch.object(commands, "capture_stdout") as register,
                self.assertRaisesRegex(commands.AndroidCommandError, "identity drift"),
            ):
                selected_gate = listeners if gate_name == "_verify_recovery_listeners" else console
                selected_gate.side_effect = commands.AndroidCommandError("identity drift")
                commands._recover_owned_emulator_transport(
                    self.layout, capability, timeout_seconds=15
                )
            register.assert_not_called()

        self.create_capability()
        physical_capability = self.load_capability()
        with (
            mock.patch.object(commands, "_validate_owned_adb_server_for_client"),
            mock.patch.object(state, "load_owned_runtime_receipt", return_value=None),
            mock.patch.object(commands, "capture_stdout") as register,
            self.assertRaisesRegex(
                commands.AndroidCommandError, "active emulator receipt"
            ),
        ):
            commands._recover_owned_emulator_transport(
                self.layout, physical_capability, timeout_seconds=15
            )
        register.assert_not_called()

    def test_emulator_transport_recovery_revalidates_after_final_absence(
        self,
    ) -> None:
        receipt = self.create_active_emulator_runtime_receipt()
        capability = self.load_capability()
        context = commands.RecoveryContext(
            layout=self.layout,
            capability=commands._recovery_adb_capability(self.layout, receipt),
            launcher=receipt.launcher_path,
            backend=receipt.backend_path,
            current_boot=True,
        )
        identity = commands.ProcessIdentity(
            pid=receipt.pid,  # type: ignore[arg-type]
            uid=receipt.uid,
            started_at=receipt.started_at,  # type: ignore[arg-type]
            started_subsecond=receipt.started_subsecond,  # type: ignore[arg-type]
            executable=receipt.backend_path,  # type: ignore[arg-type]
        )
        with (
            mock.patch.object(commands, "_validate_owned_adb_server_for_client"),
            mock.patch.object(
                commands, "_validate_recovery_receipt", return_value=context
            ),
            mock.patch.object(commands, "_same_receipt_process", return_value=identity),
            mock.patch.object(commands, "_verify_recovery_listeners"),
            mock.patch.object(commands, "_verify_owned_emulator_console_name"),
            mock.patch.object(
                commands,
                "_observe_expected_transport",
                side_effect=[
                    commands.ExpectedTransportState.ABSENT,
                    commands.ExpectedTransportState.ABSENT,
                ],
            ),
            mock.patch.object(
                commands,
                "_revalidate_emulator_transport_identity",
                side_effect=[receipt, commands.AndroidCommandError("pre-connect drift")],
            ) as identity_gate,
            mock.patch.object(commands, "capture_stdout") as register,
            self.assertRaisesRegex(commands.AndroidCommandError, "pre-connect drift"),
        ):
            commands._recover_owned_emulator_transport(
                self.layout, capability, timeout_seconds=15
            )
        self.assertEqual(identity_gate.call_count, 2)
        register.assert_not_called()

    def test_emulator_transport_recovery_post_identity_failure_cannot_succeed(
        self,
    ) -> None:
        receipt = self.create_active_emulator_runtime_receipt()
        capability = self.load_capability()
        context = commands.RecoveryContext(
            layout=self.layout,
            capability=commands._recovery_adb_capability(self.layout, receipt),
            launcher=receipt.launcher_path,
            backend=receipt.backend_path,
            current_boot=True,
        )
        identity = commands.ProcessIdentity(
            pid=receipt.pid,  # type: ignore[arg-type]
            uid=receipt.uid,
            started_at=receipt.started_at,  # type: ignore[arg-type]
            started_subsecond=receipt.started_subsecond,  # type: ignore[arg-type]
            executable=receipt.backend_path,  # type: ignore[arg-type]
        )
        accepted = b"Connected to emulator on ports 5584,5585\n"
        with (
            mock.patch.object(commands, "_validate_owned_adb_server_for_client"),
            mock.patch.object(
                commands, "_validate_recovery_receipt", return_value=context
            ),
            mock.patch.object(
                commands,
                "_same_receipt_process",
                side_effect=[identity, identity, identity, None],
            ),
            mock.patch.object(commands, "_verify_recovery_listeners"),
            mock.patch.object(commands, "_verify_owned_emulator_console_name"),
            mock.patch.object(
                commands,
                "_observe_expected_transport",
                side_effect=[
                    commands.ExpectedTransportState.ABSENT,
                    commands.ExpectedTransportState.ABSENT,
                ],
            ),
            mock.patch.object(
                commands,
                "capture_stdout",
                return_value=BoundedResult(0, accepted),
            ) as register,
            mock.patch.object(commands, "_observe_exact_device_state") as state_probe,
            self.assertRaisesRegex(
                commands.AndroidCommandError, "identity changed"
            ),
        ):
            commands._recover_owned_emulator_transport(
                self.layout, capability, timeout_seconds=15
            )
        register.assert_called_once()
        state_probe.assert_not_called()

    def test_package_state_rejects_successful_malformed_output(self) -> None:
        malformed = (
            b"package:dev.qperiapt.androidsmoke",
            b"package:dev.qperiapt.androidsmoke\n\n",
            b" package:dev.qperiapt.androidsmoke\n",
            b"package:dev.qperiapt.other\n",
            b"package:dev.qperiapt.androidsmoke\r\n",
            b"package:dev.qperiapt.androidsmoke\x00\n",
            b"\xff",
        )
        for output in malformed:
            with (
                self.subTest(output=output),
                mock.patch.object(
                    commands,
                    "capture_stdout",
                    return_value=BoundedResult(0, output),
                ),
                self.assertRaises(
                    (commands.AndroidCommandError, state.AndroidRuntimeStateError)
                ),
            ):
                self.invoke(commands.AndroidOperation.PACKAGE_STATE)

    def test_package_state_always_postchecks_owned_server(self) -> None:
        for raw in (
            BoundedResult(0, b""),
            BoundedResult(0, b"package:dev.qperiapt.androidsmoke\n"),
            BoundedResult(9, b"raw diagnostic\n"),
        ):
            with (
                self.subTest(raw=raw),
                mock.patch.object(commands, "capture_stdout", return_value=raw),
                mock.patch.object(
                    commands,
                    "_validate_owned_adb_server_for_client",
                    side_effect=[None, commands.AndroidCommandError("server drift")],
                ) as guard,
                self.assertRaisesRegex(commands.AndroidCommandError, "server drift"),
            ):
                commands.invoke_operation(
                    commands.AndroidOperation.PACKAGE_STATE,
                    run_id=self.layout.run_id,
                )
            self.assertEqual(guard.call_count, 2)

    def test_package_state_preserves_primary_when_postcheck_also_fails(self) -> None:
        with (
            mock.patch.object(
                commands,
                "capture_stdout",
                return_value=BoundedResult(0, b"malformed\n"),
            ),
            mock.patch.object(
                commands,
                "_validate_owned_adb_server_for_client",
                side_effect=[None, commands.AndroidCommandError("server drift")],
            ) as guard,
            self.assertRaisesRegex(commands.AndroidCommandError, "malformed") as raised,
        ):
            commands.invoke_operation(
                commands.AndroidOperation.PACKAGE_STATE,
                run_id=self.layout.run_id,
            )
        self.assertEqual(guard.call_count, 2)
        self.assertTrue(
            any("post-package-state" in note for note in raised.exception.__notes__)
        )

    def test_package_state_pre_query_and_postcheck_share_one_deadline(self) -> None:
        capability = self.load_capability()
        spec = commands.OPERATION_SPECS[commands.AndroidOperation.PACKAGE_STATE]
        with (
            mock.patch.object(commands.time, "monotonic", side_effect=[100.0, 101.0]),
            mock.patch.object(
                commands, "_validate_owned_adb_server_for_client"
            ) as guard,
            mock.patch.object(
                commands,
                "capture_stdout",
                return_value=BoundedResult(
                    0, b"package:dev.qperiapt.androidsmoke\n"
                ),
            ) as capture,
        ):
            result = commands._invoke_package_state(
                capability, spec, timeout_seconds=5
            )
        self.assertEqual(result, BoundedResult(0, b"present\n"))
        self.assertEqual(capture.call_args.kwargs["timeout_seconds"], 4)
        self.assertEqual(guard.call_count, 2)
        self.assertEqual(
            [call.kwargs["deadline"] for call in guard.call_args_list],
            [105.0, 105.0],
        )

    def test_timeout_cannot_exceed_operation_profile(self) -> None:
        with mock.patch.object(commands, "capture_stdout") as capture:
            with self.assertRaisesRegex(
                (commands.AndroidCommandError, state.AndroidRuntimeStateError),
                "1 through 15",
            ):
                self.invoke(commands.AndroidOperation.DEVICE_STATE, timeout_seconds=16)
            capture.assert_not_called()

    def test_only_pure_lsof_operations_bypass_private_server_guard(self) -> None:
        bypass = {
            commands.AndroidOperation.LSOF_INITIAL,
            commands.AndroidOperation.LSOF_BEFORE,
            commands.AndroidOperation.LSOF_REGISTERED,
            commands.AndroidOperation.LSOF_AFTER,
        }
        self.assertEqual(set(commands.OPERATION_SPECS), set(commands.AndroidOperation))
        self.assertEqual(
            {
                operation
                for operation, spec in commands.OPERATION_SPECS.items()
                if not spec.requires_private_server
            },
            bypass,
        )
        capability = self.load_capability()
        expected_argv = (
            "/usr/sbin/lsof",
            "-nP",
            "-a",
            "-U",
            "-Ts",
            "-FpufnT",
            capability.socket_path,
        )
        with mock.patch.object(
            commands, "_lsof_path", return_value="/usr/sbin/lsof"
        ):
            for operation in sorted(bypass, key=str):
                with self.subTest(operation=operation):
                    self.assertEqual(
                        commands.OPERATION_SPECS[operation].build_argv(capability),
                        expected_argv,
                    )

    def test_recovery_listener_capture_requests_every_parsed_lsof_field(
        self,
    ) -> None:
        receipt, _observed = self.start_physical_adb_server_receipt()
        capability = self.load_capability()
        output = (
            f"p{receipt.adb_server_pid}\nu{receipt.uid}\nf17\n"
            f"n{capability.socket_path}\n"
        ).encode("ascii")
        with (
            mock.patch.object(commands, "_lsof_path", return_value="/usr/sbin/lsof"),
            mock.patch.object(
                commands,
                "capture_stdout",
                return_value=BoundedResult(0, output),
            ) as capture,
        ):
            self.assertTrue(
                commands._capture_recovery_adb_listener(capability, receipt)
            )
        capture.assert_called_once_with(
            (
                "/usr/sbin/lsof",
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

    def test_linux_recovery_listener_requires_bound_listen_state(self) -> None:
        receipt, _observed = self.start_physical_adb_server_receipt()
        capability = self.load_capability()
        receipt = commands.dataclasses.replace(
            receipt,
            adb_profile="linux-system",
            adb_listener_descriptor=17,
        )
        output = (
            f"p{receipt.adb_server_pid}\nu{receipt.uid}\n"
            f"f17\nn{capability.socket_path} type=STREAM\nTST=LISTEN\n"
            f"f18\nn{capability.socket_path} type=STREAM\nTST=CONNECTED\n"
        ).encode("ascii")
        with mock.patch.object(
            commands,
            "capture_stdout",
            return_value=BoundedResult(0, output),
        ):
            observation = commands._capture_recovery_adb_listener(
                capability,
                receipt,
            )
        self.assertIsNotNone(observation)
        self.assertEqual(observation.listener_descriptor, 17)

        accepted_only = output.replace(b"TST=LISTEN", b"TST=CONNECTED")
        with (
            mock.patch.object(
                commands,
                "capture_stdout",
                return_value=BoundedResult(0, accepted_only),
            ),
            self.assertRaisesRegex(
                commands.AndroidCommandError,
                "bound listening descriptor",
            ),
        ):
            commands._capture_recovery_adb_listener(capability, receipt)

    def test_client_guard_runs_after_command_and_detects_midcommand_exit(self) -> None:
        with (
            mock.patch.object(
                commands,
                "_validate_owned_adb_server_for_client",
                side_effect=[
                    None,
                    commands.AndroidCommandError("server died mid-command"),
                ],
            ) as guard,
            mock.patch.object(
                commands, "capture_stdout", return_value=BoundedResult(0, b"device\n")
            ) as capture,
            self.assertRaisesRegex(
                (commands.AndroidCommandError, state.AndroidRuntimeStateError),
                "mid-command",
            ),
        ):
            commands.invoke_operation(
                commands.AndroidOperation.DEVICE_STATE,
                run_id=self.run_id,
            )
        capture.assert_called_once()
        self.assertEqual(guard.call_count, 2)

        with (
            mock.patch.object(
                commands, "_validate_owned_adb_server_for_client"
            ) as guard,
            mock.patch.object(commands, "_lsof_path", return_value="/usr/sbin/lsof"),
            mock.patch.object(
                commands, "write_stdout_at", return_value=BoundedResult(0)
            ),
        ):
            commands.invoke_operation(
                commands.AndroidOperation.LSOF_INITIAL,
                run_id=self.run_id,
            )
        guard.assert_not_called()

    def test_environment_poisoning_fails_before_process_start(self) -> None:
        with (
            mock.patch.dict(
                os.environ, {**self.environment, "ADB_TRACE": "all"}, clear=True
            ),
            mock.patch.object(commands, "run") as run,
            self.assertRaisesRegex(
                (commands.AndroidCommandError, state.AndroidRuntimeStateError),
                "ADB_TRACE",
            ),
        ):
            self.invoke(commands.AndroidOperation.DEVICE_STATE)
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
                commands,
                "capture_stdout",
                return_value=BoundedResult(0, b"device\n"),
            ) as capture,
        ):
            self.invoke(commands.AndroidOperation.DEVICE_STATE)
        child_environment = capture.call_args.kwargs["environment"]
        self.assertEqual(child_environment["PATH"], "/usr/bin:/bin:/usr/sbin:/sbin")
        self.assertNotIn("LD_PRELOAD", child_environment)
        self.assertNotIn("DYLD_INSERT_LIBRARIES", child_environment)

    def test_server_exec_uses_only_capability_owned_identity(self) -> None:
        server_environment = {
            **self.environment,
            "ADB_USB": "1",
            "ADB_EMU": "0",
        }
        state._write_owned_runtime_receipt(
            state._runtime_recovery_payload(self.load_capability())
        )
        with (
            mock.patch.dict(os.environ, server_environment, clear=True),
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(state, "_arm_lane_lock_close_on_exec") as close_lock,
            mock.patch.object(commands, "_close_nonstandard_descriptors"),
            mock.patch.object(
                os, "execve", side_effect=RuntimeError("exec boundary")
            ) as execve,
            self.assertRaisesRegex(RuntimeError, "exec boundary"),
        ):
            commands.exec_server(self.layout.run_id)
        close_lock.assert_called_once_with()
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

    def test_server_exec_durably_advances_receipt_before_fd_close_and_exec(
        self,
    ) -> None:
        server_environment = {**self.environment, "ADB_USB": "1", "ADB_EMU": "0"}
        state._write_owned_runtime_receipt(
            state._runtime_recovery_payload(self.load_capability())
        )
        identity = commands.ProcessIdentity(
            pid=os.getpid(),
            uid=os.geteuid(),
            started_at=111,
            started_subsecond=222,
            executable=pathlib.Path(sys.executable).resolve(),
        )
        order: list[str] = []

        def assert_advanced() -> None:
            receipt = state.load_owned_runtime_receipt()
            self.assertIsNotNone(receipt)
            self.assertTrue(receipt.adb_server_started)  # type: ignore[union-attr]
            self.assertEqual(receipt.adb_server_process_identity, identity.token)  # type: ignore[union-attr]
            order.append("close-lane")

        with (
            mock.patch.dict(os.environ, server_environment, clear=True),
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(commands, "process_snapshot", return_value=identity),
            mock.patch.object(
                state, "_arm_lane_lock_close_on_exec", side_effect=assert_advanced
            ),
            mock.patch.object(
                commands,
                "_close_nonstandard_descriptors",
                side_effect=lambda **_kwargs: order.append("close-all"),
            ),
            mock.patch.object(
                commands.os,
                "execve",
                side_effect=lambda *_args: (
                    order.append("exec"),
                    (_ for _ in ()).throw(RuntimeError("exec boundary")),
                )[1],
            ),
            self.assertRaisesRegex(RuntimeError, "exec boundary"),
        ):
            commands.exec_server(self.run_id)
        self.assertEqual(order, ["close-lane", "close-all", "exec"])

    def test_startup_handshake_waits_for_exact_concurrent_receipt_advance(self) -> None:
        capability = self.load_capability()
        state._write_owned_runtime_receipt(state._runtime_recovery_payload(capability))
        pending = state.load_owned_runtime_receipt()
        self.assertIsNotNone(pending)
        identity = commands.ProcessIdentity(
            pid=424242,
            uid=os.geteuid(),
            started_at=888888,
            started_subsecond=444,
            executable=pathlib.Path(sys.executable).resolve(),
        )
        executable_metadata = identity.executable.stat()
        snapshot_metadata = self.snapshot.stat()
        release_advance = threading.Event()
        advance_complete = threading.Event()
        worker_error: list[BaseException] = []

        def advance_receipt() -> None:
            try:
                if not release_advance.wait(timeout=2):
                    raise AssertionError("receipt advance was never released")
                with (
                    mock.patch.object(state, "validate_lane_lock_descriptor"),
                    mock.patch.object(state.os, "getpid", return_value=identity.pid),
                ):
                    state.register_adb_child(
                        pending,  # type: ignore[arg-type]
                        state.AdbChildRegistration(
                            process=identity,
                            initial_executable_device=executable_metadata.st_dev,
                            initial_executable_inode=executable_metadata.st_ino,
                            adb_snapshot_device=snapshot_metadata.st_dev,
                            adb_snapshot_inode=snapshot_metadata.st_ino,
                        ),
                    )
            except BaseException as exc:
                worker_error.append(exc)
            finally:
                advance_complete.set()

        worker = threading.Thread(target=advance_receipt)
        worker.start()

        def release_during_wait(_seconds: float) -> None:
            release_advance.set()
            self.assertTrue(
                advance_complete.wait(timeout=2),
                "concurrent receipt advance did not complete",
            )

        try:
            with (
                mock.patch.object(state, "validate_lane_lock_descriptor"),
                mock.patch.object(commands, "process_snapshot", return_value=identity),
                mock.patch.object(
                    commands.time, "sleep", side_effect=release_during_wait
                ),
            ):
                observed_token = commands.wait_owned_adb_server_start(
                    run_id=self.run_id,
                    timeout_seconds=5,
                )
        finally:
            release_advance.set()
            worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(worker_error, [])
        self.assertEqual(observed_token, identity.token)

    def test_startup_handshake_timeout_preserves_pending_state(self) -> None:
        state._write_owned_runtime_receipt(
            state._runtime_recovery_payload(self.load_capability())
        )
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands.time, "monotonic", side_effect=[0.0, 6.0]
            ),
            mock.patch.object(commands, "_same_receipt_adb_server_process") as inspect,
            mock.patch.object(commands.time, "sleep") as sleep,
            self.assertRaisesRegex(
                (commands.AndroidCommandError, state.AndroidRuntimeStateError),
                "did not advance",
            ),
        ):
            commands.wait_owned_adb_server_start(
                run_id=self.run_id,
                timeout_seconds=5,
            )
        inspect.assert_not_called()
        sleep.assert_not_called()
        receipt = state.load_owned_runtime_receipt()
        self.assertIsNotNone(receipt)
        self.assertFalse(receipt.adb_server_started)  # type: ignore[union-attr]
        self.assertTrue(self.state.exists())
        self.assertTrue(self.snapshot.exists())

    def test_startup_handshake_rejects_receipt_host_before_process_inspection(
        self,
    ) -> None:
        receipt, _identity = self.start_physical_adb_server_receipt()
        payload = state._runtime_receipt_payload(receipt)
        payload["host_identity"] = receipt.host_identity + "-other"
        state._replace_owned_runtime_receipt(receipt, payload)
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands, "_same_receipt_adb_server_process"
            ) as inspect,
            self.assertRaisesRegex(commands.AndroidCommandError, "different host"),
        ):
            commands.wait_owned_adb_server_start(
                run_id=self.run_id,
                timeout_seconds=5,
            )
        inspect.assert_not_called()

    def test_startup_handshake_rejects_confirmation_after_deadline(self) -> None:
        receipt, identity = self.start_physical_adb_server_receipt()
        context = commands.RecoveryContext(
            layout=self.layout,
            capability=self.load_capability(),
            launcher=None,
            backend=None,
            current_boot=True,
        )
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands, "_validate_recovery_receipt", return_value=context
            ),
            mock.patch.object(
                commands,
                "_same_receipt_adb_server_process",
                side_effect=[identity, identity],
            ),
            mock.patch.object(commands, "_validate_receipt_adb_server_executable"),
            mock.patch.object(commands.time, "monotonic", side_effect=[0.0, 5.1]),
            self.assertRaisesRegex(commands.AndroidCommandError, "after the deadline"),
        ):
            commands.wait_owned_adb_server_start(
                run_id=receipt.run_id,
                timeout_seconds=5,
            )

    def test_emulator_backend_wait_uses_only_the_registered_receipt_identity(
        self,
    ) -> None:
        receipt = self.create_active_emulator_runtime_receipt()
        capability = self.load_capability()
        context = commands.RecoveryContext(
            layout=self.layout,
            capability=capability,
            launcher=receipt.launcher_path,
            backend=receipt.backend_path,
            current_boot=True,
        )
        controller = commands.ProcessIdentity(
            pid=os.getpid(),
            uid=os.geteuid(),
            started_at=1,
            started_subsecond=1,
            executable=pathlib.Path(sys.executable).resolve(),
        )

        def at(executable: pathlib.Path) -> commands.ProcessIdentity:
            return commands.ProcessIdentity(
                pid=receipt.pid,  # type: ignore[arg-type]
                uid=receipt.uid,
                started_at=receipt.started_at,  # type: ignore[arg-type]
                started_subsecond=receipt.started_subsecond,  # type: ignore[arg-type]
                executable=executable,
            )

        observed = (
            at(controller.executable),
            at(receipt.launcher_path),  # type: ignore[arg-type]
            at(receipt.backend_path),  # type: ignore[arg-type]
            at(receipt.backend_path),  # type: ignore[arg-type]
        )
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(commands, "process_snapshot", return_value=controller),
            mock.patch.object(
                commands, "_validate_recovery_receipt", return_value=context
            ),
            mock.patch.object(
                commands, "_same_receipt_process", side_effect=observed
            ),
            mock.patch.object(commands.time, "monotonic", return_value=0.0),
            mock.patch.object(commands.time, "sleep") as sleep,
        ):
            token = commands.wait_owned_emulator_backend(
                run_id=self.run_id,
                timeout_seconds=5,
            )
        self.assertEqual(token, observed[-1].token)
        self.assertEqual(sleep.call_args_list, [mock.call(0.05), mock.call(0.05)])

        changed = commands.ProcessIdentity(
            pid=receipt.pid,  # type: ignore[arg-type]
            uid=receipt.uid,
            started_at=receipt.started_at + 1,  # type: ignore[operator]
            started_subsecond=receipt.started_subsecond,  # type: ignore[arg-type]
            executable=receipt.backend_path,  # type: ignore[arg-type]
        )
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(commands, "process_snapshot", return_value=controller),
            mock.patch.object(
                commands, "_validate_recovery_receipt", return_value=context
            ),
            mock.patch.object(
                commands,
                "_same_receipt_process",
                side_effect=[observed[-1], changed],
            ),
            self.assertRaisesRegex(
                commands.AndroidCommandError,
                "identity changed at the backend transition",
            ),
        ):
            commands.wait_owned_emulator_backend(
                run_id=self.run_id,
                timeout_seconds=5,
            )

        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(commands, "process_snapshot", return_value=controller),
            mock.patch.object(
                commands, "_validate_recovery_receipt", return_value=context
            ),
            mock.patch.object(
                commands,
                "_same_receipt_process",
                side_effect=[observed[-1], observed[-1]],
            ),
            mock.patch.object(commands.time, "monotonic", side_effect=[0.0, 5.1]),
            self.assertRaisesRegex(commands.AndroidCommandError, "after the deadline"),
        ):
            commands.wait_owned_emulator_backend(
                run_id=self.run_id,
                timeout_seconds=5,
            )

    def test_sealed_socket_directory_allows_connect_but_blocks_replacement(
        self,
    ) -> None:
        directory = pathlib.Path(tempfile.mkdtemp(prefix="qs-", dir="/tmp"))
        directory.chmod(0o700)
        endpoint_path = directory / "server.sock"
        replacement_path = directory / "replacement.sock"

        def cleanup_directory() -> None:
            directory.chmod(0o700)
            endpoint_path.unlink(missing_ok=True)
            replacement_path.unlink(missing_ok=True)
            directory.rmdir()

        self.addCleanup(cleanup_directory)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(server.close)
        self.addCleanup(client.close)
        self.addCleanup(replacement.close)
        server.bind(str(endpoint_path))
        server.listen(1)
        directory.chmod(0o500)
        client.connect(str(endpoint_path))
        accepted, _address = server.accept()
        accepted.close()
        with self.assertRaises(PermissionError):
            replacement.bind(str(replacement_path))
        with self.assertRaises(PermissionError):
            endpoint_path.unlink()

    def test_close_nonstandard_descriptors_closes_inheritable_child_fd(self) -> None:
        script = (
            "import errno, os, sys\n"
            "import android_bounded_command as commands\n"
            "fd=os.open(sys.argv[1], os.O_RDONLY)\n"
            "os.set_inheritable(fd, True)\n"
            "commands._close_nonstandard_descriptors()\n"
            "try:\n"
            " os.fstat(fd)\n"
            "except OSError as exc:\n"
            " assert exc.errno == errno.EBADF\n"
            "else:\n"
            " raise AssertionError('descriptor remained open')\n"
            "assert all(os.fstat(value) for value in (0, 1, 2))\n"
        )
        result = subprocess.run(
            [sys.executable, "-B", "-c", script, str(self.adb)],
            cwd=self.root,
            env={"PYTHONPATH": str(pathlib.Path(commands.__file__).parent)},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))

    def test_sdk_directory_replacement_executes_only_the_run_snapshot(self) -> None:
        sdk = self.root / "sdk"
        source_adb = sdk / "platform-tools/adb"
        source_adb.parent.mkdir(parents=True, mode=0o700)
        original_marker = self.root / "original-adb-ran"
        replacement_marker = self.root / "replacement-adb-ran"
        source_adb.write_text(
            f"#!/bin/sh\nprintf original > {shlex.quote(str(original_marker))}\n",
            encoding="utf-8",
        )
        source_adb.chmod(0o700)
        with mock.patch.object(
            state,
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
            result = self.invoke(commands.AndroidOperation.DEVICE_STATE)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(original_marker.read_text(encoding="ascii"), "original")
        self.assertFalse(replacement_marker.exists())

    def test_changed_adb_snapshot_is_rejected_before_operation_start(self) -> None:
        self.snapshot.chmod(0o700)
        self.snapshot.write_bytes(b"replaced snapshot")
        self.snapshot.chmod(0o500)
        with (
            mock.patch.object(commands, "run") as run,
            self.assertRaisesRegex(
                (commands.AndroidCommandError, state.AndroidRuntimeStateError),
                "snapshot changed",
            ),
        ):
            self.invoke(commands.AndroidOperation.DEVICE_STATE)
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
                    self.invoke(commands.AndroidOperation.DEVICE_STATE)
                run.assert_not_called()
                (self.work / "snapshot-link").unlink(missing_ok=True)
                (self.work / "snapshot-replacement").unlink(missing_ok=True)

    def test_capability_adb_path_action_returns_only_the_validated_snapshot(
        self,
    ) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(
                commands.main(["capability-adb-path", "--run-id", self.layout.run_id]),
                0,
            )
        self.assertEqual(output.getvalue().strip(), str(self.snapshot))

    def _invoke_installed_apk_observation(
        self,
        *,
        path_results: list[BoundedResult],
        copied_bytes: bytes | None = None,
        pull_result: BoundedResult = BoundedResult(0),
        timeout_seconds: int = 30,
    ) -> tuple[BoundedResult, mock.Mock, mock.Mock]:
        path_capture = mock.Mock(side_effect=path_results)

        def write_fixture(argv: tuple[str, ...], **arguments: object) -> BoundedResult:
            self.assertEqual(arguments["output_name"], commands.INSTALLED_APK_COPY_LEAF)
            self.assertEqual(arguments["maximum_bytes"], self.apk.stat().st_size)
            self.assertEqual(argv[-3:], ("exec-out", "cat", "/data/app/run/base.apk"))
            if pull_result.returncode == 0 and copied_bytes is not None:
                output = self.work / commands.INSTALLED_APK_COPY_LEAF
                output.write_bytes(copied_bytes)
                output.chmod(0o600)
            return pull_result

        write = mock.Mock(side_effect=write_fixture)
        with (
            mock.patch.object(commands, "capture_stdout", path_capture),
            mock.patch.object(commands, "write_stdout_at", write),
            mock.patch.object(commands, "_validate_owned_adb_server_for_client"),
        ):
            result = commands.invoke_operation(
                commands.AndroidOperation.OBSERVE_INSTALLED_APK,
                run_id=self.layout.run_id,
                timeout_seconds=timeout_seconds,
            )
        return result, path_capture, write

    def test_installed_apk_observation_keeps_only_exact_path_stable_bytes(self) -> None:
        path = b"package:/data/app/run/base.apk\n"
        result, capture, write = self._invoke_installed_apk_observation(
            path_results=[BoundedResult(0, path), BoundedResult(0, path)],
            copied_bytes=self.apk.read_bytes(),
        )
        path_sha256 = hashlib.sha256(b"/data/app/run/base.apk").hexdigest()
        self.assertEqual(result, BoundedResult(0, f"exact:{path_sha256}\n".encode()))
        self.assertEqual(capture.call_count, 2)
        write.assert_called_once()
        copy = self.work / commands.INSTALLED_APK_COPY_LEAF
        self.assertEqual(copy.read_bytes(), self.apk.read_bytes())
        self.assertEqual(stat.S_IMODE(copy.stat().st_mode), 0o600)

    def test_installed_apk_observation_retries_mismatch_without_copy(self) -> None:
        path = b"package:/data/app/run/base.apk\n"
        result, _capture, _write = self._invoke_installed_apk_observation(
            path_results=[BoundedResult(0, path), BoundedResult(0, path)],
            copied_bytes=self.apk.read_bytes()[:-1],
        )
        self.assertEqual(result, BoundedResult(0, b"retryable:bytes-mismatch\n"))
        self.assertFalse((self.work / commands.INSTALLED_APK_COPY_LEAF).exists())

    def test_installed_apk_observation_retries_path_change_without_copy(self) -> None:
        result, _capture, _write = self._invoke_installed_apk_observation(
            path_results=[
                BoundedResult(0, b"package:/data/app/run/base.apk\n"),
                BoundedResult(0, b"package:/data/app/replaced/base.apk\n"),
            ],
            copied_bytes=self.apk.read_bytes(),
        )
        self.assertEqual(result, BoundedResult(0, b"retryable:path-changed\n"))
        self.assertFalse((self.work / commands.INSTALLED_APK_COPY_LEAF).exists())

    def test_installed_apk_observation_retries_nonzero_path_or_pull(self) -> None:
        result, capture, write = self._invoke_installed_apk_observation(
            path_results=[BoundedResult(1, b"package service unavailable\n")]
        )
        self.assertEqual(result, BoundedResult(0, b"retryable:package-unavailable\n"))
        capture.assert_called_once()
        write.assert_not_called()

        path = b"package:/data/app/run/base.apk\n"
        result, capture, write = self._invoke_installed_apk_observation(
            path_results=[BoundedResult(0, path)],
            pull_result=BoundedResult(1),
        )
        self.assertEqual(result, BoundedResult(0, b"retryable:pull-failed\n"))
        capture.assert_called_once()
        write.assert_called_once()
        self.assertFalse((self.work / commands.INSTALLED_APK_COPY_LEAF).exists())

    def test_installed_apk_observation_retries_only_bounded_timeouts(self) -> None:
        with (
            mock.patch.object(
                commands,
                "capture_stdout",
                side_effect=commands.BoundedProcessError("timeout", "pm path timed out"),
            ),
            mock.patch.object(commands, "write_stdout_at") as write,
            mock.patch.object(commands, "_validate_owned_adb_server_for_client"),
        ):
            result = commands.invoke_operation(
                commands.AndroidOperation.OBSERVE_INSTALLED_APK,
                run_id=self.layout.run_id,
                timeout_seconds=30,
            )
        self.assertEqual(result, BoundedResult(0, b"retryable:package-unavailable\n"))
        write.assert_not_called()

        path = b"package:/data/app/run/base.apk\n"
        with (
            mock.patch.object(
                commands, "capture_stdout", return_value=BoundedResult(0, path)
            ),
            mock.patch.object(
                commands,
                "write_stdout_at",
                side_effect=commands.BoundedProcessError("timeout", "pull timed out"),
            ),
            mock.patch.object(commands, "_validate_owned_adb_server_for_client"),
        ):
            result = commands.invoke_operation(
                commands.AndroidOperation.OBSERVE_INSTALLED_APK,
                run_id=self.layout.run_id,
                timeout_seconds=30,
            )
        self.assertEqual(result, BoundedResult(0, b"retryable:pull-failed\n"))
        self.assertFalse((self.work / commands.INSTALLED_APK_COPY_LEAF).exists())

    def test_installed_apk_observation_preserves_timeout_cleanup_failures(
        self,
    ) -> None:
        path_timeout = commands.BoundedProcessError("timeout", "pm path timed out")
        path_timeout.add_note("bounded process cleanup failure: reap")
        with (
            mock.patch.object(
                commands,
                "capture_stdout",
                side_effect=path_timeout,
            ),
            mock.patch.object(commands, "write_stdout_at") as write,
            mock.patch.object(commands, "_validate_owned_adb_server_for_client"),
            self.assertRaises(commands.BoundedProcessError) as raised,
        ):
            commands.invoke_operation(
                commands.AndroidOperation.OBSERVE_INSTALLED_APK,
                run_id=self.layout.run_id,
                timeout_seconds=30,
            )
        self.assertIs(raised.exception, path_timeout)
        write.assert_not_called()
        self.assertFalse((self.work / commands.INSTALLED_APK_COPY_LEAF).exists())

        path = b"package:/data/app/run/base.apk\n"
        pull_timeout = commands.BoundedProcessError("timeout", "pull timed out")
        pull_timeout.add_note("bounded process cleanup failure: descriptor close")
        with (
            mock.patch.object(
                commands, "capture_stdout", return_value=BoundedResult(0, path)
            ),
            mock.patch.object(
                commands,
                "write_stdout_at",
                side_effect=pull_timeout,
            ),
            mock.patch.object(commands, "_validate_owned_adb_server_for_client"),
            self.assertRaises(commands.BoundedProcessError) as raised,
        ):
            commands.invoke_operation(
                commands.AndroidOperation.OBSERVE_INSTALLED_APK,
                run_id=self.layout.run_id,
                timeout_seconds=30,
            )
        self.assertIs(raised.exception, pull_timeout)
        self.assertFalse((self.work / commands.INSTALLED_APK_COPY_LEAF).exists())

    def test_installed_apk_observation_shares_one_deadline_with_server_guards(
        self,
    ) -> None:
        path = b"package:/data/app/run/base.apk\n"

        def write_fixture(_argv: tuple[str, ...], **arguments: object) -> BoundedResult:
            output = self.work / str(arguments["output_name"])
            output.write_bytes(self.apk.read_bytes())
            output.chmod(0o600)
            return BoundedResult(0)

        with (
            mock.patch.object(commands.time, "monotonic", return_value=100.0),
            mock.patch.object(
                commands,
                "capture_stdout",
                side_effect=[BoundedResult(0, path), BoundedResult(0, path)],
            ),
            mock.patch.object(commands, "write_stdout_at", side_effect=write_fixture),
            mock.patch.object(
                commands, "_validate_owned_adb_server_for_client"
            ) as guard,
        ):
            result = commands.invoke_operation(
                commands.AndroidOperation.OBSERVE_INSTALLED_APK,
                run_id=self.layout.run_id,
                timeout_seconds=30,
            )
        self.assertRegex(result.stdout, rb"\Aexact:[0-9a-f]{64}\n\Z")
        self.assertEqual(guard.call_count, 2)
        self.assertEqual(
            [call.kwargs for call in guard.call_args_list],
            [{"deadline": 130.0}, {"deadline": 130.0}],
        )

    def test_installed_apk_observation_respects_the_shared_deadline(self) -> None:
        with (
            mock.patch.object(commands.time, "monotonic", side_effect=[100.0, 130.0]),
            mock.patch.object(commands, "capture_stdout") as capture,
            mock.patch.object(commands, "write_stdout_at") as write,
            mock.patch.object(commands, "_validate_owned_adb_server_for_client"),
        ):
            result = commands.invoke_operation(
                commands.AndroidOperation.OBSERVE_INSTALLED_APK,
                run_id=self.layout.run_id,
                timeout_seconds=30,
            )
        self.assertEqual(result, BoundedResult(0, b"retryable:deadline-exhausted\n"))
        capture.assert_not_called()
        write.assert_not_called()
        self.assertFalse((self.work / commands.INSTALLED_APK_COPY_LEAF).exists())

    def test_installed_apk_observation_rejects_exact_bytes_completed_after_deadline(
        self,
    ) -> None:
        path = b"package:/data/app/run/base.apk\n"

        def write_fixture(_argv: tuple[str, ...], **arguments: object) -> BoundedResult:
            output = self.work / str(arguments["output_name"])
            output.write_bytes(self.apk.read_bytes())
            output.chmod(0o600)
            return BoundedResult(0)

        with (
            mock.patch.object(
                commands.time,
                "monotonic",
                side_effect=[100.0, 100.0, 101.0, 102.0, 130.0],
            ),
            mock.patch.object(
                commands,
                "capture_stdout",
                side_effect=[BoundedResult(0, path), BoundedResult(0, path)],
            ),
            mock.patch.object(commands, "write_stdout_at", side_effect=write_fixture),
            mock.patch.object(commands, "_validate_owned_adb_server_for_client"),
        ):
            result = commands.invoke_operation(
                commands.AndroidOperation.OBSERVE_INSTALLED_APK,
                run_id=self.layout.run_id,
                timeout_seconds=30,
            )
        self.assertEqual(result, BoundedResult(0, b"retryable:deadline-exhausted\n"))
        self.assertFalse((self.work / commands.INSTALLED_APK_COPY_LEAF).exists())

    def test_installed_apk_observation_postchecks_and_removes_exact_copy_on_failure(
        self,
    ) -> None:
        path = b"package:/data/app/run/base.apk\n"

        def write_fixture(_argv: tuple[str, ...], **arguments: object) -> BoundedResult:
            output = self.work / str(arguments["output_name"])
            output.write_bytes(self.apk.read_bytes())
            output.chmod(0o600)
            return BoundedResult(0)

        with (
            mock.patch.object(
                commands,
                "capture_stdout",
                side_effect=[BoundedResult(0, path), BoundedResult(0, path)],
            ),
            mock.patch.object(commands, "write_stdout_at", side_effect=write_fixture),
            mock.patch.object(
                commands,
                "_validate_owned_adb_server_for_client",
                side_effect=[None, commands.AndroidCommandError("server changed")],
            ) as guard,
            self.assertRaisesRegex(commands.AndroidCommandError, "server changed"),
        ):
            commands.invoke_operation(
                commands.AndroidOperation.OBSERVE_INSTALLED_APK,
                run_id=self.layout.run_id,
                timeout_seconds=30,
            )
        self.assertEqual(guard.call_count, 2)
        self.assertFalse((self.work / commands.INSTALLED_APK_COPY_LEAF).exists())

    def test_installed_apk_observation_preserves_primary_when_postcheck_also_fails(
        self,
    ) -> None:
        with (
            mock.patch.object(
                commands,
                "capture_stdout",
                return_value=BoundedResult(0, b"package:--help\n"),
            ),
            mock.patch.object(commands, "write_stdout_at") as write,
            mock.patch.object(
                commands,
                "_validate_owned_adb_server_for_client",
                side_effect=[None, commands.AndroidCommandError("postcheck failed")],
            ),
            self.assertRaisesRegex(
                (commands.AndroidCommandError, state.AndroidRuntimeStateError),
                "installed Android base APK path",
            ) as raised,
        ):
            commands.invoke_operation(
                commands.AndroidOperation.OBSERVE_INSTALLED_APK,
                run_id=self.layout.run_id,
                timeout_seconds=30,
            )
        write.assert_not_called()
        self.assertTrue(
            any("post-observation" in note for note in raised.exception.__notes__)
        )

    def test_installed_apk_observation_output_limit_is_structural(self) -> None:
        path = b"package:/data/app/run/base.apk\n"
        with (
            mock.patch.object(
                commands,
                "capture_stdout",
                side_effect=[BoundedResult(0, path)],
            ),
            mock.patch.object(
                commands,
                "write_stdout_at",
                side_effect=commands.BoundedProcessError(
                    "output_limit", "installed APK exceeded the expected size"
                ),
            ),
            mock.patch.object(commands, "_validate_owned_adb_server_for_client"),
            self.assertRaisesRegex(
                commands.BoundedProcessError, "exceeded the expected size"
            ),
        ):
            commands.invoke_operation(
                commands.AndroidOperation.OBSERVE_INSTALLED_APK,
                run_id=self.layout.run_id,
                timeout_seconds=30,
            )
        self.assertFalse((self.work / commands.INSTALLED_APK_COPY_LEAF).exists())

    def test_installed_apk_observation_rejects_malformed_path_structurally(self) -> None:
        hostile = (
            b"package:--help\n",
            b"package:/data/app/../other/base.apk\n",
            b"package:/data/app/run/base.apk\npackage:/data/app/other/base.apk\n",
            b"package:/data/app/run/base.apk;sh\n",
        )
        for output in hostile:
            with (
                self.subTest(output=output),
                mock.patch.object(
                    commands, "capture_stdout", return_value=BoundedResult(0, output)
                ),
                mock.patch.object(commands, "write_stdout_at") as write,
                mock.patch.object(commands, "_validate_owned_adb_server_for_client"),
                self.assertRaises(
                    (commands.AndroidCommandError, state.AndroidRuntimeStateError)
                ),
            ):
                commands.invoke_operation(
                    commands.AndroidOperation.OBSERVE_INSTALLED_APK,
                    run_id=self.layout.run_id,
                    timeout_seconds=30,
                )
            write.assert_not_called()
            self.assertFalse((self.work / commands.INSTALLED_APK_COPY_LEAF).exists())

    def test_installed_apk_observation_removes_copy_when_after_path_is_malformed(
        self,
    ) -> None:
        path = b"package:/data/app/run/base.apk\n"

        def write_fixture(_argv: tuple[str, ...], **arguments: object) -> BoundedResult:
            output = self.work / str(arguments["output_name"])
            output.write_bytes(self.apk.read_bytes())
            output.chmod(0o600)
            return BoundedResult(0)

        with (
            mock.patch.object(
                commands,
                "capture_stdout",
                side_effect=[BoundedResult(0, path), BoundedResult(0, b"package:--help\n")],
            ),
            mock.patch.object(commands, "write_stdout_at", side_effect=write_fixture),
            mock.patch.object(commands, "_validate_owned_adb_server_for_client"),
            self.assertRaises(
                (commands.AndroidCommandError, state.AndroidRuntimeStateError)
            ),
        ):
            commands.invoke_operation(
                commands.AndroidOperation.OBSERVE_INSTALLED_APK,
                run_id=self.layout.run_id,
                timeout_seconds=30,
            )
        self.assertFalse((self.work / commands.INSTALLED_APK_COPY_LEAF).exists())

    def test_runtime_control_diagnostics_are_merged_under_the_capture_limit(
        self,
    ) -> None:
        for operation in (
            commands.AndroidOperation.FORCE_STOP,
            commands.AndroidOperation.START_APP,
        ):
            spec = commands.OPERATION_SPECS[operation]
            with self.subTest(operation=operation.value):
                self.assertEqual(spec.mode, "capture")
                self.assertTrue(spec.stderr_to_stdout)
                with mock.patch.object(
                    commands,
                    "capture_stdout",
                    return_value=BoundedResult(224, b"bounded adb failure\n"),
                ) as capture:
                    result = self.invoke(operation)
                self.assertEqual(result.returncode, 224)
                self.assertEqual(result.stdout, b"bounded adb failure\n")
                self.assertEqual(capture.call_args.kwargs["maximum_bytes"], 65536)
                self.assertEqual(capture.call_args.kwargs["stderr"], subprocess.STDOUT)

    def test_logcat_epoch_is_validated_before_it_enters_argv(self) -> None:
        epoch_path = self.proof / "adb-device-time.txt"
        epoch_path.write_text("1786240000.123\n", encoding="ascii")
        epoch_path.chmod(0o600)
        with mock.patch.object(
            commands, "write_stdout_at", return_value=BoundedResult(0)
        ) as write:
            self.invoke(commands.AndroidOperation.CAPTURE_LOGCAT)
        argv = write.call_args.args[0]
        self.assertIn("1786240000.123", argv)

        epoch_path.write_text("1786240000.123 --help\n", encoding="ascii")
        epoch_path.chmod(0o600)
        with (
            mock.patch.object(commands, "write_stdout_at") as write,
            self.assertRaises(
                (commands.AndroidCommandError, state.AndroidRuntimeStateError)
            ),
        ):
            self.invoke(commands.AndroidOperation.CAPTURE_LOGCAT)
        write.assert_not_called()

    def test_parser_rejects_unknown_operation_and_extra_arguments(self) -> None:
        diagnostics = io.StringIO()
        with (
            contextlib.redirect_stderr(diagnostics),
            self.assertRaises(SystemExit) as unknown,
        ):
            commands.main(["invoke", "shell", "--run-id", self.layout.run_id])
        self.assertEqual(unknown.exception.code, 2)
        with (
            contextlib.redirect_stderr(diagnostics),
            self.assertRaises(SystemExit) as extra,
        ):
            commands.main(
                [
                    "invoke",
                    "device-state",
                    "--run-id",
                    self.layout.run_id,
                    "--",
                    "/bin/sh",
                ]
            )
        self.assertEqual(extra.exception.code, 2)

    def test_public_isolation_action_rejects_internal_checkpoints(self) -> None:
        parser = commands._build_parser()
        for checkpoint in ("emulator_pre_exec", "runtime_post_cleanup"):
            with (
                self.subTest(checkpoint=checkpoint),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as rejected,
            ):
                parser.parse_args(
                    [
                        "record-adb-isolation-checkpoint",
                        "--run-id",
                        self.run_id,
                        "--checkpoint",
                        checkpoint,
                    ]
                )
            self.assertEqual(rejected.exception.code, 2)
        with self.assertRaisesRegex(commands.AndroidCommandError, "not exposed"):
            commands.record_adb_isolation_checkpoint(
                self.run_id,
                commands.AdbIsolationCheckpoint.EMULATOR_PRE_EXEC,
            )

    def test_preexec_checkpoint_has_one_internal_production_callsite(self) -> None:
        source = pathlib.Path(commands.__file__).read_text(encoding="utf-8")
        self.assertEqual(
            source.count("record_pre_exec_adb_isolation_checkpoint("),
            1,
        )

    def test_account_state_and_lane_lock_are_fixed_private_and_stable(self) -> None:
        state_path = state.account_state_directory()
        lock = state.lane_lock_path()
        self.assertEqual(state_path.parent, self.account_state_parent)
        self.assertEqual(lock, state_path / state.LANE_LOCK_LEAF)
        self.assertEqual(stat.S_IMODE(state_path.stat().st_mode), 0o700)
        lock_metadata = lock.stat()
        self.assertEqual(stat.S_IMODE(lock_metadata.st_mode), 0o600)
        self.assertEqual(lock_metadata.st_uid, os.geteuid())
        before = (lock_metadata.st_dev, lock_metadata.st_ino)
        state.ensure_account_state()
        after_metadata = lock.stat()
        self.assertEqual(before, (after_metadata.st_dev, after_metadata.st_ino))

    def test_avd_home_path_cli_prints_only_fixed_absent_leaf(self) -> None:
        expected = state.account_state_directory() / state.AVD_HOME_LEAF
        self.assertFalse(os.path.lexists(expected))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(commands.main(["avd-home-path"]), 0)
        self.assertEqual(output.getvalue(), f"{expected}\n")
        self.assertFalse(os.path.lexists(expected))
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as rejected,
        ):
            commands.main(["avd-home-path", "--path", str(self.root / "other")])
        self.assertEqual(rejected.exception.code, 2)

    def test_runtime_avd_name_cli_prints_only_code_owned_mapping(self) -> None:
        with mock.patch.object(
            state,
            "ADB_PROFILE_PATHS",
            {
                "macos-account": self.adb,
                "linux-system": self.adb,
                "linux-opt": self.adb,
            },
        ):
            for profile, abi, expected in (
                ("macos-account", "arm64-v8a", "QPeriapt_Release_16K_API_35_V1"),
                ("linux-system", "x86_64", "QPeriapt_Release_16K_API_35_CI_V1"),
            ):
                with self.subTest(profile=profile, abi=abi):
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        self.assertEqual(
                            commands.main(
                                [
                                    "runtime-avd-name",
                                    "--adb-profile",
                                    profile,
                                    "--device-abi",
                                    abi,
                                ]
                            ),
                            0,
                        )
                    self.assertEqual(output.getvalue(), f"{expected}\n")
            with self.assertRaisesRegex(
                state.AndroidRuntimeStateError,
                "no fixed AVD selection",
            ):
                commands.main(
                    [
                        "runtime-avd-name",
                        "--adb-profile",
                        "linux-opt",
                        "--device-abi",
                        "x86_64",
                    ]
                )
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as rejected,
        ):
            commands.main(
                [
                    "emulator-nodaemon",
                    "--run-id",
                    self.layout.run_id,
                    "--device-abi",
                    "arm64-v8a",
                    "--avd-name",
                    "QPeriapt_Release_16K_API_35_V1",
                ]
            )
        self.assertEqual(rejected.exception.code, 2)

    def test_process_identity_binds_pid_uid_start_and_executable_without_environment(
        self,
    ) -> None:
        identity = commands.process_snapshot(os.getpid())
        self.assertEqual(identity.pid, os.getpid())
        self.assertEqual(identity.uid, os.geteuid())
        self.assertGreater(identity.started_at, 0)
        self.assertTrue(identity.executable.is_absolute())
        self.assertEqual(
            identity.token,
            f"{identity.pid}:{identity.uid}:{identity.started_at}:"
            f"{identity.started_subsecond}",
        )
        parsed = parse_process_identity_token(identity.token)
        self.assertEqual(
            (parsed.pid, parsed.uid, parsed.started_at, parsed.started_subsecond),
            (
                identity.pid,
                identity.uid,
                identity.started_at,
                identity.started_subsecond,
            ),
        )
        for invalid in (
            "1:0:1:0",
            "02:0:1:0",
            "2:0:0:0",
            "2:0:1:1000000",
            "2:0:1:00",
            True,
        ):
            with (
                self.subTest(invalid=invalid),
                self.assertRaises(commands.ProcessIdentityError),
            ):
                parse_process_identity_token(invalid)
        with self.assertRaises(commands.ProcessIdentityError):
            commands.process_snapshot(1)

    def test_process_execution_snapshot_is_typed_and_identity_stable(self) -> None:
        execution = commands.execution_snapshot(os.getpid())
        self.assertEqual(execution.identity.token, commands.process_snapshot(os.getpid()).token)
        self.assertTrue(execution.argv)
        self.assertTrue(dict(execution.environment))
        with self.assertRaises(TypeError):
            execution.environment["MUTATION"] = "forbidden"  # type: ignore[index]

    def test_process_execution_parser_rejects_non_utf8_and_duplicate_environment(
        self,
    ) -> None:
        identity = commands.process_snapshot(os.getpid())
        for argv, environment, message in (
            ((b"python", b"\xff"), (b"A=1",), "argument is not UTF-8"),
            ((b"python",), (b"A=1", b"A=2"), "duplicate"),
            ((b"python",), (b"MALFORMED",), "malformed"),
        ):
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(commands.ProcessIdentityError, message),
            ):
                process_identity._execution_from_parts(identity, argv, environment)

    def test_emulator_routing_accepts_launcher_nonrouting_environment_only(
        self,
    ) -> None:
        receipt = self.create_active_emulator_runtime_receipt()
        capability = self.load_capability()
        identity = commands.ProcessIdentity(
            pid=receipt.pid,
            uid=receipt.uid,
            started_at=receipt.started_at,
            started_subsecond=receipt.started_subsecond,
            executable=receipt.backend_path,
        )
        argv = (
            str(receipt.backend_path),
            "-no-direct-adb",
            "-adb-path",
            str(capability.adb_snapshot_path),
        )
        environment = {
            **commands._emulator_environment(capability),
            "MESA_RGB_VISUAL": "TrueColor 24",
            "ANDROID_EMULATOR_LAUNCHER_DIR": str(receipt.launcher_path.parent),
            "DYLD_LIBRARY_PATH": "/fixed/sdk/lib64",
        }
        self.assertTrue(
            commands.FORBIDDEN_EMULATOR_AVD_SELECTOR_ENVIRONMENT.isdisjoint(
                commands._emulator_environment(capability)
            )
        )
        execution = ProcessExecutionSnapshot(identity, argv, environment)
        digest = commands._validate_emulator_execution_routing(
            execution,
            receipt=receipt,
            capability=capability,
        )
        self.assertEqual(
            digest,
            commands.emulator_routing_environment_sha256(
                commands._emulator_environment(capability)
            ),
        )
        for label, avd_environment in (
            (
                "missing",
                {
                    name: value
                    for name, value in environment.items()
                    if name != "ANDROID_AVD_HOME"
                },
            ),
            (
                "wrong",
                {
                    **environment,
                    "ANDROID_AVD_HOME": str(self.root / "ambient-avd-home"),
                },
            ),
        ):
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(
                    commands.AndroidCommandError,
                    "routing environment projection differs",
                ),
            ):
                commands._validate_emulator_execution_routing(
                    ProcessExecutionSnapshot(identity, argv, avd_environment),
                    receipt=receipt,
                    capability=capability,
                )
        for name in ("ADB_TRACE", "ANDROID_ADB_SERVER_ADDRESS"):
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(commands.AndroidCommandError, "forbidden"),
            ):
                commands._validate_emulator_execution_routing(
                    ProcessExecutionSnapshot(
                        identity,
                        argv,
                        {**environment, name: "forbidden"},
                    ),
                    receipt=receipt,
                    capability=capability,
                )
        for name in sorted(
            commands.FORBIDDEN_EMULATOR_AVD_SELECTOR_ENVIRONMENT
        ):
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(
                    commands.AndroidCommandError,
                    "forbidden AVD selector variables",
                ),
            ):
                commands._validate_emulator_execution_routing(
                    ProcessExecutionSnapshot(
                        identity,
                        argv,
                        {**environment, name: "/unverified-avd-root"},
                    ),
                    receipt=receipt,
                    capability=capability,
                )

    def test_loopback_probe_requires_refusal_on_both_fixed_ports_and_families(
        self,
    ) -> None:
        probes: list[object] = []

        class Probe:
            def __init__(self, family: int, kind: int) -> None:
                self.family = family
                self.kind = kind
                self.timeout: float | None = None
                self.address: object = None
                probes.append(self)

            def settimeout(self, timeout: float) -> None:
                self.timeout = timeout

            def connect_ex(self, address: object) -> int:
                self.address = address
                return commands.errno.ECONNREFUSED

            def close(self) -> None:
                return None

        with mock.patch.object(commands.socket, "socket", side_effect=Probe):
            observation = commands.probe_adb_loopback_absence()
        self.assertEqual(
            observation.ports_payload(),
            {
                "5037": {"ipv4": "connection_refused", "ipv6": "connection_refused"},
                "5586": {"ipv4": "connection_refused", "ipv6": "connection_refused"},
            },
        )
        self.assertEqual(
            [(probe.family, probe.address, probe.timeout) for probe in probes],
            [
                (socket.AF_INET, ("127.0.0.1", 5037), 1.0),
                (socket.AF_INET6, ("::1", 5037, 0, 0), 1.0),
                (socket.AF_INET, ("127.0.0.1", 5586), 1.0),
                (socket.AF_INET6, ("::1", 5586, 0, 0), 1.0),
            ],
        )

    def test_loopback_probe_rejects_occupied_or_unobservable_endpoint(self) -> None:
        class Probe:
            def settimeout(self, _timeout: float) -> None:
                return None

            def connect_ex(self, _address: object) -> int:
                return 0

            def close(self) -> None:
                return None

        with (
            mock.patch.object(commands.socket, "socket", return_value=Probe()),
            self.assertRaisesRegex(commands.AndroidEmulatorControlError, "did not refuse"),
        ):
            commands.probe_adb_loopback_absence()

    def test_owned_emulator_routing_receipt_is_live_bound_and_no_replace(self) -> None:
        receipt = self.create_active_emulator_runtime_receipt()
        capability = self.load_capability()
        status = self.proof / "adb-server-status-registered.txt"
        status.write_text(
            f'executable_absolute_path: "{capability.adb_snapshot_path}"\n'
            f'keystore_path: "{capability.vendor_key}"\n'
            "mdns_enabled: false\n"
        )
        status.chmod(0o600)
        listener = self.proof / "adb-listener-registered.txt"
        listener.write_text(
            f"p{receipt.adb_server_pid}\n"
            f"u{receipt.uid}\n"
            "f7\n"
            f"n{capability.socket_path}\n"
        )
        listener.chmod(0o600)
        identity = commands.ProcessIdentity(
            pid=receipt.pid,
            uid=receipt.uid,
            started_at=receipt.started_at,
            started_subsecond=receipt.started_subsecond,
            executable=receipt.backend_path,
        )
        execution = ProcessExecutionSnapshot(
            identity,
            (
                str(receipt.backend_path),
                "-no-direct-adb",
                "-adb-path",
                str(capability.adb_snapshot_path),
            ),
            commands._emulator_environment(capability),
        )
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(commands, "_validate_owned_adb_server_for_client"),
            mock.patch.object(commands, "execution_snapshot", return_value=execution) as live,
        ):
            path = commands.record_owned_emulator_routing(self.run_id)
            with self.assertRaises(FileExistsError):
                commands.record_owned_emulator_routing(self.run_id)
        self.assertEqual(live.call_count, 4)
        self.assertEqual(path, self.proof / "emulator-routing.json")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        value = json.loads(path.read_text())
        self.assertEqual(
            set(value),
            {
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
            },
        )
        self.assertEqual(value["native_notifier_port"], 5586)
        self.assertFalse(value["raw_paths_recorded"])
        self.assertNotIn(str(capability.socket_path), path.read_text())

    def test_lane_lock_descriptor_requires_the_fixed_held_open_description(
        self,
    ) -> None:
        import fcntl

        lock_fd = os.open(state.lane_lock_path(), os.O_RDWR | os.O_CLOEXEC)
        self.addCleanup(os.close, lock_fd)
        with (
            mock.patch.object(state, "LANE_LOCK_FD", lock_fd),
            self.assertRaisesRegex(state.AndroidRuntimeStateError, "is not held"),
        ):
            state.validate_lane_lock_descriptor(lock_fd)

        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with mock.patch.object(state, "LANE_LOCK_FD", lock_fd):
            state.validate_lane_lock_descriptor(lock_fd)

        unlocked_same_inode_fd = os.open(
            state.lane_lock_path(), os.O_RDWR | os.O_CLOEXEC
        )
        self.addCleanup(os.close, unlocked_same_inode_fd)
        with (
            mock.patch.object(state, "LANE_LOCK_FD", unlocked_same_inode_fd),
            self.assertRaisesRegex(
                (commands.AndroidCommandError, state.AndroidRuntimeStateError),
                "does not hold its lock",
            ),
        ):
            state.validate_lane_lock_descriptor(unlocked_same_inode_fd)

        other = self.root / "other-lock"
        other.write_bytes(b"")
        other.chmod(0o600)
        other_fd = os.open(other, os.O_RDWR | os.O_CLOEXEC)
        self.addCleanup(os.close, other_fd)
        fcntl.flock(other_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with (
            mock.patch.object(state, "LANE_LOCK_FD", other_fd),
            self.assertRaisesRegex(
                state.AndroidRuntimeStateError, "differs from the fixed"
            ),
        ):
            state.validate_lane_lock_descriptor(other_fd)

    def test_lane_lock_descriptor_survives_real_exec_as_fd9(self) -> None:
        import fcntl

        lock_fd = os.open(state.lane_lock_path(), os.O_RDWR | os.O_CLOEXEC)
        self.addCleanup(os.close, lock_fd)
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        script = (
            "import os, pathlib, sys\n"
            "import android_runtime_state as state\n"
            "source=int(sys.argv[2])\n"
            "if source != 9: os.dup2(source, 9)\n"
            "os.set_inheritable(9, False)\n"
            "state.ACCOUNT_HOME=pathlib.Path(sys.argv[1])\n"
            "state.validate_lane_lock_descriptor()\n"
        )
        result = subprocess.run(
            [sys.executable, "-B", "-c", script, str(self.root), str(lock_fd)],
            env={"PYTHONPATH": str(pathlib.Path(commands.__file__).parent)},
            pass_fds=(lock_fd,),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))

    def test_lane_lock_rejects_mode_symlink_and_replaceable_parent(self) -> None:
        lock = state.lane_lock_path()
        lock.chmod(0o644)
        with self.assertRaises(
            (commands.EvidenceIOError, state.AndroidRuntimeStateError)
        ):
            state.ensure_account_state()
        lock.chmod(0o600)
        lock.unlink()
        replacement = self.root / "replacement-lock"
        replacement.write_bytes(b"")
        replacement.chmod(0o600)
        lock.symlink_to(replacement)
        with self.assertRaises(
            (OSError, commands.AndroidCommandError, state.AndroidRuntimeStateError)
        ):
            state.ensure_account_state()
        lock.unlink()
        state.ensure_account_state()
        self.account_state_parent.chmod(0o770)
        with self.assertRaisesRegex(
            state.AndroidRuntimeStateError, "not group/other writable"
        ):
            state.ensure_account_state()

    def test_recovery_rejects_group_writable_account_home_before_state_access(
        self,
    ) -> None:
        self.root.chmod(0o770)
        try:
            with (
                mock.patch.object(state, "validate_lane_lock_descriptor"),
                self.assertRaisesRegex(
                    (commands.AndroidCommandError, state.AndroidRuntimeStateError),
                    "not group/other writable",
                ),
            ):
                commands.recover_owned_runtime()
        finally:
            self.root.chmod(0o700)

    def test_owned_runtime_receipt_is_strict_private_and_exactly_retired(self) -> None:
        receipt = self.create_active_emulator_runtime_receipt()
        path = state.owned_runtime_receipt_path()
        metadata = path.stat()
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        self.assertEqual(metadata.st_uid, os.geteuid())
        value = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(set(value), state.OWNED_RUNTIME_RECEIPT_FIELDS)
        self.assertNotIn("private-token", path.read_text(encoding="utf-8"))
        self.assertNotIn("console_auth_token", value)
        self.assertIn("console_auth_token_sha256", value)
        self.assertEqual(receipt.run_id, self.layout.run_id)

        changed = dict(value)
        changed["unexpected"] = True
        path.write_text(json.dumps(changed), encoding="utf-8")
        path.chmod(0o600)
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            self.assertRaisesRegex(
                state.AndroidRuntimeStateError, "changed before retirement"
            ),
        ):
            state.retire_owned_runtime_receipt(receipt)
        self.assertTrue(path.exists())

    def test_owned_runtime_receipt_rejects_schema_modes_and_symlink(self) -> None:
        receipt = self.create_active_emulator_runtime_receipt()
        path = state.owned_runtime_receipt_path()
        original = path.read_bytes()
        mutations = (
            lambda value: value.update({"unexpected": True}),
            lambda value: value.update({"schema_version": True}),
            lambda value: value.update({"process_identity": "1:2:3:4"}),
            lambda value: value.update({"launcher_path": "/tmp/../tmp/emulator"}),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                value = json.loads(original)
                mutate(value)
                path.write_text(json.dumps(value), encoding="utf-8")
                path.chmod(0o600)
                with self.assertRaises(
                    (commands.AndroidCommandError, state.AndroidRuntimeStateError)
                ):
                    state.load_owned_runtime_receipt()
        path.write_bytes(original)
        path.chmod(0o644)
        with self.assertRaises(
            (commands.AndroidCommandError, state.AndroidRuntimeStateError)
        ):
            state.load_owned_runtime_receipt()
        path.unlink()
        target = self.root / "receipt-target"
        target.write_bytes(original)
        target.chmod(0o600)
        path.symlink_to(target)
        with self.assertRaises(
            (commands.AndroidCommandError, state.AndroidRuntimeStateError)
        ):
            state.load_owned_runtime_receipt()
        self.assertEqual(
            receipt.process_identity, f"{os.getpid()}:{os.geteuid()}:123456:789"
        )

    def test_receipt_create_is_no_replace_and_fsync_failure_removes_partial_file(
        self,
    ) -> None:
        receipt = self.create_active_emulator_runtime_receipt()
        path = state.owned_runtime_receipt_path()
        original = path.read_bytes()
        with self.assertRaisesRegex(
            (commands.AndroidCommandError, state.AndroidRuntimeStateError),
            "already exists",
        ):
            state._write_owned_runtime_receipt({"invalid": True})
        self.assertEqual(path.read_bytes(), original)
        with mock.patch.object(state, "validate_lane_lock_descriptor"):
            state.retire_owned_runtime_receipt(receipt)

        real_fsync = os.fsync
        calls = 0

        def fail_first_fsync(descriptor: int) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("injected receipt fsync failure")
            real_fsync(descriptor)

        payload_receipt = self.create_active_emulator_runtime_receipt()
        payload = json.loads(path.read_text(encoding="utf-8"))
        with mock.patch.object(state, "validate_lane_lock_descriptor"):
            state.retire_owned_runtime_receipt(payload_receipt)
        with (
            mock.patch.object(commands.os, "fsync", side_effect=fail_first_fsync),
            self.assertRaisesRegex(OSError, "injected receipt fsync failure"),
        ):
            state._write_owned_runtime_receipt(payload)
        self.assertFalse(path.exists())

    def test_recovery_removes_only_strict_private_abandoned_receipt_stages(
        self,
    ) -> None:
        state_path = state.account_state_directory()
        stages = (
            state_path / f".{state.OWNED_RUNTIME_RECEIPT_LEAF}.pending-424242",
            state_path / f".{state.OWNED_RUNTIME_RECEIPT_LEAF}.replace-424243",
        )
        for stage in stages:
            stage.write_bytes(b"abandoned receipt stage\n")
            stage.chmod(0o600)
        unrelated = state_path / ".unrelated.pending-424242"
        unrelated.write_bytes(b"keep\n")
        unrelated.chmod(0o600)
        with mock.patch.object(state, "validate_lane_lock_descriptor"):
            self.assertEqual(commands.recover_owned_runtime(), "none")
        self.assertTrue(unrelated.exists())
        self.assertTrue(all(not stage.exists() for stage in stages))

    def test_recovery_fails_closed_on_malformed_or_unsafe_receipt_stage(self) -> None:
        state_path = state.account_state_directory()
        malformed = (
            state_path / f".{state.OWNED_RUNTIME_RECEIPT_LEAF}.pending-not-a-pid"
        )
        malformed.write_bytes(b"malformed stage\n")
        malformed.chmod(0o600)
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            self.assertRaisesRegex(
                (commands.AndroidCommandError, state.AndroidRuntimeStateError),
                "filename is malformed",
            ),
        ):
            commands.recover_owned_runtime()
        self.assertTrue(malformed.exists())
        malformed.unlink()

        unsafe = state_path / f".{state.OWNED_RUNTIME_RECEIPT_LEAF}.replace-424244"
        unsafe.write_bytes(b"unsafe stage\n")
        unsafe.chmod(0o644)
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            self.assertRaises(commands.EvidenceIOError),
        ):
            commands.recover_owned_runtime()
        self.assertTrue(unsafe.exists())

    def test_emulator_exec_advances_receipt_before_fixed_exec_and_preserves_failure(
        self,
    ) -> None:
        self.create_capability(
            device_kind="emulator",
            expected_serial="emulator-5584",
        )
        self.create_avd_fixture()
        launcher = self.root / "fixed-emulator"
        backend = self.root / "fixed-emulator-backend"
        for executable in (launcher, backend):
            executable.write_bytes(b"exec fixture")
            executable.chmod(0o700)
        identity = commands.ProcessIdentity(
            pid=os.getpid(),
            uid=os.geteuid(),
            started_at=111,
            started_subsecond=222,
            executable=pathlib.Path(sys.executable).resolve(),
        )
        order: list[str] = []
        started, _server_identity = self.start_physical_adb_server_receipt(
            pid=os.getpid()
        )
        self.seal_test_runtime_receipt(started)

        def close_lock() -> None:
            self.assertTrue(state.owned_runtime_receipt_path().is_file())
            order.append("close-lock")

        def reject_exec(
            executable: str, argv: list[str], environment: dict[str, str]
        ) -> None:
            order.append("exec")
            self.assertEqual(executable, str(launcher))
            self.assertEqual(
                argv,
                [
                    str(launcher),
                    "-avd",
                    "QPeriapt_Release_16K_API_35_V1",
                    "-port",
                    "5584",
                    "-no-snapshot",
                    "-read-only",
                    "-no-window",
                    "-no-audio",
                    "-no-boot-anim",
                    "-no-direct-adb",
                    "-adb-path",
                    str(self.snapshot),
                    "-gpu",
                    "swiftshader_indirect",
                ],
            )
            self.assertEqual(environment["HOME"], str(self.root))
            self.assertEqual(
                environment["ANDROID_AVD_HOME"],
                str(state.avd_home_directory()),
            )
            self.assertEqual(
                environment["ANDROID_ADB_SERVER_PORT"],
                str(state.NATIVE_ADB_NOTIFIER_PORT),
            )
            self.assertEqual(environment["ADB_SERVER_SOCKET"], self.environment["ADB_SERVER_SOCKET"])
            self.assertEqual(environment["ADB_USB"], "0")
            self.assertEqual(environment["ADB_EMU"], "0")
            self.assertNotIn("DYLD_INSERT_LIBRARIES", environment)
            raise RuntimeError("exec boundary")

        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands, "_fixed_emulator_paths", return_value=(launcher, backend)
            ),
            mock.patch.object(commands, "process_snapshot", return_value=identity),
            mock.patch.object(commands, "_validate_owned_adb_server_for_client"),
            mock.patch.object(
                state, "record_pre_exec_adb_isolation_checkpoint"
            ) as checkpoint,
            mock.patch.object(
                state, "arm_lane_lock_close_on_exec", side_effect=close_lock
            ),
            mock.patch.object(commands, "_close_nonstandard_descriptors"),
            mock.patch.object(commands.os, "execve", side_effect=reject_exec),
            self.assertRaisesRegex(RuntimeError, "exec boundary"),
        ):
            commands.exec_emulator(self.layout.run_id, "arm64-v8a")
        self.assertEqual(order, ["close-lock", "exec"])
        checkpoint.assert_called_once_with(
            self.layout.run_id,
        )
        self.assertTrue(state.owned_runtime_receipt_path().exists())
        receipt = state.load_owned_runtime_receipt()
        self.assertIs(receipt.phase, state.RuntimePhase.EMULATOR_CHILD_REGISTERED)  # type: ignore[union-attr]
        self.assertEqual(
            receipt.console_auth_token_identity,  # type: ignore[union-attr]
            state.ConsoleAuthTokenIdentity(
                device=self.console_token.stat().st_dev,
                inode=self.console_token.stat().st_ino,
                sha256=hashlib.sha256(self.console_token.read_bytes()).hexdigest(),
            ),
        )

    def test_emulator_exec_missing_token_keeps_sealed_receipt_and_never_execs(self) -> None:
        self.create_capability(device_kind="emulator", expected_serial="emulator-5584")
        self.create_avd_fixture()
        launcher = self.root / "fixed-emulator"
        backend = self.root / "fixed-emulator-backend"
        for executable in (launcher, backend):
            executable.write_bytes(b"exec fixture")
            executable.chmod(0o700)
        started, _server = self.start_physical_adb_server_receipt(pid=os.getpid())
        sealed = self.seal_test_runtime_receipt(started)
        self.console_token.unlink()
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands, "_fixed_emulator_paths", return_value=(launcher, backend)
            ),
            mock.patch.object(commands, "_validate_owned_adb_server_for_client"),
            mock.patch.object(state, "arm_lane_lock_close_on_exec") as close_lock,
            mock.patch.object(commands.os, "execve") as execve,
            self.assertRaisesRegex(commands.AndroidCommandError, "cannot open"),
        ):
            commands.exec_emulator(self.layout.run_id, "arm64-v8a")
        receipt = state.load_owned_runtime_receipt()
        self.assertEqual(receipt.snapshot_sha256, sealed.snapshot_sha256)  # type: ignore[union-attr]
        self.assertIs(receipt.phase, state.RuntimePhase.ADB_SEALED)  # type: ignore[union-attr]
        close_lock.assert_not_called()
        execve.assert_not_called()

    def test_emulator_exec_rejects_unsafe_avd_before_receipt_mutation(self) -> None:
        self.create_capability(device_kind="emulator", expected_serial="emulator-5584")
        selected = self.create_avd_fixture()
        (selected / "config.ini").chmod(0o640)
        launcher = self.root / "fixed-emulator"
        backend = self.root / "fixed-emulator-backend"
        for executable in (launcher, backend):
            executable.write_bytes(b"exec fixture")
            executable.chmod(0o700)
        started, _server = self.start_physical_adb_server_receipt(pid=os.getpid())
        sealed = self.seal_test_runtime_receipt(started)
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands,
                "_fixed_emulator_paths",
                return_value=(launcher, backend),
            ),
            mock.patch.object(commands, "_validate_owned_adb_server_for_client"),
            mock.patch.object(commands, "process_snapshot") as inspect_process,
            mock.patch.object(state, "register_emulator_child") as register,
            mock.patch.object(state, "arm_lane_lock_close_on_exec") as close_lock,
            mock.patch.object(commands.os, "execve") as execve,
            self.assertRaisesRegex(
                state.AndroidRuntimeStateError,
                "group/other permissions",
            ),
        ):
            commands.exec_emulator(
                self.layout.run_id,
                "arm64-v8a",
            )
        current = state.load_owned_runtime_receipt()
        self.assertIsNotNone(current)
        self.assertEqual(current.snapshot_sha256, sealed.snapshot_sha256)
        self.assertIs(current.phase, state.RuntimePhase.ADB_SEALED)
        inspect_process.assert_not_called()
        register.assert_not_called()
        close_lock.assert_not_called()
        execve.assert_not_called()

    def test_emulator_exec_missing_avd_home_never_inspects_or_mutates_runtime(
        self,
    ) -> None:
        self.create_capability(device_kind="emulator", expected_serial="emulator-5584")
        launcher = self.root / "fixed-emulator"
        backend = self.root / "fixed-emulator-backend"
        for executable in (launcher, backend):
            executable.write_bytes(b"exec fixture")
            executable.chmod(0o700)
        started, _server = self.start_physical_adb_server_receipt(pid=os.getpid())
        sealed = self.seal_test_runtime_receipt(started)
        self.assertFalse(os.path.lexists(state.avd_home_directory()))
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands,
                "_fixed_emulator_paths",
                return_value=(launcher, backend),
            ),
            mock.patch.object(commands, "_validate_owned_adb_server_for_client"),
            mock.patch.object(commands, "process_snapshot") as inspect_process,
            mock.patch.object(commands, "_emulator_console_auth_token") as token,
            mock.patch.object(state, "register_emulator_child") as register,
            mock.patch.object(state, "arm_lane_lock_close_on_exec") as close_lock,
            mock.patch.object(commands.os, "execve") as execve,
            self.assertRaisesRegex(state.AndroidRuntimeStateError, "cannot open"),
        ):
            commands.exec_emulator(
                self.layout.run_id,
                "arm64-v8a",
            )
        current = state.load_owned_runtime_receipt()
        self.assertIsNotNone(current)
        self.assertEqual(current.snapshot_sha256, sealed.snapshot_sha256)
        self.assertIs(current.phase, state.RuntimePhase.ADB_SEALED)
        inspect_process.assert_not_called()
        token.assert_not_called()
        register.assert_not_called()
        close_lock.assert_not_called()
        execve.assert_not_called()

    def test_emulator_exec_replaced_token_keeps_sealed_receipt_and_never_execs(
        self,
    ) -> None:
        self.create_capability(device_kind="emulator", expected_serial="emulator-5584")
        self.create_avd_fixture()
        launcher = self.root / "fixed-emulator"
        backend = self.root / "fixed-emulator-backend"
        for executable in (launcher, backend):
            executable.write_bytes(b"exec fixture")
            executable.chmod(0o700)
        started, _server = self.start_physical_adb_server_receipt(pid=os.getpid())
        self.seal_test_runtime_receipt(started)
        identity = commands.ProcessIdentity(
            pid=os.getpid(),
            uid=os.geteuid(),
            started_at=111,
            started_subsecond=222,
            executable=pathlib.Path(sys.executable).resolve(),
        )
        real_executable_file_identity = commands._executable_file_identity
        replaced = False

        def replace_token_during_preflight(
            path: pathlib.Path, label: str
        ) -> tuple[int, int]:
            nonlocal replaced
            if not replaced:
                replaced = True
                self.console_token.unlink()
                self.console_token.write_bytes(b"replacement-token\n")
                self.console_token.chmod(0o600)
            return real_executable_file_identity(path, label)

        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands, "_fixed_emulator_paths", return_value=(launcher, backend)
            ),
            mock.patch.object(commands, "process_snapshot", return_value=identity),
            mock.patch.object(commands, "_validate_owned_adb_server_for_client"),
            mock.patch.object(
                commands,
                "_executable_file_identity",
                side_effect=replace_token_during_preflight,
            ),
            mock.patch.object(state, "arm_lane_lock_close_on_exec") as close_lock,
            mock.patch.object(commands.os, "execve") as execve,
            self.assertRaisesRegex(commands.AndroidCommandError, "token changed"),
        ):
            commands.exec_emulator(self.layout.run_id, "arm64-v8a")
        receipt = state.load_owned_runtime_receipt()
        self.assertIs(receipt.phase, state.RuntimePhase.ADB_SEALED)  # type: ignore[union-attr]
        self.assertIsNone(receipt.console_auth_token_identity)  # type: ignore[union-attr]
        close_lock.assert_not_called()
        execve.assert_not_called()

    def test_emulator_exec_never_replaces_an_existing_recovery_receipt(self) -> None:
        receipt = self.create_active_emulator_runtime_receipt()
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(commands, "process_snapshot") as snapshot,
            mock.patch.object(state, "arm_lane_lock_close_on_exec") as close_lock,
            mock.patch.object(commands.os, "execve") as execve,
            self.assertRaisesRegex(
                (commands.AndroidCommandError, state.AndroidRuntimeStateError),
                "not awaiting",
            ),
        ):
            commands.exec_emulator(receipt.run_id, receipt.device_abi)
        snapshot.assert_not_called()
        close_lock.assert_not_called()
        execve.assert_not_called()
        self.assertTrue(state.owned_runtime_receipt_path().exists())

    def test_pending_physical_runtime_receipt_recovers_without_emulator_actions(
        self,
    ) -> None:
        state._write_owned_runtime_receipt(
            state._runtime_recovery_payload(self.load_capability())
        )
        receipt = state.load_owned_runtime_receipt()
        self.assertIsNotNone(receipt)
        self.assertFalse(receipt.emulator_started)  # type: ignore[union-attr]
        self.assertEqual(receipt.device_kind, "physical")  # type: ignore[union-attr]
        self.assertEqual(receipt.expected_serial, "SERIAL123")  # type: ignore[union-attr]
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(commands, "_same_receipt_process") as process,
            mock.patch.object(commands, "_fixed_emulator_paths") as emulator_paths,
            mock.patch.object(commands, "run") as bounded_run,
        ):
            self.assertEqual(commands.recover_owned_runtime(), "stale-retired")
        process.assert_not_called()
        emulator_paths.assert_not_called()
        bounded_run.assert_not_called()
        self.assertFalse(state.owned_runtime_receipt_path().exists())
        self.assertFalse(self.state.exists())
        self.assertFalse(self.snapshot.exists())

    def test_pending_recovery_is_reentrant_across_partial_capability_cleanup(
        self,
    ) -> None:
        for missing in ("adb", "capability", "both"):
            with self.subTest(missing=missing):
                self.create_capability()
                state._write_owned_runtime_receipt(
                    state._runtime_recovery_payload(self.load_capability())
                )
                if missing in {"adb", "both"}:
                    self.snapshot.unlink()
                if missing in {"capability", "both"}:
                    self.state.unlink()
                with (
                    mock.patch.object(state, "validate_lane_lock_descriptor"),
                    mock.patch.object(commands, "run") as bounded_run,
                ):
                    self.assertEqual(commands.recover_owned_runtime(), "stale-retired")
                bounded_run.assert_not_called()
                self.assertFalse(state.owned_runtime_receipt_path().exists())
                self.assertFalse(self.state.exists())
                self.assertFalse(self.snapshot.exists())

    def start_physical_adb_server_receipt(
        self,
        *,
        pid: int = 424242,
    ) -> tuple[state.OwnedRuntimeReceipt, commands.ProcessIdentity]:
        state._write_owned_runtime_receipt(
            state._runtime_recovery_payload(self.load_capability())
        )
        pending = state.load_owned_runtime_receipt()
        self.assertIsNotNone(pending)
        identity = commands.ProcessIdentity(
            pid=pid,
            uid=os.geteuid(),
            started_at=777777,
            started_subsecond=333,
            executable=pathlib.Path(sys.executable).resolve(),
        )
        executable_metadata = identity.executable.stat()
        snapshot_metadata = self.snapshot.stat()
        with mock.patch.object(commands.os, "getpid", return_value=pid):
            with mock.patch.object(state, "validate_lane_lock_descriptor"):
                receipt = state.register_adb_child(
                    pending,  # type: ignore[arg-type]
                    state.AdbChildRegistration(
                        process=identity,
                        initial_executable_device=executable_metadata.st_dev,
                        initial_executable_inode=executable_metadata.st_ino,
                        adb_snapshot_device=snapshot_metadata.st_dev,
                        adb_snapshot_inode=snapshot_metadata.st_ino,
                    ),
                )
        return receipt, identity  # type: ignore[return-value]

    def seal_test_runtime_receipt(
        self, receipt: state.OwnedRuntimeReceipt
    ) -> state.OwnedRuntimeReceipt:
        self.private_adb_directory.chmod(0o500)
        with mock.patch.object(state, "validate_lane_lock_descriptor"):
            sealing = state.begin_adb_seal(receipt, 7)
            sealed = state.complete_adb_seal(sealing)
        return sealed  # type: ignore[return-value]

    def listener_observation(
        self,
        receipt: state.OwnedRuntimeReceipt,
        descriptor: int = 7,
    ) -> OwnedUnixListenerObservation:
        return OwnedUnixListenerObservation(
            pid=receipt.adb_server_pid,
            uid=receipt.uid,
            endpoint=self.load_capability().socket_path,
            descriptors=(OwnedUnixListenerDescriptor(descriptor, None),),
            listener_descriptor=descriptor,
        )

    def test_seal_private_adb_directory_binds_mode_and_receipt_phase(self) -> None:
        receipt, observed = self.start_physical_adb_server_receipt()
        observed = commands.dataclasses.replace(observed, executable=self.snapshot)
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands, "_wait_for_recovery_adb_server", return_value=observed
            ),
            mock.patch.object(
                commands,
                "_capture_recovery_adb_listener",
                return_value=OwnedUnixListenerObservation(
                    pid=receipt.adb_server_pid,
                    uid=receipt.uid,
                    endpoint=self.load_capability().socket_path,
                    descriptors=(
                        OwnedUnixListenerDescriptor(7, None),
                    ),
                    listener_descriptor=7,
                ),
            ),
        ):
            commands.seal_private_adb_directory(self.run_id)
        sealed = state.load_owned_runtime_receipt()
        self.assertIsNotNone(sealed)
        self.assertTrue(sealed.adb_socket_directory_sealed)  # type: ignore[union-attr]
        self.assertEqual(stat.S_IMODE(self.private_adb_directory.stat().st_mode), 0o500)
        self.assertEqual(
            (
                sealed.adb_socket_directory_device,  # type: ignore[union-attr]
                sealed.adb_socket_directory_inode,  # type: ignore[union-attr]
            ),
            (
                self.private_adb_directory.stat().st_dev,
                self.private_adb_directory.stat().st_ino,
            ),
        )

    def test_live_adb_child_is_reconciled_to_sealed_before_clients(self) -> None:
        receipt, observed = self.start_physical_adb_server_receipt()
        observed = commands.dataclasses.replace(observed, executable=self.snapshot)
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands,
                "_capture_recovery_adb_listener",
                return_value=OwnedUnixListenerObservation(
                    pid=receipt.adb_server_pid,
                    uid=receipt.uid,
                    endpoint=self.load_capability().socket_path,
                    descriptors=(
                        OwnedUnixListenerDescriptor(7, None),
                    ),
                    listener_descriptor=7,
                ),
            ),
        ):
            reconciled = commands._reconcile_live_adb_seal(
                self.load_capability(), receipt, observed
            )
        self.assertIs(reconciled.phase, state.RuntimePhase.ADB_SEALED)
        self.assertEqual(stat.S_IMODE(self.private_adb_directory.stat().st_mode), 0o500)

    def test_client_validation_passes_deadline_into_live_seal_reconciliation(
        self,
    ) -> None:
        receipt, observed = self.start_physical_adb_server_receipt()
        observed = commands.dataclasses.replace(observed, executable=self.snapshot)
        capability = self.load_capability()
        deadline = 103.0
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(state, "load_owned_runtime_receipt", return_value=receipt),
            mock.patch.object(commands, "host_boot_identity") as host_identity,
            mock.patch.object(
                commands, "_wait_for_recovery_adb_server", return_value=observed
            ),
            mock.patch.object(
                commands, "_reconcile_live_adb_seal", return_value=receipt
            ) as reconcile,
            mock.patch.object(commands.os.path, "lexists", return_value=True),
            mock.patch.object(commands.time, "monotonic", return_value=100.0),
            mock.patch.object(
                commands,
                "_capture_recovery_adb_listener",
                return_value=self.listener_observation(receipt),
            ),
        ):
            host_identity.return_value = process_identity.HostBootIdentity(
                host=receipt.host_identity,
                boot=receipt.boot_identity,
            )
            commands._validate_owned_adb_server_for_client(
                capability, deadline=deadline
            )
        reconcile.assert_called_once_with(
            capability, receipt, observed, deadline=deadline
        )

    def test_live_seal_reconciliation_recomputes_listener_deadline_budget(
        self,
    ) -> None:
        receipt, observed = self.start_physical_adb_server_receipt()
        observed = commands.dataclasses.replace(observed, executable=self.snapshot)
        listener = self.listener_observation(receipt)
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(commands.time, "monotonic", side_effect=[100.0, 102.0]),
            mock.patch.object(
                commands,
                "_capture_recovery_adb_listener",
                return_value=listener,
            ) as capture,
        ):
            reconciled = commands._reconcile_live_adb_seal(
                self.load_capability(), receipt, observed, deadline=106.0
            )
        self.assertIs(reconciled.phase, state.RuntimePhase.ADB_SEALED)
        self.assertEqual(
            [call.kwargs["timeout_seconds"] for call in capture.call_args_list],
            [5, 4],
        )

    def test_live_seal_reconciliation_rejects_exhausted_listener_budget(
        self,
    ) -> None:
        receipt, observed = self.start_physical_adb_server_receipt()
        observed = commands.dataclasses.replace(observed, executable=self.snapshot)
        with (
            mock.patch.object(commands.time, "monotonic", return_value=102.5),
            mock.patch.object(
                commands, "_capture_recovery_adb_listener"
            ) as capture,
            self.assertRaisesRegex(
                commands.AndroidCommandError, "validation deadline expired"
            ),
        ):
            commands._reconcile_live_adb_seal(
                self.load_capability(), receipt, observed, deadline=103.0
            )
        capture.assert_not_called()

    def test_in_progress_0500_seal_is_completed_before_clients(self) -> None:
        receipt, observed = self.start_physical_adb_server_receipt()
        observed = commands.dataclasses.replace(observed, executable=self.snapshot)
        with mock.patch.object(state, "validate_lane_lock_descriptor"):
            sealing = state.begin_adb_seal(receipt, 7)
        self.private_adb_directory.chmod(0o500)
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands,
                "_capture_recovery_adb_listener",
                return_value=self.listener_observation(receipt),
            ),
        ):
            reconciled = commands._reconcile_live_adb_seal(
                self.load_capability(), sealing, observed
            )
        self.assertIs(reconciled.phase, state.RuntimePhase.ADB_SEALED)
        self.assertEqual(stat.S_IMODE(self.private_adb_directory.stat().st_mode), 0o500)

    def test_in_progress_0700_seal_is_retried_before_clients(self) -> None:
        receipt, observed = self.start_physical_adb_server_receipt()
        observed = commands.dataclasses.replace(observed, executable=self.snapshot)
        with mock.patch.object(state, "validate_lane_lock_descriptor"):
            sealing = state.begin_adb_seal(receipt, 7)
        self.assertEqual(
            stat.S_IMODE(self.private_adb_directory.stat().st_mode),
            0o700,
        )
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands,
                "_capture_recovery_adb_listener",
                return_value=self.listener_observation(sealing),
            ),
        ):
            reconciled = commands._reconcile_live_adb_seal(
                self.load_capability(), sealing, observed
            )
        self.assertIs(reconciled.phase, state.RuntimePhase.ADB_SEALED)
        self.assertEqual(stat.S_IMODE(self.private_adb_directory.stat().st_mode), 0o500)

    def test_sealed_receipt_with_0700_directory_is_resealed_before_clients(
        self,
    ) -> None:
        receipt, observed = self.start_physical_adb_server_receipt()
        observed = commands.dataclasses.replace(observed, executable=self.snapshot)
        sealed = self.seal_test_runtime_receipt(receipt)
        self.private_adb_directory.chmod(0o700)
        with mock.patch.object(
            commands,
            "_capture_recovery_adb_listener",
            return_value=self.listener_observation(sealed),
        ):
            reconciled = commands._reconcile_live_adb_seal(
                self.load_capability(), sealed, observed
            )
        self.assertIs(reconciled.phase, state.RuntimePhase.ADB_SEALED)
        self.assertEqual(stat.S_IMODE(self.private_adb_directory.stat().st_mode), 0o500)

    def test_seal_publication_failure_stays_nonclient_safe_until_reconciled(
        self,
    ) -> None:
        receipt, observed = self.start_physical_adb_server_receipt()
        observed = commands.dataclasses.replace(observed, executable=self.snapshot)
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands, "_wait_for_recovery_adb_server", return_value=observed
            ),
            mock.patch.object(
                commands,
                "_capture_recovery_adb_listener",
                return_value=self.listener_observation(receipt),
            ),
            mock.patch.object(
                state,
                "complete_adb_seal",
                side_effect=OSError("injected receipt publish failure"),
            ),
            self.assertRaisesRegex(commands.AndroidCommandError, "publish failure"),
        ):
            commands.seal_private_adb_directory(self.run_id)
        self.assertEqual(stat.S_IMODE(self.private_adb_directory.stat().st_mode), 0o500)
        pending = state.load_owned_runtime_receipt()
        self.assertIs(pending.phase, state.RuntimePhase.ADB_SEALING)  # type: ignore[union-attr]
        self.assertFalse(pending.adb_socket_directory_sealed)  # type: ignore[union-attr]

    def test_post_publish_seal_failure_never_reopens_a_sealed_directory(self) -> None:
        receipt, observed = self.start_physical_adb_server_receipt()
        observed = commands.dataclasses.replace(observed, executable=self.snapshot)
        complete = state.complete_adb_seal

        def publish_then_fail(receipt: state.OwnedRuntimeReceipt) -> None:
            complete(receipt)
            raise OSError("injected post-publish fsync failure")

        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands, "_wait_for_recovery_adb_server", return_value=observed
            ),
            mock.patch.object(
                commands,
                "_capture_recovery_adb_listener",
                return_value=self.listener_observation(receipt),
            ),
            mock.patch.object(
                state, "complete_adb_seal", side_effect=publish_then_fail
            ),
            self.assertRaisesRegex(commands.AndroidCommandError, "post-publish"),
        ):
            commands.seal_private_adb_directory(self.run_id)
        receipt = state.load_owned_runtime_receipt()
        self.assertIs(receipt.phase, state.RuntimePhase.ADB_SEALED)  # type: ignore[union-attr]
        self.assertEqual(stat.S_IMODE(self.private_adb_directory.stat().st_mode), 0o500)

    def test_live_adb_server_without_socket_fails_closed_and_retains_receipt(
        self,
    ) -> None:
        receipt, observed = self.start_physical_adb_server_receipt()
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands, "_same_receipt_adb_server_process", return_value=observed
            ),
            mock.patch.object(commands.time, "monotonic", side_effect=[0.0, 6.0]),
            mock.patch.object(commands, "run") as bounded_run,
            self.assertRaisesRegex(
                (commands.AndroidCommandError, state.AndroidRuntimeStateError),
                "socket is not ready",
            ),
        ):
            commands.recover_owned_runtime()
        bounded_run.assert_not_called()
        self.assertTrue(state.owned_runtime_receipt_path().exists())
        self.assertTrue(self.state.exists())
        self.assertTrue(self.snapshot.exists())
        self.assertTrue(receipt.adb_server_started)

    def test_dead_or_reused_adb_server_without_socket_is_retired(self) -> None:
        self.start_physical_adb_server_receipt()
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands, "_same_receipt_adb_server_process", return_value=None
            ),
        ):
            self.assertEqual(commands.recover_owned_runtime(), "stale-retired")
        self.assertFalse(state.owned_runtime_receipt_path().exists())
        self.assertFalse(self.state.exists())
        self.assertFalse(self.snapshot.exists())

    def test_adb_socket_wrong_listener_fails_closed_before_protocol_kill(self) -> None:
        receipt, observed = self.start_physical_adb_server_receipt()
        receipt = self.seal_test_runtime_receipt(receipt)
        observed = commands.dataclasses.replace(observed, executable=self.snapshot)
        socket_path = self.private_adb_socket
        real_lstat = pathlib.Path.lstat
        socket_metadata = os.stat(self.root)
        synthetic_socket = os.stat_result(
            (
                stat.S_IFSOCK | 0o600,
                socket_metadata.st_ino,
                socket_metadata.st_dev,
                1,
                os.geteuid(),
                socket_metadata.st_gid,
                0,
                0,
                0,
                0,
            )
        )

        def selective_lstat(path: pathlib.Path) -> os.stat_result:
            if path == socket_path:
                return synthetic_socket
            return real_lstat(path)

        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands, "_same_receipt_adb_server_process", return_value=observed
            ),
            mock.patch.object(commands.os.path, "lexists", return_value=True),
            mock.patch.object(
                pathlib.Path, "lstat", autospec=True, side_effect=selective_lstat
            ),
            mock.patch.object(
                commands,
                "_capture_recovery_adb_listener",
                side_effect=commands.AndroidCommandError("wrong listener pid"),
            ),
            mock.patch.object(commands, "run") as bounded_run,
            self.assertRaisesRegex(
                (commands.AndroidCommandError, state.AndroidRuntimeStateError),
                "wrong listener pid",
            ),
        ):
            commands.recover_owned_runtime()
        bounded_run.assert_not_called()
        self.assertTrue(state.owned_runtime_receipt_path().exists())

    def test_exact_owned_adb_listener_uses_protocol_kill_and_cleans_state(self) -> None:
        receipt, observed = self.start_physical_adb_server_receipt()
        receipt = self.seal_test_runtime_receipt(receipt)
        observed = commands.dataclasses.replace(observed, executable=self.snapshot)
        socket_dir = self.private_adb_directory
        socket_path = socket_dir / "adb.sock"
        transitions = [True, True, False]

        def socket_presence(path: os.PathLike[str] | str) -> bool:
            if pathlib.Path(path) == socket_path:
                return transitions.pop(0) if transitions else False
            return False

        socket_metadata = os.stat(self.root)
        synthetic_socket = os.stat_result(
            (
                stat.S_IFSOCK | 0o600,
                socket_metadata.st_ino,
                socket_metadata.st_dev,
                1,
                os.geteuid(),
                socket_metadata.st_gid,
                0,
                0,
                0,
                0,
            )
        )
        real_lstat = pathlib.Path.lstat
        real_rmdir = pathlib.Path.rmdir

        def selective_lstat(path: pathlib.Path) -> os.stat_result:
            if path == socket_path:
                return synthetic_socket
            return real_lstat(path)

        def selective_rmdir(path: pathlib.Path) -> None:
            if path != socket_dir:
                real_rmdir(path)

        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands,
                "_same_receipt_adb_server_process",
                side_effect=[observed, None, None],
            ),
            mock.patch.object(commands.os.path, "lexists", side_effect=socket_presence),
            mock.patch.object(
                pathlib.Path, "lstat", autospec=True, side_effect=selective_lstat
            ),
            mock.patch.object(
                commands,
                "_capture_recovery_adb_listener",
                return_value=self.listener_observation(receipt),
            ),
            mock.patch.object(
                commands, "run", return_value=BoundedResult(0)
            ) as bounded_run,
            mock.patch.object(
                pathlib.Path, "rmdir", autospec=True, side_effect=selective_rmdir
            ),
        ):
            self.assertEqual(commands.recover_owned_runtime(), "stale-retired")
        bounded_run.assert_called_once()
        self.assertFalse(state.owned_runtime_receipt_path().exists())
        self.assertFalse(self.state.exists())
        self.assertFalse(self.snapshot.exists())

    def test_dead_adb_server_stale_socket_is_unlinked_offline_without_protocol(
        self,
    ) -> None:
        receipt, _observed = self.start_physical_adb_server_receipt()
        receipt = self.seal_test_runtime_receipt(receipt)
        socket_dir = self.private_adb_directory
        socket_path = socket_dir / "adb.sock"
        present = True
        metadata = os.stat(self.root)
        synthetic_socket = os.stat_result(
            (
                stat.S_IFSOCK | 0o600,
                metadata.st_ino,
                metadata.st_dev,
                1,
                os.geteuid(),
                metadata.st_gid,
                0,
                0,
                0,
                0,
            )
        )
        real_lstat = pathlib.Path.lstat
        real_unlink = pathlib.Path.unlink
        real_rmdir = pathlib.Path.rmdir

        def path_exists(path: os.PathLike[str] | str) -> bool:
            return present if pathlib.Path(path) == socket_path else False

        def path_lstat(path: pathlib.Path) -> os.stat_result:
            if path == socket_path:
                return synthetic_socket
            return real_lstat(path)

        def path_unlink(path: pathlib.Path, *args: object, **kwargs: object) -> None:
            nonlocal present
            if path == socket_path:
                present = False
                return
            real_unlink(path, *args, **kwargs)

        def path_rmdir(path: pathlib.Path) -> None:
            if path != socket_dir:
                real_rmdir(path)

        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands, "_same_receipt_adb_server_process", return_value=None
            ),
            mock.patch.object(commands.os.path, "lexists", side_effect=path_exists),
            mock.patch.object(
                pathlib.Path, "lstat", autospec=True, side_effect=path_lstat
            ),
            mock.patch.object(
                pathlib.Path, "unlink", autospec=True, side_effect=path_unlink
            ),
            mock.patch.object(
                pathlib.Path, "rmdir", autospec=True, side_effect=path_rmdir
            ),
            mock.patch.object(
                commands, "_capture_recovery_adb_listener", return_value=None
            ),
            mock.patch.object(commands, "run") as bounded_run,
        ):
            self.assertEqual(commands.recover_owned_runtime(), "stale-retired")
        bounded_run.assert_not_called()
        self.assertFalse(present)
        self.assertFalse(state.owned_runtime_receipt_path().exists())
        self.assertFalse(self.state.exists())
        self.assertFalse(self.snapshot.exists())

    def test_socket_disappearance_without_server_exit_preserves_recovery_state(
        self,
    ) -> None:
        receipt, observed = self.start_physical_adb_server_receipt()
        receipt = self.seal_test_runtime_receipt(receipt)
        observed = commands.dataclasses.replace(observed, executable=self.snapshot)
        socket_path = self.private_adb_socket
        transitions = [True, True, False]
        metadata = os.stat(self.root)
        synthetic_socket = os.stat_result(
            (
                stat.S_IFSOCK | 0o600,
                metadata.st_ino,
                metadata.st_dev,
                1,
                os.geteuid(),
                metadata.st_gid,
                0,
                0,
                0,
                0,
            )
        )
        real_lstat = pathlib.Path.lstat

        def path_exists(path: os.PathLike[str] | str) -> bool:
            if pathlib.Path(path) == socket_path:
                return transitions.pop(0) if transitions else False
            return False

        def path_lstat(path: pathlib.Path) -> os.stat_result:
            return synthetic_socket if path == socket_path else real_lstat(path)

        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands,
                "_same_receipt_adb_server_process",
                side_effect=[observed, observed],
            ),
            mock.patch.object(commands.os.path, "lexists", side_effect=path_exists),
            mock.patch.object(
                pathlib.Path, "lstat", autospec=True, side_effect=path_lstat
            ),
            mock.patch.object(
                commands,
                "_capture_recovery_adb_listener",
                return_value=self.listener_observation(receipt),
            ),
            mock.patch.object(commands, "run", return_value=BoundedResult(0)),
            mock.patch.object(commands.time, "monotonic", side_effect=[0.0, 0.0, 16.0]),
            self.assertRaisesRegex(
                (commands.AndroidCommandError, state.AndroidRuntimeStateError),
                "did not exit",
            ),
        ):
            commands.recover_owned_runtime()
        self.assertTrue(state.owned_runtime_receipt_path().exists())
        self.assertTrue(self.state.exists())
        self.assertTrue(self.snapshot.exists())

    def test_normal_physical_runtime_retirement_requires_completed_adb_cleanup(
        self,
    ) -> None:
        state._write_owned_runtime_receipt(
            state._runtime_recovery_payload(self.load_capability())
        )
        receipt = state.load_owned_runtime_receipt()
        self.assertIsNotNone(receipt)
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            self.assertRaisesRegex(
                (commands.AndroidCommandError, state.AndroidRuntimeStateError),
                "adb resources remain",
            ),
        ):
            commands.retire_stopped_owned_runtime(self.run_id)
        state.retire_recovery_capability(
            self.layout,
            receipt,  # type: ignore[arg-type]
        )
        self.private_adb_directory.rmdir()
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(commands, "probe_adb_loopback_absence") as probe,
            mock.patch.object(state, "record_post_cleanup_adb_isolation_checkpoint") as post,
        ):
            commands.retire_stopped_owned_runtime(self.run_id)
        probe.assert_not_called()
        post.assert_not_called()
        self.assertFalse(state.owned_runtime_receipt_path().exists())

    def test_live_private_adb_socket_without_snapshot_fails_closed(self) -> None:
        state._write_owned_runtime_receipt(
            state._runtime_recovery_payload(self.load_capability())
        )
        self.snapshot.unlink()
        socket_directory = self.private_adb_directory
        socket_path = socket_directory / "adb.sock"
        endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(endpoint.close)
        endpoint.bind(str(socket_path))

        def local_socket_identity(_nonce: str) -> tuple[str, str]:
            return f"localfilesystem:{socket_path}", str(socket_path)

        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                state, "_server_socket_identity", side_effect=local_socket_identity
            ),
            mock.patch.object(commands, "run") as bounded_run,
            self.assertRaisesRegex(
                (commands.AndroidCommandError, state.AndroidRuntimeStateError),
                "lacks its started server receipt",
            ),
        ):
            commands.recover_owned_runtime()
        bounded_run.assert_not_called()
        self.assertTrue(state.owned_runtime_receipt_path().exists())
        self.assertTrue(self.state.exists())

    def test_old_boot_recovery_is_offline_only_and_skips_current_sdk_paths(
        self,
    ) -> None:
        receipt = self.create_active_emulator_runtime_receipt(
            boot_identity="prior-boot"
        )
        receipt.launcher_path.unlink()  # type: ignore[union-attr]
        receipt.backend_path.unlink()  # type: ignore[union-attr]
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(commands, "_same_receipt_process") as process,
            mock.patch.object(commands, "_fixed_emulator_paths") as emulator_paths,
            mock.patch.object(commands, "run") as bounded_run,
            mock.patch.object(commands, "capture_stdout") as capture,
        ):
            self.assertEqual(commands.recover_owned_runtime(), "stale-retired")
        process.assert_not_called()
        emulator_paths.assert_not_called()
        bounded_run.assert_not_called()
        capture.assert_not_called()
        self.assertFalse(state.owned_runtime_receipt_path().exists())
        self.assertFalse(self.state.exists())
        self.assertFalse(self.snapshot.exists())

    def test_old_boot_missing_origin_checkout_retires_account_receipt_offline(
        self,
    ) -> None:
        missing_checkout = self.root / "deleted-checkout"
        self.create_active_emulator_runtime_receipt(
            boot_identity="prior-boot",
            repository_root=str(missing_checkout),
        )
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(commands, "_same_receipt_process") as emulator_process,
            mock.patch.object(
                commands, "_same_receipt_adb_server_process"
            ) as server_process,
            mock.patch.object(commands, "run") as bounded_run,
            mock.patch.object(commands, "capture_stdout") as capture,
        ):
            self.assertEqual(commands.recover_owned_runtime(), "stale-retired")
        emulator_process.assert_not_called()
        server_process.assert_not_called()
        bounded_run.assert_not_called()
        capture.assert_not_called()
        self.assertFalse(state.owned_runtime_receipt_path().exists())
        self.assertTrue(self.state.exists())
        self.assertTrue(self.snapshot.exists())

    def test_recovery_uses_receipt_repository_after_checkout_changes(self) -> None:
        state._write_owned_runtime_receipt(
            state._runtime_recovery_payload(self.load_capability())
        )
        other_repository = self.root / "other-checkout"
        other_target = other_repository / "target"
        other_runs = other_target / state.RUNS_ROOT_LEAF
        other_runs.mkdir(parents=True, mode=0o700)
        marker = other_runs / "unrelated"
        marker.write_bytes(b"untouched")
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(state, "REPOSITORY_ROOT", other_repository),
            mock.patch.object(state, "TARGET_ROOT", other_target),
            mock.patch.object(state, "RUNS_ROOT", other_runs),
        ):
            self.assertEqual(commands.recover_owned_runtime(), "stale-retired")
        self.assertEqual(marker.read_bytes(), b"untouched")
        self.assertFalse(state.owned_runtime_receipt_path().exists())

    def test_recovery_retires_only_dead_or_pid_reused_receipts(self) -> None:
        receipt = self.create_active_emulator_runtime_receipt(pid=424242)
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands,
                "_fixed_emulator_paths",
                return_value=(receipt.launcher_path, receipt.backend_path),
            ),
            mock.patch.object(
                commands,
                "process_snapshot",
                side_effect=commands.ProcessIdentityError("missing"),
            ),
            mock.patch.object(commands.os, "kill", side_effect=ProcessLookupError),
            mock.patch.object(commands, "_finish_recovery_resources") as finish,
        ):
            self.assertEqual(commands.recover_owned_runtime(), "stale-retired")
        finish.assert_called_once_with(self.layout, mock.ANY, receipt)
        self.assertFalse(state.owned_runtime_receipt_path().exists())

        receipt = self.create_active_emulator_runtime_receipt(pid=424242)
        reused = commands.ProcessIdentity(
            pid=424242,
            uid=os.geteuid(),
            started_at=999999,
            started_subsecond=0,
            executable=receipt.backend_path,
        )
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands,
                "_fixed_emulator_paths",
                return_value=(receipt.launcher_path, receipt.backend_path),
            ),
            mock.patch.object(commands, "process_snapshot", return_value=reused),
            mock.patch.object(commands, "_finish_recovery_resources") as finish,
        ):
            self.assertEqual(commands.recover_owned_runtime(), "stale-retired")
        finish.assert_called_once_with(self.layout, mock.ANY, receipt)
        self.assertFalse(state.owned_runtime_receipt_path().exists())

    def test_dead_current_boot_emulator_skips_removed_sdk_backend(self) -> None:
        receipt = self.create_active_emulator_runtime_receipt(pid=424242)
        receipt.launcher_path.unlink()  # type: ignore[union-attr]
        receipt.backend_path.unlink()  # type: ignore[union-attr]
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(commands, "_same_receipt_process", return_value=None),
            mock.patch.object(
                commands, "_same_receipt_adb_server_process", return_value=None
            ),
            mock.patch.object(commands, "_fixed_emulator_paths") as emulator_paths,
            mock.patch.object(commands, "run") as bounded_run,
        ):
            self.assertEqual(commands.recover_owned_runtime(), "stale-retired")
        emulator_paths.assert_not_called()
        bounded_run.assert_not_called()
        self.assertFalse(state.owned_runtime_receipt_path().exists())
        self.assertFalse(self.state.exists())
        self.assertFalse(self.snapshot.exists())

    def test_missing_current_boot_origin_retires_only_when_both_processes_absent(
        self,
    ) -> None:
        missing_checkout = self.root / "deleted-checkout"
        self.create_active_emulator_runtime_receipt(
            pid=424242,
            repository_root=str(missing_checkout),
        )
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(commands, "_same_receipt_process", return_value=None),
            mock.patch.object(
                commands, "_same_receipt_adb_server_process", return_value=None
            ),
            mock.patch.object(commands, "run") as bounded_run,
        ):
            self.assertEqual(commands.recover_owned_runtime(), "stale-retired")
        bounded_run.assert_not_called()
        self.assertFalse(state.owned_runtime_receipt_path().exists())
        self.assertTrue(self.state.exists())
        self.assertTrue(self.snapshot.exists())

        receipt = self.create_active_emulator_runtime_receipt(
            pid=424242,
            repository_root=str(missing_checkout),
        )
        observed = commands.ProcessIdentity(
            pid=receipt.pid,
            uid=receipt.uid,
            started_at=receipt.started_at,
            started_subsecond=receipt.started_subsecond,
            executable=pathlib.Path(sys.executable).resolve(),
        )
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands,
                "probe_adb_loopback_absence",
                return_value=commands.runtime_state.AdbIsolationObservation(),
            ),
            mock.patch.object(commands, "_same_receipt_process", return_value=observed),
            self.assertRaisesRegex(
                (commands.AndroidCommandError, state.AndroidRuntimeStateError),
                "emulator is live",
            ),
        ):
            commands.recover_owned_runtime()
        self.assertTrue(state.owned_runtime_receipt_path().exists())

    def test_recovery_preserves_receipt_when_live_identity_is_unreadable(self) -> None:
        receipt = self.create_active_emulator_runtime_receipt(pid=424242)
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands,
                "probe_adb_loopback_absence",
                return_value=commands.runtime_state.AdbIsolationObservation(),
            ),
            mock.patch.object(
                commands,
                "_fixed_emulator_paths",
                return_value=(receipt.launcher_path, receipt.backend_path),
            ),
            mock.patch.object(
                commands,
                "process_snapshot",
                side_effect=commands.ProcessIdentityError("denied"),
            ),
            mock.patch.object(commands.os, "kill", return_value=None),
            self.assertRaisesRegex(
                (commands.AndroidCommandError, state.AndroidRuntimeStateError),
                "still exists",
            ),
        ):
            commands.recover_owned_runtime()
        self.assertTrue(state.owned_runtime_receipt_path().exists())

    def test_normal_retirement_requires_matching_run_and_stopped_process(self) -> None:
        receipt = self.create_active_emulator_runtime_receipt()
        observed = commands.ProcessIdentity(
            pid=receipt.pid,
            uid=receipt.uid,
            started_at=receipt.started_at,
            started_subsecond=receipt.started_subsecond,
            executable=receipt.backend_path,
        )
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(commands, "_same_receipt_process", return_value=observed),
            mock.patch.object(
                commands,
                "_fixed_emulator_paths",
                return_value=(receipt.launcher_path, receipt.backend_path),
            ),
            self.assertRaisesRegex(
                (commands.AndroidCommandError, state.AndroidRuntimeStateError),
                "still live",
            ),
        ):
            commands.retire_stopped_owned_runtime(receipt.run_id)
        self.assertTrue(state.owned_runtime_receipt_path().exists())
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(commands, "_same_receipt_process", return_value=None),
            self.assertRaisesRegex(
                (commands.AndroidCommandError, state.AndroidRuntimeStateError),
                "different run",
            ),
        ):
            commands.retire_stopped_owned_runtime("f" * 32)
        self.assertTrue(state.owned_runtime_receipt_path().exists())
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(commands, "_same_receipt_process", return_value=None),
            self.assertRaisesRegex(
                (commands.AndroidCommandError, state.AndroidRuntimeStateError),
                "adb resources remain",
            ),
        ):
            commands.retire_stopped_owned_runtime(receipt.run_id)
        self.assertTrue(state.owned_runtime_receipt_path().exists())
        state.retire_recovery_capability(self.layout, receipt)
        self.private_adb_directory.rmdir()

        def checkpoint_before_retirement(
            exact_receipt: state.OwnedRuntimeReceipt,
        ) -> None:
            self.assertEqual(exact_receipt.snapshot_sha256, receipt.snapshot_sha256)
            self.assertTrue(state.owned_runtime_receipt_path().exists())

        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(commands, "_same_receipt_process", return_value=None),
            mock.patch.object(
                state,
                "record_post_cleanup_adb_isolation_checkpoint",
                side_effect=checkpoint_before_retirement,
            ) as checkpoint,
        ):
            commands.retire_stopped_owned_runtime(receipt.run_id)
        checkpoint.assert_called_once_with(receipt)
        self.assertFalse(state.owned_runtime_receipt_path().exists())

    def test_failed_retirement_requires_primary_failure_and_omits_checkpoints(
        self,
    ) -> None:
        receipt = self.create_active_emulator_runtime_receipt()
        with self.assertRaisesRegex(
            commands.AndroidCommandError,
            "nonzero primary exit status",
        ):
            commands.retire_failed_stopped_owned_runtime(receipt.run_id, 0)
        self.assertTrue(state.owned_runtime_receipt_path().exists())
        observed = commands.ProcessIdentity(
            pid=receipt.pid,
            uid=receipt.uid,
            started_at=receipt.started_at,
            started_subsecond=receipt.started_subsecond,
            executable=receipt.backend_path,
        )
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands,
                "_same_receipt_process",
                return_value=observed,
            ),
            self.assertRaisesRegex(
                commands.AndroidCommandError,
                "still live",
            ),
        ):
            commands.retire_failed_stopped_owned_runtime(receipt.run_id, 1)
        self.assertTrue(state.owned_runtime_receipt_path().exists())

        state.retire_recovery_capability(self.layout, receipt)
        self.private_adb_directory.rmdir()
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(commands, "_same_receipt_process", return_value=None),
            mock.patch.object(
                commands,
                "_same_receipt_adb_server_process",
                return_value=None,
            ),
            mock.patch.object(
                state,
                "record_post_cleanup_adb_isolation_checkpoint",
            ) as checkpoint,
        ):
            commands.retire_failed_stopped_owned_runtime(receipt.run_id, 1)
        checkpoint.assert_not_called()
        self.assertFalse(
            self.proof.joinpath("adb-isolation-runtime-post-cleanup.json").exists()
        )
        self.assertFalse(state.owned_runtime_receipt_path().exists())

    def test_failed_retirement_cli_emits_only_the_failed_marker(self) -> None:
        output = io.StringIO()
        with (
            mock.patch.object(
                commands,
                "retire_failed_stopped_owned_runtime",
            ) as retire,
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(
                commands.main(
                    [
                        "retire-failed-runtime",
                        "--run-id",
                        self.run_id,
                        "--primary-exit-status",
                        "17",
                    ]
                ),
                0,
            )
        retire.assert_called_once_with(self.run_id, 17)
        self.assertEqual(
            output.getvalue(),
            "ANDROID_FAILED_RUNTIME_RECEIPT_RETIRED primary_exit_status=17\n",
        )
        self.assertNotIn("ANDROID_OWNED_RUNTIME_RECEIPT_RETIRED", output.getvalue())

    def test_recovery_requires_exact_avd_name_before_console_kill(self) -> None:
        receipt = self.create_active_emulator_runtime_receipt()
        with mock.patch.object(
            commands,
            "_emulator_console_exchange",
            return_value=(
                receipt.avd_name.encode("ascii") + b"\nOK\n"
            ),
        ):
            commands._verify_owned_emulator_console_name(mock.ANY, receipt)
        for response, message in (
            (b"Other_AVD\nOK\n", "exact match"),
            (f"{receipt.avd_name}\nKO\n".encode("ascii"), "exact match"),
            (b"", "exact match"),
            (b"auth secret\n", "exact match"),
        ):
            with (
                mock.patch.object(
                    commands,
                    "_emulator_console_exchange",
                    return_value=response,
                ),
                self.assertRaisesRegex(
                    (commands.AndroidCommandError, state.AndroidRuntimeStateError),
                    message,
                ),
            ):
                commands._verify_owned_emulator_console_name(mock.ANY, receipt)

    def test_recovery_rechecks_identity_and_listeners_before_shutdown(self) -> None:
        receipt = self.create_active_emulator_runtime_receipt()
        capability = self.load_capability()
        observed = commands.ProcessIdentity(
            pid=receipt.pid,
            uid=receipt.uid,
            started_at=receipt.started_at,
            started_subsecond=receipt.started_subsecond,
            executable=receipt.backend_path,
        )
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands,
                "probe_adb_loopback_absence",
                return_value=commands.runtime_state.AdbIsolationObservation(),
            ),
            mock.patch.object(
                commands,
                "_same_receipt_process",
                side_effect=[observed, None],
            ),
            mock.patch.object(
                commands,
                "_validate_recovery_receipt",
                return_value=commands.RecoveryContext(
                    layout=self.layout,
                    capability=capability,
                    launcher=receipt.launcher_path,
                    backend=receipt.backend_path,
                    current_boot=True,
                ),
            ),
            mock.patch.object(
                commands, "_wait_for_recovery_backend", return_value=observed
            ),
            mock.patch.object(commands, "_verify_recovery_listeners") as listeners,
            mock.patch.object(commands, "_verify_owned_emulator_console_name"),
            mock.patch.object(
                commands, "_request_owned_emulator_console_shutdown"
            ) as shutdown,
            self.assertRaisesRegex(
                (commands.AndroidCommandError, state.AndroidRuntimeStateError),
                "identity changed",
            ),
        ):
            commands.recover_owned_runtime()
        listeners.assert_called_once()
        shutdown.assert_not_called()
        self.assertTrue(state.owned_runtime_receipt_path().exists())

    def test_live_emulator_recovers_after_receipt_bound_adb_server_dies(self) -> None:
        receipt = self.create_active_emulator_runtime_receipt()
        observed = commands.ProcessIdentity(
            pid=receipt.pid,
            uid=receipt.uid,
            started_at=receipt.started_at,
            started_subsecond=receipt.started_subsecond,
            executable=receipt.backend_path,
        )
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands,
                "probe_adb_loopback_absence",
                return_value=commands.runtime_state.AdbIsolationObservation(),
            ),
            mock.patch.object(commands, "_same_receipt_process", return_value=observed),
            mock.patch.object(
                commands, "_same_receipt_adb_server_process", return_value=None
            ),
            mock.patch.object(
                commands,
                "_fixed_emulator_paths",
                return_value=(receipt.launcher_path, receipt.backend_path),
            ),
            mock.patch.object(
                commands, "_request_verified_owned_emulator_stop"
            ) as stop,
            mock.patch.object(commands, "_wait_for_recovered_emulator_exit"),
            mock.patch.object(commands, "run") as adb_protocol,
        ):
            self.assertEqual(commands.recover_owned_runtime(), "recovered")
        stop.assert_called_once_with(mock.ANY, receipt)
        adb_protocol.assert_not_called()
        self.assertFalse(state.owned_runtime_receipt_path().exists())
        self.assertFalse(self.state.exists())
        self.assertFalse(self.snapshot.exists())

    def test_console_token_is_private_and_sent_only_after_fresh_peer_recheck(
        self,
    ) -> None:
        receipt = self.create_active_emulator_runtime_receipt()
        capability = self.load_capability()
        context = commands.RecoveryContext(
            layout=self.layout,
            capability=capability,
            launcher=receipt.launcher_path,
            backend=receipt.backend_path,
            current_boot=True,
        )
        observed = commands.ProcessIdentity(
            pid=receipt.pid,
            uid=receipt.uid,
            started_at=receipt.started_at,
            started_subsecond=receipt.started_subsecond,
            executable=receipt.backend_path,
        )
        token_path = self.root / ".emulator_console_auth_token"
        token_path.write_bytes(b"private-token\n")
        token_path.chmod(0o600)
        token, token_identity = commands._emulator_console_auth_token()
        self.assertEqual(token, b"private-token")
        self.assertEqual(token_identity.device, token_path.stat().st_dev)
        self.assertEqual(token_identity.inode, token_path.stat().st_ino)
        self.assertEqual(
            token_identity.sha256,
            hashlib.sha256(token_path.read_bytes()).hexdigest(),
        )
        token_path.chmod(0o644)
        with self.assertRaisesRegex(
            (commands.AndroidCommandError, state.AndroidRuntimeStateError),
            "private regular",
        ):
            commands._emulator_console_auth_token()
        token_path.chmod(0o600)
        if sys.platform == "darwin":
            subprocess.run(
                ["/bin/chmod", "+a", "everyone allow read", str(token_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
            try:
                with self.assertRaisesRegex(
                    (commands.AndroidCommandError, state.AndroidRuntimeStateError),
                    "allow ACL",
                ):
                    commands._emulator_console_auth_token()
            finally:
                subprocess.run(
                    ["/bin/chmod", "-N", str(token_path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                )

        order: list[str] = []

        class Console:
            def __enter__(self) -> Console:
                order.append("connect")
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def settimeout(self, _seconds: int) -> None:
                order.append("timeout")
                return None

            def sendall(self, data: bytes) -> None:
                self.asserted_data = data
                order.append("send")

        console = Console()
        response = (
            commands._emulator_console_authenticated_prefix()
            + b"OK: killing emulator, bye bye\n"
        )
        with (
            mock.patch.object(
                commands.socket, "create_connection", return_value=console
            ),
            mock.patch.object(
                commands,
                "_same_receipt_process",
                side_effect=lambda _receipt: (order.append("process"), observed)[1],
            ),
            mock.patch.object(
                commands,
                "_verify_recovery_listeners",
                side_effect=lambda **_kwargs: order.append("listeners"),
            ),
            mock.patch.object(
                commands,
                "_emulator_console_auth_token",
                side_effect=lambda expected: (
                    order.append("token"),
                    (b"private-token", expected),
                )[1],
            ),
            mock.patch.object(
                commands, "_receive_emulator_console", return_value=response
            ) as receive,
        ):
            commands._request_owned_emulator_console_shutdown(context, receipt)
        self.assertEqual(order, ["connect", "process", "listeners", "token", "send"])
        self.assertEqual(console.asserted_data, b"auth private-token\nkill\n")
        receive.assert_called_once_with(
            console,
            expected_responses=(
                commands._emulator_console_authenticated_prefix()
                + b"OK: killing emulator, bye bye\n",
            ),
        )

        order.clear()
        with (
            mock.patch.object(
                commands.socket, "create_connection", return_value=console
            ),
            mock.patch.object(
                commands,
                "_same_receipt_process",
                side_effect=lambda _receipt: (order.append("process"), observed)[1],
            ),
            mock.patch.object(
                commands,
                "_verify_recovery_listeners",
                side_effect=lambda **_kwargs: order.append("listeners"),
            ),
            mock.patch.object(
                commands,
                "_emulator_console_auth_token",
                side_effect=lambda expected: (
                    order.append("token"),
                    (b"private-token", expected),
                )[1],
            ),
            mock.patch.object(commands.time, "monotonic", return_value=100.0),
            mock.patch.object(
                commands, "_receive_emulator_console", return_value=response
            ) as receive,
        ):
            commands._emulator_console_exchange(
                context, receipt, b"kill\n", deadline=103.0
            )
        self.assertEqual(
            order,
            ["connect", "process", "listeners", "token", "timeout", "send"],
        )
        receive.assert_called_once_with(
            console,
            expected_responses=(
                commands._emulator_console_authenticated_prefix()
                + b"OK: killing emulator, bye bye\n",
            ),
            deadline=103.0,
        )

        with mock.patch.object(
            commands,
            "_emulator_console_exchange",
            return_value=b"OK: killing emulator, bye bye\n",
        ):
            commands._request_owned_emulator_console_shutdown(context, receipt)
        for payload in (
            b"OK: killing emulator, bye bye",
            b"OK: killing emulator, bye bye\nOK\n",
            b"KO: kill refused\n",
            b"OK: killing emulator, bye bye\nOK\nextra\n",
            b"garbage\nOK: killing emulator, bye bye\n",
            b"OK\n",
        ):
            with (
                self.subTest(rejected_payload=payload),
                mock.patch.object(
                    commands,
                    "_emulator_console_exchange",
                    return_value=payload,
                ),
                self.assertRaisesRegex(
                    commands.AndroidCommandError,
                    "rejected its authenticated shutdown request",
                ),
            ):
                commands._request_owned_emulator_console_shutdown(context, receipt)

    def test_console_authentication_framing_is_exact(self) -> None:
        marker = commands.EMULATOR_CONSOLE_AUTHENTICATED_MARKER
        prefix = commands._emulator_console_authenticated_prefix()
        payload = b"OK: killing emulator, bye bye\nOK\n"
        self.assertEqual(
            prefix,
            commands.EMULATOR_CONSOLE_AUTHENTICATION_BANNER_PREFIX
            + os.fsencode(state.ACCOUNT_HOME / ".emulator_console_auth_token")
            + b"'"
            + marker,
        )
        self.assertEqual(
            commands._authenticated_emulator_console_payload(
                prefix + payload
            ),
            payload,
        )
        for response in (
            marker + payload,
            b"Android Console: Authentication required" + marker + payload,
            prefix.replace(b".emulator_console_auth_token", b"other-token")
            + payload,
            prefix + b"garbage\n" + marker + payload,
        ):
            with (
                self.subTest(response=response),
                self.assertRaisesRegex(
                    commands.AndroidCommandError,
                    "authentication response was not exact",
                ),
            ):
                commands._authenticated_emulator_console_payload(response)

    def test_console_terminal_frames_are_fixed_by_command_and_receipt(self) -> None:
        receipt = self.create_active_emulator_runtime_receipt()
        prefix = commands._emulator_console_authenticated_prefix()
        self.assertEqual(
            commands._expected_emulator_console_responses(
                receipt,
                b"avd name\nquit\n",
            ),
            (prefix + receipt.avd_name.encode("ascii") + b"\nOK\n",),
        )
        self.assertEqual(
            commands._expected_emulator_console_responses(receipt, b"kill\n"),
            (prefix + b"OK: killing emulator, bye bye\n",),
        )
        with self.assertRaisesRegex(
            commands.AndroidCommandError,
            "command is outside the fixed set",
        ):
            commands._expected_emulator_console_responses(
                receipt,
                b"poweroff\n",
            )

    def test_console_terminal_frames_include_the_complete_official_auth_banner(
        self,
    ) -> None:
        receipt = self.create_active_emulator_runtime_receipt()
        with mock.patch.object(state, "ACCOUNT_HOME", pathlib.Path("/home/runner")):
            banner = (
                b"Android Console: Authentication required\n"
                b"Android Console: type 'auth <auth_token>' to authenticate\n"
                b"Android Console: you can find your <auth_token> in \n"
                b"'/home/runner/.emulator_console_auth_token'\nOK\n"
                b"Android Console: type 'help' for a list of commands\nOK\n"
            )
            self.assertEqual(
                commands._expected_emulator_console_responses(
                    receipt,
                    b"avd name\nquit\n",
                ),
                (banner + receipt.avd_name.encode("ascii") + b"\nOK\n",),
            )
            self.assertEqual(
                commands._expected_emulator_console_responses(receipt, b"kill\n"),
                (banner + b"OK: killing emulator, bye bye\n",),
            )

        for unsafe_home in (
            pathlib.Path("relative-home"),
            pathlib.Path("/tmp/account'with-quote"),
            pathlib.Path("/tmp/account\0with-nul"),
            pathlib.Path("/tmp/account\rwith-return"),
            pathlib.Path("/tmp/account\nwith-newline"),
            pathlib.Path("/" + ("a" * 4096)),
        ):
            with (
                self.subTest(unsafe_home=unsafe_home),
                mock.patch.object(state, "ACCOUNT_HOME", unsafe_home),
                self.assertRaisesRegex(
                    commands.AndroidCommandError,
                    "token path bytes are invalid",
                ),
            ):
                commands._expected_emulator_console_responses(receipt, b"kill\n")

    def test_console_receive_stops_at_exact_terminal_frame_without_waiting_for_eof(
        self,
    ) -> None:
        class ChunksThen:
            def __init__(self, chunks: list[bytes], failure: BaseException) -> None:
                self.chunks = list(chunks)
                self.failure = failure
                self.calls = 0
                self.timeouts: list[float] = []

            def settimeout(self, seconds: float) -> None:
                self.timeouts.append(seconds)

            def recv(self, _maximum: int) -> bytes:
                self.calls += 1
                if self.chunks:
                    return self.chunks.pop(0)
                raise self.failure

        acknowledgement = b"OK: killing emulator, bye bye\n"
        fragmented = ChunksThen(
            [b"OK: killing emulator,", b" bye bye\r", b"\n"],
            TimeoutError("must not wait for EOF"),
        )
        self.assertEqual(
            commands._receive_emulator_console(
                fragmented,
                expected_responses=(acknowledgement,),
            ),
            acknowledgement,
        )
        self.assertEqual(fragmented.calls, 3)

        trailing = ChunksThen(
            [b"OK: killing emulator, bye bye\nextra\n"],
            AssertionError("unreachable"),
        )
        self.assertEqual(
            commands._receive_emulator_console(
                trailing,
                expected_responses=(acknowledgement,),
            ),
            acknowledgement,
        )
        self.assertEqual(trailing.calls, 1)

        incomplete_timeout = ChunksThen(
            [b"OK: killing emulator,"],
            TimeoutError("fixture timeout"),
        )

        with self.assertRaisesRegex(
            commands.AndroidCommandError,
            "response timed out",
        ):
            commands._receive_emulator_console(
                incomplete_timeout,
                expected_responses=(acknowledgement,),
            )

        incomplete_reset = ChunksThen(
            [b"OK: killing emulator,"],
            ConnectionResetError(errno.ECONNRESET, "fixture reset"),
        )
        with self.assertRaisesRegex(
            commands.AndroidCommandError,
            "ended before its terminal frame",
        ):
            commands._receive_emulator_console(
                incomplete_reset,
                expected_responses=(acknowledgement,),
            )

        with self.assertRaisesRegex(
            commands.AndroidCommandError,
            "response contract is invalid",
        ):
            commands._receive_emulator_console(
                mock.sentinel.socket,
                expected_responses=(b"x" * 16,),
                maximum=16,
            )

        invalid_prefix = ChunksThen(
            [b"NO\n"],
            AssertionError("unreachable"),
        )
        with self.assertRaisesRegex(
            commands.AndroidCommandError,
            "outside its exact grammar",
        ):
            commands._receive_emulator_console(
                invalid_prefix,
                expected_responses=(acknowledgement,),
            )

        oversized = ChunksThen(
            [b"x" * 17],
            AssertionError("unreachable"),
        )
        with self.assertRaisesRegex(
            commands.AndroidCommandError,
            "exceeded its fixed bound",
        ):
            commands._receive_emulator_console(
                oversized,
                expected_responses=(b"x\n",),
                maximum=16,
            )

        with self.assertRaisesRegex(
            commands.AndroidCommandError,
            "terminal frames must not overlap",
        ):
            commands._receive_emulator_console(
                mock.sentinel.socket,
                expected_responses=(b"OK\n", b"OK\nextra\n"),
            )

    def test_console_receive_is_chunk_invariant_for_full_protocol_frames(
        self,
    ) -> None:
        class ChunksThenTimeout:
            def __init__(self, chunks: list[bytes]) -> None:
                self.chunks = list(chunks)
                self.calls = 0
                self.timeouts: list[float] = []

            def settimeout(self, seconds: float) -> None:
                self.timeouts.append(seconds)

            def recv(self, _maximum: int) -> bytes:
                self.calls += 1
                if self.chunks:
                    return self.chunks.pop(0)
                raise TimeoutError("terminal frame must finish the read")

        receipt = self.create_active_emulator_runtime_receipt()
        for command in (b"avd name\nquit\n", b"kill\n"):
            expected = commands._expected_emulator_console_responses(
                receipt,
                command,
            )[0]
            wire = expected.replace(b"\n", b"\r\n")
            for split in range(1, len(wire)):
                with self.subTest(command=command, split=split):
                    fragmented = ChunksThenTimeout(
                        [wire[:split], wire[split:]],
                    )
                    self.assertEqual(
                        commands._receive_emulator_console(
                            fragmented,
                            expected_responses=(expected,),
                        ),
                        expected,
                    )
                    self.assertLessEqual(fragmented.calls, 2)

            same_chunk_trailer = ChunksThenTimeout([wire + b"ignored trailer"])
            self.assertEqual(
                commands._receive_emulator_console(
                    same_chunk_trailer,
                    expected_responses=(expected,),
                ),
                expected,
            )
            later_trailer = ChunksThenTimeout([wire, b"ignored trailer"])
            self.assertEqual(
                commands._receive_emulator_console(
                    later_trailer,
                    expected_responses=(expected,),
                ),
                expected,
            )
            self.assertEqual(same_chunk_trailer.calls, 1)
            self.assertEqual(later_trailer.calls, 1)

    def test_console_receive_has_one_total_response_deadline(self) -> None:
        class SlowPrefix:
            def __init__(self) -> None:
                self.timeouts: list[float] = []
                self.calls = 0

            def settimeout(self, seconds: float) -> None:
                self.timeouts.append(seconds)

            def recv(self, _maximum: int) -> bytes:
                self.calls += 1
                return b"O" if self.calls == 1 else b"K"

        stream = SlowPrefix()
        with (
            mock.patch.object(
                commands.time,
                "monotonic",
                side_effect=[100.0, 101.0, 106.0],
            ),
            self.assertRaisesRegex(
                commands.AndroidCommandError,
                "response timed out",
            ),
        ):
            commands._receive_emulator_console(
                stream,
                expected_responses=(b"OK\n",),
            )
        self.assertEqual(stream.calls, 1)
        self.assertEqual(stream.timeouts, [4.0])

    def test_console_ack_without_process_exit_keeps_recovery_receipt(self) -> None:
        receipt = self.create_active_emulator_runtime_receipt()
        with (
            mock.patch.object(
                commands, "_same_receipt_process", return_value=mock.sentinel.live
            ),
            mock.patch.object(commands.time, "monotonic", side_effect=[0.0, 21.0]),
            mock.patch.object(commands.time, "sleep") as sleep,
            self.assertRaisesRegex(
                commands.AndroidCommandError,
                "did not exit after its authenticated console shutdown",
            ),
        ):
            commands._wait_for_recovered_emulator_exit(receipt)
        sleep.assert_not_called()
        self.assertTrue(state.owned_runtime_receipt_path().exists())

    def test_complete_recovery_uses_only_verified_protocol_shutdown(self) -> None:
        receipt = self.create_active_emulator_runtime_receipt()
        capability = self.load_capability()
        observed = commands.ProcessIdentity(
            pid=receipt.pid,
            uid=receipt.uid,
            started_at=receipt.started_at,
            started_subsecond=receipt.started_subsecond,
            executable=receipt.backend_path,
        )
        order: list[str] = []
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                commands,
                "probe_adb_loopback_absence",
                return_value=commands.runtime_state.AdbIsolationObservation(),
            ),
            mock.patch.object(commands, "_same_receipt_process", return_value=observed),
            mock.patch.object(
                commands,
                "_validate_recovery_receipt",
                return_value=commands.RecoveryContext(
                    layout=self.layout,
                    capability=capability,
                    launcher=receipt.launcher_path,
                    backend=receipt.backend_path,
                    current_boot=True,
                ),
            ),
            mock.patch.object(
                commands, "_wait_for_recovery_backend", return_value=observed
            ),
            mock.patch.object(
                commands,
                "_verify_recovery_listeners",
                side_effect=lambda **_kwargs: order.append("listeners"),
            ),
            mock.patch.object(
                commands,
                "_verify_owned_emulator_console_name",
                side_effect=lambda _context, _receipt: order.append("avd-name"),
            ),
            mock.patch.object(
                commands,
                "_request_owned_emulator_console_shutdown",
                side_effect=lambda _context, _receipt: order.append("console-kill"),
            ),
            mock.patch.object(
                commands,
                "_wait_for_recovered_emulator_exit",
                side_effect=lambda _receipt: order.append("exit"),
            ),
            mock.patch.object(
                commands,
                "_finish_recovery_resources",
                side_effect=lambda _layout, _capability, _receipt: order.append(
                    "resources"
                ),
            ),
            mock.patch.object(commands.os, "kill") as pid_signal,
        ):
            self.assertEqual(commands.recover_owned_runtime(), "recovered")
        self.assertEqual(
            order,
            [
                "listeners",
                "avd-name",
                "listeners",
                "console-kill",
                "exit",
                "resources",
            ],
        )
        pid_signal.assert_not_called()
        self.assertFalse(state.owned_runtime_receipt_path().exists())


if __name__ == "__main__":
    unittest.main()
