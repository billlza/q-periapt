from __future__ import annotations

import hashlib
import json
import os
import pathlib
import select
import sys
import tempfile
import unittest
from unittest import mock

import android_runtime_state as state
from process_identity import ProcessIdentity


class AndroidRuntimeStateTests(unittest.TestCase):
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
        self.socket_directory = self.root / "qperiapt-adb.ABCDEFGH"
        self.socket_directory.mkdir(mode=0o700)
        if sys.platform == "darwin":
            self.account_state_parent = self.root / "Library" / "Application Support"
        else:
            self.account_state_parent = self.root / ".local" / "state"
        self.account_state_parent.mkdir(parents=True, mode=0o700)
        self.patchers = (
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
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.layout = state.create_run_layout(self.run_id)
        self.layout.signed_apk.write_bytes(b"signed apk")
        self.layout.signed_apk.chmod(0o600)
        state.create_capability(
            adb_profile="macos-account",
            socket_nonce="ABCDEFGH",
            device_kind="emulator",
            expected_serial="emulator-5584",
            run_id=self.run_id,
            signed_apk_size=self.layout.signed_apk.stat().st_size,
            signed_apk_sha256=hashlib.sha256(
                self.layout.signed_apk.read_bytes()
            ).hexdigest(),
        )
        state.ensure_account_state()
        state._write_owned_runtime_receipt(
            state._runtime_recovery_payload(state.load_capability(self.run_id))
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def receipt(self) -> state.OwnedRuntimeReceipt:
        receipt = state.load_owned_runtime_receipt()
        self.assertIsNotNone(receipt)
        return receipt

    def adb_registration(self, *, pid: int | None = None) -> state.AdbChildRegistration:
        process = ProcessIdentity(
            pid=os.getpid() if pid is None else pid,
            uid=os.geteuid(),
            started_at=123456,
            started_subsecond=789,
            executable=pathlib.Path(sys.executable).resolve(),
        )
        executable = process.executable.stat()
        snapshot = state.load_capability(self.run_id).adb_snapshot_path.stat()
        return state.AdbChildRegistration(
            process=process,
            initial_executable_device=executable.st_dev,
            initial_executable_inode=executable.st_ino,
            adb_snapshot_device=snapshot.st_dev,
            adb_snapshot_inode=snapshot.st_ino,
        )

    def advance_to_sealed(self) -> state.OwnedRuntimeReceipt:
        with mock.patch.object(state, "validate_lane_lock_descriptor"):
            registered = state.register_adb_child(
                self.receipt(), self.adb_registration()
            )
            sealing = state.begin_adb_seal(registered)
            return state.complete_adb_seal(sealing)

    def emulator_registration(self) -> state.EmulatorChildRegistration:
        launcher = self.root / "emulator"
        backend = self.root / "qemu-system-aarch64-headless"
        launcher.write_bytes(b"launcher")
        backend.write_bytes(b"backend")
        launcher.chmod(0o700)
        backend.chmod(0o700)
        launcher_stat = launcher.stat()
        backend_stat = backend.stat()
        return state.EmulatorChildRegistration(
            process=ProcessIdentity(
                pid=os.getpid(),
                uid=os.geteuid(),
                started_at=223456,
                started_subsecond=890,
                executable=pathlib.Path(sys.executable).resolve(),
            ),
            avd_name="QPeriapt_16K_API_35",
            device_abi="arm64-v8a",
            console_port=5584,
            native_adb_notifier_port=state.NATIVE_ADB_NOTIFIER_PORT,
            console_auth_token=state.ConsoleAuthTokenIdentity(
                device=7,
                inode=11,
                sha256="1" * 64,
            ),
            launcher_path=launcher,
            launcher_device=launcher_stat.st_dev,
            launcher_inode=launcher_stat.st_ino,
            backend_path=backend,
            backend_device=backend_stat.st_dev,
            backend_inode=backend_stat.st_ino,
            backend_sha256=hashlib.sha256(backend.read_bytes()).hexdigest(),
        )

    def active_emulator_receipt(self) -> state.OwnedRuntimeReceipt:
        sealed = self.advance_to_sealed()
        with mock.patch.object(state, "validate_lane_lock_descriptor"):
            return state.register_emulator_child(
                receipt=sealed,
                registration=self.emulator_registration(),
            )

    def write_prior_isolation_checkpoints(self) -> None:
        for checkpoint in tuple(state.AdbIsolationCheckpoint)[:-1]:
            payload = {
                "schema": state.ADB_ISOLATION_RECEIPT_SCHEMA_VERSION,
                "kind": state.ADB_ISOLATION_RECEIPT_KIND,
                "run_id": self.run_id,
                "checkpoint": checkpoint.value,
                "ports": state.AdbIsolationObservation().ports_payload(),
            }
            path = self.layout.proof / state.ADB_ISOLATION_CHECKPOINT_LEAVES[checkpoint]
            path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
            path.chmod(0o600)

    def test_schema3_uses_one_phase_and_no_lifecycle_booleans(self) -> None:
        receipt = self.receipt()
        value = json.loads(state.owned_runtime_receipt_path().read_text())
        self.assertEqual(value["schema_version"], 4)
        self.assertEqual(value["phase"], state.RuntimePhase.PREPARED.value)
        self.assertEqual(set(value), state.OWNED_RUNTIME_RECEIPT_FIELDS)
        for removed in (
            "adb_server_started",
            "adb_socket_directory_sealed",
            "emulator_started",
        ):
            self.assertNotIn(removed, value)
        self.assertFalse(receipt.adb_server_started)
        self.assertFalse(receipt.adb_socket_directory_sealed)
        self.assertFalse(receipt.emulator_started)

    def test_legal_phase_path_is_monotonic_and_derived(self) -> None:
        with mock.patch.object(state, "validate_lane_lock_descriptor"):
            registered = state.register_adb_child(
                self.receipt(), self.adb_registration()
            )
            self.assertIs(registered.phase, state.RuntimePhase.ADB_CHILD_REGISTERED)
            sealing = state.begin_adb_seal(registered)
            self.assertIs(sealing.phase, state.RuntimePhase.ADB_SEALING)
            sealed = state.complete_adb_seal(sealing)
            self.assertIs(sealed.phase, state.RuntimePhase.ADB_SEALED)
            active = state.register_emulator_child(
                receipt=sealed,
                registration=self.emulator_registration(),
            )
        self.assertIs(active.phase, state.RuntimePhase.EMULATOR_CHILD_REGISTERED)
        self.assertTrue(active.adb_server_started)
        self.assertTrue(active.adb_socket_directory_sealed)
        self.assertTrue(active.emulator_started)

    def test_every_illegal_phase_jump_fails_before_replace(self) -> None:
        prepared = self.receipt()
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(state, "_replace_owned_runtime_receipt") as replace,
        ):
            for operation in (
                lambda: state.begin_adb_seal(prepared),
                lambda: state.complete_adb_seal(prepared),
                lambda: state.register_emulator_child(
                    receipt=prepared,
                    registration=self.emulator_registration(),
                ),
            ):
                with (
                    self.subTest(operation=operation),
                    self.assertRaises(state.AndroidRuntimeStateError),
                ):
                    operation()
            replace.assert_not_called()

    @unittest.skipUnless(hasattr(os, "fork"), "concurrent CAS test requires fork")
    def test_two_forked_writers_with_one_prior_have_exactly_one_success(self) -> None:
        prepared = self.receipt()
        registration = self.adb_registration()
        ready_read, ready_write = os.pipe()
        go_read, go_write = os.pipe()
        result_read, result_write = os.pipe()
        children: list[int] = []
        original_open = state._open_owned_runtime_receipt_for_mutation
        try:
            for _index in range(2):
                pid = os.fork()
                if pid == 0:
                    try:
                        os.close(ready_read)
                        os.close(go_write)
                        os.close(result_read)

                        def open_old_receipt_then_wait(state_fd: int) -> int:
                            descriptor = original_open(state_fd)
                            os.write(ready_write, b"r")
                            if os.read(go_read, 1) != b"g":
                                os.close(descriptor)
                                raise RuntimeError("parent did not release CAS barrier")
                            return descriptor

                        child_process = ProcessIdentity(
                            pid=os.getpid(),
                            uid=registration.process.uid,
                            started_at=registration.process.started_at,
                            started_subsecond=registration.process.started_subsecond,
                            executable=registration.process.executable,
                        )
                        child_registration = state.AdbChildRegistration(
                            process=child_process,
                            initial_executable_device=registration.initial_executable_device,
                            initial_executable_inode=registration.initial_executable_inode,
                            adb_snapshot_device=registration.adb_snapshot_device,
                            adb_snapshot_inode=registration.adb_snapshot_inode,
                        )
                        with (
                            mock.patch.object(state, "validate_lane_lock_descriptor"),
                            mock.patch.object(
                                state,
                                "_open_owned_runtime_receipt_for_mutation",
                                side_effect=open_old_receipt_then_wait,
                            ),
                        ):
                            try:
                                state.register_adb_child(prepared, child_registration)
                            except state.AndroidRuntimeStateError as exc:
                                result = b"rejected:" + str(exc).encode("utf-8") + b"\n"
                            else:
                                result = b"success\n"
                        os.write(result_write, result)
                        os._exit(0)
                    except BaseException as exc:
                        os.write(
                            result_write,
                            b"crash:" + repr(exc).encode("utf-8") + b"\n",
                        )
                        os._exit(4)
                children.append(pid)
            os.close(ready_write)
            ready_write = -1
            os.close(go_read)
            go_read = -1
            os.close(result_write)
            result_write = -1
            ready = b""
            while len(ready) < 2:
                readable, _, _ = select.select([ready_read], [], [], 5)
                self.assertEqual(readable, [ready_read])
                ready += os.read(ready_read, 2 - len(ready))
            self.assertEqual(ready, b"rr")
            os.write(go_write, b"gg")
            os.close(go_write)
            go_write = -1
            results = b""
            while True:
                chunk = os.read(result_read, 64)
                if not chunk:
                    break
                results += chunk
            statuses = [os.waitpid(pid, 0)[1] for pid in children]
            children.clear()
            self.assertTrue(
                all(os.waitstatus_to_exitcode(status) == 0 for status in statuses)
            )
            lines = results.splitlines()
            self.assertEqual(lines.count(b"success"), 1, lines)
            self.assertEqual(
                sum(line.startswith(b"rejected:") for line in lines), 1, lines
            )
            rejected = next(line for line in lines if line.startswith(b"rejected:"))
            self.assertTrue(
                b"concurrent lifecycle mutation" in rejected
                or b"changed before lifecycle advance" in rejected,
                lines,
            )
        finally:
            for descriptor in (
                ready_read,
                ready_write,
                go_read,
                go_write,
                result_read,
                result_write,
            ):
                if descriptor >= 0:
                    os.close(descriptor)
            for pid in children:
                try:
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass

    def test_schema2_and_unknown_phase_are_rejected_without_compatibility(self) -> None:
        path = state.owned_runtime_receipt_path()
        for mutation in (
            lambda value: value.update({"schema_version": 2}),
            lambda value: value.update({"phase": "unknown"}),
        ):
            value = json.loads(path.read_text())
            mutation(value)
            path.write_text(json.dumps(value) + "\n")
            path.chmod(0o600)
            with self.assertRaises(state.AndroidRuntimeStateError):
                state.load_owned_runtime_receipt()
            path.unlink()
            state._write_owned_runtime_receipt(
                state._runtime_recovery_payload(state.load_capability(self.run_id))
            )

    def test_emulator_registration_persists_only_token_identity(self) -> None:
        registration = self.emulator_registration()
        sealed = self.advance_to_sealed()
        with mock.patch.object(state, "validate_lane_lock_descriptor"):
            active = state.register_emulator_child(
                receipt=sealed,
                registration=registration,
            )
        value = json.loads(state.owned_runtime_receipt_path().read_text())
        self.assertEqual(
            active.console_auth_token_identity,
            registration.console_auth_token,
        )
        self.assertNotIn("console_auth_token", value)
        self.assertNotIn(
            "private-token", state.owned_runtime_receipt_path().read_text()
        )

    def test_typed_mutations_require_lane_lock(self) -> None:
        prepared = self.receipt()
        with mock.patch.object(
            state,
            "validate_lane_lock_descriptor",
            side_effect=state.AndroidRuntimeStateError("lane lock required"),
        ) as validate:
            with self.assertRaisesRegex(state.AndroidRuntimeStateError, "lane lock"):
                state.register_adb_child(prepared, self.adb_registration())
        validate.assert_called_once_with()

    def test_isolation_checkpoint_is_admitted_before_probe_and_is_no_replace(
        self,
    ) -> None:
        sealed = self.advance_to_sealed()
        with mock.patch.object(state, "validate_lane_lock_descriptor"):
            state.register_emulator_child(
                receipt=sealed,
                registration=self.emulator_registration(),
            )
        self.socket_directory.chmod(0o500)
        checkpoint = state.AdbIsolationCheckpoint.EMULATOR_PRE_EXEC
        leaf = self.layout.proof / state.ADB_ISOLATION_CHECKPOINT_LEAVES[checkpoint]
        order: list[str] = []
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                state,
                "probe_adb_loopback_absence",
                side_effect=lambda: (
                    order.append("probe"),
                    state.AdbIsolationObservation(),
                )[1],
            ),
        ):
            self.assertEqual(
                state.record_pre_exec_adb_isolation_checkpoint(self.run_id),
                leaf,
            )
            order.append("published" if leaf.exists() else "missing")
            with self.assertRaises(FileExistsError):
                state.record_pre_exec_adb_isolation_checkpoint(self.run_id)
        self.assertEqual(order, ["probe", "published", "probe"])
        self.assertEqual(oct(leaf.stat().st_mode & 0o777), "0o600")
        self.assertEqual(
            json.loads(leaf.read_text()),
            {
                "schema": state.ADB_ISOLATION_RECEIPT_SCHEMA_VERSION,
                "kind": state.ADB_ISOLATION_RECEIPT_KIND,
                "run_id": self.run_id,
                "checkpoint": checkpoint.value,
                "ports": state.AdbIsolationObservation().ports_payload(),
            },
        )

    def test_isolation_checkpoint_rejects_wrong_phase_and_postcleanup_api(
        self,
    ) -> None:
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(state, "probe_adb_loopback_absence") as probe,
            self.assertRaisesRegex(state.AndroidRuntimeStateError, "not admitted"),
        ):
            state.record_adb_isolation_checkpoint(
                self.run_id,
                state.AdbIsolationCheckpoint.EMULATOR_PRE_EXEC,
            )
        probe.assert_not_called()
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            self.assertRaisesRegex(state.AndroidRuntimeStateError, "not admitted"),
        ):
            state.record_adb_isolation_checkpoint(
                self.run_id,
                state.AdbIsolationCheckpoint.RUNTIME_POST_CLEANUP,
            )

    def test_postregistration_checkpoint_requires_canonical_routing_receipt(
        self,
    ) -> None:
        sealed = self.advance_to_sealed()
        with mock.patch.object(state, "validate_lane_lock_descriptor"):
            state.register_emulator_child(
                receipt=sealed,
                registration=self.emulator_registration(),
            )
        self.socket_directory.chmod(0o500)
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                state,
                "probe_adb_loopback_absence",
                return_value=state.AdbIsolationObservation(),
            ),
        ):
            state.record_pre_exec_adb_isolation_checkpoint(self.run_id)
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(state, "probe_adb_loopback_absence") as probe,
            self.assertRaises(state.AndroidRuntimeStateError),
        ):
            state.record_adb_isolation_checkpoint(
                self.run_id,
                state.AdbIsolationCheckpoint.EMULATOR_POST_REGISTRATION,
            )
        probe.assert_not_called()
        routing = self.layout.proof / state.EMULATOR_ROUTING_RECEIPT_LEAF
        routing.write_text("{}\n")
        routing.chmod(0o600)
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(state, "probe_adb_loopback_absence") as probe,
            self.assertRaisesRegex(state.AndroidRuntimeStateError, "routing receipt"),
        ):
            state.record_adb_isolation_checkpoint(
                self.run_id,
                state.AdbIsolationCheckpoint.EMULATOR_POST_REGISTRATION,
            )
        probe.assert_not_called()

    def test_postcleanup_checkpoint_owns_probe_and_never_accepts_observation(
        self,
    ) -> None:
        receipt = self.active_emulator_receipt()
        with self.assertRaises(TypeError):
            state.record_post_cleanup_adb_isolation_checkpoint(  # type: ignore[call-arg]
                receipt,
                state.AdbIsolationObservation(),
            )
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(state, "load_owned_runtime_receipt", return_value=None),
            mock.patch.object(state, "probe_adb_loopback_absence") as probe,
            self.assertRaises(state.AndroidRuntimeStateError),
        ):
            state.record_post_cleanup_adb_isolation_checkpoint(receipt)
        probe.assert_not_called()

    def test_postcleanup_probe_failure_publishes_no_final_receipt(self) -> None:
        receipt = self.active_emulator_receipt()
        self.write_prior_isolation_checkpoints()
        state.retire_recovery_capability(self.layout, receipt)
        final_path = (
            self.layout.proof
            / state.ADB_ISOLATION_CHECKPOINT_LEAVES[
                state.AdbIsolationCheckpoint.RUNTIME_POST_CLEANUP
            ]
        )
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                state,
                "probe_adb_loopback_absence",
                side_effect=state.AndroidEmulatorControlError("occupied notifier"),
            ) as probe,
            self.assertRaisesRegex(state.AndroidRuntimeStateError, "occupied notifier"),
        ):
            state.record_post_cleanup_adb_isolation_checkpoint(receipt)
        probe.assert_called_once_with()
        self.assertFalse(final_path.exists())
        self.assertTrue(state.owned_runtime_receipt_path().exists())

    def test_postcleanup_checkpoint_is_exactly_idempotent_and_keeps_receipt(
        self,
    ) -> None:
        receipt = self.active_emulator_receipt()
        self.write_prior_isolation_checkpoints()
        state.retire_recovery_capability(self.layout, receipt)
        final_path = (
            self.layout.proof
            / state.ADB_ISOLATION_CHECKPOINT_LEAVES[
                state.AdbIsolationCheckpoint.RUNTIME_POST_CLEANUP
            ]
        )
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                state,
                "probe_adb_loopback_absence",
                return_value=state.AdbIsolationObservation(),
            ) as probe,
        ):
            self.assertEqual(
                state.record_post_cleanup_adb_isolation_checkpoint(receipt),
                final_path,
            )
            with mock.patch.object(state.os, "fsync") as fsync:
                self.assertEqual(
                    state.record_post_cleanup_adb_isolation_checkpoint(receipt),
                    final_path,
                )
            fsync.assert_called_once()
        self.assertEqual(probe.call_count, 2)
        self.assertTrue(final_path.exists())
        self.assertTrue(state.owned_runtime_receipt_path().exists())

        final_path.write_text("{}\n")
        final_path.chmod(0o600)
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                state,
                "probe_adb_loopback_absence",
                return_value=state.AdbIsolationObservation(),
            ),
            self.assertRaisesRegex(
                state.AndroidRuntimeStateError,
                "existing post-cleanup adb isolation checkpoint changed",
            ),
        ):
            state.record_post_cleanup_adb_isolation_checkpoint(receipt)
        self.assertTrue(state.owned_runtime_receipt_path().exists())

    def test_postcleanup_fsync_failure_is_retryable_with_receipt_preserved(
        self,
    ) -> None:
        receipt = self.active_emulator_receipt()
        self.write_prior_isolation_checkpoints()
        state.retire_recovery_capability(self.layout, receipt)
        final_path = (
            self.layout.proof
            / state.ADB_ISOLATION_CHECKPOINT_LEAVES[
                state.AdbIsolationCheckpoint.RUNTIME_POST_CLEANUP
            ]
        )
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                state,
                "probe_adb_loopback_absence",
                return_value=state.AdbIsolationObservation(),
            ),
            mock.patch.object(
                state.os, "fsync", side_effect=[OSError("fsync denied"), None]
            ),
            self.assertRaisesRegex(OSError, "fsync denied"),
        ):
            state.record_post_cleanup_adb_isolation_checkpoint(receipt)
        self.assertFalse(final_path.exists())
        self.assertTrue(state.owned_runtime_receipt_path().exists())

        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                state,
                "probe_adb_loopback_absence",
                return_value=state.AdbIsolationObservation(),
            ),
        ):
            state.record_post_cleanup_adb_isolation_checkpoint(receipt)
        self.assertTrue(final_path.exists())


if __name__ == "__main__":
    unittest.main()
