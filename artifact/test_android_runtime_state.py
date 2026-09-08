from __future__ import annotations

import dataclasses
import errno
import hashlib
import json
import os
import pathlib
import select
import stat
import sys
import tempfile
import types
import unittest
from collections.abc import Iterator
from unittest import mock

import android_runtime_state as state
import android_emulator_control as emulator_control
from process_identity import ProcessIdentity


class AndroidRuntimeStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.production_adb_profile_paths = frozenset(state.ADB_PROFILE_PATHS)

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

    def create_avd_fixture(
        self,
        name: str = "QPeriapt_Release_16K_API_35_V1",
    ) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
        home = state.avd_home_directory()
        home.mkdir(mode=0o700, exist_ok=False)
        directory = home / f"{name}.avd"
        directory.mkdir(mode=0o700)
        config = directory / "config.ini"
        config.write_text("hw.cpu.arch=arm64\n", encoding="utf-8")
        config.chmod(0o600)
        nested = directory / "snapshots"
        nested.mkdir(mode=0o700)
        marker = nested / "state.bin"
        marker.write_bytes(b"state fixture")
        marker.chmod(0o600)
        ini = home / f"{name}.ini"
        ini.write_text(
            f"avd.ini.encoding=UTF-8\npath={directory}\ntarget=android-35\n",
            encoding="utf-8",
        )
        ini.chmod(0o600)
        return home, directory, ini

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
            sealing = state.begin_adb_seal(registered, 7)
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
            avd_name="QPeriapt_Release_16K_API_35_V1",
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

    def create_sdk_pstore_fixture(
        self,
    ) -> tuple[state.OwnedRuntimeReceipt, pathlib.Path]:
        _home, directory, _ini = self.create_avd_fixture()
        parent = directory
        for leaf in ("data", "misc", "pstore"):
            parent = parent / leaf
            parent.mkdir(mode=0o700)
        parent.chmod(0o777)
        return self.active_emulator_receipt(), parent

    def test_owned_pstore_restoration_preserves_inode_and_strict_admission(
        self,
    ) -> None:
        receipt, pstore = self.create_sdk_pstore_fixture()
        before = pstore.stat()
        receipt_bytes = state.owned_runtime_receipt_path().read_bytes()
        marker = pstore.parents[2] / "snapshots" / "state.bin"
        with self.assertRaisesRegex(state.AndroidRuntimeStateError, "0700"):
            state.validate_runtime_avd_selection("macos-account", "arm64-v8a")
        self.assertEqual(stat.S_IMODE(pstore.stat().st_mode), 0o777)
        with mock.patch.object(state, "validate_lane_lock_descriptor"):
            state.restore_owned_avd_pstore_permissions(receipt)
        after = pstore.stat()
        self.assertEqual(stat.S_IMODE(after.st_mode), 0o700)
        self.assertEqual(
            (after.st_dev, after.st_ino, after.st_uid, after.st_gid, after.st_mtime_ns),
            (
                before.st_dev,
                before.st_ino,
                before.st_uid,
                before.st_gid,
                before.st_mtime_ns,
            ),
        )
        self.assertEqual(list(pstore.iterdir()), [])
        self.assertEqual(marker.read_bytes(), b"state fixture")
        self.assertEqual(state.owned_runtime_receipt_path().read_bytes(), receipt_bytes)
        state.validate_runtime_avd_selection("macos-account", "arm64-v8a")

    def test_owned_pstore_private_mode_is_idempotent_and_missing_is_not_created(
        self,
    ) -> None:
        receipt, pstore = self.create_sdk_pstore_fixture()
        pstore.chmod(0o700)
        before = pstore.stat()
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(state.os, "fchmod", wraps=os.fchmod) as chmod,
        ):
            state.restore_owned_avd_pstore_permissions(receipt)
            state.restore_owned_avd_pstore_permissions(receipt)
            self.assertEqual(pstore.stat().st_ctime_ns, before.st_ctime_ns)
            for missing in (pstore, pstore.parent, pstore.parent.parent):
                with self.subTest(missing=missing.name):
                    missing.rmdir()
                    state.restore_owned_avd_pstore_permissions(receipt)
                    self.assertFalse(os.path.lexists(missing))
            chmod.assert_not_called()
        self.assertEqual(self.receipt().snapshot_sha256, receipt.snapshot_sha256)

    def test_owned_pstore_requires_lane_and_current_receipt_before_mutation(
        self,
    ) -> None:
        receipt, pstore = self.create_sdk_pstore_fixture()
        failure = state.AndroidRuntimeStateError("lane is not held")
        with (
            mock.patch.object(
                state, "validate_lane_lock_descriptor", side_effect=failure
            ),
            mock.patch.object(state.os, "fchmod") as chmod,
            self.assertRaises(state.AndroidRuntimeStateError) as raised,
        ):
            state.restore_owned_avd_pstore_permissions(receipt)
        self.assertIs(raised.exception, failure)
        chmod.assert_not_called()
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(state, "load_owned_runtime_receipt", return_value=None),
            mock.patch.object(state.os, "fchmod") as chmod,
            self.assertRaisesRegex(state.AndroidRuntimeStateError, "receipt changed"),
        ):
            state.restore_owned_avd_pstore_permissions(receipt)
        chmod.assert_not_called()
        self.assertEqual(stat.S_IMODE(pstore.stat().st_mode), 0o777)

    def test_unregistered_runtime_does_not_inspect_or_create_avd_scratch(self) -> None:
        prepared = self.receipt()
        sealed = self.advance_to_sealed()
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(state, "_open_account_state") as account,
            mock.patch.object(state, "validate_runtime_avd_selection") as validate,
            mock.patch.object(state.os, "fchmod") as chmod,
        ):
            state.restore_owned_avd_pstore_permissions(prepared)
            state.restore_owned_avd_pstore_permissions(sealed)
        account.assert_not_called()
        validate.assert_not_called()
        chmod.assert_not_called()
        self.assertFalse(os.path.lexists(state.avd_home_directory()))

    def test_owned_pstore_rejects_nonempty_and_unknown_modes_without_changes(
        self,
    ) -> None:
        receipt, pstore = self.create_sdk_pstore_fixture()
        marker = pstore / ".retained-crash-data"
        marker.write_bytes(b"preserve this data")
        marker.chmod(0o600)
        for mode in (0o777, 0o700):
            pstore.chmod(mode)
            with (
                self.subTest(mode=mode),
                mock.patch.object(state, "validate_lane_lock_descriptor"),
                mock.patch.object(state.os, "fchmod") as chmod,
                self.assertRaisesRegex(state.AndroidRuntimeStateError, "not empty"),
            ):
                state.restore_owned_avd_pstore_permissions(receipt)
            chmod.assert_not_called()
            self.assertEqual(stat.S_IMODE(pstore.stat().st_mode), mode)
            self.assertEqual(marker.read_bytes(), b"preserve this data")
        marker.unlink()
        for mode in (0o500, 0o710, 0o1777):
            pstore.chmod(mode)
            with (
                self.subTest(mode=mode),
                mock.patch.object(state, "validate_lane_lock_descriptor"),
                mock.patch.object(state.os, "fchmod") as chmod,
                self.assertRaisesRegex(state.AndroidRuntimeStateError, "0700 or 0777"),
            ):
                state.restore_owned_avd_pstore_permissions(receipt)
            chmod.assert_not_called()
            self.assertEqual(stat.S_IMODE(pstore.stat().st_mode), mode)
        pstore.chmod(0o700)
        self.assertEqual(self.receipt().snapshot_sha256, receipt.snapshot_sha256)

    def test_owned_pstore_rejects_links_special_files_and_unsafe_ancestors(
        self,
    ) -> None:
        receipt, pstore = self.create_sdk_pstore_fixture()
        pstore.rmdir()
        outside = self.root / "outside-scratch"
        outside.mkdir(mode=0o700)
        for kind in ("symlink", "file", "fifo"):
            if kind == "symlink":
                pstore.symlink_to(outside, target_is_directory=True)
            elif kind == "file":
                pstore.write_bytes(b"not a directory")
            else:
                os.mkfifo(pstore, 0o600)
            with (
                self.subTest(kind=kind),
                mock.patch.object(state, "validate_lane_lock_descriptor"),
                mock.patch.object(state.os, "fchmod") as chmod,
                self.assertRaisesRegex(state.AndroidRuntimeStateError, "directory"),
            ):
                state.restore_owned_avd_pstore_permissions(receipt)
            chmod.assert_not_called()
            pstore.unlink()
        pstore.mkdir(mode=0o700)
        pstore.chmod(0o777)
        misc = pstore.parent
        moved = misc.with_name("saved-misc")
        misc.rename(moved)
        misc.symlink_to(moved, target_is_directory=True)
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(state.os, "fchmod") as chmod,
            self.assertRaisesRegex(state.AndroidRuntimeStateError, "ancestor"),
        ):
            state.restore_owned_avd_pstore_permissions(receipt)
        chmod.assert_not_called()
        self.assertEqual(stat.S_IMODE((moved / "pstore").stat().st_mode), 0o777)
        self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o700)
        self.assertEqual(self.receipt().snapshot_sha256, receipt.snapshot_sha256)

    def test_owned_pstore_rejects_wrong_owner_and_allow_acl(self) -> None:
        receipt, pstore = self.create_sdk_pstore_fixture()
        actual_stat = os.stat

        def wrong_owner(
            path: object, *args: object, **kwargs: object
        ) -> os.stat_result:
            result = actual_stat(path, *args, **kwargs)
            if path == "pstore":
                fields = list(result)
                fields[4] = os.geteuid() + 1
                return os.stat_result(fields)
            return result

        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(state.os, "stat", side_effect=wrong_owner),
            mock.patch.object(state.os, "fchmod") as chmod,
            self.assertRaisesRegex(
                state.AndroidRuntimeStateError, "current-user-owned"
            ),
        ):
            state.restore_owned_avd_pstore_permissions(receipt)
        chmod.assert_not_called()
        actual_acl_check = state._reject_macos_allow_acl

        def reject_leaf_acl(descriptor: int, label: str) -> None:
            if label == "AVD pstore":
                raise state.AndroidRuntimeStateError("fixture allow ACL")
            actual_acl_check(descriptor, label)

        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                state, "_reject_macos_allow_acl", side_effect=reject_leaf_acl
            ),
            mock.patch.object(state.os, "fchmod") as chmod,
            self.assertRaisesRegex(state.AndroidRuntimeStateError, "allow ACL"),
        ):
            state.restore_owned_avd_pstore_permissions(receipt)
        chmod.assert_not_called()
        self.assertEqual(stat.S_IMODE(pstore.stat().st_mode), 0o777)

    def test_owned_pstore_open_swap_is_rejected_before_chmod(self) -> None:
        receipt, pstore = self.create_sdk_pstore_fixture()
        moved = pstore.with_name("saved-pstore")
        actual_open = os.open

        def swap_before_open(
            path: object, flags: int, *args: object, **kwargs: object
        ) -> int:
            if path == "pstore":
                self.assertTrue(flags & os.O_NOFOLLOW)
                self.assertTrue(flags & os.O_DIRECTORY)
                pstore.rename(moved)
                pstore.mkdir(mode=0o700)
            return actual_open(path, flags, *args, **kwargs)

        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(state.os, "open", side_effect=swap_before_open),
            mock.patch.object(state.os, "fchmod") as chmod,
            self.assertRaisesRegex(
                state.AndroidRuntimeStateError, "changed while opening"
            ),
        ):
            state.restore_owned_avd_pstore_permissions(receipt)
        chmod.assert_not_called()
        self.assertEqual(stat.S_IMODE(moved.stat().st_mode), 0o777)
        self.assertEqual(stat.S_IMODE(pstore.stat().st_mode), 0o700)
        self.assertEqual(self.receipt().snapshot_sha256, receipt.snapshot_sha256)

    def test_owned_pstore_post_chmod_swap_holds_receipt_without_rollback(self) -> None:
        receipt, pstore = self.create_sdk_pstore_fixture()
        moved = pstore.with_name("saved-pstore")
        actual_chmod = os.fchmod

        def swap_after_chmod(descriptor: int, mode: int) -> None:
            actual_chmod(descriptor, mode)
            pstore.rename(moved)
            pstore.mkdir(mode=0o700)
            pstore.chmod(0o777)

        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                state.os, "fchmod", side_effect=swap_after_chmod
            ) as chmod,
            self.assertRaisesRegex(state.AndroidRuntimeStateError, "identity changed"),
        ):
            state.restore_owned_avd_pstore_permissions(receipt)
        self.assertEqual(chmod.call_count, 1)
        self.assertEqual(stat.S_IMODE(moved.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(pstore.stat().st_mode), 0o777)
        self.assertEqual(self.receipt().snapshot_sha256, receipt.snapshot_sha256)

    def test_owned_pstore_chmod_failure_preserves_mode_and_receipt(self) -> None:
        receipt, pstore = self.create_sdk_pstore_fixture()
        failure = PermissionError("fixture chmod denied")
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(state.os, "fchmod", side_effect=failure),
            self.assertRaisesRegex(
                state.AndroidRuntimeStateError, "chmod denied"
            ) as raised,
        ):
            state.restore_owned_avd_pstore_permissions(receipt)
        self.assertIs(raised.exception.__cause__, failure)
        self.assertEqual(stat.S_IMODE(pstore.stat().st_mode), 0o777)
        self.assertEqual(self.receipt().snapshot_sha256, receipt.snapshot_sha256)

    def test_owned_pstore_postcheck_and_close_failure_preserve_primary_and_release_fds(
        self,
    ) -> None:
        receipt, pstore = self.create_sdk_pstore_fixture()
        failure = state.AndroidRuntimeStateError("fixture strict postcheck failure")
        actual_open = state._open_private_directory_at
        actual_chmod = os.fchmod
        actual_close = os.close
        descriptors: list[int] = []
        leaf_fd = -1

        def track_open(*args: object, **kwargs: object) -> int:
            descriptor = actual_open(*args, **kwargs)
            if kwargs["label"] == "AVD scratch ancestor":
                descriptors.append(descriptor)
            return descriptor

        def track_chmod(descriptor: int, mode: int) -> None:
            nonlocal leaf_fd
            leaf_fd = descriptor
            descriptors.append(descriptor)
            actual_chmod(descriptor, mode)

        def close_then_fail(descriptor: int) -> None:
            nonlocal leaf_fd
            actual_close(descriptor)
            if descriptor == leaf_fd:
                leaf_fd = -1
                raise OSError("fixture leaf close failure")

        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(
                state, "_open_private_directory_at", side_effect=track_open
            ),
            mock.patch.object(state.os, "fchmod", side_effect=track_chmod),
            mock.patch.object(state.os, "close", side_effect=close_then_fail),
            mock.patch.object(
                state, "validate_runtime_avd_selection", side_effect=failure
            ),
            self.assertRaises(state.AndroidRuntimeStateError) as raised,
        ):
            state.restore_owned_avd_pstore_permissions(receipt)
        self.assertIs(raised.exception, failure)
        self.assertTrue(any("leaf close failure" in note for note in failure.__notes__))
        self.assertEqual(len(descriptors), 5)
        for descriptor in descriptors:
            with self.assertRaises(OSError) as closed:
                os.fstat(descriptor)
            self.assertEqual(closed.exception.errno, errno.EBADF)
        self.assertEqual(stat.S_IMODE(pstore.stat().st_mode), 0o700)
        self.assertEqual(self.receipt().snapshot_sha256, receipt.snapshot_sha256)

    def test_owned_pstore_retains_first_close_failure_and_continues_all_closes(
        self,
    ) -> None:
        receipt, pstore = self.create_sdk_pstore_fixture()
        actual_close = state._close_owned_descriptor
        for postcheck_fails in (False, True):
            primary = state.AndroidRuntimeStateError("fixture strict postcheck")
            first_close = state.AndroidRuntimeStateError("fixture first close failure")
            later_close = KeyboardInterrupt("fixture later close interruption")
            closed: list[int] = []

            def close_with_failures(
                descriptor: int,
                *,
                label: str,
                primary: BaseException | None = None,
            ) -> None:
                actual_close(descriptor, label=label, primary=primary)
                if label.startswith("AVD scratch") or label == "AVD pstore":
                    closed.append(descriptor)
                    if len(closed) == 1:
                        raise first_close
                    if len(closed) == 2:
                        raise later_close

            with (
                self.subTest(postcheck_fails=postcheck_fails),
                mock.patch.object(state, "validate_lane_lock_descriptor"),
                mock.patch.object(
                    state, "_close_owned_descriptor", side_effect=close_with_failures
                ),
                mock.patch.object(
                    state,
                    "validate_runtime_avd_selection",
                    side_effect=primary if postcheck_fails else None,
                    wraps=state.validate_runtime_avd_selection,
                ),
                self.assertRaises(state.AndroidRuntimeStateError) as raised,
            ):
                state.restore_owned_avd_pstore_permissions(receipt)
            self.assertIs(raised.exception, primary if postcheck_fails else first_close)
            notes = "\n".join(raised.exception.__notes__)
            self.assertIn("later close interruption", notes)
            if postcheck_fails:
                self.assertIn("first close failure", notes)
            self.assertEqual(len(closed), 6)
            for descriptor in closed:
                with self.assertRaises(OSError) as failure:
                    os.fstat(descriptor)
                self.assertEqual(failure.exception.errno, errno.EBADF)
            self.assertEqual(stat.S_IMODE(pstore.stat().st_mode), 0o700)
            self.assertEqual(self.receipt().snapshot_sha256, receipt.snapshot_sha256)

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

    def test_current_schema_uses_one_phase_and_no_lifecycle_booleans(self) -> None:
        receipt = self.receipt()
        value = json.loads(state.owned_runtime_receipt_path().read_text())
        self.assertEqual(value["schema_version"], 6)
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

    def test_avd_home_is_fixed_but_never_created_by_account_state_setup(self) -> None:
        fixed = state.account_state_directory() / state.AVD_HOME_LEAF
        self.assertEqual(state.avd_home_directory(), fixed)
        self.assertFalse(os.path.lexists(fixed))
        with mock.patch.dict(
            os.environ,
            {"ANDROID_AVD_HOME": str(self.root / "ambient-avd")},
            clear=False,
        ):
            state.ensure_account_state()
            self.assertEqual(state.avd_home_directory(), fixed)
        self.assertFalse(os.path.lexists(fixed))

    def test_runtime_avd_name_is_derived_only_from_fixed_profile_abi_pairs(
        self,
    ) -> None:
        with mock.patch.object(
            state,
            "ADB_PROFILE_PATHS",
            {
                "macos-account": self.adb,
                "linux-system": self.adb,
                "linux-opt": self.adb,
            },
        ):
            self.assertEqual(
                state.runtime_avd_name("macos-account", "arm64-v8a"),
                "QPeriapt_Release_16K_API_35_V1",
            )
            self.assertEqual(
                state.runtime_avd_name("linux-system", "x86_64"),
                "QPeriapt_Release_16K_API_35_CI_V1",
            )
            for profile, abi in (
                ("macos-account", "x86_64"),
                ("linux-system", "arm64-v8a"),
                ("linux-opt", "x86_64"),
            ):
                with (
                    self.subTest(profile=profile, abi=abi),
                    self.assertRaisesRegex(
                        state.AndroidRuntimeStateError,
                        "no fixed AVD selection",
                    ),
                ):
                    state.runtime_avd_name(profile, abi)
        with self.assertRaisesRegex(
            state.AndroidRuntimeStateError,
            "adb profile is unsupported",
        ):
            state.runtime_avd_name("ambient", "arm64-v8a")
        for profile in ([], True):
            with (
                self.subTest(profile=profile),
                self.assertRaisesRegex(
                    state.AndroidRuntimeStateError,
                    "adb profile is unsupported",
                ),
            ):
                state.runtime_avd_name(profile, "arm64-v8a")
        with self.assertRaisesRegex(
            state.AndroidRuntimeStateError,
            "require arm64-v8a or x86_64",
        ):
            state.runtime_avd_name("macos-account", "armeabi-v7a")

    def test_runtime_paths_cover_every_shared_adb_profile(self) -> None:
        self.assertEqual(
            self.production_adb_profile_paths,
            set(emulator_control.OWNED_ADB_PROFILE_DIALECTS),
        )

    def test_exact_private_avd_selection_passes_with_bounded_inventory(self) -> None:
        home, directory, ini = self.create_avd_fixture()
        selected = state._validate_avd_home_selection("QPeriapt_Release_16K_API_35_V1")
        self.assertEqual(selected.home, home)
        self.assertEqual(selected.directory, directory)
        self.assertEqual(selected.ini, ini)
        self.assertEqual(selected.name, "QPeriapt_Release_16K_API_35_V1")
        # Count the top-level ini, selected .avd directory, and each descendant.
        self.assertEqual(selected.tree_entries, 5)
        self.assertGreater(selected.tree_bytes, 0)

    def test_avd_selection_rejects_unsafe_home_and_selected_directory(self) -> None:
        home = state.avd_home_directory()
        with self.assertRaisesRegex(state.AndroidRuntimeStateError, "cannot open"):
            state._validate_avd_home_selection("QPeriapt_Release_16K_API_35_V1")

        home, directory, _ini = self.create_avd_fixture()
        home.chmod(0o770)
        with self.assertRaisesRegex(state.AndroidRuntimeStateError, "mode 0700"):
            state._validate_avd_home_selection("QPeriapt_Release_16K_API_35_V1")
        home.chmod(0o700)

        directory.chmod(0o770)
        with self.assertRaisesRegex(state.AndroidRuntimeStateError, "mode 0700"):
            state._validate_avd_home_selection("QPeriapt_Release_16K_API_35_V1")
        directory.chmod(0o700)

        moved = home / "moved.avd"
        directory.rename(moved)
        with self.assertRaisesRegex(state.AndroidRuntimeStateError, "cannot open"):
            state._validate_avd_home_selection("QPeriapt_Release_16K_API_35_V1")
        directory.symlink_to(moved, target_is_directory=True)
        with self.assertRaisesRegex(state.AndroidRuntimeStateError, "cannot open"):
            state._validate_avd_home_selection("QPeriapt_Release_16K_API_35_V1")
        directory.unlink()
        moved.rename(directory)

    def test_avd_selection_never_falls_back_to_default_android_home(self) -> None:
        default_home = self.root / ".android/avd"
        default_home.mkdir(parents=True, mode=0o700)
        generic_directory = default_home / "QPeriapt_16K_API_35.avd"
        generic_directory.mkdir(mode=0o700)
        generic_sentinel = generic_directory / "sentinel"
        generic_sentinel.write_bytes(b"existing generic AVD")
        generic_sentinel.chmod(0o600)
        generic_ini = default_home / "QPeriapt_16K_API_35.ini"
        generic_ini.write_text(f"path={generic_directory}\n", encoding="utf-8")
        generic_ini.chmod(0o600)

        self.create_avd_fixture()
        selected = state.validate_runtime_avd_selection(
            "macos-account", "arm64-v8a"
        )
        self.assertEqual(selected.name, "QPeriapt_Release_16K_API_35_V1")
        self.assertEqual(generic_sentinel.read_bytes(), b"existing generic AVD")

        selected_name = selected.name
        selected_ini = default_home / f"{selected_name}.ini"
        selected_ini.write_text("must remain untouched\n", encoding="utf-8")
        selected_ini.chmod(0o600)
        with self.assertRaisesRegex(state.AndroidRuntimeStateError, "must be absent"):
            state.validate_runtime_avd_selection("macos-account", "arm64-v8a")
        self.assertEqual(selected_ini.read_bytes(), b"must remain untouched\n")
        selected_ini.unlink()

        selected_directory = default_home / f"{selected_name}.avd"
        selected_directory.mkdir(mode=0o700)
        sentinel = selected_directory / "sentinel"
        sentinel.write_bytes(b"must remain untouched")
        sentinel.chmod(0o600)
        with self.assertRaisesRegex(state.AndroidRuntimeStateError, "must be absent"):
            state.validate_runtime_avd_selection("macos-account", "arm64-v8a")
        self.assertEqual(sentinel.read_bytes(), b"must remain untouched")

    def test_avd_fallback_root_must_be_safe_and_inspectable(self) -> None:
        default_android = self.root / ".android"
        default_home = default_android / "avd"
        default_home.mkdir(parents=True, mode=0o700)
        self.create_avd_fixture()

        default_home.chmod(0o775)
        with self.assertRaisesRegex(
            state.AndroidRuntimeStateError, "not group/other writable"
        ):
            state.validate_runtime_avd_selection("macos-account", "arm64-v8a")
        default_home.chmod(0o700)

        moved = self.root / "default-avd-moved"
        default_home.rename(moved)
        default_home.symlink_to(moved, target_is_directory=True)
        with self.assertRaisesRegex(
            state.AndroidRuntimeStateError,
            "cannot open default Android AVD fallback",
        ):
            state.validate_runtime_avd_selection("macos-account", "arm64-v8a")

    def test_avd_fallback_root_replacement_is_a_domain_error(self) -> None:
        default_home = self.root / ".android/avd"
        default_home.mkdir(parents=True, mode=0o700)
        self.create_avd_fixture()
        moved = self.root / "default-avd-replaced"
        original = state._require_avd_fallback_leaf_absent
        calls = 0

        def replace_after_leaf_checks(
            directory_fd: int,
            leaf: str,
            *,
            display_path: pathlib.Path,
        ) -> None:
            nonlocal calls
            original(
                directory_fd,
                leaf,
                display_path=display_path,
            )
            calls += 1
            if calls == 2:
                default_home.rename(moved)

        with (
            mock.patch.object(
                state,
                "_require_avd_fallback_leaf_absent",
                side_effect=replace_after_leaf_checks,
            ),
            self.assertRaisesRegex(
                state.AndroidRuntimeStateError,
                "fallback directory changed during validation",
            ),
        ):
            state.validate_runtime_avd_selection("macos-account", "arm64-v8a")

    def test_avd_selection_rejects_ini_alias_mode_link_acl_and_wrong_path(self) -> None:
        _home, directory, ini = self.create_avd_fixture()
        original = ini.read_bytes()
        for label, mutation, message in (
            (
                "mode",
                lambda: ini.chmod(0o640),
                "mode 0600",
            ),
            (
                "hardlink",
                lambda: os.link(ini, ini.with_name("ini-hardlink")),
                "mode 0600",
            ),
            (
                "wrong-path",
                lambda: ini.write_text(
                    "path=/tmp/other.avd\n",
                    encoding="utf-8",
                ),
                "does not exactly name",
            ),
            (
                "wrong-relative-path",
                lambda: ini.write_text(
                    f"path={directory}\npath.rel=avd/Other.avd\n",
                    encoding="utf-8",
                ),
                "must not define a relative fallback path",
            ),
            (
                "duplicate-path",
                lambda: ini.write_text(
                    f"path={directory}\npath={directory}\n",
                    encoding="utf-8",
                ),
                "duplicate key",
            ),
        ):
            with self.subTest(label=label):
                mutation()
                ini.chmod(0o600 if label not in {"mode"} else 0o640)
                with self.assertRaisesRegex(state.AndroidRuntimeStateError, message):
                    state._validate_avd_home_selection("QPeriapt_Release_16K_API_35_V1")
                ini.with_name("ini-hardlink").unlink(missing_ok=True)
                ini.write_bytes(original)
                ini.chmod(0o600)

        def reject_ini_acl(_descriptor: int, label: str) -> None:
            if label == "selected Android AVD ini":
                raise state.AndroidRuntimeStateError(
                    "selected Android AVD ini has an allow ACL"
                )

        with (
            mock.patch.object(state, "_reject_macos_allow_acl", reject_ini_acl),
            self.assertRaisesRegex(state.AndroidRuntimeStateError, "allow ACL"),
        ):
            state._validate_avd_home_selection("QPeriapt_Release_16K_API_35_V1")

        ini.unlink()
        ini.symlink_to(self.root / "outside.ini")
        with self.assertRaisesRegex(state.AndroidRuntimeStateError, "cannot safely read"):
            state._validate_avd_home_selection("QPeriapt_Release_16K_API_35_V1")

    def test_avd_selection_rejects_oversized_and_non_utf8_ini(self) -> None:
        _home, _directory, ini = self.create_avd_fixture()
        ini.write_bytes(b"x" * (state.MAX_AVD_INI_BYTES + 1))
        with self.assertRaisesRegex(state.AndroidRuntimeStateError, "exceeds"):
            state._validate_avd_home_selection("QPeriapt_Release_16K_API_35_V1")

        ini.write_bytes(b"path=\xff\n")
        with self.assertRaisesRegex(state.AndroidRuntimeStateError, "not UTF-8"):
            state._validate_avd_home_selection("QPeriapt_Release_16K_API_35_V1")

    def test_avd_selection_rejects_non_utf8_tree_leaf(self) -> None:
        _home, directory, _ini = self.create_avd_fixture()
        directory_fd = os.open(
            directory,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0),
        )
        leaf_fd = -1
        filesystem_rejected_leaf = False
        try:
            try:
                leaf_fd = os.open(
                    b"\xff",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=directory_fd,
                )
            except OSError as exc:
                if exc.errno != errno.EILSEQ:
                    raise
                filesystem_rejected_leaf = True
            else:
                os.write(leaf_fd, b"invalid UTF-8 leaf")
        finally:
            if leaf_fd >= 0:
                os.close(leaf_fd)
            os.close(directory_fd)
        if filesystem_rejected_leaf:
            class SurrogateScan:
                def __enter__(self) -> "SurrogateScan":
                    return self

                def __exit__(self, *_args: object) -> None:
                    return None

                def __iter__(self) -> Iterator[types.SimpleNamespace]:
                    return iter((types.SimpleNamespace(name=os.fsdecode(b"\xff")),))

            directory_fd = os.open(
                directory,
                os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                with (
                    mock.patch.object(state.os, "scandir", return_value=SurrogateScan()),
                    self.assertRaisesRegex(
                        state.AndroidRuntimeStateError,
                        "path is not UTF-8",
                    ),
                ):
                    state._scan_selected_avd_tree(
                        directory_fd,
                        relative=pathlib.PurePosixPath(directory.name),
                        depth=0,
                        budget=[2, 0],
                    )
            finally:
                os.close(directory_fd)
            return
        with self.assertRaisesRegex(state.AndroidRuntimeStateError, "path is not UTF-8"):
            state._validate_avd_home_selection("QPeriapt_Release_16K_API_35_V1")

    def test_avd_selection_rejects_unsafe_tree_entries_and_bounded_limits(self) -> None:
        _home, directory, _ini = self.create_avd_fixture()
        config = directory / "config.ini"
        cases = (
            (
                "group-permissions",
                lambda: config.chmod(0o640),
                "group/other permissions",
            ),
            (
                "hardlink",
                lambda: os.link(config, directory / "config-hardlink"),
                "owner-readable regular file",
            ),
            (
                "symlink",
                lambda: (directory / "unsafe-link").symlink_to(config),
                "symlink or special",
            ),
            (
                "special",
                lambda: os.mkfifo(directory / "unsafe-fifo", 0o600),
                "symlink or special",
            ),
        )
        original = config.read_bytes()
        for label, mutation, message in cases:
            with self.subTest(label=label):
                mutation()
                with self.assertRaisesRegex(state.AndroidRuntimeStateError, message):
                    state._validate_avd_home_selection("QPeriapt_Release_16K_API_35_V1")
                (directory / "config-hardlink").unlink(missing_ok=True)
                (directory / "unsafe-link").unlink(missing_ok=True)
                (directory / "unsafe-fifo").unlink(missing_ok=True)
                config.write_bytes(original)
                config.chmod(0o600)

        wrong_owner = types.SimpleNamespace(
            st_uid=os.geteuid() + 1,
            st_mode=stat.S_IFREG | 0o600,
            st_nlink=1,
        )
        with self.assertRaisesRegex(state.AndroidRuntimeStateError, "wrong owner"):
            state._validate_avd_tree_entry_metadata(
                wrong_owner,  # type: ignore[arg-type]
                relative=pathlib.PurePosixPath("fixture"),
                directory=False,
            )
        wrong_ini_owner = types.SimpleNamespace(
            st_uid=os.geteuid() + 1,
            st_mode=stat.S_IFREG | 0o600,
            st_nlink=1,
        )
        with self.assertRaisesRegex(state.EvidenceIOError, "mode 0600"):
            state._avd_ini_metadata(wrong_ini_owner)  # type: ignore[arg-type]

        with (
            mock.patch.object(state, "MAX_AVD_TREE_ENTRIES", 2),
            self.assertRaisesRegex(state.AndroidRuntimeStateError, "too many entries"),
        ):
            state._validate_avd_home_selection("QPeriapt_Release_16K_API_35_V1")
        with (
            mock.patch.object(state, "MAX_AVD_TREE_BYTES", 1),
            self.assertRaisesRegex(state.AndroidRuntimeStateError, "apparent size"),
        ):
            state._validate_avd_home_selection("QPeriapt_Release_16K_API_35_V1")
        with (
            mock.patch.object(state, "MAX_AVD_TREE_DEPTH", 0),
            self.assertRaisesRegex(
                state.AndroidRuntimeStateError,
                "maximum directory depth",
            ),
        ):
            state._validate_avd_home_selection("QPeriapt_Release_16K_API_35_V1")
        with (
            mock.patch.object(state, "MAX_AVD_RELATIVE_PATH_BYTES", 1),
            self.assertRaisesRegex(state.AndroidRuntimeStateError, "path is too long"),
        ):
            state._validate_avd_home_selection("QPeriapt_Release_16K_API_35_V1")

    def test_legal_phase_path_is_monotonic_and_derived(self) -> None:
        with mock.patch.object(state, "validate_lane_lock_descriptor"):
            registered = state.register_adb_child(
                self.receipt(), self.adb_registration()
            )
            self.assertIs(registered.phase, state.RuntimePhase.ADB_CHILD_REGISTERED)
            sealing = state.begin_adb_seal(registered, 7)
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

    def test_listener_descriptor_is_bound_by_one_seal_intent_cas(self) -> None:
        with mock.patch.object(state, "validate_lane_lock_descriptor"):
            registered = state.register_adb_child(
                self.receipt(), self.adb_registration()
            )
            sealing = state.begin_adb_seal(registered, 7)
            self.assertEqual(sealing.adb_listener_descriptor, 7)
            with self.assertRaisesRegex(
                state.AndroidRuntimeStateError,
                "changed before lifecycle advance|concurrent lifecycle mutation",
            ):
                state.begin_adb_seal(registered, 8)
        current = self.receipt()
        self.assertIs(current.phase, state.RuntimePhase.ADB_SEALING)
        self.assertEqual(current.adb_listener_descriptor, 7)

    def test_inherited_listener_intent_requires_ready_before_sealing(self) -> None:
        registration = dataclasses.replace(
            self.adb_registration(),
            listener_activation=state.AdbListenerActivation(7),
        )
        with mock.patch.object(state, "validate_lane_lock_descriptor"):
            registered = state.register_adb_child(self.receipt(), registration)
            self.assertEqual(registered.adb_listener_activation, registration.listener_activation)
            self.assertIsNone(registered.adb_listener_descriptor)
            with self.assertRaisesRegex(state.AndroidRuntimeStateError, "awaiting adb sealing"):
                state.begin_adb_seal(registered, 7)
            ready = state.complete_adb_listener_activation(registered)
            self.assertIs(ready.phase, state.RuntimePhase.ADB_LISTENER_READY)
            self.assertEqual(ready.adb_listener_descriptor, 7)
            with self.assertRaisesRegex(state.AndroidRuntimeStateError, "awaiting adb sealing"):
                state.begin_adb_seal(ready, 8)
            sealed = state.complete_adb_seal(state.begin_adb_seal(ready, 7))
        self.assertTrue(sealed.adb_socket_directory_sealed)
        self.assertEqual(sealed.adb_listener_activation, state.AdbListenerActivation(7, 128))

    def test_activation_rejects_invalid_descriptor_and_backlog_before_write(self) -> None:
        original = state.owned_runtime_receipt_path().read_bytes()
        for activation in (
            state.AdbListenerActivation(0),
            state.AdbListenerActivation(True),
            state.AdbListenerActivation(state.LANE_LOCK_FD),
            state.AdbListenerActivation(7, 4),
        ):
            with (
                self.subTest(activation=activation),
                mock.patch.object(state, "validate_lane_lock_descriptor"),
                self.assertRaises(state.AndroidRuntimeStateError),
            ):
                state.register_adb_child(
                    self.receipt(),
                    dataclasses.replace(self.adb_registration(), listener_activation=activation),
                )
            self.assertEqual(state.owned_runtime_receipt_path().read_bytes(), original)

    def test_activation_refresh_accepts_only_exact_intent_to_ready(self) -> None:
        with mock.patch.object(state, "validate_lane_lock_descriptor"):
            intended = state.register_adb_child(
                self.receipt(),
                dataclasses.replace(
                    self.adb_registration(), listener_activation=state.AdbListenerActivation(7)
                ),
            )
            self.assertEqual(state.refresh_adb_listener_activation(intended), intended)
            ready = state.complete_adb_listener_activation(intended)
            self.assertEqual(state.refresh_adb_listener_activation(intended), ready)
            state.begin_adb_seal(ready, 7)
        with self.assertRaisesRegex(state.AndroidRuntimeStateError, "outside its ready transition"):
            state.refresh_adb_listener_activation(intended)

    def test_activation_ready_post_replace_failure_keeps_recoverable_intent(self) -> None:
        with mock.patch.object(state, "validate_lane_lock_descriptor"):
            registered = state.register_adb_child(
                self.receipt(),
                dataclasses.replace(
                    self.adb_registration(), listener_activation=state.AdbListenerActivation(7)
                ),
            )
        real_fsync = state.os.fsync
        calls = 0

        def fail_directory_fsync(descriptor: int) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("activation receipt directory fsync")
            real_fsync(descriptor)

        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(state.os, "fsync", side_effect=fail_directory_fsync),
            self.assertRaisesRegex(OSError, "activation receipt directory fsync"),
        ):
            state.complete_adb_listener_activation(registered)
        recovered = self.receipt()
        self.assertIs(recovered.phase, state.RuntimePhase.ADB_LISTENER_READY)
        self.assertEqual(recovered.adb_listener_descriptor, 7)
        self.assertEqual(recovered.adb_listener_activation, state.AdbListenerActivation(7))

    def test_schema_five_recovery_keeps_exact_old_contract(self) -> None:
        path = state.owned_runtime_receipt_path()
        payload = json.loads(path.read_text())
        payload["schema_version"] = 5
        del payload["adb_listener_activation"]
        path.write_text(json.dumps(payload) + "\n")
        old_bytes = path.read_bytes()
        legacy = self.receipt()
        self.assertEqual(legacy.schema_version, 5)
        self.assertIsNone(legacy.adb_listener_activation)
        self.assertEqual(path.read_bytes(), old_bytes)
        with mock.patch.object(state, "validate_lane_lock_descriptor"):
            with self.assertRaisesRegex(state.AndroidRuntimeStateError, "not admitted"):
                state.register_adb_child(
                    legacy,
                    dataclasses.replace(
                        self.adb_registration(), listener_activation=state.AdbListenerActivation(7)
                    ),
                )
            registered = state.register_adb_child(legacy, self.adb_registration())
            sealed = state.complete_adb_seal(state.begin_adb_seal(registered, 7))
        self.assertEqual(sealed.schema_version, 5)
        value = json.loads(path.read_text())
        self.assertEqual(set(value), state.LEGACY_OWNED_RUNTIME_RECEIPT_FIELDS)
        self.assertEqual(value["schema_version"], 5)
        for mutation in (
            {"adb_listener_activation": None},
            {"phase": "adb_listener_ready"},
            {"adb_listener_descriptor": None},
        ):
            with self.subTest(mutation=mutation):
                path.write_text(json.dumps({**value, **mutation}) + "\n")
                with self.assertRaises(state.AndroidRuntimeStateError):
                    self.receipt()

    def test_post_replace_seal_fsync_failure_keeps_bound_recovery_state(
        self,
    ) -> None:
        with mock.patch.object(state, "validate_lane_lock_descriptor"):
            registered = state.register_adb_child(
                self.receipt(), self.adb_registration()
            )
        real_fsync = state.os.fsync
        calls = 0

        def fail_directory_fsync(descriptor: int) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected post-replace fsync failure")
            real_fsync(descriptor)

        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(state.os, "fsync", side_effect=fail_directory_fsync),
            self.assertRaisesRegex(OSError, "post-replace"),
        ):
            state.begin_adb_seal(registered, 7)
        recovered = self.receipt()
        self.assertIs(recovered.phase, state.RuntimePhase.ADB_SEALING)
        self.assertEqual(recovered.adb_listener_descriptor, 7)

    def test_every_illegal_phase_jump_fails_before_replace(self) -> None:
        prepared = self.receipt()
        with (
            mock.patch.object(state, "validate_lane_lock_descriptor"),
            mock.patch.object(state, "_replace_owned_runtime_receipt") as replace,
        ):
            for operation in (
                lambda: state.begin_adb_seal(prepared, 7),
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

    def test_prior_schemas_and_unknown_phase_are_rejected_without_compatibility(
        self,
    ) -> None:
        path = state.owned_runtime_receipt_path()
        for mutation in (
            lambda value: value.update({"schema_version": 1}),
            lambda value: value.update({"schema_version": 2}),
            lambda value: value.update({"schema_version": 3}),
            lambda value: value.update({"schema_version": 4}),
            lambda value: value.update({"schema_version": True}),
            lambda value: value.update({"schema_version": 5.0}),
            lambda value: value.update({"schema_version": 7}),
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
