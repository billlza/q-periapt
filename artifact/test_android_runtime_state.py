from __future__ import annotations

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
        with self.assertRaisesRegex(
            state.AndroidRuntimeStateError,
            "require arm64-v8a or x86_64",
        ):
            state.runtime_avd_name("macos-account", "armeabi-v7a")

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
