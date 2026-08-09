#!/usr/bin/env python3

from __future__ import annotations

import argparse
import copy
import datetime as dt
import os
import pathlib
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import android_device_proof


def create_private_adb_test_directory() -> pathlib.Path:
    for _ in range(100):
        directory = pathlib.Path("/tmp") / f"qperiapt-adb.{secrets.token_hex(4)}"
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            continue
        directory.chmod(0o700)
        return directory
    raise RuntimeError("could not allocate a private adb test directory")


def complete_proof_shape() -> dict[str, object]:
    native = {
        abi: {
            "ffi_so_sha256": "1" * 64,
            "jni_so_sha256": "2" * 64,
        }
        for abi in android_device_proof.REQUIRED_NATIVE_ABIS
    }

    return {
        "schema": android_device_proof.PROOF_SCHEMA_VERSION,
        "generated_at": "2026-07-15T00:00:00Z",
        "git_commit": "a" * 40,
        "source_tree_dirty": False,
        "proof_source_tree_sha256": "b" * 64,
        "device_runtime_proof": True,
        "package_only": False,
        "release_candidate_mode": False,
        "run_id": "c" * 32,
        "package": "dev.qperiapt.androidsmoke",
        "paths": {
            key: f"target/android/{key}"
            for key in android_device_proof.PROOF_PATH_KEYS
        },
        "device": {
            "kind": "emulator",
            "serial_sha256_prefix": "3" * 12,
            "raw_serial_recorded": False,
            "manufacturer": "Google",
            "model": "Android SDK built for arm64",
            "abi": "arm64-v8a",
            "page_size": 16384,
            "sdk": 35,
            "release": "15",
            "fingerprint_sha256_prefix": "4" * 12,
        },
        "android": {
            "platform": "android-35",
            "build_tools": "36.0.0",
            "ndk": "29.0.14206865",
            "native_page_alignment": 16384,
            "min_sdk": 23,
            "target_sdk": 35,
            "adb_version": "Android Debug Bridge version 1.0.41",
            "apksigner_sha256": "5" * 64,
            "zipalign_sha256": "6" * 64,
        },
        "abi": {
            "major": 2,
            "contract_path": "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json",
            "contract_sha256": "7" * 64,
            "runtime_library": "libq_periapt_ffi_abi2.so",
            "jni_library": "libqperiapt_jni_abi2.so",
            "legacy_library_names_present": False,
        },
        "result": {
            "marker_sha256": "8" * 64,
            "json_sha256": "9" * 64,
            "status": "pass",
            "test_count": len(android_device_proof.EXPECTED_TESTS),
            "passed_tests": list(android_device_proof.EXPECTED_TESTS),
        },
        "artifacts": {
            "aar_sha256": "a" * 64,
            "aar_manifest_sha256": "b" * 64,
            "smoke_apk_sha256": "c" * 64,
            "apksigner_verify_sha256": "d" * 64,
            "zipalign_verify_sha256": "e" * 64,
            "logcat_sha256": "f" * 64,
            "native": native,
        },
        "source_hashes": {
            name + "_sha256": "0" * 64
            for name in android_device_proof.SOURCE_INPUTS
        },
    }


class AndroidAdbIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.account_home = pathlib.Path(self.temp_dir.name) / "account-home"
        self.account_home.mkdir(mode=0o700)
        self.account_home.chmod(0o700)
        self.android_dir = self.account_home / ".android"
        self.android_dir.mkdir(mode=0o700)
        self.android_dir.chmod(0o700)
        self.private_key = self.android_dir / "adbkey"
        self.public_key = self.android_dir / "adbkey.pub"
        self.private_key.write_text("private fixture\n", encoding="utf-8")
        self.public_key.write_text("public fixture\n", encoding="utf-8")
        self.private_key.chmod(0o600)
        self.public_key.chmod(0o644)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_owner_controlled_identity_passes(self) -> None:
        android_device_proof.validate_adb_identity_directory(self.android_dir)
        android_device_proof.validate_account_adb_identity(
            self.account_home, account_home=self.account_home
        )

    def test_different_or_group_writable_account_home_is_rejected(self) -> None:
        with self.assertRaisesRegex(SystemExit, "must match the current account home"):
            android_device_proof.validate_account_adb_identity(
                self.account_home, account_home=self.account_home.parent
            )
        self.account_home.chmod(0o770)
        with self.assertRaisesRegex(SystemExit, "home must not be writable by group"):
            android_device_proof.validate_account_adb_identity(
                self.account_home, account_home=self.account_home
            )

    def test_group_writable_identity_directory_is_rejected(self) -> None:
        self.android_dir.chmod(0o770)
        with self.assertRaisesRegex(SystemExit, "must not be writable by group"):
            android_device_proof.validate_adb_identity_directory(self.android_dir)

    def test_symlink_identity_directory_is_rejected(self) -> None:
        link = pathlib.Path(self.temp_dir.name) / "android-link"
        link.symlink_to(self.android_dir, target_is_directory=True)
        with self.assertRaisesRegex(SystemExit, "non-symlink directory"):
            android_device_proof.validate_adb_identity_directory(link)

    def test_insecure_or_empty_key_is_rejected(self) -> None:
        self.private_key.chmod(0o640)
        with self.assertRaisesRegex(SystemExit, "must not be accessible"):
            android_device_proof.validate_adb_identity_directory(self.android_dir)
        self.private_key.chmod(0o600)
        self.public_key.write_bytes(b"")
        with self.assertRaisesRegex(SystemExit, "must not be empty"):
            android_device_proof.validate_adb_identity_directory(self.android_dir)

    def test_non_key_leaf_cannot_substitute_for_regular_key(self) -> None:
        self.private_key.unlink()
        self.private_key.mkdir(mode=0o700)
        with self.assertRaisesRegex(SystemExit, "regular non-symlink file"):
            android_device_proof.validate_adb_identity_directory(self.android_dir)

    def test_fifo_key_is_rejected_without_blocking(self) -> None:
        self.private_key.unlink()
        os.mkfifo(self.private_key, mode=0o600)
        artifact_directory = pathlib.Path(__file__).resolve().parent
        script = (
            "import pathlib, sys; "
            f"sys.path.insert(0, {str(artifact_directory)!r}); "
            "import android_device_proof; "
            "android_device_proof.validate_adb_identity_directory("
            f"pathlib.Path({str(self.android_dir)!r}))"
        )
        completed = subprocess.run(
            [sys.executable, "-I", "-S", "-B", "-c", script],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("regular non-symlink file", completed.stderr)

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS extended ACLs")
    def test_macos_allow_acl_on_every_identity_node_is_rejected(self) -> None:
        for path in (
            self.account_home,
            self.android_dir,
            self.private_key,
            self.public_key,
        ):
            with self.subTest(path=path):
                subprocess.run(
                    ["/bin/chmod", "+a", "everyone allow readattr", str(path)],
                    check=True,
                )
                try:
                    with self.assertRaisesRegex(SystemExit, "allow ACL is forbidden"):
                        android_device_proof.validate_account_adb_identity(
                            self.account_home, account_home=self.account_home
                        )
                finally:
                    subprocess.run(["/bin/chmod", "-N", str(path)], check=True)

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS extended ACLs")
    def test_macos_deny_only_home_acl_is_accepted(self) -> None:
        subprocess.run(
            ["/bin/chmod", "+a", "everyone deny delete", str(self.account_home)],
            check=True,
        )
        try:
            android_device_proof.validate_account_adb_identity(
                self.account_home, account_home=self.account_home
            )
        finally:
            subprocess.run(
                ["/bin/chmod", "-N", str(self.account_home)], check=True
            )

    def test_adb_server_status_requires_exact_executable_and_keystore(self) -> None:
        executable = pathlib.Path(sys.executable).resolve()
        expected_keystore = self.android_dir / "adbkey"
        fields = android_device_proof.parse_adb_server_status(
            f'executable_absolute_path: "{executable}"\n'
            f'keystore_path: "{expected_keystore}"\n'
            "mdns_enabled: false\n"
        )
        android_device_proof.validate_adb_server_status_fields(
            fields,
            selected_adb=executable,
            home_directory=self.account_home,
            account_home=self.account_home,
        )
        fields["keystore_path"] = str(self.android_dir / "different-key")
        with self.assertRaisesRegex(SystemExit, "keystore differs"):
            android_device_proof.validate_adb_server_status_fields(
                fields,
                selected_adb=executable,
                home_directory=self.account_home,
                account_home=self.account_home,
            )
        fields["keystore_path"] = str(expected_keystore)
        fields["mdns_enabled"] = True
        with self.assertRaisesRegex(SystemExit, "disable mDNS"):
            android_device_proof.validate_adb_server_status_fields(
                fields,
                selected_adb=executable,
                home_directory=self.account_home,
                account_home=self.account_home,
            )

    def test_adb_server_status_rejects_missing_duplicate_or_malformed_fields(self) -> None:
        invalid_statuses = (
            'executable_absolute_path: "/bin/false"\n',
            'keystore_path: "/tmp/key"\nkeystore_path: "/tmp/key"\n',
            "keystore_path: not-json\n",
            'keystore_path: {"path":"a","path":"b"}\n',
            "mdns_enabled: NaN\n",
        )
        for status in invalid_statuses:
            with self.subTest(status=status):
                with self.assertRaises(SystemExit):
                    android_device_proof.parse_adb_server_status(status)

    def test_lsof_listener_requires_one_canonical_pid_and_uid(self) -> None:
        self.assertEqual(
            android_device_proof.parse_lsof_adb_listener(
                "p123\nu501\nf18\nn127.0.0.1:5037\n",
                expected_endpoint="127.0.0.1:5037",
            ),
            (123, 501),
        )
        self.assertEqual(
            android_device_proof.parse_lsof_adb_listener(
                "p124\nu501\nf19\nn/tmp/qperiapt-adb.12345678/adb.sock\n",
                expected_endpoint="/tmp/qperiapt-adb.12345678/adb.sock",
            ),
            (124, 501),
        )
        invalid_outputs = (
            "",
            "p0123\nu501\nf18\n",
            "p123\nf18\n",
            "p123\nu501\np124\nu501\n",
            "p123\nu501\nu501\n",
            "p123\nu501\ncunknown\n",
            "p123\nu501\nf18\nn*:5037\n",
        )
        for output in invalid_outputs:
            with self.subTest(output=output):
                with self.assertRaises(SystemExit):
                    android_device_proof.parse_lsof_adb_listener(
                        output, expected_endpoint="127.0.0.1:5037"
                    )

    def test_default_adb_endpoint_probe_fails_closed(self) -> None:
        class Probe:
            def __init__(self, result: int) -> None:
                self.result = result

            def __enter__(self) -> "Probe":
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def settimeout(self, _: float) -> None:
                pass

            def connect_ex(self, _: tuple[object, ...]) -> int:
                return self.result

        with (
            mock.patch.object(android_device_proof.socket, "has_ipv6", False),
            mock.patch.object(
                android_device_proof.socket,
                "socket",
                return_value=Probe(android_device_proof.errno.ECONNREFUSED),
            ),
        ):
            android_device_proof.assert_default_adb_server_absent(
                argparse.Namespace()
            )

        for result in (0, android_device_proof.errno.EACCES):
            with self.subTest(result=result):
                with (
                    mock.patch.object(
                        android_device_proof.socket, "has_ipv6", False
                    ),
                    mock.patch.object(
                        android_device_proof.socket,
                        "socket",
                        return_value=Probe(result),
                    ),
                ):
                    with self.assertRaises(SystemExit):
                        android_device_proof.assert_default_adb_server_absent(
                            argparse.Namespace()
                        )

    def test_adb_listener_identity_rejects_wrong_process_or_environment(self) -> None:
        executable = pathlib.Path(sys.executable).resolve()
        uid = os.geteuid()

        def validate(**overrides: object) -> str:
            arguments: dict[str, object] = {
                "pid": 123,
                "reported_uid": uid,
                "process_uid": uid,
                "started_at": 456,
                "started_subsecond": 789,
                "executable": executable,
                "environment": {"HOME": str(self.account_home)},
                "selected_adb": executable,
                "account_home": self.account_home,
                "expected_identity": None,
            }
            arguments.update(overrides)
            return android_device_proof.validate_adb_listener_identity(**arguments)

        self.assertEqual(validate(), f"123:{uid}:456:789")
        private_environment = {
            "HOME": str(self.account_home),
            "ADB_SERVER_SOCKET": "localfilesystem:/tmp/qperiapt-adb.12345678/adb.sock",
            "ADB_VENDOR_KEYS": str(self.private_key),
            "ADB_MDNS": "0",
            "ADB_MDNS_AUTO_CONNECT": "0",
            "ADB_USB": "1",
            "ADB_EMU": "0",
            "ADB_LOCAL_TRANSPORT_MAX_PORT": "5585",
        }
        private_forbidden_environment = (
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
        )
        self.assertEqual(
            validate(
                environment=private_environment,
                expected_environment={
                    "ADB_SERVER_SOCKET": private_environment["ADB_SERVER_SOCKET"],
                    "ADB_VENDOR_KEYS": private_environment["ADB_VENDOR_KEYS"],
                    "ADB_MDNS": "0",
                    "ADB_MDNS_AUTO_CONNECT": "0",
                    "ADB_USB": "1",
                    "ADB_EMU": "0",
                    "ADB_LOCAL_TRANSPORT_MAX_PORT": "5585",
                },
                forbidden_environment=private_forbidden_environment,
            ),
            f"123:{uid}:456:789",
        )
        invalid_overrides = (
            {"reported_uid": uid + 1},
            {"executable": pathlib.Path("/bin/false")},
            {"environment": {"HOME": str(self.account_home), "ADB_VENDOR_KEYS": ""}},
            {"environment": {"HOME": "/different"}},
            {"expected_identity": "123:0:456:789"},
            {
                "environment": private_environment,
                "expected_environment": {
                    "ADB_SERVER_SOCKET": "localfilesystem:/tmp/wrong/adb.sock",
                    "ADB_VENDOR_KEYS": str(self.private_key),
                    "ADB_MDNS": "0",
                    "ADB_MDNS_AUTO_CONNECT": "0",
                    "ADB_USB": "1",
                    "ADB_EMU": "0",
                    "ADB_LOCAL_TRANSPORT_MAX_PORT": "5585",
                },
                "forbidden_environment": private_forbidden_environment,
            },
        )
        for overrides in invalid_overrides:
            with self.subTest(overrides=overrides):
                with self.assertRaises(SystemExit):
                    validate(**overrides)

    def test_private_adb_socket_requires_owned_directory_and_exact_socket_leaf(
        self,
    ) -> None:
        directory = create_private_adb_test_directory()
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        try:
            arguments = argparse.Namespace(directory=directory, state="absent")
            android_device_proof.verify_private_adb_socket(arguments)

            socket_path = directory / "adb.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.addCleanup(listener.close)
            listener.bind(str(socket_path))
            android_device_proof.verify_private_adb_socket(
                argparse.Namespace(directory=directory, state="present")
            )
            with self.assertRaisesRegex(SystemExit, "already exists"):
                android_device_proof.verify_private_adb_socket(arguments)
            listener.close()
            socket_path.unlink()

            os.mkfifo(socket_path, mode=0o600)
            with self.assertRaisesRegex(SystemExit, "not a socket"):
                android_device_proof.verify_private_adb_socket(
                    argparse.Namespace(directory=directory, state="present")
                )
            socket_path.unlink()

            directory.chmod(0o770)
            with self.assertRaisesRegex(SystemExit, "writable by group"):
                android_device_proof.verify_private_adb_socket(arguments)
            directory.chmod(0o750)
            with self.assertRaisesRegex(SystemExit, "mode 0700"):
                android_device_proof.verify_private_adb_socket(arguments)
        finally:
            directory.chmod(0o700)

    def test_private_listener_cli_binds_endpoint_pid_and_environment(self) -> None:
        endpoint = "/tmp/qperiapt-adb.12345678/adb.sock"
        lsof_output = self.account_home / "listener.txt"
        lsof_output.write_text(
            f"p123\nu{os.geteuid()}\nf18\nn{endpoint}\n", encoding="utf-8"
        )
        lsof_output = lsof_output.resolve()
        environment = {
            "HOME": str(self.account_home),
            "ADB_SERVER_SOCKET": f"localfilesystem:{endpoint}",
            "ADB_VENDOR_KEYS": str(self.private_key),
            "ADB_MDNS": "0",
            "ADB_MDNS_AUTO_CONNECT": "0",
            "ADB_USB": "1",
            "ADB_EMU": "0",
            "ADB_LOCAL_TRANSPORT_MAX_PORT": "5585",
        }
        arguments = argparse.Namespace(
            lsof_output=lsof_output,
            adb=pathlib.Path(sys.executable),
            expected_endpoint=endpoint,
            expected_pid=123,
            expected_identity=None,
            expected_server_socket=f"localfilesystem:{endpoint}",
            expected_vendor_keys=str(self.private_key),
            expected_mdns="0",
            expected_transport_kind="physical",
        )
        process_identity = (
            os.geteuid(),
            456,
            789,
            pathlib.Path(sys.executable).resolve(),
            environment,
        )
        with (
            mock.patch.object(android_device_proof.sys, "platform", "linux"),
            mock.patch.object(
                android_device_proof,
                "_linux_process_identity",
                return_value=process_identity,
            ),
            mock.patch.object(
                android_device_proof,
                "current_account_home",
                return_value=self.account_home,
            ),
        ):
            android_device_proof.verify_adb_listener(arguments)
            wrong_socket = copy.copy(arguments)
            wrong_socket.expected_server_socket = (
                "localfilesystem:/tmp/qperiapt-adb.87654321/adb.sock"
            )
            with self.assertRaisesRegex(SystemExit, "does not name"):
                android_device_proof.verify_adb_listener(wrong_socket)
            missing_pid = copy.copy(arguments)
            missing_pid.expected_pid = None
            with self.assertRaisesRegex(SystemExit, "requires its owned pid"):
                android_device_proof.verify_adb_listener(missing_pid)

    def test_private_adb_socket_rejects_wrong_shape_and_symlink_leaf(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wrong-adb.", dir="/tmp") as raw:
            directory = pathlib.Path(raw)
            directory.chmod(0o700)
            with self.assertRaisesRegex(SystemExit, "fixed-shape child"):
                android_device_proof.verify_private_adb_socket(
                    argparse.Namespace(directory=directory, state="absent")
                )

        directory = create_private_adb_test_directory()
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        target = directory / "target"
        target.write_bytes(b"not a socket")
        (directory / "adb.sock").symlink_to(target)
        with self.assertRaisesRegex(SystemExit, "not a socket"):
            android_device_proof.verify_private_adb_socket(
                argparse.Namespace(directory=directory, state="present")
            )

    def test_staged_proof_publication_is_atomic_and_never_clobbers(self) -> None:
        staging = self.account_home / "proof.pending"
        destination = self.account_home / "proof.json"
        staging.write_bytes(b'{"status":"pass"}\n')
        staging.chmod(0o600)
        android_device_proof.publish_staged_proof(
            argparse.Namespace(staging=staging, destination=destination)
        )
        self.assertFalse(staging.exists())
        self.assertEqual(destination.read_bytes(), b'{"status":"pass"}\n')
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)

        second_staging = self.account_home / "second.pending"
        second_staging.write_bytes(b"replacement\n")
        second_staging.chmod(0o600)
        with self.assertRaisesRegex(SystemExit, "destination already exists"):
            android_device_proof.publish_staged_proof(
                argparse.Namespace(staging=second_staging, destination=destination)
            )
        self.assertEqual(destination.read_bytes(), b'{"status":"pass"}\n')
        self.assertEqual(second_staging.read_bytes(), b"replacement\n")

    def test_staged_proof_publication_rejects_symlink_or_insecure_mode(self) -> None:
        source = self.account_home / "source"
        source.write_bytes(b"proof\n")
        source.chmod(0o600)
        staging = self.account_home / "proof.pending"
        staging.symlink_to(source)
        destination = self.account_home / "proof.json"
        with self.assertRaisesRegex(SystemExit, "not a regular file"):
            android_device_proof.publish_staged_proof(
                argparse.Namespace(staging=staging, destination=destination)
            )
        staging.unlink()
        staging.write_bytes(b"proof\n")
        staging.chmod(0o640)
        with self.assertRaisesRegex(SystemExit, "mode changed"):
            android_device_proof.publish_staged_proof(
                argparse.Namespace(staging=staging, destination=destination)
            )
        staging.chmod(0o600)
        extra_link = self.account_home / "proof.extra-link"
        os.link(staging, extra_link)
        with self.assertRaisesRegex(SystemExit, "unexpected hard links"):
            android_device_proof.publish_staged_proof(
                argparse.Namespace(staging=staging, destination=destination)
            )


class AndroidDeviceProofProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp_dir.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.name", "QPeriapt Test"], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.email", "test@invalid.local"], check=True)
        (self.root / ".gitignore").write_text("target/\n", encoding="utf-8")
        (self.root / "tracked.txt").write_text("clean\n", encoding="utf-8")
        self.core_source = self.root / "crates" / "q-periapt-core" / "src" / "lib.rs"
        self.core_source.parent.mkdir(parents=True)
        self.core_source.write_text("pub const PROOF_INPUT: &str = \"original\";\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "fixture"], check=True)
        self.commit = android_device_proof.git_commit(self.root)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_matching_clean_provenance_passes(self) -> None:
        android_device_proof.verify_git_provenance(
            self.root,
            {"git_commit": self.commit, "source_tree_dirty": False},
            allow_dirty_proof=False,
        )

    def test_apksigner_output_requires_one_exact_signer_digest(self) -> None:
        digest = "a" * 64
        output = (
            "Signer #1 certificate DN: CN=QPeriapt Android Smoke\n"
            f"Signer #1 certificate SHA-256 digest: {digest}\n"
            "Signer #1 certificate SHA-1 digest: deadbeef\n"
        )
        self.assertEqual(
            android_device_proof.parse_single_signer_sha256(output), digest
        )
        malformed_outputs = (
            "",
            "Signer #1 certificate SHA-256 digest: deadbeef\n",
            (
                f"Signer #1 certificate SHA-256 digest: {digest}\n"
                f"Signer #2 certificate SHA-256 digest: {'b' * 64}\n"
            ),
            f"Signer #2 certificate SHA-256 digest: {digest}\n",
        )
        for malformed in malformed_outputs:
            with self.subTest(output=malformed):
                with self.assertRaisesRegex(
                    SystemExit, "exactly one signer #1 SHA-256"
                ):
                    android_device_proof.parse_single_signer_sha256(malformed)

    def test_allow_dirty_never_bypasses_commit_binding(self) -> None:
        with self.assertRaisesRegex(SystemExit, "commit provenance failed"):
            android_device_proof.verify_git_provenance(
                self.root,
                {"git_commit": "0" * 40, "source_tree_dirty": True},
                allow_dirty_proof=True,
            )

    def test_evidence_only_successor_commit_can_bind_release_proof(self) -> None:
        proof_commit = self.commit
        proof_digest = android_device_proof.current_source_tree_digest(self.root)
        results = self.root / "artifact" / "results.json"
        results.parent.mkdir()
        results.write_text('{"proof":"bound"}\n', encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "artifact/results.json"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "bind evidence"], check=True)

        android_device_proof.verify_git_provenance(
            self.root,
            {"git_commit": proof_commit, "source_tree_dirty": False},
            allow_dirty_proof=False,
        )
        android_device_proof.verify_source_tree_digest(
            self.root,
            {"proof_source_tree_sha256": proof_digest},
        )

    def test_source_changing_successor_commit_is_rejected(self) -> None:
        proof_commit = self.commit
        (self.root / "tracked.txt").write_text("changed\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "tracked.txt"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "change source"], check=True)

        with self.assertRaisesRegex(SystemExit, "commit provenance failed"):
            android_device_proof.verify_git_provenance(
                self.root,
                {"git_commit": proof_commit, "source_tree_dirty": False},
                allow_dirty_proof=False,
            )

    def test_strict_verification_rejects_current_dirty_tree(self) -> None:
        (self.root / "untracked.txt").write_text("dirty\n", encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "current source tree is dirty"):
            android_device_proof.verify_git_provenance(
                self.root,
                {"git_commit": self.commit, "source_tree_dirty": False},
                allow_dirty_proof=False,
            )

    def test_diagnostic_verification_allows_dirty_tree_but_keeps_commit_binding(self) -> None:
        (self.root / "untracked.txt").write_text("dirty\n", encoding="utf-8")
        android_device_proof.verify_git_provenance(
            self.root,
            {"git_commit": self.commit, "source_tree_dirty": True},
            allow_dirty_proof=True,
        )

    def test_proof_schema_v3_is_required(self) -> None:
        proof = complete_proof_shape()
        wrong_schema = copy.deepcopy(proof)
        wrong_schema["schema"] = 2
        with self.assertRaisesRegex(SystemExit, "Android proof schema must be 3"):
            android_device_proof.verify_proof_schema(wrong_schema)
        android_device_proof.verify_proof_schema(proof)

        extra_top_level = copy.deepcopy(proof)
        extra_top_level["raw_serial"] = "emulator-5554"
        with self.assertRaisesRegex(SystemExit, "Android proof fields differ"):
            android_device_proof.verify_proof_schema(extra_top_level)

        extra_device_field = copy.deepcopy(proof)
        extra_device_field["device"]["serial"] = "emulator-5554"
        with self.assertRaisesRegex(SystemExit, "Android proof device fields differ"):
            android_device_proof.verify_proof_schema(extra_device_field)

        extra_result_field = copy.deepcopy(proof)
        extra_result_field["result"]["raw_serial"] = "emulator-5554"
        with self.assertRaisesRegex(SystemExit, "Android proof result fields differ"):
            android_device_proof.verify_proof_schema(extra_result_field)

    def test_freshness_gate_is_separate_from_timeless_schema_validation(self) -> None:
        proof = complete_proof_shape()
        android_device_proof.verify_proof_schema(proof)
        generated_at = dt.datetime(2026, 7, 15, tzinfo=dt.timezone.utc)
        proof["generated_at"] = generated_at.isoformat().replace("+00:00", "Z")
        android_device_proof.verify_proof_freshness(
            proof,
            86400,
            reference_time=generated_at + dt.timedelta(hours=23),
        )
        with self.assertRaisesRegex(SystemExit, "Android proof is stale"):
            android_device_proof.verify_proof_freshness(
                proof,
                86400,
                reference_time=generated_at + dt.timedelta(days=8),
            )

    def test_verify_bundle_cli_is_timeless_but_bundle_creation_has_freshness_gate(self) -> None:
        parser = android_device_proof.build_parser()
        bundle_args = parser.parse_args(
            [
                "verify-bundle",
                "--root",
                ".",
                "--bundle",
                "bundle.zip",
                "--llvm-nm",
                "llvm-nm",
                "--llvm-readelf",
                "llvm-readelf",
                "--apksigner",
                "apksigner",
                "--zipalign",
                "zipalign",
            ]
        )
        self.assertFalse(hasattr(bundle_args, "max_age_seconds"))
        create_args = parser.parse_args(
            [
                "create-bundle",
                "--root",
                ".",
                "--proof",
                "proof.json",
                "--output",
                "bundle.zip",
                "--llvm-nm",
                "llvm-nm",
                "--llvm-readelf",
                "llvm-readelf",
                "--apksigner",
                "apksigner",
                "--zipalign",
                "zipalign",
            ]
        )
        self.assertEqual(create_args.max_age_seconds, 86400)

    def test_release_device_metadata_requires_exact_16k_abi_bound_proof(self) -> None:
        proof = {
            "release_candidate_mode": True,
            "device": {
                "kind": "emulator",
                "serial_sha256_prefix": "3" * 12,
                "raw_serial_recorded": False,
                "manufacturer": "Google",
                "model": "Android SDK built for arm64",
                "abi": "arm64-v8a",
                "page_size": 16384,
                "sdk": 35,
                "release": "15",
                "fingerprint_sha256_prefix": "4" * 12,
            },
            "android": {
                "platform": "android-35",
                "min_sdk": 23,
                "target_sdk": 35,
                "ndk": "29.0.14206865",
                "native_page_alignment": 16384,
                "build_tools": "36.0.0",
                "adb_version": "Android Debug Bridge version 1.0.41",
                "apksigner_sha256": "0" * 64,
                "zipalign_sha256": "1" * 64,
            },
        }
        android_device_proof.verify_device_metadata(
            proof,
            expected_device_kind="emulator",
            expected_device_abi="arm64-v8a",
            expected_page_size=16384,
            expected_device_sdk=35,
            require_release_mode=True,
        )

    def test_device_kind_matches_explicit_expectation(self) -> None:
        proof = complete_proof_shape()
        proof["release_candidate_mode"] = True
        for actual_kind, other_kind in (
            ("emulator", "physical"),
            ("physical", "emulator"),
        ):
            with self.subTest(actual_kind=actual_kind):
                proof["device"]["kind"] = actual_kind
                android_device_proof.verify_device_metadata(
                    proof,
                    expected_device_kind=actual_kind,
                    expected_device_abi="arm64-v8a",
                    expected_page_size=16384,
                    expected_device_sdk=35,
                    require_release_mode=True,
                )
                with self.assertRaisesRegex(
                    SystemExit,
                    re.escape(
                        f"expected Android device kind {other_kind}, got {actual_kind}"
                    ),
                ):
                    android_device_proof.verify_device_metadata(
                        proof,
                        expected_device_kind=other_kind,
                        expected_device_abi="arm64-v8a",
                        expected_page_size=16384,
                        expected_device_sdk=35,
                        require_release_mode=True,
                    )

    def test_release_device_metadata_rejects_4k_device(self) -> None:
        proof = {
            "release_candidate_mode": True,
            "device": {
                "kind": "emulator",
                "serial_sha256_prefix": "3" * 12,
                "raw_serial_recorded": False,
                "manufacturer": "Google",
                "model": "Android SDK built for arm64",
                "abi": "arm64-v8a",
                "page_size": 4096,
                "sdk": 35,
                "release": "15",
                "fingerprint_sha256_prefix": "4" * 12,
            },
            "android": {
                "platform": "android-35",
                "min_sdk": 23,
                "target_sdk": 35,
                "ndk": "29.0.14206865",
                "native_page_alignment": 16384,
                "build_tools": "36.0.0",
                "adb_version": "Android Debug Bridge version 1.0.41",
                "apksigner_sha256": "0" * 64,
                "zipalign_sha256": "1" * 64,
            },
        }
        with self.assertRaisesRegex(SystemExit, "expected Android page size 16384"):
            android_device_proof.verify_device_metadata(
                proof,
                expected_device_abi="arm64-v8a",
                expected_page_size=16384,
                expected_device_sdk=35,
                require_release_mode=True,
            )

    def test_device_sdk_is_an_exact_integer_and_matches_expectation(self) -> None:
        proof = {
            "release_candidate_mode": False,
            "device": {
                "kind": "emulator",
                "serial_sha256_prefix": "3" * 12,
                "raw_serial_recorded": False,
                "manufacturer": "Google",
                "model": "Android SDK built for arm64",
                "abi": "arm64-v8a",
                "page_size": 16384,
                "sdk": 35,
                "release": "15",
                "fingerprint_sha256_prefix": "4" * 12,
            },
            "android": {
                "platform": "android-35",
                "min_sdk": 23,
                "target_sdk": 35,
                "ndk": "29.0.14206865",
                "native_page_alignment": 16384,
                "build_tools": "36.0.0",
                "adb_version": "Android Debug Bridge version 1.0.41",
                "apksigner_sha256": "0" * 64,
                "zipalign_sha256": "1" * 64,
            },
        }
        android_device_proof.verify_device_metadata(
            proof, expected_device_sdk=35
        )
        for invalid in (None, True, "35", 35.0):
            with self.subTest(invalid=invalid):
                proof["device"]["sdk"] = invalid
                with self.assertRaisesRegex(SystemExit, "invalid Android device SDK"):
                    android_device_proof.verify_device_metadata(
                        proof, expected_device_sdk=35
                    )
        proof["device"]["sdk"] = 34
        with self.assertRaisesRegex(SystemExit, "expected Android device SDK 35"):
            android_device_proof.verify_device_metadata(
                proof, expected_device_sdk=35
            )

    def test_release_requires_expected_device_and_target_sdk_35(self) -> None:
        proof = {
            "release_candidate_mode": True,
            "device": {
                "kind": "emulator",
                "serial_sha256_prefix": "3" * 12,
                "raw_serial_recorded": False,
                "manufacturer": "Google",
                "model": "Android SDK built for arm64",
                "abi": "arm64-v8a",
                "page_size": 16384,
                "sdk": 35,
                "release": "15",
                "fingerprint_sha256_prefix": "4" * 12,
            },
            "android": {
                "platform": "android-35",
                "min_sdk": 23,
                "target_sdk": 35,
                "ndk": "29.0.14206865",
                "native_page_alignment": 16384,
                "build_tools": "36.0.0",
                "adb_version": "Android Debug Bridge version 1.0.41",
                "apksigner_sha256": "0" * 64,
                "zipalign_sha256": "1" * 64,
            },
        }
        for expected_sdk in (None, 34):
            with self.subTest(expected_sdk=expected_sdk):
                with self.assertRaisesRegex(
                    SystemExit, "release verification requires expected Android device SDK 35"
                ):
                    android_device_proof.verify_device_metadata(
                        proof,
                        expected_device_abi="arm64-v8a",
                        expected_page_size=16384,
                        expected_device_sdk=expected_sdk,
                        require_release_mode=True,
                    )
        proof["android"]["platform"] = "android-34"
        proof["android"]["target_sdk"] = 34
        with self.assertRaisesRegex(SystemExit, "not built against SDK 35"):
            android_device_proof.verify_device_metadata(
                proof,
                expected_device_abi="arm64-v8a",
                expected_page_size=16384,
                expected_device_sdk=35,
                require_release_mode=True,
            )

    def test_release_toolchain_metadata_is_exact_and_bound_to_ndk_tools(self) -> None:
        proof = complete_proof_shape()
        proof["release_candidate_mode"] = True
        android_device_proof.verify_device_metadata(
            proof,
            expected_device_abi="arm64-v8a",
            expected_page_size=16384,
            expected_device_sdk=35,
            require_release_mode=True,
        )
        proof["android"]["ndk"] = "29.1.0"
        with self.assertRaisesRegex(SystemExit, "must use NDK 29.0.14206865"):
            android_device_proof.verify_device_metadata(
                proof,
                expected_device_abi="arm64-v8a",
                expected_page_size=16384,
                expected_device_sdk=35,
                require_release_mode=True,
            )
        proof["android"]["ndk"] = "29.0.14206865"
        proof["android"]["build_tools"] = "35.0.0"
        with self.assertRaisesRegex(SystemExit, "must use build-tools 36.0.0"):
            android_device_proof.verify_device_metadata(
                proof,
                expected_device_abi="arm64-v8a",
                expected_page_size=16384,
                expected_device_sdk=35,
                require_release_mode=True,
            )
        proof["android"]["build_tools"] = "not-a-version"
        with self.assertRaisesRegex(SystemExit, "invalid build-tools metadata"):
            android_device_proof.verify_device_metadata(proof)
        proof["android"]["build_tools"] = "36.0.0"
        proof["android"]["adb_version"] = "adb 1.0.41\nsecret"
        with self.assertRaisesRegex(SystemExit, "invalid adb version metadata"):
            android_device_proof.verify_device_metadata(proof)

        ndk = self.root / "ndk" / "29.0.14206865"
        bin_directory = (
            ndk / "toolchains" / "llvm" / "prebuilt" / "darwin-aarch64" / "bin"
        )
        bin_directory.mkdir(parents=True)
        (ndk / "source.properties").write_text(
            "Pkg.Revision = 29.0.14206865\n", encoding="utf-8"
        )
        llvm_nm = bin_directory / "llvm-nm"
        llvm_readelf = bin_directory / "llvm-readelf"
        for tool in (llvm_nm, llvm_readelf):
            tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            tool.chmod(0o700)
        resolved_nm, resolved_readelf, revision = (
            android_device_proof.verified_ndk_tools(llvm_nm, llvm_readelf)
        )
        self.assertEqual(resolved_nm, llvm_nm.resolve(strict=True))
        self.assertEqual(resolved_readelf, llvm_readelf.resolve(strict=True))
        self.assertEqual(revision, "29.0.14206865")

    def test_device_sdk_cli_type_is_canonical_and_bounded(self) -> None:
        self.assertEqual(android_device_proof.validate_device_sdk("35"), 35)
        for invalid in ("0", "+35", "035", "35.0", "1000"):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(
                    argparse.ArgumentTypeError, "canonical integer between 1 and 999"
                ):
                    android_device_proof.validate_device_sdk(invalid)

    def test_matching_canonical_source_tree_digest_passes(self) -> None:
        digest = android_device_proof.current_source_tree_digest(self.root)
        android_device_proof.verify_source_tree_digest(
            self.root,
            {"proof_source_tree_sha256": digest},
        )

    def test_missing_source_tree_digest_fails_closed(self) -> None:
        with self.assertRaisesRegex(SystemExit, "lacks a valid proof_source_tree_sha256"):
            android_device_proof.verify_source_tree_digest(self.root, {})

    def test_tampered_source_tree_digest_fails_closed(self) -> None:
        with self.assertRaisesRegex(SystemExit, "canonical source-input tree changed"):
            android_device_proof.verify_source_tree_digest(
                self.root,
                {"proof_source_tree_sha256": "0" * 64},
            )

    def test_core_change_invalidates_dirty_diagnostic_proof(self) -> None:
        digest = android_device_proof.current_source_tree_digest(self.root)
        self.core_source.write_text("pub const PROOF_INPUT: &str = \"changed\";\n", encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "canonical source-input tree changed"):
            android_device_proof.verify_source_tree_digest(
                self.root,
                {"proof_source_tree_sha256": digest},
            )

    def test_ignored_target_proof_does_not_create_a_self_hash_loop(self) -> None:
        digest = android_device_proof.current_source_tree_digest(self.root)
        proof_output = self.root / "target" / "android" / "proof.json"
        proof_output.parent.mkdir(parents=True)
        proof_output.write_text('{"proof_source_tree_sha256":"placeholder"}\n', encoding="utf-8")
        self.assertEqual(digest, android_device_proof.current_source_tree_digest(self.root))

    def test_expected_runtime_inventory_uses_atomic_policy_decision(self) -> None:
        self.assertIn(
            "signedPolicyDecisionIsExactAndFailClosed",
            android_device_proof.EXPECTED_TESTS,
        )
        self.assertNotIn(
            "combineReferenceVectors",
            android_device_proof.EXPECTED_TESTS,
        )
        self.assertEqual(len(android_device_proof.EXPECTED_TESTS), 3)

    def test_producer_and_verifier_source_input_inventories_match(self) -> None:
        producer = (pathlib.Path(__file__).resolve().parent / "android-device-smoke.sh").read_text(
            encoding="utf-8"
        )
        match = re.search(r"source_paths = \{\n(?P<body>.*?)\n\}", producer, re.DOTALL)
        self.assertIsNotNone(match)
        entries = dict(
            re.findall(r'^    "([^"]+)": root / "([^"]+)",$', match.group("body"), re.MULTILINE)
        )
        self.assertEqual(entries, android_device_proof.SOURCE_INPUTS)

    def test_producer_runs_independent_verifier_before_pass_marker(self) -> None:
        producer = (pathlib.Path(__file__).resolve().parent / "android-device-smoke.sh").read_text(
            encoding="utf-8"
        )
        verify = producer.index("artifact/android_device_proof.py verify")
        bundle = producer.index("artifact/android_device_proof.py create-bundle")
        pass_marker = producer.index("ANDROID_DEVICE_RUNTIME_PASS")
        self.assertLess(verify, pass_marker)
        self.assertLess(verify, bundle)
        self.assertLess(bundle, pass_marker)
        self.assertIn('QPERIAPT_ANDROID_EXPECT_SDK=35', producer)
        self.assertIn('"sdk": device_sdk', producer)
        self.assertIn('--expected-device-sdk "$DEVICE_SDK"', producer)

    def test_temporary_keystore_is_private_and_cleaned_on_every_exit(self) -> None:
        producer = (
            pathlib.Path(__file__).resolve().parent / "android-device-smoke.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("umask 077", producer)
        self.assertIn('chmod 700 "$WORK" "$DIST"', producer)
        keystore_assignment = producer.index(
            'KEYSTORE="$WORK/qperiapt-android-smoke.p12"'
        )
        exit_trap = producer.index("trap cleanup_exit EXIT")
        keytool = producer.index("keytool -genkeypair")
        signer = producer.index('"$APKSIGNER" sign')
        eager_removal = producer.index('rm -f -- "$KEYSTORE"', signer)
        self.assertLess(keystore_assignment, exit_trap)
        self.assertLess(exit_trap, keytool)
        self.assertLess(keytool, eager_removal)
        self.assertIn('rm -f -- "$KEYSTORE"', producer[keystore_assignment:keytool])
        self.assertIn("stop_emulator_process()", producer)
        self.assertIn("emulator_cleanup_deadline=$(monotonic_deadline 20)", producer)
        self.assertNotIn('kill -TERM "$EMULATOR_PID"', producer)
        self.assertNotIn('kill -KILL "$EMULATOR_PID"', producer)
        self.assertNotIn('kill -TERM "$ADB_PRIVATE_SERVER_PID"', producer)
        self.assertNotIn('kill -KILL "$ADB_PRIVATE_SERVER_PID"', producer)
        self.assertNotIn("|| :", producer)
        self.assertNotIn("|| true", producer)
        self.assertNotIn("qperiapt-android-smoke.p12", "\n".join(android_device_proof.BUNDLE_FILE_PATHS.values()))

    def test_temporary_app_and_booted_avd_are_bound_and_cleaned(self) -> None:
        producer = (
            pathlib.Path(__file__).resolve().parent / "android-device-smoke.sh"
        ).read_text(encoding="utf-8")
        trap_index = producer.index("trap cleanup_exit EXIT")
        preflight_index = producer.index(
            "if ! package_state=$(query_package_state); then", trap_index
        )
        armed_index = producer.index("ANDROID_APP_CLEANUP_ARMED=1", preflight_index)
        install_index = producer.index(
            'adb_for_serial 120 install --no-incremental "$SIGNED_APK"', armed_index
        )
        normal_cleanup_index = producer.index(
            "if ! cleanup_android_app; then", install_index
        )
        cleanup_index = producer.index(
            'if [ "${ANDROID_APP_CLEANUP_ARMED:-0}" = "1" ]; then'
        )
        emulator_cleanup_index = producer.index(
            'if [ "${EMULATOR_STARTED:-0}" = "1" ]', cleanup_index
        )
        boot_loop_index = producer.index(
            "EMULATOR_ADB_DEADLINE=$(monotonic_deadline 90)"
        )
        child_liveness_index = producer.index(
            "if ! emulator_process_active; then", boot_loop_index
        )
        bound_serial_index = producer.index(
            '-s "$EXPECTED_EMULATOR_SERIAL" get-state', boot_loop_index
        )
        self.assertLess(producer.index("ANDROID_APP_CLEANUP_ARMED=0"), trap_index)
        self.assertLess(trap_index, preflight_index)
        self.assertLess(preflight_index, armed_index)
        self.assertLess(armed_index, install_index)
        self.assertLess(install_index, normal_cleanup_index)
        self.assertLess(cleanup_index, emulator_cleanup_index)
        self.assertLess(child_liveness_index, bound_serial_index)
        self.assertIn("adb-uninstall-cleanup.log", producer)
        self.assertIn(
            "cleanup_android_app || runtime_internal_cleanup_status=1",
            producer[cleanup_index:emulator_cleanup_index],
        )
        self.assertNotIn("\n\tcleanup_status=", producer)
        self.assertNotIn("\n\towned_process_recorded=", producer)
        self.assertNotIn("\n\tprocess_stopped=", producer)
        verifier_start = producer.index("verify_installed_apk_signer()")
        verifier_end = producer.index("cleanup_android_app()", verifier_start)
        verifier = producer[verifier_start:verifier_end]
        self.assertLess(
            verifier.index('installed_apk_identity" != "$SIGNED_APK_IDENTITY'),
            verifier.index('installed_signer_sha256" != "$EXPECTED_APK_SIGNER_SHA256'),
        )
        cleanup_start = verifier_end
        cleanup_end = producer.index("cleanup_runtime()", cleanup_start)
        cleanup = producer[cleanup_start:cleanup_end]
        threshold = cleanup.index(
            'if [ "$absent_observations" -ge "$required_absent_observations" ]'
        )
        disarm = cleanup.index("ANDROID_APP_CLEANUP_ARMED=0", threshold)
        present = cleanup.index("present)")
        signer_gate = cleanup.index("verify_installed_apk_signer", present)
        owned_uninstall = cleanup.index(
            'adb_for_serial 60 uninstall "$PACKAGE"', signer_gate
        )
        unknown_outcome = cleanup.index("uninstall=unknown-or-failed", owned_uninstall)
        self.assertLess(threshold, disarm)
        self.assertLess(present, signer_gate)
        self.assertLess(signer_gate, owned_uninstall)
        self.assertLess(owned_uninstall, unknown_outcome)
        self.assertNotIn('install -r "$SIGNED_APK"', producer)
        self.assertNotIn("logcat -c", producer)
        self.assertIn("QPERIAPT_ANDROID_SERIAL is required", producer)
        self.assertIn(
            "QPERIAPT_ANDROID_EXPECT_DEVICE_KIND=physical", producer
        )
        self.assertIn("refusing automatic Android device selection", producer)
        self.assertIn("run_bounded_command()", producer)
        self.assertIn("run_bounded_to_file()", producer)
        self.assertIn("artifact/bounded_process.py run", producer)
        self.assertIn("artifact/bounded_process.py write", producer)
        bounded_process_source = (
            pathlib.Path(__file__).resolve().parent / "bounded_process.py"
        ).read_text(encoding="utf-8")
        self.assertIn("command timed out after", bounded_process_source)
        self.assertIn("command output exceeds", bounded_process_source)
        self.assertIn("remaining_bounded_timeout()", producer)
        self.assertIn(
            "BOOT_COMPLETION_DEADLINE=$(monotonic_deadline 120)", producer
        )
        self.assertIn(
            "RUNTIME_RESULT_DEADLINE=$(monotonic_deadline 90)", producer
        )
        self.assertIn(
            'run_bounded_command "$emulator_attempt_timeout"', producer
        )
        self.assertIn('adb_for_serial "$boot_attempt_timeout"', producer)
        self.assertIn(
            'run_bounded_to_file "$result_attempt_timeout"', producer
        )
        self.assertNotIn('while [ "$i" -lt 90 ]; do', producer)
        self.assertNotIn('while [ "$i" -lt 120 ]; do', producer)
        self.assertIn("ADB_VENDOR_KEYS is not supported", producer)
        self.assertIn("ADB_SERVER_SOCKET is not supported", producer)
        self.assertIn("ANDROID_ADB_SERVER_ADDRESS is not supported", producer)
        self.assertIn("ANDROID_ADB_SERVER_PORT is not supported", producer)
        for variable in (
            "ADB_VENDOR_KEYS",
            "ADB_SERVER_SOCKET",
            "ANDROID_ADB_SERVER_ADDRESS",
            "ANDROID_ADB_SERVER_PORT",
            "ADB_MDNS",
            "ADB_MDNS_AUTO_CONNECT",
            "ADB_MDNS_OPENSCREEN",
            "ADB_USB",
            "ADB_EMU",
            "ADB_REJECT_KILL_SERVER",
            "ADB_LOCAL_TRANSPORT_MAX_PORT",
            "ADB_OSX_USB_CLEAR_ENDPOINTS",
            "ANDROID_ADB_LOG_PATH",
            "ADB_TRACE",
            "ADB_INSTALL_DEFAULT_INCREMENTAL",
            "ADB_LIBUSB",
            "ADB_LIBUSB_START_DETACHED",
        ):
            self.assertIn(f'"${{{variable}+x}}" = x', producer)
        self.assertIn("verify-adb-identity", producer)
        self.assertIn('--home-directory "$HOME"', producer)
        verifier_source = (
            pathlib.Path(__file__).resolve().parent / "android_device_proof.py"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "existing {label} is required before device proof", verifier_source
        )
        self.assertIn(
            "HOME must match the current account home directory", verifier_source
        )
        self.assertLess(
            producer.index("verify-adb-identity"),
            producer.index("server nodaemon"),
        )
        device_selection_section = producer.index("=== Select Android runtime device ===")
        default_listener_gate = producer.index(
            "\nassert_default_adb_server_absent\n", device_selection_section
        )
        server_cleanup_arm = producer.index("ADB_PRIVATE_SERVER_CLEANUP_ARMED=1")
        server_start = producer.index("server nodaemon", server_cleanup_arm)
        server_pid_capture = producer.index("ADB_PRIVATE_SERVER_PID=$!", server_start)
        client_transport_disable = producer.index(
            "export ADB_USB=0", server_pid_capture
        )
        recovery_identity_print = producer.index("private-adb: pid=", server_pid_capture)
        initial_listener_check = producer.index("verify-adb-listener", server_start)
        first_server_check = producer.index(
            "verify-adb-server-status", initial_listener_check
        )
        first_listener_check = producer.index(
            "verify-adb-listener", first_server_check
        )
        device_selection = producer.index("SERIAL=$(select_serial_or_empty)")
        second_server_check = producer.rindex("verify-adb-server-status")
        second_listener_check = producer.rindex("verify-adb-listener")
        proof_emission = producer.index('python3 - "$ROOT" "$RUN_ID"', device_selection)
        proof_staging_write = producer.index(
            "descriptor = os.open(proof, flags, 0o600)", proof_emission
        )
        proof_publication = producer.index("publish-staged-proof", second_listener_check)
        runtime_cleanup = producer.index(
            "cleanup_runtime_with_deferred_signals", second_listener_check
        )
        final_default_listener_gate = producer.rindex(
            "\nassert_default_adb_server_absent\n"
        )
        proof_verification = producer.index(
            "artifact/android_device_proof.py verify \\", second_listener_check
        )
        proof_bundle = producer.index(
            "artifact/android_device_proof.py create-bundle", proof_verification
        )
        evidence_confirmation = producer.index(
            "ANDROID_PROOF_EVIDENCE_CONFIRMED=1", proof_bundle
        )
        pass_marker = producer.index("ANDROID_DEVICE_RUNTIME_PASS", evidence_confirmation)
        self.assertLess(default_listener_gate, server_cleanup_arm)
        self.assertLess(server_cleanup_arm, server_start)
        self.assertLess(server_start, server_pid_capture)
        self.assertLess(server_pid_capture, client_transport_disable)
        self.assertLess(client_transport_disable, recovery_identity_print)
        self.assertLess(recovery_identity_print, initial_listener_check)
        self.assertLess(client_transport_disable, initial_listener_check)
        self.assertLess(initial_listener_check, first_server_check)
        self.assertLess(first_server_check, first_listener_check)
        self.assertLess(first_listener_check, device_selection)
        self.assertLess(proof_staging_write, second_server_check)
        self.assertLess(second_server_check, second_listener_check)
        self.assertLess(second_listener_check, runtime_cleanup)
        self.assertLess(runtime_cleanup, final_default_listener_gate)
        self.assertLess(final_default_listener_gate, proof_publication)
        self.assertLess(second_listener_check, proof_publication)
        self.assertLess(proof_publication, proof_verification)
        self.assertLess(proof_verification, proof_bundle)
        self.assertLess(proof_bundle, evidence_confirmation)
        self.assertLess(evidence_confirmation, pass_marker)
        self.assertLess(second_listener_check, proof_verification)
        self.assertIn('--expected-identity "$ADB_LISTENER_IDENTITY"', producer)
        self.assertIn('--expected-pid "$ADB_PRIVATE_SERVER_PID"', producer)
        self.assertIn(
            '--expected-server-socket "$ADB_PRIVATE_SERVER_SOCKET_SPEC"', producer
        )
        self.assertIn(
            '--expected-vendor-keys "$ADB_PRIVATE_VENDOR_KEY"', producer
        )
        self.assertIn("--expected-mdns 0", producer)
        self.assertIn(
            '--expected-transport-kind "$EXPECTED_DEVICE_KIND"', producer
        )
        self.assertIn(
            'ADB_PRIVATE_SERVER_SOCKET_SPEC="localfilesystem:$ADB_PRIVATE_SERVER_SOCKET_PATH"',
            producer,
        )
        self.assertIn('"$ADB" -L "$ADB_PRIVATE_SERVER_SOCKET_SPEC"', producer)
        self.assertIn("default adb server is already listening", verifier_source)
        self.assertNotIn('"$ADB" start-server', producer)
        self.assertNotIn('"$ADB" kill-server', producer)
        self.assertNotIn('"$ADB" -s ', producer)
        self.assertNotIn('"$ADB" devices', producer)
        self.assertNotIn('"$ADB" server-status', producer)
        self.assertNotIn('[str(adb), "-s"', producer)
        self.assertNotIn('[str(adb), "version"', producer)
        self.assertIn('--one-device "$QPERIAPT_ANDROID_SERIAL"', producer)
        self.assertIn("export ADB_MDNS=0", producer)
        self.assertIn("export ADB_MDNS_AUTO_CONNECT=0", producer)
        self.assertIn("export ADB_LOCAL_TRANSPORT_MAX_PORT=5585", producer)
        self.assertIn("export ADB_USB=1", producer)
        self.assertIn("export ADB_EMU=0", producer)
        self.assertIn("physical Android evidence requires one USB transport", producer)
        self.assertEqual(
            producer.count("\nassert_default_adb_server_absent\n"), 3
        )
        self.assertIn(
            'PROOF_STAGING="$WORK/qperiapt-android-device-proof.json.pending"',
            producer,
        )
        self.assertIn("ANDROID_PROOF_EVIDENCE_CONFIRMED=1", producer)
        self.assertIn("cleanup_unconfirmed_proof", producer)
        self.assertIn('proof_destination.parent / "apksigner-verify.txt"', producer)
        self.assertIn('proof_destination.parent / "zipalign-verify.txt"', producer)
        self.assertIn("was not already authorized", producer)
        self.assertIn("ANDROID_APP_INSTALL_CONFIRMED=1", producer)
        self.assertIn("required_absent_observations=8", producer)
        self.assertIn("Android app cleanup outcome is unresolved", producer)
        self.assertIn(
            "refusing to boot a proof AVD while another adb device is already online",
            producer,
        )
        self.assertIn(
            'ANDROID_EMULATOR_PORT=${QPERIAPT_ANDROID_EMULATOR_PORT:-5584}',
            producer,
        )
        self.assertIn('ANDROID_BOOT_AVD=${QPERIAPT_ANDROID_BOOT_AVD:-0}', producer)
        self.assertIn(
            'ANDROID_KEEP_EMULATOR=${QPERIAPT_ANDROID_KEEP_EMULATOR:-0}', producer
        )
        self.assertIn(
            'EXPECTED_DEVICE_KIND=${QPERIAPT_ANDROID_EXPECT_DEVICE_KIND:-any}', producer
        )
        self.assertIn(
            "Android release emulator proof requires QPERIAPT_ANDROID_BOOT_AVD=1",
            producer,
        )
        self.assertIn(
            "Android release emulator proof must use the script-started cold-boot AVD",
            producer,
        )
        self.assertIn(
            "Android release mode requires an explicit QPERIAPT_ANDROID_EXPECT_DEVICE_KIND",
            producer,
        )
        self.assertIn('EXPECTED_EMULATOR_SERIAL="emulator-$ANDROID_EMULATOR_PORT"', producer)
        self.assertIn('-port "$ANDROID_EMULATOR_PORT"', producer)
        self.assertIn('SERIAL=$EXPECTED_EMULATOR_SERIAL', producer)
        self.assertIn("temporary Android emulator exited before its bound adb serial", producer)
        self.assertIn("\n\t\t-read-only \\\n", producer)
        self.assertNotIn(
            'if [ -z "$SERIAL" ] && [ "${QPERIAPT_ANDROID_BOOT_AVD:-0}" = "1" ]',
            producer,
        )

    def test_android_release_entrypoints_default_to_stable_sdk_contract(self) -> None:
        artifact = pathlib.Path(__file__).resolve().parent
        for name in ("android-aar.sh", "android-device-smoke.sh"):
            with self.subTest(entrypoint=name):
                source = (artifact / name).read_text(encoding="utf-8")
                self.assertIn(
                    'ANDROID_PLATFORM=${QPERIAPT_ANDROID_PLATFORM:-"$ANDROID_SDK/platforms/android-35"}',
                    source,
                )
                self.assertNotIn(
                    'ANDROID_PLATFORM=${QPERIAPT_ANDROID_PLATFORM:-$(choose_highest_child',
                    source,
                )
                self.assertIn(
                    'ANDROID_BUILD_TOOLS=${QPERIAPT_ANDROID_BUILD_TOOLS:-"$ANDROID_SDK/build-tools/36.0.0"}',
                    source,
                )
                self.assertNotIn(
                    'ANDROID_BUILD_TOOLS=${QPERIAPT_ANDROID_BUILD_TOOLS:-$(choose_highest_child',
                    source,
                )

        producer = (artifact / "android-device-smoke.sh").read_text(encoding="utf-8")
        self.assertIn("\n\t\t-no-snapshot \\\n", producer)
        self.assertIn("ANDROID_RELEASE_BUILD_TOOLS=36.0.0", producer)
        self.assertIn(
            'ANDROID_BUILD_TOOLS=${QPERIAPT_ANDROID_BUILD_TOOLS:-"$ANDROID_SDK/build-tools/36.0.0"}',
            producer,
        )
        self.assertIn(
            'if [ "$ANDROID_RELEASE_MODE" = "1" ] && [ "$ANDROID_BUILD_TOOLS" != "$EXPECTED_RELEASE_BUILD_TOOLS" ]; then',
            producer,
        )

    def test_producer_captures_only_the_smoke_log_tag(self) -> None:
        producer = (
            pathlib.Path(__file__).resolve().parent / "android-device-smoke.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("capture_app_logcat()", producer)
        self.assertIn(
            'logcat -d -v tag -T "$LOGCAT_START_EPOCH"', producer
        )
        self.assertIn("needle = f\"run-id={run_id}\"", producer)
        self.assertNotIn('"$ADB" -s "$SERIAL" logcat -d >', producer)
        self.assertNotIn("logcat -c", producer)

    def test_result_verifier_rejects_unrelated_logcat_data(self) -> None:
        run_id = "a" * 32
        result_txt = self.root / "result.txt"
        result_json = self.root / "result.json"
        logcat = self.root / "logcat.txt"
        result_txt.write_text(
            android_device_proof.expected_marker(run_id) + "\n", encoding="utf-8"
        )
        result_json.write_text(
            '{"schema":1,"status":"pass","run_id":"'
            + run_id
            + '","test_count":3,"passed_tests":['
            '"runtimeMetadataMatches",'
            '"signedPolicyDecisionIsExactAndFailClosed",'
            '"osRandomPolicyRoundtripAndWipes"]}\n',
            encoding="utf-8",
        )
        paths = {
            "result_txt": result_txt,
            "result_json": result_json,
            "logcat": logcat,
        }
        valid_line = (
            "I/QPeriaptSmoke: QPERIAPT_ANDROID_DEVICE_PASS "
            f"run-id={run_id} tests=3\n"
        )
        logcat.write_text(valid_line, encoding="utf-8")
        android_device_proof.verify_result_files(paths, run_id)
        logcat.write_text(
            "--------- beginning of main\n"
            "I/QPeriaptSmoke( 123): QPERIAPT_ANDROID_DEVICE_PASS "
            f"run-id={run_id} tests=3\n",
            encoding="utf-8",
        )
        android_device_proof.verify_result_files(paths, run_id)
        logcat.write_text(
            valid_line + "I/OtherApplication: private data\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(SystemExit, "outside the QPeriaptSmoke tag"):
            android_device_proof.verify_result_files(paths, run_id)
        logcat.write_text(
            "I/QPeriaptSmoke: QPERIAPT_ANDROID_DEVICE_PASS "
            f"run-id={'b' * 32} tests=3\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(SystemExit, "another run"):
            android_device_proof.verify_result_files(paths, run_id)
        logcat.write_text("", encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "exactly one run-bound PASS"):
            android_device_proof.verify_result_files(paths, run_id)
        logcat.write_text(
            "I/OtherApplication: mentions QPeriaptSmoke but is unrelated\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(SystemExit, "outside the QPeriaptSmoke tag"):
            android_device_proof.verify_result_files(paths, run_id)

    def test_private_directory_canonicalization_accepts_only_aliases_above_leaf(self) -> None:
        physical_parent = self.root / "physical-parent"
        private_directory = physical_parent / "private"
        private_directory.mkdir(parents=True, mode=0o700)
        private_directory.chmod(0o700)
        alias_parent = self.root / "alias-parent"
        try:
            alias_parent.symlink_to(physical_parent, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"platform cannot create a directory symlink: {exc}")

        resolved = android_device_proof.canonical_private_directory(
            alias_parent / "private", "test private directory"
        )
        self.assertEqual(resolved, private_directory.resolve(strict=True))
        self.assertTrue(stat.S_ISDIR(resolved.lstat().st_mode))

        leaf_alias = self.root / "private-leaf-alias"
        leaf_alias.symlink_to(private_directory, target_is_directory=True)
        with self.assertRaisesRegex(SystemExit, "must be a non-symlink directory"):
            android_device_proof.canonical_private_directory(
                leaf_alias, "test private directory"
            )

    def test_bundle_manifest_binds_exact_fixed_file_set(self) -> None:
        bundle_root = self.root / "bundle"
        proof = complete_proof_shape()
        payloads = {
            key: (
                android_device_proof.canonical_json(proof)
                if key == "proof"
                else f"evidence-{key}\n".encode("utf-8")
            )
            for key in android_device_proof.BUNDLE_FILE_PATHS
        }
        records = {}
        for key, relative in android_device_proof.BUNDLE_FILE_PATHS.items():
            path = bundle_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payloads[key])
            records[key] = {
                "bytes": len(payloads[key]),
                "path": relative,
                "sha256": android_device_proof.sha256_bytes(payloads[key]),
            }
        manifest = {
            "schema_version": android_device_proof.BUNDLE_SCHEMA_VERSION,
            "kind": android_device_proof.BUNDLE_KIND,
            "source_date_epoch": 1_700_000_000,
            "git_commit": proof["git_commit"],
            "run_id": proof["run_id"],
            "release_candidate_mode": False,
            "device": {
                key: proof["device"][key]
                for key in ("kind", "abi", "page_size", "sdk")
            },
            "raw_serial_recorded": False,
            "files": records,
        }
        selected, parsed_proof = android_device_proof.verify_bundle_manifest(
            bundle_root,
            manifest,
            archive_mtime=1_700_000_000,
        )
        self.assertEqual(set(android_device_proof.BUNDLE_FILE_PATHS), set(selected))
        self.assertEqual(proof, parsed_proof)
        self.assertNotIn("keystore", "\n".join(android_device_proof.BUNDLE_FILE_PATHS.values()))

        missing_sdk = copy.deepcopy(manifest)
        del missing_sdk["device"]["sdk"]
        with self.assertRaisesRegex(SystemExit, "bundle device fields differ"):
            android_device_proof.verify_bundle_manifest(
                bundle_root,
                missing_sdk,
                archive_mtime=1_700_000_000,
            )

        wrong_sdk = copy.deepcopy(manifest)
        wrong_sdk["device"]["sdk"] = 34
        with self.assertRaisesRegex(SystemExit, "device metadata differs from proof"):
            android_device_proof.verify_bundle_manifest(
                bundle_root,
                wrong_sdk,
                archive_mtime=1_700_000_000,
            )

        extra_device_field = copy.deepcopy(manifest)
        extra_device_field["device"]["model"] = "unbound"
        with self.assertRaisesRegex(SystemExit, "bundle device fields differ"):
            android_device_proof.verify_bundle_manifest(
                bundle_root,
                extra_device_field,
                archive_mtime=1_700_000_000,
            )

        tampered_proof = copy.deepcopy(proof)
        tampered_proof["device"]["sdk"] = 34
        proof_path = selected["proof"]
        proof_path.write_bytes(android_device_proof.canonical_json(tampered_proof))
        cross_tamper = copy.deepcopy(manifest)
        cross_tamper["files"]["proof"] = android_device_proof.bundle_file_record(
            proof_path,
            android_device_proof.BUNDLE_FILE_PATHS["proof"],
        )
        with self.assertRaisesRegex(SystemExit, "device metadata differs from proof"):
            android_device_proof.verify_bundle_manifest(
                bundle_root,
                cross_tamper,
                archive_mtime=1_700_000_000,
            )
        proof_path.write_bytes(android_device_proof.canonical_json(proof))

        selected["logcat"].write_text("tampered\n", encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "bundled evidence bytes differ"):
            android_device_proof.verify_bundle_manifest(
                bundle_root,
                manifest,
                archive_mtime=1_700_000_000,
            )

    def test_proof_path_inventory_rejects_extra_dependencies(self) -> None:
        paths = {key: f"target/{key}" for key in android_device_proof.PROOF_PATH_KEYS}
        android_device_proof.proof_path_fields({"paths": paths})
        paths["keystore"] = "target/debug.keystore"
        with self.assertRaisesRegex(SystemExit, "path fields differ"):
            android_device_proof.proof_path_fields({"paths": paths})


if __name__ == "__main__":
    unittest.main()
