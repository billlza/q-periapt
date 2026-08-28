from __future__ import annotations

import argparse
import contextlib
import copy
import errno
import hashlib
import io
import json
import os
import pathlib
import stat
import tarfile
import tempfile
import types
import unittest
from unittest import mock

import release_consumer_smoke


class ReleaseConsumerFlagTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.package = pathlib.Path(self.temporary.name).resolve()
        self.include = self.package / "include/qperiapt/abi2"
        self.library = self.package / "lib"
        self.include.mkdir(parents=True)
        self.library.mkdir()
        self.dynamic = self.library / "libq_periapt_ffi.2.dylib"
        self.static = self.library / "libq_periapt_ffi_abi2.a"
        self.dynamic.write_bytes(b"dynamic fixture")
        self.static.write_bytes(b"static fixture")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_canonical_dynamic_and_static_flags_pass(self) -> None:
        dynamic = release_consumer_smoke.validate_pkg_config_flags(
            self.package,
            [
                f"-I{self.include}",
                str(self.dynamic),
                f"-Wl,-rpath,{self.library}",
            ],
            static=False,
        )
        self.assertEqual(
            dynamic,
            [
                f"-I{self.include}",
                str(self.dynamic),
                f"-Wl,-rpath,{self.library}",
            ],
        )
        static = release_consumer_smoke.validate_pkg_config_flags(
            self.package,
            [f"-I{self.include}", str(self.static), "-liconv"],
            static=True,
        )
        self.assertEqual(static, [f"-I{self.include}", str(self.static), "-liconv"])

    def test_compiler_control_flags_fail_closed(self) -> None:
        hostile = (
            "@response-file",
            "-o",
            "-specs=hostile.specs",
            "-Wl,-plugin,/tmp/plugin.so",
            "-Xlinker",
            "-I/tmp/outside",
            "/tmp/libq_periapt_ffi.2.dylib",
        )
        for flag in hostile:
            with self.subTest(flag=flag), self.assertRaises(SystemExit):
                release_consumer_smoke.validate_pkg_config_flags(
                    self.package,
                    [f"-I{self.include}", str(self.dynamic), flag],
                    static=False,
                )

    def test_compile_and_runtime_use_allowlisted_environment(self) -> None:
        smoke = self.package / "share/q-periapt/smoke.c"
        smoke.parent.mkdir(parents=True)
        smoke.write_text("int main(void) { return 0; }\n", encoding="utf-8")
        hostile = {
            "CFLAGS": "-fplugin=/tmp/hostile.so",
            "CPATH": "/tmp/hostile-include",
            "DEVELOPER_DIR": "/tmp/hostile-xcode",
            "HOME": "/tmp/hostile-home",
            "LIBRARY_PATH": "/tmp/hostile-lib",
            "LD_PRELOAD": "/tmp/hostile.so",
            "MACOSX_DEPLOYMENT_TARGET": "99.0",
            "SDKROOT": "/tmp/hostile-sdk",
            "TMPDIR": "/tmp/hostile-tmp",
        }
        with (
            mock.patch.dict(os.environ, hostile, clear=False),
            mock.patch.object(
                release_consumer_smoke,
                "run_cmd",
                side_effect=["", "ALL PASS\n"],
            ) as run,
        ):
            release_consumer_smoke.compile_and_run_c_smoke(
                self.package,
                self.package / "work",
                "/usr/bin/cc",
                "dynamic",
                [f"-I{self.include}", str(self.dynamic)],
            )

        compile_environment = run.call_args_list[0].kwargs["env"]
        runtime_environment = run.call_args_list[1].kwargs["env"]
        for name in hostile:
            self.assertNotIn(name, compile_environment)
            self.assertNotIn(name, runtime_environment)

    def test_tool_resolution_ignores_caller_path(self) -> None:
        hostile_tool = self.package / "cc"
        hostile_tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        hostile_tool.chmod(0o755)
        with mock.patch.dict(os.environ, {"PATH": str(self.package)}):
            resolved = pathlib.Path(release_consumer_smoke.need_tool("cc"))
        self.assertNotEqual(resolved, hostile_tool)
        self.assertTrue(
            any(
                resolved.is_relative_to(trusted_root)
                for _candidate, trusted_root in release_consumer_smoke.TRUSTED_TOOL_CANDIDATES[
                    "cc"
                ]
            )
        )

    def test_cli_uses_only_fixed_repository_paths(self) -> None:
        source = pathlib.Path(release_consumer_smoke.__file__).read_text(
            encoding="utf-8"
        )
        for option in ("--root", "--index", "--out-dir"):
            self.assertNotIn(f'add_argument("{option}"', source)
        for variable in (
            "QPERIAPT_RELEASE_INDEX_PATH",
            "QPERIAPT_RELEASE_CONSUMER_OUT_DIR",
        ):
            self.assertNotIn(variable, source)

    def test_output_directory_is_private_and_fixed(self) -> None:
        repository = self.package / "repository"
        (repository / "target").mkdir(parents=True)
        with mock.patch.object(
            release_consumer_smoke, "REPOSITORY_ROOT", repository
        ):
            output = release_consumer_smoke.resolve_output_dir()
        self.assertEqual(output, repository / "target/qperiapt-release-consumer-smoke")
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)

    def test_archive_is_consumed_from_the_verified_size_and_digest_snapshot(self) -> None:
        archive_path = self.package / "package.tar.gz"

        def archive_bytes(payload: bytes) -> bytes:
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode="w:gz") as archive:
                info = tarfile.TarInfo("package/README.md")
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            return output.getvalue()

        original = archive_bytes(b"original")
        replacement = archive_bytes(b"replacement")
        archive_path.write_bytes(original)
        reference = release_consumer_smoke.VerifiedArchiveReference(
            path=archive_path,
            size=len(original),
            sha256=hashlib.sha256(original).hexdigest(),
        )
        archive_path.write_bytes(replacement)
        with self.assertRaisesRegex(SystemExit, "changed after release-index"):
            release_consumer_smoke.safe_extract_tar_gz(
                reference,
                self.package / "replacement-extract",
            )

        archive_path.write_bytes(original)
        destination = self.package / "original-extract"
        release_consumer_smoke.safe_extract_tar_gz(reference, destination)
        self.assertEqual(
            (destination / "package/README.md").read_bytes(),
            b"original",
        )
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)

    def test_mode_results_are_returned_only_after_both_consumers_pass(self) -> None:
        root = self.package / "repository"
        out_dir = root / "target/consumer"
        out_dir.mkdir(parents=True)
        archive = release_consumer_smoke.VerifiedArchiveReference(
            path=root / "target/package.tar.gz",
            size=123,
            sha256="a" * 64,
        )

        def run_smoke(
            failure_mode: str | None,
        ) -> tuple[release_consumer_smoke.ConsumerModeResults | None, list[str]]:
            executed: list[str] = []

            def compile_mode(
                _package_root: pathlib.Path,
                _work: pathlib.Path,
                _cc: str,
                label: str,
                _flags: list[str],
            ) -> None:
                executed.append(label)
                if label == failure_mode:
                    raise SystemExit(f"error: {label} consumer failed")

            with (
                mock.patch.object(release_consumer_smoke, "safe_extract_tar_gz"),
                mock.patch.object(
                    release_consumer_smoke,
                    "find_c_package_root",
                    return_value=self.package,
                ),
                mock.patch.object(release_consumer_smoke, "verify_sha256s"),
                mock.patch.object(
                    release_consumer_smoke,
                    "need_tool",
                    side_effect=["/usr/bin/cc", "/usr/bin/pkg-config"],
                ),
                mock.patch.object(
                    release_consumer_smoke.platform,
                    "system",
                    return_value="Darwin",
                ),
                mock.patch.object(
                    release_consumer_smoke,
                    "pkg_config",
                    side_effect=[["dynamic-flags"], ["static-flags"]],
                ),
                mock.patch.object(
                    release_consumer_smoke,
                    "compile_and_run_c_smoke",
                    side_effect=compile_mode,
                ),
            ):
                try:
                    result = release_consumer_smoke.smoke_c_archive(
                        root,
                        "b" * 64,
                        archive,
                        out_dir,
                    )
                except SystemExit:
                    result = None
            return result, executed

        result, executed = run_smoke(None)
        self.assertEqual(result, release_consumer_smoke.ConsumerModeResults.passed())
        self.assertEqual(executed, ["dynamic", "static"])

        result, executed = run_smoke("dynamic")
        self.assertIsNone(result)
        self.assertEqual(executed, ["dynamic"])

        result, executed = run_smoke("static")
        self.assertIsNone(result)
        self.assertEqual(executed, ["dynamic", "static"])

    def test_nonpassing_mode_results_cannot_be_serialized(self) -> None:
        with self.assertRaisesRegex(SystemExit, "modes are not both passing"):
            release_consumer_smoke.ConsumerModeResults(
                dynamic="pass",
                static="fail",
            ).receipt_value()


class ReleaseConsumerReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name).resolve()
        self.target = self.root / "target"
        self.target.mkdir(mode=0o700)
        self.out_dir = self.target / "qperiapt-release-consumer-smoke"
        self.out_dir.mkdir(mode=0o700)
        self.index_path = (
            self.target
            / "qperiapt-local-release/release/0.1.4"
            / ("a" * 40)
            / "index.json"
        )
        self.index_path.parent.mkdir(parents=True, mode=0o700)
        self.index_path.write_text("{}\n", encoding="utf-8")
        self.archive_path = self.index_path.parent / "artifacts/c/package.tar.gz"
        self.archive_path.parent.mkdir(parents=True)
        archive_bytes = b"verified C archive fixture"
        self.archive_path.write_bytes(archive_bytes)
        self.archive = release_consumer_smoke.VerifiedArchiveReference(
            path=self.archive_path,
            size=len(archive_bytes),
            sha256=hashlib.sha256(archive_bytes).hexdigest(),
        )
        self.source_commit = "a" * 40
        self.source_tree_sha256 = "b" * 64
        self.index_sha256 = "c" * 64
        self.runtime_run_id = "d" * 32
        self.runtime_proof_sha256 = "e" * 64
        self.android_aar_sha256 = "f" * 64
        self.index_generated_at = "2026-08-12T12:00:00Z"
        self.receipt_generated_at = "2026-08-12T12:01:00Z"
        self.index = {
            "schema_version": release_consumer_smoke.RELEASE_INDEX_SCHEMA_VERSION,
            "channel": "release",
            "diagnostic_only": False,
            "generated_at": self.index_generated_at,
            "git": {
                "commit": self.source_commit,
                "source_tree_dirty": False,
            },
            "artifacts": [
                {
                    "face": "android",
                    "files": [{"sha256": self.android_aar_sha256}],
                }
            ],
            "proof_summaries": {
                "android_runtime": {
                    "sha256": self.runtime_proof_sha256,
                    "result": {"run_id": self.runtime_run_id},
                }
            },
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def publish(self, run_id: str = "1" * 32):
        with (
            mock.patch.object(
                release_consumer_smoke,
                "repository_paths",
                return_value=(pathlib.Path("Cargo.toml"),),
            ),
            mock.patch.object(
                release_consumer_smoke,
                "canonical_tree_digest",
                return_value=self.source_tree_sha256,
            ),
            mock.patch.object(
                release_consumer_smoke,
                "canonical_utc_now",
                return_value=self.receipt_generated_at,
            ),
            mock.patch.object(
                release_consumer_smoke.secrets,
                "token_hex",
                side_effect=[run_id, "2" * 32],
            ),
        ):
            return release_consumer_smoke.publish_consumer_receipt(
                root=self.root,
                out_dir=self.out_dir,
                index_path=self.index_path,
                index_sha256=self.index_sha256,
                index=self.index,
                archive=self.archive,
                mode_results=release_consumer_smoke.ConsumerModeResults.passed(),
            )

    def receipt_validation_arguments(self, run_id: str) -> dict[str, object]:
        return {
            "root": self.root,
            "expected_run_id": run_id,
            "expected_source_commit": self.source_commit,
            "expected_source_tree_dirty": False,
            "expected_source_tree_sha256": self.source_tree_sha256,
            "expected_index_path": self.index_path.relative_to(self.root).as_posix(),
            "expected_index_sha256": self.index_sha256,
            "expected_index_generated_at": self.index_generated_at,
            "expected_c_archive": self.archive,
            "expected_android_aar_sha256": self.android_aar_sha256,
            "expected_android_runtime_run_id": self.runtime_run_id,
            "expected_android_runtime_proof_sha256": self.runtime_proof_sha256,
        }

    @staticmethod
    def write_receipt(path: pathlib.Path, value: dict[str, object]) -> str:
        data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
        path.write_bytes(data)
        path.chmod(0o600)
        return hashlib.sha256(data).hexdigest()

    def test_success_publishes_one_private_append_only_schema1_receipt(self) -> None:
        run_id = "1" * 32
        snapshot = self.publish(run_id)
        expected_path = (
            self.out_dir
            / "receipts"
            / run_id
            / release_consumer_smoke.CONSUMER_RECEIPT_LEAF
        )
        self.assertEqual(snapshot.file.path, expected_path)
        self.assertEqual(snapshot.value["schema_version"], 1)
        self.assertEqual(
            snapshot.value["consumer_modes"],
            {"dynamic": "pass", "static": "pass"},
        )
        self.assertEqual(snapshot.value["android_aar_sha256"], self.android_aar_sha256)
        self.assertEqual(snapshot.value["android_runtime_run_id"], self.runtime_run_id)
        self.assertEqual(
            snapshot.value["android_runtime_proof_sha256"],
            self.runtime_proof_sha256,
        )
        self.assertEqual(stat.S_IMODE(expected_path.stat().st_mode), 0o600)
        self.assertEqual(expected_path.stat().st_nlink, 1)
        for directory in (self.out_dir, expected_path.parents[1], expected_path.parent):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        reloaded = release_consumer_smoke.load_private_consumer_receipt(
            expected_path,
            expected_sha256=snapshot.file.sha256,
        )
        self.assertEqual(reloaded.value, snapshot.value)

    def test_existing_run_and_existing_receipt_are_never_replaced(self) -> None:
        run_id = "3" * 32
        receipts = self.out_dir / "receipts"
        receipts.mkdir(mode=0o700)
        run_directory = receipts / run_id
        run_directory.mkdir(mode=0o700)
        receipt_path = run_directory / release_consumer_smoke.CONSUMER_RECEIPT_LEAF
        sentinel = b"existing immutable receipt\n"
        receipt_path.write_bytes(sentinel)
        receipt_path.chmod(0o600)

        with (
            mock.patch.object(
                release_consumer_smoke,
                "repository_paths",
                return_value=(pathlib.Path("Cargo.toml"),),
            ),
            mock.patch.object(
                release_consumer_smoke,
                "canonical_tree_digest",
                return_value=self.source_tree_sha256,
            ),
            mock.patch.object(
                release_consumer_smoke,
                "canonical_utc_now",
                return_value=self.receipt_generated_at,
            ),
            mock.patch.object(
                release_consumer_smoke.secrets,
                "token_hex",
                return_value=run_id,
            ),
            self.assertRaisesRegex(SystemExit, "refusing replacement"),
        ):
            release_consumer_smoke.publish_consumer_receipt(
                root=self.root,
                out_dir=self.out_dir,
                index_path=self.index_path,
                index_sha256=self.index_sha256,
                index=self.index,
                archive=self.archive,
                mode_results=release_consumer_smoke.ConsumerModeResults.passed(),
            )
        self.assertEqual(receipt_path.read_bytes(), sentinel)

        with (
            mock.patch.object(
                release_consumer_smoke.secrets,
                "token_hex",
                return_value="4" * 32,
            ),
            self.assertRaisesRegex(SystemExit, "append-only and already exists"),
        ):
            release_consumer_smoke._publish_append_only_receipt(
                run_directory,
                b'{"replacement":true}\n',
            )
        self.assertEqual(receipt_path.read_bytes(), sentinel)
        self.assertEqual(list(run_directory.iterdir()), [receipt_path])

    def test_receipt_outer_hash_and_private_metadata_are_enforced(self) -> None:
        snapshot = self.publish("5" * 32)
        receipt_path = snapshot.file.path
        receipt_path.write_bytes(snapshot.file.data + b" ")
        receipt_path.chmod(0o600)
        with self.assertRaisesRegex(SystemExit, "hash differs"):
            release_consumer_smoke.load_private_consumer_receipt(
                receipt_path,
                expected_sha256=snapshot.file.sha256,
            )

        receipt_path.write_bytes(snapshot.file.data)
        insecure_metadata = os.stat_result(
            (
                stat.S_IFREG | 0o644,
                1,
                1,
                1,
                os.geteuid(),
                os.getegid(),
                len(snapshot.file.data),
                0,
                0,
                0,
            )
        )
        with self.assertRaisesRegex(
            release_consumer_smoke.EvidenceIOError,
            "mode 0600",
        ):
            release_consumer_smoke._private_receipt_metadata(insecure_metadata)

        hardlink = receipt_path.with_name("receipt-hardlink.json")
        os.link(receipt_path, hardlink)
        with self.assertRaisesRegex(SystemExit, "mode 0600"):
            release_consumer_smoke.load_private_consumer_receipt(receipt_path)
        hardlink.unlink()

    def test_all_receipt_bindings_reject_inner_tampering(self) -> None:
        run_id = "6" * 32
        snapshot = self.publish(run_id)
        cases = {
            "source_commit": "9" * 40,
            "source_tree_dirty": True,
            "proof_source_tree_sha256": "9" * 64,
            "index_path": "target/other/index.json",
            "index_sha256": "9" * 64,
            "index_generated_at": "2026-08-12T12:00:01Z",
            "c_archive_path": "target/other/package.tar.gz",
            "c_archive_bytes": self.archive.size + 1,
            "c_archive_sha256": "9" * 64,
            "android_aar_sha256": "9" * 64,
            "android_runtime_run_id": "9" * 32,
            "android_runtime_proof_sha256": "9" * 64,
            "consumer_modes": {"dynamic": "pass", "static": "skipped"},
        }
        arguments = self.receipt_validation_arguments(run_id)
        for field, replacement in cases.items():
            with self.subTest(field=field), self.assertRaises(SystemExit):
                tampered = copy.deepcopy(snapshot.value)
                tampered[field] = replacement
                release_consumer_smoke.validate_consumer_receipt(
                    tampered,
                    **arguments,
                )

    def test_dynamic_or_static_failure_never_calls_receipt_publisher(self) -> None:
        selection = types.SimpleNamespace(
            path=self.index_path,
            expected_sha256=self.index_sha256,
            expected_generated_at=self.index_generated_at,
        )
        verified = types.SimpleNamespace(
            path=self.index_path,
            sha256=self.index_sha256,
            value=self.index,
        )
        arguments = argparse.Namespace(channel="release", allow_diagnostic=False)
        for failure_mode in ("dynamic", "static"):
            with (
                self.subTest(failure_mode=failure_mode),
                mock.patch.object(
                    release_consumer_smoke,
                    "REPOSITORY_ROOT",
                    self.root,
                ),
                mock.patch.object(
                    release_consumer_smoke,
                    "resolve_output_dir",
                    return_value=self.out_dir,
                ),
                mock.patch.object(
                    release_consumer_smoke,
                    "release_pointer_selection",
                    return_value=selection,
                ),
                mock.patch.object(
                    release_consumer_smoke,
                    "verify_release_index_snapshot",
                    return_value=verified,
                ),
                mock.patch.object(
                    release_consumer_smoke,
                    "c_archive_entries",
                    return_value=[self.archive],
                ),
                mock.patch.object(
                    release_consumer_smoke,
                    "smoke_c_archive",
                    side_effect=SystemExit(f"error: {failure_mode} consumer failed"),
                ),
                mock.patch.object(
                    release_consumer_smoke,
                    "publish_consumer_receipt",
                ) as publish,
                self.assertRaisesRegex(SystemExit, failure_mode),
            ):
                release_consumer_smoke.run_consumer(arguments)
            publish.assert_not_called()
            self.assertFalse((self.out_dir / "receipts").exists())

    def test_run_success_publishes_receipt_and_only_then_prints_pass(self) -> None:
        run_id = "7" * 32
        selection = types.SimpleNamespace(
            path=self.index_path,
            expected_sha256=self.index_sha256,
            expected_generated_at=self.index_generated_at,
        )
        verified = types.SimpleNamespace(
            path=self.index_path,
            sha256=self.index_sha256,
            value=self.index,
        )
        output = io.StringIO()
        with (
            mock.patch.object(release_consumer_smoke, "REPOSITORY_ROOT", self.root),
            mock.patch.object(
                release_consumer_smoke,
                "resolve_output_dir",
                return_value=self.out_dir,
            ),
            mock.patch.object(
                release_consumer_smoke,
                "release_pointer_selection",
                return_value=selection,
            ),
            mock.patch.object(
                release_consumer_smoke,
                "verify_release_index_snapshot",
                return_value=verified,
            ) as verify_index,
            mock.patch.object(
                release_consumer_smoke,
                "c_archive_entries",
                return_value=[self.archive],
            ),
            mock.patch.object(
                release_consumer_smoke,
                "smoke_c_archive",
                return_value=release_consumer_smoke.ConsumerModeResults.passed(),
            ),
            mock.patch.object(
                release_consumer_smoke,
                "repository_paths",
                return_value=(pathlib.Path("Cargo.toml"),),
            ),
            mock.patch.object(
                release_consumer_smoke,
                "canonical_tree_digest",
                return_value=self.source_tree_sha256,
            ),
            mock.patch.object(
                release_consumer_smoke,
                "canonical_utc_now",
                return_value=self.receipt_generated_at,
            ),
            mock.patch.object(
                release_consumer_smoke.secrets,
                "token_hex",
                side_effect=[run_id, "8" * 32],
            ),
            contextlib.redirect_stdout(output),
        ):
            release_consumer_smoke.run_consumer(
                argparse.Namespace(channel="release", allow_diagnostic=False)
            )
        receipt_path = (
            self.out_dir
            / "receipts"
            / run_id
            / release_consumer_smoke.CONSUMER_RECEIPT_LEAF
        )
        self.assertTrue(receipt_path.is_file())
        self.assertEqual(verify_index.call_count, 3)
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].startswith("QPERIAPT_RELEASE_CONSUMER_RECEIPT_PASS"))
        self.assertEqual(lines[1], "QPERIAPT_RELEASE_CONSUMER_SMOKE_PASS c-abi")

    def test_post_receipt_source_recheck_failure_preserves_receipt_without_pass(
        self,
    ) -> None:
        run_id = "4" * 32
        selection = types.SimpleNamespace(
            path=self.index_path,
            expected_sha256=self.index_sha256,
            expected_generated_at=self.index_generated_at,
        )
        verified = types.SimpleNamespace(
            path=self.index_path,
            sha256=self.index_sha256,
            value=self.index,
        )
        output = io.StringIO()
        with (
            mock.patch.object(release_consumer_smoke, "REPOSITORY_ROOT", self.root),
            mock.patch.object(
                release_consumer_smoke, "resolve_output_dir", return_value=self.out_dir
            ),
            mock.patch.object(
                release_consumer_smoke,
                "release_pointer_selection",
                return_value=selection,
            ),
            mock.patch.object(
                release_consumer_smoke,
                "verify_release_index_snapshot",
                side_effect=[
                    verified,
                    verified,
                    SystemExit("error: source changed after receipt publication"),
                ],
            ),
            mock.patch.object(
                release_consumer_smoke,
                "c_archive_entries",
                return_value=[self.archive],
            ),
            mock.patch.object(
                release_consumer_smoke,
                "smoke_c_archive",
                return_value=release_consumer_smoke.ConsumerModeResults.passed(),
            ),
            mock.patch.object(
                release_consumer_smoke,
                "repository_paths",
                return_value=(pathlib.Path("Cargo.toml"),),
            ),
            mock.patch.object(
                release_consumer_smoke,
                "canonical_tree_digest",
                return_value=self.source_tree_sha256,
            ),
            mock.patch.object(
                release_consumer_smoke,
                "canonical_utc_now",
                return_value=self.receipt_generated_at,
            ),
            mock.patch.object(
                release_consumer_smoke.secrets,
                "token_hex",
                side_effect=[run_id, "5" * 32],
            ),
            contextlib.redirect_stdout(output),
            self.assertRaisesRegex(SystemExit, "source changed"),
        ):
            release_consumer_smoke.run_consumer(
                argparse.Namespace(channel="release", allow_diagnostic=False)
            )
        receipt_path = (
            self.out_dir
            / "receipts"
            / run_id
            / release_consumer_smoke.CONSUMER_RECEIPT_LEAF
        )
        self.assertTrue(receipt_path.is_file())
        self.assertEqual(output.getvalue(), "")

    def test_receipt_cleanup_failure_is_visible_with_primary_failure(self) -> None:
        run_id = "9" * 32
        with (
            mock.patch.object(
                release_consumer_smoke,
                "repository_paths",
                return_value=(pathlib.Path("Cargo.toml"),),
            ),
            mock.patch.object(
                release_consumer_smoke,
                "canonical_tree_digest",
                return_value=self.source_tree_sha256,
            ),
            mock.patch.object(
                release_consumer_smoke,
                "canonical_utc_now",
                return_value=self.receipt_generated_at,
            ),
            mock.patch.object(
                release_consumer_smoke.secrets,
                "token_hex",
                return_value=run_id,
            ),
            mock.patch.object(
                release_consumer_smoke,
                "_publish_append_only_receipt",
                side_effect=SystemExit("error: publication failed"),
            ),
            mock.patch.object(
                pathlib.Path,
                "rmdir",
                side_effect=OSError("cleanup denied"),
            ),
            self.assertRaisesRegex(SystemExit, "publication failed") as raised,
        ):
            release_consumer_smoke.publish_consumer_receipt(
                root=self.root,
                out_dir=self.out_dir,
                index_path=self.index_path,
                index_sha256=self.index_sha256,
                index=self.index,
                archive=self.archive,
                mode_results=release_consumer_smoke.ConsumerModeResults.passed(),
            )
        self.assertIn("cleanup also failed", str(raised.exception))
        self.assertIn("receipt cleanup also failed", str(raised.exception))
        self.assertIn("cleanup denied", str(raised.exception))

    def test_staging_cleanup_failure_is_visible_with_publication_failure(self) -> None:
        run_directory = self.out_dir / "direct-publication"
        run_directory.mkdir(mode=0o700)
        with (
            mock.patch.object(
                release_consumer_smoke.secrets,
                "token_hex",
                return_value="a" * 32,
            ),
            mock.patch.object(
                release_consumer_smoke.os,
                "link",
                side_effect=OSError(errno.EIO, "link failed"),
            ),
            mock.patch.object(
                release_consumer_smoke.os,
                "unlink",
                side_effect=OSError(errno.EACCES, "pending cleanup denied"),
            ),
            self.assertRaisesRegex(SystemExit, "link failed") as raised,
        ):
            release_consumer_smoke._publish_append_only_receipt(
                run_directory,
                b'{"complete":true}\n',
            )
        self.assertIn("cleanup also failed", str(raised.exception))
        self.assertIn("staging cleanup also failed", str(raised.exception))
        self.assertIn("pending cleanup denied", str(raised.exception))

    def test_diagnostic_consumer_runs_without_emitting_a_release_receipt(self) -> None:
        diagnostic = copy.deepcopy(self.index)
        diagnostic["channel"] = "diagnostic"
        diagnostic["diagnostic_only"] = True
        verified = types.SimpleNamespace(
            path=self.index_path,
            sha256=self.index_sha256,
            value=diagnostic,
        )
        with (
            mock.patch.object(release_consumer_smoke, "REPOSITORY_ROOT", self.root),
            mock.patch.object(
                release_consumer_smoke, "resolve_output_dir", return_value=self.out_dir
            ),
            mock.patch.object(
                release_consumer_smoke,
                "release_pointer_selection",
                return_value=types.SimpleNamespace(
                    path=self.index_path,
                    expected_sha256=self.index_sha256,
                    expected_generated_at=self.index_generated_at,
                ),
            ),
            mock.patch.object(
                release_consumer_smoke,
                "verify_release_index_snapshot",
                return_value=verified,
            ),
            mock.patch.object(
                release_consumer_smoke,
                "c_archive_entries",
                return_value=[self.archive],
            ),
            mock.patch.object(
                release_consumer_smoke,
                "smoke_c_archive",
                return_value=release_consumer_smoke.ConsumerModeResults.passed(),
            ),
            mock.patch.object(
                release_consumer_smoke, "publish_consumer_receipt"
            ) as publish,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            release_consumer_smoke.run_consumer(
                argparse.Namespace(channel="diagnostic", allow_diagnostic=True)
            )
        publish.assert_not_called()
        self.assertEqual(
            output.getvalue().strip(),
            "QPERIAPT_DIAGNOSTIC_RELEASE_CONSUMER_SMOKE_PASS c-abi receipt=not_emitted",
        )

    def bound_manifest(self, snapshot) -> dict[str, object]:
        return {
            "local_release_index": {
                "current_source_status": "current_clean_tree_local_index_consumer_pass",
                "source_commit": self.source_commit,
                "proof_source_tree_sha256": self.source_tree_sha256,
                "index_path": self.index_path.relative_to(self.root).as_posix(),
                "index_sha256": self.index_sha256,
                "generated_at": self.index_generated_at,
                "consumer_receipt_run_id": snapshot.value["run_id"],
                "consumer_receipt_generated_at": self.receipt_generated_at,
                "android_runtime_run_id": self.runtime_run_id,
                "android_runtime_proof_sha256": self.runtime_proof_sha256,
            },
            "android_device_runtime": {
                "run_id": self.runtime_run_id,
                "proof_sha256": self.runtime_proof_sha256,
            },
            "android_aar": {"aar_sha256": self.android_aar_sha256},
        }

    def verify_bound(
        self,
        manifest_value: dict[str, object],
        receipt_path: pathlib.Path,
        receipt_sha256: str,
    ) -> None:
        section = manifest_value["local_release_index"]
        assert isinstance(section, dict)
        index_declaration = types.SimpleNamespace(
            path=self.root / str(section["index_path"]),
            sha256=section["index_sha256"],
        )
        receipt_declaration = types.SimpleNamespace(
            path=receipt_path,
            sha256=receipt_sha256,
        )

        def declaration(_root, _manifest, *, binding: str):
            if binding == "local_release_index":
                return index_declaration
            if binding == "local_release_consumer":
                return receipt_declaration
            raise AssertionError(f"unexpected binding {binding}")

        verified = types.SimpleNamespace(
            path=index_declaration.path,
            sha256=index_declaration.sha256,
            value=self.index,
        )
        with (
            mock.patch.object(release_consumer_smoke, "REPOSITORY_ROOT", self.root),
            mock.patch.object(
                release_consumer_smoke,
                "load_results_manifest_snapshot",
                return_value=types.SimpleNamespace(value=manifest_value),
            ) as load_results,
            mock.patch.object(
                release_consumer_smoke,
                "resolve_bound_file_declaration",
                side_effect=declaration,
            ),
            mock.patch.object(
                release_consumer_smoke,
                "verify_release_index_snapshot",
                return_value=verified,
            ) as verify_index,
            mock.patch.object(
                release_consumer_smoke,
                "c_archive_entries",
                return_value=[self.archive],
            ),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            release_consumer_smoke.verify_bound_consumer("0" * 64)
        self.assertTrue(
            output.getvalue().startswith(
                "QPERIAPT_RESULTS_BOUND_RELEASE_CONSUMER_VERIFY_PASS "
            )
        )
        load_results.assert_called_once_with(
            self.root / "artifact/results.json",
            expected_sha256="0" * 64,
        )
        verify_index.assert_called_once_with(
            index_declaration.path,
            self.root,
            allow_diagnostic=False,
            expected_index_sha256=index_declaration.sha256,
            expected_generated_at=section["generated_at"],
        )

    def test_bound_verifier_accepts_the_exact_selected_chain(self) -> None:
        snapshot = self.publish("a" * 32)
        self.verify_bound(
            self.bound_manifest(snapshot),
            snapshot.file.path,
            snapshot.file.sha256,
        )

    def test_bound_verifier_rejects_hash_index_aar_runtime_and_source_mismatch(
        self,
    ) -> None:
        snapshot = self.publish("b" * 32)
        baseline = self.bound_manifest(snapshot)
        mismatches: list[tuple[str, tuple[str, ...], object]] = [
            ("index hash", ("local_release_index", "index_sha256"), "1" * 64),
            ("AAR", ("android_aar", "aar_sha256"), "1" * 64),
            ("runtime run", ("android_device_runtime", "run_id"), "1" * 32),
            (
                "runtime proof",
                ("android_device_runtime", "proof_sha256"),
                "1" * 64,
            ),
            (
                "source commit",
                ("local_release_index", "source_commit"),
                "1" * 40,
            ),
            (
                "source digest",
                ("local_release_index", "proof_source_tree_sha256"),
                "1" * 64,
            ),
        ]
        for label, keys, replacement in mismatches:
            manifest = copy.deepcopy(baseline)
            target = manifest
            for key in keys[:-1]:
                selected = target[key]
                assert isinstance(selected, dict)
                target = selected
            target[keys[-1]] = replacement
            with self.subTest(label=label), self.assertRaises(SystemExit):
                self.verify_bound(
                    manifest,
                    snapshot.file.path,
                    snapshot.file.sha256,
                )

        with self.assertRaisesRegex(SystemExit, "hash differs"):
            self.verify_bound(
                copy.deepcopy(baseline),
                snapshot.file.path,
                "1" * 64,
            )

    def test_rehashed_inner_receipt_tampering_still_fails_bound_verification(
        self,
    ) -> None:
        snapshot = self.publish("c" * 32)
        manifest = self.bound_manifest(snapshot)
        tampered = copy.deepcopy(snapshot.value)
        tampered["consumer_modes"] = {"dynamic": "pass", "static": "skipped"}
        tampered_sha256 = self.write_receipt(snapshot.file.path, tampered)
        with self.assertRaisesRegex(SystemExit, "mode results differ"):
            self.verify_bound(manifest, snapshot.file.path, tampered_sha256)

    def test_shell_entrypoint_selects_explicit_run_command(self) -> None:
        shell = pathlib.Path(__file__).with_name(
            "local-release-consumer-smoke.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("artifact/release_consumer_smoke.py run", shell)


if __name__ == "__main__":
    unittest.main()
