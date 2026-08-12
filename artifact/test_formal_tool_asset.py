from __future__ import annotations

import contextlib
import hashlib
import io
import operator
import os
import pathlib
import stat
import tempfile
import unittest
from types import MappingProxyType
from unittest import mock

import formal_tool_asset as assets
from bounded_process import BoundedProcessError, BoundedResult, ErrorKind
from evidence_io import EvidenceIOError


class FormalToolAssetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name).resolve(strict=True)
        self.root.chmod(0o700)
        self.fixed_parent = mock.patch.object(
            assets, "_FIXED_TEMPORARY_PARENT", self.root
        )
        self.fixed_parent.start()
        self.addCleanup(self.fixed_parent.stop)
        self.payload = b"fixed formal tool asset\n"
        self.asset = assets.FormalToolAsset(
            url="https://github.com/example/tool/releases/download/v1/tool.bin",
            sha256=hashlib.sha256(self.payload).hexdigest(),
            size=len(self.payload),
            leaf="tool.bin",
        )
        self.mapping = mock.patch.object(
            assets,
            "ASSETS",
            MappingProxyType({"test-asset": self.asset}),
        )
        self.mapping.start()
        self.addCleanup(self.mapping.stop)

    @staticmethod
    def _write_all(descriptor: int, payload: bytes) -> None:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise AssertionError("test fixture encountered a short write")
            view = view[written:]

    def write_result(
        self,
        arguments: dict[str, object],
        payload: bytes,
        *,
        returncode: int = 0,
        mode: int = 0o600,
    ) -> BoundedResult:
        if returncode == 0:
            descriptor = os.open(
                str(arguments["output_name"]),
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                mode,
                dir_fd=int(arguments["output_directory_fd"]),
            )
            try:
                os.fchmod(descriptor, mode)
                self._write_all(descriptor, payload)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        return BoundedResult(returncode)

    @staticmethod
    def cleanup_success(path: pathlib.Path) -> None:
        path.unlink(missing_ok=True)
        path.parent.rmdir()

    def assert_root_empty(self) -> None:
        self.assertEqual(list(self.root.iterdir()), [])

    def test_production_asset_table_is_exact_and_immutable(self) -> None:
        self.mapping.stop()
        expected = {
            "maude-3.5.1": assets.FormalToolAsset(
                "https://github.com/maude-lang/Maude/releases/download/"
                "Maude3.5.1/Maude-3.5.1-linux-x86_64.zip",
                "72ed1ca87e3b3d0dfc6ee1436baf154b"
                "f04c45ff97d521bec040c5e8dfc8f92c",
                2_893_486,
                "Maude-3.5.1-linux-x86_64.zip",
            ),
            "tamarin-1.12.0": assets.FormalToolAsset(
                "https://github.com/tamarin-prover/tamarin-prover/releases/"
                "download/1.12.0/tamarin-prover-1.12.0-linux64-ubuntu.tar.gz",
                "201be06f469e47cff554df6ca93db8366"
                "fc2c69d70c61fcbd1370a1074b469c6",
                13_048_539,
                "tamarin-prover-1.12.0-linux64-ubuntu.tar.gz",
            ),
            "opam-2.5.2": assets.FormalToolAsset(
                "https://github.com/ocaml/opam/releases/download/"
                "2.5.2/opam-2.5.2-x86_64-linux",
                "edfca2630c373b44b7ee1c2f81cd8dcf"
                "67468d0db57d6c02158de553ac63dbd4",
                8_945_008,
                "opam-2.5.2-x86_64-linux",
            ),
        }
        self.assertIsInstance(assets.ASSETS, MappingProxyType)
        self.assertEqual(assets.ASSETS, expected)
        with self.assertRaises(TypeError):
            operator.setitem(
                assets.ASSETS,
                "replacement",
                expected["maude-3.5.1"],
            )

    def test_success_uses_one_fixed_curl_command_and_private_output(self) -> None:
        calls: list[tuple[tuple[str, ...], dict[str, object]]] = []

        def runner(argv: tuple[str, ...], **arguments: object) -> BoundedResult:
            calls.append((argv, arguments))
            return self.write_result(arguments, self.payload)

        with mock.patch.object(
            assets.os,
            "chmod",
            side_effect=AssertionError("path chmod must not be used"),
        ):
            path = assets.download("test-asset", runner=runner)
        self.addCleanup(self.cleanup_success, path)
        self.assertTrue(path.is_absolute())
        self.assertEqual(path.parent.parent, self.root)
        self.assertEqual(path.read_bytes(), self.payload)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertEqual(len(calls), 1)
        argv, arguments = calls[0]
        self.assertEqual(
            argv,
            (
                "/usr/bin/curl",
                "-q",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--tlsv1.2",
                "--fail",
                "--location",
                "--silent",
                "--show-error",
                "--connect-timeout",
                "30",
                "--max-time",
                "270",
                "--max-filesize",
                str(len(self.payload)),
                self.asset.url,
            ),
        )
        for forbidden in (
            "--output",
            "--continue-at",
            "--retry",
            "--retry-all-errors",
            "--retry-max-time",
            "--insecure",
        ):
            self.assertNotIn(forbidden, argv)
        self.assertEqual(arguments["output_name"], self.asset.leaf)
        self.assertEqual(arguments["timeout_seconds"], 300)
        self.assertEqual(arguments["maximum_bytes"], len(self.payload))
        self.assertIsNone(arguments["stderr"])
        self.assertEqual(
            arguments["environment"],
            {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )

    def test_hostile_runner_temp_is_ignored(self) -> None:
        def runner(_argv: tuple[str, ...], **arguments: object) -> BoundedResult:
            return self.write_result(arguments, self.payload)

        hostile = self.root.parent / "hostile-runner-temp"
        with mock.patch.dict(
            os.environ,
            {"RUNNER_TEMP": str(hostile)},
            clear=True,
        ):
            path = assets.download("test-asset", runner=runner)
        self.addCleanup(self.cleanup_success, path)
        self.assertEqual(path.parent.parent, self.root)
        self.assertFalse(hostile.exists())

    def test_removed_temporary_parent_api_is_rejected(self) -> None:
        with self.assertRaisesRegex(TypeError, "temporary_parent"):
            assets.download("test-asset", temporary_parent=self.root)
        self.assert_root_empty()

    def test_private_fixed_parent_rejects_relative_symlink_and_wrong_mode(self) -> None:
        with (
            mock.patch.object(
                assets, "_FIXED_TEMPORARY_PARENT", pathlib.Path("relative")
            ),
            self.assertRaisesRegex(assets.FormalToolAssetError, "must be one absolute"),
        ):
            assets.download("test-asset")

        symlink = self.root.parent / f"{self.root.name}-link"
        symlink.symlink_to(self.root, target_is_directory=True)
        self.addCleanup(symlink.unlink)
        with (
            mock.patch.object(assets, "_FIXED_TEMPORARY_PARENT", symlink),
            self.assertRaisesRegex(
                assets.FormalToolAssetError, "canonical.*symlink"
            ),
        ):
            assets.download("test-asset")

        self.root.chmod(0o770)
        try:
            with self.assertRaisesRegex(
                assets.FormalToolAssetError, "mode-0700"
            ):
                assets.download("test-asset")
        finally:
            self.root.chmod(0o700)
        self.assert_root_empty()

    def test_production_fixed_parent_requires_linux_root_owned_exact_01777(
        self,
    ) -> None:
        valid = os.stat_result(
            (stat.S_IFDIR | 0o1777, 0, 0, 1, 0, 0, 0, 0, 0, 0)
        )
        self.assertEqual(assets._LINUX_TEMPORARY_PARENT, pathlib.Path("/tmp"))
        with (
            mock.patch.object(
                assets, "_FIXED_TEMPORARY_PARENT", assets._LINUX_TEMPORARY_PARENT
            ),
            mock.patch.object(assets.sys, "platform", "darwin"),
            self.assertRaisesRegex(assets.FormalToolAssetError, "require Linux"),
        ):
            assets._fixed_temporary_parent()

        with (
            mock.patch.object(
                assets, "_FIXED_TEMPORARY_PARENT", assets._LINUX_TEMPORARY_PARENT
            ),
            mock.patch.object(assets.sys, "platform", "linux"),
            mock.patch.object(
                assets.pathlib.Path,
                "resolve",
                return_value=assets._LINUX_TEMPORARY_PARENT,
            ),
            mock.patch.object(assets.os, "lstat", return_value=valid),
        ):
            self.assertEqual(
                assets._fixed_temporary_parent(),
                assets._LINUX_TEMPORARY_PARENT,
            )

        invalid = (
            os.stat_result((stat.S_IFLNK | 0o777, 0, 0, 1, 0, 0, 0, 0, 0, 0)),
            os.stat_result((stat.S_IFDIR | 0o1777, 0, 0, 1, 501, 0, 0, 0, 0, 0)),
            os.stat_result((stat.S_IFDIR | 0o0777, 0, 0, 1, 0, 0, 0, 0, 0, 0)),
        )
        for metadata in invalid:
            with (
                self.subTest(mode=metadata.st_mode, uid=metadata.st_uid),
                self.assertRaisesRegex(
                    assets.FormalToolAssetError, "root-owned.*01777"
                ),
            ):
                assets._linux_temporary_parent_metadata(metadata)
        assets._linux_temporary_parent_metadata(valid)

    def test_two_curl_failures_retry_from_absent_target_then_succeed(self) -> None:
        attempts = 0
        sleeps: list[float] = []

        def runner(_argv: tuple[str, ...], **arguments: object) -> BoundedResult:
            nonlocal attempts
            attempts += 1
            with self.assertRaises(FileNotFoundError):
                os.stat(
                    str(arguments["output_name"]),
                    dir_fd=int(arguments["output_directory_fd"]),
                    follow_symlinks=False,
                )
            if attempts < 3:
                return BoundedResult(56)
            return self.write_result(arguments, self.payload)

        path = assets.download(
            "test-asset",
            runner=runner,
            sleeper=sleeps.append,
        )
        self.addCleanup(self.cleanup_success, path)
        self.assertEqual(attempts, 3)
        self.assertEqual(sleeps, [15, 30])

    def test_two_timeouts_retry_then_succeed_and_preserve_from_zero(self) -> None:
        attempts = 0
        sleeps: list[float] = []

        def runner(_argv: tuple[str, ...], **arguments: object) -> BoundedResult:
            nonlocal attempts
            attempts += 1
            with self.assertRaises(FileNotFoundError):
                os.stat(
                    str(arguments["output_name"]),
                    dir_fd=int(arguments["output_directory_fd"]),
                    follow_symlinks=False,
                )
            if attempts < 3:
                raise BoundedProcessError("timeout", f"timeout {attempts}")
            return self.write_result(arguments, self.payload)

        path = assets.download(
            "test-asset",
            runner=runner,
            sleeper=sleeps.append,
        )
        self.addCleanup(self.cleanup_success, path)
        self.assertEqual(attempts, 3)
        self.assertEqual(sleeps, [15, 30])

    def test_persistent_curl_failure_is_bounded_and_cleans(self) -> None:
        attempts = 0

        def runner(_argv: tuple[str, ...], **_arguments: object) -> BoundedResult:
            nonlocal attempts
            attempts += 1
            return BoundedResult(22)

        with self.assertRaisesRegex(
            assets.FormalToolAssetError,
            "failed after 3 attempts with curl status 22",
        ):
            assets.download(
                "test-asset",
                runner=runner,
                sleeper=lambda _delay: None,
            )
        self.assertEqual(attempts, 3)
        self.assert_root_empty()

    def test_persistent_timeout_is_bounded_chained_and_cleans(self) -> None:
        attempts = 0

        def runner(_argv: tuple[str, ...], **_arguments: object) -> BoundedResult:
            nonlocal attempts
            attempts += 1
            raise BoundedProcessError("timeout", f"timeout {attempts}")

        with self.assertRaisesRegex(
            assets.FormalToolAssetError, "timed out on all 3 attempts"
        ) as raised:
            assets.download(
                "test-asset",
                runner=runner,
                sleeper=lambda _delay: None,
            )
        self.assertEqual(attempts, 3)
        self.assertIsInstance(raised.exception.__cause__, BoundedProcessError)
        self.assertEqual(str(raised.exception.__cause__), "timeout 3")
        self.assert_root_empty()

    def test_structural_process_errors_fail_immediately_and_clean(self) -> None:
        kinds: tuple[ErrorKind, ...] = (
            "arguments",
            "start",
            "output_limit",
            "io",
            "reap",
            "output_path",
        )
        for kind in kinds:
            calls = 0

            def runner(
                _argv: tuple[str, ...], **_arguments: object
            ) -> BoundedResult:
                nonlocal calls
                calls += 1
                raise BoundedProcessError(kind, f"structural {kind}")

            with self.subTest(kind=kind), self.assertRaisesRegex(
                BoundedProcessError, f"structural {kind}"
            ):
                assets.download("test-asset", runner=runner)
            self.assertEqual(calls, 1)
            self.assert_root_empty()

    def test_integrity_and_metadata_failures_never_retry_and_clean(self) -> None:
        fixtures = (
            (self.payload[:-1], 0o600, assets.FormalToolAssetError, "size mismatch"),
            (
                b"X" * len(self.payload),
                0o600,
                assets.FormalToolAssetError,
                "SHA-256 mismatch",
            ),
            (self.payload, 0o640, EvidenceIOError, "mode 0600"),
        )
        for payload, mode, error_type, message in fixtures:
            calls = 0

            def runner(
                _argv: tuple[str, ...], **arguments: object
            ) -> BoundedResult:
                nonlocal calls
                calls += 1
                return self.write_result(arguments, payload, mode=mode)

            with self.subTest(message=message), self.assertRaisesRegex(
                error_type, message
            ):
                assets.download("test-asset", runner=runner)
            self.assertEqual(calls, 1)
            self.assert_root_empty()

    def test_oversize_and_symlink_outputs_fail_without_retry(self) -> None:
        calls = 0

        def oversized(
            _argv: tuple[str, ...], **arguments: object
        ) -> BoundedResult:
            nonlocal calls
            calls += 1
            return self.write_result(arguments, self.payload + b"extra")

        with self.assertRaisesRegex(EvidenceIOError, "exceeds"):
            assets.download("test-asset", runner=oversized)
        self.assertEqual(calls, 1)
        self.assert_root_empty()

        target = self.root / "target"
        target.write_bytes(self.payload)
        target.chmod(0o600)

        def symlink(
            _argv: tuple[str, ...], **arguments: object
        ) -> BoundedResult:
            os.symlink(
                target,
                str(arguments["output_name"]),
                dir_fd=int(arguments["output_directory_fd"]),
            )
            return BoundedResult(0)

        with self.assertRaisesRegex(EvidenceIOError, "safely open"):
            assets.download("test-asset", runner=symlink)
        self.assertEqual(target.read_bytes(), self.payload)
        target.unlink()
        self.assert_root_empty()

    def test_nonzero_runner_cannot_leave_a_retry_target(self) -> None:
        calls = 0

        def runner(_argv: tuple[str, ...], **arguments: object) -> BoundedResult:
            nonlocal calls
            calls += 1
            if calls == 1:
                self.write_result(arguments, b"partial")
                return BoundedResult(56)
            return self.write_result(arguments, self.payload)

        with self.assertRaisesRegex(
            assets.FormalToolAssetError, "retry target unexpectedly exists"
        ):
            assets.download(
                "test-asset",
                runner=runner,
                sleeper=lambda _delay: None,
            )
        self.assertEqual(calls, 1)
        self.assert_root_empty()

    def test_malformed_runner_result_fails_without_retry(self) -> None:
        for result in (object(), BoundedResult(True)):
            runner = mock.Mock(return_value=result)

            with self.subTest(result=result), self.assertRaisesRegex(
                assets.FormalToolAssetError, "malformed result"
            ):
                assets.download("test-asset", runner=runner)
            runner.assert_called_once()
            self.assert_root_empty()

    def test_interrupts_and_sleep_failure_propagate_after_cleanup(self) -> None:
        for error in (KeyboardInterrupt(), SystemExit(143)):
            def interrupted(
                _argv: tuple[str, ...], **_arguments: object
            ) -> BoundedResult:
                raise error

            with self.subTest(error=type(error).__name__), self.assertRaises(
                type(error)
            ):
                assets.download("test-asset", runner=interrupted)
            self.assert_root_empty()

        with self.assertRaisesRegex(RuntimeError, "sleep interrupted"):
            assets.download(
                "test-asset",
                runner=lambda _argv, **_arguments: BoundedResult(56),
                sleeper=lambda _delay: (_ for _ in ()).throw(
                    RuntimeError("sleep interrupted")
                ),
            )
        self.assert_root_empty()

    def test_cleanup_failure_is_a_note_and_never_replaces_primary(self) -> None:
        primary = BoundedProcessError("start", "primary start failure")
        with mock.patch.object(
            assets,
            "_cleanup_failed_download",
            return_value=["secondary cleanup failure"],
        ):
            with self.assertRaises(BoundedProcessError) as raised:
                assets.download(
                    "test-asset",
                    runner=lambda _argv, **_arguments: (_ for _ in ()).throw(
                        primary
                    ),
                )
        self.assertIs(raised.exception, primary)
        self.assertIn(
            "secondary cleanup failure",
            " ".join(getattr(raised.exception, "__notes__", ())),
        )
        for child in self.root.iterdir():
            child.rmdir()

    def test_directory_path_replacement_is_detected_without_deleting_replacement(
        self,
    ) -> None:
        moved: pathlib.Path | None = None
        replacement: pathlib.Path | None = None

        def runner(_argv: tuple[str, ...], **arguments: object) -> BoundedResult:
            nonlocal moved, replacement
            result = self.write_result(arguments, self.payload)
            descriptor_path = next(
                child
                for child in self.root.iterdir()
                if child.name.startswith("qperiapt-formal-tool-asset.")
            )
            moved = descriptor_path.with_name(descriptor_path.name + ".moved")
            descriptor_path.rename(moved)
            replacement = descriptor_path
            replacement.mkdir(mode=0o700)
            (replacement / "sentinel").write_text("do not delete", encoding="ascii")
            return result

        with self.assertRaisesRegex(
            assets.FormalToolAssetError, "directory path changed"
        ) as raised:
            assets.download("test-asset", runner=runner)
        self.assertIsNotNone(replacement)
        self.assertEqual(
            (replacement / "sentinel").read_text(encoding="ascii"),
            "do not delete",
        )
        self.assertIn(
            "retain changed asset directory path",
            " ".join(getattr(raised.exception, "__notes__", ())),
        )
        self.assertIsNotNone(moved)
        self.assertEqual(list(moved.iterdir()), [])
        (replacement / "sentinel").unlink()
        replacement.rmdir()
        moved.rmdir()
        self.assert_root_empty()

    def test_main_success_prints_only_the_path(self) -> None:
        def runner(_argv: tuple[str, ...], **arguments: object) -> BoundedResult:
            return self.write_result(arguments, self.payload)

        path = assets.download("test-asset", runner=runner)
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(assets, "download", return_value=path),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(assets.main(["--asset", "test-asset"]), 0)
        self.addCleanup(self.cleanup_success, path)
        self.assertEqual(stdout.getvalue(), f"{path}\n")
        self.assertEqual(stderr.getvalue(), "")

    def test_main_reports_explicit_download_error_to_stderr(self) -> None:
        failure = assets.FormalToolAssetError("primary")
        failure.add_note("cleanup also failed")
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(assets, "download", side_effect=failure),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(assets.main(["--asset", "test-asset"]), 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("primary", stderr.getvalue())
        self.assertIn("cleanup also failed", stderr.getvalue())

    def test_published_cleanup_refuses_a_matching_directory_outside_fixed_parent(
        self,
    ) -> None:
        outside_directory = pathlib.Path(
            tempfile.mkdtemp(
                prefix="qperiapt-formal-tool-asset.outside.",
                dir=self.root.parent,
            )
        )
        outside_directory.chmod(0o700)
        outside_path = outside_directory / self.asset.leaf
        outside_path.write_bytes(self.payload)
        outside_path.chmod(0o600)
        self.addCleanup(outside_directory.rmdir)
        self.addCleanup(outside_path.unlink, missing_ok=True)

        self.assertEqual(
            assets._cleanup_published_download(outside_path, self.asset),
            ["refusing to clean an unexpected published asset path"],
        )
        self.assertEqual(outside_path.read_bytes(), self.payload)

    def test_stdout_write_or_flush_failure_cleans_before_propagating(self) -> None:
        for operation in ("write", "flush"):
            def runner(
                _argv: tuple[str, ...], **arguments: object
            ) -> BoundedResult:
                return self.write_result(arguments, self.payload)

            path = assets.download("test-asset", runner=runner)
            stream = mock.Mock()
            if operation == "write":
                stream.write.side_effect = BrokenPipeError("stdout closed")
            else:
                stream.write.return_value = len(f"{path}\n")
                stream.flush.side_effect = BrokenPipeError("stdout closed")
            with (
                self.subTest(operation=operation),
                mock.patch.object(assets, "download", return_value=path),
                mock.patch.object(assets.sys, "stdout", stream),
                self.assertRaisesRegex(BrokenPipeError, "stdout closed"),
            ):
                assets.main(["--asset", "test-asset"])
            self.assertFalse(path.exists())
            self.assertFalse(path.parent.exists())
            self.assert_root_empty()


if __name__ == "__main__":
    unittest.main()
