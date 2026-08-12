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

        path = assets.download(
            "test-asset", runner=runner, temporary_parent=self.root
        )
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

    def test_default_parent_is_exact_absolute_runner_temp(self) -> None:
        def runner(_argv: tuple[str, ...], **arguments: object) -> BoundedResult:
            return self.write_result(arguments, self.payload)

        with mock.patch.dict(
            os.environ,
            {"RUNNER_TEMP": str(self.root)},
            clear=True,
        ):
            path = assets.download("test-asset", runner=runner)
        self.addCleanup(self.cleanup_success, path)
        self.assertEqual(path.parent.parent, self.root)

        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(assets.FormalToolAssetError, "RUNNER_TEMP"):
                assets.download("test-asset", runner=runner)
        self.assertEqual(list(self.root.iterdir()), [path.parent])

    def test_parent_rejects_relative_symlink_and_group_writable_paths(self) -> None:
        with self.assertRaisesRegex(assets.FormalToolAssetError, "must be absolute"):
            assets.download("test-asset", temporary_parent="relative")

        symlink = self.root.parent / f"{self.root.name}-link"
        symlink.symlink_to(self.root, target_is_directory=True)
        self.addCleanup(symlink.unlink)
        with self.assertRaisesRegex(
            assets.FormalToolAssetError, "canonical.*symlink"
        ):
            assets.download("test-asset", temporary_parent=symlink)

        self.root.chmod(0o770)
        try:
            with self.assertRaisesRegex(
                assets.FormalToolAssetError, "group/other write"
            ):
                assets.download("test-asset", temporary_parent=self.root)
        finally:
            self.root.chmod(0o700)
        self.assert_root_empty()

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
            temporary_parent=self.root,
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
            temporary_parent=self.root,
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
                temporary_parent=self.root,
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
                temporary_parent=self.root,
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
                assets.download(
                    "test-asset", runner=runner, temporary_parent=self.root
                )
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
                assets.download(
                    "test-asset", runner=runner, temporary_parent=self.root
                )
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
            assets.download(
                "test-asset", runner=oversized, temporary_parent=self.root
            )
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
            assets.download(
                "test-asset", runner=symlink, temporary_parent=self.root
            )
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
                temporary_parent=self.root,
            )
        self.assertEqual(calls, 1)
        self.assert_root_empty()

    def test_malformed_runner_result_fails_without_retry(self) -> None:
        for result in (object(), BoundedResult(True)):
            runner = mock.Mock(return_value=result)

            with self.subTest(result=result), self.assertRaisesRegex(
                assets.FormalToolAssetError, "malformed result"
            ):
                assets.download(
                    "test-asset", runner=runner, temporary_parent=self.root
                )
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
                assets.download(
                    "test-asset", runner=interrupted, temporary_parent=self.root
                )
            self.assert_root_empty()

        with self.assertRaisesRegex(RuntimeError, "sleep interrupted"):
            assets.download(
                "test-asset",
                runner=lambda _argv, **_arguments: BoundedResult(56),
                sleeper=lambda _delay: (_ for _ in ()).throw(
                    RuntimeError("sleep interrupted")
                ),
                temporary_parent=self.root,
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
                    temporary_parent=self.root,
                )
        self.assertIs(raised.exception, primary)
        self.assertIn(
            "secondary cleanup failure",
            " ".join(getattr(raised.exception, "__notes__", ())),
        )
        for child in self.root.iterdir():
            child.rmdir()

    def test_directory_path_replacement_is_detected_without_deleting_replacement(self) -> None:
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
            assets.download(
                "test-asset", runner=runner, temporary_parent=self.root
            )
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

        path = assets.download(
            "test-asset", runner=runner, temporary_parent=self.root
        )
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

    def test_stdout_write_or_flush_failure_cleans_before_propagating(self) -> None:
        for operation in ("write", "flush"):
            def runner(
                _argv: tuple[str, ...], **arguments: object
            ) -> BoundedResult:
                return self.write_result(arguments, self.payload)

            path = assets.download(
                "test-asset", runner=runner, temporary_parent=self.root
            )
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
