from __future__ import annotations

import pathlib
import tempfile
import unittest
from unittest import mock

import release_binary_scan
from release_binary_scan import (
    ReleaseBinaryScanError,
    scan_release_file,
)


class ReleaseBinaryScanTests(unittest.TestCase):
    def test_clean_regular_file_returns_digest_bound_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "library.bin"
            path.write_bytes(b"QPERIAPT_ABI2_RELEASE_PAYLOAD")

            result = scan_release_file(path)

            self.assertEqual(result.path, path)
            self.assertEqual(result.bytes, path.stat().st_size)
            self.assertEqual(
                result.sha256,
                "3915493139ec82e20792cd8afa0e04f98d8c3fc358c98dc5db96fb21018b84cf",
            )

    def test_private_paths_are_rejected_in_every_supported_encoding(self) -> None:
        cases = {
            "utf8": "/Users/release/source".encode(),
            "utf16le": "D:\\a\\repo\\target".encode("utf-16-le"),
            "utf16be": "/home/runner/work/repo".encode("utf-16-be"),
            "windows-case-and-slashes": b"c:/users/release/source",
            "github-case-and-slashes": b"d:/A/repo/target",
            "msys-user-home": b"/c/USERS/release/source",
            "msys-github-workspace": b"/D/A/repo/target",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for label, data in cases.items():
                with self.subTest(label=label):
                    path = root / f"{label}.bin"
                    path.write_bytes(b"prefix" + data + b"suffix")
                    with self.assertRaisesRegex(
                        ReleaseBinaryScanError, "release binary contains"
                    ):
                        scan_release_file(path)

    def test_bare_windows_namespace_markers_are_not_private_paths(self) -> None:
        cases = {
            "machine-code": b"\x81\x3f\x5c\x5c\x3f\x5c\x81",
            "utf8-extended": b"prefix \\\\?\\ suffix",
            "utf8-unc": b"prefix \\\\?\\UNC suffix",
            "utf8-drive-root": b"\\\\?\\C:\\",
            "utf8-namespace-root": b"\\\\?\\GLOBALROOT\\",
            "utf16le-unc": r"\\?\UNC".encode("utf-16-le"),
            "utf16be-posix": r"//?/UNC".encode("utf-16-be"),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for label, data in cases.items():
                with self.subTest(label=label):
                    path = root / f"{label}.bin"
                    path.write_bytes(data)
                    scan_release_file(path)

    def test_dense_bare_namespace_markers_have_fixed_chunk_work(self) -> None:
        marker_count = 20_000
        marker = "\\\\?\\"
        window = release_binary_scan._WIDE_SCAN_WINDOW_CHARS
        overlap = release_binary_scan._WIDE_EXTENDED_PATH_WINDOW_CODE_UNITS
        step = window - overlap

        def windows(code_units: int) -> int:
            if code_units <= 0:
                return 0
            return 1 + max(0, (code_units - window + step - 1) // step)

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            raw_path = root / "dense-raw.bin"
            raw_path.write_bytes(marker.encode() * marker_count)
            original_pattern = release_binary_scan._WINDOWS_EXTENDED_BYTE_PATTERN
            with mock.patch.object(
                release_binary_scan,
                "_WINDOWS_EXTENDED_BYTE_PATTERN",
                wraps=original_pattern,
            ) as pattern:
                scan_release_file(raw_path)
            self.assertEqual(pattern.search.call_count, 1)

            for encoding in ("utf-16-le", "utf-16-be"):
                for alignment in (0, 1):
                    with self.subTest(encoding=encoding, alignment=alignment):
                        data = b"X" * alignment + (
                            marker * marker_count
                        ).encode(encoding)
                        path = root / f"dense-{encoding}-{alignment}.bin"
                        path.write_bytes(data)
                        maximum_calls = 2 * sum(
                            windows((len(data) - alignment_view) // 2)
                            for alignment_view in (0, 1)
                        )
                        with mock.patch.object(
                            release_binary_scan,
                            "_first_windows_extended_text_match",
                            wraps=(
                                release_binary_scan._first_windows_extended_text_match
                            ),
                        ) as text_match:
                            scan_release_file(path)
                        self.assertGreater(text_match.call_count, 0)
                        self.assertLessEqual(
                            text_match.call_count,
                            maximum_calls,
                        )
                        self.assertLess(
                            text_match.call_count,
                            marker_count // 100,
                        )

    def test_concrete_windows_extended_paths_are_rejected(self) -> None:
        cases = {
            "utf8-drive": b"prefix \\\\?\\C:\\private suffix",
            "utf8-drive-leading-space": rb"\\?\C:\ private",
            "utf8-posix-drive": b"prefix //?/c:/build/output suffix",
            "utf8-unc-root-with-spaces": (
                r"\\?\UNC\private host\secret share".encode()
            ),
            "utf8-quoted-unc-root": rb'"\\?\UNC\private-host\secret-share"',
            "utf8-long-unicode-unc": (
                ("\\\\?\\UNC\\" + "构" * 86 + "\\share").encode()
            ),
            "utf8-volume-namespace": (
                rb"\\?\Volume{01234567-89AB-CDEF-0123-456789ABCDEF}"
                rb"\private\file"
            ),
            "utf8-globalroot-namespace": (
                rb"\\?\GLOBALROOT\Device\HarddiskVolume1\file"
            ),
            "utf8-posix-volume-namespace": (
                rb"//?/Volume{01234567-89AB-CDEF-0123-456789ABCDEF}"
                rb"/private/file"
            ),
            "utf16le-unc-unicode": (
                r"\\?\UNC\构建机\发布".encode("utf-16-le")
            ),
            "utf16le-quoted-unc-root": (
                '"\\\\?\\UNC\\private-host\\secret-share"'.encode(
                    "utf-16-le"
                )
            ),
            "utf16be-drive-odd": (
                b"0" + r"\\?\z:/build/output".encode("utf-16-be")
            ),
            "utf16le-posix-unc-odd": (
                b"0" + r"//?/unc/构建机/发布".encode("utf-16-le")
            ),
            "utf16be-volume-odd": (
                b"0"
                + (
                    r"\\?\Volume{01234567-89AB-CDEF-0123-456789ABCDEF}"
                    r"\private\file"
                ).encode("utf-16-be")
            ),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for label, data in cases.items():
                with self.subTest(label=label):
                    path = root / f"{label}.bin"
                    path.write_bytes(data)
                    with self.assertRaisesRegex(
                        ReleaseBinaryScanError, "Windows extended"
                    ):
                        scan_release_file(path)

    def test_non_bmp_utf16_extended_unc_path_is_rejected(self) -> None:
        server = "😀" * 255
        share = "🧪" * 80
        text = "A" * 7600 + rf"\\?\UNC\{server}\{share}"
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "wide-unc-boundary.bin"
            path.write_bytes(text.encode("utf-16-le"))
            with self.assertRaisesRegex(
                ReleaseBinaryScanError, "UTF-16 Windows extended UNC path"
            ):
                scan_release_file(path)

    def test_caller_forbidden_text_and_credentials_are_rejected_without_echoing_secret(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            caller_path = root / "caller.bin"
            caller_path.write_bytes(b"prefix/private/build/root/suffix")
            with self.assertRaisesRegex(
                ReleaseBinaryScanError, "caller-forbidden text 0"
            ):
                scan_release_file(caller_path, forbidden_text=["/private/build/root"])

            secret_path = root / "secret.bin"
            secret = b"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
            secret_path.write_bytes(b"prefix" + secret + b"suffix")
            with self.assertRaises(ReleaseBinaryScanError) as captured:
                scan_release_file(secret_path)
            self.assertIn("GitHub token", str(captured.exception))
            self.assertNotIn(secret.decode(), str(captured.exception))

    def test_credentials_are_rejected_in_both_utf16_encodings_and_alignments(self) -> None:
        cases = {
            "utf16le-even": (
                b"prefix",
                "secret_token=correct-horse-battery-staple".encode("utf-16-le"),
                "UTF-16 named token",
            ),
            "utf16le-odd": (
                b"prefix0",
                "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345".encode("utf-16-le"),
                "UTF-16 GitHub token",
            ),
            "utf16be-even": (
                b"prefix",
                "password=correct-horse-battery-staple".encode("utf-16-be"),
                "UTF-16 named password",
            ),
            "utf16be-odd": (
                b"prefix0",
                "-----BEGIN PRIVATE KEY-----".encode("utf-16-be"),
                "UTF-16 private key marker",
            ),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            for label, (prefix, secret, expected_message) in cases.items():
                with self.subTest(label=label):
                    path = root / f"{label}.bin"
                    path.write_bytes(prefix + secret + b"suffix")
                    with self.assertRaises(ReleaseBinaryScanError) as captured:
                        scan_release_file(path)
                    self.assertIn(expected_message, str(captured.exception))
                    self.assertNotIn(
                        secret.decode(
                            "utf-16-le" if "utf16le" in label else "utf-16-be"
                        ),
                        str(captured.exception),
                    )

    def test_dense_utf16_sensitive_runs_retain_only_the_earliest_match(self) -> None:
        run_count = 50_000

        class TrackedLabel:
            live = 0
            peak = 0

            def __init__(self) -> None:
                type(self).live += 1
                type(self).peak = max(type(self).peak, type(self).live)

            def __del__(self) -> None:
                type(self).live -= 1

            def __str__(self) -> str:
                return "tracked sensitive run"

        data = b"A\x00\xff\xff" * run_count
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "dense-wide-runs.bin"
            path.write_bytes(data)

            def match_every_run(_projected: bytes):
                return TrackedLabel(), 0

            with (
                mock.patch.object(
                    release_binary_scan,
                    "_first_prefiltered_sensitive_match",
                    side_effect=match_every_run,
                ) as matcher,
                self.assertRaisesRegex(
                    ReleaseBinaryScanError,
                    "tracked sensitive run",
                ),
            ):
                scan_release_file(path)

        self.assertGreaterEqual(matcher.call_count, run_count)
        self.assertLessEqual(TrackedLabel.peak, 4)
        self.assertEqual(TrackedLabel.live, 0)

    def test_utf16_credential_crossing_scan_window_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "wide-boundary.bin"
            text = "A" * 8180 + "bearer ABCDEFGHIJKLMNOP"
            path.write_bytes(text.encode("utf-16-le"))

            with self.assertRaisesRegex(
                ReleaseBinaryScanError, "UTF-16 bearer credential"
            ):
                scan_release_file(path)

    def test_symlinks_and_oversized_files_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            target = root / "target.bin"
            target.write_bytes(b"clean")
            link = root / "link.bin"
            link.symlink_to(target)
            with self.assertRaises(ReleaseBinaryScanError):
                scan_release_file(link)
            with self.assertRaises(ReleaseBinaryScanError):
                scan_release_file(target, maximum=4)

    def test_invalid_caller_forbidden_text_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "library.bin"
            path.write_bytes(b"clean")
            for value in ("", "bad\x00value"):
                with self.subTest(value=value), self.assertRaises(
                    ReleaseBinaryScanError
                ):
                    scan_release_file(path, forbidden_text=[value])


if __name__ == "__main__":
    unittest.main()
