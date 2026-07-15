from __future__ import annotations

import pathlib
import tempfile
import unittest

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
