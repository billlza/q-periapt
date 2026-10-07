#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SCRIPT_ROOT = Path(__file__).resolve().parent


def load_script(module_name: str, filename: str):
    spec = importlib.util.spec_from_file_location(module_name, SCRIPT_ROOT / filename)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load test subject: {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verify_vendor = load_script("qperiapt_verify_vendor", "verify-vendor.py")
update_vendor = load_script("qperiapt_update_vendor", "update-vendor.py")


class FakeResponse:
    def __init__(self, data: bytes, content_length: str | None = None) -> None:
        self.status = 200
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = content_length
        self._data = data
        self._offset = 0
        self.read_calls = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        return False

    def read(self, size: int = -1) -> bytes:
        self.read_calls += 1
        if size < 0:
            size = len(self._data) - self._offset
        end = min(self._offset + size, len(self._data))
        chunk = self._data[self._offset : end]
        self._offset = end
        return chunk


class VerifyVendorTests(unittest.TestCase):
    def test_vendor_root_symlink_is_rejected_before_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir()
            vendor_link = root / "mlkem-native"
            vendor_link.symlink_to(target, target_is_directory=True)
            with mock.patch.object(verify_vendor, "VENDOR_ROOT", vendor_link):
                with self.assertRaisesRegex(SystemExit, "vendor root must not be a symlink"):
                    verify_vendor.main()


class UpdateVendorDownloadTests(unittest.TestCase):
    def read_remote(self, response: FakeResponse) -> bytes:
        with mock.patch.object(
            update_vendor.urllib.request, "urlopen", return_value=response
        ):
            return update_vendor.read_archive(None)

    def test_declared_download_over_limit_is_rejected_without_reading(self) -> None:
        response = FakeResponse(b"", content_length="5")
        with mock.patch.object(update_vendor, "MAX_ARCHIVE_BYTES", 4):
            with self.assertRaisesRegex(SystemExit, "Content-Length 5 exceeds"):
                self.read_remote(response)
        self.assertEqual(response.read_calls, 0)

    def test_actual_download_over_limit_is_rejected_without_content_length(self) -> None:
        response = FakeResponse(b"12345")
        with (
            mock.patch.object(update_vendor, "MAX_ARCHIVE_BYTES", 4),
            mock.patch.object(update_vendor, "DOWNLOAD_CHUNK_BYTES", 3),
        ):
            with self.assertRaisesRegex(SystemExit, "archive download exceeds"):
                self.read_remote(response)

    def test_content_length_mismatch_is_rejected(self) -> None:
        response = FakeResponse(b"123", content_length="4")
        with self.assertRaisesRegex(SystemExit, "differs from Content-Length"):
            self.read_remote(response)

    def test_download_with_matching_length_is_returned(self) -> None:
        response = FakeResponse(b"1234", content_length="4")
        self.assertEqual(self.read_remote(response), b"1234")

    def test_local_archive_over_limit_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "source.tar.gz"
            archive.write_bytes(b"12345")
            with mock.patch.object(update_vendor, "MAX_ARCHIVE_BYTES", 4):
                with self.assertRaisesRegex(SystemExit, "local archive size 5 exceeds"):
                    update_vendor.read_archive(archive)


if __name__ == "__main__":
    unittest.main()
