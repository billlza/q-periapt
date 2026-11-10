"""Reject wrong scanned filesystems and untrusted tools before component reads."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import android_system_image_runtime as image


def listing(kind, metadata, entries):
    # 7-Zip's offset warning footer has three newlines after the final entry.
    return ("7-Zip fixture\n\n--\nType = " + kind + "\n" + metadata
            + "\n----------\n" + "\n\n".join(entries) + "\n\n\nWarnings: 2\n").encode()


class AndroidSystemImageRuntimeTests(unittest.TestCase):
    def inputs(self):
        return (
            listing("GPT", "Physical Size = 8388608\n", [
                "Path = 1.super.img\nOffset = 2097152\nSize = 5242880"]),
            listing("LP", "Offset = 2097152\nPhysical Size = 5242880\nComment = \n{\nGroups:\n}\n", [
                "Path = system.img\nOffset = 1048576\nSize = 2097152\nMethod = RAW\nBlocks = 1"]),
            listing("Ext", "Offset = 3145728\nPhysical Size = 1048576\n", [
                f"Path = {path}\nFolder = -\nSize = 4096\nMode = -rwxr-xr-x\nLinks = 1\nSymbolic Link = "
                for path in image.COMPONENTS]),
        )

    def test_nested_offsets_select_the_actual_system_filesystem(self):
        result = image.verify_layout(*self.inputs(), 8388608)
        self.assertEqual(result["filesystem"]["Offset"], "3145728")
        self.assertEqual({x["Path"] for x in result["files"]}, set(image.COMPONENTS))

    def test_wrong_container_extent_or_scanned_filesystem_is_rejected(self):
        for index, old, new in (
            (0, b"Physical Size = 8388608", b"Physical Size = 8388609"),
            (0, b"Size = 5242880", b"Size = 8388608"),
            (0, b"1.super.img", b"1.other.img"),
            (1, b"Offset = 2097152", b"Offset = 2097153"),
            (1, b"Blocks = 1", b"Blocks = 2"),
            (1, b"Method = RAW", b"Method = ZERO"),
            (1, b"Size = 2097152", b"Size = 5242880"),
            (2, b"Offset = 3145728", b"Offset = 3145729"),
            (2, b"Physical Size = 1048576", b"Physical Size = 3145728"),
        ):
            with self.subTest(index=index, old=old, new=new):
                values = list(self.inputs())
                values[index] = values[index].replace(old, new)
                with self.assertRaises(ValueError):
                    image.verify_layout(*values, 8388608)

    def test_links_duplicate_paths_and_oversized_components_are_rejected(self):
        for old, new in (
            (b"Folder = -", b"Folder = +"),
            (b"Mode = -rwx", b"Mode = lrwx"),
            (b"Links = 1", b"Links = 2"),
            (b"Symbolic Link = ", b"Symbolic Link = ../../elsewhere"),
            (b"Size = 4096", b"Size = 4194305"),
            (b"Size = 4096", b"Size = 0"),
            (b"system/build.prop", b"system/bin/lmkd"),
            (b"system/build.prop", b"product/build.prop"),
        ):
            with self.subTest(old=old, new=new):
                gpt, lp, ext = self.inputs()
                with self.assertRaises(ValueError):
                    image.verify_layout(gpt, lp, ext.replace(old, new), 8388608)

    def test_ambiguous_or_truncated_listing_is_rejected(self):
        gpt, lp, ext = self.inputs()
        for data in (ext[:100], ext.replace(b"Type = Ext", b"Type = Ext\nType = Ext"),
                     ext.replace(b"Size = 4096", b"Size = 4096\nSize = 4096"),
                     ext + b"\nUnexpected status\n"):
            with self.subTest(data=data):
                with self.assertRaises(ValueError): image.verify_layout(gpt, lp, data, 8388608)

    def test_avd_must_select_exact_sdk_package_without_overrides(self):
        sdk = Path("/sdk")
        relative = "system-images/android-35/google_apis_ps16k/x86_64/"
        for prefix in ("", "/sdk/"):
            raw = f"image.sysdir.1={prefix}{relative}\nabi.type=x86_64\n".encode()
            self.assertEqual(image.verify_avd(raw, sdk, "x86_64")["abi.type"], "x86_64")
            for suffix in (b"kernel.path=/other\n", b"image.sysdir.2=/other\n",
                           b"disk.systemPartition.path=/other\n", b"abi.type=x86_64\n"):
                with self.assertRaises(ValueError): image.verify_avd(raw + suffix, sdk, "x86_64")
            with self.assertRaises(ValueError): image.verify_avd(raw, sdk, "arm64-v8a")

    def test_wrong_tool_is_not_executed_and_failure_is_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            installed = root / "system-images/android-35/google_apis_ps16k/x86_64"
            installed.mkdir(parents=True)
            for name in ("system.img", "kernel-ranchu", "ramdisk.img"):
                (installed / name).write_bytes(b"fixture input")
            (installed / "source.properties").write_bytes(
                b"AndroidVersion.ApiLevel=35\nSystemImage.Abi=x86_64\nSystemImage.TagId=google_apis,page_size_16kb\n")
            tool = root / "untrusted-tool"
            tool.write_bytes(b"must not execute")
            with mock.patch.object(image, "capture_output") as execute:
                with self.assertRaisesRegex(ValueError, "executable digest differs"):
                    image.inspect(root, "x86_64", tool, root / "output")
                execute.assert_not_called()
            result = json.loads((root / "output/REPORT.json").read_bytes())
            self.assertFalse(result["completed"])
            self.assertEqual(result["commands"], [])
            self.assertIn("executable digest differs", result["failure"]["message"])

    def test_completed_native_failure_retains_both_streams_and_cannot_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            installed = root / "system-images/android-35/google_apis_ps16k/x86_64"
            installed.mkdir(parents=True)
            for name in ("system.img", "kernel-ranchu", "ramdisk.img"):
                (installed / name).write_bytes(b"fixture input")
            (installed / "source.properties").write_bytes(
                b"AndroidVersion.ApiLevel=35\nSystemImage.Abi=x86_64\nSystemImage.TagId=google_apis,page_size_16kb\n")
            tool = root / "native-fixture"
            tool.write_bytes(b"#!/bin/sh\nprintf 'partial listing\\n'\nprintf 'native error\\n' >&2\nexit 7\n")
            license_file = root / "License.txt"
            license_file.write_bytes(b"fixture license")
            with mock.patch.object(image, "TOOL_HASHES", {hashlib.sha256(tool.read_bytes()).hexdigest()}), \
                 mock.patch.object(image, "LICENSE_HASH", hashlib.sha256(license_file.read_bytes()).hexdigest()):
                with self.assertRaisesRegex(ValueError, "image tool failed: gpt.txt"):
                    image.inspect(root, "x86_64", tool, root / "output")
            self.assertEqual((root / "output/gpt.txt").read_bytes(), b"partial listing\n")
            self.assertEqual((root / "output/gpt.txt.stderr").read_bytes(), b"native error\n")
            result = json.loads((root / "output/REPORT.json").read_bytes())
            self.assertFalse(result["completed"])
            self.assertEqual(len(result["commands"]), 1)
            self.assertEqual(result["commands"][0]["returncode"], 7)
            self.assertFalse((root / "output/lmkd.elf").exists())


if __name__ == "__main__":
    unittest.main()
