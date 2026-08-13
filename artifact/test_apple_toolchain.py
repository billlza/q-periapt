from __future__ import annotations

import copy
import os
import pathlib
import plistlib
import stat
import tempfile
import unittest
from unittest import mock

import apple_toolchain
from bounded_process import BoundedResult


CDHASH = "8" * 64


class AppleToolchainFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name).resolve()
        self.applications = self.root / "Applications"
        self.app = self.applications / "Xcode-27.0.app"
        self.developer_dir = self.app / "Contents" / "Developer"
        self._create_toolchain()

        platform_patch = mock.patch.object(apple_toolchain.sys, "platform", "darwin")
        applications_patch = mock.patch.object(
            apple_toolchain, "APPLICATIONS_ROOT", self.applications
        )
        uid_patch = mock.patch.object(
            apple_toolchain, "REQUIRED_ROOT_UID", os.geteuid()
        )
        platform_patch.start()
        applications_patch.start()
        uid_patch.start()
        self.addCleanup(platform_patch.stop)
        self.addCleanup(applications_patch.stop)
        self.addCleanup(uid_patch.stop)

    def _create_toolchain(self) -> None:
        for relative in apple_toolchain.ARTIFACT_PATHS.values():
            (self.app / pathlib.Path(*relative.parts)).parent.mkdir(
                parents=True, exist_ok=True
            )
        info = {
            "CFBundleIdentifier": apple_toolchain.EXPECTED_BUNDLE_IDENTIFIER,
            "CFBundleShortVersionString": "27.0",
            "CFBundleVersion": "25183.64.12",
            "DTXcode": "2700",
            # Apple may ship a DT build one revision behind the product build.
            "DTXcodeBuild": "27A5228g",
        }
        version = {
            "CFBundleShortVersionString": "27.0",
            "CFBundleVersion": "25183.64.12",
            "ProductBuildVersion": "27A5228h",
        }
        payloads = {
            "code_resources": b"sealed resources\n",
            "info_plist": plistlib.dumps(info),
            "version_plist": plistlib.dumps(version),
            "xcode_executable": b"Mach-O Xcode fixture\n",
            "xcodebuild": b"Mach-O xcodebuild fixture\n",
            "swift_frontend": b"Mach-O swift frontend fixture\n",
            "iphoneos_sdk_settings": plistlib.dumps({"Version": "27.0"}),
        }
        for name, relative in apple_toolchain.ARTIFACT_PATHS.items():
            (self.app / pathlib.Path(*relative.parts)).write_bytes(payloads[name])
        for directory in (
            self.app,
            self.app / "Contents",
            self.developer_dir,
        ):
            directory.chmod(0o755)

    def _codesign_display(self) -> str:
        return "\n".join(
            (
                f"Executable={self.app}/Contents/MacOS/Xcode",
                "Identifier=com.apple.dt.Xcode",
                "Hash type=sha256 size=32",
                f"CandidateCDHashFull sha256={CDHASH}",
                "Authority=Software Signing",
                "Authority=Apple Code Signing Certification Authority",
                "Authority=Apple Root CA",
                "TeamIdentifier=59GAB85EFG",
                "",
            )
        )

    def _command_result(self, argv: list[str], **_: object) -> str:
        if argv[:2] == ["/usr/bin/codesign", "--verify"]:
            return ""
        if argv[:2] == ["/usr/bin/codesign", "--display"]:
            return self._codesign_display()
        if argv[0] == "/usr/sbin/spctl":
            return f"{self.app}: accepted\nsource=Apple System\n"
        if argv == ["/usr/bin/xcodebuild", "-version"]:
            return "Xcode 27.0\nBuild version 27A5228h\n"
        if argv == ["/usr/bin/xcrun", "swift", "--version"]:
            return (
                "swift-driver version: 1.168.5 Apple Swift version 6.4 "
                "(swiftlang-6.4.0.27.1 clang-2100.3.27.1)\n"
                "Target: arm64-apple-macosx27.0.0\n"
            )
        raise AssertionError(f"unexpected command: {argv}")

    def capture(self) -> dict[str, object]:
        with mock.patch.object(
            apple_toolchain, "_run_command", side_effect=self._command_result
        ):
            return apple_toolchain.capture_receipt(self.developer_dir)


class AppleToolchainReceiptTests(AppleToolchainFixture):
    def test_capture_and_verify_exact_schema(self) -> None:
        receipt = self.capture()
        self.assertEqual(receipt["schema_version"], 1)
        self.assertEqual(receipt["kind"], "qperiapt.apple_toolchain_receipt")
        self.assertEqual(receipt["trust_boundary"], apple_toolchain.TRUST_BOUNDARY)
        self.assertEqual(set(receipt["artifacts"]), set(apple_toolchain.ARTIFACT_PATHS))
        self.assertIn("Apple Swift version 6.4", receipt["swift_version"])
        with mock.patch.object(
            apple_toolchain, "_run_command", side_effect=self._command_result
        ):
            self.assertEqual(
                apple_toolchain.verify_receipt(self.developer_dir, receipt), receipt
            )

    def test_receipt_schema_rejects_missing_and_extra_fields(self) -> None:
        receipt = self.capture()
        for mutation in (
            lambda value: value.pop("kind"),
            lambda value: value.__setitem__("unexpected", True),
            lambda value: value.__setitem__("schema_version", 2),
        ):
            changed = copy.deepcopy(receipt)
            mutation(changed)
            with self.assertRaises(apple_toolchain.AppleToolchainError):
                apple_toolchain.verify_receipt(self.developer_dir, changed)

    def test_codesign_parser_rejects_identity_chain_and_cdhash_drift(self) -> None:
        valid = self._codesign_display()
        replacements = (
            ("Identifier=com.apple.dt.Xcode", "Identifier=invalid"),
            ("TeamIdentifier=59GAB85EFG", "TeamIdentifier=INVALID"),
            ("Authority=Apple Root CA", "Authority=Unexpected Root"),
            (f"CandidateCDHashFull sha256={CDHASH}", "CandidateCDHashFull sha256=abc"),
        )
        for old, new in replacements:
            with self.subTest(new=new), self.assertRaises(
                apple_toolchain.AppleToolchainError
            ):
                apple_toolchain.parse_codesign_display(
                    valid.replace(old, new), self.app
                )

    def test_layout_rejects_outside_applications_and_symlink(self) -> None:
        outside = self.root / "Outside" / "Xcode.app" / "Contents" / "Developer"
        outside.mkdir(parents=True)
        with self.assertRaises(apple_toolchain.AppleToolchainError):
            apple_toolchain._inspect_layout(outside)

        real = self.app / "Contents" / "Developer.real"
        self.developer_dir.rename(real)
        self.developer_dir.symlink_to(real, target_is_directory=True)
        with self.assertRaises(apple_toolchain.AppleToolchainError):
            apple_toolchain._inspect_layout(self.developer_dir)

    def test_layout_rejects_writable_or_wrong_owner_directory(self) -> None:
        self.developer_dir.chmod(0o775)
        with self.assertRaises(apple_toolchain.AppleToolchainError):
            apple_toolchain._inspect_layout(self.developer_dir)
        self.developer_dir.chmod(0o755)
        with mock.patch.object(
            apple_toolchain, "REQUIRED_ROOT_UID", os.geteuid() + 1
        ), self.assertRaises(apple_toolchain.AppleToolchainError):
            apple_toolchain._inspect_layout(self.developer_dir)

    def test_signature_and_gatekeeper_fail_closed(self) -> None:
        def failing_signature(argv: list[str], **kwargs: object) -> str:
            if argv[:2] == ["/usr/bin/codesign", "--verify"]:
                raise apple_toolchain.AppleToolchainError("signature rejected")
            return self._command_result(argv, **kwargs)

        with mock.patch.object(
            apple_toolchain, "_run_command", side_effect=failing_signature
        ), self.assertRaisesRegex(
            apple_toolchain.AppleToolchainError, "signature rejected"
        ):
            apple_toolchain.capture_receipt(self.developer_dir)

        with self.assertRaises(apple_toolchain.AppleToolchainError):
            apple_toolchain.parse_gatekeeper_assessment(
                f"{self.app}: accepted\nsource=Developer ID\n", self.app
            )

    def test_verify_detects_artifact_hash_drift(self) -> None:
        receipt = self.capture()
        path = self.app / pathlib.Path(
            *apple_toolchain.ARTIFACT_PATHS["xcodebuild"].parts
        )
        path.write_bytes(path.read_bytes() + b"drift")
        with mock.patch.object(
            apple_toolchain, "_run_command", side_effect=self._command_result
        ), self.assertRaisesRegex(
            apple_toolchain.AppleToolchainError,
            r"receipt\.artifacts\.xcodebuild\.(sha256|size) changed",
        ):
            apple_toolchain.verify_receipt(self.developer_dir, receipt)

    def test_private_writer_is_no_replace_and_mode_0600(self) -> None:
        receipt = self.capture()
        output = self.root / "receipt.json"
        digest = apple_toolchain._write_new_private_json(output, receipt)
        original = output.read_bytes()
        self.assertEqual(len(digest), 64)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(apple_toolchain._load_private_receipt(output), receipt)
        with self.assertRaisesRegex(
            apple_toolchain.AppleToolchainError, "refusing to replace"
        ):
            apple_toolchain._write_new_private_json(output, receipt)
        self.assertEqual(output.read_bytes(), original)

    def test_private_loader_rejects_permissive_receipt(self) -> None:
        receipt = self.capture()
        output = self.root / "receipt.json"
        apple_toolchain._write_new_private_json(output, receipt)
        output.chmod(0o644)
        with self.assertRaises(apple_toolchain.AppleToolchainError):
            apple_toolchain._load_private_receipt(output)

    def test_command_boundary_is_bounded_and_minimal(self) -> None:
        with mock.patch.object(
            apple_toolchain,
            "capture_stdout",
            return_value=BoundedResult(returncode=0, stdout=b"ok"),
        ) as capture:
            output = apple_toolchain._run_command(
                ["/usr/bin/xcodebuild", "-version"],
                developer_dir=self.developer_dir,
                label="version",
                timeout_seconds=7,
                maximum_bytes=99,
            )
        self.assertEqual(output, "ok")
        self.assertEqual(
            capture.call_args.kwargs["environment"],
            {
                "PATH": apple_toolchain.COMMAND_ENVIRONMENT_PATH,
                "LC_ALL": "C",
                "LANG": "C",
                "DEVELOPER_DIR": str(self.developer_dir),
            },
        )
        self.assertEqual(capture.call_args.kwargs["timeout_seconds"], 7)
        self.assertEqual(capture.call_args.kwargs["maximum_bytes"], 99)

    def test_xcodebuild_version_must_match_version_plist(self) -> None:
        artifacts = apple_toolchain._artifact_snapshots(self.app)
        self.assertIsInstance(artifacts["info_plist"], apple_toolchain.FileSnapshot)
        self.assertIsInstance(artifacts["version_plist"], apple_toolchain.FileSnapshot)
        with self.assertRaises(apple_toolchain.AppleToolchainError):
            apple_toolchain._parse_version_metadata(
                artifacts["info_plist"],
                artifacts["version_plist"],
                "Xcode 27.0\nBuild version 27A9999z\n",
            )

        metadata = apple_toolchain._parse_version_metadata(
            artifacts["info_plist"],
            artifacts["version_plist"],
            "Xcode 27.0\nBuild version 27A5228h\n",
        )
        self.assertEqual(metadata["info_plist"]["dtxcode_build"], "27A5228g")
        self.assertEqual(metadata["build_version"], "27A5228h")

    def test_swift_version_must_be_exact_apple_two_line_output(self) -> None:
        self.assertIn(
            "Apple Swift version 6.4",
            apple_toolchain.parse_swift_version(
                "swift-driver version: 1.168.5 Apple Swift version 6.4 "
                "(swiftlang-6.4.0.27.1 clang-2100.3.27.1)\n"
                "Target: arm64-apple-macosx27.0.0\n"
            ),
        )
        with self.assertRaises(apple_toolchain.AppleToolchainError):
            apple_toolchain.parse_swift_version("Swift 6.4\n")


if __name__ == "__main__":
    unittest.main()
