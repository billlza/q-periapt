#!/usr/bin/env python3
"""Regression tests for the fail-closed static Apple distribution contract."""

from __future__ import annotations

import hashlib
import io
import json
import os
import pathlib
import stat
import struct
import subprocess
import tempfile
import unittest
import zipfile
from unittest import mock

import apple_distribution


SOURCE_COMMIT = "ab" * 20
TEAM_ID = "YKUPL7Z869"
CDHASH = "0123456789abcdef0123456789abcdef01234567"


def codesign_display(*, team_id: str = TEAM_ID, timestamp: bool = True) -> str:
    lines = [
        "Identifier=CQPeriapt",
        "Format=bundle with generic",
        "CodeDirectory v=20500 size=492 flags=0x0(none) hashes=4+7 location=embedded",
        "Signature size=9078",
        f"Authority=Developer ID Application: Example ({TEAM_ID})",
        "Authority=Developer ID Certification Authority",
        "Authority=Apple Root CA",
    ]
    if timestamp:
        lines.append("Timestamp=Jul 14, 2026 at 10:00:00")
    lines.extend(
        [
            f"TeamIdentifier={team_id}",
            "Sealed Resources version=2 rules=13 files=10",
            "Internal requirements count=1 size=180",
            f"CDHash={CDHASH}",
        ]
    )
    return "\n".join(lines) + "\n"


def thin_archive(payload: bytes = b"object") -> bytes:
    return apple_distribution.AR_MAGIC + payload


def fat_static_archive() -> bytes:
    first = thin_archive(b"x86_64")
    second = thin_archive(b"arm64")
    header_size = 8 + 2 * 20
    first_offset = header_size
    second_offset = first_offset + len(first)
    return b"".join(
        [
            struct.pack(">II", 0xCAFEBABE, 2),
            struct.pack(">IIIII", 0x01000007, 3, first_offset, len(first), 0),
            struct.pack(">IIIII", 0x0100000C, 0, second_offset, len(second), 0),
            first,
            second,
        ]
    )


def archive_bytes(relative: str) -> bytes:
    if relative == "ios-arm64/libq_periapt_ffi_abi2.a":
        return thin_archive(b"ios-arm64")
    return fat_static_archive()


def write_zip_entry(
    archive: zipfile.ZipFile,
    name: str,
    data: bytes,
    *,
    mode: int,
) -> None:
    info = zipfile.ZipInfo(name, (2000, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.external_attr = mode << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    archive.writestr(info, data)


def signing_evidence(library_hashes: dict[str, str]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "qperiapt.apple_xcframework_signature",
        "signature": {
            "identity_class": "Developer ID Application",
            "authority": f"Developer ID Application: Example ({TEAM_ID})",
            "authority_chain": [
                f"Developer ID Application: Example ({TEAM_ID})",
                "Developer ID Certification Authority",
                "Apple Root CA",
            ],
            "team_id": TEAM_ID,
            "identifier": "CQPeriapt",
            "format": "bundle",
            "secure_timestamp": "Jul 14, 2026 at 10:00:00",
            "cdhash": CDHASH,
            "hardened_runtime": False,
            "code_directory_flags": "none",
            "strict_verification": True,
        },
        "certificate": {
            "sha1": "11" * 20,
            "sha256": "22" * 32,
            "subject": f"CN=Developer ID Application: Example ({TEAM_ID})",
            "issuer": "CN=Developer ID Certification Authority",
            "serial": "01",
            "notBefore": "Jul 1 00:00:00 2026 GMT",
            "notAfter": "Jul 1 00:00:00 2027 GMT",
        },
        "sealed_resources": {
            "code_resources_sha256": hashlib.sha256(b"sealed-resources").hexdigest(),
            "static_libraries": library_hashes,
        },
    }


class StaticArchiveTests(unittest.TestCase):
    def test_accepts_thin_and_two_slice_fat_static_archives(self) -> None:
        apple_distribution._validate_static_archive(thin_archive(), label="thin")
        apple_distribution._validate_static_archive(fat_static_archive(), label="fat")

    def test_rejects_mach_o_executable_magic(self) -> None:
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError, "not a static archive"
        ):
            apple_distribution._validate_static_archive(
                b"\xcf\xfa\xed\xfe" + b"\x00" * 64, label="executable"
            )

    def test_rejects_fat_container_with_non_archive_slice(self) -> None:
        data = bytearray(fat_static_archive())
        first_offset = struct.unpack_from(">I", data, 16)[0]
        data[first_offset : first_offset + 8] = b"NOT-ARCH"
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError, "not an ar archive"
        ):
            apple_distribution._validate_static_archive(bytes(data), label="fat")

    def test_rejects_out_of_bounds_or_overlapping_fat_slices(self) -> None:
        out_of_bounds = bytearray(fat_static_archive())
        struct.pack_into(">I", out_of_bounds, 20, len(out_of_bounds) + 1)
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError, "out of bounds"
        ):
            apple_distribution._validate_static_archive(
                bytes(out_of_bounds), label="fat"
            )
        overlap = bytearray(fat_static_archive())
        first_offset = struct.unpack_from(">I", overlap, 16)[0]
        struct.pack_into(">I", overlap, 36, first_offset)
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError, "overlap|not an ar archive"
        ):
            apple_distribution._validate_static_archive(bytes(overlap), label="fat")


class ZipFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.archive = self.root / "CQPeriapt.xcframework.zip"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_archive(
        self,
        *,
        signed: bool = True,
        extra_name: str | None = None,
        duplicate: bool = False,
        executable_name: str | None = None,
        symlink_name: str | None = None,
        library_override: tuple[str, bytes] | None = None,
    ) -> dict[str, str]:
        entries = set(
            apple_distribution.EXPECTED_XCFRAMEWORK_DIRECTORIES
            | apple_distribution.EXPECTED_XCFRAMEWORK_FILES
        )
        if signed:
            entries.update(apple_distribution.EXPECTED_SIGNATURE_DIRECTORIES)
            entries.update(apple_distribution.EXPECTED_SIGNATURE_FILES)
        if extra_name:
            entries.add(extra_name)
        library_hashes: dict[str, str] = {}
        with zipfile.ZipFile(self.archive, "w") as archive:
            for name in sorted(entries):
                if name.endswith("/"):
                    write_zip_entry(archive, name, b"", mode=stat.S_IFDIR | 0o755)
                    continue
                relative = name.removeprefix("CQPeriapt.xcframework/")
                if relative in apple_distribution.EXPECTED_XCFRAMEWORK_LIBRARIES:
                    data = archive_bytes(relative)
                    if library_override and relative == library_override[0]:
                        data = library_override[1]
                    library_hashes[relative] = hashlib.sha256(data).hexdigest()
                elif name.endswith("CodeResources"):
                    data = b"sealed-resources"
                else:
                    data = f"fixture:{name}".encode("utf-8")
                mode = stat.S_IFREG | (
                    0o755 if name == executable_name else 0o644
                )
                if name == symlink_name:
                    mode = stat.S_IFLNK | 0o777
                write_zip_entry(archive, name, data, mode=mode)
            if duplicate:
                name = "CQPeriapt.xcframework/Info.plist"
                write_zip_entry(
                    archive, name, b"duplicate", mode=stat.S_IFREG | 0o644
                )
        return library_hashes


class ExactZipLayoutTests(ZipFixture):
    def test_accepts_exact_signed_and_unsigned_static_layouts(self) -> None:
        self.write_archive(signed=True)
        apple_distribution.validate_xcframework_zip(
            self.archive, require_signature=True
        )
        self.write_archive(signed=False)
        apple_distribution.validate_xcframework_zip(
            self.archive, require_signature=False
        )

    def test_signed_mode_rejects_missing_signature(self) -> None:
        self.write_archive(signed=False)
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError, "exact static-only layout"
        ):
            apple_distribution.validate_xcframework_zip(
                self.archive, require_signature=True
            )

    def test_rejects_every_extra_executable_or_bundle_shape(self) -> None:
        for relative in (
            "CQPeriapt.xcframework/tool",
            "CQPeriapt.xcframework/libevil.dylib",
            "CQPeriapt.xcframework/Evil.framework/Evil",
            "CQPeriapt.xcframework/Evil.app/Contents/MacOS/Evil",
            "CQPeriapt.xcframework/Evil.bundle/Evil",
            "CQPeriapt.xcframework/install.sh",
        ):
            with self.subTest(relative=relative):
                self.write_archive(signed=True, extra_name=relative)
                with self.assertRaisesRegex(
                    apple_distribution.AppleDistributionError,
                    "exact static-only layout",
                ):
                    apple_distribution.validate_xcframework_zip(
                        self.archive, require_signature=True
                    )

    def test_rejects_executable_mode_on_expected_regular_file(self) -> None:
        self.write_archive(
            executable_name="CQPeriapt.xcframework/Info.plist"
        )
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError, "mode is not exactly 0644"
        ):
            apple_distribution.validate_xcframework_zip(
                self.archive, require_signature=True
            )

    def test_rejects_symlink_entry(self) -> None:
        self.write_archive(
            symlink_name="CQPeriapt.xcframework/Info.plist"
        )
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError, "unsupported.*entry type"
        ):
            apple_distribution.validate_xcframework_zip(
                self.archive, require_signature=True
            )

    def test_rejects_duplicate_entry(self) -> None:
        with mock.patch("warnings.warn"):
            self.write_archive(duplicate=True)
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError, "duplicate"
        ):
            apple_distribution.validate_xcframework_zip(
                self.archive, require_signature=True
            )

    def test_rejects_non_archive_library_payload(self) -> None:
        relative = sorted(apple_distribution.EXPECTED_XCFRAMEWORK_LIBRARIES)[0]
        self.write_archive(library_override=(relative, b"not-an-archive"))
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError, "not a static archive"
        ):
            apple_distribution.validate_xcframework_zip(
                self.archive, require_signature=True
            )

    def test_rejects_corrupt_zip(self) -> None:
        self.archive.write_bytes(b"not-a-zip")
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError, "invalid XCFramework ZIP"
        ):
            apple_distribution.validate_xcframework_zip(
                self.archive, require_signature=True
            )


class CodesignDisplayTests(unittest.TestCase):
    def test_accepts_exact_developer_id_origin_signature(self) -> None:
        parsed = apple_distribution.parse_codesign_display(
            codesign_display(), expected_team_id=TEAM_ID
        )
        self.assertEqual(parsed["identity_class"], "Developer ID Application")
        self.assertEqual(parsed["team_id"], TEAM_ID)
        self.assertEqual(parsed["cdhash"], CDHASH)
        self.assertFalse(parsed["hardened_runtime"])

    def test_rejects_missing_timestamp_wrong_team_and_runtime(self) -> None:
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError, "Timestamp"
        ):
            apple_distribution.parse_codesign_display(
                codesign_display(timestamp=False), expected_team_id=TEAM_ID
            )
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError, "does not match"
        ):
            apple_distribution.parse_codesign_display(
                codesign_display(team_id="ABCDEFGHIJ"), expected_team_id=TEAM_ID
            )
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError, "hardened runtime"
        ):
            apple_distribution.parse_codesign_display(
                codesign_display() + "Runtime Version=26.0.0\n",
                expected_team_id=TEAM_ID,
            )

    def test_rejects_nonzero_code_directory_flags(self) -> None:
        display = codesign_display().replace(
            "flags=0x0(none)", "flags=0x10000(runtime)"
        )
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError, "flags are not exactly none"
        ):
            apple_distribution.parse_codesign_display(
                display, expected_team_id=TEAM_ID
            )


class SigningEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.xcframework = self.root / "CQPeriapt.xcframework"
        for directory in (
            apple_distribution.EXPECTED_XCFRAMEWORK_DIRECTORIES
            | apple_distribution.EXPECTED_SIGNATURE_DIRECTORIES
        ):
            relative = directory.removeprefix("CQPeriapt.xcframework/").rstrip("/")
            (self.xcframework / relative).mkdir(parents=True, exist_ok=True)
        for name in (
            apple_distribution.EXPECTED_XCFRAMEWORK_FILES
            | apple_distribution.EXPECTED_SIGNATURE_FILES
        ):
            relative = name.removeprefix("CQPeriapt.xcframework/")
            path = self.xcframework / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if relative in apple_distribution.EXPECTED_XCFRAMEWORK_LIBRARIES:
                path.write_bytes(archive_bytes(relative))
            elif relative == "_CodeSignature/CodeResources":
                path.write_bytes(b"sealed-resources")
            else:
                path.write_bytes(f"fixture:{relative}".encode("utf-8"))
            path.chmod(0o644)
        self.display = self.root / "codesign.txt"
        self.display.write_text(codesign_display(), encoding="utf-8")
        self.certificate = self.root / "certificate.der"
        self.certificate.write_bytes(b"pinned-developer-id-certificate")
        certificate = self.certificate.read_bytes()
        self.identity_sha1 = hashlib.sha1(
            certificate, usedforsecurity=False
        ).hexdigest()
        self.certificate_sha256 = hashlib.sha256(certificate).hexdigest()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build(self) -> dict[str, object]:
        metadata = {
            "subject": f"CN=Developer ID Application: Example ({TEAM_ID})",
            "issuer": "CN=Developer ID Certification Authority",
            "serial": "01",
            "notBefore": "Jul 1 00:00:00 2026 GMT",
            "notAfter": "Jul 1 00:00:00 2027 GMT",
        }
        with mock.patch.object(
            apple_distribution,
            "_openssl_certificate_metadata",
            return_value=metadata,
        ):
            return apple_distribution.build_signing_evidence(
                xcframework=self.xcframework,
                codesign_display=self.display,
                certificate=self.certificate,
                expected_team_id=TEAM_ID,
                expected_identity_sha1=self.identity_sha1,
                expected_certificate_sha256=self.certificate_sha256,
            )

    def test_binds_exact_layout_certificate_and_static_slice_hashes(self) -> None:
        evidence = self.build()
        self.assertEqual(evidence["certificate"]["sha1"], self.identity_sha1)
        self.assertEqual(
            set(evidence["sealed_resources"]["static_libraries"]),
            apple_distribution.EXPECTED_XCFRAMEWORK_LIBRARIES,
        )

    def test_rejects_extra_executable_or_symlink(self) -> None:
        extra = self.xcframework / "tool"
        extra.write_bytes(b"tool")
        extra.chmod(0o755)
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError, "mode/type is not exactly 0644"
        ):
            self.build()
        extra.unlink()
        target = self.xcframework / "Info.plist"
        target.unlink()
        target.symlink_to("elsewhere")
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError, "mode/type is not exactly 0644"
        ):
            self.build()

    def test_rejects_wrong_pinned_certificate(self) -> None:
        with mock.patch.object(
            apple_distribution,
            "_openssl_certificate_metadata",
            return_value={},
        ), self.assertRaisesRegex(
            apple_distribution.AppleDistributionError, "SHA-256 does not match"
        ):
            apple_distribution.build_signing_evidence(
                xcframework=self.xcframework,
                codesign_display=self.display,
                certificate=self.certificate,
                expected_team_id=TEAM_ID,
                expected_identity_sha1=self.identity_sha1,
                expected_certificate_sha256="00" * 32,
            )


class DistributionEvidenceTests(ZipFixture):
    def setUp(self) -> None:
        super().setUp()
        hashes = self.write_archive(signed=True)
        self.signing = signing_evidence(hashes)
        self.digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()

    def build(self) -> dict[str, object]:
        return apple_distribution.build_static_xcframework_distribution_evidence(
            artifact=self.archive,
            source_commit=SOURCE_COMMIT,
            swiftpm_checksum=self.digest,
            signing_evidence=self.signing,
        )

    def test_emits_honest_signed_static_sdk_semantics(self) -> None:
        evidence = self.build()
        self.assertEqual(
            evidence["kind"], "qperiapt.apple_static_xcframework_distribution"
        )
        self.assertEqual(evidence["source_commit"], SOURCE_COMMIT)
        self.assertEqual(evidence["artifact"]["sha256"], self.digest)
        self.assertEqual(evidence["format"]["static_archive_count"], 3)
        self.assertEqual(evidence["format"]["standalone_executable_count"], 0)
        notarization = evidence["notarization"]
        self.assertEqual(
            notarization["applicability"],
            "not_applicable_static_sdk_payload",
        )
        self.assertFalse(notarization["submission_performed"])
        self.assertFalse(notarization["notarized"])
        self.assertFalse(notarization["stapled"])
        self.assertNotIn("Accepted", json.dumps(evidence, sort_keys=True))

    def test_rejects_checksum_source_and_signature_schema_mismatch(self) -> None:
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError, "checksum does not match"
        ):
            apple_distribution.build_static_xcframework_distribution_evidence(
                artifact=self.archive,
                source_commit=SOURCE_COMMIT,
                swiftpm_checksum="00" * 32,
                signing_evidence=self.signing,
            )
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError, "source commit"
        ):
            apple_distribution.build_static_xcframework_distribution_evidence(
                artifact=self.archive,
                source_commit="not-a-commit",
                swiftpm_checksum=self.digest,
                signing_evidence=self.signing,
            )
        self.signing["fallback"] = True
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError, "fields differ"
        ):
            self.build()

    def test_rejects_zip_slice_hash_different_from_signature(self) -> None:
        relative = sorted(apple_distribution.EXPECTED_XCFRAMEWORK_LIBRARIES)[0]
        self.signing["sealed_resources"]["static_libraries"][relative] = "00" * 32
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError, "hashes differ"
        ):
            self.build()

    def test_rejects_notarized_or_accepted_injected_into_signing_evidence(self) -> None:
        for field, value in (("notarized", True), ("status", "Accepted")):
            with self.subTest(field=field):
                self.signing[field] = value
                with self.assertRaisesRegex(
                    apple_distribution.AppleDistributionError, "fields differ"
                ):
                    self.build()
                del self.signing[field]


class AtomicEvidenceWriterTests(unittest.TestCase):
    def test_atomic_writer_never_replaces_existing_path(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            output = pathlib.Path(raw) / "APPLE_DISTRIBUTION.json"
            apple_distribution._write_new_json(output, {"value": "complete"})
            self.assertEqual(
                json.loads(output.read_text(encoding="utf-8")),
                {"value": "complete"},
            )
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o644)
            with self.assertRaises(FileExistsError):
                apple_distribution._write_new_json(output, {"value": "replacement"})
            self.assertEqual(
                json.loads(output.read_text(encoding="utf-8"))["value"],
                "complete",
            )

    def test_atomic_writer_does_not_follow_existing_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            target = root / "target"
            target.write_text("preserve", encoding="utf-8")
            output = root / "APPLE_DISTRIBUTION.json"
            output.symlink_to(target)
            with self.assertRaises(FileExistsError):
                apple_distribution._write_new_json(output, {"value": "replacement"})
            self.assertEqual(target.read_text(encoding="utf-8"), "preserve")


class ReleaseWorkflowSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = pathlib.Path(__file__).resolve().parents[1]
        cls.builder = (cls.root / "artifact/swift-xcframework.sh").read_text(
            encoding="utf-8"
        )
        cls.release = (
            cls.root / "artifact/swift-xcframework-release.sh"
        ).read_text(encoding="utf-8")
        cls.remote = (
            cls.root / "artifact/swift-xcframework-remote-consumer.sh"
        ).read_text(encoding="utf-8")

    def test_release_path_is_signing_only_and_has_no_notary_credentials(self) -> None:
        source = self.builder + self.release
        for forbidden in (
            "notarytool",
            "NOTARIZATION.json",
            "NOTARY_KEYCHAIN_PROFILE",
            "QPERIAPT_NOTARY_SUBMISSION_ID",
            "apple-id",
            "--password",
            "submission-state",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)
        self.assertIn("APPLE_DISTRIBUTION.json", self.builder)
        self.assertIn("APPLE_DISTRIBUTION.json", self.release)
        self.assertIn("apple-distribution-evidence", self.builder)

    def test_signing_identity_and_certificate_remain_exactly_pinned(self) -> None:
        self.assertIn("2DA7764ED42B213AE04925B6261238B24C758FE1", self.release)
        self.assertIn(
            "806673908A3DDCD558DCC8D3EF055085F1FFF100BDA0ACFB2E1315AFD652AC8D",
            self.release,
        )
        self.assertIn('EXPECTED_TEAM_ID="YKUPL7Z869"', self.release)
        self.assertIn('codesign --timestamp', self.builder)
        self.assertIn('--extract-certificates="$CERTIFICATE_PREFIX"', self.builder)
        self.assertNotIn("--force", source := self.builder + self.release)
        self.assertNotIn("--deep", source)
        self.assertNotIn("--timestamp=none", source)

    def test_git_environment_overrides_fail_before_external_commands(self) -> None:
        names = (
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_SHALLOW_FILE",
            "GIT_NAMESPACE",
            "GIT_REPLACE_REF_BASE",
            "GIT_CONFIG_SYSTEM",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_NOSYSTEM",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_PARAMETERS",
            "GIT_CEILING_DIRECTORIES",
            "GIT_DISCOVERY_ACROSS_FILESYSTEM",
        )
        environment = os.environ.copy()
        for name in names:
            environment.pop(name, None)
        for script in (
            self.root / "artifact/swift-xcframework.sh",
            self.root / "artifact/swift-xcframework-release.sh",
        ):
            source = script.read_text(encoding="utf-8")
            for name in names:
                with self.subTest(script=script.name, name=name):
                    self.assertIn(f'${{{name}+x}}', source)
                    overridden = environment.copy()
                    overridden[name] = ""
                    completed = subprocess.run(
                        ["/bin/sh", str(script)],
                        cwd=self.root,
                        env=overridden,
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(completed.returncode, 2, completed.stderr)
                    self.assertIn(
                        "rejects Git repository/configuration environment overrides",
                        completed.stderr,
                    )

    def test_manifest_never_derives_notarized_from_release_mode(self) -> None:
        self.assertNotIn('"notarized": apple_release_mode', self.builder)
        self.assertIn('"notarized": False', self.builder)
        self.assertIn("not_applicable_static_sdk_payload", self.builder)
        self.assertIn('"schema_version": 3', self.builder)

    def test_wrapper_reverifies_all_public_assets_and_signature(self) -> None:
        for name in (
            "CQPeriapt.xcframework.zip",
            "APPLE_DISTRIBUTION.json",
            "MANIFEST.json",
            "SHA256SUMS",
        ):
            with self.subTest(name=name):
                self.assertIn(name, self.release)
        self.assertGreaterEqual(self.release.count("shasum -c SHA256SUMS"), 2)
        self.assertIn(
            'codesign --verify --strict --verbose=4 "$PUBLIC_DIST/CQPeriapt.xcframework"',
            self.release,
        )

    def test_remote_consumer_download_is_hash_pinned_and_atomic(self) -> None:
        self.assertIn("curl --fail --location", self.remote)
        self.assertIn("url_effective", self.remote)
        self.assertIn("REMOTE_ZIP_PART", self.remote)
        self.assertIn('mv "$REMOTE_ZIP_PART" "$REMOTE_ZIP"', self.remote)
        self.assertIn("swift package compute-checksum", self.remote)
        self.assertIn("codesign --verify --strict", self.remote)
        self.assertIn("release-assets.githubusercontent.com", self.remote)
        self.assertNotIn("--insecure", self.remote)


if __name__ == "__main__":
    unittest.main()
