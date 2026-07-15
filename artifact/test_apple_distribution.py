#!/usr/bin/env python3
"""Regression tests for the fail-closed static Apple distribution contract."""

from __future__ import annotations

import hashlib
import io
import json
import os
import pathlib
import copy
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

import apple_distribution


SOURCE_COMMIT = "ab" * 20
TEAM_ID = "YKUPL7Z869"
CDHASH = "0123456789abcdef0123456789abcdef01234567"


def isolated_apple_preflight_environment(
    **overrides: str,
) -> dict[str, str]:
    """Return the minimal trusted environment for Apple preflight subprocesses."""

    home = os.environ.get("HOME")
    if not home or not pathlib.Path(home).is_absolute():
        raise RuntimeError("Apple preflight tests require an absolute HOME")
    python = pathlib.Path(sys.executable).resolve(strict=True)
    environment = {
        "HOME": home,
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "QPERIAPT_PYTHON": str(python),
    }
    environment.update(overrides)
    return environment


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


def thin_archive(payload: bytes = b"object", *, member_name: bytes = b"member.o") -> bytes:
    if len(member_name) <= 15:
        name_field = member_name + b"/"
        archive_payload = payload
    else:
        name_field = f"#1/{len(member_name)}".encode("ascii")
        archive_payload = member_name + payload
    header = b"".join(
        (
            name_field.ljust(16, b" "),
            b"0".ljust(12, b" "),
            b"0".ljust(6, b" "),
            b"0".ljust(6, b" "),
            b"100644".ljust(8, b" "),
            str(len(archive_payload)).encode("ascii").ljust(10, b" "),
            b"`\n",
        )
    )
    padding = b"\n" if len(archive_payload) % 2 else b""
    return apple_distribution.AR_MAGIC + header + archive_payload + padding


def fat_static_archive(
    first_payload: bytes = b"x86_64", second_payload: bytes = b"arm64"
) -> bytes:
    first = thin_archive(first_payload)
    second = thin_archive(second_payload)
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
    create_system: int = 3,
    extra: bytes = b"",
    compression: int = zipfile.ZIP_DEFLATED,
) -> None:
    info = zipfile.ZipInfo(name, (2000, 1, 1, 0, 0, 0))
    info.create_system = create_system
    info.external_attr = mode << 16
    info.compress_type = compression
    info.extra = extra
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

    def test_rejects_malformed_ar_headers_sizes_padding_and_trailing_bytes(self) -> None:
        valid = thin_archive(b"odd")
        malformed = []
        malformed.append(apple_distribution.AR_MAGIC + b"truncated")
        bad_terminator = bytearray(valid)
        bad_terminator[66:68] = b"??"
        malformed.append(bytes(bad_terminator))
        bad_size = bytearray(valid)
        bad_size[56:66] = b"9999999999"
        malformed.append(bytes(bad_size))
        bad_padding = bytearray(valid)
        bad_padding[-1:] = b"X"
        malformed.append(bytes(bad_padding))
        malformed.append(valid + b"X")
        for archive in malformed:
            with self.subTest(size=len(archive)), self.assertRaises(
                apple_distribution.AppleDistributionError
            ):
                apple_distribution._validate_static_archive(
                    archive, label="malformed"
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

    def test_rejects_private_build_paths_without_echoing_them(self) -> None:
        private_paths = (
            b"/Users/alice/.cargo/registry/src/crate/src/lib.rs",
            b"/Users/Alice Smith/project/src/lib.rs",
            b"file:///home/alice/project/src/lib.rs",
            b"/root/build/project/src/lib.rs",
            b"/private/var/folders/ab/temp/object.o",
            b"C:\\Users\\alice\\project\\source.c",
            b"D:\\projects\\qperiapt\\source.rs",
            b"D:\\Program Files\\qperiapt\\source.rs",
            b"E:/repo/qperiapt/source.rs",
            b"\\\\server\\private-share\\project\\source.c",
            b"\\\\?\\UNC\\server\\private share\\project\\source.c",
            b"//server/private-share/project/source.c",
            b"file://server/private-share/project/source.c",
            b"/c/Users/alice/project/source.c",
            b"/d/projects/qperiapt/source.rs",
        )
        for private_path in private_paths:
            with self.subTest(private_path=private_path):
                with self.assertRaises(
                    apple_distribution.AppleDistributionError
                ) as captured:
                    apple_distribution._validate_static_archive(
                        thin_archive(private_path), label="private"
                    )
                message = str(captured.exception)
                self.assertIn("forbidden private build path", message)
                self.assertNotIn(private_path.decode("ascii"), message)
                self.assertNotIn("match_sha256", message)

    def test_rejects_generic_windows_paths_in_both_utf16_encodings(self) -> None:
        private_paths = (
            r"D:\projects\qperiapt\source.rs",
            r"\\?\UNC\server\private share\project\source.c",
            "E:/repo/qperiapt/source.rs",
            "//server/private-share/project/source.c",
            "file://server/private-share/project/source.c",
            "/d/projects/qperiapt/source.rs",
        )
        for private_path in private_paths:
            for encoding in ("utf-16-le", "utf-16-be"):
                with self.subTest(private_path=private_path, encoding=encoding):
                    with self.assertRaisesRegex(
                        apple_distribution.AppleDistributionError,
                        "utf16_.*absolute_path|utf16_.*share",
                    ):
                        apple_distribution._validate_static_archive(
                            thin_archive(private_path.encode(encoding)),
                            label="utf16-private",
                        )

    def test_does_not_treat_drive_like_noise_as_a_windows_path(self) -> None:
        allowed = (
            b"object-marker p:/! end",
            b"binary-marker /H/P/8 end",
            b"binary-marker /h/p/8 end",
            b"http://www.apple.com/DTDs/PropertyList-1.0.dtd",
            b"https://github.com/billlza/q-periapt/releases",
            "http://www.apple.com/DTDs/PropertyList-1.0.dtd".encode("utf-16-le"),
            "https://github.com/billlza/q-periapt/releases".encode("utf-16-be"),
        )
        for payload in allowed:
            with self.subTest(payload=payload):
                apple_distribution._validate_static_archive(
                    thin_archive(payload), label="path-like-public-text"
                )

    def test_scans_ar_and_fat_container_metadata_outside_member_payloads(self) -> None:
        ar_header = bytearray(thin_archive())
        ar_header[8:24] = b"/Users/alice/".ljust(16, b" ")

        fat_header = bytearray(fat_static_archive())
        fat_header[8:24] = b"/Users/alice/".ljust(16, b" ")

        fat_gap = bytearray(fat_static_archive())
        second_offset = struct.unpack_from(">I", fat_gap, 36)[0]
        gap = b"/Users/alice/"
        fat_gap[second_offset:second_offset] = gap
        struct.pack_into(">I", fat_gap, 36, second_offset + len(gap))

        fat_trailing = fat_static_archive() + b"/Users/alice/"
        for label, archive in (
            ("ar-header", bytes(ar_header)),
            ("fat-header", bytes(fat_header)),
            ("fat-gap", bytes(fat_gap)),
            ("fat-trailing", fat_trailing),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(
                apple_distribution.AppleDistributionError,
                "forbidden private build path",
            ):
                apple_distribution._validate_static_archive(archive, label=label)

    def test_rejects_dynamic_prefix_and_utf16_paths_in_fat_second_slice(self) -> None:
        private_prefix = "/Volumes/private-builder/release"
        private_path = f"{private_prefix}/source.rs"
        data = fat_static_archive(
            second_payload=private_path.encode("utf-16-le")
        )
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "exact_build_prefix_utf-16-le",
        ):
            apple_distribution._validate_static_archive(
                data,
                label="fat-private",
                forbidden_build_prefixes=(private_prefix,),
            )

    def test_accepts_only_synthetic_and_system_build_paths(self) -> None:
        allowed = b"\x00".join(
            (
                b"/__qperiapt__/cargo-home/registry/src/crate/src/lib.rs",
                b"/System/Library/Frameworks/Security.framework/Security",
                b"/dev/urandom",
                b"/rustc/0123456789abcdef/library/core/src/lib.rs",
            )
        )
        apple_distribution._validate_static_archive(
            thin_archive(allowed),
            label="allowed",
        )

    def test_rejects_every_rust_upstream_build_path(self) -> None:
        prefix = (
            b"/Users/runner/work/rust/rust/build/aarch64-apple-darwin/"
            b"stage1-std/aarch64-apple-darwin/dist/build/"
        )
        paths = (
            prefix
            + b"compiler_builtins-7be819c9f191cb18/out/lse_cas8.S",
            prefix
            + b"compiler_builtins-bbfabc7edd9dfc35/out/lse_cas8.S",
            prefix + b"compiler_builtins-deadbeef/out/lse_cas8.S",
            prefix + b"compiler_builtins-7be819c9f191cb18/outside/file.c",
            prefix
            + b"compiler_builtins-7be819c9f191cb18/out/lse_cas8.S/extra",
            b"/Users/runner/work/rust/rust/library/compiler-builtins/"
            b"compiler-builtins/extra",
        )
        for path in paths:
            with self.subTest(path=path), self.assertRaisesRegex(
                apple_distribution.AppleDistributionError, "macos_user_home"
            ):
                apple_distribution._validate_static_archive(
                    thin_archive(
                        path,
                        member_name=b"4134eb5fb31f69b6-lse_cas8.o",
                    ),
                    label="rust-upstream",
                )

    def test_rejects_rust_upstream_path_in_an_application_member(self) -> None:
        path = (
            b"/Users/runner/work/rust/rust/library/compiler-builtins/"
            b"compiler-builtins"
        )
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError, "macos_user_home"
        ):
            apple_distribution._validate_static_archive(
                thin_archive(path, member_name=b"application-object.o"),
                label="wrong-member",
            )

    def test_rejects_invalid_dynamic_prefix_contract(self) -> None:
        for prefix in (
            "relative",
            "/",
            "/path=ambiguous",
            "/path\nline",
            "/not//canonical",
            "/not/../canonical",
            "/trailing/",
        ):
            with self.subTest(prefix=prefix), self.assertRaisesRegex(
                apple_distribution.AppleDistributionError,
                "absolute canonical POSIX paths",
            ):
                apple_distribution._validate_static_archive(
                    thin_archive(),
                    label="invalid-prefix",
                    forbidden_build_prefixes=(prefix,),
                )

    def test_dynamic_prefix_requires_a_path_boundary(self) -> None:
        apple_distribution._validate_static_archive(
            thin_archive(b"/Volumes/private-builder-release/source.rs"),
            label="similar-prefix",
            forbidden_build_prefixes=("/Volumes/private-builder",),
        )


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
        file_override: tuple[str, bytes] | None = None,
        metadata_extra_name: str | None = None,
        non_unix_origin_name: str | None = None,
        compression: int = zipfile.ZIP_DEFLATED,
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
                    write_zip_entry(
                        archive,
                        name,
                        b"",
                        mode=stat.S_IFDIR | 0o755,
                        compression=compression,
                    )
                    continue
                relative = name.removeprefix("CQPeriapt.xcframework/")
                if relative in apple_distribution.EXPECTED_XCFRAMEWORK_LIBRARIES:
                    data = archive_bytes(relative)
                    if library_override and relative == library_override[0]:
                        data = library_override[1]
                elif name.endswith("CodeResources"):
                    data = b"sealed-resources"
                else:
                    data = f"fixture:{name}".encode("utf-8")
                if file_override and name == file_override[0]:
                    data = file_override[1]
                if relative in apple_distribution.EXPECTED_XCFRAMEWORK_LIBRARIES:
                    library_hashes[relative] = hashlib.sha256(data).hexdigest()
                mode = stat.S_IFREG | (
                    0o755 if name == executable_name else 0o644
                )
                if name == symlink_name:
                    mode = stat.S_IFLNK | 0o777
                write_zip_entry(
                    archive,
                    name,
                    data,
                    mode=mode,
                    create_system=0 if name == non_unix_origin_name else 3,
                    extra=b"\x01\x00\x00\x00" if name == metadata_extra_name else b"",
                    compression=compression,
                )
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

    def test_rejects_private_path_inside_decompressed_static_zip_entry(self) -> None:
        relative = sorted(apple_distribution.EXPECTED_XCFRAMEWORK_LIBRARIES)[0]
        private_path = b"/Users/alice/.cargo/registry/src/crate/src/lib.rs"
        self.write_archive(
            library_override=(relative, thin_archive(private_path))
        )
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "forbidden private build path",
        ):
            apple_distribution.validate_xcframework_zip(
                self.archive, require_signature=True
            )

    def test_rejects_private_path_in_every_regular_entry_class(self) -> None:
        names = (
            "CQPeriapt.xcframework/Info.plist",
            "CQPeriapt.xcframework/ios-arm64/Headers/q_periapt.h",
            "CQPeriapt.xcframework/_CodeSignature/CodeResources",
        )
        for name in names:
            with self.subTest(name=name):
                self.write_archive(
                    file_override=(name, b"/Users/alice/private/build-input")
                )
                with self.assertRaisesRegex(
                    apple_distribution.AppleDistributionError,
                    "forbidden private build path",
                ):
                    apple_distribution.validate_xcframework_zip(
                        self.archive, require_signature=True
                    )

    def test_rejects_central_directory_extra_fields(self) -> None:
        name = "CQPeriapt.xcframework/Info.plist"
        self.write_archive(metadata_extra_name=name)
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "central directory metadata|extended",
        ):
            apple_distribution.validate_xcframework_zip(
                self.archive, require_signature=True
            )

    def test_rejects_non_unix_zip_origin_metadata(self) -> None:
        name = "CQPeriapt.xcframework/Info.plist"
        self.write_archive(non_unix_origin_name=name)
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "central directory metadata|Unix-origin",
        ):
            apple_distribution.validate_xcframework_zip(
                self.archive, require_signature=True
            )

    def test_rejects_nonzero_local_and_central_zip_flags(self) -> None:
        self.write_archive()
        payload = bytearray(self.archive.read_bytes())
        for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            offset = 0
            while True:
                offset = payload.find(signature, offset)
                if offset < 0:
                    break
                struct.pack_into("<H", payload, offset + flag_offset, 0x4000)
                offset += len(signature)
        self.archive.write_bytes(payload)
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError, "flagged|local header"
        ):
            apple_distribution.validate_xcframework_zip(
                self.archive, require_signature=True
            )

    def test_rejects_extra_data_present_only_in_a_local_header(self) -> None:
        self.write_archive()
        with zipfile.ZipFile(self.archive) as archive:
            target = max(archive.infolist(), key=lambda info: info.header_offset)
            self.assertIsNone(archive.testzip())
        payload = bytearray(self.archive.read_bytes())
        old_eocd = len(payload) - apple_distribution.ZIP_END_OF_CENTRAL_DIRECTORY.size
        old_central_offset = struct.unpack_from("<I", payload, old_eocd + 16)[0]
        name_length = struct.unpack_from("<H", payload, target.header_offset + 26)[0]
        local_extra_length = struct.unpack_from(
            "<H", payload, target.header_offset + 28
        )[0]
        self.assertEqual(local_extra_length, 0)
        private_path = b"/Users/local-private/"
        local_extra = struct.pack("<HH", 0xCAFE, len(private_path)) + private_path
        insertion = target.header_offset + 30 + name_length
        payload[insertion:insertion] = local_extra
        struct.pack_into(
            "<H", payload, target.header_offset + 28, len(local_extra)
        )
        new_eocd = old_eocd + len(local_extra)
        struct.pack_into(
            "<I", payload, new_eocd + 16, old_central_offset + len(local_extra)
        )
        self.archive.write_bytes(payload)
        with zipfile.ZipFile(self.archive) as archive:
            self.assertIsNone(archive.testzip())
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError, "local header"
        ):
            apple_distribution.validate_xcframework_zip(
                self.archive, require_signature=True
            )

    def test_rejects_prefixed_or_trailing_zip_container_data(self) -> None:
        self.write_archive()
        canonical = self.archive.read_bytes()
        for payload in (b"prefix" + canonical, canonical + b"trailing"):
            with self.subTest(kind=payload[:8]):
                self.archive.write_bytes(payload)
                with self.assertRaisesRegex(
                    apple_distribution.AppleDistributionError,
                    "prefixed|trailing|local records|central directory",
                ):
                    apple_distribution.validate_xcframework_zip(
                        self.archive, require_signature=True
                    )

    def test_rejects_hidden_bytes_after_deflate_or_stored_entry_payload(self) -> None:
        for compression in (zipfile.ZIP_DEFLATED, zipfile.ZIP_STORED):
            with self.subTest(compression=compression):
                self.write_archive(compression=compression)
                with zipfile.ZipFile(self.archive) as archive:
                    target = max(
                        archive.infolist(), key=lambda info: info.header_offset
                    )
                    self.assertIsNone(archive.testzip())
                payload = bytearray(self.archive.read_bytes())
                old_eocd = (
                    len(payload)
                    - apple_distribution.ZIP_END_OF_CENTRAL_DIRECTORY.size
                )
                old_central_offset = struct.unpack_from(
                    "<I", payload, old_eocd + 16
                )[0]
                hidden = b"/Users/local-private/"
                payload[old_central_offset:old_central_offset] = hidden
                local_compressed_size = struct.unpack_from(
                    "<I", payload, target.header_offset + 18
                )[0]
                struct.pack_into(
                    "<I",
                    payload,
                    target.header_offset + 18,
                    local_compressed_size + len(hidden),
                )
                new_central_offset = old_central_offset + len(hidden)
                central_cursor = new_central_offset
                while central_cursor < old_eocd + len(hidden):
                    self.assertEqual(
                        struct.unpack_from("<I", payload, central_cursor)[0],
                        apple_distribution.ZIP_CENTRAL_DIRECTORY_SIGNATURE,
                    )
                    name_length, extra_length, comment_length = struct.unpack_from(
                        "<HHH", payload, central_cursor + 28
                    )
                    local_offset = struct.unpack_from(
                        "<I", payload, central_cursor + 42
                    )[0]
                    if local_offset == target.header_offset:
                        central_compressed_size = struct.unpack_from(
                            "<I", payload, central_cursor + 20
                        )[0]
                        struct.pack_into(
                            "<I",
                            payload,
                            central_cursor + 20,
                            central_compressed_size + len(hidden),
                        )
                        break
                    central_cursor += (
                        apple_distribution.ZIP_CENTRAL_DIRECTORY_HEADER.size
                        + name_length
                        + extra_length
                        + comment_length
                    )
                else:
                    self.fail("target central directory entry not found")
                new_eocd = old_eocd + len(hidden)
                struct.pack_into(
                    "<I", payload, new_eocd + 16, new_central_offset
                )
                self.archive.write_bytes(payload)
                with zipfile.ZipFile(self.archive) as archive:
                    self.assertIsNone(archive.testzip())
                with self.assertRaisesRegex(
                    apple_distribution.AppleDistributionError,
                    "deflate stream|stored XCFramework ZIP entry",
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
        self.assertEqual(evidence["schema_version"], 2)
        self.assertEqual(
            evidence["kind"], "qperiapt.apple_static_xcframework_distribution"
        )
        self.assertEqual(evidence["source_commit"], SOURCE_COMMIT)
        self.assertEqual(evidence["artifact"]["sha256"], self.digest)
        self.assertEqual(evidence["format"]["static_archive_count"], 3)
        self.assertEqual(evidence["format"]["standalone_executable_count"], 0)
        self.assertEqual(
            evidence["path_hygiene"],
            {
                "policy": apple_distribution.BUILD_PATH_HYGIENE_POLICY,
                "artifact_scan": {
                    "scope": "all_decompressed_regular_zip_entries",
                    "forbidden_match_count": 0,
                },
                "synthetic_build_path_prefix": "/__qperiapt__/",
                "allowed_upstream_toolchain_path_rules": [],
            },
        )
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


class ReleaseAssetVerificationTests(ZipFixture):
    def setUp(self) -> None:
        super().setUp()
        library_hashes = self.write_archive(signed=True)
        self.release = self.root / "release"
        self.release.mkdir()
        self.zip_path = self.release / apple_distribution.XCFRAMEWORK_ZIP_NAME
        self.zip_path.write_bytes(self.archive.read_bytes())
        self.signing = signing_evidence(library_hashes)
        self.distribution = (
            apple_distribution.build_static_xcframework_distribution_evidence(
                artifact=self.zip_path,
                source_commit=SOURCE_COMMIT,
                swiftpm_checksum=hashlib.sha256(self.zip_path.read_bytes()).hexdigest(),
                signing_evidence=self.signing,
            )
        )
        self.manifest = self._manifest_fixture()
        self.results = self.root / "results.json"
        self._publish()

    def _manifest_fixture(self) -> dict[str, object]:
        digest = hashlib.sha256(self.zip_path.read_bytes()).hexdigest()
        with zipfile.ZipFile(self.zip_path) as archive:
            info_plist_sha256 = hashlib.sha256(
                archive.read("CQPeriapt.xcframework/Info.plist")
            ).hexdigest()
        input_names = {
            "apple_distribution_verifier_sha256",
            "apple_release_script_sha256",
            "binary_consumer_link_probe_sha256",
            "binary_consumer_tests_sha256",
            "c_abi_contract_sha256",
            "consumer_check_script_sha256",
            "q_periapt_header_sha256",
            "script_sha256",
            "signed_policy_vectors_sha256",
            "swift_remote_consumer_script_sha256",
            "swift_vendored_header_sha256",
            "swift_wrapper_sha256",
        }
        source_inputs = {name: hashlib.sha256(name.encode()).hexdigest() for name in input_names}
        contract_sha256 = source_inputs["c_abi_contract_sha256"]
        return {
            "schema_version": 4,
            "kind": "qperiapt.swift_xcframework_manifest",
            "package": "q-periapt-swift",
            "version": apple_distribution.RELEASE_VERSION,
            "type": "swiftpm-binaryTarget-xcframework",
            "git_commit": SOURCE_COMMIT,
            "git_dirty": False,
            "targets": list(apple_distribution.EXPECTED_APPLE_TARGETS),
            "abi": {
                "contract_path": "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json",
                "contract_sha256": contract_sha256,
                "export_count": 9,
                "exports_sha256": "33" * 32,
                "major": 2,
                "platform": "apple-xcframework",
                "runtime_identity": {
                    "container": "CQPeriapt.xcframework",
                    "linkage": "static",
                    "slice_library": "libq_periapt_ffi_abi2.a",
                    "targets": list(apple_distribution.EXPECTED_APPLE_TARGETS),
                },
                "shared_filename": "CQPeriapt.xcframework",
                "static_filename": "libq_periapt_ffi_abi2.a",
            },
            "artifacts": {
                "xcframework_zip": {
                    "path": apple_distribution.XCFRAMEWORK_ZIP_NAME,
                    "sha256": digest,
                    "swiftpm_checksum": digest,
                },
                "xcframework_info_plist_sha256": info_plist_sha256,
                "apple_distribution_evidence": {
                    "path": apple_distribution.APPLE_DISTRIBUTION_NAME,
                    "sha256": "00" * 32,
                },
            },
            "build_path_hygiene": {
                "artifact_scan": {
                    "forbidden_match_count": 0,
                    "scope": "all_decompressed_regular_zip_entries",
                },
                "policy": apple_distribution.BUILD_PATH_HYGIENE_POLICY,
                "synthetic_build_path_prefix": apple_distribution.SYNTHETIC_BUILD_PATH_PREFIX,
            },
            "public_release_boundary": {
                "consumer_distribution_responsibilities": {
                    "ios": {
                        "requires_final_app_signing_and_provisioning": True,
                        "sdk_notarization_applicable": False,
                    },
                    "macos": {
                        "requires_final_app_notarization": True,
                        "requires_final_app_signing": True,
                    },
                },
                "contains_device_udid": False,
                "contains_mobileprovision": False,
                "contains_raw_device_proof": False,
                "distribution_signed": True,
                "notarization_applicability": "not_applicable_static_sdk_payload",
                "notarized": False,
                "requires_clean_tree_for_release": True,
                "stapled": False,
            },
            "source_inputs": source_inputs,
            "toolchain": {
                "rustc": "rustc fixture",
                "swift": "swift fixture",
                "xcode": ["Xcode fixture", "Build version fixture"],
            },
            "consumer_verification": {
                "ios_device_link": {
                    "architectures": ["arm64"],
                    "deployment_target": "16.0",
                    "log_sha256": "44" * 32,
                    "platform": "IOS",
                    "warning_or_error_diagnostics": 0,
                },
                "ios_simulator_link": {
                    "architectures": ["arm64", "x86_64"],
                    "deployment_target": "16.0",
                    "log_sha256": "55" * 32,
                    "platform": "IOSSIMULATOR",
                    "warning_or_error_diagnostics": 0,
                },
                "macos_dual_arch_runtime": {
                    "executed_architectures": ["arm64", "x86_64"],
                    "log_sha256": "66" * 32,
                    "warning_or_error_diagnostics": 0,
                },
                "macos_runtime_tests": {
                    "executed": 3,
                    "failures": 0,
                    "log_sha256": "77" * 32,
                    "warning_or_error_diagnostics": 0,
                },
                "macos_universal_link": {
                    "architectures": ["arm64", "x86_64"],
                    "deployment_target": "13.0",
                    "logs_sha256": {"arm64": "88" * 32, "x86_64": "99" * 32},
                    "platform": "MACOS",
                    "warning_or_error_diagnostics": 0,
                },
            },
        }

    def _publish(self) -> None:
        apple_path = self.release / apple_distribution.APPLE_DISTRIBUTION_NAME
        manifest_path = self.release / apple_distribution.MANIFEST_NAME
        apple_path.write_bytes(apple_distribution._json_bytes(self.distribution))
        apple_sha256 = hashlib.sha256(apple_path.read_bytes()).hexdigest()
        self.manifest["artifacts"]["apple_distribution_evidence"][
            "sha256"
        ] = apple_sha256
        manifest_path.write_bytes(apple_distribution._json_bytes(self.manifest))
        member_hashes = {
            name: hashlib.sha256((self.release / name).read_bytes()).hexdigest()
            for name in apple_distribution.RELEASE_CHECKSUM_MEMBERS
        }
        checksums = "".join(
            f"{member_hashes[name]}  {name}\n"
            for name in apple_distribution.RELEASE_CHECKSUM_MEMBERS
        ).encode("ascii")
        (self.release / apple_distribution.SHA256SUMS_NAME).write_bytes(checksums)
        self.hashes = {
            name: hashlib.sha256((self.release / name).read_bytes()).hexdigest()
            for name in (
                *apple_distribution.RELEASE_CHECKSUM_MEMBERS,
                apple_distribution.SHA256SUMS_NAME,
            )
        }
        certificate = self.distribution["origin_signature"]["certificate"]
        signature = self.distribution["origin_signature"]["signature"]
        trusted_distribution = {
            "apple_distribution_evidence_sha256": self.hashes[
                apple_distribution.APPLE_DISTRIBUTION_NAME
            ],
            "artifact_path": apple_distribution.XCFRAMEWORK_ZIP_NAME,
            "artifact_sha256": self.hashes[apple_distribution.XCFRAMEWORK_ZIP_NAME],
            "artifact_size": self.zip_path.stat().st_size,
            "checksums_sha256": self.hashes[apple_distribution.SHA256SUMS_NAME],
            "distribution_signed": True,
            "immutable_release": True,
            "manifest_sha256": self.hashes[apple_distribution.MANIFEST_NAME],
            "notarization_applicability": "not_applicable_static_sdk_payload",
            "notarized": False,
            "origin_signature_certificate_sha256": certificate["sha256"],
            "origin_signature_identity_class": "Developer ID Application",
            "origin_signature_team_id": signature["team_id"],
            "public_release": False,
            "release_tag": apple_distribution.RELEASE_TAG,
            "release_url": apple_distribution.RELEASE_URL,
            "remote_consumer_verified": False,
            "remote_verification": {
                "log_sha256": None,
                "verified_at": None,
                "verifier_commit": None,
            },
            "source_commit": SOURCE_COMMIT,
            "stapled": False,
            "swiftpm_checksum": self.hashes[apple_distribution.XCFRAMEWORK_ZIP_NAME],
            "version": apple_distribution.RELEASE_VERSION,
        }
        self.results.write_bytes(
            apple_distribution._json_bytes(
                {"swift_xcframework": {"distribution": trusted_distribution}}
            )
        )

    def verify(self, **overrides: object) -> dict[str, str]:
        arguments: dict[str, object] = {
            "release_directory": self.release,
            "results_manifest": self.results,
            "expected_source_commit": SOURCE_COMMIT,
            "expected_zip_sha256": self.hashes[
                apple_distribution.XCFRAMEWORK_ZIP_NAME
            ],
            "expected_apple_distribution_sha256": self.hashes[
                apple_distribution.APPLE_DISTRIBUTION_NAME
            ],
            "expected_manifest_sha256": self.hashes[
                apple_distribution.MANIFEST_NAME
            ],
            "expected_sha256sums_sha256": self.hashes[
                apple_distribution.SHA256SUMS_NAME
            ],
            "expected_swiftpm_checksum": self.hashes[
                apple_distribution.XCFRAMEWORK_ZIP_NAME
            ],
        }
        arguments.update(overrides)
        return apple_distribution.verify_release_assets(**arguments)

    def test_accepts_exact_results_pinned_four_asset_set(self) -> None:
        self.assertEqual(
            apple_distribution.BUILD_PATH_HYGIENE_POLICY,
            "qperiapt.apple_static_archive_build_paths.v2",
        )
        verified = self.verify()
        self.assertEqual(verified["source_commit"], SOURCE_COMMIT)
        self.assertEqual(
            verified["zip_sha256"],
            self.hashes[apple_distribution.XCFRAMEWORK_ZIP_NAME],
        )
        self.assertEqual(len(verified), 6)

    def test_rejects_path_hygiene_policy_downgrade_or_allowlist(self) -> None:
        base_distribution = copy.deepcopy(self.distribution)
        base_manifest = copy.deepcopy(self.manifest)
        mutations = (
            (
                "distribution policy downgrade",
                lambda: self.distribution["path_hygiene"].__setitem__(
                    "policy", "qperiapt.apple_static_archive_build_paths.v1"
                ),
            ),
            (
                "distribution upstream allowlist",
                lambda: self.distribution["path_hygiene"].__setitem__(
                    "allowed_upstream_toolchain_path_rules",
                    ["rust_distributed_compiler_builtins_members_v1"],
                ),
            ),
            (
                "manifest policy downgrade",
                lambda: self.manifest["build_path_hygiene"].__setitem__(
                    "policy", "qperiapt.apple_static_archive_build_paths.v1"
                ),
            ),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                self.distribution = copy.deepcopy(base_distribution)
                self.manifest = copy.deepcopy(base_manifest)
                mutate()
                self._publish()
                with self.assertRaisesRegex(
                    apple_distribution.AppleDistributionError,
                    "path hygiene|build path hygiene",
                ):
                    self.verify()

    def test_rejects_tamper_and_wrong_caller_pin(self) -> None:
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError, "caller.*differs"
        ):
            self.verify(expected_manifest_sha256="00" * 32)
        apple_path = self.release / apple_distribution.APPLE_DISTRIBUTION_NAME
        apple_path.write_bytes(apple_path.read_bytes() + b" ")
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError, "trusted release pin"
        ):
            self.verify()

    def test_rejects_cross_release_mix_even_when_all_four_files_are_repinned(self) -> None:
        mixed_zip = self.root / "mixed" / apple_distribution.XCFRAMEWORK_ZIP_NAME
        mixed_zip.parent.mkdir()
        self.write_archive(
            signed=True,
            file_override=(
                "CQPeriapt.xcframework/_CodeSignature/CodeRequirements",
                b"different-release",
            ),
        )
        mixed_zip.write_bytes(self.archive.read_bytes())
        mixed_digest = hashlib.sha256(mixed_zip.read_bytes()).hexdigest()
        mixed_distribution = (
            apple_distribution.build_static_xcframework_distribution_evidence(
                artifact=mixed_zip,
                source_commit=SOURCE_COMMIT,
                swiftpm_checksum=mixed_digest,
                signing_evidence=self.signing,
            )
        )
        self.distribution = mixed_distribution
        self._publish()
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "artifact (size|SHA-256).*release ZIP",
        ):
            self.verify()

    def test_rejects_commit_size_checksum_and_evidence_hash_mismatch(self) -> None:
        mutations = {
            "wrong commit": lambda: self.distribution.__setitem__(
                "source_commit", "cd" * 20
            ),
            "wrong size": lambda: self.distribution["artifact"].__setitem__(
                "size", self.zip_path.stat().st_size + 1
            ),
            "wrong checksum": lambda: self.distribution["artifact"].__setitem__(
                "swiftpm_checksum", "00" * 32
            ),
            "wrong evidence hash": lambda: self.manifest["artifacts"][
                "apple_distribution_evidence"
            ].__setitem__("sha256", "00" * 32),
            "dirty manifest": lambda: self.manifest.__setitem__("git_dirty", True),
        }
        base_distribution = copy.deepcopy(self.distribution)
        base_manifest = copy.deepcopy(self.manifest)
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                self.distribution = copy.deepcopy(base_distribution)
                self.manifest = copy.deepcopy(base_manifest)
                mutate()
                self._publish()
                if label == "wrong evidence hash":
                    # Publish normally repairs this binding; corrupt it after Apple hash is known.
                    self.manifest["artifacts"]["apple_distribution_evidence"][
                        "sha256"
                    ] = "00" * 32
                    manifest_path = self.release / apple_distribution.MANIFEST_NAME
                    manifest_path.write_bytes(
                        apple_distribution._json_bytes(self.manifest)
                    )
                    self.hashes[apple_distribution.MANIFEST_NAME] = hashlib.sha256(
                        manifest_path.read_bytes()
                    ).hexdigest()
                    results = json.loads(self.results.read_text(encoding="utf-8"))
                    results["swift_xcframework"]["distribution"][
                        "manifest_sha256"
                    ] = self.hashes[apple_distribution.MANIFEST_NAME]
                    self.results.write_bytes(apple_distribution._json_bytes(results))
                with self.assertRaises(apple_distribution.AppleDistributionError):
                    self.verify()

    def test_rejects_missing_duplicate_and_extra_checksum_entries(self) -> None:
        canonical = (
            self.release / apple_distribution.SHA256SUMS_NAME
        ).read_bytes().splitlines(keepends=True)
        variants = {
            "missing": b"".join(canonical[:-1]),
            "duplicate": b"".join([*canonical, canonical[0]]),
            "extra": b"".join([*canonical, b"00" * 32 + b"  EXTRA\n"]),
        }
        for label, payload in variants.items():
            with self.subTest(label=label):
                sums = self.release / apple_distribution.SHA256SUMS_NAME
                sums.write_bytes(payload)
                digest = hashlib.sha256(payload).hexdigest()
                self.hashes[apple_distribution.SHA256SUMS_NAME] = digest
                results = json.loads(self.results.read_text(encoding="utf-8"))
                results["swift_xcframework"]["distribution"][
                    "checksums_sha256"
                ] = digest
                self.results.write_bytes(apple_distribution._json_bytes(results))
                with self.assertRaisesRegex(
                    apple_distribution.AppleDistributionError, "canonical, unique"
                ):
                    self.verify()
                self._publish()

    def test_rejects_consumer_schema_missing_or_unknown_field(self) -> None:
        base = copy.deepcopy(self.manifest)
        for label, mutate in (
            (
                "unknown",
                lambda value: value["consumer_verification"][
                    "ios_device_link"
                ].__setitem__("fallback", True),
            ),
            (
                "missing",
                lambda value: value["consumer_verification"][
                    "ios_device_link"
                ].pop("platform"),
            ),
        ):
            with self.subTest(label=label):
                self.manifest = copy.deepcopy(base)
                mutate(self.manifest)
                self._publish()
                with self.assertRaisesRegex(
                    apple_distribution.AppleDistributionError, "fields differ"
                ):
                    self.verify()

    def test_rejects_results_type_confusion_and_unknown_distribution_field(self) -> None:
        for label, key, value in (
            ("size bool", "artifact_size", True),
            ("signed int", "distribution_signed", 1),
            ("unknown", "fallback", True),
        ):
            with self.subTest(label=label):
                results = json.loads(self.results.read_text(encoding="utf-8"))
                results["swift_xcframework"]["distribution"][key] = value
                self.results.write_bytes(apple_distribution._json_bytes(results))
                with self.assertRaises(apple_distribution.AppleDistributionError):
                    self.verify()
                self._publish()

    def test_remote_verification_evidence_is_all_or_nothing(self) -> None:
        results = json.loads(self.results.read_text(encoding="utf-8"))
        distribution = results["swift_xcframework"]["distribution"]
        distribution["remote_consumer_verified"] = True
        distribution["remote_verification"] = {
            "log_sha256": "11" * 32,
            "verified_at": "2026-07-15T00:00:00Z",
            "verifier_commit": "ab" * 20,
        }
        self.results.write_bytes(apple_distribution._json_bytes(results))
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "requires a public release",
        ):
            self.verify()

        distribution["public_release"] = True
        self.results.write_bytes(apple_distribution._json_bytes(results))
        self.assertEqual(self.verify()["source_commit"], SOURCE_COMMIT)

        distribution["remote_consumer_verified"] = False
        self.results.write_bytes(apple_distribution._json_bytes(results))
        with self.assertRaisesRegex(
            apple_distribution.AppleDistributionError,
            "must not carry verification evidence",
        ):
            self.verify()


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
        cls.workflow = (cls.root / ".github/workflows/ci.yml").read_text(
            encoding="utf-8"
        )

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
        source = self.builder + self.release
        self.assertNotIn("codesign --force", source)
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
        environment = isolated_apple_preflight_environment()
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
        self.assertIn('"schema_version": 4', self.builder)

    def test_compiler_path_remapping_and_archive_gates_precede_signing(self) -> None:
        self.assertIn('CARGO_ENCODED_RUSTFLAGS="-Dwarnings"', self.builder)
        self.assertIn("--remap-path-prefix=$1=$2", self.builder)
        for option in ("file", "macro", "debug"):
            self.assertIn(f'-f{{option}}-prefix-map=', self.builder)
        self.assertIn("CC_SHELL_ESCAPED_FLAGS=1", self.builder)
        self.assertIn('LLVM_STRIP="$RUST_LLVM_TOOLS/llvm-strip"', self.builder)
        self.assertIn('"$LLVM_NM" -g --defined-only "$1"', self.builder)
        strip_command = (
            '"$LLVM_STRIP" --strip-debug --enable-deterministic-archives '
            '"$sanitized_archive"'
        )
        self.assertIn(strip_command, self.builder)
        self.assertNotIn("--strip-all", self.builder)
        self.assertNotIn(
            '"$LLVM_STRIP" --strip-debug --enable-deterministic-archives '
            '"$built_archive"',
            self.builder,
        )
        scratch_init = self.builder.index(
            "SANITIZED_TARGET_ARCHIVES=\ntmp_header="
        )
        cleanup_trap = self.builder.index("trap cleanup EXIT")
        scratch_create = self.builder.index(
            'SANITIZED_TARGET_ARCHIVES=$(/usr/bin/mktemp -d '
            '"$ROOT/target/qperiapt-swift-xcframework-archives.XXXXXX")'
        )
        header_create = self.builder.index(
            'tmp_header=$(/usr/bin/mktemp '
            '"$ROOT/target/qperiapt-swift-xcframework-header.XXXXXX.h")'
        )
        self.assertLess(scratch_init, cleanup_trap)
        self.assertLess(cleanup_trap, scratch_create)
        self.assertLess(scratch_create, header_create)
        self.assertIn(
            '/bin/chmod 0700 "$SANITIZED_TARGET_ARCHIVES"', self.builder
        )
        self.assertIn(
            '/bin/rm -rf "$SANITIZED_TARGET_ARCHIVES"', self.builder
        )
        self.assertNotIn(
            '$OUT_ROOT/qperiapt-swift-xcframework-archives', self.builder
        )
        build = self.builder.index(
            'cargo build -p q-periapt-ffi --release --locked --target "$target"'
        )
        raw_abi_gate = self.builder.index(
            'validate_abi2_exports "$built_archive"'
        )
        copy = self.builder.index('cp "$built_archive" "$sanitized_archive"')
        strip = self.builder.index(strip_command)
        scan = self.builder.index(
            'validate_apple_static_archive_paths "$sanitized_archive"'
        )
        sanitized_abi_gate = self.builder.index(
            'validate_abi2_exports "$sanitized_archive"'
        )
        lipo = self.builder.index("\nlipo -create ")
        self.assertLess(build, strip)
        self.assertLess(build, raw_abi_gate)
        self.assertLess(raw_abi_gate, copy)
        self.assertLess(copy, strip)
        self.assertLess(strip, scan)
        self.assertLess(scan, sanitized_abi_gate)
        self.assertLess(sanitized_abi_gate, lipo)
        self.assertLess(self.builder.index('LLVM_STRIP="$RUST_LLVM_TOOLS/llvm-strip"'), build)
        assembly = self.builder[
            self.builder.index("=== Assemble release slices ===") :
            self.builder.index("PASS: release slices")
        ]
        for target in (
            "aarch64-apple-darwin",
            "x86_64-apple-darwin",
            "aarch64-apple-ios",
            "aarch64-apple-ios-sim",
            "x86_64-apple-ios",
        ):
            self.assertIn(f"$SANITIZED_TARGET_ARCHIVES/{target}/", assembly)
            self.assertNotIn(f"$ROOT/target/{target}/", assembly)
        self.assertGreaterEqual(
            self.builder.count("validate_apple_static_archive_paths"), 4
        )
        self.assertGreaterEqual(
            self.builder.count(
                'validate_apple_static_archive_paths "$lib"\n'
                '\tvalidate_abi2_exports "$lib"'
            ),
            2,
        )
        final_archive_gate = self.builder.index(
            '"$XCFRAMEWORK/macos-arm64_x86_64/libq_periapt_ffi_abi2.a"'
        )
        self.assertLess(final_archive_gate, self.builder.index("codesign --timestamp"))
        self.assertGreaterEqual(
            self.builder.count('--forbidden-build-prefix "$BUILD_HOME"'), 3
        )
        self.assertIn(
            "unset RUSTFLAGS CARGO_INCREMENTAL\n"
            "          sh artifact/swift-xcframework.sh",
            self.workflow,
        )
        self.assertEqual(
            self.workflow.count(
                "cargo +stable install cbindgen --version 0.29.4 --locked"
            ),
            3,
        )
        self.assertNotIn("cargo install cbindgen", self.workflow)
        self.assertNotIn(
            "rust_distributed_compiler_builtins_members_v1", self.builder
        )

    def test_abi2_export_validator_propagates_nm_and_set_failures(self) -> None:
        marker_start = "# BEGIN_ABI2_EXPORT_VALIDATOR"
        marker_end = "# END_ABI2_EXPORT_VALIDATOR"
        start = self.builder.index(marker_start)
        end = self.builder.index(marker_end, start) + len(marker_end)
        validator = self.builder[start:end]
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            fake_nm = root / "llvm-nm"
            fake_nm.write_text(
                """#!/bin/sh
set -eu
if [ "$#" -ne 3 ] || [ "$1" != "-g" ] || [ "$2" != "--defined-only" ]; then
    exit 9
fi
mode=${FAKE_NM_MODE:-exact}
for symbol in \
    q_periapt_abi_version \
    q_periapt_decapsulate \
    q_periapt_decision_from_signed_policy \
    q_periapt_encapsulate \
    q_periapt_fixed_suite_id \
    q_periapt_fixed_suite_id_len \
    q_periapt_generate_keypair \
    q_periapt_status_name \
    q_periapt_version; do
    if [ "$mode" = "missing" ] && [ "$symbol" = "q_periapt_version" ]; then
        continue
    fi
    printf '0000000000000000 T _%s\n' "$symbol"
done
if [ "$mode" = "extra" ]; then
    printf '0000000000000000 T _q_periapt_unexpected\n'
fi
if [ "$mode" = "error" ]; then
    exit 7
fi
""",
                encoding="utf-8",
            )
            fake_nm.chmod(0o755)
            archive = root / "fixture.a"
            archive.write_bytes(b"fixture")
            harness = root / "harness.sh"
            harness.write_text(
                "#!/bin/sh\nset -eu\nLLVM_NM=$1\n"
                + validator
                + '\nvalidate_abi2_exports "$2"\n',
                encoding="utf-8",
            )
            harness.chmod(0o755)
            for mode, expected_status in (
                ("exact", 0),
                ("error", 1),
                ("missing", 1),
                ("extra", 1),
            ):
                with self.subTest(mode=mode):
                    environment = isolated_apple_preflight_environment(
                        FAKE_NM_MODE=mode
                    )
                    completed = subprocess.run(
                        ["/bin/sh", str(harness), str(fake_nm), str(archive)],
                        env=environment,
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(
                        completed.returncode, expected_status, completed.stderr
                    )
                    if expected_status:
                        self.assertIn("Apple static archive", completed.stderr)

    def test_untrusted_configuration_preflight_precedes_platform_tool_probes(
        self,
    ) -> None:
        tool_probe = self.builder.index("need cargo\n")
        for marker in (
            "rejects caller compiler/flag overrides",
            "rejects ambient Cargo configuration files",
            "QPERIAPT_SWIFT_XCFRAMEWORK_SKIP_VERIFY is not supported",
            "credentialed Apple distribution never permits dirty diagnostic mode",
        ):
            with self.subTest(marker=marker):
                self.assertLess(self.builder.index(marker), tool_probe)

    def test_caller_compiler_and_target_flag_overrides_fail_fast(self) -> None:
        script = self.root / "artifact/swift-xcframework.sh"
        environment = isolated_apple_preflight_environment()
        for name in (
            "RUSTFLAGS",
            "CARGO_INCREMENTAL",
            "CFLAGS_aarch64_apple_ios",
            "CARGO_TARGET_AARCH64_APPLE_IOS_RUSTFLAGS",
            "CARGO_BUILD_TARGET_DIR",
            "CARGO_BUILD_BUILD_DIR",
            "RUSTC_LINKER",
            "CROSS_COMPILE",
            "CPATH",
        ):
            with self.subTest(name=name):
                overridden = environment | {name: "-Cunsafe-example"}
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
                    "rejects caller compiler/flag overrides", completed.stderr
                )
                self.assertIn(name, completed.stderr)

    def test_ambient_cargo_configuration_fails_before_build(self) -> None:
        script = self.root / "artifact/swift-xcframework.sh"
        with tempfile.TemporaryDirectory() as raw:
            cargo_home = pathlib.Path(raw)
            (cargo_home / "config.toml").write_text(
                '[build]\nrustflags = ["-C", "unexpected"]\n', encoding="utf-8"
            )
            environment = isolated_apple_preflight_environment(
                CARGO_HOME=str(cargo_home)
            )
            completed = subprocess.run(
                ["/bin/sh", str(script)],
                cwd=self.root,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 2, completed.stderr)
            self.assertIn(
                "rejects ambient Cargo configuration files", completed.stderr
            )

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
        self.assertIn('release_worktree_python \\\n\t"$WORKTREE_ROOT/artifact/apple_distribution.py"', self.release)
        self.assertNotIn('PYTHONPATH="$WORKTREE_ROOT/artifact"', self.release)
        self.assertIn('worktree remove --force "$WORKTREE_ROOT"', self.release)
        self.assertIn("source_worktree_cleaned=true", self.release)
        self.assertIn(
            "status --porcelain=v1 --untracked-files=normal", self.release
        )
        self.assertIn("refusing to force-remove a changed", self.release)
        self.assertIn('COMPLETION_PENDING="$RELEASE_ROOT/completed.json.pending"', self.release)
        self.assertIn('COMPLETION_LEDGER="$RELEASE_ROOT/completed.json"', self.release)
        pending_write = self.release.index(
            'python3 - "$COMPLETION_PENDING" "$SOURCE_COMMIT" "$PUBLIC_DIST"'
        )
        cleanup = self.release.rindex("cleanup_owned_release_worktree")
        ledger_rename = self.release.index("os.rename(pending, completed)")
        self.assertLess(pending_write, cleanup)
        self.assertLess(cleanup, ledger_rename)

    def test_remote_consumer_download_is_hash_pinned_and_atomic(self) -> None:
        self.assertIn("curl -q --fail --location", self.remote)
        self.assertIn("url_effective", self.remote)
        self.assertIn('part="$destination.part"', self.remote)
        self.assertIn("swift package compute-checksum", self.remote)
        self.assertIn("codesign --verify --strict", self.remote)
        self.assertIn("release-assets.githubusercontent.com", self.remote)
        for asset in (
            "CQPeriapt.xcframework.zip",
            "APPLE_DISTRIBUTION.json",
            "MANIFEST.json",
            "SHA256SUMS",
        ):
            with self.subTest(asset=asset):
                self.assertIn(f'$RELEASE_BASE/{asset}', self.remote)
        self.assertIn('remote_git cat-file blob "$expected_blob"', self.remote)
        self.assertIn('remote_git cat-file -s "$expected_blob"', self.remote)
        self.assertIn('remote_git ls-tree "$commit"', self.remote)
        self.assertIn('remote_git hash-object --no-filters "$part"', self.remote)
        self.assertIn("MAX_SOURCE_BLOB_BYTES=4194304", self.remote)
        self.assertIn("set -C", self.remote)
        self.assertIn('/usr/bin/wc -c <"$part"', self.remote)
        self.assertIn('trap cleanup_remote_state EXIT', self.remote)
        self.assertLess(
            self.remote.index('trap cleanup_remote_state EXIT'),
            self.remote.index("materialize_source_input()"),
        )
        self.assertIn('[ -L "$ROOT/target" ]', self.remote)
        self.assertLess(
            self.remote.index('if [ ! -d "$ROOT/target" ]'),
            self.remote.index('mkdir -m 700 "$LOCK_DIR"'),
        )
        for relative in (
            "artifact/swift-xcframework-remote-consumer.sh",
            "artifact/apple_distribution.py",
            "artifact/evidence_io.py",
            "artifact/swift-xcframework-consumer-check.sh",
            "artifact/python-env.sh",
            "artifact/python_bootstrap.py",
            "artifact/results.json",
            "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json",
        ):
            with self.subTest(relative=relative):
                self.assertIn(relative, self.remote)
        self.assertIn(
            'materialize_source_input "$ARTIFACT_SOURCE_COMMIT" "$ARTIFACT_SNAPSHOT"',
            self.remote,
        )
        self.assertIn(
            'materialize_source_input "$VERIFIER_COMMIT" "$VERIFIER_SNAPSHOT"',
            self.remote,
        )
        self.assertIn("verify-release-assets", self.remote)
        self.assertIn('--results-manifest "$VERIFIER_SNAPSHOT/artifact/results.json"', self.remote)
        self.assertLess(
            self.remote.index("# This gate precedes every URL consumer or extractor."),
            self.remote.index(".binaryTarget"),
        )
        self.assertGreaterEqual(self.remote.count("verify_release_assets"), 4)
        self.assertIn('rm -rf "$ARTIFACT_SNAPSHOT" "$VERIFIER_SNAPSHOT"', self.remote)
        self.assertIn("artifact_source_commit=%s verifier_commit=%s", self.remote)
        self.assertNotIn("SOURCE_WORKTREE", self.remote)
        self.assertNotIn("qperiapt-apple-release-worktrees", self.remote)
        self.assertNotIn("--insecure", self.remote)


if __name__ == "__main__":
    unittest.main()
