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

    def test_accepts_synthetic_system_and_narrow_rust_upstream_paths(self) -> None:
        allowed = b"\x00".join(
            (
                b"/__qperiapt__/cargo-home/registry/src/crate/src/lib.rs",
                b"/System/Library/Frameworks/Security.framework/Security",
                b"/dev/urandom",
                b"/rustc/0123456789abcdef/library/core/src/lib.rs",
                b"/Users/runner/work/rust/rust/build/aarch64-apple-darwin/"
                b"stage1-std/aarch64-apple-darwin/dist/build/"
                b"compiler_builtins-7be819c9f191cb18/out/lse_cas8.S",
                b"/Users/runner/work/rust/rust/library/compiler-builtins/"
                b"compiler-builtins",
            )
        )
        apple_distribution._validate_static_archive(
            thin_archive(
                allowed,
                member_name=b"4134eb5fb31f69b6-lse_cas8.o",
            ),
            label="allowed",
        )

    def test_rejects_unpinned_rust_upstream_build_path(self) -> None:
        prefix = (
            b"/Users/runner/work/rust/rust/build/aarch64-apple-darwin/"
            b"stage1-std/aarch64-apple-darwin/dist/build/"
        )
        paths = (
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
                    thin_archive(path), label="unpinned-upstream"
                )

    def test_rejects_pinned_upstream_path_in_an_unpinned_member(self) -> None:
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
                "allowed_upstream_toolchain_path_rules": [
                    "rust_distributed_compiler_builtins_members_v1"
                ],
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
        self.assertIn('"schema_version": 4', self.builder)

    def test_compiler_path_remapping_and_archive_gates_precede_signing(self) -> None:
        self.assertIn('CARGO_ENCODED_RUSTFLAGS="-Dwarnings"', self.builder)
        self.assertIn("--remap-path-prefix=$1=$2", self.builder)
        for option in ("file", "macro", "debug"):
            self.assertIn(f'-f{{option}}-prefix-map=', self.builder)
        self.assertIn("CC_SHELL_ESCAPED_FLAGS=1", self.builder)
        self.assertGreaterEqual(
            self.builder.count("validate_apple_static_archive_paths"), 4
        )
        final_archive_gate = self.builder.index(
            '"$XCFRAMEWORK/macos-arm64_x86_64/libq_periapt_ffi_abi2.a"'
        )
        self.assertLess(final_archive_gate, self.builder.index("codesign --timestamp"))
        self.assertGreaterEqual(
            self.builder.count('--forbidden-build-prefix "$BUILD_HOME"'), 3
        )
        self.assertIn("unset RUSTFLAGS\n          sh artifact/swift-xcframework.sh", self.workflow)

    def test_caller_compiler_and_target_flag_overrides_fail_fast(self) -> None:
        script = self.root / "artifact/swift-xcframework.sh"
        environment = os.environ.copy()
        exact = {
            "AR",
            "ARFLAGS",
            "CC",
            "CC_SHELL_ESCAPED_FLAGS",
            "CFLAGS",
            "CPPFLAGS",
            "CXX",
            "CXXFLAGS",
            "CARGO_BUILD_RUSTFLAGS",
            "CARGO_BUILD_RUSTC",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
            "CARGO_BUILD_RUSTDOCFLAGS",
            "CARGO_BUILD_BUILD_DIR",
            "CARGO_BUILD_TARGET",
            "CARGO_BUILD_TARGET_DIR",
            "CARGO_ENCODED_RUSTDOCFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_TARGET_DIR",
            "CARGO_INCREMENTAL",
            "CC_FORCE_DISABLE",
            "COMPILER_PATH",
            "CPATH",
            "CPLUS_INCLUDE_PATH",
            "CROSS_COMPILE",
            "CRATE_CC_NO_DEFAULTS",
            "C_INCLUDE_PATH",
            "DEVELOPER_DIR",
            "HOST_AR",
            "HOST_ARFLAGS",
            "HOST_CC",
            "HOST_CFLAGS",
            "HOST_CPPFLAGS",
            "HOST_CXX",
            "HOST_CXXFLAGS",
            "HOST_RANLIB",
            "HOST_RANLIBFLAGS",
            "IPHONEOS_DEPLOYMENT_TARGET",
            "GCC_EXEC_PREFIX",
            "LD",
            "LDFLAGS",
            "LIBRARY_PATH",
            "MACOSX_DEPLOYMENT_TARGET",
            "OBJC_INCLUDE_PATH",
            "RANLIB",
            "RANLIBFLAGS",
            "RUSTC",
            "RUSTC_BOOTSTRAP",
            "RUSTC_LINKER",
            "RUSTC_WORKSPACE_WRAPPER",
            "RUSTC_WRAPPER",
            "RUSTDOCFLAGS",
            "RUSTFLAGS",
            "RUSTUP_TOOLCHAIN",
            "SDKROOT",
            "SOURCE_DATE_EPOCH",
            "TARGET_AR",
            "TARGET_ARFLAGS",
            "TARGET_CC",
            "TARGET_CFLAGS",
            "TARGET_CPPFLAGS",
            "TARGET_CXX",
            "TARGET_CXXFLAGS",
            "TARGET_RANLIB",
            "TARGET_RANLIBFLAGS",
            "TVOS_DEPLOYMENT_TARGET",
            "WATCHOS_DEPLOYMENT_TARGET",
            "XROS_DEPLOYMENT_TARGET",
            "ZERO_AR_DATE",
        }
        compiler_prefixes = ("AR_", "CC_", "CFLAGS_", "CPPFLAGS_", "CXX_", "CXXFLAGS_")
        compiler_suffixes = (
            "_AR",
            "_CC",
            "_CFLAGS",
            "_CPPFLAGS",
            "_CXX",
            "_CXXFLAGS",
        )
        for name in tuple(environment):
            if (
                name in exact
                or name.startswith(compiler_prefixes)
                or name.endswith(compiler_suffixes)
                or name.startswith("CARGO_TARGET_")
            ):
                environment.pop(name)
        for name in (
            "RUSTFLAGS",
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
            environment = os.environ.copy()
            for name in (
                "RUSTFLAGS",
                "CARGO_ENCODED_RUSTFLAGS",
                "CARGO_BUILD_RUSTFLAGS",
            ):
                environment.pop(name, None)
            environment["CARGO_HOME"] = str(cargo_home)
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
        self.assertIn("REMOTE_ZIP_PART", self.remote)
        self.assertIn('mv "$REMOTE_ZIP_PART" "$REMOTE_ZIP"', self.remote)
        self.assertIn("swift package compute-checksum", self.remote)
        self.assertIn("codesign --verify --strict", self.remote)
        self.assertIn("release-assets.githubusercontent.com", self.remote)
        self.assertIn('remote_git cat-file blob "$expected_blob"', self.remote)
        self.assertIn('remote_git cat-file -s "$expected_blob"', self.remote)
        self.assertIn('remote_git ls-tree "$SOURCE_COMMIT"', self.remote)
        self.assertIn('remote_git hash-object --no-filters "$part"', self.remote)
        self.assertIn("MAX_SOURCE_BLOB_BYTES=4194304", self.remote)
        self.assertIn("set -C", self.remote)
        self.assertIn('wc -c <"$part"', self.remote)
        self.assertIn('trap cleanup_remote_state EXIT', self.remote)
        self.assertLess(
            self.remote.index('trap cleanup_remote_state EXIT'),
            self.remote.index("materialize_source_input()"),
        )
        for relative in (
            "artifact/swift-xcframework-remote-consumer.sh",
            "artifact/apple_distribution.py",
            "artifact/evidence_io.py",
            "artifact/swift-xcframework-consumer-check.sh",
            "artifact/python-env.sh",
            "artifact/python_bootstrap.py",
            "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json",
        ):
            with self.subTest(relative=relative):
                self.assertIn(relative, self.remote)
        self.assertIn(
            'snapshot_python "$SOURCE_SNAPSHOT/artifact/apple_distribution.py" validate-zip',
            self.remote,
        )
        self.assertIn(
            'sh "$SOURCE_SNAPSHOT/artifact/swift-xcframework-consumer-check.sh"',
            self.remote,
        )
        self.assertIn('rm -rf "$SOURCE_SNAPSHOT"', self.remote)
        self.assertNotIn("SOURCE_WORKTREE", self.remote)
        self.assertNotIn("qperiapt-apple-release-worktrees", self.remote)
        self.assertNotIn("--insecure", self.remote)


if __name__ == "__main__":
    unittest.main()
