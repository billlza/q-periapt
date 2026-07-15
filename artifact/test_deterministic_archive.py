from __future__ import annotations

import binascii
import io
import os
import pathlib
import stat
import struct
import tempfile
import unittest
import warnings
import zipfile
import zlib
from unittest import mock

import deterministic_archive
from deterministic_archive import (
    ArchiveLimits,
    DeterministicArchiveError,
    audit_tar_gz,
    audit_zip,
    create_tar_gz,
    create_zip,
    extract_tar_gz,
    extract_zip,
)


if os.name == "nt":
    import ctypes


MTIME = 1_700_000_000


def _gzip(payload: bytes, mtime: int = MTIME) -> bytes:
    compressor = zlib.compressobj(level=9, wbits=-zlib.MAX_WBITS)
    compressed = compressor.compress(payload) + compressor.flush()
    return (
        b"\x1f\x8b\x08\x00"
        + struct.pack("<L", mtime)
        + b"\x02\xff"
        + compressed
        + struct.pack(
            "<LL",
            binascii.crc32(payload) & 0xFFFFFFFF,
            len(payload) & 0xFFFFFFFF,
        )
    )


def _gunzip(data: bytes) -> bytes:
    return zlib.decompress(data, 16 + zlib.MAX_WBITS)


def _tar_checksum(header: bytearray) -> None:
    header[148:156] = b"        "
    header[148:156] = f"{sum(header):06o}\0 ".encode("ascii")


def _replace_tar_name(data: bytes, offset: int, name: bytes) -> bytes:
    payload = bytearray(_gunzip(data))
    if len(name) > 99:
        raise AssertionError("test name is too long")
    if offset < 0 or offset % 512 or offset + 512 > len(payload):
        raise AssertionError("test tar header offset is invalid")
    payload[offset : offset + 100] = b"\0" * 100
    payload[offset : offset + len(name)] = name
    header = bytearray(payload[offset : offset + 512])
    _tar_checksum(header)
    payload[offset : offset + 512] = header
    return _gzip(bytes(payload))


def _replace_zip_member_name(data: bytes, original: bytes, replacement: bytes) -> bytes:
    if len(original) != len(replacement):
        raise AssertionError("test ZIP replacement name must preserve length")
    if data.count(original) != 2:
        raise AssertionError("test ZIP member name must occur once locally and centrally")
    return data.replace(original, replacement)


def _zip_central_record(data: bytes, member_name: str) -> int:
    eocd_offset = len(data) - struct.calcsize("<4s4H2LH")
    central_offset = struct.unpack_from("<L", data, eocd_offset + 16)[0]
    central_size = struct.unpack_from("<L", data, eocd_offset + 12)[0]
    cursor = central_offset
    while cursor < central_offset + central_size:
        self_size = struct.calcsize("<4s6H3L5H2L")
        fields = struct.unpack_from("<4s6H3L5H2L", data, cursor)
        name_length, extra_length, comment_length = fields[10:13]
        name_start = cursor + self_size
        name_end = name_start + name_length
        if data[name_start:name_end].decode("ascii") == member_name:
            return cursor
        cursor = name_end + extra_length + comment_length
    raise AssertionError(f"ZIP central member not found: {member_name}")


class DeterministicArchiveTests(unittest.TestCase):
    def _source(self, root: pathlib.Path) -> pathlib.Path:
        source = root / "source"
        (source / "lib").mkdir(parents=True)
        (source / "README.md").write_text("release\n", encoding="utf-8")
        (source / "lib/library.bin").write_bytes(b"\x00ABI2\xff")
        return source

    def _assert_host_regular_release_file(self, path: pathlib.Path) -> None:
        metadata = path.lstat()
        self.assertTrue(stat.S_ISREG(metadata.st_mode))
        self.assertFalse(path.is_symlink())
        mode = stat.S_IMODE(metadata.st_mode)
        self.assertTrue(mode & stat.S_IRUSR)
        self.assertTrue(mode & stat.S_IWUSR)
        self.assertEqual(
            mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH),
            0,
        )
        if os.name == "nt":
            attributes = getattr(metadata, "st_file_attributes", 0)
            self.assertEqual(attributes & 0x00000400, 0)
            self.assertEqual(attributes & 0x00000001, 0)
        else:
            self.assertEqual(mode, 0o644)

    def _assert_host_release_directory(self, path: pathlib.Path) -> None:
        metadata = path.lstat()
        self.assertTrue(stat.S_ISDIR(metadata.st_mode))
        self.assertFalse(path.is_symlink())
        if os.name == "nt":
            attributes = getattr(metadata, "st_file_attributes", 0)
            self.assertEqual(attributes & 0x00000400, 0)
            self.assertEqual(attributes & 0x00000001, 0)
        else:
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o755)

    def test_tar_and_zip_are_deterministic_and_extract_exact_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            source = self._source(root)
            first_tar = root / "first.tar.gz"
            second_tar = root / "second.tar.gz"
            first_zip = root / "first.zip"
            second_zip = root / "second.zip"

            tar_audit = create_tar_gz(
                source, first_tar, root_name="package", mtime=MTIME
            )
            zip_audit = create_zip(
                source, first_zip, root_name="package", mtime=MTIME
            )
            os.utime(source / "README.md", (MTIME + 200, MTIME + 200))
            os.chmod(source / "README.md", 0o755)
            create_tar_gz(source, second_tar, root_name="package", mtime=MTIME)
            create_zip(source, second_zip, root_name="package", mtime=MTIME)

            self.assertEqual(first_tar.read_bytes(), second_tar.read_bytes())
            self.assertEqual(first_zip.read_bytes(), second_zip.read_bytes())
            self._assert_host_regular_release_file(first_tar)
            self._assert_host_regular_release_file(first_zip)
            self.assertEqual(tar_audit.format, "tar.gz")
            self.assertEqual(zip_audit.format, "zip")
            expected_paths_and_modes = [
                ("package", 0o755),
                ("package/README.md", 0o644),
                ("package/lib", 0o755),
                ("package/lib/library.bin", 0o644),
            ]
            for audit in (tar_audit, zip_audit):
                self.assertEqual(
                    [(entry.path, entry.mode) for entry in audit.entries],
                    expected_paths_and_modes,
                )

            tar_destination = root / "tar-extracted"
            zip_destination = root / "zip-extracted"
            extract_tar_gz(
                first_tar,
                tar_destination,
                root_name="package",
                mtime=MTIME,
                expected_sha256=tar_audit.archive_sha256,
            )
            extract_zip(
                first_zip,
                zip_destination,
                root_name="package",
                mtime=MTIME,
                expected_sha256=zip_audit.archive_sha256,
            )
            for destination, audit in (
                (tar_destination, tar_audit),
                (zip_destination, zip_audit),
            ):
                self.assertEqual(
                    (destination / "package/README.md").read_text(encoding="utf-8"),
                    "release\n",
                )
                self.assertEqual(
                    (destination / "package/lib/library.bin").read_bytes(),
                    b"\x00ABI2\xff",
                )
                for entry in audit.entries:
                    extracted = destination.joinpath(
                        *pathlib.PurePosixPath(entry.path).parts
                    )
                    self.assertEqual(
                        extracted.stat().st_mtime_ns,
                        MTIME * 1_000_000_000,
                    )
                    if entry.kind == "file":
                        self._assert_host_regular_release_file(extracted)
                    else:
                        self._assert_host_release_directory(extracted)

    def test_source_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            source = self._source(root)
            (source / "link").symlink_to(source / "README.md")
            with self.assertRaisesRegex(
                DeterministicArchiveError, "symlink or special"
            ):
                create_tar_gz(
                    source, root / "bad.tar.gz", root_name="package", mtime=MTIME
                )

    def test_ambiguous_member_names_are_rejected_from_archive_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            source = root / "source"
            source.mkdir()
            (source / "safe").write_bytes(b"x")
            archive = root / "package.tar.gz"
            create_tar_gz(source, archive, root_name="package", mtime=MTIME)
            original = archive.read_bytes()

            cases = (
                ("backslash", b"package/bad\\name", "backslash"),
                ("windows-invalid", b"package/bad?name", "Windows-invalid"),
            )
            for label, member_name, error in cases:
                with self.subTest(label=label):
                    forged = root / f"{label}.tar.gz"
                    forged.write_bytes(_replace_tar_name(original, 512, member_name))
                    with self.assertRaisesRegex(DeterministicArchiveError, error):
                        audit_tar_gz(
                            forged,
                            root_name="package",
                            mtime=MTIME,
                        )

            zip_source = self._source(root / "zip-fixture")
            zip_archive = root / "package.zip"
            create_zip(zip_source, zip_archive, root_name="package", mtime=MTIME)
            original_zip = zip_archive.read_bytes()
            original_name = b"package/README.md"
            zip_cases = (
                ("zip-backslash", b"package/bad\\namex", "backslash"),
                ("zip-windows-invalid", b"package/bad?namex", "Windows-invalid"),
            )
            for label, member_name, error in zip_cases:
                with self.subTest(label=label):
                    forged = root / f"{label}.zip"
                    forged.write_bytes(
                        _replace_zip_member_name(
                            original_zip,
                            original_name,
                            member_name,
                        )
                    )
                    with self.assertRaisesRegex(DeterministicArchiveError, error):
                        audit_zip(
                            forged,
                            root_name="package",
                            mtime=MTIME,
                        )

    def test_existing_outputs_and_destinations_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            source = self._source(root)
            archive = root / "package.tar.gz"
            create_tar_gz(source, archive, root_name="package", mtime=MTIME)
            with self.assertRaisesRegex(DeterministicArchiveError, "already exists"):
                create_tar_gz(source, archive, root_name="package", mtime=MTIME)
            destination = root / "destination"
            destination.mkdir()
            with self.assertRaisesRegex(DeterministicArchiveError, "must not already exist"):
                extract_tar_gz(
                    archive, destination, root_name="package", mtime=MTIME
                )
            wrong_digest_destination = root / "wrong-digest"
            with self.assertRaisesRegex(DeterministicArchiveError, "SHA-256"):
                extract_tar_gz(
                    archive,
                    wrong_digest_destination,
                    root_name="package",
                    mtime=MTIME,
                    expected_sha256="0" * 64,
                )
            self.assertFalse(wrong_digest_destination.exists())

    def test_extraction_rejects_ancestor_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            archive = root / "package.tar.gz"
            create_tar_gz(
                self._source(root), archive, root_name="package", mtime=MTIME
            )
            real_parent = root / "real-parent"
            real_parent.mkdir()
            linked_parent = root / "linked-parent"
            try:
                linked_parent.symlink_to(real_parent, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"platform cannot create a directory symlink: {exc}")
            destination = linked_parent / "destination"
            with self.assertRaisesRegex(
                DeterministicArchiveError, "parent chain.*non-symlink"
            ):
                extract_tar_gz(
                    archive, destination, root_name="package", mtime=MTIME
                )
            self.assertFalse(destination.exists())

    def test_extraction_rejects_windows_reparse_ancestor_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            archive = root / "package.tar.gz"
            create_tar_gz(
                self._source(root), archive, root_name="package", mtime=MTIME
            )
            reparse_parent = root / "reparse-parent"
            reparse_parent.mkdir()
            destination = reparse_parent / "destination"
            original_lstat = pathlib.Path.lstat

            def reparse_lstat(
                path: pathlib.Path, *args: object, **kwargs: object
            ) -> object:
                metadata = original_lstat(path, *args, **kwargs)
                if path == reparse_parent:
                    return mock.Mock(
                        st_mode=metadata.st_mode,
                        st_file_attributes=0x00000400,
                    )
                return metadata

            with mock.patch.object(pathlib.Path, "lstat", reparse_lstat):
                with self.assertRaisesRegex(
                    DeterministicArchiveError, "parent chain.*non-reparse"
                ):
                    extract_tar_gz(
                        archive, destination, root_name="package", mtime=MTIME
                    )
            self.assertFalse(destination.exists())

    def test_canonical_destination_accepts_alias_only_above_its_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            archive = root / "package.tar.gz"
            create_tar_gz(
                self._source(root), archive, root_name="package", mtime=MTIME
            )
            physical_parent = root / "physical-parent"
            canonical_anchor = physical_parent / "private"
            canonical_anchor.mkdir(parents=True)
            alias_parent = root / "alias-parent"
            try:
                alias_parent.symlink_to(physical_parent, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"platform cannot create a directory symlink: {exc}")

            resolved_anchor = (alias_parent / "private").resolve(strict=True)
            self.assertEqual(resolved_anchor, canonical_anchor.resolve(strict=True))
            destination = resolved_anchor / "destination"
            extract_tar_gz(
                archive, destination, root_name="package", mtime=MTIME
            )
            self.assertEqual(
                (destination / "package/README.md").read_text(encoding="utf-8"),
                "release\n",
            )

    def test_extraction_rejects_symlink_below_canonical_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            archive = root / "package.tar.gz"
            create_tar_gz(
                self._source(root), archive, root_name="package", mtime=MTIME
            )
            canonical_anchor = root / "canonical-anchor"
            canonical_anchor.mkdir()
            real_parent = canonical_anchor / "real-parent"
            real_parent.mkdir()
            linked_parent = canonical_anchor / "linked-parent"
            try:
                linked_parent.symlink_to(real_parent, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"platform cannot create a directory symlink: {exc}")

            destination = linked_parent / "destination"
            with self.assertRaisesRegex(
                DeterministicArchiveError, "parent chain.*non-symlink"
            ):
                extract_tar_gz(
                    archive, destination, root_name="package", mtime=MTIME
                )
            self.assertFalse(destination.exists())

    def test_extraction_never_replaces_racing_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            archive = root / "package.tar.gz"
            create_tar_gz(
                self._source(root), archive, root_name="package", mtime=MTIME
            )
            destination = root / "destination"
            original_mkdir = pathlib.Path.mkdir

            def racing_mkdir(
                path: pathlib.Path, *args: object, **kwargs: object
            ) -> None:
                if path == destination:
                    original_mkdir(path, mode=0o755)
                    (path / "rival.txt").write_text("rival\n", encoding="utf-8")
                original_mkdir(path, *args, **kwargs)

            with mock.patch.object(pathlib.Path, "mkdir", racing_mkdir):
                with self.assertRaisesRegex(
                    DeterministicArchiveError, "cannot extract archive"
                ):
                    extract_tar_gz(
                        archive, destination, root_name="package", mtime=MTIME
                    )
            self.assertEqual(
                (destination / "rival.txt").read_text(encoding="utf-8"),
                "rival\n",
            )
            self.assertFalse(root.joinpath(f".destination.tmp-{os.getpid()}").exists())

    def test_extraction_never_removes_racing_archive_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            archive = root / "package.tar.gz"
            create_tar_gz(
                self._source(root), archive, root_name="package", mtime=MTIME
            )
            destination = root / "destination"
            original_rename = os.rename

            def racing_rename(source: object, target: object) -> None:
                competitor = pathlib.Path(target)
                competitor.mkdir(mode=0o755)
                (competitor / "rival.txt").write_text(
                    "rival\n", encoding="utf-8"
                )
                original_rename(source, target)

            with mock.patch(
                "deterministic_archive.os.rename", side_effect=racing_rename
            ):
                with self.assertRaisesRegex(
                    DeterministicArchiveError, "cannot extract archive"
                ):
                    extract_tar_gz(
                        archive, destination, root_name="package", mtime=MTIME
                    )
            self.assertEqual(
                (destination / "package/rival.txt").read_text(encoding="utf-8"),
                "rival\n",
            )
            self.assertFalse(root.joinpath(f".destination.tmp-{os.getpid()}").exists())

    def test_extraction_io_failure_cleans_staging_and_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            archive = root / "package.tar.gz"
            create_tar_gz(
                self._source(root), archive, root_name="package", mtime=MTIME
            )
            destination = root / "destination"
            with mock.patch(
                "deterministic_archive.os.fsync",
                side_effect=OSError("synthetic extraction write failure"),
            ):
                with self.assertRaisesRegex(
                    DeterministicArchiveError, "cannot extract archive"
                ):
                    extract_tar_gz(
                        archive, destination, root_name="package", mtime=MTIME
                    )
            self.assertFalse(destination.exists())
            self.assertFalse(root.joinpath(f".destination.tmp-{os.getpid()}").exists())

    def test_extraction_metadata_failure_cleans_staging_and_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            archive = root / "package.tar.gz"
            create_tar_gz(
                self._source(root), archive, root_name="package", mtime=MTIME
            )
            cases = (
                (
                    "file-os-error",
                    "deterministic_archive._apply_open_file_metadata",
                    OSError,
                ),
                (
                    "file-not-implemented",
                    "deterministic_archive._apply_open_file_metadata",
                    NotImplementedError,
                ),
                (
                    "directory-os-error",
                    "deterministic_archive._apply_directory_metadata",
                    OSError,
                ),
                (
                    "directory-not-implemented",
                    "deterministic_archive._apply_directory_metadata",
                    NotImplementedError,
                ),
            )
            for label, helper, error_type in cases:
                with self.subTest(label=label):
                    destination = root / f"destination-{label}"
                    error = error_type("synthetic metadata failure")
                    with mock.patch(helper, side_effect=error):
                        with self.assertRaisesRegex(
                            DeterministicArchiveError, "cannot extract archive"
                        ) as captured:
                            extract_tar_gz(
                                archive,
                                destination,
                                root_name="package",
                                mtime=MTIME,
                            )
                    self.assertIsInstance(captured.exception.__cause__, error_type)
                    self.assertFalse(destination.exists())
                    staging = root / f".{destination.name}.tmp-{os.getpid()}"
                    self.assertFalse(staging.exists())

    def test_tar_rejects_trailing_concatenated_and_wrong_mtime_gzip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            archive = root / "package.tar.gz"
            create_tar_gz(
                self._source(root), archive, root_name="package", mtime=MTIME
            )
            original = archive.read_bytes()
            cases = {
                "trailing": original + b"\0",
                "concatenated": original + original,
                "prefix": b"x" + original,
            }
            for label, value in cases.items():
                with self.subTest(label=label):
                    forged = root / f"{label}.tar.gz"
                    forged.write_bytes(value)
                    with self.assertRaises(DeterministicArchiveError):
                        audit_tar_gz(
                            forged, root_name="package", mtime=MTIME
                        )
            with self.assertRaisesRegex(DeterministicArchiveError, "mtime"):
                audit_tar_gz(
                    archive, root_name="package", mtime=MTIME + 1
                )

    def test_tar_rejects_noncanonical_paths_types_metadata_and_end(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            source = root / "source"
            source.mkdir()
            (source / "a").write_bytes(b"x")
            archive = root / "package.tar.gz"
            create_tar_gz(source, archive, root_name="package", mtime=MTIME)
            original = archive.read_bytes()

            traversal = root / "traversal.tar.gz"
            traversal.write_bytes(_replace_tar_name(original, 0, b".."))
            with self.assertRaises(DeterministicArchiveError):
                audit_tar_gz(traversal, root_name="package", mtime=MTIME)

            payload = bytearray(_gunzip(original))
            # Second header is the one-byte file after the root directory.
            second = 512
            payload[second + 156] = ord("2")
            header = bytearray(payload[second : second + 512])
            _tar_checksum(header)
            payload[second : second + 512] = header
            symlink = root / "symlink.tar.gz"
            symlink.write_bytes(_gzip(bytes(payload)))
            with self.assertRaisesRegex(DeterministicArchiveError, "special"):
                audit_tar_gz(symlink, root_name="package", mtime=MTIME)

            payload = bytearray(_gunzip(original))
            payload[second + 108 : second + 116] = b"0000001\0"
            header = bytearray(payload[second : second + 512])
            _tar_checksum(header)
            payload[second : second + 512] = header
            owner = root / "owner.tar.gz"
            owner.write_bytes(_gzip(bytes(payload)))
            with self.assertRaisesRegex(DeterministicArchiveError, "uid/gid"):
                audit_tar_gz(owner, root_name="package", mtime=MTIME)

            extra_end = root / "extra-end.tar.gz"
            extra_end.write_bytes(_gzip(_gunzip(original) + b"\0" * 512))
            with self.assertRaisesRegex(DeterministicArchiveError, "exactly two"):
                audit_tar_gz(extra_end, root_name="package", mtime=MTIME)

    def test_tar_rejects_duplicate_and_normalized_duplicate_members(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            source = root / "source"
            source.mkdir()
            (source / "a").write_bytes(b"x")
            archive = root / "package.tar.gz"
            create_tar_gz(source, archive, root_name="package", mtime=MTIME)
            payload = _gunzip(archive.read_bytes())
            file_record = payload[512:1536]
            duplicate_payload = payload[:-1024] + file_record + payload[-1024:]
            duplicate = root / "duplicate.tar.gz"
            duplicate.write_bytes(_gzip(duplicate_payload))
            with self.assertRaisesRegex(
                DeterministicArchiveError, "duplicate"
            ):
                audit_tar_gz(duplicate, root_name="package", mtime=MTIME)

    def test_tar_limits_fail_before_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            archive = root / "package.tar.gz"
            create_tar_gz(
                self._source(root), archive, root_name="package", mtime=MTIME
            )
            destination = root / "destination"
            limits = ArchiveLimits(
                maximum_archive_bytes=1024 * 1024,
                maximum_member_count=2,
                maximum_member_bytes=1024,
                maximum_total_bytes=1024,
            )
            with self.assertRaisesRegex(DeterministicArchiveError, "too many"):
                extract_tar_gz(
                    archive,
                    destination,
                    root_name="package",
                    mtime=MTIME,
                    limits=limits,
                )
            self.assertFalse(destination.exists())

    def test_zip_rejects_trailing_prefix_concatenation_and_wrong_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            archive = root / "package.zip"
            create_zip(
                self._source(root), archive, root_name="package", mtime=MTIME
            )
            original = archive.read_bytes()
            cases = {
                "trailing": original + b"\0",
                "prefix": b"x" + original,
                "concatenated": original + original,
            }
            for label, data in cases.items():
                with self.subTest(label=label):
                    forged = root / f"{label}.zip"
                    forged.write_bytes(data)
                    with self.assertRaises(DeterministicArchiveError):
                        audit_zip(forged, root_name="package", mtime=MTIME)
            with self.assertRaises(DeterministicArchiveError):
                audit_zip(archive, root_name="different", mtime=MTIME)

    def test_zip_rejects_duplicate_traversal_symlink_and_extra_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            cases: dict[str, bytes] = {}

            duplicate_buffer = io.BytesIO()
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(duplicate_buffer, "w") as archive:
                    archive.writestr("package/a", b"one")
                    archive.writestr("package/a", b"two")
            cases["duplicate"] = duplicate_buffer.getvalue()

            traversal_buffer = io.BytesIO()
            with zipfile.ZipFile(traversal_buffer, "w") as archive:
                archive.writestr("package/../escape", b"bad")
            cases["traversal"] = traversal_buffer.getvalue()

            symlink_buffer = io.BytesIO()
            with zipfile.ZipFile(symlink_buffer, "w") as archive:
                info = zipfile.ZipInfo("package/link")
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(info, b"target")
            cases["symlink"] = symlink_buffer.getvalue()

            extra_buffer = io.BytesIO()
            with zipfile.ZipFile(extra_buffer, "w") as archive:
                info = zipfile.ZipInfo("package/a")
                info.extra = b"\x01\x00\x00\x00"
                archive.writestr(info, b"bad")
            cases["extra"] = extra_buffer.getvalue()

            for label, data in cases.items():
                with self.subTest(label=label):
                    path = root / f"{label}.zip"
                    path.write_bytes(data)
                    destination = root / f"extract-{label}"
                    with self.assertRaises(DeterministicArchiveError):
                        extract_zip(
                            path,
                            destination,
                            root_name="package",
                            mtime=MTIME,
                        )
                    self.assertFalse(destination.exists())

    def test_zip_rejects_casefold_collision_and_resource_limits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            collision = io.BytesIO()
            with zipfile.ZipFile(collision, "w") as archive:
                archive.writestr("package/A", b"one")
                archive.writestr("package/a", b"two")
            collision_path = root / "collision.zip"
            collision_path.write_bytes(collision.getvalue())
            with self.assertRaises(DeterministicArchiveError):
                audit_zip(collision_path, root_name="package")

            archive = root / "package.zip"
            create_zip(
                self._source(root), archive, root_name="package", mtime=MTIME
            )
            limits = ArchiveLimits(
                maximum_archive_bytes=1024 * 1024,
                maximum_member_count=100,
                maximum_member_bytes=4,
                maximum_total_bytes=1024,
            )
            with self.assertRaisesRegex(DeterministicArchiveError, "per-member"):
                audit_zip(
                    archive, root_name="package", mtime=MTIME, limits=limits
                )

    def test_zip_rejects_noncanonical_local_and_central_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            archive = root / "package.zip"
            create_zip(
                self._source(root), archive, root_name="package", mtime=MTIME
            )
            original = archive.read_bytes()
            eocd_offset = len(original) - struct.calcsize("<4s4H2LH")
            central_offset = struct.unpack_from("<L", original, eocd_offset + 16)[0]

            local_time = bytearray(original)
            stored_time = struct.unpack_from("<H", local_time, 10)[0]
            struct.pack_into("<H", local_time, 10, stored_time ^ 1)

            internal_attributes = bytearray(original)
            struct.pack_into("<H", internal_attributes, central_offset + 36, 1)

            external_attributes = bytearray(original)
            external_value = struct.unpack_from(
                "<L", external_attributes, central_offset + 38
            )[0]
            struct.pack_into(
                "<L", external_attributes, central_offset + 38, external_value | 1
            )

            utf8_flag = bytearray(original)
            struct.pack_into("<H", utf8_flag, 6, 0x800)
            struct.pack_into("<H", utf8_flag, central_offset + 8, 0x800)

            for label, data in {
                "local-time": local_time,
                "internal-attributes": internal_attributes,
                "external-attributes": external_attributes,
                "utf8-flag": utf8_flag,
            }.items():
                with self.subTest(label=label):
                    forged = root / f"{label}.zip"
                    forged.write_bytes(data)
                    with self.assertRaises(DeterministicArchiveError):
                        audit_zip(forged, root_name="package", mtime=MTIME)

    def test_zip_rejects_trailing_bytes_inside_deflate_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            source = root / "source"
            source.mkdir()
            (source / "payload.bin").write_bytes(b"payload" * 20)
            archive = root / "package.zip"
            create_zip(source, archive, root_name="package", mtime=MTIME)
            original = archive.read_bytes()

            with zipfile.ZipFile(io.BytesIO(original), "r") as reader:
                info = reader.getinfo("package/payload.bin")
            local_offset = info.header_offset
            name_length, extra_length = struct.unpack_from(
                "<2H", original, local_offset + 26
            )
            data_start = local_offset + 30 + name_length + extra_length
            data_end = data_start + info.compress_size
            central_offset = struct.unpack_from(
                "<L", original, len(original) - 22 + 16
            )[0]
            member_central = _zip_central_record(
                original, "package/payload.bin"
            )

            junk = b"JUNK"
            forged = bytearray(original[:data_end] + junk + original[data_end:])
            struct.pack_into(
                "<L", forged, local_offset + 18, info.compress_size + len(junk)
            )
            struct.pack_into(
                "<L",
                forged,
                member_central + len(junk) + 20,
                info.compress_size + len(junk),
            )
            new_eocd = len(forged) - 22
            struct.pack_into(
                "<L", forged, new_eocd + 16, central_offset + len(junk)
            )

            with zipfile.ZipFile(io.BytesIO(forged), "r") as permissive_reader:
                self.assertIsNone(permissive_reader.testzip())
            forged_path = root / "trailing-deflate.zip"
            forged_path.write_bytes(forged)
            with self.assertRaisesRegex(
                DeterministicArchiveError, "trailing data"
            ):
                audit_zip(forged_path, root_name="package", mtime=MTIME)


if os.name == "nt":

    class WindowsMetadataHandleTests(unittest.TestCase):
        def _file_information(self, attributes: int):
            def populate(
                _handle: object,
                _information_class: object,
                information_pointer: object,
                _information_size: object,
            ) -> int:
                information = ctypes.cast(
                    information_pointer,
                    ctypes.POINTER(deterministic_archive._FileAttributeTagInfo),
                ).contents
                information.FileAttributes = attributes
                information.ReparseTag = 0
                return 1

            return populate

        def test_metadata_handle_validation_rejects_unsafe_object_kinds(self) -> None:
            path = pathlib.Path(r"C:\release\fixture")
            with mock.patch.object(
                deterministic_archive,
                "_GetFileType",
                return_value=3,
            ):
                with self.assertRaisesRegex(OSError, "not a disk file"):
                    deterministic_archive._windows_validate_metadata_handle(
                        1,
                        path=path,
                        expected_directory=False,
                    )

            cases = (
                (
                    "reparse",
                    deterministic_archive._FILE_ATTRIBUTE_REPARSE_POINT,
                    False,
                    "reparse point",
                ),
                (
                    "directory-instead-of-file",
                    deterministic_archive._FILE_ATTRIBUTE_DIRECTORY,
                    False,
                    "expected regular file",
                ),
                (
                    "file-instead-of-directory",
                    0,
                    True,
                    "expected directory",
                ),
                (
                    "readonly",
                    deterministic_archive._FILE_ATTRIBUTE_READONLY,
                    False,
                    "read-only",
                ),
            )
            for label, attributes, expected_directory, error in cases:
                with self.subTest(label=label):
                    with mock.patch.object(
                        deterministic_archive,
                        "_GetFileType",
                        return_value=deterministic_archive._FILE_TYPE_DISK,
                    ), mock.patch.object(
                        deterministic_archive,
                        "_GetFileInformationByHandleEx",
                        side_effect=self._file_information(attributes),
                    ):
                        with self.assertRaisesRegex(OSError, error):
                            deterministic_archive._windows_validate_metadata_handle(
                                1,
                                path=path,
                                expected_directory=expected_directory,
                            )

        def test_windows_metadata_api_failures_remain_observable(self) -> None:
            path = pathlib.Path(r"C:\release\fixture")

            def fail_with_access_denied(*_arguments: object) -> int:
                ctypes.set_last_error(5)
                return 0

            with mock.patch.object(
                deterministic_archive,
                "_SetFileTime",
                side_effect=fail_with_access_denied,
            ):
                with self.assertRaisesRegex(OSError, "deterministic timestamp"):
                    deterministic_archive._windows_set_mtime(
                        1,
                        path=path,
                        mtime=MTIME,
                    )
            with mock.patch.object(
                deterministic_archive,
                "_CloseHandle",
                side_effect=fail_with_access_denied,
            ):
                with self.assertRaisesRegex(OSError, "close metadata handle"):
                    deterministic_archive._windows_close_metadata_handle(1, path)


if __name__ == "__main__":
    unittest.main()
