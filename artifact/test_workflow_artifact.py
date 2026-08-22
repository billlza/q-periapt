from __future__ import annotations

import contextlib
import dataclasses
import io
import os
import pathlib
import shutil
import stat
import struct
import tempfile
import unittest
import zipfile
import zlib
from unittest import mock

import workflow_artifact


class _UnseekableBytesIO(io.BytesIO):
    def seekable(self) -> bool:
        return False

    def seek(self, *_args: object, **_kwargs: object) -> int:
        raise io.UnsupportedOperation("fixture stream is not seekable")


class WorkflowArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repository = pathlib.Path(self.temporary.name).resolve() / "repository"
        self.repository.mkdir()
        self.root_patch = mock.patch.object(
            workflow_artifact, "REPOSITORY_ROOT", self.repository
        )
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    @property
    def raw(self) -> pathlib.Path:
        return self.repository / "target/workflow-artifact/raw"

    @staticmethod
    def _zip_info(
        name: str,
        *,
        mode: int = stat.S_IFREG | 0o644,
        compression: int = zipfile.ZIP_DEFLATED,
        comment: bytes = b"",
        extra: bytes = b"",
    ) -> zipfile.ZipInfo:
        info = zipfile.ZipInfo(name, date_time=(2026, 8, 13, 0, 0, 0))
        info.create_system = 3
        info.external_attr = mode << 16
        info.compress_type = compression
        info.comment = comment
        info.extra = extra
        return info

    def _write_zip(
        self,
        path: pathlib.Path,
        entries: list[tuple[zipfile.ZipInfo, bytes]],
        *,
        archive_comment: bytes = b"",
        data_descriptors: bool = False,
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if data_descriptors:
            buffer = _UnseekableBytesIO()
            with zipfile.ZipFile(buffer, "w", allowZip64=False) as archive:
                archive.comment = archive_comment
                for info, data in entries:
                    archive.writestr(info, data)
            path.write_bytes(buffer.getvalue())
            return
        with zipfile.ZipFile(path, "w", allowZip64=False) as archive:
            archive.comment = archive_comment
            for info, data in entries:
                archive.writestr(info, data)

    @staticmethod
    def _payload(member: workflow_artifact.MemberSpec) -> bytes:
        return f"fixture bytes for {member.archive_name}\n".encode("ascii")

    def _container_path(
        self,
        profile: workflow_artifact.ProfileSpec,
        container: workflow_artifact.ContainerSpec,
    ) -> pathlib.Path:
        if profile.nested_raw_containers:
            return (
                self.raw
                / container.artifact_name
                / f"{container.artifact_name}.zip"
            )
        return self.raw / f"{container.artifact_name}.zip"

    def _write_profile(
        self,
        profile: workflow_artifact.ProfileSpec,
        *,
        container_entries: dict[
            str, list[tuple[zipfile.ZipInfo, bytes]]
        ]
        | None = None,
        data_descriptors: bool = False,
    ) -> dict[str, bytes]:
        expected_outputs: dict[str, bytes] = {}
        overrides = container_entries or {}
        for container in profile.containers:
            entries = overrides.get(container.artifact_name)
            if entries is None:
                entries = []
                for member in container.members:
                    payload = self._payload(member)
                    entries.append((self._zip_info(member.archive_name), payload))
                    expected_outputs[member.destination_name] = payload
            else:
                destination_by_archive = {
                    member.archive_name: member.destination_name
                    for member in container.members
                }
                for info, payload in entries:
                    destination = destination_by_archive.get(info.filename)
                    if destination is not None:
                        expected_outputs[destination] = payload
            self._write_zip(
                self._container_path(profile, container),
                entries,
                data_descriptors=data_descriptors,
            )
        return expected_outputs

    def _assert_outputs(
        self,
        destination: pathlib.Path,
        expected: dict[str, bytes],
    ) -> None:
        self.assertEqual(
            sorted(path.name for path in destination.iterdir()), sorted(expected)
        )
        for name, data in expected.items():
            output = destination / name
            self.assertEqual(output.read_bytes(), data)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o755)

    def test_android_profile_extracts_one_fixed_raw_wrapper(self) -> None:
        profile = workflow_artifact.ANDROID_AAR_PROFILE
        expected = self._write_profile(profile)

        destination = workflow_artifact.extract_profile(profile.name)

        self.assertEqual(
            destination,
            self.repository
            / "target/qperiapt-android-aar/q-periapt-android-0.1.1",
        )
        self._assert_outputs(destination, expected)

    def test_platform_candidate_extracts_three_fixed_wrappers(self) -> None:
        profile = workflow_artifact.PLATFORM_CANDIDATE_PROFILE
        expected = self._write_profile(profile)

        destination = workflow_artifact.extract_profile(profile.name)

        self.assertEqual(destination, self.repository / "candidate")
        self._assert_outputs(destination, expected)

    def test_data_descriptor_zip_is_crc_checked_and_supported(self) -> None:
        profile = workflow_artifact.ANDROID_AAR_PROFILE
        expected = self._write_profile(profile, data_descriptors=True)
        destination = workflow_artifact.extract_profile(profile.name)
        self._assert_outputs(destination, expected)

    def test_cli_exposes_profiles_but_no_source_or_destination_paths(self) -> None:
        parser = workflow_artifact.build_parser()
        self.assertEqual(parser.parse_args(["android-aar"]).profile, "android-aar")
        self.assertEqual(
            parser.parse_args(["platform-candidate"]).profile,
            "platform-candidate",
        )
        for arguments in (
            ["android-aar", "--source", "elsewhere.zip"],
            ["android-aar", "--destination", "elsewhere"],
            ["unknown"],
        ):
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(
                io.StringIO()
            ), self.assertRaises(SystemExit):
                parser.parse_args(arguments)

    def test_profile_contract_rejects_exact_and_casefold_archive_collisions(
        self,
    ) -> None:
        container = workflow_artifact.ANDROID_AAR_PROFILE.containers[0]
        first = container.members[0]
        collisions = (
            dataclasses.replace(
                first,
                destination_name="collision-exact.bin",
            ),
            dataclasses.replace(
                first,
                archive_name=first.archive_name.swapcase(),
                destination_name="collision-casefold.bin",
            ),
        )
        for collision in collisions:
            with self.subTest(archive_name=collision.archive_name):
                changed_container = dataclasses.replace(
                    container,
                    members=(*container.members, collision),
                )
                changed_profile = dataclasses.replace(
                    workflow_artifact.ANDROID_AAR_PROFILE,
                    containers=(changed_container,),
                )
                with self.assertRaisesRegex(
                    workflow_artifact.WorkflowArtifactError,
                    "archive members collide",
                ):
                    workflow_artifact._validate_profile_contract(changed_profile)

    def test_output_parent_descriptor_walk_rejects_ancestor_symlink_race(
        self,
    ) -> None:
        profile = workflow_artifact.ANDROID_AAR_PROFILE
        self._write_profile(profile)
        outside = self.repository / "outside"
        outside.mkdir()
        real_open = os.open
        raced = False

        def raced_open(
            path: os.PathLike[str] | str,
            flags: int,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal raced
            if os.fspath(path) == "qperiapt-android-aar" and dir_fd is not None:
                self.assertFalse(raced)
                os.rmdir("qperiapt-android-aar", dir_fd=dir_fd)
                os.symlink(
                    outside,
                    "qperiapt-android-aar",
                    dir_fd=dir_fd,
                )
                raced = True
            self.assertEqual(flags & os.O_CREAT, 0)
            if dir_fd is None:
                return real_open(path, flags)
            return real_open(path, flags, dir_fd=dir_fd)

        with mock.patch.object(
            workflow_artifact.os,
            "open",
            side_effect=raced_open,
        ), self.assertRaisesRegex(
            workflow_artifact.WorkflowArtifactError,
            "cannot safely open output parent component",
        ):
            workflow_artifact.extract_profile(profile.name)

        self.assertTrue(raced)
        self.assertEqual(list(outside.iterdir()), [])

    def test_cleanup_refuses_replaced_staging_basename(self) -> None:
        profile = workflow_artifact.ANDROID_AAR_PROFILE
        self._write_profile(profile)
        parent = self.repository / "target/qperiapt-android-aar"
        preserved: dict[str, pathlib.Path] = {}

        def replace_staging_and_fail(
            _path: pathlib.Path,
            _container: workflow_artifact.ContainerSpec,
            _staging_fd: int,
            _staged_files: dict[str, workflow_artifact.StagedFileRecord],
        ) -> None:
            candidates = [
                path
                for path in parent.iterdir()
                if path.name.startswith(
                    ".q-periapt-android-0.1.1.workflow-artifact-"
                )
            ]
            self.assertEqual(len(candidates), 1)
            staging = candidates[0]
            moved = staging.with_name(f"{staging.name}.moved")
            staging.rename(moved)
            staging.mkdir(mode=0o700)
            sentinel = staging / "sentinel"
            sentinel.write_bytes(b"preserve replacement")
            preserved.update(staging=staging, moved=moved, sentinel=sentinel)
            raise workflow_artifact.WorkflowArtifactError(
                "injected extraction failure"
            )

        with mock.patch.object(
            workflow_artifact,
            "_extract_container",
            side_effect=replace_staging_and_fail,
        ), self.assertRaisesRegex(
            workflow_artifact.WorkflowArtifactError,
            "injected extraction failure",
        ) as raised:
            workflow_artifact.extract_profile(profile.name)

        notes = getattr(raised.exception, "__notes__", ())
        self.assertTrue(
            any("staging identity, owner, or mode changed" in note for note in notes)
        )
        self.assertEqual(
            preserved["sentinel"].read_bytes(),
            b"preserve replacement",
        )
        self.assertTrue(preserved["moved"].is_dir())

    def test_publication_rejects_replaced_staging_basename(self) -> None:
        profile = workflow_artifact.ANDROID_AAR_PROFILE
        self._write_profile(profile)
        parent = self.repository / "target/qperiapt-android-aar"
        original_extract = workflow_artifact._extract_container
        preserved: dict[str, pathlib.Path] = {}

        def extract_then_replace_staging(
            path: pathlib.Path,
            container: workflow_artifact.ContainerSpec,
            staging_fd: int,
            staged_files: dict[str, workflow_artifact.StagedFileRecord],
        ) -> None:
            original_extract(
                path,
                container,
                staging_fd,
                staged_files,
            )
            candidates = [
                candidate
                for candidate in parent.iterdir()
                if candidate.name.startswith(
                    ".q-periapt-android-0.1.1.workflow-artifact-"
                )
            ]
            self.assertEqual(len(candidates), 1)
            staging = candidates[0]
            moved = staging.with_name(f"{staging.name}.moved")
            staging.rename(moved)
            staging.mkdir(mode=0o700)
            preserved.update(staging=staging, moved=moved)

        with mock.patch.object(
            workflow_artifact,
            "_extract_container",
            side_effect=extract_then_replace_staging,
        ), self.assertRaisesRegex(
            workflow_artifact.WorkflowArtifactError,
            "staging identity, owner, or mode changed",
        ):
            workflow_artifact.extract_profile(profile.name)

        destination = self.repository.joinpath(*profile.destination.parts)
        self.assertFalse(destination.exists())
        self.assertTrue(preserved["staging"].is_dir())
        self.assertTrue(preserved["moved"].is_dir())

    def test_publication_rejects_extra_staging_leaf(self) -> None:
        profile = workflow_artifact.ANDROID_AAR_PROFILE
        self._write_profile(profile)
        original_extract = workflow_artifact._extract_container

        def extract_then_add_leaf(
            path: pathlib.Path,
            container: workflow_artifact.ContainerSpec,
            staging_fd: int,
            staged_files: dict[str, workflow_artifact.StagedFileRecord],
        ) -> None:
            original_extract(
                path,
                container,
                staging_fd,
                staged_files,
            )
            descriptor = os.open(
                "unexpected.bin",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=staging_fd,
            )
            try:
                os.write(descriptor, b"unexpected")
            finally:
                os.close(descriptor)

        with mock.patch.object(
            workflow_artifact,
            "_extract_container",
            side_effect=extract_then_add_leaf,
        ), self.assertRaisesRegex(
            workflow_artifact.WorkflowArtifactError,
            "unexpected leaf|fixed leaf limit",
        ):
            workflow_artifact.extract_profile(profile.name)

        destination = self.repository.joinpath(*profile.destination.parts)
        self.assertFalse(destination.exists())
        parent = destination.parent
        staging = [
            path
            for path in parent.iterdir()
            if path.name.startswith(f".{destination.name}.workflow-artifact-")
        ]
        self.assertEqual(len(staging), 1)
        self.assertEqual((staging[0] / "unexpected.bin").read_bytes(), b"unexpected")

    def test_raw_shape_rejects_missing_extra_and_wrong_container_layout(self) -> None:
        profile = workflow_artifact.ANDROID_AAR_PROFILE
        cases = ("missing", "extra", "nested")
        for case in cases:
            with self.subTest(case=case):
                shutil_root = self.raw.parent.parent
                if shutil_root.exists():
                    shutil.rmtree(shutil_root)
                if case == "missing":
                    self.raw.mkdir(parents=True)
                elif case == "extra":
                    self._write_profile(profile)
                    (self.raw / "unexpected.zip").write_bytes(b"not used")
                else:
                    wrapper = self.raw / "abi2-android-aar"
                    wrapper.mkdir(parents=True)
                    (wrapper / "abi2-android-aar.zip").write_bytes(b"not used")
                with self.assertRaisesRegex(
                    workflow_artifact.WorkflowArtifactError,
                    "raw artifact files differ",
                ):
                    workflow_artifact.extract_profile(profile.name)

    def test_candidate_raw_shape_requires_same_named_zip_in_each_wrapper(self) -> None:
        profile = workflow_artifact.PLATFORM_CANDIDATE_PROFILE
        self._write_profile(profile)
        container = profile.containers[0]
        expected = self._container_path(profile, container)
        renamed = expected.with_name("payload.zip")
        expected.rename(renamed)
        with self.assertRaisesRegex(
            workflow_artifact.WorkflowArtifactError,
            "must contain only",
        ):
            workflow_artifact.extract_profile(profile.name)

    def test_raw_symlink_is_rejected(self) -> None:
        profile = workflow_artifact.ANDROID_AAR_PROFILE
        outside = self.repository / "outside.zip"
        outside.write_bytes(b"not a zip")
        self.raw.mkdir(parents=True)
        (self.raw / "abi2-android-aar.zip").symlink_to(outside)
        with self.assertRaisesRegex(
            workflow_artifact.WorkflowArtifactError,
            "not a regular file",
        ):
            workflow_artifact.extract_profile(profile.name)

    def _android_entries(self) -> list[tuple[zipfile.ZipInfo, bytes]]:
        container = workflow_artifact.ANDROID_AAR_PROFILE.containers[0]
        return [
            (self._zip_info(member.archive_name), self._payload(member))
            for member in container.members
        ]

    def _run_android_entries(
        self,
        entries: list[tuple[zipfile.ZipInfo, bytes]],
        *,
        archive_comment: bytes = b"",
    ) -> pathlib.Path:
        profile = workflow_artifact.ANDROID_AAR_PROFILE
        container = profile.containers[0]
        path = self._container_path(profile, container)
        self._write_zip(path, entries, archive_comment=archive_comment)
        return path

    @staticmethod
    def _append_to_first_compressed_stream(
        archive_bytes: bytes, trailing: bytes
    ) -> bytes:
        """Extend member zero's declared compressed slice and shift later records."""

        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            infos = archive.infolist()
        first = infos[0]
        local_name_length, local_extra_length = struct.unpack_from(
            "<2H", archive_bytes, first.header_offset + 26
        )
        insertion = (
            first.header_offset
            + workflow_artifact._ZIP_LOCAL.size
            + local_name_length
            + local_extra_length
            + first.compress_size
        )
        old_eocd = len(archive_bytes) - workflow_artifact._ZIP_EOCD.size
        old_central = struct.unpack_from("<L", archive_bytes, old_eocd + 16)[0]
        changed = bytearray(
            archive_bytes[:insertion] + trailing + archive_bytes[insertion:]
        )
        delta = len(trailing)
        struct.pack_into(
            "<L",
            changed,
            first.header_offset + 18,
            first.compress_size + delta,
        )
        new_central = old_central + delta
        cursor = new_central
        for info in infos:
            if info is first:
                struct.pack_into("<L", changed, cursor + 20, info.compress_size + delta)
            elif info.header_offset > first.header_offset:
                struct.pack_into("<L", changed, cursor + 42, info.header_offset + delta)
            name_length, extra_length, comment_length = struct.unpack_from(
                "<3H", changed, cursor + 28
            )
            cursor += (
                workflow_artifact._ZIP_CENTRAL.size
                + name_length
                + extra_length
                + comment_length
            )
        new_eocd = len(changed) - workflow_artifact._ZIP_EOCD.size
        struct.pack_into("<L", changed, new_eocd + 16, new_central)
        return bytes(changed)

    def test_missing_extra_and_too_many_zip_members_are_rejected(self) -> None:
        entries = self._android_entries()
        mutations = (
            ("missing", entries[:-1], "members differ"),
            (
                "extra",
                [*entries, (self._zip_info("unexpected.bin"), b"extra")],
                "entry limit",
            ),
        )
        for name, changed, message in mutations:
            with self.subTest(name=name):
                if self.raw.parent.parent.exists():
                    shutil.rmtree(self.raw.parent.parent)
                self._run_android_entries(changed)
                with self.assertRaisesRegex(
                    workflow_artifact.WorkflowArtifactError, message
                ):
                    workflow_artifact.extract_profile("android-aar")

    def test_duplicate_and_casefold_colliding_zip_members_are_rejected(self) -> None:
        entries = self._android_entries()
        duplicate = [entries[0], entries[1], entries[1]]
        with self.assertWarns(UserWarning):
            self._run_android_entries(duplicate)
        with self.assertRaisesRegex(
            workflow_artifact.WorkflowArtifactError,
            "duplicate or case-insensitive collision",
        ):
            workflow_artifact.extract_profile("android-aar")

        shutil.rmtree(self.raw.parent.parent)
        casefold = [
            entries[0],
            entries[1],
            (self._zip_info("manifest.JSON"), b"collision"),
        ]
        self._run_android_entries(casefold)
        with self.assertRaisesRegex(
            workflow_artifact.WorkflowArtifactError,
            "case-insensitive collision",
        ):
            workflow_artifact.extract_profile("android-aar")

    def test_absolute_traversal_and_backslash_member_paths_are_rejected(self) -> None:
        base = self._android_entries()
        unsafe = ("/SHA256SUMS", "../SHA256SUMS", "dir\\SHA256SUMS")
        for index, name in enumerate(unsafe):
            with self.subTest(name=name):
                if self.raw.parent.parent.exists():
                    shutil.rmtree(self.raw.parent.parent)
                changed = [base[0], base[1], (self._zip_info(name), b"unsafe")]
                self._run_android_entries(changed)
                with self.assertRaisesRegex(
                    workflow_artifact.WorkflowArtifactError,
                    "absolute|traversal|backslash",
                ):
                    workflow_artifact.extract_profile("android-aar")

    def test_symlink_and_special_file_metadata_are_rejected(self) -> None:
        base = self._android_entries()
        for kind, mode in (
            ("symlink", stat.S_IFLNK | 0o777),
            ("fifo", stat.S_IFIFO | 0o600),
        ):
            with self.subTest(kind=kind):
                if self.raw.parent.parent.exists():
                    shutil.rmtree(self.raw.parent.parent)
                changed = list(base)
                changed[0] = (
                    self._zip_info(changed[0][0].filename, mode=mode),
                    changed[0][1],
                )
                self._run_android_entries(changed)
                with self.assertRaisesRegex(
                    workflow_artifact.WorkflowArtifactError,
                    "symlinks, and special files",
                ):
                    workflow_artifact.extract_profile("android-aar")

    def test_encryption_and_unsupported_compression_are_rejected(self) -> None:
        entries = self._android_entries()
        path = self._run_android_entries(entries)
        data = bytearray(path.read_bytes())
        local = data.index(workflow_artifact._ZIP_LOCAL_SIGNATURE)
        central = data.index(workflow_artifact._ZIP_CENTRAL_SIGNATURE)
        local_flags = struct.unpack_from("<H", data, local + 6)[0]
        central_flags = struct.unpack_from("<H", data, central + 8)[0]
        struct.pack_into("<H", data, local + 6, local_flags | 1)
        struct.pack_into("<H", data, central + 8, central_flags | 1)
        path.write_bytes(data)
        with self.assertRaisesRegex(
            workflow_artifact.WorkflowArtifactError, "encrypted"
        ):
            workflow_artifact.extract_profile("android-aar")

        shutil.rmtree(self.raw.parent.parent)
        compressed = list(entries)
        compressed[0] = (
            self._zip_info(
                compressed[0][0].filename,
                compression=zipfile.ZIP_BZIP2,
            ),
            compressed[0][1],
        )
        self._run_android_entries(compressed)
        with self.assertRaisesRegex(
            workflow_artifact.WorkflowArtifactError, "unsupported compression"
        ):
            workflow_artifact.extract_profile("android-aar")

    def test_archive_and_member_comments_and_extras_are_rejected(self) -> None:
        base = self._android_entries()
        cases = (
            (
                "archive-comment",
                base,
                b"comment",
            ),
            (
                "member-comment",
                [
                    (
                        self._zip_info(
                            info.filename,
                            comment=b"comment" if index == 0 else b"",
                        ),
                        data,
                    )
                    for index, (info, data) in enumerate(base)
                ],
                b"",
            ),
            (
                "member-extra",
                [
                    (
                        self._zip_info(
                            info.filename,
                            extra=b"\x01\x00\x00\x00" if index == 0 else b"",
                        ),
                        data,
                    )
                    for index, (info, data) in enumerate(base)
                ],
                b"",
            ),
        )
        for name, entries, archive_comment in cases:
            with self.subTest(name=name):
                if self.raw.parent.parent.exists():
                    shutil.rmtree(self.raw.parent.parent)
                self._run_android_entries(entries, archive_comment=archive_comment)
                with self.assertRaisesRegex(
                    workflow_artifact.WorkflowArtifactError,
                    "comments|extras",
                ):
                    workflow_artifact.extract_profile("android-aar")

    def test_crc_failure_cleans_private_staging_and_publishes_nothing(self) -> None:
        entries = [
            (self._zip_info(info.filename, compression=zipfile.ZIP_STORED), data)
            for info, data in self._android_entries()
        ]
        path = self._run_android_entries(entries)
        data = bytearray(path.read_bytes())
        name_length = struct.unpack_from("<H", data, 26)[0]
        extra_length = struct.unpack_from("<H", data, 28)[0]
        payload_offset = workflow_artifact._ZIP_LOCAL.size + name_length + extra_length
        data[payload_offset] ^= 0x01
        path.write_bytes(data)

        with self.assertRaisesRegex(
            workflow_artifact.WorkflowArtifactError, "CRC|Bad CRC"
        ):
            workflow_artifact.extract_profile("android-aar")

        destination = (
            self.repository
            / "target/qperiapt-android-aar/q-periapt-android-0.1.1"
        )
        self.assertFalse(destination.exists())
        parent = destination.parent
        self.assertEqual(
            [path.name for path in parent.iterdir()] if parent.exists() else [], []
        )

    def test_deflate_stream_trailing_bytes_are_rejected_before_extraction(self) -> None:
        path = self._run_android_entries(self._android_entries())
        path.write_bytes(
            self._append_to_first_compressed_stream(path.read_bytes(), b"JUNK")
        )

        with self.assertRaisesRegex(
            workflow_artifact.WorkflowArtifactError,
            "unconsumed trailing bytes",
        ):
            workflow_artifact.extract_profile("android-aar")

        destination = self.repository.joinpath(
            *workflow_artifact.ANDROID_AAR_PROFILE.destination.parts
        )
        self.assertFalse(destination.exists())

    def test_raw_payload_audit_rejects_truncation_crc_and_oversize(self) -> None:
        payload = b"bounded deflate fixture" * 32
        compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
        compressed = compressor.compress(payload) + compressor.flush()

        def info(*, file_size: int = len(payload), crc: int | None = None) -> zipfile.ZipInfo:
            member = self._zip_info("payload.bin")
            member.compress_size = len(compressed)
            member.file_size = file_size
            member.CRC = zlib.crc32(payload) & 0xFFFFFFFF if crc is None else crc
            return member

        with self.assertRaisesRegex(
            workflow_artifact.WorkflowArtifactError,
            "truncated",
        ):
            truncated = info()
            truncated.compress_size -= 1
            workflow_artifact._validate_compressed_payload(compressed[:-1], truncated)

        with self.assertRaisesRegex(
            workflow_artifact.WorkflowArtifactError,
            "CRC differs",
        ):
            workflow_artifact._validate_compressed_payload(
                compressed,
                info(crc=(zlib.crc32(payload) + 1) & 0xFFFFFFFF),
            )

        with self.assertRaisesRegex(
            workflow_artifact.WorkflowArtifactError,
            "exceeds its declared size",
        ):
            workflow_artifact._validate_compressed_payload(
                compressed,
                info(file_size=len(payload) - 1),
            )

    def test_stored_payload_audit_requires_exact_size_and_crc(self) -> None:
        payload = b"stored fixture"
        info = self._zip_info("payload.bin", compression=zipfile.ZIP_STORED)
        info.compress_size = len(payload)
        info.file_size = len(payload) + 1
        info.CRC = zlib.crc32(payload) & 0xFFFFFFFF
        with self.assertRaisesRegex(
            workflow_artifact.WorkflowArtifactError,
            "stored sizes differ",
        ):
            workflow_artifact._validate_compressed_payload(payload, info)

    def test_archive_member_and_total_bounds_are_enforced(self) -> None:
        profile = workflow_artifact.ANDROID_AAR_PROFILE
        container = profile.containers[0]
        entries = self._android_entries()
        path = self._run_android_entries(entries)

        tiny_archive = dataclasses.replace(
            container, maximum_archive_bytes=path.stat().st_size - 1
        )
        tiny_profile = dataclasses.replace(profile, containers=(tiny_archive,))
        with mock.patch.dict(
            workflow_artifact.PROFILES,
            {"android-aar": tiny_profile},
        ), self.assertRaisesRegex(
            workflow_artifact.WorkflowArtifactError, "exceeds"
        ):
            workflow_artifact.extract_profile("android-aar")

        limited_members = list(container.members)
        limited_members[0] = dataclasses.replace(
            limited_members[0], maximum_bytes=len(entries[0][1]) - 1
        )
        limited_container = dataclasses.replace(
            container, members=tuple(limited_members)
        )
        limited_profile = dataclasses.replace(
            profile, containers=(limited_container,)
        )
        with mock.patch.dict(
            workflow_artifact.PROFILES,
            {"android-aar": limited_profile},
        ), self.assertRaisesRegex(
            workflow_artifact.WorkflowArtifactError, "member exceeds"
        ):
            workflow_artifact.extract_profile("android-aar")

    def test_trailing_bytes_are_rejected(self) -> None:
        path = self._run_android_entries(self._android_entries())
        path.write_bytes(path.read_bytes() + b"trailing")
        with self.assertRaisesRegex(
            workflow_artifact.WorkflowArtifactError,
            "trailing bytes|end record",
        ):
            workflow_artifact.extract_profile("android-aar")

    def test_local_and_central_member_metadata_must_match(self) -> None:
        path = self._run_android_entries(self._android_entries())
        data = bytearray(path.read_bytes())
        modified_time = struct.unpack_from("<H", data, 10)[0]
        struct.pack_into("<H", data, 10, modified_time ^ 1)
        path.write_bytes(data)
        with self.assertRaisesRegex(
            workflow_artifact.WorkflowArtifactError,
            "local and central metadata differ",
        ):
            workflow_artifact.extract_profile("android-aar")

    def test_close_helper_preserves_primary_cleanup_context(self) -> None:
        primary = workflow_artifact.WorkflowArtifactError("primary failure")

        def fail_close() -> object:
            raise OSError("injected close failure")

        workflow_artifact._close_with_primary(
            fail_close,
            label="fixture descriptor",
            primary=primary,
        )
        notes = getattr(primary, "__notes__", ())
        self.assertEqual(
            notes,
            ["closing fixture descriptor also failed: injected close failure"],
        )
        with self.assertRaisesRegex(OSError, "injected close failure"):
            workflow_artifact._close_with_primary(
                fail_close,
                label="fixture descriptor",
                primary=None,
            )

    def test_existing_destination_is_never_replaced(self) -> None:
        profile = workflow_artifact.ANDROID_AAR_PROFILE
        self._write_profile(profile)
        destination = self.repository.joinpath(*profile.destination.parts)
        destination.mkdir(parents=True)
        sentinel = destination / "sentinel"
        sentinel.write_bytes(b"preserve")

        with self.assertRaisesRegex(
            workflow_artifact.WorkflowArtifactError, "already exists"
        ):
            workflow_artifact.extract_profile(profile.name)

        self.assertEqual(sentinel.read_bytes(), b"preserve")
        self.assertEqual([path.name for path in destination.iterdir()], ["sentinel"])
        self.assertFalse(
            any(
                path.name.startswith(f".{destination.name}.workflow-artifact-")
                for path in destination.parent.iterdir()
            )
        )

    def test_cleanup_failure_is_attached_without_masking_primary_error(self) -> None:
        entries = [
            (self._zip_info(info.filename, compression=zipfile.ZIP_STORED), data)
            for info, data in self._android_entries()
        ]
        path = self._run_android_entries(entries)
        data = bytearray(path.read_bytes())
        name_length = struct.unpack_from("<H", data, 26)[0]
        payload_offset = workflow_artifact._ZIP_LOCAL.size + name_length
        data[payload_offset] ^= 0x01
        path.write_bytes(data)

        with mock.patch.object(
            workflow_artifact,
            "_cleanup_staging_directory",
            side_effect=OSError("injected cleanup failure"),
        ), self.assertRaises(workflow_artifact.WorkflowArtifactError) as raised:
            workflow_artifact.extract_profile("android-aar")

        notes = getattr(raised.exception, "__notes__", ())
        self.assertTrue(any("injected cleanup failure" in note for note in notes))
        self.assertRegex(str(raised.exception), "CRC|Bad CRC")


if __name__ == "__main__":
    unittest.main()
