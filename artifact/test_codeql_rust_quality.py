from __future__ import annotations

import dataclasses
import os
import pathlib
import stat
import tempfile
import unittest
from unittest import mock

import codeql_rust_quality
from bounded_process import BoundedProcessError, BoundedResult
from git_provenance import WorktreeInspection


def clean_metrics(source_count: int = 2) -> dict[str, int]:
    metrics = {name: 0 for name in codeql_rust_quality.EXPECTED_METRICS}
    metrics.update(
        {
            "extracted_files": source_count,
            "successfully_extracted_files": source_count,
            "source_macro_calls": 7,
            "source_format_args": 3,
        }
    )
    return metrics


class CodeQLRustQualityTests(unittest.TestCase):
    def _fixed_layout(
        self, root: pathlib.Path
    ) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path, pathlib.Path]:
        binary = root / "codeql"
        binary.write_bytes(b"fixed executable\n")
        binary.chmod(0o500)
        runner_temp = root / "runner-temp"
        runner_temp.mkdir(mode=0o700)
        database = runner_temp / "database" / "rust"
        database.mkdir(parents=True, mode=0o700)
        metadata = database / "codeql-database.yml"
        metadata.write_text("name: rust\n", encoding="utf-8")
        metadata.chmod(0o600)
        return binary, runner_temp, database, metadata

    def test_clean_quality_evidence_passes(self) -> None:
        tracked = frozenset({"crates/a/src/lib.rs", "crates/b/build.rs"})
        codeql_rust_quality.validate_quality(tracked, tracked, clean_metrics())

    def test_path_set_must_match_exactly(self) -> None:
        tracked = frozenset({"crates/a/src/lib.rs", "crates/b/build.rs"})
        with self.assertRaisesRegex(
            codeql_rust_quality.CodeQLRustQualityError,
            "successfully extracted path set differs",
        ):
            codeql_rust_quality.validate_quality(
                tracked,
                frozenset({"crates/a/src/lib.rs", "target/generated.rs"}),
                clean_metrics(),
            )

    def test_every_zero_metric_fails_closed(self) -> None:
        tracked = frozenset({"crates/a/src/lib.rs", "crates/b/build.rs"})
        for name in sorted(codeql_rust_quality.ZERO_METRICS):
            with self.subTest(metric=name):
                metrics = clean_metrics()
                metrics[name] = 1
                with self.assertRaisesRegex(
                    codeql_rust_quality.CodeQLRustQualityError,
                    rf"{name} must be zero",
                ):
                    codeql_rust_quality.validate_quality(tracked, tracked, metrics)

    def test_positive_sentinels_cannot_be_vacuous(self) -> None:
        tracked = frozenset({"crates/a/src/lib.rs", "crates/b/build.rs"})
        for name in ("source_macro_calls", "source_format_args"):
            with self.subTest(metric=name):
                metrics = clean_metrics()
                metrics[name] = 0
                with self.assertRaisesRegex(
                    codeql_rust_quality.CodeQLRustQualityError,
                    rf"{name} sentinel must be nonzero",
                ):
                    codeql_rust_quality.validate_quality(tracked, tracked, metrics)

    def test_internal_consistency_telemetry_is_observed_without_false_failure(self) -> None:
        tracked = frozenset({"crates/a/src/lib.rs", "crates/b/build.rs"})
        metrics = clean_metrics()
        metrics.update(
            {
                "path_resolution_inconsistencies": 3,
                "path_multiple_canonical_paths": 2,
                "path_multiple_resolved_targets": 1,
                "type_inference_inconsistencies": 2,
                "type_ill_formed_mention": 2,
            }
        )
        codeql_rust_quality.validate_quality(tracked, tracked, metrics)

    def test_internal_consistency_category_totals_must_reconcile(self) -> None:
        tracked = frozenset({"crates/a/src/lib.rs", "crates/b/build.rs"})
        for total, category in (
            ("path_resolution_inconsistencies", "path_multiple_canonical_paths"),
            ("type_inference_inconsistencies", "type_ill_formed_mention"),
        ):
            with self.subTest(total=total):
                metrics = clean_metrics()
                metrics[total] = 2
                metrics[category] = 1
                with self.assertRaisesRegex(
                    codeql_rust_quality.CodeQLRustQualityError,
                    "categories do not sum to total",
                ):
                    codeql_rust_quality.validate_quality(tracked, tracked, metrics)

    def test_metric_keys_types_and_duplicates_are_exact(self) -> None:
        rows = [[name, value] for name, value in clean_metrics().items()]
        self.assertEqual(codeql_rust_quality._parse_metrics(rows), clean_metrics())
        with self.assertRaisesRegex(
            codeql_rust_quality.CodeQLRustQualityError, "duplicated extraction_errors"
        ):
            codeql_rust_quality._parse_metrics([*rows, ["extraction_errors", 0]])
        with self.assertRaisesRegex(
            codeql_rust_quality.CodeQLRustQualityError, "malformed row"
        ):
            codeql_rust_quality._parse_metrics(
                [
                    [name, (True if name == "extraction_errors" else value)]
                    for name, value in clean_metrics().items()
                ]
            )

    def test_extracted_paths_reject_non_rust_noncanonical_and_duplicates(self) -> None:
        self.assertEqual(
            codeql_rust_quality._parse_extracted_paths(
                [["crates/a/src/lib.rs"], ["crates/b/build.rs"]]
            ),
            frozenset({"crates/a/src/lib.rs", "crates/b/build.rs"}),
        )
        for rows in (
            [["README.md"]],
            [["../escape.rs"]],
            [["/absolute.rs"]],
            [["a.rs"], ["a.rs"]],
        ):
            with self.subTest(rows=rows), self.assertRaises(
                codeql_rust_quality.CodeQLRustQualityError
            ):
                codeql_rust_quality._parse_extracted_paths(rows)

    def test_fixed_bindings_bind_exact_paths_and_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            binary, runner_temp, database, metadata = self._fixed_layout(root)
            with (
                mock.patch.object(codeql_rust_quality.sys, "platform", "linux"),
                mock.patch.object(codeql_rust_quality, "FIXED_CODEQL_BINARY", binary),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_CODEQL_DATABASE", database
                ),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_RUNNER_TEMP", runner_temp
                ),
            ):
                bindings = (
                    codeql_rust_quality._open_fixed_codeql_bindings()
                )
                try:
                    codeql_rust_quality._revalidate_fixed_codeql_bindings(
                        bindings
                    )
                    held_metadata = os.fstat(
                        bindings.database_metadata_descriptor
                    )
                    self.assertEqual(
                        codeql_rust_quality._identity(held_metadata),
                        bindings.database_metadata_identity,
                    )
                    metadata.unlink()
                    metadata.write_text("replaced: true\n", encoding="utf-8")
                    metadata.chmod(0o600)
                    self.assertEqual(
                        os.fstat(bindings.database_metadata_descriptor).st_nlink,
                        0,
                    )
                    with self.assertRaisesRegex(
                        codeql_rust_quality.CodeQLRustQualityError,
                        "metadata identity changed",
                    ):
                        codeql_rust_quality._revalidate_fixed_codeql_bindings(
                            bindings
                        )
                finally:
                    codeql_rust_quality._close_fixed_codeql_bindings(
                        bindings
                    )

    def test_binding_open_flags_are_fail_closed(self) -> None:
        self.assertEqual(
            codeql_rust_quality._file_open_flags(),
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        self.assertEqual(
            codeql_rust_quality._directory_open_flags(),
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )

    def test_binding_open_calls_use_fixed_flags_and_relative_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            binary, runner_temp, database, _metadata = self._fixed_layout(root)
            real_open = os.open
            calls: list[tuple[os.PathLike[str] | str, int, int | None]] = []

            def record_open(
                path: os.PathLike[str] | str,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                dir_fd = kwargs.get("dir_fd")
                self.assertTrue(dir_fd is None or isinstance(dir_fd, int))
                calls.append((path, flags, dir_fd))
                return real_open(path, flags, *args, **kwargs)

            with (
                mock.patch.object(codeql_rust_quality.sys, "platform", "linux"),
                mock.patch.object(codeql_rust_quality, "FIXED_CODEQL_BINARY", binary),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_CODEQL_DATABASE", database
                ),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_RUNNER_TEMP", runner_temp
                ),
                mock.patch.object(
                    codeql_rust_quality.os, "open", side_effect=record_open
                ),
            ):
                bindings = codeql_rust_quality._open_fixed_codeql_bindings()
                try:
                    self.assertEqual(
                        calls,
                        [
                            (binary, codeql_rust_quality._file_open_flags(), None),
                            (
                                database,
                                codeql_rust_quality._directory_open_flags(),
                                None,
                            ),
                            (
                                "codeql-database.yml",
                                codeql_rust_quality._file_open_flags(),
                                bindings.database_descriptor,
                            ),
                            (
                                runner_temp,
                                codeql_rust_quality._directory_open_flags(),
                                None,
                            ),
                        ],
                    )
                finally:
                    codeql_rust_quality._close_fixed_codeql_bindings(bindings)

    def test_metadata_revalidation_uses_fd_policy_and_initial_identity(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            binary, runner_temp, database, metadata = self._fixed_layout(root)
            other_metadata = root / "other-metadata"
            other_metadata.write_text("name: other\n", encoding="utf-8")
            other_metadata.chmod(0o600)
            with (
                mock.patch.object(codeql_rust_quality.sys, "platform", "linux"),
                mock.patch.object(codeql_rust_quality, "FIXED_CODEQL_BINARY", binary),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_CODEQL_DATABASE", database
                ),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_RUNNER_TEMP", runner_temp
                ),
            ):
                bindings = codeql_rust_quality._open_fixed_codeql_bindings()
                try:
                    changed_initial = dataclasses.replace(
                        bindings,
                        database_metadata_identity=codeql_rust_quality._identity(
                            other_metadata.stat()
                        ),
                    )
                    with self.assertRaisesRegex(
                        codeql_rust_quality.CodeQLRustQualityError,
                        "metadata identity changed",
                    ):
                        codeql_rust_quality._revalidate_fixed_codeql_bindings(
                            changed_initial
                        )

                    real_fstat = os.fstat

                    def replace_metadata_fstat(descriptor: int) -> os.stat_result:
                        if descriptor == bindings.database_metadata_descriptor:
                            return other_metadata.stat()
                        return real_fstat(descriptor)

                    with mock.patch.object(
                        codeql_rust_quality.os,
                        "fstat",
                        side_effect=replace_metadata_fstat,
                    ), self.assertRaisesRegex(
                        codeql_rust_quality.CodeQLRustQualityError,
                        "metadata identity changed",
                    ):
                        codeql_rust_quality._revalidate_fixed_codeql_bindings(
                            bindings
                        )

                    metadata.chmod(0o620)
                    with self.assertRaisesRegex(
                        codeql_rust_quality.CodeQLRustQualityError,
                        "database metadata must be",
                    ):
                        codeql_rust_quality._revalidate_fixed_codeql_bindings(
                            bindings
                        )
                finally:
                    codeql_rust_quality._close_fixed_codeql_bindings(bindings)

    def test_metadata_open_rejects_path_fd_identity_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            binary, runner_temp, database, _metadata = self._fixed_layout(root)
            other_metadata = root / "other-metadata"
            other_metadata.write_text("name: other\n", encoding="utf-8")
            other_metadata.chmod(0o600)
            real_stat = os.stat

            def replace_metadata_path_stat(
                path: os.PathLike[str] | str,
                *args: object,
                **kwargs: object,
            ) -> os.stat_result:
                if (
                    os.fspath(path) == "codeql-database.yml"
                    and kwargs.get("dir_fd") is not None
                ):
                    return other_metadata.stat()
                return real_stat(path, *args, **kwargs)

            with (
                mock.patch.object(codeql_rust_quality.sys, "platform", "linux"),
                mock.patch.object(codeql_rust_quality, "FIXED_CODEQL_BINARY", binary),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_CODEQL_DATABASE", database
                ),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_RUNNER_TEMP", runner_temp
                ),
                mock.patch.object(
                    codeql_rust_quality.os,
                    "stat",
                    side_effect=replace_metadata_path_stat,
                ),
                self.assertRaisesRegex(
                    codeql_rust_quality.CodeQLRustQualityError,
                    "metadata changed while it was being opened",
                ),
            ):
                codeql_rust_quality._open_fixed_codeql_bindings()

    def test_fixed_bindings_reject_cross_account_write_and_unsafe_types(
        self,
    ) -> None:
        for case in (
            "binary-group-writable",
            "binary-not-executable",
            "binary-not-regular",
            "binary-symlink",
            "database-group-writable",
            "database-not-directory",
            "metadata-group-writable",
            "metadata-hardlink",
            "metadata-symlink",
            "metadata-not-regular",
            "temporary-parent-group-writable",
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary).resolve()
                binary, runner_temp, database, metadata = self._fixed_layout(root)
                if case == "binary-group-writable":
                    binary.chmod(0o520)
                elif case == "binary-not-executable":
                    binary.chmod(0o400)
                elif case == "binary-not-regular":
                    binary.unlink()
                    binary.mkdir(mode=0o500)
                elif case == "binary-symlink":
                    target = root / "real-codeql"
                    binary.rename(target)
                    binary.symlink_to(target)
                elif case == "database-group-writable":
                    database.chmod(0o720)
                elif case == "database-not-directory":
                    metadata.unlink()
                    database.rmdir()
                    database.write_bytes(b"not a directory\n")
                elif case == "metadata-group-writable":
                    metadata.chmod(0o620)
                elif case == "metadata-hardlink":
                    os.link(metadata, root / "second-database-metadata-link")
                elif case == "metadata-symlink":
                    target = database / "real-codeql-database.yml"
                    metadata.rename(target)
                    metadata.symlink_to(target.name)
                elif case == "metadata-not-regular":
                    metadata.unlink()
                    metadata.mkdir(mode=0o700)
                else:
                    runner_temp.chmod(0o720)
                with (
                    mock.patch.object(codeql_rust_quality.sys, "platform", "linux"),
                    mock.patch.object(
                        codeql_rust_quality, "FIXED_CODEQL_BINARY", binary
                    ),
                    mock.patch.object(
                        codeql_rust_quality, "FIXED_CODEQL_DATABASE", database
                    ),
                    mock.patch.object(
                        codeql_rust_quality, "FIXED_RUNNER_TEMP", runner_temp
                    ),
                    self.assertRaises(codeql_rust_quality.CodeQLRustQualityError),
                ):
                    codeql_rust_quality._open_fixed_codeql_bindings()

    def test_fixed_bindings_accept_multiply_linked_fixed_binary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            binary, runner_temp, database, _metadata = self._fixed_layout(root)
            os.link(binary, root / "second-codeql-link")
            with (
                mock.patch.object(codeql_rust_quality.sys, "platform", "linux"),
                mock.patch.object(codeql_rust_quality, "FIXED_CODEQL_BINARY", binary),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_CODEQL_DATABASE", database
                ),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_RUNNER_TEMP", runner_temp
                ),
            ):
                bindings = codeql_rust_quality._open_fixed_codeql_bindings()
                try:
                    self.assertEqual(os.fstat(bindings.codeql_descriptor).st_nlink, 2)
                    codeql_rust_quality._revalidate_fixed_codeql_bindings(bindings)
                finally:
                    codeql_rust_quality._close_fixed_codeql_bindings(bindings)

        with tempfile.TemporaryDirectory() as temporary:
            not_directory = pathlib.Path(temporary) / "regular"
            not_directory.write_bytes(b"not a directory\n")
            with self.assertRaisesRegex(
                codeql_rust_quality.CodeQLRustQualityError,
                "must be a current-user-owned directory",
            ):
                codeql_rust_quality._require_owned_directory_metadata(
                    not_directory.stat(), "fixed CodeQL temporary parent"
                )

    def test_fixed_bindings_reject_non_linux_and_database_outside_parent(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            binary, runner_temp, database, _metadata = self._fixed_layout(root)
            with (
                mock.patch.object(codeql_rust_quality.sys, "platform", "darwin"),
                mock.patch.object(codeql_rust_quality, "FIXED_CODEQL_BINARY", binary),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_CODEQL_DATABASE", database
                ),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_RUNNER_TEMP", runner_temp
                ),
                self.assertRaisesRegex(
                    codeql_rust_quality.CodeQLRustQualityError,
                    "require the Linux analysis lane",
                ),
            ):
                codeql_rust_quality._open_fixed_codeql_bindings()

            with (
                mock.patch.object(codeql_rust_quality.sys, "platform", "linux"),
                mock.patch.object(codeql_rust_quality, "FIXED_CODEQL_BINARY", binary),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_CODEQL_DATABASE", root
                ),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_RUNNER_TEMP", runner_temp
                ),
                self.assertRaisesRegex(
                    codeql_rust_quality.CodeQLRustQualityError,
                    "must be under the fixed temporary parent",
                ),
            ):
                codeql_rust_quality._open_fixed_codeql_bindings()

    def test_fixed_binding_owner_policy_is_exact(self) -> None:
        regular = os.stat(__file__)
        executable = os.stat_result(
            (
                stat.S_IFREG | 0o500,
                regular.st_ino,
                regular.st_dev,
                1,
                os.geteuid(),
                regular.st_gid,
                regular.st_size,
                regular.st_atime,
                regular.st_mtime,
                regular.st_ctime,
            )
        )
        foreign = os.stat_result(
            (*regular[:4], os.geteuid() + 1000, *regular[5:])
        )
        foreign_executable = os.stat_result(
            (*executable[:4], foreign.st_uid, *executable[5:])
        )
        codeql_rust_quality._require_codeql_metadata(executable)
        codeql_rust_quality._require_codeql_metadata(foreign_executable)
        with self.assertRaises(codeql_rust_quality.CodeQLRustQualityError):
            codeql_rust_quality._require_database_metadata(foreign)
        foreign_directory = os.stat_result(
            (
                stat.S_IFDIR | 0o700,
                foreign.st_ino,
                foreign.st_dev,
                1,
                foreign.st_uid,
                foreign.st_gid,
                0,
                foreign.st_atime,
                foreign.st_mtime,
                foreign.st_ctime,
            )
        )
        with self.assertRaises(codeql_rust_quality.CodeQLRustQualityError):
            codeql_rust_quality._require_owned_directory_metadata(
                foreign_directory, "foreign directory"
            )

    def test_query_revalidation_detects_binary_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            binary, runner_temp, database, _metadata = self._fixed_layout(root)
            with (
                mock.patch.object(codeql_rust_quality.sys, "platform", "linux"),
                mock.patch.object(codeql_rust_quality, "FIXED_CODEQL_BINARY", binary),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_CODEQL_DATABASE", database
                ),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_RUNNER_TEMP", runner_temp
                ),
            ):
                bindings = (
                    codeql_rust_quality._open_fixed_codeql_bindings()
                )
                try:
                    def replace_binary(
                        _argv: list[str], **_kwargs: object
                    ) -> BoundedResult:
                        binary.unlink()
                        binary.write_bytes(b"replacement\n")
                        binary.chmod(0o500)
                        return BoundedResult(0, b"")

                    with mock.patch.object(
                        codeql_rust_quality,
                        "capture_stdout",
                        side_effect=replace_binary,
                    ), self.assertRaisesRegex(
                        codeql_rust_quality.CodeQLRustQualityError,
                        "fixed CodeQL binary",
                    ):
                        codeql_rust_quality._run_query(
                            bindings,
                            pathlib.Path("/query.ql"),
                            pathlib.Path("/result.bqrs"),
                        )
                finally:
                    codeql_rust_quality._close_fixed_codeql_bindings(
                        bindings
                    )

    def test_query_revalidation_detects_database_metadata_and_parent_drift(
        self,
    ) -> None:
        for case in (
            "database-mode",
            "metadata-mode",
            "metadata-replacement",
            "parent-mode",
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary).resolve()
                binary, runner_temp, database, metadata = self._fixed_layout(root)
                with (
                    mock.patch.object(codeql_rust_quality.sys, "platform", "linux"),
                    mock.patch.object(
                        codeql_rust_quality, "FIXED_CODEQL_BINARY", binary
                    ),
                    mock.patch.object(
                        codeql_rust_quality, "FIXED_CODEQL_DATABASE", database
                    ),
                    mock.patch.object(
                        codeql_rust_quality, "FIXED_RUNNER_TEMP", runner_temp
                    ),
                ):
                    bindings = codeql_rust_quality._open_fixed_codeql_bindings()
                    try:
                        def mutate_binding(
                            _argv: list[str], **_kwargs: object
                        ) -> BoundedResult:
                            if case == "database-mode":
                                database.chmod(0o720)
                            elif case == "metadata-mode":
                                metadata.chmod(0o620)
                            elif case == "metadata-replacement":
                                metadata.unlink()
                                metadata.write_text(
                                    "replacement: true\n", encoding="utf-8"
                                )
                                metadata.chmod(0o600)
                            else:
                                runner_temp.chmod(0o720)
                            return BoundedResult(0, b"")

                        with mock.patch.object(
                            codeql_rust_quality,
                            "capture_stdout",
                            side_effect=mutate_binding,
                        ), self.assertRaises(codeql_rust_quality.CodeQLRustQualityError):
                            codeql_rust_quality._run_query(
                                bindings,
                                pathlib.Path("/query.ql"),
                                pathlib.Path("/result.bqrs"),
                            )
                    finally:
                        codeql_rust_quality._close_fixed_codeql_bindings(bindings)

    def test_open_failure_closes_earlier_fixed_binding_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            binary, runner_temp, database, _metadata = self._fixed_layout(root)
            real_open = os.open
            opened_binary: list[int] = []

            def fail_database_open(
                path: os.PathLike[str] | str,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                if pathlib.Path(path) == database:
                    raise OSError("synthetic database open failure")
                descriptor = real_open(path, flags, *args, **kwargs)
                if pathlib.Path(path) == binary:
                    opened_binary.append(descriptor)
                return descriptor

            with (
                mock.patch.object(codeql_rust_quality.sys, "platform", "linux"),
                mock.patch.object(codeql_rust_quality, "FIXED_CODEQL_BINARY", binary),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_CODEQL_DATABASE", database
                ),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_RUNNER_TEMP", runner_temp
                ),
                mock.patch.object(
                    codeql_rust_quality.os,
                    "open",
                    side_effect=fail_database_open,
                ),
                self.assertRaisesRegex(
                    codeql_rust_quality.CodeQLRustQualityError,
                    "cannot open fixed Rust CodeQL path binding",
                ),
            ):
                codeql_rust_quality._open_fixed_codeql_bindings()
            self.assertEqual(len(opened_binary), 1)
            with self.assertRaises(OSError):
                os.fstat(opened_binary[0])

    def test_open_failure_after_metadata_closes_every_open_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            binary, runner_temp, database, _metadata = self._fixed_layout(root)
            real_open = os.open
            opened: list[int] = []

            def fail_runner_temp_open(
                path: os.PathLike[str] | str,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                if pathlib.Path(path) == runner_temp:
                    raise OSError("synthetic temporary-parent open failure")
                descriptor = real_open(path, flags, *args, **kwargs)
                opened.append(descriptor)
                return descriptor

            with (
                mock.patch.object(codeql_rust_quality.sys, "platform", "linux"),
                mock.patch.object(codeql_rust_quality, "FIXED_CODEQL_BINARY", binary),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_CODEQL_DATABASE", database
                ),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_RUNNER_TEMP", runner_temp
                ),
                mock.patch.object(
                    codeql_rust_quality.os,
                    "open",
                    side_effect=fail_runner_temp_open,
                ),
                self.assertRaisesRegex(
                    codeql_rust_quality.CodeQLRustQualityError,
                    "cannot open fixed Rust CodeQL path binding",
                ),
            ):
                codeql_rust_quality._open_fixed_codeql_bindings()
            self.assertEqual(len(opened), 3)
            for descriptor in opened:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def test_open_failure_reports_secondary_close_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            binary, runner_temp, database, _metadata = self._fixed_layout(root)
            real_open = os.open
            real_close = os.close
            binary_descriptor = -1

            def fail_database_open(
                path: os.PathLike[str] | str,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                nonlocal binary_descriptor
                if pathlib.Path(path) == database:
                    raise OSError("PRIMARY_OPEN_FAILURE")
                descriptor = real_open(path, flags, *args, **kwargs)
                if pathlib.Path(path) == binary:
                    binary_descriptor = descriptor
                return descriptor

            def fail_binary_close(descriptor: int) -> None:
                if descriptor == binary_descriptor:
                    real_close(descriptor)
                    raise OSError("SECONDARY_CLOSE_FAILURE")
                real_close(descriptor)

            with (
                mock.patch.object(codeql_rust_quality.sys, "platform", "linux"),
                mock.patch.object(codeql_rust_quality, "FIXED_CODEQL_BINARY", binary),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_CODEQL_DATABASE", database
                ),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_RUNNER_TEMP", runner_temp
                ),
                mock.patch.object(
                    codeql_rust_quality.os,
                    "open",
                    side_effect=fail_database_open,
                ),
                mock.patch.object(
                    codeql_rust_quality.os,
                    "close",
                    side_effect=fail_binary_close,
                ),
                self.assertRaisesRegex(
                    codeql_rust_quality.CodeQLRustQualityError,
                    "PRIMARY_OPEN_FAILURE.*SECONDARY_CLOSE_FAILURE",
                ),
            ):
                codeql_rust_quality._open_fixed_codeql_bindings()

    def test_open_domain_failure_reports_secondary_close_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            binary, runner_temp, database, _metadata = self._fixed_layout(root)
            binary.chmod(0o520)
            real_close = os.close
            binary_descriptor = -1
            real_open = os.open

            def record_binary_open(
                path: os.PathLike[str] | str,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                nonlocal binary_descriptor
                descriptor = real_open(path, flags, *args, **kwargs)
                if pathlib.Path(path) == binary:
                    binary_descriptor = descriptor
                return descriptor

            def fail_binary_close(descriptor: int) -> None:
                real_close(descriptor)
                if descriptor == binary_descriptor:
                    raise OSError("SECONDARY_CLOSE_FAILURE")

            with (
                mock.patch.object(codeql_rust_quality.sys, "platform", "linux"),
                mock.patch.object(codeql_rust_quality, "FIXED_CODEQL_BINARY", binary),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_CODEQL_DATABASE", database
                ),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_RUNNER_TEMP", runner_temp
                ),
                mock.patch.object(
                    codeql_rust_quality.os, "open", side_effect=record_binary_open
                ),
                mock.patch.object(
                    codeql_rust_quality.os,
                    "close",
                    side_effect=fail_binary_close,
                ),
                self.assertRaisesRegex(
                    codeql_rust_quality.CodeQLRustQualityError,
                    "group-or-other-writable.*SECONDARY_CLOSE_FAILURE",
                ),
            ):
                codeql_rust_quality._open_fixed_codeql_bindings()

    def test_open_cleanup_preserves_control_exception(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            binary, runner_temp, database, _metadata = self._fixed_layout(root)
            real_open = os.open
            real_close = os.close
            binary_descriptor = -1
            interrupt = KeyboardInterrupt("CLEANUP_INTERRUPT")

            def fail_database_open(
                path: os.PathLike[str] | str,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                nonlocal binary_descriptor
                if pathlib.Path(path) == database:
                    raise OSError("PRIMARY_OPEN_FAILURE")
                descriptor = real_open(path, flags, *args, **kwargs)
                if pathlib.Path(path) == binary:
                    binary_descriptor = descriptor
                return descriptor

            def interrupt_binary_close(descriptor: int) -> None:
                real_close(descriptor)
                if descriptor == binary_descriptor:
                    raise interrupt

            with (
                mock.patch.object(codeql_rust_quality.sys, "platform", "linux"),
                mock.patch.object(codeql_rust_quality, "FIXED_CODEQL_BINARY", binary),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_CODEQL_DATABASE", database
                ),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_RUNNER_TEMP", runner_temp
                ),
                mock.patch.object(
                    codeql_rust_quality.os, "open", side_effect=fail_database_open
                ),
                mock.patch.object(
                    codeql_rust_quality.os,
                    "close",
                    side_effect=interrupt_binary_close,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                codeql_rust_quality._open_fixed_codeql_bindings()
            self.assertIs(raised.exception, interrupt)
            self.assertIn(
                "PRIMARY_OPEN_FAILURE",
                " ".join(getattr(interrupt, "__notes__", ())),
            )
            with self.assertRaises(OSError):
                os.fstat(binary_descriptor)

    def test_open_primary_control_exception_survives_cleanup_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            binary, runner_temp, database, _metadata = self._fixed_layout(root)
            real_open = os.open
            real_close = os.close
            binary_descriptor = -1
            interrupt = KeyboardInterrupt("PRIMARY_INTERRUPT")

            def interrupt_database_open(
                path: os.PathLike[str] | str,
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                nonlocal binary_descriptor
                if pathlib.Path(path) == database:
                    raise interrupt
                descriptor = real_open(path, flags, *args, **kwargs)
                if pathlib.Path(path) == binary:
                    binary_descriptor = descriptor
                return descriptor

            def fail_binary_close(descriptor: int) -> None:
                real_close(descriptor)
                if descriptor == binary_descriptor:
                    raise OSError("SECONDARY_CLOSE_FAILURE")

            with (
                mock.patch.object(codeql_rust_quality.sys, "platform", "linux"),
                mock.patch.object(codeql_rust_quality, "FIXED_CODEQL_BINARY", binary),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_CODEQL_DATABASE", database
                ),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_RUNNER_TEMP", runner_temp
                ),
                mock.patch.object(
                    codeql_rust_quality.os,
                    "open",
                    side_effect=interrupt_database_open,
                ),
                mock.patch.object(
                    codeql_rust_quality.os,
                    "close",
                    side_effect=fail_binary_close,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                codeql_rust_quality._open_fixed_codeql_bindings()
            self.assertIs(raised.exception, interrupt)
            self.assertIn(
                "SECONDARY_CLOSE_FAILURE",
                " ".join(getattr(interrupt, "__notes__", ())),
            )
            with self.assertRaises(OSError):
                os.fstat(binary_descriptor)

    def test_close_bindings_attempts_every_descriptor_and_aggregates(self) -> None:
        bindings = mock.Mock(
            database_metadata_descriptor=11,
            database_descriptor=12,
            runner_temp_descriptor=13,
            codeql_descriptor=14,
        )
        closed: list[int] = []

        def fail_close(descriptor: int) -> None:
            closed.append(descriptor)
            raise OSError(f"synthetic close {descriptor}")

        with mock.patch.object(
            codeql_rust_quality.os, "close", side_effect=fail_close
        ), self.assertRaisesRegex(
            codeql_rust_quality.CodeQLRustQualityError,
            "database-metadata.*database.*temporary-parent.*binary",
        ):
            codeql_rust_quality._close_fixed_codeql_bindings(bindings)
        self.assertEqual(closed, [11, 12, 13, 14])

    def test_close_bindings_preserves_control_exception_and_continues(self) -> None:
        bindings = mock.Mock(
            database_metadata_descriptor=21,
            database_descriptor=22,
            runner_temp_descriptor=23,
            codeql_descriptor=24,
        )
        closed: list[int] = []
        interrupt = KeyboardInterrupt("PRIMARY_INTERRUPT")

        def fail_close(descriptor: int) -> None:
            closed.append(descriptor)
            if descriptor == 21:
                raise interrupt
            if descriptor == 22:
                raise OSError("SECONDARY_CLOSE_FAILURE")

        with mock.patch.object(
            codeql_rust_quality.os, "close", side_effect=fail_close
        ), self.assertRaises(KeyboardInterrupt) as raised:
            codeql_rust_quality._close_fixed_codeql_bindings(bindings)
        self.assertIs(raised.exception, interrupt)
        self.assertEqual(closed, [21, 22, 23, 24])
        self.assertIn(
            "SECONDARY_CLOSE_FAILURE",
            " ".join(getattr(interrupt, "__notes__", ())),
        )

    def test_cleanup_merge_preserves_control_exception(self) -> None:
        interrupt = KeyboardInterrupt("PRIMARY_INTERRUPT")
        codeql_rust_quality._merge_cleanup_failure(
            interrupt, "SECONDARY_CLEANUP_FAILURE"
        )
        self.assertIn(
            "SECONDARY_CLEANUP_FAILURE",
            " ".join(getattr(interrupt, "__notes__", ())),
        )

    def test_database_identity_replacement_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            binary, runner_temp, database, metadata = self._fixed_layout(root)
            with (
                mock.patch.object(codeql_rust_quality.sys, "platform", "linux"),
                mock.patch.object(codeql_rust_quality, "FIXED_CODEQL_BINARY", binary),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_CODEQL_DATABASE", database
                ),
                mock.patch.object(
                    codeql_rust_quality, "FIXED_RUNNER_TEMP", runner_temp
                ),
            ):
                bindings = codeql_rust_quality._open_fixed_codeql_bindings()
                try:
                    metadata.unlink()
                    database.rmdir()
                    database.mkdir(mode=0o700)
                    replacement_metadata = database / "codeql-database.yml"
                    replacement_metadata.write_text(
                        "replacement: true\n", encoding="utf-8"
                    )
                    replacement_metadata.chmod(0o600)
                    with self.assertRaisesRegex(
                        codeql_rust_quality.CodeQLRustQualityError,
                        "database identity changed",
                    ):
                        codeql_rust_quality._revalidate_fixed_codeql_bindings(
                            bindings
                        )
                finally:
                    codeql_rust_quality._close_fixed_codeql_bindings(bindings)

    def test_bqrs_decode_requires_strict_json_and_empty_stderr(self) -> None:
        bindings = mock.Mock(codeql=pathlib.Path("/codeql"))
        bqrs = pathlib.Path("/result.bqrs")
        valid = b'{"#select":{"tuples":[]}}'
        for stdout in (
            b'{"#select":{"tuples":[],"tuples":[]}}',
            b'{"#select":{"tuples":[[NaN]]}}',
            b'{"#select":{"tuples":[["\xff"]]}}',
        ):
            with self.subTest(stdout=stdout), mock.patch.object(
                codeql_rust_quality,
                "capture_stdout",
                return_value=BoundedResult(0, stdout),
            ), self.assertRaisesRegex(
                codeql_rust_quality.CodeQLRustQualityError,
                "not strict UTF-8 JSON",
            ), mock.patch.object(
                codeql_rust_quality,
                "_revalidate_fixed_codeql_bindings",
            ):
                codeql_rust_quality._decode_query(bindings, bqrs)

        with mock.patch.object(
            codeql_rust_quality,
            "capture_stdout",
            return_value=BoundedResult(
                0, b"warning: synthetic decoder diagnostic\n" + valid
            ),
        ), self.assertRaisesRegex(
            codeql_rust_quality.CodeQLRustQualityError,
            "not strict UTF-8 JSON",
        ), mock.patch.object(
            codeql_rust_quality,
            "_revalidate_fixed_codeql_bindings",
        ):
            codeql_rust_quality._decode_query(bindings, bqrs)

    def test_decode_revalidates_fixed_bindings_before_and_after(self) -> None:
        bindings = mock.Mock(codeql=pathlib.Path("/codeql"))
        valid = b'{"#select":{"tuples":[]}}'
        with mock.patch.object(
            codeql_rust_quality,
            "capture_stdout",
            return_value=BoundedResult(0, valid),
        ), mock.patch.object(
            codeql_rust_quality,
            "_revalidate_fixed_codeql_bindings",
        ) as revalidate:
            self.assertEqual(
                codeql_rust_quality._decode_query(
                    bindings, pathlib.Path("/result.bqrs")
                ),
                [],
            )
        self.assertEqual(revalidate.call_count, 2)

    def test_codeql_process_boundaries_fail_closed(self) -> None:
        bindings = mock.Mock(
            codeql=pathlib.Path("/codeql"),
            database=pathlib.Path("/database"),
        )
        query = pathlib.Path("/query.ql")
        output = pathlib.Path("/result.bqrs")
        for kind in ("timeout", "output_limit"):
            with self.subTest(kind=kind), mock.patch.object(
                codeql_rust_quality,
                "capture_stdout",
                side_effect=BoundedProcessError(kind, f"synthetic {kind}"),
            ), self.assertRaisesRegex(
                codeql_rust_quality.CodeQLRustQualityError,
                rf"failed at {kind} boundary",
            ), mock.patch.object(
                codeql_rust_quality,
                "_revalidate_fixed_codeql_bindings",
            ):
                codeql_rust_quality._run_query(bindings, query, output)

        with mock.patch.object(
            codeql_rust_quality,
            "capture_stdout",
            return_value=BoundedResult(7, b"fatal query diagnostic\n"),
        ), mock.patch.object(
            codeql_rust_quality.sys.stdout, "write"
        ) as write, self.assertRaisesRegex(
            codeql_rust_quality.CodeQLRustQualityError,
            "exited with status 7",
        ), mock.patch.object(
            codeql_rust_quality,
            "_revalidate_fixed_codeql_bindings",
        ):
            codeql_rust_quality._run_query(bindings, query, output)
        write.assert_called_once_with("fatal query diagnostic\n")

        for result, message in (
            (BoundedResult(9, b"fatal decoder diagnostic\n"), "status 9"),
            (
                BoundedProcessError("timeout", "synthetic timeout"),
                "timeout boundary",
            ),
            (
                BoundedProcessError("output_limit", "synthetic output limit"),
                "output_limit boundary",
            ),
        ):
            with self.subTest(result=result), mock.patch.object(
                codeql_rust_quality,
                "capture_stdout",
                side_effect=(result if isinstance(result, Exception) else None),
                return_value=(None if isinstance(result, Exception) else result),
            ), self.assertRaisesRegex(
                codeql_rust_quality.CodeQLRustQualityError,
                message,
            ), mock.patch.object(
                codeql_rust_quality,
                "_revalidate_fixed_codeql_bindings",
            ):
                codeql_rust_quality._decode_query(bindings, output)

    def test_codeql_process_limits_are_fixed(self) -> None:
        bindings = mock.Mock(
            codeql=pathlib.Path("/codeql"),
            database=pathlib.Path("/database"),
        )
        query = pathlib.Path("/query.ql")
        output = pathlib.Path("/result.bqrs")
        with mock.patch.object(
            codeql_rust_quality,
            "capture_stdout",
            return_value=BoundedResult(0, b"query progress\n"),
        ) as capture, mock.patch.object(
            codeql_rust_quality.sys.stdout, "write"
        ), mock.patch.object(
            codeql_rust_quality,
            "_revalidate_fixed_codeql_bindings",
        ):
            codeql_rust_quality._run_query(bindings, query, output)
        self.assertEqual(
            capture.call_args.kwargs,
            {
                "timeout_seconds": 300,
                "maximum_bytes": 4 * 1024 * 1024,
                "stderr": codeql_rust_quality.subprocess.STDOUT,
            },
        )
        self.assertEqual(
            capture.call_args.args[0],
            [
                "/codeql",
                "query",
                "run",
                "--warnings=error",
                "--database=/database",
                "--output=/result.bqrs",
                "/query.ql",
            ],
        )

        valid = b'{"#select":{"tuples":[]}}'
        with mock.patch.object(
            codeql_rust_quality,
            "capture_stdout",
            return_value=BoundedResult(0, valid),
        ) as capture, mock.patch.object(
            codeql_rust_quality,
            "_revalidate_fixed_codeql_bindings",
        ):
            self.assertEqual(
                codeql_rust_quality._decode_query(bindings, output), []
            )
        self.assertEqual(
            capture.call_args.kwargs,
            {
                "timeout_seconds": 300,
                "maximum_bytes": 16 * 1024 * 1024,
                "stderr": codeql_rust_quality.subprocess.STDOUT,
            },
        )
        self.assertEqual(
            capture.call_args.args[0],
            [
                "/codeql",
                "bqrs",
                "decode",
                "--format=json",
                "/result.bqrs",
            ],
        )

    def test_tracked_inventory_is_nonempty_and_nul_terminated(self) -> None:
        tracked = codeql_rust_quality.tracked_rust_paths()
        self.assertIn(
            "crates/q-periapt-backends/examples/binding_dk_format_witness.rs",
            tracked,
        )
        self.assertEqual(
            len(tracked), codeql_rust_quality.EXPECTED_TRACKED_RUST_SOURCE_COUNT
        )
        with self.assertRaisesRegex(
            codeql_rust_quality.CodeQLRustQualityError, "not NUL terminated"
        ):
            codeql_rust_quality._decode_nul_paths(b"a.rs")

    def test_unresolved_macro_details_are_strictly_typed_and_canonical(self) -> None:
        rows = [["crates/a/src/lib.rs", 7, 3, "concat!..."]]
        self.assertEqual(
            codeql_rust_quality._parse_unresolved_macros(rows),
            [["crates/a/src/lib.rs", 7, 3, "concat!..."]],
        )
        for invalid in (
            [["../escape.rs", 7, 3, "concat!..."]],
            [["README.md", 7, 3, "concat!..."]],
            [["crates/a/src/lib.rs", 0, 3, "concat!..."]],
            [["crates/a/src/lib.rs", 7, True, "concat!..."]],
            [["crates/a/src/lib.rs", 7, 3, ""]],
            [["crates/a/src/lib.rs", 7, 3, "concat!...", "unexpected"]],
            [rows[0], rows[0]],
        ):
            with self.subTest(invalid=invalid), self.assertRaises(
                codeql_rust_quality.CodeQLRustQualityError
            ):
                codeql_rust_quality._parse_unresolved_macros(invalid)

    def test_unresolved_macro_detail_count_must_match_metric_exactly(self) -> None:
        codeql_rust_quality.validate_unresolved_detail_count(0, [])
        codeql_rust_quality.validate_unresolved_detail_count(2, ["a", "b"])
        with self.assertRaisesRegex(
            codeql_rust_quality.CodeQLRustQualityError,
            "detail count differs",
        ):
            codeql_rust_quality.validate_unresolved_detail_count(2, ["a"])

    def test_checkout_provenance_binds_commit_and_worktree_bytes(self) -> None:
        commit = "a" * 40
        clean = WorktreeInspection(commit=commit, dirty=False, reasons=())
        with mock.patch.object(codeql_rust_quality, "inspect_worktree", return_value=clean):
            codeql_rust_quality.require_clean_checkout(commit)

        changed = WorktreeInspection(
            commit=commit,
            dirty=True,
            reasons=("tracked bytes differ from HEAD: crates/a/src/lib.rs",),
        )
        with mock.patch.object(
            codeql_rust_quality, "inspect_worktree", return_value=changed
        ), self.assertRaisesRegex(
            codeql_rust_quality.CodeQLRustQualityError, "checkout changed"
        ):
            codeql_rust_quality.require_clean_checkout(commit)

        with mock.patch.object(
            codeql_rust_quality, "inspect_worktree", return_value=clean
        ), self.assertRaisesRegex(
            codeql_rust_quality.CodeQLRustQualityError, "does not match"
        ):
            codeql_rust_quality.require_clean_checkout("b" * 40)

    def test_repository_target_entry_is_always_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            codeql_rust_quality.require_repository_target_absent(root)

            target = root / "target"
            target.mkdir()
            with self.assertRaisesRegex(
                codeql_rust_quality.CodeQLRustQualityError,
                "repository-local target must be absent",
            ):
                codeql_rust_quality.require_repository_target_absent(root)
            target.rmdir()

            target.symlink_to(root / "missing-target")
            with self.assertRaisesRegex(
                codeql_rust_quality.CodeQLRustQualityError,
                "repository-local target must be absent",
            ):
                codeql_rust_quality.require_repository_target_absent(root)


if __name__ == "__main__":
    unittest.main()
