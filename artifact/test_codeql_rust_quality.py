from __future__ import annotations

import pathlib
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

    def test_database_location_is_exact_rust_child_of_runner_temp(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            database = root / "database"
            database.mkdir()
            (database / "codeql-database.yml").write_text(
                "name: rust\n", encoding="utf-8"
            )
            encoded = '{"rust": "' + str(database) + '"}'
            self.assertEqual(
                codeql_rust_quality._require_database(encoded, root), database
            )
            outside = root.parent
            with self.assertRaises(codeql_rust_quality.CodeQLRustQualityError):
                codeql_rust_quality._require_database(
                    '{"rust": "' + str(outside) + '"}', root
                )
            with self.assertRaises(codeql_rust_quality.CodeQLRustQualityError):
                codeql_rust_quality._require_database(
                    '{"rust": "' + str(database) + '", "cpp": "' + str(database) + '"}',
                    root,
                )

            for malformed in (
                '{"rust":"a","rust":"b"}',
                '{"rust":NaN}',
                '{"rust":"\udcff"}',
            ):
                with self.subTest(malformed=malformed), self.assertRaisesRegex(
                    codeql_rust_quality.CodeQLRustQualityError,
                    "not strict UTF-8 JSON",
                ):
                    codeql_rust_quality._require_database(malformed, root)

    def test_bqrs_decode_requires_strict_json_and_empty_stderr(self) -> None:
        codeql = pathlib.Path("/codeql")
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
            ):
                codeql_rust_quality._decode_query(codeql, bqrs)

        with mock.patch.object(
            codeql_rust_quality,
            "capture_stdout",
            return_value=BoundedResult(
                0, b"warning: synthetic decoder diagnostic\n" + valid
            ),
        ), self.assertRaisesRegex(
            codeql_rust_quality.CodeQLRustQualityError,
            "not strict UTF-8 JSON",
        ):
            codeql_rust_quality._decode_query(codeql, bqrs)

    def test_codeql_process_boundaries_fail_closed(self) -> None:
        codeql = pathlib.Path("/codeql")
        database = pathlib.Path("/database")
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
            ):
                codeql_rust_quality._run_query(codeql, database, query, output)

        with mock.patch.object(
            codeql_rust_quality,
            "capture_stdout",
            return_value=BoundedResult(7, b"fatal query diagnostic\n"),
        ), mock.patch.object(codeql_rust_quality.sys.stdout, "write") as write, self.assertRaisesRegex(
            codeql_rust_quality.CodeQLRustQualityError,
            "exited with status 7",
        ):
            codeql_rust_quality._run_query(codeql, database, query, output)
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
            ):
                codeql_rust_quality._decode_query(codeql, output)

    def test_codeql_process_limits_are_fixed(self) -> None:
        codeql = pathlib.Path("/codeql")
        database = pathlib.Path("/database")
        query = pathlib.Path("/query.ql")
        output = pathlib.Path("/result.bqrs")
        with mock.patch.object(
            codeql_rust_quality,
            "capture_stdout",
            return_value=BoundedResult(0, b"query progress\n"),
        ) as capture, mock.patch.object(codeql_rust_quality.sys.stdout, "write"):
            codeql_rust_quality._run_query(codeql, database, query, output)
        self.assertEqual(
            capture.call_args.kwargs,
            {
                "timeout_seconds": 300,
                "maximum_bytes": 4 * 1024 * 1024,
                "stderr": codeql_rust_quality.subprocess.STDOUT,
            },
        )

        valid = b'{"#select":{"tuples":[]}}'
        with mock.patch.object(
            codeql_rust_quality,
            "capture_stdout",
            return_value=BoundedResult(0, valid),
        ) as capture:
            self.assertEqual(codeql_rust_quality._decode_query(codeql, output), [])
        self.assertEqual(
            capture.call_args.kwargs,
            {
                "timeout_seconds": 300,
                "maximum_bytes": 16 * 1024 * 1024,
                "stderr": codeql_rust_quality.subprocess.STDOUT,
            },
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
