"""Independent controls for the paired retained-database memory experiment."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import codeql_current_memory as control
from bounded_process import BoundedProcessError
from evidence_io import EvidenceIOError


MANIFEST = json.loads(Path(__file__).with_name("codeql_rust_queries.json").read_text())
QUERY_HASHES = MANIFEST["queries"]
FULL_SUMMARY = "queries/summary/SummaryStats.ql"
REDUCED_SUMMARY = "queries/summary/SummaryStatsReduced.ql"
SOURCE = {
    "artifact_id": 13609897355,
    "artifact_bytes": 600073757,
    "artifact_sha256": "68fc0a7e8f3fc02d9f072acc7eaa457d8e9174ab597d888ca632330ea6ba86c9",
    "source_head": "72acaaccde1ca9ea27e5af022da5fbce932ed4e9",
    "analyzed_commit": "cf5bf0195936c2f38197aa571c452a216c757abe",
    "source_run": 42439010975,
}
BUNDLE_HASH = "acf2050189aeede5b9aa566f8fb382b02ac1ace72f534778f68b06fce5371cea"


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def zip_member(name: str, body: bytes, *, mode: int = stat.S_IFREG | 0o640):
    info = zipfile.ZipInfo(name, (2024, 1, 2, 3, 4, 6))
    info.create_system = 3
    info.external_attr = mode << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    return info, body


def archive_bytes(members) -> bytes:
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w") as archive:
        for member, body in members:
            archive.writestr(member, body)
    return target.getvalue()


def database_members():
    return [
        zip_member("codeql-database.yml", b"primaryLanguage: rust\nfinalised: true\ncreationMetadata:\n  cliVersion: 2.27.2\n  sha: cf5bf0195936c2f38197aa571c452a216c757abe\n"),
        zip_member("db-rust/", b"", mode=stat.S_IFDIR | 0o750),
        zip_member("db-rust/default/data.bin", b"retained database bytes"),
        zip_member("db-rust/default/cache/entry.bin", b"retained cache bytes"),
        zip_member("results/codeql/rust-queries/queries/summary/old.bqrs", b"retained result"),
    ]


def valid_report(profile: str) -> dict:
    heap, native = {"baseline": (5668, 6733), "native-heavy": (3072, 9329)}[profile]
    return {
        "schema": 1,
        "kind": "qperiapt.codeql_current_memory",
        "profile": profile,
        "completed": True,
        "release_claim_eligible": False,
        "sarif_published": False,
        "experiment_commit": "f" * 40,
        "configuration": {
            "requested_ram_mb": 14000,
            "heap_mb": heap,
            "native_mb": native,
            "reserved_mb": 1599,
            "threads": 4,
            "deadline_seconds": 18000,
        },
        "source": copy.deepcopy(SOURCE),
        "input_identity": {
            "inner_sha256": digest(b"authenticated inner zip"),
            "inner_bytes": 123456,
            "database_inventory_sha256": digest(b"frozen database inventory"),
            "cache_inventory_sha256": digest(b"frozen cache inventory"),
            "metadata_sha256": digest(b"retained metadata"),
        },
        "tool_identity": {
            "codeql_version": "2.27.2",
            "query_pack": "0.1.44",
            "tool_bundle_sha256": BUNDLE_HASH,
            "tool_bundle_bytes": 98247028,
            "codeql_sha256": digest(b"pinned codeql executable"),
        },
        "query_hashes": copy.deepcopy(QUERY_HASHES),
        "compiled_query_hashes": {
            query: digest(("compiled:" + query).encode()) for query in QUERY_HASHES
        },
        "ram_resolution": ["-J-Xmx5668M", "--off-heap-ram=6733"],
        "query_command": control.query_command(
            Path("/tool/codeql"), Path("/case/database"), Path("/case"), profile
        ),
        "results": {
            query: {"bqrs_sha256": digest(query.encode()), "semantic_sha256": digest(b"same rows")}
            for query in QUERY_HASHES
        },
        "evaluation": {"returncode": 0, "stopped": None},
    }


class FixedConfigurationTests(unittest.TestCase):
    def test_selected_versions_and_all_query_identities_are_retained(self):
        self.assertEqual(control.CLI_VERSION, "2.27.2")
        self.assertEqual(control.QUERY_VERSION, "0.1.44")
        self.assertEqual(MANIFEST["codeql_version"], "2.27.2")
        self.assertEqual(MANIFEST["query_pack"], "0.1.44")
        self.assertEqual(len(QUERY_HASHES), 39)
        self.assertIn(FULL_SUMMARY, QUERY_HASHES)
        self.assertIn(REDUCED_SUMMARY, QUERY_HASHES)

    def test_only_two_memory_arguments_change_between_profiles(self):
        self.assertEqual(control.PROFILES, {"baseline": (5668, 6733), "native-heavy": (3072, 9329)})
        self.assertEqual(control.RAM_MB, 14000)
        self.assertEqual(control.THREADS, 4)
        self.assertEqual(control.EVALUATION_SECONDS, 18000)
        baseline = control.query_command(Path("/tool/codeql"), Path("/case/database"), Path("/case"), "baseline")
        candidate = control.query_command(Path("/tool/codeql"), Path("/case/database"), Path("/case"), "native-heavy")
        changes = [(a, b) for a, b in zip(baseline, candidate) if a != b]
        self.assertEqual(len(baseline), len(candidate))
        self.assertCountEqual(changes, [("-J-Xmx5668M", "-J-Xmx3072M"),
                                        ("--off-heap-ram=6733", "--off-heap-ram=9329")])
        for command in (baseline, candidate):
            self.assertIn("--threads=4", command)
            self.assertIn("--threat-model=local", command)
            self.assertIn("--dynamic-join-order-mode=none", command)
            self.assertIn("--no-rerun", command)
            self.assertNotIn("--expect-discarded-cache", command)
            self.assertNotIn("--no-expect-discarded-cache", command)
            self.assertIn("--output=/case/results", command)
            self.assertIn("--common-caches=/case/cache", command)
            self.assertIn("path:/case/frozen.qls", command)
            self.assertFalse(any("sarif" in value.lower() for value in command))
        self.assertEqual({sum(allocation) for allocation in control.PROFILES.values()}, {12401})
        self.assertEqual(control.RAM_MB - 12401, 1599)

    def test_exact_plaintext_inventory_is_accepted(self):
        control.validate_query_inventory(copy.deepcopy(QUERY_HASHES), copy.deepcopy(MANIFEST))

    def test_plaintext_hash_substitution_is_rejected(self):
        observed = copy.deepcopy(QUERY_HASHES)
        observed[FULL_SUMMARY] = "0" * 64
        with self.assertRaises(control.ControlError):
            control.validate_query_inventory(observed, MANIFEST)

    def test_omission_or_replacement_cannot_pass_the_query_census(self):
        for name in (FULL_SUMMARY, REDUCED_SUMMARY):
            with self.subTest(name=name):
                observed = copy.deepcopy(QUERY_HASHES)
                del observed[name]
                with self.assertRaises(control.ControlError):
                    control.validate_query_inventory(observed, MANIFEST)
                observed["queries/replacement.ql"] = "a" * 64
                with self.assertRaises(control.ControlError):
                    control.validate_query_inventory(observed, MANIFEST)


class DatabaseRestorationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def select(self, members):
        with zipfile.ZipFile(io.BytesIO(archive_bytes(members))) as archive:
            return control.select_database_members(archive)

    def test_normal_bundle_members_are_admitted(self):
        selected = self.select(database_members())
        self.assertEqual({member.filename for member in selected},
                         {member.filename for member, _ in database_members()})

    def test_unsafe_paths_are_rejected_before_restoration(self):
        for name in ("/outside", "../outside", "a/../../outside", "a//b", "a/./b", "a\\b"):
            with self.subTest(name=name), self.assertRaises(control.ControlError):
                self.select(database_members() + [zip_member(name, b"unsafe")])

    def test_nul_truncated_zip_names_are_rejected(self):
        raw = archive_bytes(database_members() + [zip_member("axb", b"unsafe")])
        raw = raw.replace(b"axb", b"a\0b")
        with zipfile.ZipFile(io.BytesIO(raw)) as archive, self.assertRaises(control.ControlError):
            control.select_database_members(archive)

    def test_non_regular_archive_members_are_rejected(self):
        for kind in (stat.S_IFLNK, stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR):
            with self.subTest(kind=kind), self.assertRaises(control.ControlError):
                self.select(database_members() + [zip_member("special", b"target", mode=kind | 0o777)])

    def test_duplicate_members_are_rejected(self):
        members = database_members()
        with self.assertWarns(UserWarning):
            raw = archive_bytes(members + [members[0]])
        with zipfile.ZipFile(io.BytesIO(raw)) as archive, self.assertRaises(control.ControlError):
            control.select_database_members(archive)

    def test_oversized_member_is_rejected_before_read(self):
        with zipfile.ZipFile(io.BytesIO(archive_bytes(database_members()))) as archive:
            archive.infolist()[0].file_size = 1 << 60
            with patch.object(archive, "open", side_effect=AssertionError("must reject before reading")):
                with self.assertRaises(control.ControlError):
                    control.select_database_members(archive)

    def test_empty_archive_is_not_a_database(self):
        with self.assertRaises(control.ControlError):
            self.select([])

    def test_archive_count_and_total_size_bounds_are_enforced(self):
        for setting in ("MAX_DATABASE_MEMBERS", "MAX_DATABASE_BYTES"):
            with self.subTest(setting=setting), patch.object(control, setting, 1):
                with self.assertRaises(control.ControlError):
                    self.select(database_members())

    def test_two_restorations_have_equal_relative_inventory_bytes_and_times(self):
        source = self.root / "retained.zip"
        source.write_bytes(archive_bytes(database_members()))
        first, second = self.root / "first", self.root / "second"
        first_inventory = control.restore_database(source, first)
        second_inventory = control.restore_database(source, second)
        self.assertEqual(first_inventory, second_inventory)
        for path in first.rglob("*"):
            other = second / path.relative_to(first)
            self.assertEqual(path.stat().st_mode, other.stat().st_mode)
            self.assertEqual(path.stat().st_mtime_ns, other.stat().st_mtime_ns)
            if path.is_file():
                self.assertEqual(path.read_bytes(), other.read_bytes())
        self.assertEqual(stat.S_IMODE((first / "db-rust").stat().st_mode), 0o750)
        self.assertEqual(stat.S_IMODE((first / "db-rust/default/data.bin").stat().st_mode), 0o640)
        self.assertEqual((first / "db-rust").stat().st_mtime_ns,
                         (first / "db-rust/default/data.bin").stat().st_mtime_ns)
        self.assertEqual((first / "db-rust/default").stat().st_mtime, 946684800)
        self.assertEqual((first / "db-rust/default/cache").stat().st_mtime, 946684800)
        self.assertEqual(first_inventory["files"]["db-rust/default/cache/entry.bin"]["sha256"],
                         digest(b"retained cache bytes"))

    def test_zip_order_does_not_change_the_restored_inventory(self):
        forward, reverse = self.root / "forward.zip", self.root / "reverse.zip"
        forward.write_bytes(archive_bytes(database_members()))
        reverse.write_bytes(archive_bytes(list(reversed(database_members()))))
        self.assertEqual(control.restore_database(forward, self.root / "forward"),
                         control.restore_database(reverse, self.root / "reverse"))

    def test_changed_cache_bytes_change_both_cache_and_database_identity(self):
        baseline, changed = self.root / "baseline.zip", self.root / "changed.zip"
        baseline.write_bytes(archive_bytes(database_members()))
        members = database_members()
        members[3] = zip_member("db-rust/default/cache/entry.bin", b"different retained cache bytes")
        changed.write_bytes(archive_bytes(members))
        first = control.restore_database(baseline, self.root / "baseline")
        second = control.restore_database(changed, self.root / "changed")
        self.assertNotEqual(first["cache_inventory_sha256"], second["cache_inventory_sha256"])
        self.assertNotEqual(first["database_inventory_sha256"], second["database_inventory_sha256"])
        self.assertEqual(first["metadata_sha256"], second["metadata_sha256"])

    def test_wrong_outer_artifact_is_rejected_before_zip_extraction(self):
        def wrong_download(path):
            path.write_bytes(b"not the pinned outer archive")
        with patch.object(control.retained, "download", side_effect=wrong_download):
            with patch.object(control.zipfile, "ZipFile", side_effect=AssertionError("must not extract")):
                with self.assertRaisesRegex(control.ControlError, "outer artifact identity differs"):
                    control.prepare_database(self.root)
        self.assertFalse((self.root / "database").exists())
        self.assertFalse((self.root / "retained-database.zip").exists())

    def test_restore_refuses_existing_destination_without_overwriting(self):
        source = self.root / "retained.zip"
        source.write_bytes(archive_bytes(database_members()))
        destination = self.root / "existing"
        destination.mkdir()
        marker = destination / "keep"
        marker.write_bytes(b"must survive")
        with self.assertRaises((control.ControlError, FileExistsError)):
            control.restore_database(source, destination)
        self.assertEqual(marker.read_bytes(), b"must survive")
        self.assertEqual(list(destination.iterdir()), [marker])


class EvaluationEvidenceTests(unittest.TestCase):
    def test_transfer_failure_receipt_excludes_exception_credentials(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            output = root / "case"
            secret = "never-retain-signed-url-secret"
            with patch.dict(os.environ, {"RUNNER_TEMP": str(root), "GH_TOKEN": secret}):
                with patch.object(control, "prepare_database", side_effect=RuntimeError(secret)):
                    with self.assertRaises(RuntimeError) as raised:
                        control.evaluate(Path("/unused/codeql"), Path("/unused/tool.tar.zst"), output, "baseline")
            self.assertNotIn(secret, str(raised.exception))
            receipt = (output / "evidence/RESULT.json").read_text()
            self.assertNotIn(secret, receipt)
            retained = json.loads(receipt)
            self.assertIs(retained["completed"], False)
            self.assertEqual(retained["failure"]["phase"], "prepare_database")

    def test_evaluator_environment_excludes_download_credentials(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            output = root / "case"
            environments = []
            def stop_after_environment(codeql, bundle, database, selected_root, environment):
                environments.append(environment.copy())
                raise RuntimeError("stop after independent environment inspection")
            with patch.dict(os.environ, {"RUNNER_TEMP": str(root), "GH_TOKEN": "download-token"}):
                with patch.object(control, "prepare_database", return_value=(output / "database", {})):
                    with patch.object(control, "admit_tool", side_effect=stop_after_environment):
                        with self.assertRaises(RuntimeError):
                            control.evaluate(Path("/unused/codeql"), Path("/unused/tool.tar.zst"), output, "baseline")
            self.assertEqual(len(environments), 1)
            self.assertNotIn("GH_TOKEN", environments[0])
            self.assertNotIn("download-token", environments[0].values())
            self.assertEqual(environments[0]["HOME"], str(output / "home"))
            self.assertEqual(environments[0]["TMPDIR"], str(output / "tmp"))

    def test_nonzero_exit_and_both_output_streams_are_retained(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            result = control.run_queries(
                [sys.executable, "-c", "import sys;print('out');print('err',file=sys.stderr);sys.exit(7)"],
                root, dict(os.environ), 5,
            )
            self.assertEqual(result["returncode"], 7)
            retained = json.loads((root / "query.json").read_text())
            self.assertEqual(retained["returncode"], 7)
            output = b"\n".join(path.read_bytes() for path in root.iterdir()
                                if path.is_file() and path.suffix != ".json")
            self.assertIn(b"out\n", output)
            self.assertIn(b"err\n", output)

    def test_timeout_is_failure_with_partial_output_and_receipt(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with self.assertRaises(BoundedProcessError) as raised:
                control.run_queries(
                    [sys.executable, "-c", "import sys,time;print('partial',flush=True);print('error-stream',file=sys.stderr,flush=True);time.sleep(60)"],
                    root, dict(os.environ), 1,
                )
            self.assertEqual(raised.exception.kind, "timeout")
            retained = json.loads((root / "query.json").read_text())
            self.assertEqual(retained["stopped"], "timeout")
            self.assertIsNone(retained["returncode"])
            output = b"\n".join(path.read_bytes() for path in root.iterdir()
                                if path.is_file() and path.suffix != ".json")
            self.assertIn(b"partial\n", output)
            self.assertIn(b"error-stream\n", output)

    def test_old_bqrs_cannot_satisfy_fresh_output_admission(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            queries = {name: Path("/unused") / name for name in QUERY_HASHES}
            for name in queries:
                old = root / "database/results/codeql/rust-queries" / Path(name).with_suffix(".bqrs")
                old.parent.mkdir(parents=True, exist_ok=True)
                old.write_bytes(b"old successful result")
            with self.assertRaisesRegex(control.ControlError, "fresh query result missing"):
                control.decode_results(Path("/unused/codeql"), queries, root, {})

    def test_empty_results_are_not_completed(self):
        with tempfile.TemporaryDirectory() as folder, self.assertRaises(control.ControlError):
            control.decode_results(Path("/unused/codeql"), {}, Path(folder), {})


class FreshResultDecodingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / "evidence").mkdir()
        self.queries = {name: Path("/unused/queries") / name for name in QUERY_HASHES}
        for name in self.queries:
            output = self.root / "results/codeql/rust-queries" / Path(name).with_suffix(".bqrs")
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(("fresh:" + name).encode())

    def decode(self, output: bytes):
        with patch.object(control, "small_command", return_value=output):
            return control.decode_results(Path("/unused/codeql"), self.queries, self.root, {})

    def test_all_39_fresh_results_are_decoded_with_binary_and_semantic_hashes(self):
        results = self.decode(b'{"#select":{"columns":[{"kind":"i"}],"tuples":[[1],[2]]}}')
        self.assertEqual(set(results), set(QUERY_HASHES))
        self.assertIn(FULL_SUMMARY, results)
        self.assertIn(REDUCED_SUMMARY, results)
        self.assertEqual(results[FULL_SUMMARY]["bqrs_sha256"], digest(("fresh:" + FULL_SUMMARY).encode()))
        self.assertEqual(len(results[FULL_SUMMARY]["semantic_sha256"]), 64)

    def test_tuple_order_does_not_change_semantics_but_content_and_multiplicity_do(self):
        first = self.decode(b'{"#select":{"columns":[{"kind":"i"}],"tuples":[[1],[2]]}}')
        reordered = self.decode(b'{"#select":{"tuples":[[2],[1]],"columns":[{"kind":"i"}]}}')
        changed = self.decode(b'{"#select":{"columns":[{"kind":"i"}],"tuples":[[1],[3]]}}')
        duplicated = self.decode(b'{"#select":{"columns":[{"kind":"i"}],"tuples":[[1],[2],[2]]}}')
        self.assertEqual(first, reordered)
        self.assertNotEqual(first[FULL_SUMMARY]["semantic_sha256"], changed[FULL_SUMMARY]["semantic_sha256"])
        self.assertNotEqual(first[FULL_SUMMARY]["semantic_sha256"], duplicated[FULL_SUMMARY]["semantic_sha256"])

    def test_missing_full_summary_does_not_pass_with_the_other_38_results(self):
        output = self.root / "results/codeql/rust-queries" / Path(FULL_SUMMARY).with_suffix(".bqrs")
        output.unlink()
        with self.assertRaises(control.ControlError):
            self.decode(b'{"#select":{"tuples":[]}}')

    def test_duplicate_keys_and_nonfinite_json_cannot_be_decoded_as_evidence(self):
        for output in (b'{"#select":{"tuples":[],"tuples":[[1]]}}',
                       b'{"#select":{"tuples":[[NaN]]}}',
                       b'{"#select":{"tuples":[[1e999]]}}'):
            with self.subTest(output=output), self.assertRaises((control.ControlError, EvidenceIOError)):
                self.decode(output)

    def test_malformed_result_tables_are_rejected(self):
        for output in (b'{"#select":null}', b'{"#select":{"tuples":{}}}', b'{"#select":{}}'):
            with self.subTest(output=output), self.assertRaises(control.ControlError):
                self.decode(output)


class PairedComparisonTests(unittest.TestCase):
    def test_complete_equal_results_are_comparable(self):
        result = control.compare_reports(valid_report("baseline"), valid_report("native-heavy"))
        self.assertIs(result["completed"], True)
        self.assertEqual(result["query_count"], 39)
        self.assertIs(result["semantic_results_equal"], True)
        self.assertEqual(result["source"], SOURCE)
        self.assertIs(result["release_claim_eligible"], False)
        self.assertIs(result["sarif_published"], False)

    def test_empty_input_identity_is_rejected_even_when_both_arms_agree(self):
        baseline, candidate = valid_report("baseline"), valid_report("native-heavy")
        baseline["input_identity"] = candidate["input_identity"] = {}
        with self.assertRaises(control.ControlError):
            control.compare_reports(baseline, candidate)

    def test_null_or_empty_semantic_digest_is_rejected_even_when_both_arms_agree(self):
        for value in (None, ""):
            with self.subTest(value=value):
                baseline, candidate = valid_report("baseline"), valid_report("native-heavy")
                for report in (baseline, candidate):
                    report["results"][FULL_SUMMARY]["semantic_sha256"] = value
                with self.assertRaises(control.ControlError):
                    control.compare_reports(baseline, candidate)

    def test_missing_or_malformed_digests_are_rejected_in_each_receipt_group(self):
        locations = [("input_identity", key) for key in
                     ("inner_sha256", "database_inventory_sha256", "cache_inventory_sha256", "metadata_sha256")]
        locations += [("tool_identity", "codeql_sha256"), ("compiled_query_hashes", FULL_SUMMARY)]
        for group, key in locations:
            for malformed in (None, "", "g" * 64, "0" * 63, 1):
                with self.subTest(group=group, key=key, malformed=malformed):
                    baseline, candidate = valid_report("baseline"), valid_report("native-heavy")
                    for report in (baseline, candidate):
                        report[group][key] = malformed
                    with self.assertRaises(control.ControlError):
                        control.compare_reports(baseline, candidate)
        for key in ("semantic_sha256", "bqrs_sha256"):
            for malformed in (None, "", "g" * 64, "0" * 63, 1):
                with self.subTest(result_key=key, malformed=malformed):
                    baseline, candidate = valid_report("baseline"), valid_report("native-heavy")
                    for report in (baseline, candidate):
                        report["results"][FULL_SUMMARY][key] = malformed
                    with self.assertRaises(control.ControlError):
                        control.compare_reports(baseline, candidate)

    def test_database_zip_size_requires_a_positive_bounded_integer(self):
        for value in (None, True, False, 0, -1, 1.5, "12", control.MAX_DATABASE_ZIP_BYTES + 1):
            with self.subTest(value=value):
                baseline, candidate = valid_report("baseline"), valid_report("native-heavy")
                for report in (baseline, candidate):
                    report["input_identity"]["inner_bytes"] = value
                with self.assertRaises(control.ControlError):
                    control.compare_reports(baseline, candidate)

    def test_experiment_commit_must_be_the_same_full_identity(self):
        for value in (None, "", "g" * 40, "0" * 39, 1):
            with self.subTest(value=value):
                baseline, candidate = valid_report("baseline"), valid_report("native-heavy")
                baseline["experiment_commit"] = candidate["experiment_commit"] = value
                with self.assertRaises(control.ControlError):
                    control.compare_reports(baseline, candidate)
        baseline, candidate = valid_report("baseline"), valid_report("native-heavy")
        candidate["experiment_commit"] = "e" * 40
        with self.assertRaises(control.ControlError):
            control.compare_reports(baseline, candidate)

    def test_equal_unpinned_source_or_tool_identity_is_not_admitted(self):
        mutations = (("source", "artifact_id", 1),
                     ("tool_identity", "codeql_version", "2.27.3"),
                     ("tool_identity", "query_pack", "0.1.45"),
                     ("tool_identity", "tool_bundle_sha256", "1" * 64),
                     ("tool_identity", "tool_bundle_bytes", 1))
        for group, key, value in mutations:
            with self.subTest(group=group, key=key):
                baseline, candidate = valid_report("baseline"), valid_report("native-heavy")
                baseline[group][key] = value
                candidate[group][key] = value
                with self.assertRaises(control.ControlError):
                    control.compare_reports(baseline, candidate)

    def test_failed_cli_comparison_leaves_an_incomplete_diagnostic_receipt(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            baseline, candidate, output = root / "baseline.json", root / "candidate.json", root / "comparison.json"
            first, second = valid_report("baseline"), valid_report("native-heavy")
            second["completed"] = False
            baseline.write_text(json.dumps(first))
            candidate.write_text(json.dumps(second))
            argv = ["codeql_current_memory.py", "compare", "--baseline", str(baseline),
                    "--candidate", str(candidate), "--output", str(output)]
            with patch.object(sys, "argv", argv), self.assertRaises(RuntimeError):
                control.main()
            receipt = json.loads(output.read_text())
            self.assertIs(receipt["completed"], False)
            self.assertIs(receipt["release_claim_eligible"], False)
            self.assertIs(receipt["sarif_published"], False)
            self.assertIn("failure", receipt)

    def test_source_input_tool_and_query_identity_mismatches_are_rejected(self):
        mutations = [
            ("source", "artifact_id", 1),
            ("source", "source_head", "1" * 40),
            ("source", "analyzed_commit", "1" * 40),
            ("input_identity", "inner_sha256", "1" * 64),
            ("input_identity", "database_inventory_sha256", "1" * 64),
            ("input_identity", "cache_inventory_sha256", "1" * 64),
            ("input_identity", "metadata_sha256", "1" * 64),
            ("tool_identity", "codeql_version", "2.27.3"),
            ("tool_identity", "query_pack", "0.1.45"),
            ("tool_identity", "tool_bundle_sha256", "1" * 64),
            ("query_hashes", FULL_SUMMARY, "1" * 64),
            ("compiled_query_hashes", FULL_SUMMARY, "1" * 64),
        ]
        for group, key, value in mutations:
            with self.subTest(group=group, key=key):
                candidate = valid_report("native-heavy")
                candidate[group][key] = value
                with self.assertRaises(control.ControlError):
                    control.compare_reports(valid_report("baseline"), candidate)

    def test_noncompletion_timeout_and_nonzero_exit_are_rejected(self):
        for mutation in ("incomplete", "timeout", "nonzero"):
            with self.subTest(mutation=mutation):
                candidate = valid_report("native-heavy")
                if mutation == "incomplete":
                    candidate["completed"] = False
                elif mutation == "timeout":
                    candidate["evaluation"]["stopped"] = "timeout"
                else:
                    candidate["evaluation"]["returncode"] = 7
                with self.assertRaises(control.ControlError):
                    control.compare_reports(valid_report("baseline"), candidate)

    def test_missing_full_summary_result_is_rejected_despite_success_flags(self):
        candidate = valid_report("native-heavy")
        del candidate["results"][FULL_SUMMARY]
        with self.assertRaises(control.ControlError):
            control.compare_reports(valid_report("baseline"), candidate)

    def test_missing_compiled_identity_is_rejected_even_when_both_arms_omit_it(self):
        baseline = valid_report("baseline")
        candidate = valid_report("native-heavy")
        del baseline["compiled_query_hashes"][FULL_SUMMARY]
        del candidate["compiled_query_hashes"][FULL_SUMMARY]
        with self.assertRaises(control.ControlError):
            control.compare_reports(baseline, candidate)

    def test_changed_semantic_result_is_rejected(self):
        candidate = valid_report("native-heavy")
        candidate["results"][FULL_SUMMARY]["semantic_sha256"] = "9" * 64
        with self.assertRaises(control.ControlError):
            control.compare_reports(valid_report("baseline"), candidate)

    def test_bqrs_container_bytes_need_not_match_when_semantics_match(self):
        candidate = valid_report("native-heavy")
        candidate["results"][FULL_SUMMARY]["bqrs_sha256"] = "9" * 64
        control.compare_reports(valid_report("baseline"), candidate)

    def test_command_changes_outside_the_memory_pair_are_rejected(self):
        for added in ("--threads=1", "--threat-model=remote", "--expect-discarded-cache"):
            with self.subTest(added=added):
                candidate = valid_report("native-heavy")
                candidate["query_command"].append(added)
                with self.assertRaises(control.ControlError):
                    control.compare_reports(valid_report("baseline"), candidate)

    def test_equal_changes_to_fixed_arguments_are_rejected(self):
        changes = {
            "--threads=4": "--threads=1",
            "--threat-model=local": "--threat-model=remote",
            "--no-rerun": "--rerun",
            "--common-caches=/case/cache": "--common-caches=/shared/cache",
            "--output=/case/results": "--output=/other/results",
            "/case/database/db-rust": "/other/database/db-rust",
            "path:/case/frozen.qls": "path:/other/changed.qls",
            "/tool/codeql": "codeql",
        }
        for old, new in changes.items():
            with self.subTest(old=old, new=new):
                baseline, candidate = valid_report("baseline"), valid_report("native-heavy")
                for report in (baseline, candidate):
                    report["query_command"] = [new if arg == old else arg for arg in report["query_command"]]
                with self.assertRaises(control.ControlError):
                    control.compare_reports(baseline, candidate)

    def test_equal_extra_or_missing_arguments_are_rejected(self):
        for mutation, option in (("add", "--expect-discarded-cache"),
                                 ("add", "--no-expect-discarded-cache"),
                                 ("add", "--threads=4"),
                                 ("add", "--output=/case/results"),
                                 ("remove", "--no-rerun"),
                                 ("remove", "--dynamic-join-order-mode=none"),
                                 ("remove", "--threat-model=local")):
            with self.subTest(mutation=mutation, option=option):
                baseline, candidate = valid_report("baseline"), valid_report("native-heavy")
                for report in (baseline, candidate):
                    if mutation == "add":
                        report["query_command"].insert(5, option)
                    else:
                        report["query_command"].remove(option)
                with self.assertRaises(control.ControlError):
                    control.compare_reports(baseline, candidate)

    def test_additional_memory_options_cannot_hide_behind_expected_arguments(self):
        for extra in ("--off-heap-ram=1", "-J-Xmx1M"):
            with self.subTest(extra=extra):
                candidate = valid_report("native-heavy")
                candidate["query_command"].append(extra)
                with self.assertRaises(control.ControlError):
                    control.compare_reports(valid_report("baseline"), candidate)

    def test_ram_resolution_and_execution_budget_changes_are_rejected(self):
        for field, value in (("requested_ram_mb", 16000), ("threads", 1),
                             ("deadline_seconds", 900), ("heap_mb", 4096),
                             ("native_mb", 9000), ("reserved_mb", 0)):
            with self.subTest(field=field):
                candidate = valid_report("native-heavy")
                candidate["configuration"][field] = value
                with self.assertRaises(control.ControlError):
                    control.compare_reports(valid_report("baseline"), candidate)
        candidate = valid_report("native-heavy")
        candidate["ram_resolution"] = ["-J-Xmx4096M", "--off-heap-ram=8305"]
        with self.assertRaises(control.ControlError):
            control.compare_reports(valid_report("baseline"), candidate)

    def test_same_profile_twice_is_not_a_paired_experiment(self):
        with self.assertRaises(control.ControlError):
            control.compare_reports(valid_report("baseline"), valid_report("baseline"))

    def test_diagnostic_reports_cannot_claim_release_or_publication(self):
        for field in ("release_claim_eligible", "sarif_published"):
            with self.subTest(field=field):
                candidate = valid_report("native-heavy")
                candidate[field] = True
                with self.assertRaises(control.ControlError):
                    control.compare_reports(valid_report("baseline"), candidate)


if __name__ == "__main__":
    unittest.main()
