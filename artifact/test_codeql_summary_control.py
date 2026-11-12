"""Independent controls for the paired retained-database memory experiment."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import shutil
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import codeql_summary_control as control
from bounded_process import BoundedProcessError
from evidence_io import EvidenceIOError


MANIFEST = json.loads(Path(__file__).with_name("codeql_rust_queries.json").read_text())
QUERY_HASHES = MANIFEST["queries"]
FULL_SUMMARY = "queries/summary/SummaryStats.ql"
REDUCED_SUMMARY = "queries/summary/SummaryStatsReduced.ql"
SOURCE = {
    "artifact_id": 13677417145,
    "artifact_bytes": 288417501,
    "artifact_sha256": "cb0bd89478b9a8d0f635a9ffa2156a06e3fbbf81b0054b8a1a474c045711d43d",
    "source_head": "3254c81066af26cd23a2881198010fb616ce6b7a",
    "analyzed_commit": "56f191f04a57806869b8a03078ee4d27ffe900ab",
    "source_run": 42554273879,
}
COMPILED_HASHES = {'queries/diagnostics/AstConsistencyCounts.ql': 'ac7b48bf00cdc0d4a27f9ef2b60892fe9b14a1f580b093e0b6f77744eaec8992',
 'queries/diagnostics/CfgConsistencyCounts.ql': '106bf6901fa18962eea85ca582d21896c84dcd54cdf1191ab28e920908895334',
 'queries/diagnostics/DataFlowConsistencyCounts.ql': '89e8c819e1a4df77e27bbe6d89991670373583639dfe41c21b2ea1991f35621b',
 'queries/diagnostics/ExtractedFiles.ql': '02ea240b3f2e67b43d81e986ef5ef16fd097bf5d6d1d2ebeea26c47f6c3e9f88',
 'queries/diagnostics/ExtractionErrors.ql': 'fc33fbb18bcbc4f7430cffc0d76bd2a752f8a7ece13d5f8a2a28884f7752b100',
 'queries/diagnostics/ExtractionWarnings.ql': '0a4be624691ca9160c83a8f900c180488845eea32ab365cf8485a0cf2e46acdf',
 'queries/diagnostics/SsaConsistencyCounts.ql': '4e964ae6967e7069ffe482eb19edfc77927d2c0263e8897cb6724b1a011f1ee4',
 'queries/diagnostics/TypeInferenceConsistencyCounts.ql': '8cdf06a238bdf82774ff47172ef136a315faa3b57348cada6cf2636e178a86ec',
 'queries/diagnostics/UnextractedElements.ql': '08d55d6f6d20c6dae12a6805660894cdaf41d84ab598d2405057515609f8932a',
 'queries/diagnostics/UnresolvedMacroCalls.ql': 'c15df1bed33e47b59e0ac478dc52f4f18b8e6114f4746720dd5605081dab55f5',
 'queries/security/CWE-020/RegexInjection.ql': '20f20aef63f0b312d83d48bd5083b29626f9f391e6a89e7a09b25d59600490c9',
 'queries/security/CWE-022/TaintedPath.ql': '292bdb8b98d36eab315e30088797d80c2a7d510f88127f427bea8b572006a1ef',
 'queries/security/CWE-078/CommandInjection.ql': '18053fe50164fd8f10d97582adb740f1d413553a286b74857d15bbd1aff4937e',
 'queries/security/CWE-079/XSS.ql': '6899d043134657864522ffce81668e46bdf8779722fb614aaa5277ab237492be',
 'queries/security/CWE-089/SqlInjection.ql': 'b9cc8ba65a359388e2bf1810109fa65a8852317fd14d7d22c7bf70418e4214e8',
 'queries/security/CWE-117/LogInjection.ql': 'f34b4cbf73dedec8ad05d8dc5de20b666b521d5b77844d23514422e28de0c592',
 'queries/security/CWE-295/DisabledCertificateCheck.ql': '383b62092e0cea04d930ed4807011955dc7a9bc46263410ab3311ec10db9e1b3',
 'queries/security/CWE-311/CleartextTransmission.ql': '71b918d7fc207f82cb43a0508defc091d30d23c71d9e03fc1173c0c54f86cc61',
 'queries/security/CWE-312/CleartextLogging.ql': 'b0af90203696722ed4b06d514a71f60f3920bee01f3a2f6ba4300c6b78773b68',
 'queries/security/CWE-312/CleartextStorageDatabase.ql': '01b1ed605e4e874560aa61407b5e48eed469eb7deb8b5d58f884ecfa558d1431',
 'queries/security/CWE-319/UseOfHttp.ql': '5dd2f895e3f7196c0079c1d1b5afacca9b76a31bda539ca2a2b68f6065942490',
 'queries/security/CWE-327/BrokenCryptoAlgorithm.ql': '6bc456f127ce53b792e5bba69749c750e98c24e88133f49a10115c481dcfaa00',
 'queries/security/CWE-327/WeakSensitiveDataHashing.ql': 'd2420712e951c55dfe2b11d3b143791d53ad8116d33c06fa2d3b200da8685b19',
 'queries/security/CWE-614/InsecureCookie.ql': '59d26745830cb0f517350051675aea906e87431861e23a21bfe29b21198d749e',
 'queries/security/CWE-770/UncontrolledAllocationSize.ql': 'da2a7d3c0af1842980ed7501faba1f97cccf38b6df7875aad9cb3dac31ab80e0',
 'queries/security/CWE-798/HardcodedCryptographicValue.ql': '77ffc85292bb9d72f66e6cc177545adc2a1b45ed997f3bdd501c8057df5b0c58',
 'queries/security/CWE-825/AccessAfterLifetime.ql': '91d03be6b35c33e8fa17da0c41ad82af1dacee81bc9059d14782b167a8e17138',
 'queries/security/CWE-825/AccessInvalidPointer.ql': '108a9283ac51bb43b73a12ae003c8953b05d149de0f3ea085e45e51c2f4c9fc1',
 'queries/security/CWE-918/RequestForgery.ql': '349ae1bcd3cfa1cdfd70c1b18b41c278c9386ebf7ec3db616a4c884577bb194a',
 'queries/summary/LinesOfCode.ql': 'de201bea93eaa2b3aeaa580bd961704e068f4a6bacb5dfc95ee82a5dc67cd23c',
 'queries/summary/LinesOfUserCode.ql': 'ab6d4fa3a666f2ff4516a25bb4e82bc062e48c3a084b52de6a9632e2d3ca13f6',
 'queries/summary/NodesWithTypeAtLengthLimit.ql': '4f8d7d1593c762b29f9d3930b8f3a58e9e296cc32ee65011d8baf35cbb9b5138',
 'queries/summary/NumberOfFilesExtractedWithErrors.ql': '84578f86e3b6b44efad3c304938a588b904121b92bf87fbca789994de6ba9c67',
 'queries/summary/NumberOfSuccessfullyExtractedFiles.ql': '94534405867fd989251464bbb55c90e6dbbe046b5b260ced6cec88a8289b85e1',
 'queries/summary/QuerySinkCounts.ql': '11142162d957898cd640b96bb7caabd3fc9c72a9ff2bdf1b258fcb9443bf3410',
 'queries/summary/SummaryStats.ql': 'bc65daf746a13e0d162f0853b3a21eda41ff2d573774e6862983a916c06244a6',
 'queries/summary/SummaryStatsReduced.ql': 'ec84f96f284498fc71f3b29137ed9a1b625ee1d081a07f0cbdee9402ea99fd92',
 'queries/telemetry/DatabaseQualityDiagnostics.ql': 'ff6b9b8b7669630e6cc62908f0dcd403c3bca33d191de8cdc5639c23656188a8',
 'queries/telemetry/ExtractorInformation.ql': 'abc7ac6e1f02f23697e55b1db2536c3883f4f3cc44ea57e84d946ded6cbcb51e'}
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
        zip_member("codeql-database.yml", b"primaryLanguage: rust\nfinalised: true\ncreationMetadata:\n  cliVersion: 2.27.2\n  sha: 56f191f04a57806869b8a03078ee4d27ffe900ab\n"),
        zip_member("db-rust/", b"", mode=stat.S_IFDIR | 0o750),
        zip_member("db-rust/default/data.bin", b"retained database bytes"),
        zip_member("db-rust/default/cache/entry.bin", b"retained cache bytes"),
        zip_member("results/codeql/rust-queries/queries/summary/old.bqrs", b"retained result"),
    ]


def prefixed_database_members(prefix="rust", include_root=True):
    members = [zip_member(prefix + "/", b"", mode=stat.S_IFDIR | 0o750)] if include_root else []
    for member, body in database_members():
        renamed = copy.copy(member)
        renamed.filename = renamed.orig_filename = prefix + "/" + member.filename
        members.append((renamed, body))
    return members


def valid_report(profile: str) -> dict:
    heap, native = {"heap-2048": (2048, 10643), "heap-1536": (1536, 11155)}[profile]
    return {
        "schema": 1,
        "kind": "qperiapt.codeql_summary_control",
        "profile": profile,
        "completed": True,
        "release_claim_eligible": False,
        "sarif_published": False,
        "experiment_commit": "f" * 40,
        "configuration": {
            "requested_ram_mb": 14000,
            "heap_mb": heap,
            "native_mb": native,
            "reserved_mb": 1309,
            "threads": 4,
            "deadline_seconds": 18000,
        },
        "source": copy.deepcopy(SOURCE),
        "input_identity": copy.deepcopy(control.INPUT_IDENTITY),
        "cache_scope": control.CACHE_SCOPE,
        "jvm_admission": {"max_heap_bytes_observed": [heap * 1024**2], "codeql_version": "2.27.2"},
        "observations": {"schema": 1, "max_heap_bytes_observed": [heap * 1024**2],
                         "off_heap_mb_observed": [native], "evaluator_start_lines": 1,
                         "pause_count": 12, "eviction_pause_count": 10},
        "retained_results": {
            query: {"bqrs_sha256": digest(query.encode()), "semantic_sha256": digest(b"same rows")}
            for query in QUERY_HASHES if query != FULL_SUMMARY
        },
        "tool_identity": {
            "codeql_version": "2.27.2",
            "query_pack": "0.1.44",
            "tool_bundle_sha256": BUNDLE_HASH,
            "tool_bundle_bytes": 98247028,
            "codeql_sha256": "5010324098d11f9e2d34e0fcf53bb44e40e8e3ffc8aecefe695269b54edaa413",
        },
        "query_hashes": copy.deepcopy(QUERY_HASHES),
        "compiled_query_hashes": copy.deepcopy(COMPILED_HASHES),
        "ram_resolution": ["-J-Xmx3362M", "--off-heap-ram=9329"],
        "query_command": control.query_command(
            Path("/tool/codeql"), Path("/case/database"), Path("/case"), profile
        ),
        "results": {
            query: {"bqrs_sha256": digest(query.encode()), "semantic_sha256": digest(b"same rows")}
            for query in QUERY_HASHES
        },
        "evaluation": {"returncode": 0, "stopped": None, "seconds": 1.0,
                       "command": control.query_command(Path("/tool/codeql"), Path("/case/database"),
                                                        Path("/case"), profile)},
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
        self.assertEqual(control.PROFILES, {"heap-2048": (2048, 10643), "heap-1536": (1536, 11155),
                                           "memory-56000": (4096, 50595), "memory-120000": (4096, 114595),
                                            "memory-120000-threads-16": (4096, 114595)})
        self.assertEqual(control.RAM_MB, 14000)
        self.assertEqual(control.THREADS, 4)
        self.assertEqual(control.EVALUATION_SECONDS, 18000)
        baseline = control.query_command(Path("/tool/codeql"), Path("/case/database"), Path("/case"), "heap-2048")
        candidate = control.query_command(Path("/tool/codeql"), Path("/case/database"), Path("/case"), "heap-1536")
        changes = [(a, b) for a, b in zip(baseline, candidate) if a != b]
        self.assertEqual(len(baseline), len(candidate))
        self.assertCountEqual(changes, [("-J-Xmx2048M", "-J-Xmx1536M"),
                                        ("--off-heap-ram=10643", "--off-heap-ram=11155")])
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
        self.assertEqual({sum(allocation) for allocation in control.PROFILES.values()}, {12691, 54691, 118691})
        self.assertEqual(control.configuration("memory-56000")["requested_ram_mb"], 56000)
        self.assertEqual(control.RAM_MB - 12691, 1309)

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

    def test_single_prefix_is_normalized_and_root_metadata_is_preserved(self):
        source = self.root / "bundled.zip"
        source.write_bytes(archive_bytes(prefixed_database_members()))
        destination = self.root / "restored"
        inventory = control.restore_database(source, destination)
        self.assertEqual(inventory["archive_root"], "rust")
        self.assertFalse((destination / "rust").exists())
        self.assertEqual((destination / "db-rust/default/cache/entry.bin").read_bytes(), b"retained cache bytes")
        self.assertEqual(set(inventory["files"]), {member.filename for member, _ in database_members() if not member.is_dir()})
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o750)
        self.assertEqual(destination.stat().st_mtime_ns, (destination / "codeql-database.yml").stat().st_mtime_ns)
        self.assertEqual(stat.S_IMODE((destination / "db-rust/default/data.bin").stat().st_mode), 0o640)

    def test_prefix_without_explicit_directory_entry_retains_all_file_identities(self):
        flat, wrapped = self.root / "flat.zip", self.root / "wrapped.zip"
        flat.write_bytes(archive_bytes(database_members()))
        wrapped.write_bytes(archive_bytes(prefixed_database_members(include_root=False)))
        first = control.restore_database(flat, self.root / "first")
        second = control.restore_database(wrapped, self.root / "second")
        self.assertEqual(first["files"], second["files"])
        self.assertEqual(first["directories"], second["directories"])
        self.assertEqual(first["database_inventory_sha256"], second["database_inventory_sha256"])
        self.assertEqual(first["cache_inventory_sha256"], second["cache_inventory_sha256"])

    def test_multiple_or_nested_metadata_roots_are_rejected(self):
        cases = [prefixed_database_members() + prefixed_database_members("other"),
                 prefixed_database_members() + [database_members()[0]],
                 prefixed_database_members("outer/rust"),
                 database_members() + [zip_member("nested/codeql-database.yml", b"other metadata")]]
        for members in cases:
            with self.subTest(names=[member.filename for member, _ in members]), self.assertRaises(control.ControlError):
                self.select(members)

    def test_member_outside_selected_metadata_root_is_rejected(self):
        for name in ("outside.txt", "db-rust/default/cache/foreign", "other/extra"):
            with self.subTest(name=name), self.assertRaises(control.ControlError):
                self.select(prefixed_database_members() + [zip_member(name, b"outside")])

    def test_directory_metadata_and_wrong_dataset_location_are_rejected(self):
        members = database_members()[1:] + [zip_member("codeql-database.yml/", b"", mode=stat.S_IFDIR | 0o750)]
        with self.assertRaises(control.ControlError):
            self.select(members)
        members = prefixed_database_members()
        for member, _ in members:
            member.filename = member.orig_filename = member.filename.replace("rust/db-rust", "rust/not-db-rust")
        with self.assertRaises(control.ControlError):
            self.select(members)

    def test_normalized_duplicates_and_file_ancestor_conflicts_are_rejected(self):
        for extras in ([zip_member("rust/db-rust", b"regular file")],
                       [zip_member("rust/extra", b"file"), zip_member("rust/extra/child", b"child")]):
            with self.subTest(names=[member.filename for member, _ in extras]), self.assertRaises(control.ControlError):
                self.select(prefixed_database_members() + extras)

    def test_matching_scalar_quotes_keep_exact_metadata_identities(self):
        for quote in (b"'", b'"'):
            with self.subTest(quote=quote):
                members = database_members()
                info, metadata = members[0]
                for plain in (b"rust", b"2.27.2", SOURCE["analyzed_commit"].encode()):
                    metadata = metadata.replace(plain, quote + plain + quote)
                members[0] = (info, metadata)
                source = self.root / ("quoted-" + str(quote[0]) + ".zip")
                source.write_bytes(archive_bytes(members))
                inventory = control.restore_database(source, self.root / ("quote-" + str(quote[0])))
                self.assertEqual(inventory["metadata_git_sha"], SOURCE["analyzed_commit"])

    def test_completed_database_without_legacy_finalised_field_is_admitted(self):
        members = prefixed_database_members()
        info, metadata = members[1]
        members[1] = (info, metadata.replace(b"finalised: true\n", b""))
        source = self.root / "current-format.zip"
        source.write_bytes(archive_bytes(members))
        inventory = control.restore_database(source, self.root / "current-format")
        self.assertEqual(inventory["archive_root"], "rust")
        self.assertEqual(inventory["metadata_git_sha"], SOURCE["analyzed_commit"])

    def test_any_root_in_progress_key_rejects_regardless_of_value_or_quoting(self):
        count = 0
        for key in (b"inProgress", b"'inProgress'", b'"inProgress"', b'"inPro\\u0067ress"'):
            for value in (b"", b"null", b"false", b"true", b"0", b"{}", b"[]", b'"false"'):
                with self.subTest(key=key, value=value):
                    members = database_members()
                    info, metadata = members[0]
                    members[0] = (info, metadata.replace(b"finalised: true\n", b"") + key + b": " + value + b"\n")
                    source = self.root / ("progress-" + str(count) + ".zip")
                    source.write_bytes(archive_bytes(members))
                    with self.assertRaises(control.ControlError):
                        control.restore_database(source, self.root / ("progress-" + str(count)))
                    count += 1

    def test_legacy_finalised_must_be_explicit_boolean_true_when_present(self):
        for index, value in enumerate((b"false", b"null", b"", b'"true"', b"true\n'finalised': false")):
            with self.subTest(value=value):
                members = database_members()
                info, metadata = members[0]
                members[0] = (info, metadata.replace(b"finalised: true", b"finalised: " + value))
                source = self.root / ("legacy-" + str(index) + ".zip")
                source.write_bytes(archive_bytes(members))
                with self.assertRaises(control.ControlError):
                    control.restore_database(source, self.root / ("legacy-" + str(index)))

    def test_wrong_or_ambiguous_metadata_and_missing_cache_remain_rejected(self):
        original = database_members()[0][1]
        bad_metadata = [original.replace(b"rust", b"java"), original.replace(b"2.27.2", b"2.27.3"),
                        original.replace(b"true", b"false"), original.replace(SOURCE["analyzed_commit"].encode(), b"0" * 40),
                        original + b"primaryLanguage: java\n", original.replace(b"rust", b'"rust\''),
                        original.replace(b"  cliVersion: 2.27.2\n", b"")]
        for index, metadata in enumerate(bad_metadata):
            with self.subTest(index=index):
                members = database_members()
                members[0] = (members[0][0], metadata)
                source = self.root / (str(index) + ".zip")
                source.write_bytes(archive_bytes(members))
                with self.assertRaises(control.ControlError):
                    control.restore_database(source, self.root / ("bad-" + str(index)))
        source = self.root / "no-cache.zip"
        source.write_bytes(archive_bytes([(member, body) for member, body in database_members() if "/cache/" not in member.filename]))
        with self.assertRaisesRegex(control.ControlError, "retained evaluator cache is absent"):
            control.restore_database(source, self.root / "no-cache")

    def test_archive_receipt_is_bounded_and_records_actual_metadata_paths(self):
        source = self.root / "observed.zip"
        members = prefixed_database_members()
        members[1] = (members[1][0], b"x" * 40000)
        source.write_bytes(archive_bytes(members))
        control.record_database_archive(source, self.root)
        receipt = json.loads((self.root / "DATABASE_ARCHIVE.json").read_text())
        self.assertEqual(receipt["inner_sha256"], digest(source.read_bytes()))
        self.assertEqual(receipt["member_count"], len(members))
        self.assertEqual(receipt["top_level_components"], ["rust"])
        self.assertEqual(receipt["metadata_candidates"][0]["path"], "rust/codeql-database.yml")
        self.assertIs(receipt["metadata_candidates"][0]["truncated"], True)
        self.assertEqual(len(receipt["metadata_candidates"][0]["text"]), 32768)
        self.assertLess((self.root / "DATABASE_ARCHIVE.json").stat().st_size, 40000)

    def test_prepare_retains_archive_receipt_before_metadata_rejection(self):
        members = prefixed_database_members()
        info, metadata = members[1]
        members[1] = (info, metadata.replace(b"rust", b"java"))
        inner = archive_bytes(members)
        outer = archive_bytes([zip_member(control.INNER_MEMBER, inner)])
        fake_source = dict(control.SOURCE, artifact_bytes=len(outer), artifact_sha256=digest(outer))
        (self.root / "evidence").mkdir()
        with patch.object(control, "SOURCE", fake_source), \
             patch.object(control, "INNER_BYTES", len(inner)), \
             patch.object(control, "INNER_SHA256", digest(inner)), \
             patch.object(control, "download", side_effect=lambda path: path.write_bytes(outer)):
            with self.assertRaisesRegex(control.ControlError, "database language, finalization, or CLI identity differs"):
                control.prepare_database(self.root)
        receipt = json.loads((self.root / "evidence/DATABASE_ARCHIVE.json").read_text())
        self.assertEqual(receipt["metadata_candidates"][0]["path"], "rust/codeql-database.yml")
        self.assertIn("primaryLanguage: java", receipt["metadata_candidates"][0]["text"])
        self.assertFalse((self.root / "evidence/DATABASE_INPUTS.json").exists())

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
        first = control.restore_database(baseline, self.root / "heap-2048")
        second = control.restore_database(changed, self.root / "changed")
        self.assertNotEqual(first["cache_inventory_sha256"], second["cache_inventory_sha256"])
        self.assertNotEqual(first["database_inventory_sha256"], second["database_inventory_sha256"])
        self.assertEqual(first["metadata_sha256"], second["metadata_sha256"])

    def test_wrong_outer_artifact_is_rejected_before_zip_extraction(self):
        def wrong_download(path):
            path.write_bytes(b"not the pinned outer archive")
        with patch.object(control, "download", side_effect=wrong_download):
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
                        control.evaluate(Path("/unused/codeql"), Path("/unused/tool.tar.zst"), output, "heap-2048")
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
                            control.evaluate(Path("/unused/codeql"), Path("/unused/tool.tar.zst"), output, "heap-2048")
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

    def test_both_log_streams_are_readable_before_the_child_exits(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            child = """\
from pathlib import Path
import sys, time
expected = (b'live stdout\\n', b'live stderr\\n')
sys.stdout.buffer.write(expected[0]); sys.stdout.buffer.flush()
sys.stderr.buffer.write(expected[1]); sys.stderr.buffer.flush()
logs = [Path(path) for path in sys.argv[1:3]]
deadline = time.monotonic() + 5
while time.monotonic() < deadline:
    if tuple(path.read_bytes() for path in logs) == expected:
        assert not Path(sys.argv[3]).exists(), 'completion preceded the live read'
        Path(sys.argv[4]).write_bytes(b'visible before exit\\n')
        break
    time.sleep(0.01)
else:
    raise SystemExit('small stdout/stderr writes were not visible before child exit')
"""
            result = control.run_queries(
                [sys.executable, "-c", child, str(root / "query.stdout"), str(root / "query.stderr"),
                 str(root / "query.json"), str(root / "child-observed.txt")],
                root, dict(os.environ), 10,
            )
            self.assertEqual(result["returncode"], 0)
            self.assertEqual((root / "child-observed.txt").read_bytes(), b"visible before exit\n")
            self.assertEqual((root / "query.stdout").read_bytes(), b"live stdout\n")
            self.assertEqual((root / "query.stderr").read_bytes(), b"live stderr\n")

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
            with self.assertRaisesRegex(control.ControlError, "query output directory is missing"):
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
        for path in (self.root / "evidence").glob("*-bqrs"):
            shutil.rmtree(path)
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


class PartialResultRetentionTests(unittest.TestCase):
    """Synthetic BQRS fixtures test retention; no Rust query evaluation is simulated as evidence."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / "evidence").mkdir()
        self.queries = {name: Path("/unused/queries") / name for name in QUERY_HASHES}
        self.decoded = b'{"#select":{"tuples":[[1],[2]]}}'
        self.original = {name: {"semantic_sha256": control.result_semantic_sha(self.decoded)}
                         for name in self.queries if name != FULL_SUMMARY}

    def source(self, query):
        return self.root / "results/codeql/rust-queries" / Path(query).with_suffix(".bqrs")

    def populate(self, names):
        for name in names:
            path = self.source(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("synthetic fresh:" + name).encode())

    def retain(self, cleanup_ambiguous=False):
        return control.retain_partial_results(Path("/unused/codeql"), self.queries, self.root, {},
                                              self.original, cleanup_ambiguous=cleanup_ambiguous)

    def test_38_fresh_results_are_preserved_but_do_not_satisfy_complete_comparison(self):
        self.populate(self.original)
        with patch.object(control, "small_command", return_value=self.decoded):
            result = self.retain()
        self.assertEqual(result["captured_query_count"], 38)
        self.assertEqual(result["decoded_query_count"], 38)
        self.assertEqual(result["missing_queries"], [FULL_SUMMARY])
        self.assertEqual(result["uncaptured_queries"], [FULL_SUMMARY])
        self.assertFalse(result["all_expected_bqrs_captured"])
        self.assertEqual(result["status"], "partial")
        self.assertFalse(result["analysis_completed"])
        self.assertTrue(all(item["retained_semantics_equal"] for item in result["results"].values()))
        candidate = valid_report("heap-1536")
        candidate["partial_results"] = result
        candidate.pop("results")
        with self.assertRaisesRegex(control.ControlError, "fresh 39-query result census differs"):
            control.compare_reports(valid_report("heap-2048"), candidate)
        candidate["results"] = result["results"]
        with self.assertRaisesRegex(control.ControlError, "fresh 39-query result census differs"):
            control.compare_reports(valid_report("heap-2048"), candidate)
        self.assertEqual(control.read_json(self.root / "evidence/PARTIAL_RESULTS.json"), result)

    def test_all_snapshots_precede_decoding_and_replaced_source_is_not_decoded(self):
        self.populate(self.queries)
        unexpected = self.source("queries/summary/Unexpected.ql")
        unexpected.write_bytes(b"not a pinned query")
        first = sorted(self.queries)[0]
        def decode(command, prefix, environment, *, timeout_seconds):
            copies = list((self.root / "evidence/partial-fresh-bqrs").rglob("*.bqrs"))
            self.assertEqual(len(copies), 39)
            self.source(first).write_bytes(b"later source replacement")
            path = Path(command[-1])
            relative = path.relative_to(self.root / "evidence/partial-fresh-bqrs").with_suffix(".ql").as_posix()
            self.assertEqual(path.read_bytes(), ("synthetic fresh:" + relative).encode())
            self.assertGreaterEqual(timeout_seconds, 1)
            self.assertLessEqual(timeout_seconds, control.PARTIAL_RESULT_SECONDS)
            return self.decoded
        with patch.object(control, "small_command", side_effect=decode):
            result = self.retain()
        self.assertTrue(result["all_expected_bqrs_captured"])
        self.assertFalse(result["analysis_completed"])
        self.assertEqual(result["results"][first]["bqrs_sha256"], digest(("synthetic fresh:" + first).encode()))
        self.assertEqual(result["captured_query_count"], 39)
        self.assertNotIn("queries/summary/Unexpected.ql", result["results"])

    def test_invalid_decode_preserves_raw_bqrs_and_other_semantic_results(self):
        names = sorted(self.queries)[:2]
        self.populate(names)
        with patch.object(control, "small_command", side_effect=[b'{"#select":{"tuples":[[NaN]]}}', self.decoded]):
            result = self.retain()
        self.assertEqual(result["captured_query_count"], 2)
        self.assertEqual(result["decoded_query_count"], 1)
        self.assertEqual(result["results"][names[0]]["decode_status"], "failed")
        self.assertNotIn("semantic_sha256", result["results"][names[0]])
        for name in names:
            self.assertEqual((self.root / "evidence" / result["results"][name]["path"]).read_bytes(),
                             ("synthetic fresh:" + name).encode())

    def test_partial_semantic_mismatch_is_recorded_without_hiding_other_results(self):
        names = sorted(self.original)[:2]
        self.populate(names)
        self.original[names[0]]["semantic_sha256"] = digest(b"different retained semantics")
        with patch.object(control, "small_command", return_value=self.decoded):
            result = self.retain()
        self.assertFalse(result["results"][names[0]]["retained_semantics_equal"])
        self.assertTrue(result["results"][names[1]]["retained_semantics_equal"])
        self.assertFalse(result["analysis_completed"])

    def test_ambiguous_cleanup_skips_all_capture_and_decoding(self):
        self.populate(self.queries)
        with patch.object(control, "small_command") as decoder:
            result = self.retain(cleanup_ambiguous=True)
        decoder.assert_not_called()
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["captured_query_count"], 0)
        self.assertEqual(result["reason"], "evaluator cleanup is ambiguous")
        self.assertFalse((self.root / "evidence/partial-fresh-bqrs").exists())

    def test_old_database_results_are_not_used_when_fresh_outputs_are_absent(self):
        for name in self.original:
            path = self.root / "database/results/codeql/rust-queries" / Path(name).with_suffix(".bqrs")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"retained old result")
        with patch.object(control, "small_command") as decoder:
            result = self.retain()
        decoder.assert_not_called()
        self.assertEqual(result["captured_query_count"], 0)
        self.assertEqual(result["missing_queries"], sorted(self.queries))

    def test_unsafe_and_oversized_bqrs_are_not_published_as_stable_snapshots(self):
        names = sorted(self.queries)[:3]
        self.populate(names)
        self.source(names[0]).unlink()
        self.source(names[0]).symlink_to(self.source(names[2]))
        with self.source(names[1]).open("wb") as stream:
            stream.truncate(64 * 1024**2 + 1)
        with patch.object(control, "small_command", return_value=self.decoded):
            result = self.retain()
        self.assertEqual(set(result["capture_errors"]), set(names[:2]))
        self.assertEqual(set(result["results"]), {names[2]})
        copies = list((self.root / "evidence/partial-fresh-bqrs").rglob("*.bqrs"))
        self.assertEqual(len(copies), 1)

    def test_capture_byte_bound_retains_only_prior_complete_snapshots(self):
        names = sorted(self.queries)[:2]
        self.populate(names)
        with patch.object(control, "MAX_PARTIAL_RESULT_BYTES", self.source(names[0]).stat().st_size), \
                patch.object(control, "small_command", return_value=self.decoded):
            result = self.retain()
        self.assertTrue(result["byte_budget_exhausted"])
        self.assertEqual(set(result["results"]), {names[0]})
        self.assertIn(names[1], result["capture_errors"])
        self.assertEqual(len(list((self.root / "evidence/partial-fresh-bqrs").rglob("*.bqrs"))), 1)

    def test_real_decoder_timeout_preserves_all_raw_snapshots_and_stops_at_shared_budget(self):
        self.populate(self.original)
        decoder = self.root / "decoder"
        decoder.write_text("#!" + sys.executable + "\nimport sys,time\nprint('partial decode',flush=True)\n"
                           "print('decoder stderr',file=sys.stderr,flush=True)\ntime.sleep(60)\n")
        decoder.chmod(0o700)
        with patch.object(control, "PARTIAL_RESULT_SECONDS", 2):
            result = control.retain_partial_results(decoder, self.queries, self.root, dict(os.environ),
                                                     self.original, cleanup_ambiguous=False)
        self.assertEqual(result["captured_query_count"], 38)
        self.assertEqual(result["decoded_query_count"], 0)
        self.assertTrue(result["budget_exhausted"])
        attempted = [item for item in result["results"].values() if item["decode_status"] == "failed"]
        self.assertEqual(len(attempted), 1)
        self.assertEqual(attempted[0]["decode_error"]["stopped"], "timeout")
        self.assertLess(result["seconds"], 10)
        streams = list((self.root / "evidence").glob("partial-fresh-*-decoded.stdout"))
        self.assertEqual(len(streams), 1)
        self.assertIn(b"partial decode", streams[0].read_bytes())
        self.assertIn(b"decoder stderr", streams[0].with_suffix(".stderr").read_bytes())
        self.assertEqual(len(list((self.root / "evidence/partial-fresh-bqrs").rglob("*.bqrs"))), 38)

    def run_failed_evaluation(self, *, timeout=False, retention_failure=False):
        output = self.root / "case"
        name = sorted(self.queries)[0]
        source = output / "results/codeql/rust-queries" / Path(name).with_suffix(".bqrs")
        script = "from pathlib import Path;import sys,time;p=Path(sys.argv[1]);p.parent.mkdir(parents=True);p.write_bytes(b'synthetic child BQRS');print('evaluator output',flush=True);"
        script += "time.sleep(60)" if timeout else "sys.exit(7)"
        real_run = control.run_queries
        def run(command, evidence, environment, *, progress_queries=None):
            return real_run([sys.executable, "-c", script, str(source)], evidence, environment, 1 if timeout else 5)
        with patch.dict(os.environ, {"RUNNER_TEMP": str(self.root)}), \
                patch.object(control, "prepare_database", return_value=(output / "database", {})), \
                patch.object(control, "admit_tool", return_value=(self.queries, {}, QUERY_HASHES, COMPILED_HASHES, control.SOURCE_ALLOCATION)), \
                patch.object(control, "jvm_probe", return_value=valid_report("heap-2048")["jvm_admission"]), \
                patch.object(control, "decode_retained_results", return_value=self.original), \
                patch.object(control, "evaluator_observations", return_value=valid_report("heap-2048")["observations"]), \
                patch.object(control, "run_queries", side_effect=run), \
                patch.object(control, "small_command", return_value=self.decoded), \
                patch.object(control, "retain_partial_results", side_effect=OSError("secondary retention error")
                             if retention_failure else control.retain_partial_results):
            with self.assertRaisesRegex(RuntimeError, "Retained SummaryStats control failed"):
                control.evaluate(Path("/unused/codeql"), Path("/unused/tool.tar.zst"), output, "heap-2048")
        return output, control.read_json(output / "evidence/RESULT.json")

    def test_evaluate_real_timeout_captures_child_results_and_keeps_timeout_failure(self):
        output, result = self.run_failed_evaluation(timeout=True)
        self.assertEqual(result["evaluation"]["stopped"], "timeout")
        self.assertEqual(result["failure"]["type"], "BoundedProcessError")
        self.assertEqual(result["failure"]["phase"], "evaluate")
        self.assertFalse(result["completed"])
        self.assertNotIn("results", result)
        self.assertEqual(result["partial_results"]["captured_query_count"], 1)
        snapshot = next(iter(result["partial_results"]["results"].values()))
        self.assertEqual((output / "evidence" / snapshot["path"]).read_bytes(), b"synthetic child BQRS")
        self.assertEqual(snapshot["bqrs_sha256"], digest(b"synthetic child BQRS"))

    def test_evaluate_nonzero_exit_captures_results_without_claiming_completion(self):
        _, result = self.run_failed_evaluation()
        self.assertEqual(result["evaluation"]["returncode"], 7)
        self.assertEqual(result["failure"]["phase"], "evaluate")
        self.assertFalse(result["completed"])
        self.assertEqual(result["partial_results"]["decoded_query_count"], 1)

    def test_secondary_capture_error_does_not_replace_real_timeout(self):
        _, result = self.run_failed_evaluation(timeout=True, retention_failure=True)
        self.assertEqual(result["evaluation"]["stopped"], "timeout")
        self.assertEqual(result["failure"]["type"], "BoundedProcessError")
        self.assertEqual(result["failure"]["phase"], "evaluate")
        self.assertEqual(result["partial_result_failure"], {"type": "OSError"})
        self.assertFalse(result["completed"])


class PairedComparisonTests(unittest.TestCase):
    def test_complete_equal_results_are_comparable(self):
        result = control.compare_reports(valid_report("heap-2048"), valid_report("heap-1536"))
        self.assertIs(result["completed"], True)
        self.assertEqual(result["query_count"], 39)
        self.assertIs(result["semantic_results_equal"], True)
        self.assertEqual(result["source"], SOURCE)
        self.assertIs(result["release_claim_eligible"], False)
        self.assertIs(result["sarif_published"], False)

    def test_empty_input_identity_is_rejected_even_when_both_arms_agree(self):
        baseline, candidate = valid_report("heap-2048"), valid_report("heap-1536")
        baseline["input_identity"] = candidate["input_identity"] = {}
        with self.assertRaises(control.ControlError):
            control.compare_reports(baseline, candidate)

    def test_null_or_empty_semantic_digest_is_rejected_even_when_both_arms_agree(self):
        for value in (None, ""):
            with self.subTest(value=value):
                baseline, candidate = valid_report("heap-2048"), valid_report("heap-1536")
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
                    baseline, candidate = valid_report("heap-2048"), valid_report("heap-1536")
                    for report in (baseline, candidate):
                        report[group][key] = malformed
                    with self.assertRaises(control.ControlError):
                        control.compare_reports(baseline, candidate)
        for key in ("semantic_sha256", "bqrs_sha256"):
            for malformed in (None, "", "g" * 64, "0" * 63, 1):
                with self.subTest(result_key=key, malformed=malformed):
                    baseline, candidate = valid_report("heap-2048"), valid_report("heap-1536")
                    for report in (baseline, candidate):
                        report["results"][FULL_SUMMARY][key] = malformed
                    with self.assertRaises(control.ControlError):
                        control.compare_reports(baseline, candidate)

    def test_database_zip_size_requires_a_positive_bounded_integer(self):
        for value in (None, True, False, 0, -1, 1.5, "12", control.MAX_DATABASE_ZIP_BYTES + 1):
            with self.subTest(value=value):
                baseline, candidate = valid_report("heap-2048"), valid_report("heap-1536")
                for report in (baseline, candidate):
                    report["input_identity"]["inner_bytes"] = value
                with self.assertRaises(control.ControlError):
                    control.compare_reports(baseline, candidate)

    def test_experiment_commit_must_be_the_same_full_identity(self):
        for value in (None, "", "g" * 40, "0" * 39, 1):
            with self.subTest(value=value):
                baseline, candidate = valid_report("heap-2048"), valid_report("heap-1536")
                baseline["experiment_commit"] = candidate["experiment_commit"] = value
                with self.assertRaises(control.ControlError):
                    control.compare_reports(baseline, candidate)
        baseline, candidate = valid_report("heap-2048"), valid_report("heap-1536")
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
                baseline, candidate = valid_report("heap-2048"), valid_report("heap-1536")
                baseline[group][key] = value
                candidate[group][key] = value
                with self.assertRaises(control.ControlError):
                    control.compare_reports(baseline, candidate)

    def test_failed_cli_comparison_leaves_an_incomplete_diagnostic_receipt(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            baseline, candidate, output = root / "baseline.json", root / "candidate.json", root / "comparison.json"
            first, second = valid_report("heap-2048"), valid_report("heap-1536")
            second["completed"] = False
            baseline.write_text(json.dumps(first))
            candidate.write_text(json.dumps(second))
            argv = ["codeql_summary_control.py", "compare", "--baseline", str(baseline),
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
                candidate = valid_report("heap-1536")
                candidate[group][key] = value
                with self.assertRaises(control.ControlError):
                    control.compare_reports(valid_report("heap-2048"), candidate)

    def test_noncompletion_timeout_and_nonzero_exit_are_rejected(self):
        for mutation in ("incomplete", "timeout", "nonzero"):
            with self.subTest(mutation=mutation):
                candidate = valid_report("heap-1536")
                if mutation == "incomplete":
                    candidate["completed"] = False
                elif mutation == "timeout":
                    candidate["evaluation"]["stopped"] = "timeout"
                else:
                    candidate["evaluation"]["returncode"] = 7
                with self.assertRaises(control.ControlError):
                    control.compare_reports(valid_report("heap-2048"), candidate)

    def test_missing_full_summary_result_is_rejected_despite_success_flags(self):
        candidate = valid_report("heap-1536")
        del candidate["results"][FULL_SUMMARY]
        with self.assertRaises(control.ControlError):
            control.compare_reports(valid_report("heap-2048"), candidate)

    def test_missing_compiled_identity_is_rejected_even_when_both_arms_omit_it(self):
        baseline = valid_report("heap-2048")
        candidate = valid_report("heap-1536")
        del baseline["compiled_query_hashes"][FULL_SUMMARY]
        del candidate["compiled_query_hashes"][FULL_SUMMARY]
        with self.assertRaises(control.ControlError):
            control.compare_reports(baseline, candidate)

    def test_changed_semantic_result_is_rejected(self):
        candidate = valid_report("heap-1536")
        candidate["results"][FULL_SUMMARY]["semantic_sha256"] = "9" * 64
        with self.assertRaises(control.ControlError):
            control.compare_reports(valid_report("heap-2048"), candidate)

    def test_bqrs_container_bytes_need_not_match_when_semantics_match(self):
        candidate = valid_report("heap-1536")
        candidate["results"][FULL_SUMMARY]["bqrs_sha256"] = "9" * 64
        control.compare_reports(valid_report("heap-2048"), candidate)

    def test_command_changes_outside_the_memory_pair_are_rejected(self):
        for added in ("--threads=1", "--threat-model=remote", "--expect-discarded-cache"):
            with self.subTest(added=added):
                candidate = valid_report("heap-1536")
                candidate["query_command"].append(added)
                with self.assertRaises(control.ControlError):
                    control.compare_reports(valid_report("heap-2048"), candidate)

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
                baseline, candidate = valid_report("heap-2048"), valid_report("heap-1536")
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
                baseline, candidate = valid_report("heap-2048"), valid_report("heap-1536")
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
                candidate = valid_report("heap-1536")
                candidate["query_command"].append(extra)
                with self.assertRaises(control.ControlError):
                    control.compare_reports(valid_report("heap-2048"), candidate)

    def test_ram_resolution_and_execution_budget_changes_are_rejected(self):
        for field, value in (("requested_ram_mb", 16000), ("threads", 1),
                             ("deadline_seconds", 900), ("heap_mb", 4096),
                             ("native_mb", 9000), ("reserved_mb", 0)):
            with self.subTest(field=field):
                candidate = valid_report("heap-1536")
                candidate["configuration"][field] = value
                with self.assertRaises(control.ControlError):
                    control.compare_reports(valid_report("heap-2048"), candidate)
        candidate = valid_report("heap-1536")
        candidate["ram_resolution"] = ["-J-Xmx4096M", "--off-heap-ram=8305"]
        with self.assertRaises(control.ControlError):
            control.compare_reports(valid_report("heap-2048"), candidate)

    def test_same_profile_twice_is_not_a_paired_experiment(self):
        with self.assertRaises(control.ControlError):
            control.compare_reports(valid_report("heap-2048"), valid_report("heap-2048"))

    def test_diagnostic_reports_cannot_claim_release_or_publication(self):
        for field in ("release_claim_eligible", "sarif_published"):
            with self.subTest(field=field):
                candidate = valid_report("heap-1536")
                candidate[field] = True
                with self.assertRaises(control.ControlError):
                    control.compare_reports(valid_report("heap-2048"), candidate)


class SummaryAllocationEvidenceTests(unittest.TestCase):
    def test_retained_source_is_the_failed_macos_database_not_a_new_package_identity(self):
        self.assertEqual(control.SOURCE, SOURCE)
        self.assertEqual(control.INNER_MEMBER, "qperiapt-codeql-macos/diagnostics/database.zip")
        self.assertEqual(control.INNER_BYTES, 269008328)
        self.assertEqual(control.INNER_SHA256, "c8bdc47f5cbb0b6d83c0d60c63e8ff9f80ad63683c58cdf32311dd8bb6c9dbf1")
        self.assertEqual(control.INPUT_IDENTITY["cache_file_count"], 1437)
        self.assertEqual(control.INPUT_IDENTITY["retained_result_count"], 38)
        self.assertEqual(control.INPUT_IDENTITY["metadata_git_sha"], "56f191f04a57806869b8a03078ee4d27ffe900ab")

    def test_neither_arm_reruns_the_known_failed_allocation(self):
        for profile, (heap, native) in control.PROFILES.items():
            self.assertGreater(native, 9329)
            self.assertEqual(heap + native + control.RESERVED_MB,
                             {"heap-2048": 14000, "heap-1536": 14000,
                              "memory-56000": 56000, "memory-120000": 120000, "memory-120000-threads-16": 120000}[profile])
            self.assertIn("-J-XX:+PrintFlagsFinal", control.query_command(
                Path("/tool/codeql"), Path("/case/database"), Path("/case"), profile))

    def test_equal_forged_cache_input_cannot_pass_pair_comparison(self):
        for key, value in (("cache_file_count", 1436), ("retained_result_count", 39),
                           ("cache_inventory_sha256", "e" * 64), ("inner_sha256", "e" * 64),
                           ("metadata_git_sha", "a" * 40)):
            with self.subTest(key=key):
                first, second = valid_report("heap-2048"), valid_report("heap-1536")
                first["input_identity"][key] = second["input_identity"][key] = value
                with self.assertRaises(control.ControlError):
                    control.compare_reports(first, second)

    def test_bundle_jvm_probe_fails_before_long_queries_for_ignored_or_bad_flags(self):
        output = b"   size_t MaxHeapSize = 2147483648 {product} {command line}\n2.27.2\n"
        with patch.object(control, "small_command", return_value=output):
            self.assertEqual(control.jvm_probe(Path("/tool/codeql"), Path("/case"), {}, "heap-2048"),
                             {"max_heap_bytes_observed": [2147483648], "codeql_version": "2.27.2"})
        for wrong in (b"2.27.2\n", output.replace(b"2147483648", b"1073741824"),
                      output.replace(b"2.27.2", b"2.27.4")):
            with patch.object(control, "small_command", return_value=wrong), self.assertRaises(control.ControlError):
                control.jvm_probe(Path("/tool/codeql"), Path("/case"), {}, "heap-2048")

    def test_actual_heap_and_offheap_are_required_in_addition_to_requested_arguments(self):
        for replacement in (None, {}, {"max_heap_bytes_observed": [1024**3]}):
            candidate = valid_report("heap-1536")
            candidate["observations"] = replacement
            with self.subTest(replacement=replacement), self.assertRaises(control.ControlError):
                control.compare_reports(valid_report("heap-2048"), candidate)
        for field, value in (("max_heap_bytes_observed", [1536 * 1024**2, 1536 * 1024**2]),
                             ("off_heap_mb_observed", [9329]), ("evaluator_start_lines", 0),
                             ("pause_count", -1), ("eviction_pause_count", 13)):
            candidate = valid_report("heap-1536")
            candidate["observations"][field] = value
            with self.subTest(field=field), self.assertRaises(control.ControlError):
                control.compare_reports(valid_report("heap-2048"), candidate)

    def test_success_receipt_must_bind_the_executed_command_and_finite_elapsed_time(self):
        for field, value in (("command", ["unrelated", "command"]), ("seconds", None),
                             ("seconds", -1), ("seconds", float("inf")), ("seconds", 20000),
                             ("cleanup_ambiguous", True)):
            candidate = valid_report("heap-1536")
            candidate["evaluation"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(control.ControlError):
                control.compare_reports(valid_report("heap-2048"), candidate)

    def test_retained_bqrs_semantics_are_checked_even_when_new_arms_agree(self):
        first, second = valid_report("heap-2048"), valid_report("heap-1536")
        query = next(iter(first["retained_results"]))
        first["retained_results"][query]["semantic_sha256"] = "f" * 64
        second["retained_results"][query]["semantic_sha256"] = "f" * 64
        with self.assertRaisesRegex(control.ControlError, "retained result"):
            control.compare_reports(first, second)

    def test_old_and_fresh_binary_encodings_may_differ_when_all_semantics_match(self):
        first, second = valid_report("heap-2048"), valid_report("heap-1536")
        for report in (first, second):
            for result in report["results"].values():
                result["bqrs_sha256"] = "b" * 64
        result = control.compare_reports(first, second)
        self.assertTrue(result["retained_semantic_results_equal"])
        self.assertFalse(result["production_default_validated"])
        self.assertIn("Warm-cache", result["cache_scope"])

    def test_a_claim_of_cold_cache_start_cannot_pass(self):
        first, second = valid_report("heap-2048"), valid_report("heap-1536")
        first["cache_scope"] = second["cache_scope"] = "cold cache"
        with self.assertRaises(control.ControlError):
            control.compare_reports(first, second)

    def test_missing_database_creation_sha_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            members = database_members()
            info, metadata = members[0]
            members[0] = (info, metadata.replace(b"  sha: 56f191f04a57806869b8a03078ee4d27ffe900ab\n", b""))
            source = root / "source.zip"
            source.write_bytes(archive_bytes(members))
            with self.assertRaisesRegex(control.ControlError, "creation commit"):
                control.restore_database(source, root / "destination")


class SnapshotBindingTests(unittest.TestCase):
    def test_replaced_outer_path_cannot_change_the_bytes_parsed_after_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.zip"
            original = archive_bytes([zip_member("expected", b"admitted bytes")])
            replacement = archive_bytes([zip_member("wrong", b"different bytes")])
            path.write_bytes(original)
            with control.verified_source(path, size=len(original), digest=digest(original), label="fixture") as private:
                path.unlink()
                path.write_bytes(replacement)
                with zipfile.ZipFile(private) as archive:
                    self.assertEqual(archive.namelist(), ["expected"])
                    self.assertEqual(archive.read("expected"), b"admitted bytes")

    def test_wrong_digest_and_symlink_cannot_be_admitted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "input"
            path.write_bytes(b"input")
            for selected, expected in ((path, "0" * 64), (root / "link", digest(b"input"))):
                if selected != path:
                    selected.symlink_to(path)
                with self.subTest(selected=selected), self.assertRaises(control.ControlError):
                    with control.verified_source(selected, size=5, digest=expected, label="fixture"):
                        self.fail("wrong identity was admitted")

    def test_in_place_mutation_during_snapshot_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            original = b"a" * (2 * 1024**2)
            path.write_bytes(original)
            actual_consumer = control.consume_regular_snapshot
            def mutate_mid_read(selected, **arguments):
                original_capture = arguments["consume"]
                altered = False
                def capture(block):
                    nonlocal altered
                    original_capture(block)
                    if not altered:
                        altered = True
                        with selected.open("r+b") as output:
                            output.seek(1024**2)
                            output.write(b"b")
                arguments["consume"] = capture
                return actual_consumer(selected, **arguments)
            with patch.object(control, "consume_regular_snapshot", side_effect=mutate_mid_read):
                with self.assertRaises(control.ControlError):
                    with control.verified_source(path, size=len(original), digest=digest(original), label="fixture"):
                        self.fail("mutated snapshot was admitted")

    def test_result_decoder_reads_and_publishes_the_same_snapshot_as_its_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result_root, evidence = root / "results", root / "evidence"
            result_root.mkdir()
            evidence.mkdir()
            bqrs = result_root / "a.bqrs"
            bqrs.write_bytes(b"authenticated original BQRS")
            def decode(command, prefix, environment):
                bqrs.write_bytes(b"later original-path replacement")
                self.assertEqual(Path(command[-1]).read_bytes(), b"authenticated original BQRS")
                self.assertEqual(Path(command[-1]), evidence / "fresh-bqrs/a.bqrs")
                return b'{"#select":{"tuples":[[1]]}}'
            with patch.object(control, "small_command", side_effect=decode):
                results = control.decode_query_results(Path("/unused/codeql"), {"a.ql": Path("/a.ql")},
                                                       result_root, evidence, {}, "fresh-")
            self.assertEqual(results["a.ql"]["bqrs_sha256"], digest(b"authenticated original BQRS"))


class EvaluatorLogObservationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.evidence = Path(self.temporary.name)
        (self.evidence / "evaluator").mkdir()
        self.raw = (
            "[2026-11-09 10:00:00] This is codeql execute queries -J-Xmx2048M --off-heap-ram=10643 --threads=4\n"
            "[2026-11-09 10:00:01] [PROGRESS] Starting evaluation of SummaryStats.ql.\n"
            "[2026-11-09 10:00:02] Pausing evaluation to hard-clear memory at sequence stamp o+0\n"
            "[2026-11-09 10:00:03] Pausing evaluation to evict 200.12MiB ARRAYS and 90.4MiB VITAL\n"
            "[2026-11-09 10:00:04] TaintReach::Flow::Stage4::rel (iteration 281)\n"
            "[2026-11-09 10:00:05] [PROGRESS] Evaluation done; writing results to fresh/SummaryStats.bqrs\n"
        ).encode()
        (self.evidence / "evaluator/run.log").write_bytes(self.raw)
        (self.evidence / "query.stdout").write_bytes(
            b"   size_t MaxHeapSize = 2147483648 {product} {command line}\n")
        (self.evidence / "query.stderr").write_bytes(b"")

    def test_raw_logs_and_actual_jvm_allocation_produce_bounded_observations(self):
        result = control.evaluator_observations(self.evidence)
        control.validate_observations(result, "heap-2048")
        self.assertEqual(result["pause_count"], 2)
        self.assertEqual(result["eviction_pause_count"], 1)
        self.assertEqual(result["eviction_categories"], {"ARRAYS": 1, "VITAL": 1})
        self.assertEqual(result["query_starts"], 1)
        self.assertEqual(result["query_completions"], 1)
        self.assertEqual(result["max_taint_stage_iterations"], {"4": 281})
        self.assertEqual(result["first_timestamp"], "2026-11-09 10:00:00")
        self.assertEqual(result["last_timestamp"], "2026-11-09 10:00:05")
        self.assertEqual(result["logs"][0]["sha256"], digest(self.raw))

    def test_early_partial_logs_remain_observable_but_do_not_claim_actual_allocation(self):
        (self.evidence / "query.stdout").unlink()
        result = control.evaluator_observations(self.evidence)
        self.assertEqual(result["pause_count"], 2)
        with self.assertRaises(control.ControlError):
            control.validate_observations(result, "heap-2048")

    def test_repeated_log_prefixes_do_not_fabricate_observations(self):
        malformed = (
            "[PROGRESS] " + "] Loaded a" * 16000 + "\n"
            + "Pausing evaluation to evict " + "." * 128000 + "x\n"
            + "TaintReach::" + "Stage0::" * 16000 + "x\n"
        ).encode()
        (self.evidence / "evaluator/run.log").write_bytes(self.raw + malformed)
        result = control.evaluator_observations(self.evidence)
        self.assertEqual(result["precompiled_query_loads"], [])
        self.assertEqual(result["max_taint_stage_iterations"], {"4": 281})
        self.assertEqual(result["eviction_categories"], {"ARRAYS": 1, "VITAL": 1})
        self.assertEqual(result["eviction_pause_count"], 2)

    def test_log_markers_preserve_first_stage_last_iteration_and_complete_path(self):
        extra = (
            "[PROGRESS] Loaded /tmp/a ] Loaded b.qlx. \t\n"
            "TaintReach::Stage2::a (iteration 3) Stage4::b (iteration 19)\n"
            "Pausing evaluation to evict 1.2MiB ARRAYS and ..GiB VITAL and 2B ARRAYS\n"
        ).encode()
        (self.evidence / "evaluator/run.log").write_bytes(self.raw + extra)
        result = control.evaluator_observations(self.evidence)
        self.assertEqual(result["precompiled_query_loads"], ["/tmp/a ] Loaded b.qlx"])
        self.assertEqual(result["max_taint_stage_iterations"], {"4": 281, "2": 19})
        self.assertEqual(result["eviction_categories"], {"ARRAYS": 2, "VITAL": 2})

    def test_final_unterminated_line_cannot_complete_after_observation_deadline(self):
        (self.evidence / "evaluator/run.log").write_bytes(b"last unterminated line")
        clock = [0.0]
        original_consumer = control.evaluator_logs.consume_regular_snapshot
        def consume_then_expire(*args, **kwargs):
            snapshot = original_consumer(*args, **kwargs)
            clock[0] = control.OBSERVATION_SECONDS + 1
            return snapshot
        with patch.object(control.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(control.evaluator_logs, "consume_regular_snapshot", side_effect=consume_then_expire):
            with self.assertRaisesRegex(control.ControlError, "observation exceeded"):
                control.evaluator_observations(self.evidence)

    def test_heap_observation_never_joins_separate_physical_lines(self):
        (self.evidence / "query.stdout").write_bytes(b"size_t MaxHeapSize\n = 2147483648 \n")
        result = control.evaluator_observations(self.evidence)
        self.assertEqual(result["max_heap_bytes_observed"], [])
        with self.assertRaises(control.ControlError):
            control.validate_observations(result, "heap-2048")

    def test_observation_rejects_unbounded_or_redirected_log_input(self):
        for field in ("MAX_EVALUATOR_LOG_BYTES", "MAX_EVALUATOR_TOTAL_BYTES"):
            with self.subTest(field=field), patch.object(control, field, 1):
                with self.assertRaises((control.ControlError, EvidenceIOError)):
                    control.evaluator_observations(self.evidence)
        (self.evidence / "evaluator/link.log").symlink_to(self.evidence / "query.stdout")
        with self.assertRaises(control.ControlError):
            control.evaluator_observations(self.evidence)


if __name__ == "__main__":
    unittest.main()

