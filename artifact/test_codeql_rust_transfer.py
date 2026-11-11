from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

from codeql_rust_profile import ProfileRun
import codeql_rust_transfer as transfer


def profile_fixture(source=None, *, attempt="1"):
    return {"schema": 1, "profile": "macos", "target": transfer.TARGET,
            "source_commit": "a" * 40, "run_id": "123", "run_attempt": attempt,
            "compiler_host": transfer.TARGET, "compiler": transfer.COMPILER,
            "codeql_version": transfer.VERSION, "query_threads": 2, "query_ram_mb": 5500,
            "active_target_quality_passed": True, "paired_target_quality_passed": False,
            "source_sha256": source or {}}


def record_fixture(profile, profile_hash, evidence=None):
    return {"schema": 1, "profile": "macos", "target": transfer.TARGET,
            "source_commit": profile["source_commit"], "run_id": profile["run_id"],
            "origin_attempt": profile["run_attempt"], "origin_host": "darwin",
            "compiler_host": transfer.TARGET, "compiler": transfer.COMPILER,
            "codeql_version": transfer.VERSION, "profile_sha256": profile_hash,
            "database": {"file": "database.zip", "bytes": 100, "sha256": "b" * 64},
            "database_inventory_sha256": "c" * 64, "database_members": 3, "database_expanded_bytes": 200,
            "evidence": evidence or {name: {"bytes": 100, "sha256": profile_hash if name == "PROFILE.json" else "d" * 64}
                                     for name in transfer.REQUIRED_EVIDENCE}}


class RustTransferTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "repository"
        (self.root / "src").mkdir(parents=True)
        (self.root / "src/lib.rs").write_text("pub fn active_macos_code() {}\n")
        self.source = {"src/lib.rs": self.digest(self.root / "src/lib.rs")}
        self.profile = profile_fixture(self.source)
        self.incoming = self.base / "temporary/qperiapt-codeql-macos-transfer"
        (self.incoming / "evidence").mkdir(parents=True)
        for name in transfer.REQUIRED_EVIDENCE:
            (self.incoming / "evidence" / name).write_text(json.dumps(self.profile if name == "PROFILE.json" else []))
        self.archive = self.incoming / "database.zip"
        self.make_archive(self.archive)
        self.record = record_fixture(self.profile, self.digest(self.incoming / "evidence/PROFILE.json"),
                    {p.name: {"bytes": p.stat().st_size, "sha256": self.digest(p)}
                     for p in (self.incoming / "evidence").iterdir()})
        self.record["database"].update(bytes=self.archive.stat().st_size, sha256=self.digest(self.archive))
        self.record.update(transfer.bundle_inventory(self.archive))
        self.write_record()
        self.environment = {"CODEQL_EXPECTED_COMMIT": "a" * 40, "GITHUB_RUN_ID": "123",
                            "GITHUB_RUN_ATTEMPT": "2", "CODEQL_TRANSFER_ATTEMPT": "1",
                            "CODEQL_TRANSFER_SHA256": self.digest(self.incoming / "TRANSFER.json")}
        self.run = ProfileRun(self.root, self.base / "output", Path(sys.executable), {}, host="linux")
        self.run.configuration = dataclasses.replace(self.run.configuration,
              database=self.base / "temporary/qperiapt-codeql-database/rust", runner_temp=self.base / "temporary")
        self.patches = [mock.patch.dict(os.environ, self.environment),
                        mock.patch.object(transfer.quality, "require_clean_checkout"),
                        mock.patch.object(transfer.quality, "tracked_rust_paths", return_value=frozenset(self.source))]
        for patch in self.patches:
            patch.start(); self.addCleanup(patch.stop)

    @staticmethod
    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def make_archive(path, extra=()):
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("rust/codeql-database.yml", "primaryLanguage: rust\nfinalised: true\n")
            archive.writestr("rust/src.zip", b"source archive fixture")
            archive.writestr("rust/db-rust/rust.dbscheme", b"schema fixture")
            for name, data in extra:
                archive.writestr(name, data)

    def write_record(self):
        (self.incoming / "TRANSFER.json").write_text(json.dumps(self.record))

    def check_record(self, record=None, profile=None, *, attempt=2):
        transfer.validate_transfer_record(record or self.record, profile or self.profile,
            self.digest(self.incoming / "evidence/PROFILE.json"), expected_commit="a" * 40,
            run_id="123", analysis_attempt=attempt)

    def unbundle(self, label, argv, **options):
        self.assertEqual(label, "transfer-unbundle")
        self.assertEqual(argv[1:3], ["database", "unbundle"])
        self.assertIn("--target=" + str(self.run.configuration.database.parent), argv)
        self.assertIn("--name=rust", argv)
        with zipfile.ZipFile(argv[3]) as archive:
            archive.extractall(self.run.configuration.database.parent)
        return b""

    def test_same_run_transfer_allows_retry_without_rewriting_the_origin(self):
        self.check_record(attempt=1)
        self.check_record(attempt=2)
        original = (self.incoming / "evidence/PROFILE.json").read_bytes()
        with mock.patch.object(self.run, "command", side_effect=self.unbundle) as command:
            transfer.import_database(self.run)
        command.assert_called_once()
        self.assertEqual((self.run.evidence / "PROFILE.json").read_bytes(), original)
        self.assertEqual(json.loads(original)["run_attempt"], "1")
        self.assertEqual((self.run.evidence / "TRANSFER.json").read_bytes(), (self.incoming / "TRANSFER.json").read_bytes())
        self.assertFalse((self.run.evidence / "ANALYSIS.json").exists())
        self.assertFalse((self.run.evidence / "results.sarif").exists())
        self.assertTrue((self.run.configuration.database / "db-rust/rust.dbscheme").is_file())

    def test_transfer_identity_rejects_mixed_source_host_target_attempt_and_types(self):
        mutations = [("schema", True), ("profile", "native"), ("target", "wasm32-unknown-unknown"),
                     ("source_commit", "b" * 40), ("run_id", "124"), ("origin_attempt", "3"),
                     ("origin_attempt", 1), ("origin_host", "linux"), ("compiler_host", "x86_64-unknown-linux-gnu"),
                     ("compiler", "1.98.2"), ("codeql_version", "2.27.1"), ("profile_sha256", "e" * 64),
                     ("database_members", True), ("database_expanded_bytes", 0),
                     ("database_inventory_sha256", "C" * 64), ("extra", 1)]
        for key, value in mutations:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                changed = copy.deepcopy(self.record); changed[key] = value
                self.check_record(changed)
        for key, value in [("query_threads", True), ("query_ram_mb", 14000),
                           ("active_target_quality_passed", False), ("paired_target_quality_passed", True)]:
            with self.subTest(profile_key=key), self.assertRaises(ValueError):
                self.check_record(profile=dict(self.profile, **{key: value}))

    def test_invalid_database_and_evidence_records_are_rejected(self):
        for key, value in [("file", "../database.zip"), ("bytes", True), ("bytes", transfer.MAX_BUNDLE + 1),
                           ("sha256", "x" * 64), ("extra", 0)]:
            with self.subTest(database_key=key), self.assertRaises(ValueError):
                record = copy.deepcopy(self.record); record["database"][key] = value
                self.check_record(record)
        for name in ("../escape", "ANALYSIS.json", "TRANSFER.json", "analyze.json", "transfer-unbundle.stdout"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                record = copy.deepcopy(self.record)
                record["evidence"][name] = {"bytes": 0, "sha256": "d" * 64}
                self.check_record(record)
        record = copy.deepcopy(self.record); del record["evidence"]["Metrics.json"]
        with self.assertRaises(ValueError):
            self.check_record(record)

    def test_tampered_job_anchor_stops_before_import(self):
        with mock.patch.dict(os.environ, {"CODEQL_TRANSFER_SHA256": "f" * 64}), \
                mock.patch.object(self.run, "command") as command, self.assertRaisesRegex(ValueError, "origin job output"):
            transfer.import_database(self.run)
        command.assert_not_called()
        self.assertEqual(list(self.run.evidence.iterdir()), [])

    def test_wrong_selected_origin_attempt_stops_before_import(self):
        with mock.patch.dict(os.environ, {"CODEQL_TRANSFER_ATTEMPT": "2"}), \
                mock.patch.object(self.run, "command") as command, self.assertRaisesRegex(ValueError, "origin attempt"):
            transfer.import_database(self.run)
        command.assert_not_called()

    def test_changed_bundle_stops_before_codeql(self):
        self.archive.write_bytes(self.archive.read_bytes() + b"changed")
        with mock.patch.object(self.run, "command") as command, self.assertRaisesRegex(ValueError, "file bytes differ"):
            transfer.import_database(self.run)
        command.assert_not_called()
        self.assertFalse(self.run.configuration.database.exists())

    def test_changed_quality_evidence_stops_before_codeql(self):
        (self.incoming / "evidence/Metrics.json").write_text("[1]")
        with mock.patch.object(self.run, "command") as command, self.assertRaisesRegex(ValueError, "file bytes differ"):
            transfer.import_database(self.run)
        command.assert_not_called()

    def test_different_current_source_stops_before_codeql(self):
        (self.root / "src/lib.rs").write_text("pub fn different() {}\n")
        with mock.patch.object(self.run, "command") as command, self.assertRaisesRegex(ValueError, "source bytes differ"):
            transfer.import_database(self.run)
        command.assert_not_called()

    def test_unexpected_transfer_files_fail(self):
        extra = self.incoming / "extra.txt"; extra.write_text("extra")
        with self.assertRaisesRegex(ValueError, "extra or missing"):
            transfer.import_database(self.run)

    @unittest.skipIf(os.name == "nt", "database transfer executes on macOS and Linux")
    def test_symlinked_transfer_files_fail(self):
        original = self.incoming / "evidence/Metrics.json"
        backup = self.base / "metrics"; original.replace(backup); original.symlink_to(backup)
        with mock.patch.object(self.run, "command") as command, self.assertRaises(ValueError):
            transfer.import_database(self.run)
        command.assert_not_called()

    def test_failed_unbundle_never_admits_analysis(self):
        with mock.patch.object(self.run, "command", side_effect=ValueError("unbundle failed")), \
                self.assertRaisesRegex(ValueError, "unbundle failed"):
            transfer.import_database(self.run)
        self.assertFalse((self.run.evidence / "TRANSFER.json").exists())
        self.assertFalse((self.run.evidence / "ANALYSIS.json").exists())

    def test_archive_rejects_escape_symlink_collision_and_previous_results(self):
        cases = [("../escape", b"bad"), ("rust/../escape", b"bad"), ("rust\\escape", b"bad"),
                 ("rust/results/old.bqrs", b"stale"), ("rust/db-rust/rust.dbscheme/child", b"collision")]
        for index, member in enumerate(cases):
            path = self.base / f"bad-{index}.zip"; self.make_archive(path, [member])
            with self.subTest(name=member[0]), self.assertRaises(ValueError):
                transfer.bundle_inventory(path)
        path = self.base / "symlink.zip"
        self.make_archive(path)
        with zipfile.ZipFile(path, "a") as archive:
            member = zipfile.ZipInfo("rust/link"); member.create_system = 3
            member.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(member, "outside")
        with self.assertRaisesRegex(ValueError, "non-regular"):
            transfer.bundle_inventory(path)
        path = self.base / "file-directory-collision.zip"
        self.make_archive(path, [("rust/collision", b"file"), ("rust/collision/", b"")])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            transfer.bundle_inventory(path)

    def test_export_excludes_cached_results_and_preserves_origin_profile(self):
        origin = ProfileRun(self.root, self.base / "origin", Path(sys.executable), {}, host="darwin")
        origin.configuration = dataclasses.replace(origin.configuration,
            runner_temp=self.base / "origin-temporary", database=self.base / "origin-database")
        for file in (self.incoming / "evidence").iterdir():
            (origin.evidence / file.name).write_bytes(file.read_bytes())
        origin.configuration.runner_temp.mkdir()
        def bundle(label, argv, **options):
            self.assertEqual(label, "transfer-bundle")
            for option in ("--no-include-results", "--no-include-logs", "--no-include-temp", "--cache-cleanup=clear", "--name=rust"):
                self.assertIn(option, argv)
            self.make_archive(Path(next(value.split("=", 1)[1] for value in argv if value.startswith("--output="))))
            return b""
        with mock.patch.object(origin, "command", side_effect=bundle):
            transfer.export_database(origin)
        directory = transfer.transfer_directory(origin.configuration)
        self.assertEqual((directory / "evidence/PROFILE.json").read_bytes(), (origin.evidence / "PROFILE.json").read_bytes())
        record = json.loads((directory / "TRANSFER.json").read_text())
        self.assertEqual(record["origin_attempt"], "1")
        self.assertEqual(record["database"]["sha256"], self.digest(directory / "database.zip"))
        with self.assertRaisesRegex(ValueError, "must be fresh"):
            transfer.export_database(origin)

    def test_archive_rejects_raw_nul_names_before_zipinfo_truncation(self):
        path = self.base / "nul-name.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("rust/codeql-database.yml", b"metadata")
            archive.writestr("rust/src.zipXevil", b"source")
            archive.writestr("rust/db-rust/rust.dbscheme", b"schema")
        data = path.read_bytes()
        self.assertEqual(data.count(b"rust/src.zipXevil"), 2)
        path.write_bytes(data.replace(b"rust/src.zipXevil", b"rust/src.zip\x00evil"))
        with zipfile.ZipFile(path) as archive:
            self.assertIn("rust/src.zip", archive.namelist())
            self.assertNotEqual(archive.getinfo("rust/src.zip").orig_filename, "rust/src.zip")
        with self.assertRaisesRegex(ValueError, "unsafe"):
            transfer.bundle_inventory(path)


if __name__ == "__main__":
    unittest.main()
