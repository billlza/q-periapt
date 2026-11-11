from pathlib import Path
from contextlib import contextmanager, ExitStack
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

import codeql_memory_control as control
from bounded_process import BoundedProcessError


class MemoryControlTests(unittest.TestCase):
    @contextmanager
    def _database_fixture(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            manifest = json.loads(control.QUERY_MANIFEST.read_text())
            suite = ("queries:\n" + "".join(
                "  query: " + control.QUERY_PREFIX + name + "\n"
                for name in manifest["query_hashes"])).encode()
            metadata = ("\nfinalised: true\n  sha: " + control.MERGE_SHA
                        + "\n  cliVersion: 2.27.1\nprimaryLanguage: rust\n").encode()

            def database(path, payload):
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr("db-rust/control.txt", payload)
                    archive.writestr("codeql-database.yml", metadata)
                    archive.writestr("temp/analysisConfig.json",
                                     json.dumps({"extensionPacks": [], "threatModels": ["local"]}))
                    archive.writestr("temp/config-queries.qls", suite)
                    for number in range(38):
                        archive.writestr(f"results/retained-{number}.bqrs", b"fixture")

            admitted = root / "admitted.zip"
            database(admitted, b"trusted-data\n")
            replacement = root / "replacement.zip"
            database(replacement, b"altered-data\n")
            with zipfile.ZipFile(admitted) as archive:
                expected_members = len(archive.infolist())
                expected_uncompressed = sum(member.file_size for member in archive.infolist())
            outer = root / "outer.zip"
            with zipfile.ZipFile(outer, "w") as archive:
                archive.write(admitted, "db-rust-partial.zip")
            output = root / "output"
            output.mkdir()
            actual_require, actual_infolist = control.require, zipfile.ZipFile.infolist
            last_members = []

            def record_members(archive):
                nonlocal last_members
                last_members = actual_infolist(archive)
                return last_members

            def fixture_require(condition, message):
                if message == "retained database inventory differs":
                    # Substitute only the two aggregate corpus constants for
                    # this small real ZIP; member and 39-query checks stay real.
                    condition = (len(last_members) == len({m.filename for m in last_members})
                                 == expected_members
                                 and sum(m.file_size for m in last_members) == expected_uncompressed)
                return actual_require(condition, message)

            def download_fixture(path):
                shutil.copyfile(outer, path)
                actual_require(path.stat().st_size == control.ARCHIVE_BYTES
                               and control.sha(path) == control.ARCHIVE_SHA,
                               "artifact digest differs")

            with ExitStack() as patches:
                for name, value in {
                    "DB_BYTES": admitted.stat().st_size,
                    "DB_SHA": control.sha(admitted),
                    "SUITE_SHA": hashlib.sha256(suite).hexdigest(),
                    "ARCHIVE_BYTES": outer.stat().st_size,
                    "ARCHIVE_SHA": control.sha(outer),
                }.items():
                    patches.enter_context(mock.patch.object(control, name, value))
                patches.enter_context(mock.patch.object(control, "require", side_effect=fixture_require))
                patches.enter_context(mock.patch.object(zipfile.ZipFile, "infolist", record_members))
                patches.enter_context(mock.patch.object(control, "download", side_effect=download_fixture))
                yield root, admitted, replacement, output

    def test_verified_database_fixture_inspects_and_extracts(self):
        with self._database_fixture() as (_root, admitted, _replacement, output):
            queries = control.inspect_database(admitted)
            database, extracted_queries = control.prepare_database(output)
            self.assertEqual(len(queries), 39)
            self.assertEqual(extracted_queries, queries)
            self.assertEqual((database / "db-rust/control.txt").read_bytes(), b"trusted-data\n")

    def test_database_path_replacement_after_hash_is_rejected(self):
        with self._database_fixture() as (_root, admitted, replacement, _output):
            identity = (admitted.stat().st_dev, admitted.stat().st_ino)
            actual_digest = hashlib.file_digest
            replaced = False

            def digest(source, algorithm, **kwargs):
                nonlocal replaced
                result = actual_digest(source, algorithm, **kwargs)
                observed = os.fstat(source.fileno())
                if not replaced and (observed.st_dev, observed.st_ino) == identity:
                    os.replace(replacement, admitted)
                    replaced = True
                return result

            with mock.patch.object(hashlib, "file_digest", side_effect=digest):
                with self.assertRaisesRegex(control.ControlError, "archive.*changed"):
                    control.inspect_database(admitted)
                    self.fail("inspection accepted an archive replaced after its actual pin hash")
            self.assertTrue(replaced)

    def test_database_path_replacement_after_inspection_is_rejected(self):
        with self._database_fixture() as (_root, _admitted, replacement, output):
            actual_parse = control.parse_strict_json_bytes
            replaced = False

            def parse(data, *, label):
                nonlocal replaced
                result = actual_parse(data, label=label)
                if label == "frozen query manifest" and not replaced:
                    os.replace(replacement, output / "db.zip")
                    replaced = True
                return result

            with mock.patch.object(control, "parse_strict_json_bytes", side_effect=parse):
                with self.assertRaisesRegex(control.ControlError, "archive.*changed"):
                    database, _queries = control.prepare_database(output)
                    self.assertEqual((database / "db-rust/control.txt").read_bytes(),
                                     b"trusted-data\n", "extraction consumed the unpinned replacement")
                    self.fail("preparation accepted a replaced database archive")
            self.assertTrue(replaced)
            self.assertFalse((output / "database/db-rust/control.txt").exists())

    def test_database_in_place_change_after_hash_is_rejected(self):
        with self._database_fixture() as (_root, admitted, replacement, _output):
            before = admitted.stat()
            replacement_bytes = replacement.read_bytes()
            self.assertEqual(len(replacement_bytes), before.st_size)
            actual_digest = hashlib.file_digest
            changed = False

            def digest(source, algorithm, **kwargs):
                nonlocal changed
                result = actual_digest(source, algorithm, **kwargs)
                observed = os.fstat(source.fileno())
                if not changed and (observed.st_dev, observed.st_ino) == (before.st_dev, before.st_ino):
                    with admitted.open("r+b") as destination:
                        destination.write(replacement_bytes)
                    changed = True
                return result

            with mock.patch.object(hashlib, "file_digest", side_effect=digest):
                with self.assertRaisesRegex(control.ControlError, "archive.*changed"):
                    control.inspect_database(admitted)
                    self.fail("inspection accepted an equal-length in-place change after its pin hash")
            after = admitted.stat()
            self.assertTrue(changed)
            self.assertEqual((after.st_dev, after.st_ino, after.st_size),
                             (before.st_dev, before.st_ino, before.st_size))

    def test_archive_escape_and_links_are_rejected(self):
        for name in ("/outside", "../outside", "a/../../outside", "a\\outside", "a//b"):
            with self.subTest(name=name), self.assertRaises(control.ControlError):
                control.safe_name(zipfile.ZipInfo(name))
        link = zipfile.ZipInfo("link")
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaises(control.ControlError):
            control.safe_name(link)

    def test_wrong_database_is_rejected_before_extraction(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "different.zip"
            path.write_bytes(b"not the selected database")
            with self.assertRaises(control.ControlError):
                control.inspect_database(path)

    def test_memory_is_the_only_evaluator_difference(self):
        commands = [control.query_command(Path('/tool/codeql'), Path('/db'), Path('/case'), p)
                    for p in ('baseline', 'more-native')]
        strip_memory = lambda c: [v for v in c if not v.startswith(('-J-Xmx', '--off-heap-ram='))]
        self.assertEqual(strip_memory(commands[0]), strip_memory(commands[1]))
        self.assertEqual({heap + native for heap, native, _ in control.PROFILES.values()}, {12686})
        for command in commands:
            self.assertNotIn('--no-rerun', command)
            self.assertIn('--threat-model=local', command)
            self.assertIn('--threads=4', command)

    def test_reusable_cache_changes_only_cache_expectation(self):
        baseline = control.query_command(Path('/tool/codeql'), Path('/db'), Path('/case'),
                                         'baseline')
        reusable = control.query_command(Path('/tool/codeql'), Path('/db'), Path('/case'),
                                         'reusable-cache')
        self.assertEqual(baseline.count('--expect-discarded-cache'), 1)
        self.assertEqual(reusable.count('--no-expect-discarded-cache'), 1)
        self.assertEqual(reusable, [
            '--no-expect-discarded-cache' if value == '--expect-discarded-cache' else value
            for value in baseline
        ])
        self.assertNotIn('--no-rerun', reusable)

    def test_single_thread_changes_only_execution_concurrency(self):
        baseline = control.query_command(Path('/tool/codeql'), Path('/db'), Path('/case'),
                                         'baseline')
        single = control.query_command(Path('/tool/codeql'), Path('/db'), Path('/case'),
                                       'single-thread')
        self.assertEqual(baseline.count('--threads=4'), 1)
        self.assertEqual(single, [
            '--threads=1' if value == '--threads=4' else value for value in baseline
        ])
        self.assertEqual(control.PROFILES['single-thread'][:2], control.PROFILES['baseline'][:2])
        self.assertNotIn('--no-rerun', single)
        self.assertEqual(control.EVALUATION_SECONDS, 900)

    def test_manifest_retains_full_summary_and_all_query_plans(self):
        manifest = json.loads(control.QUERY_MANIFEST.read_text())
        self.assertEqual(len(manifest['query_hashes']), 39)
        self.assertEqual(set(manifest['query_hashes']), set(manifest['compiled_query_hashes']))
        self.assertIn('qlpacks/codeql/rust-queries/0.1.43/queries/summary/SummaryStats.ql',
                      manifest['query_hashes'])

    @unittest.skipUnless(os.name == 'posix', 'experiment executes on Linux')
    def test_timeout_is_failure_and_reaps_owned_process(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            pid_file = root / 'child.pid'
            script = ('import os,pathlib,time; '
                      f'pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid())); time.sleep(60)')
            with self.assertRaises(BoundedProcessError) as raised:
                control.run_queries([sys.executable, '-c', script], root, dict(os.environ), 1)
            self.assertEqual(raised.exception.kind, 'timeout')
            receipt = json.loads((root / 'query.json').read_text())
            self.assertEqual(receipt['stopped'], 'timeout')
            self.assertIsNone(receipt['returncode'])
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pid_file.read_text()), 0)

    @unittest.skipUnless(os.name == 'posix', 'experiment executes on Linux')
    def test_nonzero_status_is_retained(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            receipt = control.run_queries([sys.executable, '-c', 'print("failed"); raise SystemExit(7)'],
                                          root, dict(os.environ), 5)
            self.assertEqual(receipt['returncode'], 7)
            self.assertEqual((root / 'query.console').read_text(), 'failed\n')

    def test_old_bqrs_cannot_satisfy_fresh_results(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            old = root / 'database/results/codeql/rust-queries/queries/summary/SummaryStats.bqrs'
            old.parent.mkdir(parents=True)
            old.write_bytes(b'old result')
            query = control.QUERY_PREFIX + 'qlpacks/codeql/rust-queries/0.1.43/queries/summary/SummaryStats.ql'
            with self.assertRaisesRegex(control.ControlError, 'fresh query result missing'):
                control.decode_results(Path('/unused/codeql'), [query], root, {})

    def test_no_results_is_not_completed(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(control.ControlError, 'incomplete query results'):
                control.decode_results(Path('/unused/codeql'), [], Path(folder), {})


if __name__ == '__main__':
    unittest.main()
