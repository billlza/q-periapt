from pathlib import Path
import json
import os
import stat
import sys
import tempfile
import unittest
import zipfile

import codeql_memory_control as control
from bounded_process import BoundedProcessError


class MemoryControlTests(unittest.TestCase):
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
