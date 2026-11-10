"""Failure preservation, bounded observation and absence/ambiguity are distinct."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import continuity_process_failure as failure
from test_continuity_process_crash import EVENT, START, ips, report, PRIVATE


def line(**changes):
    fields = dict(parent_pid=123, pid=456, start_ms=START, end_ms=START + 1000,
        signal=6, exit='none', program_hex=b'qpc-c-client'.hex(), label='peer-roster-accounted-1',
        stdout_bytes=0, stderr_bytes=0)
    fields.update(changes)
    return ('QPC_CHILD_FAILURE_V1 ' + ' '.join(f'{k}={v}' for k,v in fields.items()) + '\n').encode()


class ProcessFailureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.prefix = self.root / 'command'
        self.prefix.with_suffix('.stderr').write_bytes(line())

    def collect(self, **kw):
        return failure.collect(self.prefix, directory=self.root, platform='darwin', pause=lambda _: None, **kw)

    def put(self, name='qpc-c-client-report.ips', data=None):
        path = self.root / name
        path.write_bytes(ips() if data is None else data)
        os.utime(path, (START / 1000 + 2, START / 1000 + 2))
        return path

    def test_event_preserves_signal_or_exit_with_stderr_failure(self):
        row = failure.events(line())[0]
        self.assertEqual(row['signal'], 6)
        self.assertIsNone(row['exit_code'])
        for status in (0, 7):
            self.assertEqual(failure.events(line(signal='none', exit=status, stderr_bytes=3))[0]['exit_code'], status)
        self.assertIsNone(failure.events(line(start_ms='unavailable'))[0]['start_ms'])

    def test_malformed_duplicate_excessive_events_fail_explicitly(self):
        for raw in (line() * 2, line(signal='none'), line(exit=1), line(pid=0),
                    line(signal=0), line(exit=0, signal='none'), line(program_hex='2e2e'),
                    line(program_hex='ff'), line(label='bad label'), line(stdout_bytes=2**64),
                    b'x' * (16*1024*1024+1), b''.join(line(pid=n+1) for n in range(33))):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                failure.events(raw)

    def test_matching_report_and_private_canary_projection(self):
        self.put()
        result = self.collect()
        self.assertEqual(result['crash_reports'][0]['status'], 'matched')
        self.assertTrue(result['scan_complete'])
        self.assertFalse(result['root_cause_confirmed'])
        self.assertNotIn(PRIVATE, json.dumps(result))

    def test_unrelated_reports_are_not_exposed_and_missing_has_bounded_observations(self):
        self.put('other-program-report.ips', b'not-json-' + PRIVATE.encode())
        waits = []
        result = failure.collect(self.prefix, directory=self.root, platform='darwin', pause=waits.append)
        self.assertEqual(waits, [1, 1])
        self.assertEqual(len(result['observations']), 3)
        self.assertEqual(result['crash_reports'][0]['status'], 'unavailable')
        self.assertEqual([o['recent_files_read'] for o in result['observations']], [0, 0, 0])

    def test_ambiguous_distinct_reports_are_retained_without_selecting_one(self):
        self.put(); row = report(); row['threads'][0]['frames'][0]['imageOffset'] = 124
        self.put('qpc-c-client-second.ips', ips(row))
        result = self.collect()
        self.assertEqual(result['crash_reports'][0]['status'], 'ambiguous')
        self.assertEqual(len(result['crash_reports'][0]['reports']), 2)

    def test_partial_scans_cannot_claim_unique_match(self):
        self.put(); self.put('qpc-c-client-broken.ips', b'broken')
        result = self.collect(attempts=1)
        self.assertFalse(result['scan_complete'])
        self.assertEqual(result['crash_reports'][0]['status'], 'incomplete')
        self.assertEqual(len(result['crash_reports'][0]['reports']), 1)
        for setting in ('MAX_DIRECTORY_ENTRIES', 'MAX_RECENT_FILES'):
            with patch.object(failure, setting, 0):
                self.assertEqual(self.collect()['crash_reports'][0]['status'], 'incomplete')

    def test_symlinks_and_unavailable_directory_are_observable(self):
        actual = self.put('different.ips')
        (self.root / 'qpc-c-client-link.ips').symlink_to(actual)
        result = self.collect(attempts=1)
        self.assertFalse(result['scan_complete'])
        result = failure.collect(self.prefix, directory=self.root/'absent', platform='darwin')
        self.assertEqual(result['observations'][0]['status'], 'directory_unavailable')

    def test_nonmac_missing_events_and_unavailable_clock_remain_explicit(self):
        result = failure.collect(self.prefix, platform='linux')
        self.assertEqual(result['collection_status'], 'platform_crash_reader_unavailable')
        self.prefix.with_suffix('.stderr').write_bytes(line(start_ms='unavailable'))
        self.assertEqual(self.collect()['observations'][0]['status'], 'no_attributable_signal_event')
        self.prefix.with_suffix('.stderr').write_bytes(b'no child event')
        self.assertEqual(self.collect()['collection_status'], 'no_child_failure_event')
        self.prefix.with_suffix('.stderr').unlink()
        self.assertEqual(self.collect()['collection_status'], 'failure_events_unavailable')

    def test_original_command_failure_keeps_exit_and_never_reruns(self):
        prefix = self.root/'real-child'; marker = self.root/'runs'
        script = 'from pathlib import Path; import sys; Path(sys.argv[1]).open("a").write("one\\n"); sys.exit(7)'
        with self.assertRaisesRegex(ValueError, r'command failed \(7\)'):
            failure.command([sys.executable, '-c', script, str(marker)], prefix, self.root,
                            diagnostic_directory=self.root)
        self.assertEqual(marker.read_text(), 'one\n')
        self.assertEqual(json.loads(prefix.with_suffix('.json').read_text())['returncode'], 7)
        diagnostic = json.loads((self.root/'real-child-process-failure.json').read_text())
        self.assertTrue(diagnostic['primary_command_failed'])
        self.assertEqual(diagnostic['collection_status'], 'no_child_failure_event')

    def test_successful_command_keeps_exact_output_without_failure_report(self):
        prefix = self.root/'success'
        result = failure.command([sys.executable, '-c', 'print("exact-output")'], prefix, self.root)
        self.assertEqual(result, b'exact-output\n')
        self.assertFalse((self.root/'success-process-failure.json').exists())

    def test_excessive_observation_attempts_are_rejected(self):
        for attempts in (0, 4, True):
            with self.assertRaisesRegex(ValueError, 'diagnostic_attempt_bound'):
                self.collect(attempts=attempts)

    def test_secondary_failure_preserves_original_exception_and_context(self):
        primary = ValueError('original failure')
        secondary = RuntimeError('diagnostic bug')
        with patch.object(failure.sdk, 'command', side_effect=primary) as command, \
                patch.object(failure, 'collect', side_effect=secondary):
            with self.assertRaises(ValueError) as raised:
                failure.command([], self.prefix, self.root)
        self.assertIs(raised.exception, primary)
        self.assertIs(raised.exception.__cause__, secondary)
        command.assert_called_once()

    def test_contract_verifier_rejects_missing_skipped_duplicate_tests(self):
        rows = [f'test {name} ... ok\n'.encode() for name in sorted(failure.CONTRACT_TESTS)]
        summary = b'test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n'
        good = b''.join(rows) + summary
        failure.verify_contract(good)
        for raw in (summary, b''.join(rows[:-1])+summary, b''.join(rows[:-1]+[rows[0]])+summary,
                    good.replace(b'0 ignored', b'1 ignored')):
            with self.assertRaises(ValueError):
                failure.verify_contract(raw)
