"""Synthetic IPS schema, exact process attribution and public-field projection."""
import copy
import json
import unittest

import continuity_process_crash as crash

PRIVATE = "SECRET_REGISTER_APPLICATION_MESSAGE_PATH_CANARY"
START = 1792944000000
EVENT = dict(parent_pid=123, pid=456, program="qpc-c-client", signal=6,
             start_ms=START, end_ms=START + 1000)


def report():
    return {"pid": 456, "parentPid": 123, "procName": "qpc-c-client",
        "procLaunch": "2026-10-25 16:00:00.010 +0000",
        "captureTime": "2026-10-25 16:00:00.900 +0000", "faultingThread": 0,
        "exception": {"type": "EXC_CRASH", "signal": "SIGABRT", "message": PRIVATE},
        "termination": {"namespace": "SIGNAL", "code": 6, "indicator": PRIVATE},
        "threads": [{"threadState": {"x": PRIVATE}, "frames": [
            {"imageIndex": 0, "imageOffset": 123, "symbol": "abort", "symbolLocation": 12}]}],
        "usedImages": [{"name": "libsystem_c.dylib", "path": PRIVATE,
                        "uuid": "12345678-1234-1234-1234-123456789abc", "base": 456}],
        "asi": PRIVATE, "vmSummary": PRIVATE, "crashReporterKey": PRIVATE}


def ips(value=None, metadata=None):
    return (json.dumps(metadata if metadata is not None else {"bug_type": "309", "name": "qpc-c-client"})
            + "\n" + json.dumps(report() if value is None else value)).encode()


class CrashReportTests(unittest.TestCase):
    def test_exact_match_exports_only_selected_public_fields(self):
        result = crash.match_report(ips(), EVENT)
        self.assertEqual(result['signal'], 'SIGABRT')
        self.assertEqual(result['frames'], [{'image_name': 'libsystem_c.dylib', 'image_offset': 123,
            'image_uuid': '12345678-1234-1234-1234-123456789abc', 'symbol': 'abort', 'symbol_offset': 12}])
        self.assertNotIn(PRIVATE, json.dumps(result))
        self.assertEqual(set(result), {'report_sha256', 'matched_pid', 'matched_parent_pid', 'exception_type',
            'signal', 'termination_namespace', 'termination_code', 'faulting_thread_index', 'frames',
            'total_frame_count', 'stack_truncated', 'capture_after_wait_ms', 'capture_delay_bound_ms'})

    def test_foreign_identity_and_reused_pid_are_not_matches(self):
        for field, value in [('pid', 999), ('parentPid', 999), ('procName', 'different'),
                ('procLaunch', '2026-10-25 15:59:59 +0000'),
                ('captureTime', '2026-10-25 16:00:03.001 +0000')]:
            with self.subTest(field=field):
                row = report(); row[field] = value
                self.assertIsNone(crash.match_report(ips(row), EVENT))
        self.assertIsNone(crash.match_report(ips(metadata={'bug_type': '309', 'name': 'different'}), EVENT))
        row = report(); row['exception']['signal'] = 'SIGSEGV'
        self.assertIsNone(crash.match_report(ips(row), EVENT))

    def test_time_requires_zone_and_available_ordered_child_clocks(self):
        for value in ('2026-10-25 16:00:00', 'not-time'):
            row = report(); row['procLaunch'] = value
            with self.assertRaises(crash.CrashFormatError):
                crash.match_report(ips(row), EVENT)
        for event in (dict(EVENT, start_ms=None), dict(EVENT, start_ms=START + 2000)):
            with self.assertRaises(crash.CrashFormatError):
                crash.match_report(ips(), event)

    def test_corpse_capture_after_wait_preserves_exact_launch_binding(self):
        row = report(); row['captureTime'] = '2026-10-25 16:00:01.052 +0000'
        matched = crash.match_report(ips(row), EVENT)
        self.assertEqual(matched['capture_after_wait_ms'], 52)
        row['procLaunch'] = '2026-10-25 16:00:01.003 +0000'
        self.assertIsNone(crash.match_report(ips(row), EVENT))

    def test_boolean_ids_and_simulated_or_nonfatal_reports_are_rejected(self):
        for field in ('isSimulated', 'isNonFatal'):
            row = report(); row[field] = True
            with self.assertRaises(crash.CrashFormatError):
                crash.match_report(ips(row), EVENT)
        row = report(); row['pid'] = True
        with self.assertRaises(crash.CrashFormatError):
            crash.match_report(ips(row), dict(EVENT, pid=1))

    def test_duplicate_json_keys_nonfinite_and_oversized_reports_are_rejected(self):
        values = [ips().replace(b'"pid": 456', b'"pid": 456, "pid": 456'),
                  ips().replace(b'"pid": 456', b'"pid": NaN'), b'x' * (crash.MAX_CRASH_BYTES + 1),
                  b'{}', ips(metadata={'bug_type': '298', 'name': 'qpc-c-client'})]
        for value in values:
            with self.subTest(size=len(value)), self.assertRaises(crash.CrashFormatError):
                crash.match_report(value, EVENT)

    def test_stack_is_bounded_and_truncation_is_explicit(self):
        row = report(); row['threads'][0]['frames'] *= 33
        result = crash.match_report(ips(row), EVENT)
        self.assertEqual(len(result['frames']), 32)
        self.assertEqual(result['total_frame_count'], 33)
        self.assertTrue(result['stack_truncated'])

    def test_bad_stack_indexes_paths_and_unbounded_symbols_are_rejected(self):
        changes = [lambda r: r.update(faultingThread=1),
            lambda r: r['threads'][0]['frames'][0].update(imageIndex=-1),
            lambda r: r['usedImages'][0].update(name='/private/' + PRIVATE),
            lambda r: r['threads'][0]['frames'][0].update(symbol='x' * 513),
            lambda r: r['threads'][0]['frames'][0].update(imageOffset=True),
            lambda r: r['usedImages'][0].update(uuid='not-a-uuid'),
            lambda r: r['termination'].update(code=11),
            lambda r: r.update(threads=[])]
        for change in changes:
            row = copy.deepcopy(report()); change(row)
            with self.assertRaises(crash.CrashFormatError):
                crash.match_report(ips(row), EVENT)
