"""Enrollment fixture failures must retain evidence and reap the owned child."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
PEER = ROOT / 'research/continuity-openssl-peer'


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, PEER / filename)
    module = importlib.util.module_from_spec(spec)
    # The fixture imports only standard-library modules until exercise().
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


SESSION = load_module('enrollment_fixture_cleanup_subject', 'enrollment_session_checks.py')
RUN = load_module('enrollment_fixture_cleanup_counterpart', 'run.py')


class Closing:
    def __init__(self, name, events, error=None):
        self.name, self.events, self.error = name, events, error
        self.records = [{'case': 'request-sent'}]

    def close(self):
        self.events.append(self.name)
        self.records.append({'case': 'worker-stopped'})
        if self.error is not None:
            raise self.error


class EnrollmentFixtureCleanupTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.out = Path(self.directory.name)
        self.events, self.children = [], []
        self.refusals = [{'case': 'original-rejection', 'error': 'expected refusal'}]

    def tearDown(self):
        for native in self.children:
            RUN.Counterpart.close(native)
        self.directory.cleanup()

    def native(self, error=None):
        events = self.events

        class Native(RUN.Counterpart):
            def close(self):
                events.append('native')
                super().close()
                if error is not None:
                    raise error

        native = Native.__new__(Native)
        native.stderr = (self.out / ('native-' + str(len(self.children)) + '.stderr')).open('xb')
        native.process = subprocess.Popen(
            [sys.executable, '-c', 'import time; time.sleep(60)'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=native.stderr,
            start_new_session=True)
        native.commands = [{'case': 'original-command', 'status': 1}]
        self.children.append(native)
        return native

    def finish(self, native, client=None, registry=None, bridge=None, primary=None):
        primary_error = None
        try:
            if primary is not None:
                raise primary
        except BaseException as error:
            primary_error = error
            raise
        finally:
            SESSION._finish_fixture(self.out, native, client, registry, bridge,
                                    self.refusals, primary_error)

    def assert_reaped(self, native):
        self.assertIsNotNone(native.process.poll(), 'owned native child survived cleanup')
        self.assertTrue(native.process.stdin.closed)
        self.assertTrue(native.process.stdout.closed)
        self.assertTrue(native.stderr.closed)

    def read(self, name):
        return json.loads((self.out / name).read_text())

    def test_success_and_absent_optional_owners_retain_transcripts_and_reap(self):
        native = self.native()
        self.finish(native)
        self.assertEqual(self.events, ['native'])
        self.assertEqual(self.read('NATIVE.json'), native.commands)
        self.assertEqual(self.read('REFUSALS.json'), self.refusals)
        self.assertFalse((self.out / 'WITNESS.json').exists())
        self.assert_reaped(native)

    def test_original_failure_propagates_unchanged_when_cleanup_succeeds(self):
        native = self.native()
        original = ValueError('original protocol failure')
        with self.assertRaises(ValueError) as caught:
            self.finish(native, primary=original)
        self.assertIs(caught.exception, original)
        self.assertEqual(self.read('NATIVE.json'), native.commands)
        self.assertEqual(self.read('REFUSALS.json'), self.refusals)
        self.assert_reaped(native)

    def test_bridge_failure_preserves_original_error_and_all_public_evidence(self):
        native = self.native()
        original = ValueError('original foreground failure')
        bridge_error = RuntimeError('witness bridge failed')
        bridge_error.__cause__ = TimeoutError('header deadline expired')
        bridge = Closing('bridge', self.events, bridge_error)
        with self.assertRaises(ExceptionGroup) as caught:
            self.finish(native, Closing('client', self.events),
                        Closing('registry', self.events), bridge, original)
        self.assertEqual(caught.exception.exceptions, (original, bridge_error))
        self.assertIsInstance(bridge_error.__cause__, TimeoutError)
        self.assertEqual(self.events, ['client', 'registry', 'bridge', 'native'])
        self.assertEqual(self.read('WITNESS.json'), bridge.records)
        self.assertEqual(self.read('WITNESS.json')[-1], {'case': 'worker-stopped'})
        self.assertEqual(self.read('NATIVE.json'), native.commands)
        self.assertEqual(self.read('REFUSALS.json'), self.refusals)
        self.assert_reaped(native)

    def test_cleanup_failure_alone_still_fails_the_case(self):
        native = self.native()
        failure = RuntimeError('witness worker failed')
        with self.assertRaises(RuntimeError) as caught:
            self.finish(native, bridge=Closing('bridge', self.events, failure))
        self.assertIs(caught.exception, failure)
        self.assertEqual(self.read('NATIVE.json'), native.commands)
        self.assertEqual(self.read('REFUSALS.json'), self.refusals)
        self.assert_reaped(native)

    def test_every_owner_is_closed_and_each_failure_is_retained(self):
        errors = [RuntimeError(name + ' close failed')
                  for name in ('client', 'registry', 'bridge', 'native')]
        native = self.native(errors[-1])
        with self.assertRaises(ExceptionGroup) as caught:
            self.finish(native, Closing('client', self.events, errors[0]),
                        Closing('registry', self.events, errors[1]),
                        Closing('bridge', self.events, errors[2]))
        self.assertEqual(caught.exception.exceptions, tuple(errors))
        self.assertEqual(self.events, ['client', 'registry', 'bridge', 'native'])
        for name in ('WITNESS.json', 'NATIVE.json', 'REFUSALS.json'):
            self.assertTrue((self.out / name).is_file())
        self.assert_reaped(native)

    def test_a_previously_handled_caller_error_is_not_reported_as_a_fixture_failure(self):
        native = self.native()
        failure = RuntimeError('bridge cleanup failure')
        try:
            raise ValueError('already handled by caller')
        except ValueError:
            with self.assertRaises(RuntimeError) as caught:
                self.finish(native, bridge=Closing('bridge', self.events, failure))
        self.assertIs(caught.exception, failure)
        self.assert_reaped(native)

    def test_real_transcript_write_errors_do_not_skip_other_evidence_or_native_close(self):
        for failing in ('WITNESS.json', 'NATIVE.json', 'REFUSALS.json'):
            with self.subTest(transcript=failing):
                for name in ('WITNESS.json', 'NATIVE.json', 'REFUSALS.json'):
                    path = self.out / name
                    if path.is_dir():
                        path.rmdir()
                    elif path.exists():
                        path.unlink()
                (self.out / failing).mkdir()
                native = self.native()
                bridge = Closing('bridge', self.events)
                with self.assertRaises(IsADirectoryError) as caught:
                    self.finish(native, bridge=bridge)
                self.assertIn('Enrollment fixture cleanup: write ' + failing,
                              caught.exception.__notes__)
                for name in ('WITNESS.json', 'NATIVE.json', 'REFUSALS.json'):
                    if name != failing:
                        self.assertTrue((self.out / name).is_file())
                self.assert_reaped(native)

    def test_process_cancellation_is_retained_with_cleanup_failure(self):
        native = self.native()
        interrupted = KeyboardInterrupt('cancelled by caller')
        failure = RuntimeError('bridge close failed')
        with self.assertRaises(BaseExceptionGroup) as caught:
            self.finish(native, bridge=Closing('bridge', self.events, failure),
                        primary=interrupted)
        self.assertNotIsInstance(caught.exception, ExceptionGroup)
        self.assertEqual(caught.exception.exceptions, (interrupted, failure))
        self.assert_reaped(native)


if __name__ == '__main__':
    unittest.main()

