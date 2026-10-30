"""Exercise acquisition coordination; Cargo/network execution remains a CI gate."""
import ast
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace

from continuity_fetch import fetch_locked, retryable_network_failure

NETWORK = (b'warning: spurious network error (3 tries remaining): [56] Failure when receiving '
           b'data from the peer (OpenSSL SSL_read: error:0A000126:SSL routines::unexpected eof while reading)\n')


class CommandFailure(ValueError):
    pass


class LockedFetch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.output = self.root / 'output'
        self.output.mkdir()
        self.manifest = self.root / 'Cargo.toml'
        self.lock = self.root / 'Cargo.lock'
        self.manifest.write_bytes(b'[package]\nname="test"\nversion="0.0.0"\n')
        self.lock.write_bytes(b'version = 4\n')
        self.argv = ['cargo', '+1.98.1', 'fetch', '--locked', '--manifest-path', str(self.manifest)]
        self.calls = []
        self.effects = []

    @staticmethod
    def write_json(path, value):
        with path.open('x') as stream:
            json.dump(value, stream)

    def execute(self, argv, label, cwd, *, env):
        self.calls.append((list(argv), label, Path(cwd), dict(env)))
        effect = self.effects.pop(0) if self.effects else (0, b'', b'')
        if isinstance(effect, BaseException):
            raise effect
        if callable(effect):
            effect = effect()
        code, stdout, stderr = effect
        (self.output / (label + '.stdout')).write_bytes(stdout)
        (self.output / (label + '.stderr')).write_bytes(stderr)
        self.write_json(self.output / (label + '.json'),
                        {'argv': argv, 'cwd': str(cwd), 'returncode': code})
        if code or b'warning:' in (stdout + stderr).lower():
            raise CommandFailure('retained rejected command ' + label)
        return stdout

    def run_fetch(self):
        return fetch_locked(self.argv, self.output, self.root,
                            {'CARGO_HOME': str(self.root / 'isolated-cargo'), 'CARGO_NET_RETRY': '99'},
                            execute=self.execute, read=Path.read_bytes,
                            write_json=self.write_json, command_errors=(CommandFailure,))

    def receipt(self):
        return json.loads((self.output / 'fetch-attempts.json').read_text())

    def test_clean_fetch_requires_locked_offline_check(self):
        self.assertEqual(self.run_fetch(), b'')
        self.assertEqual([x[1] for x in self.calls], ['fetch-network-01', 'fetch'])
        self.assertEqual(self.calls[-1][0], [*self.argv, '--offline'])
        self.assertEqual(self.calls[-1][3]['CARGO_NET_OFFLINE'], 'true')
        self.assertEqual(self.calls[0][3]['CARGO_NET_RETRY'], '0')
        self.assertTrue(self.receipt()['accepted'])

    def test_warning_even_with_zero_exit_is_not_success(self):
        self.effects = [(0, b'', NETWORK), (0, b'', b''), (0, b'', b'')]
        self.run_fetch()
        rows = self.receipt()['attempts']
        self.assertEqual(len(rows), 3)
        self.assertFalse(rows[0]['accepted'])
        self.assertEqual(rows[0]['stderr_sha256'], hashlib.sha256(NETWORK).hexdigest())
        self.assertEqual((self.output / 'fetch-network-01.stderr').read_bytes(), NETWORK)
        self.assertTrue(rows[-1]['offline'])

    def test_final_curl_error_without_warning_is_retried(self):
        diagnostic = (b'error: failed to download from `https://static.crates.io/crates/test/0.0.0/download`\n'
                      b'\nCaused by:\n  [56] Failure when receiving data from the peer '
                      b'(OpenSSL SSL_read: error:0A000126:SSL routines::unexpected eof while reading)\n')
        self.effects = [(101, b'', diagnostic), (0, b'', b''), (0, b'', b'')]
        self.run_fetch()
        self.assertEqual(len(self.calls), 3)
        self.assertFalse(self.receipt()['attempts'][0]['accepted'])
        self.assertTrue(self.receipt()['attempts'][0]['retryable_transport'])
        self.assertTrue(self.receipt()['accepted'])

    def test_curl_line_alone_or_unknown_error_cannot_authorize_retry(self):
        curl = b'[56] Failure when receiving data from the peer\n'
        self.assertFalse(retryable_network_failure(b'', curl))
        self.assertFalse(retryable_network_failure(b'', b'error: build failed\nCaused by:\n' + curl))
        self.assertFalse(retryable_network_failure(b'', b'error: failed to download package\n' + curl))
        self.assertFalse(retryable_network_failure(b'',
            b'error: failed to download package\nCaused by:\n[60] SSL peer certificate verification failed\n'))

    def test_two_rejected_network_attempts_preserve_failure(self):
        self.effects = [(101, b'', NETWORK), (101, b'', NETWORK)]
        with self.assertRaisesRegex(CommandFailure, 'fetch-network-02'):
            self.run_fetch()
        self.assertEqual(len(self.calls), 2)
        self.assertFalse(self.receipt()['accepted'])
        self.assertIsNone(self.receipt()['offline_label'])

    def test_unknown_warning_is_not_retryable(self):
        self.effects = [(0, b'', NETWORK + b'warning: unused manifest key\n')]
        with self.assertRaises(CommandFailure):
            self.run_fetch()
        self.assertEqual(len(self.calls), 1)

    def test_checksum_and_authentication_failures_are_not_retried(self):
        for extra in (b'checksum mismatch', b'certificate verify failed', b'HTTP 403',
                      b'failed to parse manifest', b'permission denied', b'no space left'):
            with self.subTest(extra=extra):
                self.assertFalse(retryable_network_failure(b'', NETWORK + extra))

    def test_nonzero_unknown_exit_is_not_retried(self):
        self.effects = [(-9, b'', NETWORK)]
        with self.assertRaises(CommandFailure):
            self.run_fetch()
        self.assertEqual(len(self.calls), 1)

    def test_stdout_and_unknown_error_refuse_retry(self):
        self.assertFalse(retryable_network_failure(b'wrong command output', NETWORK))
        self.assertFalse(retryable_network_failure(b'', NETWORK + b'error: unexpected internal failure\n'))
        self.assertFalse(retryable_network_failure(b'', b'error: failed to download package\n'))
        self.assertFalse(retryable_network_failure(b'', NETWORK + b'\xff'))

    def test_lock_mutation_cannot_recover_via_retry(self):
        def changed():
            self.lock.write_bytes(b'version = 3\n')
            return (101, b'', NETWORK)
        self.effects = [changed]
        with self.assertRaisesRegex(ValueError, 'changed its original'):
            self.run_fetch()
        self.assertEqual(len(self.calls), 1)
        self.assertFalse(self.receipt()['accepted'])

    def test_manifest_mutation_also_refuses(self):
        def changed():
            self.manifest.write_bytes(b'[workspace]\n')
            return (0, b'', b'')
        self.effects = [changed]
        with self.assertRaisesRegex(ValueError, 'changed its original'):
            self.run_fetch()
        self.assertFalse(self.receipt()['accepted'])

    def test_offline_error_is_not_retried_or_accepted(self):
        self.effects = [(0, b'', b''), (101, b'', b'error: offline cache incomplete')]
        with self.assertRaisesRegex(CommandFailure, 'fetch$'):
            self.run_fetch()
        self.assertEqual(len(self.calls), 2)
        self.assertFalse(self.receipt()['accepted'])

    def test_offline_warning_remains_fatal(self):
        self.effects = [(0, b'', b''), (0, b'', NETWORK)]
        with self.assertRaises(CommandFailure):
            self.run_fetch()
        self.assertFalse(self.receipt()['accepted'])

    def test_existing_attempt_is_not_overwritten(self):
        path = self.output / 'fetch-network-01.stderr'
        path.write_bytes(b'previous evidence')
        with self.assertRaisesRegex(ValueError, 'already exist'):
            self.run_fetch()
        self.assertEqual(path.read_bytes(), b'previous evidence')
        self.assertEqual(self.calls, [])

    def test_unrecorded_error_cannot_be_assumed_transient(self):
        self.effects = [RuntimeError('runner failed before recording')]
        with self.assertRaisesRegex(RuntimeError, 'before recording'):
            self.run_fetch()
        self.assertEqual(len(self.calls), 1)
        self.assertFalse(self.receipt()['accepted'])

    def test_non_fetch_and_unlocked_invocations_refuse(self):
        for replacement in ('build', 'test'):
            original = self.argv[:]
            self.argv[2] = replacement
            with self.assertRaises(ValueError):
                self.run_fetch()
            self.argv = original
        self.argv.remove('--locked')
        with self.assertRaises(ValueError):
            self.run_fetch()
        self.assertEqual(self.calls, [])

    def test_windows_fetch_route_uses_coordinator_without_retrying_builds(self):
        tree = ast.parse((Path(__file__).parent / 'continuity_windows_prepare.py').read_text())
        functions = [node for node in ast.walk(tree)
                     if isinstance(node, ast.FunctionDef) and node.name in ('execute', 'run')]
        self.assertEqual([node.name for node in functions], ['execute', 'run'])
        sdk = SimpleNamespace(ROOT=self.root,
                              command=lambda argv, prefix, cwd, environment:
                                  self.execute(argv, prefix.name, cwd, env=environment),
                              snapshot=lambda path: SimpleNamespace(data=path.read_bytes()),
                              write_json=self.write_json)
        scope = {'sdk': sdk, 'output': self.output, 'environment': {},
                 'fetch_locked': fetch_locked, 'RustPublishContractError': CommandFailure}
        self.effects = [(0, b'', NETWORK), (0, b'', b''), (0, b'', b'')]
        exec(compile(ast.Module(body=functions, type_ignores=[]), '<producer-runner>', 'exec'), scope)
        scope['run'](self.argv, 'fetch')
        self.assertTrue(self.receipt()['accepted'])
        self.effects = [(101, b'', NETWORK)]
        with self.assertRaises(CommandFailure):
            scope['run'](['cargo', 'build', '--locked'], 'build')
        self.assertEqual(self.calls[-1][1], 'build')
        self.assertEqual(len(self.calls), 4)

    def test_receipt_failure_does_not_hide_original_command_failure(self):
        self.effects = [(101, b'', b'error: checksum failure')]
        def record(path, value):
            if path.name == 'fetch-attempts.json':
                raise OSError('receipt disk error')
            LockedFetch.write_json(path, value)
        with self.assertRaises(BaseExceptionGroup) as caught:
            fetch_locked(self.argv, self.output, self.root, {}, execute=self.execute,
                         read=Path.read_bytes, write_json=record, command_errors=(CommandFailure,))
        self.assertIsInstance(caught.exception.exceptions[0], CommandFailure)
        self.assertIsInstance(caught.exception.exceptions[1], OSError)


if __name__ == '__main__':
    unittest.main()
