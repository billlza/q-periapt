"""Windows first-registration readbacks retain all six original trust routes."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import continuity_windows_configuration as windows
from test_continuity_first_configuration import fixture


def evidence(root):
    public = root / 'debug-configuration-public'
    public.mkdir()
    stdout = fixture(public).replace(b'5 filtered out;', b'9 filtered out;')
    (root / 'debug-first-registration.stdout').write_bytes(stdout)
    invocation = {'argv': windows.command('debug'), 'returncode': 0}
    (root / 'debug-first-registration.json').write_bytes(json.dumps(invocation).encode())
    checked = windows.verify(stdout, public)
    files = {name: {'sha256': digest, 'bytes': (public / name).stat().st_size}
             for name, digest in checked['public_readbacks'].items()}
    binaries = {name: 'a' * 64 for name in ('first-configuration.exe', 'owner-client.exe',
                                          'q_periapt_continuity_c_consumer.dll')}
    return public, {'files': files, 'verification': checked, 'binaries': binaries}


class WindowsConfigurationTests(unittest.TestCase):
    def test_complete_routes_replay_and_extra_files_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            public, receipt = evidence(root)
            self.assertEqual(windows.review(root, 'debug', receipt), receipt['verification'])
            self.assertEqual(len(receipt['files']), 190)
            bad = copy.deepcopy(receipt)
            bad['binaries'].pop('owner-client.exe')
            with self.assertRaisesRegex(ValueError, 'binary identities differ'):
                windows.review(root, 'debug', bad)
            (public / 'private-store').write_bytes(b'not public')
            with self.assertRaisesRegex(ValueError, 'inventory differs'):
                windows.review(root, 'debug', receipt)

    def test_changed_original_effect_is_refused_even_with_forged_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            public, receipt = evidence(root)
            name = 'tls-recoverable/effect.bin'
            path = public / name
            path.write_bytes(path.read_bytes()[:-1] + b'!')
            with self.assertRaisesRegex(ValueError, 'public bytes changed'):
                windows.review(root, 'debug', receipt)
            forged = copy.deepcopy(receipt)
            forged['files'][name]['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, 'original registration/session/message'):
                windows.review(root, 'debug', forged)

    def test_wrong_command_and_omitted_route_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, receipt = evidence(root)
            invocation = root / 'debug-first-registration.json'
            command = invocation.read_bytes()
            invocation.write_bytes(command.replace(b'independent_c_', b'other_'))
            with self.assertRaisesRegex(ValueError, 'execution differs'):
                windows.review(root, 'debug', receipt)
            invocation.write_bytes(command)
            log = root / 'debug-first-registration.stdout'
            log.write_bytes(log.read_bytes().replace(b'carrier=tls profile=recoverable', b'carrier=signed profile=recoverable'))
            with self.assertRaisesRegex(ValueError, 'omitted or duplicated'):
                windows.review(root, 'debug', receipt)


if __name__ == '__main__':
    unittest.main()
