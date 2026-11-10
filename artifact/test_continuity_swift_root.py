"""Claim-boundary checks only; process traces establish actual Swift execution."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import continuity_swift_root as root


class SwiftRootReadbackTests(unittest.TestCase):
    def test_shared_native_fixture_cannot_be_relabelled_as_swift_or_skip_arc_revocation(self):
        native = {"scope": "C", "public_readbacks": {}, "default_thread_stacks": {},
                  "application_traffic": {"default_thread_stacks": {}, "reverse": {"default_thread_stacks": {}}}}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary); public = path / 'public'; public.mkdir()
            language = public / 'client-language'; arc = public / 'arc-revokes-successor'
            for selected, revoked, valid in ((b'Swift', 1, True), (b'C', 1, False), (b'Swift', 0, False)):
                language.write_bytes(selected); arc.write_bytes(revoked.to_bytes(8, 'big'))
                with self.subTest(language=selected, revoked=revoked), mock.patch.object(
                        root.driver, 'verify_execution', return_value=copy.deepcopy(native)):
                    if valid:
                        checked = root.verify_execution(b'fixture output', path, variant='original')
                        self.assertEqual(checked['client_language'], 'Swift')
                        self.assertTrue(checked['final_arc_release_revokes_successor'])
                        self.assertEqual(set(checked['public_readbacks']),
                            {'public/client-language', 'public/arc-revokes-successor'})
                        self.assertNotIn('default_thread_stacks', checked)
                    else:
                        with self.assertRaises(ValueError):
                            root.verify_execution(b'fixture output', path, variant='original')


if __name__ == '__main__':
    unittest.main()
