"""Claim-boundary tests; real process traces establish Kotlin root execution."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import continuity_kotlin_root as root


class KotlinRootReadbackTests(unittest.TestCase):
    def test_gc_claim_requires_kotlin_selected_collector_actual_progress_and_revocation(self):
        base = {"scope": "C", "public_readbacks": {}, "default_thread_stacks": {},
                "application_traffic": {"default_thread_stacks": {}, "reverse": {"default_thread_stacks": {}}}}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder); public = path / 'public'; public.mkdir()
            for language, collector, revoked, count, valid in (
                    (b'Kotlin', b'Serial', 1, 1, True), (b'Kotlin', b'G1', 1, 2, True),
                    (b'C', b'Serial', 1, 1, False), (b'Kotlin', b'ZGC', 1, 1, False),
                    (b'Kotlin', b'Serial', 0, 1, False), (b'Kotlin', b'Serial', 1, 0, False),
                    (b'Kotlin', b'Serial', 1, 4097, False)):
                for name, value in {'client-language': language, 'root-gc-collector': collector,
                                    'gc-revokes-successor': revoked.to_bytes(8, 'big'),
                                    'gc-collections': count.to_bytes(8, 'big')}.items():
                    (public / name).write_bytes(value)
                selected = 'G1' if collector == b'G1' else 'Serial'
                with self.subTest(language=language, collector=collector, revoked=revoked, count=count), mock.patch.object(
                        root.driver, 'verify_execution', return_value=copy.deepcopy(base)):
                    if valid:
                        result = root.verify_execution(b'fixture', path, variant='original', collector=selected)
                        self.assertTrue(result['final_cleaner_revokes_successor'])
                        self.assertEqual(result['observed_collections'], count)
                        self.assertNotIn('default_thread_stacks', result)
                    else:
                        with self.assertRaises(ValueError): root.verify_execution(b'fixture', path, variant='original', collector=selected)

    def test_single_collector_cannot_be_treated_as_both(self):
        with self.assertRaisesRegex(ValueError, 'both garbage collectors'):
            root.qualify(Path('/unused'), Path('/unused'), 'debug', {}, {'Serial': Path('/unused')}, {}, Path('/unused'), None)


if __name__ == '__main__':
    unittest.main()
