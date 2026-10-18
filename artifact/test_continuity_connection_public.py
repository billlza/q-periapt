"""Public export refuses unknown leaves and unsafe names before publishing them."""
from pathlib import Path
import tempfile
import unittest

from continuity_connection_public import copy_selected, exact_tree, message


class PublicConnectionExport(unittest.TestCase):
    def test_closed_public_tree_rejects_extra_private_leaf_and_empty_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'public').write_bytes(b'public fixture')
            exact_tree(root, {'public'})
            (root / 'wrap.key').write_bytes(b'fake private test bytes')
            with self.assertRaises(ValueError):
                exact_tree(root, {'public'})
            (root / 'wrap.key').unlink()
            (root / 'unexpected').mkdir()
            with self.assertRaises(ValueError):
                exact_tree(root, {'public'})

    def test_copy_never_selects_neighboring_state_and_refuses_path_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / 'source'; root.mkdir()
            (root / 'public').write_bytes(b'public fixture')
            (root / 'wrap.key').write_bytes(b'fake private test bytes')
            result = copy_selected(root, parent / 'exported', {'public'})
            self.assertEqual(set(result), {'public'})
            self.assertEqual({p.name for p in (parent / 'exported').iterdir()}, {'public'})
            self.assertEqual((root / 'wrap.key').read_bytes(), b'fake private test bytes')
            for index, name in enumerate(('../wrap.key', '/absolute', 'C:private', 'dir\\file')):
                target = parent / f'refused-{index}'
                with self.assertRaises(ValueError):
                    copy_selected(root, target, {name})
                self.assertFalse(target.exists())

    def test_message_derived_filename_is_bounded_lowercase_hex(self):
        self.assertEqual(message({'id': 'ab' * 32}, 'id'), 'ab' * 32)
        for value in ('../private', 'A' * 64, 'a' * 63, 123, None):
            with self.assertRaises(ValueError):
                message({'id': value}, 'id')


if __name__ == '__main__':
    unittest.main()
