"""Windows forced-process evidence cannot be relabelled as Unix signal evidence."""
import unittest

import test_continuity_c_root_reverse as reverse_test


class WindowsRootReadbackTests(unittest.TestCase):
    def test_explicit_windows_marker_and_unchanged_effect_contract(self):
        fixture = reverse_test.ReverseReadbackTests()
        files, options = fixture.fixture()
        options.update(darwin=False, windows=True)
        with self.assertRaisesRegex(ValueError, 'scope or completion differs'):
            fixture.verify(files, options)
        marker = 'public/traffic/reverse-result'
        files[marker] = files[marker].replace(b'sigkill', b'terminateprocess')
        result = fixture.verify(files, options)
        self.assertEqual(result['receiver_terminateprocess'], 1)
        self.assertNotIn('receiver_sigkill', result)
        with self.assertRaisesRegex(ValueError, 'scope or completion differs'):
            fixture.verify(files, dict(options, windows=False))
        files['public/traffic/effect-reply-recover'] = b'changed effect'
        with self.assertRaises(ValueError):
            fixture.verify(files, options)


if __name__ == '__main__':
    unittest.main()
