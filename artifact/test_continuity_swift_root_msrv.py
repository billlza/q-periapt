"""Reject a substituted compiler or incomplete minimum-root regression."""
from pathlib import Path
import unittest

import continuity_package as package
import continuity_swift_root_msrv as minimum


class MinimumRootTests(unittest.TestCase):
    def test_requires_minimum_compiler_and_cargo(self):
        minimum.validate_versions(minimum.RUSTC + '\nbinary: rustc\n', 'cargo 1.90.0 (840b83a10 2025-07-30)')
        for rustc, cargo in ((minimum.RUSTC.replace('1.90.0', '1.98.1'), 'cargo 1.90.0 (id)'),
                             (minimum.RUSTC, 'cargo 1.98.1 (id)'), ('', 'cargo 1.90.0 (id)')):
            with self.subTest(rustc=rustc, cargo=cargo), self.assertRaisesRegex(ValueError, 'actual Rust/Cargo'):
                minimum.validate_versions(rustc, cargo)

    def test_swift_selector_cannot_omit_or_silently_ignore_minimum_lane(self):
        package.validate_swift_minimum(True, Path('/toolchain'))
        package.validate_swift_minimum(False, None)
        for selected, toolchain in ((True, None), (False, Path('/toolchain'))):
            with self.subTest(selected=selected), self.assertRaisesRegex(ValueError, 'requires'):
                package.validate_swift_minimum(selected, toolchain)

    def test_native_test_census_rejects_zero_missing_duplicate_and_failed_tests(self):
        rows = [f'test {name} ... ok' for name in sorted(minimum.ROOT_TESTS)]
        summary = 'test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 48 filtered out;'
        good = '\n'.join([*rows, summary]).encode()
        minimum.verify_native_tests(good)
        changed = [summary.encode(), '\n'.join([*rows[:-1], summary]).encode(),
                   '\n'.join([*rows, rows[0], summary]).encode(), good.replace(b' ... ok', b' ... FAILED', 1),
                   good.replace(b'0 failed', b'1 failed'), good.replace(b'0 ignored', b'1 ignored')]
        for output in changed:
            with self.subTest(output=output[-100:]), self.assertRaisesRegex(ValueError, 'execute completely'):
                minimum.verify_native_tests(output)

    def test_minimum_collector_is_bound_to_package_source(self):
        name = 'artifact/continuity_swift_root_msrv.py'
        self.assertEqual(package.source_inputs()['files'][name], minimum.sdk.snapshot(package.ROOT / name).sha256)


if __name__ == '__main__':
    unittest.main()
