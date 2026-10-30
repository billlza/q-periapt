"""Windows archive qualification must exercise its acquisition implementation."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github/workflows/continuity-windows-package.yml'


def validate(text):
    trigger = text.split('\npermissions:', 1)[0]
    for name in ('artifact/continuity_fetch.py', 'artifact/test_continuity_fetch.py'):
        if '      - ' + name + '\n' not in trigger:
            raise ValueError('acquisition changes must trigger installed Windows qualification')
    prepare = text.split('  prepare:\n', 1)[1].split('\n  native:', 1)[0]
    step = prepare.split('      - name: Check public C export and substitution refusals\n', 1)[1]
    step = step.split('      - uses:', 1)[0]
    required = ('set -euo pipefail',
                "-m unittest discover -s artifact -p 'test_continuity_windows_*.py'",
                'sh artifact/python-run.sh artifact/test_continuity_fetch.py')
    if any(value not in step for value in required) or 'continue-on-error' in prepare:
        raise ValueError('existing and acquisition checks must both pass before packaging')


class AcquisitionQualification(unittest.TestCase):
    def test_current_workflow(self):
        validate(WORKFLOW.read_text())

    def test_removing_either_trigger_refuses(self):
        text = WORKFLOW.read_text()
        for name in ('artifact/continuity_fetch.py', 'artifact/test_continuity_fetch.py'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate(text.replace('      - ' + name + '\n', '', 1))

    def test_skipped_test_or_masked_failure_refuses(self):
        text = WORKFLOW.read_text()
        for before, after in (
            ('sh artifact/python-run.sh artifact/test_continuity_fetch.py', 'echo skipped'),
            ("-p 'test_continuity_windows_*.py'", "-p 'absent-tests.py'"),
            ('set -euo pipefail', 'set +e'),
            ('  prepare:\n', '  prepare:\n    continue-on-error: true\n'),
        ):
            with self.subTest(before=before), self.assertRaises(ValueError):
                validate(text.replace(before, after, 1))


if __name__ == '__main__':
    unittest.main()
