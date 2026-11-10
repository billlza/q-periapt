"""Windows archive qualification must exercise its acquisition implementation."""
from pathlib import Path
import unittest

from continuity_windows_workflow_paths import event_paths, path_matches, triggered

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github/workflows/continuity-windows-package.yml'


def validate(text):
    for event, patterns in event_paths(text).items():
        for name in ('artifact/continuity_fetch.py', 'artifact/test_continuity_fetch.py'):
            if not triggered(patterns, name):
                raise ValueError(f'{event}: acquisition changes must trigger installed Windows qualification')
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
        # Leave the other event intact and explicitly retain the other file.
        # Removing coverage in one event alone must fail, even with broad globs.
        push, pr = text.split('\n  pull_request:\n', 1)
        for event, patterns in event_paths(text).items():
            for missing, retained in (('artifact/continuity_fetch.py', 'artifact/test_continuity_fetch.py'),
                                      ('artifact/test_continuity_fetch.py', 'artifact/continuity_fetch.py')):
                part = push if event == 'push' else pr
                for pattern in patterns:
                    if path_matches(pattern, missing):
                        part = part.replace('      - ' + pattern + '\n', '')
                part = part.replace('    paths:\n', '    paths:\n      - ' + retained + '\n', 1)
                changed = (part if event == 'push' else push) + '\n  pull_request:\n' + (part if event == 'pull_request' else pr)
                with self.subTest(event=event, missing=missing), self.assertRaises(ValueError):
                    validate(changed)

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
