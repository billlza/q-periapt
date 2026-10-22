"""Installed root checks need their interpreter, wheel and native producer first."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent.parent
CONSUMER = 'name: Build and consume the independent enrollment exchange wheel\n'


def validate(text):
    steps = text.split('\n      - ')
    consumers = [step for step in steps if step.startswith(CONSUMER)]
    if len(consumers) != 1:
        raise ValueError('one independent installed consumer step required')
    consumer = consumers[0]
    if 'QPERIAPT_PYTHON: ${{ steps.python.outputs.python-path }}' not in consumer:
        raise ValueError('installed checks require selected Python')
    prerequisites = (
        '--target "$RUNNER_TEMP/reference-provider"',
        'sh artifact/python-run.sh artifact/continuity_host_exchange.py',
        'installed_reference=$(jq -er',
        'cargo build --locked --release --manifest-path research/continuity-openssl-peer/native/Cargo.toml',
    )
    for flag in ('--root-child-inspection', '--root-retirement "$mode"', '--root-retirement-cuts',
                 '--root-successor "$mode"', '--retirement-result'):
        owners = [step for step in steps if flag in step]
        if owners != [consumer]:
            raise ValueError('root checks must share the installed producer step')
        position = consumer.index(flag)
        if any(item not in consumer or consumer.index(item) >= position for item in prerequisites):
            raise ValueError('root checks precede installed inputs')


class ReferenceAccountWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / '.github/workflows/reference-account.yml').read_text()

    def test_root_checks_follow_their_installed_inputs(self):
        validate(self.text)

    def test_unassigned_installation_path_and_wrong_interpreter_refuse(self):
        for before, after in (('installed_reference=$(jq -er', 'unused_reference=$(jq -er'),
                              ('QPERIAPT_PYTHON: ${{ steps.python.outputs.python-path }}', 'QPERIAPT_PYTHON: /usr/bin/python3')):
            changed = self.text.replace(before, after)
            self.assertNotEqual(changed, self.text)
            with self.assertRaisesRegex(ValueError, 'installed inputs|selected Python'):
                validate(changed)

    def test_moving_root_checks_before_the_consumer_is_rejected(self):
        marker = '          for mode in steady ordinary-before ordinary-after credential'
        start = self.text.index(marker)
        end = self.text.index('          done\n', start) + len('          done\n')
        block = self.text[start:end]
        moved = self.text[:start] + self.text[end:]
        split = moved.index('      - ' + CONSUMER)
        moved = moved[:split] + block + moved[split:]
        self.assertNotEqual(moved, self.text)
        with self.assertRaisesRegex(ValueError, 'installed producer step'):
            validate(moved)


if __name__ == '__main__':
    unittest.main()
