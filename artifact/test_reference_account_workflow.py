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
                 '--root-successor "$mode"', '--root-successor-cuts', '--root-successor-cancellation',
                 '--root-successor-process-restart', '--root-successor-later-cuts', '--retirement-result'):
        owners = [step for step in steps if flag in step]
        if owners != [consumer]:
            raise ValueError('root checks must share the installed producer step')
        position = consumer.index(flag)
        if any(item not in consumer or consumer.index(item) >= position for item in prerequisites):
            raise ValueError('root checks precede installed inputs')
    successor_modes = consumer.split('--root-successor "$mode"', 1)[0].rsplit('for mode in ', 1)[1].split('; do', 1)[0].split()
    if successor_modes.count('peer-root-revocation') != 1:
        raise ValueError('later root permission revocation must run exactly once')
    if successor_modes.count('peer-root-replacement') != 1:
        raise ValueError('later root committed replacement must run exactly once')
    if successor_modes.count('peer-root-continuation') != 1:
        raise ValueError('later root independent traffic must run exactly once')
    restart_modes = consumer.split('--root-successor-process-restart "$mode"', 1)[0].rsplit('for mode in ', 1)[1].split('; do', 1)[0].split()
    if restart_modes != ['peer', 'peer-credential', 'peer-before', 'peer-after', 'peer-root-continuation']:
        raise ValueError('original and later root process restarts must each run exactly once')
    for required in ('for phase in bind retire; do', '--root-successor-later-cuts "$phase"',
                     'later_cut_pids+=("$!")', 'for later_cut_pid in "${later_cut_pids[@]}"; do',
                     'if ! wait "$later_cut_pid"; then later_cut_status=1; fi', 'test "$later_cut_status" -eq 0'):
        if consumer.count(required) != 1:
            raise ValueError('both later root cut groups must finish and propagate failures')


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

    def test_later_root_revocation_cannot_be_omitted_or_repeated(self):
        for mode in ('peer-root-revocation', 'peer-root-replacement', 'peer-root-continuation'):
            for replacement in ('', mode + ' ' + mode):
                changed = self.text.replace(mode, replacement, 1)
                self.assertNotEqual(changed, self.text)
                with self.assertRaisesRegex(ValueError, 'later root .* must run exactly once'):
                    validate(changed)

    def test_later_root_cut_groups_cannot_be_omitted_or_hide_failure(self):
        for before, after in (('for phase in bind retire; do', 'for phase in bind; do'),
                              ('then later_cut_status=1;', 'then later_cut_status=0;'),
                              ('test "$later_cut_status" -eq 0', 'true')):
            changed = self.text.replace(before, after)
            self.assertNotEqual(changed, self.text)
            with self.assertRaisesRegex(ValueError, 'cut groups must finish and propagate failures'):
                validate(changed)

    def test_later_root_restart_cannot_be_omitted_or_repeated(self):
        loop = 'for mode in peer peer-credential peer-before peer-after peer-root-continuation; do'
        for replacement in ('', 'peer-root-continuation peer-root-continuation'):
            changed = self.text.replace(loop, loop.replace('peer-root-continuation', replacement))
            self.assertNotEqual(changed, self.text)
            with self.assertRaisesRegex(ValueError, 'process restarts must each run exactly once'):
                validate(changed)


if __name__ == '__main__':
    unittest.main()
