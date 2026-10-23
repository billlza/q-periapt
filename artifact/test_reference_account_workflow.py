"""Installed root checks need their interpreter, wheel and native producer first."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent.parent
CONSUMER = 'name: Build and consume the independent enrollment exchange wheel\n'
CONTINUATION = 'name: Verify independent root continuation from the installed wheel\n'


def validate(text):
    if text.count('      - research/continuity-openssl-peer/root_transition*.py\n') != 2:
        raise ValueError('closure transitions require push and pull-request triggers')
    if text.count('      - artifact/continuity_independent_install.py\n') != 2:
        raise ValueError('installation helper requires push and pull-request triggers')
    jobs = text.split('\n  root-continuation:\n')
    if len(jobs) != 2 or any(job.count('    timeout-minutes: 60\n') != 1 for job in jobs):
        raise ValueError('root continuation requires a separate bounded job')
    steps = text.split('\n      - ')
    consumers = [step for step in steps if step.startswith(CONSUMER)]
    later = [step for step in steps if step.startswith(CONTINUATION)]
    if len(consumers) != 1 or len(later) != 1 or CONTINUATION not in jobs[1] or CONSUMER not in jobs[0]:
        raise ValueError('each job requires its independent installed producer step')
    consumer, continuation = consumers[0], later[0]
    for owner, installer, flags in (
        (consumer, 'continuity_host_exchange.py', ('--root-child-inspection', '--root-retirement "$mode"',
            '--root-retirement-cuts', '--root-successor-cuts', '--root-successor-cancellation',
            '--root-successor-process-restart "$mode"', '--retirement-result')),
        (continuation, 'continuity_independent_install.py', ('--root-successor-later-cuts', '--root-transition-cuts',
            '--root-successor-process-restart peer-root-continuation')),
    ):
        if 'QPERIAPT_PYTHON: ${{ steps.python.outputs.python-path }}' not in owner:
            raise ValueError('installed checks require selected Python')
        prerequisites = ('--target "$RUNNER_TEMP/reference-provider"',
                         'sh artifact/python-run.sh artifact/' + installer, 'installed_reference=$(jq -er',
                         'cargo build --locked --release --manifest-path research/continuity-openssl-peer/native/Cargo.toml')
        for flag in flags:
            if [step for step in steps if flag in step] != [owner]:
                raise ValueError('root checks must share the installed producer step')
        for flag in (*flags, '--root-successor "$mode"'):
            position = owner.index(flag)
            if any(item not in owner or owner.index(item) >= position for item in prerequisites):
                raise ValueError('root checks precede installed inputs')
    original_modes = consumer.split('--root-successor "$mode"', 1)[0].rsplit('for mode in ', 1)[1].split('; do', 1)[0].split()
    if original_modes != ['steady', 'credential', 'before', 'after', 'parent', 'ready', 'peer', 'peer-credential', 'peer-before', 'peer-after']:
        raise ValueError('original successor coverage must remain complete')
    successor_modes = continuation.split('--root-successor "$mode"', 1)[0].rsplit('for mode in ', 1)[1].split('; do', 1)[0].split()
    if successor_modes.count('peer-root-revocation') != 1:
        raise ValueError('later root permission revocation must run exactly once')
    if successor_modes.count('peer-root-replacement') != 1:
        raise ValueError('later root committed replacement must run exactly once')
    if successor_modes.count('peer-root-continuation') != 1:
        raise ValueError('later root independent traffic must run exactly once')
    if any(successor_modes.count(mode)!=1 for mode in ('replan-plan','replan-decision')):
        raise ValueError('both root closure transitions must run exactly once')
    restart_modes = consumer.split('--root-successor-process-restart "$mode"', 1)[0].rsplit('for mode in ', 1)[1].split('; do', 1)[0].split()
    if restart_modes != ['peer', 'peer-credential', 'peer-before', 'peer-after'] or continuation.count('--root-successor-process-restart peer-root-continuation') != 1:
        raise ValueError('original and later root process restarts must each run exactly once')
    for required in ('for phase in bind retire; do', '--root-successor-later-cuts "$phase"',
                     'later_cut_pids+=("$!")', 'for later_cut_pid in "${later_cut_pids[@]}"; do',
                     'if ! wait "$later_cut_pid"; then later_cut_status=1; fi', 'test "$later_cut_status" -eq 0'):
        if continuation.count(required) != 1:
            raise ValueError('both later root cut groups must finish and propagate failures')
    for required in ('for closure in plan decision; do','--root-transition-cuts "$closure"',
                     'transition_pids+=("$!")','for transition_pid in "${transition_pids[@]}"; do',
                     'if ! wait "$transition_pid"; then transition_status=1; fi','test "$transition_status" -eq 0'):
        if continuation.count(required)!=1:
            raise ValueError('both closure transition cut groups must finish and propagate failures')


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
        command = '--root-successor-process-restart peer-root-continuation'
        for replacement in ('', command + ' ' + command):
            changed = self.text.replace(command, replacement)
            self.assertNotEqual(changed, self.text)
            with self.assertRaisesRegex(ValueError, 'installed producer step|process restarts must each run exactly once'):
                validate(changed)

    def test_continuation_cannot_be_stacked_or_budget_relaxed(self):
        for before, after in (('\n  root-continuation:\n', '\n  other:\n'),
                              ('timeout-minutes: 60', 'timeout-minutes: 90'),
                              ('continuity_independent_install.py', 'unverified_install.py')):
            with self.assertRaisesRegex(ValueError, 'separate bounded job|helper requires'):
                validate(self.text.replace(before, after))

    def test_closure_transitions_cannot_be_omitted_or_hide_failure(self):
        for before,after in (('replan-plan replan-decision','replan-plan'),
                             ('      - research/continuity-openssl-peer/root_transition*.py\n',''),
                             ('for closure in plan decision; do','for closure in plan; do'),
                             ('then transition_status=1;','then transition_status=0;'),
                             ('test "$transition_status" -eq 0','true')):
            changed=self.text.replace(before,after)
            self.assertNotEqual(changed,self.text)
            with self.assertRaisesRegex(ValueError,'closure transition'):
                validate(changed)


if __name__ == '__main__':
    unittest.main()
