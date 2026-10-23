"""Keep baseline account coverage and dispatch all complete root cohorts."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parent.parent
CONSUMER='name: Build and consume the independent enrollment exchange wheel\n'


def validate(text):
    for path in ('.github/workflows/reference-root.yml','artifact/continuity_independent_install.py',
                 'artifact/continuity_root_scenarios.sh','artifact/test_reference_root_workflow.py',
                 'research/continuity-openssl-peer/root_transition*.py','research/continuity-openssl-peer/root_winner*.py',
                 'research/continuity-openssl-peer/root_unactivated*.py',
                 'research/continuity-openssl-peer/tests/fixtures/account-authority-v1/**'):
        if text.count('      - '+path+'\n')!=2:raise ValueError('root lifecycle requires push and pull-request triggers')
    for lane in ('continuation','winner','unactivated'):
        call='  root-'+lane+':\n    uses: ./.github/workflows/reference-root.yml\n    with:\n      lane: '+lane+'\n'
        if text.count(call)!=1:raise ValueError('each complete root cohort needs its own reusable job')
    if text.count('    timeout-minutes: 60\n')!=1:raise ValueError('baseline account job keeps its original time budget')
    steps=text.split('\n      - ');owners=[step for step in steps if step.startswith(CONSUMER)]
    if len(owners)!=1:raise ValueError('one installed account producer required')
    owner=owners[0]
    if 'QPERIAPT_PYTHON: ${{ steps.python.outputs.python-path }}' not in owner:
        raise ValueError('installed checks require selected Python')
    prerequisites=('--target "$RUNNER_TEMP/reference-provider"',
                   'sh artifact/python-run.sh artifact/continuity_host_exchange.py','installed_reference=$(jq -er',
                   'cargo build --locked --release --manifest-path research/continuity-openssl-peer/native/Cargo.toml')
    for flag in ('--root-child-inspection','--root-retirement "$mode"','--root-retirement-cuts',
                 '--root-successor "$mode"','--root-successor-cuts','--root-successor-cancellation',
                 '--root-successor-process-restart "$mode"','--retirement-result'):
        if [step for step in steps if flag in step]!=[owner]:raise ValueError('root checks must share the installed producer step')
        if any(item not in owner or owner.index(item)>=owner.index(flag) for item in prerequisites):
            raise ValueError('root checks precede installed inputs')
    def modes(flag):return owner.split(flag,1)[0].rsplit('for mode in ',1)[1].split('; do',1)[0].split()
    if modes('--root-successor "$mode"')!=['steady','credential','before','after','parent','ready','peer','peer-credential','peer-before','peer-after']:
        raise ValueError('original successor coverage must remain complete')
    if modes('--root-successor-process-restart "$mode"')!=['peer','peer-credential','peer-before','peer-after']:
        raise ValueError('original process restarts must each run exactly once')


class ReferenceAccountWorkflowTests(unittest.TestCase):
    def setUp(self):self.text=(ROOT/'.github/workflows/reference-account.yml').read_text()
    def test_complete_account_and_two_root_cohorts(self):validate(self.text)
    def test_installed_inputs_and_interpreter_cannot_be_dropped(self):
        for before,after in (('installed_reference=$(jq -er','unused_reference=$(jq -er'),
                             ('QPERIAPT_PYTHON: ${{ steps.python.outputs.python-path }}','QPERIAPT_PYTHON: /usr/bin/python3')):
            with self.assertRaisesRegex(ValueError,'installed inputs|selected Python'):validate(self.text.replace(before,after))
    def test_root_checks_cannot_move_before_their_producer(self):
        start=self.text.index('          for mode in steady ordinary-before ordinary-after credential')
        end=self.text.index('          done\n',start)+len('          done\n');block=self.text[start:end]
        moved=self.text[:start]+self.text[end:];position=moved.index('      - '+CONSUMER)
        with self.assertRaisesRegex(ValueError,'installed producer step'):validate(moved[:position]+block+moved[position:])
    def test_baseline_modes_cannot_be_dropped_or_repeated(self):
        for before,after in (('parent ready peer peer-credential','parent peer peer-credential'),
                             ('for mode in peer peer-credential peer-before peer-after; do','for mode in peer peer-credential peer-before peer-before peer-after; do')):
            with self.assertRaisesRegex(ValueError,'coverage|restarts'):validate(self.text.replace(before,after))
    def test_root_cohort_and_source_trigger_are_required(self):
        for before,after in (('      lane: winner\n','      lane: continuation\n'),
                             ('      - artifact/continuity_root_scenarios.sh\n',''),
                             ('timeout-minutes: 60','timeout-minutes: 90')):
            with self.assertRaisesRegex(ValueError,'cohort|triggers|budget'):validate(self.text.replace(before,after))


if __name__=='__main__':unittest.main()
