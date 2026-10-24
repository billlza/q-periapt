"""Keep baseline account coverage and dispatch all complete root cohorts."""
from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parent.parent
CONSUMER='name: Build and consume the independent enrollment exchange wheel\n'
VALIDATION_STEPS=(
    'Verify browser recovery and exact integer transport',
    'Verify account Debug regression and lint',
    'Verify account Release regression and native signers',
)
SHARED_STEPS=(
    'Build account and native release executables',
    'Record native executable and dependency identities',
)
FIXTURE_STEP='Prepare the original root registry inputs'


def validate_lanes(text, steps):
    lanes=re.findall(r'          - os: (\S+)\n            arch: (\S+)\n            lane: (\S+)\n',text)
    expected={(host,arch,lane) for host,arch in (('ubuntu-24.04','x86_64'),('macos-15','arm64'))
              for lane in ('validation','exchange')}
    if len(lanes)!=4 or set(lanes)!=expected:
        raise ValueError('each supported host requires both complete account lanes')
    if 'case "$ACCOUNT_LANE" in validation|exchange) ;; *) exit 2 ;; esac' not in text:
        raise ValueError('unknown account lane must fail')
    if 'name: reference-account-${{ matrix.os }}-${{ matrix.lane }}\n' not in text:
        raise ValueError('account lane evidence must not collide')
    if '      fail-fast: false\n' not in text:
        raise ValueError('failed account lane must not cancel its peers')
    def step(name):
        found=[s for s in steps if s.startswith('name: '+name+'\n')]
        if len(found)!=1:raise ValueError('each account step is required exactly once')
        return found[0]
    for name,lane in [(n,'validation') for n in VALIDATION_STEPS]+[(FIXTURE_STEP,'exchange'),(CONSUMER[6:-1],'exchange')]:
        if re.findall(r'^        if: (.+)$',step(name),re.M)!=["matrix.lane == '"+lane+"'"]:
            raise ValueError('account step routed to wrong lane')
    for name in SHARED_STEPS:
        if re.search(r'^        if:',step(name),re.M):
            raise ValueError('both account lanes require native builds and identities')
    fixture=step(FIXTURE_STEP)
    if '--lib --no-run --message-format=json' not in fixture or 'original_root_registry_fixture_child -- --nocapture' not in fixture:
        raise ValueError('exchange requires its own original root fixture and test executable')
    order=[steps.index(step(name)) for name in (SHARED_STEPS[0],FIXTURE_STEP,SHARED_STEPS[1],CONSUMER[6:-1])]
    if order!=sorted(order):raise ValueError('exchange inputs must be prepared before their consumer')
    for name in SHARED_STEPS+(FIXTURE_STEP,CONSUMER[6:-1]):
        if 'CARGO_TARGET_DIR: ${{ runner.temp }}/reference-account-build' not in step(name):
            raise ValueError('exchange inputs must share the same native build')


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
    validate_lanes(text,steps)
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
    def test_both_hosts_require_both_lanes_and_distinct_evidence(self):
        for before,after in (('            lane: exchange\n','            lane: validation\n'),
                             ('            arch: arm64\n','            arch: x86_64\n'),
                             ('name: reference-account-${{ matrix.os }}-${{ matrix.lane }}',
                              'name: reference-account-${{ matrix.os }}'),
                             ('fail-fast: false','fail-fast: true'),
                             ('validation|exchange) ;; *) exit 2 ;; esac','validation|exchange) ;; *) ;; esac')):
            with self.assertRaises(ValueError):validate(self.text.replace(before,after))
    def test_native_checks_and_exchange_cannot_be_skipped_or_misrouted(self):
        for name,lane in [(n,'validation') for n in VALIDATION_STEPS]+[(FIXTURE_STEP,'exchange'),(CONSUMER[6:-1],'exchange')]:
            prefix='name: '+name+'\n        if: '
            for condition in ('false',"matrix.lane == 'missing'",'always()'):
                with self.assertRaisesRegex(ValueError,'wrong lane'):
                    validate(self.text.replace(prefix+"matrix.lane == '"+lane+"'",prefix+condition))
    def test_fixture_build_and_consumer_stay_together(self):
        for before,after in (('--lib --no-run --message-format=json','--lib --no-run'),
                             ('original_root_registry_fixture_child -- --nocapture','wrong_fixture -- --nocapture'),
                             ('name: '+FIXTURE_STEP+'\n','name: omitted fixture\n'),
                             ('name: '+SHARED_STEPS[0]+'\n','name: '+SHARED_STEPS[0]+"\n        if: matrix.lane == 'validation'\n"),
                             ('CARGO_TARGET_DIR: ${{ runner.temp }}/reference-account-build','CARGO_TARGET_DIR: /wrong/build')):
            with self.assertRaises(ValueError):validate(self.text.replace(before,after))
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
