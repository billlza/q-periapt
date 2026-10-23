"""Check workflow routing and shell failure propagation, not product behavior."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parent.parent
SCRIPT=ROOT/'artifact/continuity_root_scenarios.sh'


def validate(text):
    if '  workflow_call:\n' not in text or text.count('    timeout-minutes: 60\n')!=1:
        raise ValueError('reusable lifecycle job requires its unchanged time budget')
    for entry in ('          - os: ubuntu-24.04\n            arch: x86_64',
                  '          - os: macos-15\n            arch: arm64'):
        if text.count(entry)!=1:raise ValueError('both supported hosts are required')
    if 'QPERIAPT_PYTHON: ${{ steps.python.outputs.python-path }}' not in text:
        raise ValueError('root lifecycle requires selected Python')
    command='bash artifact/continuity_root_scenarios.sh "$ROOT_LANE" "$installed_reference"'
    required=('--target "$RUNNER_TEMP/reference-provider"','sh artifact/python-run.sh artifact/continuity_independent_install.py',
              "installed_reference=$(jq -er '.installed'",'cargo build --locked --release --manifest-path research/continuity-openssl-peer/native/Cargo.toml')
    if text.count(command)!=1 or any(item not in text or text.index(item)>=text.index(command) for item in required):
        raise ValueError('cohort execution must follow verified installed inputs')
    if '          case "$ROOT_LANE" in continuation|winner|unactivated) ;; *) exit 2 ;; esac' not in text:
        raise ValueError('unknown lifecycle input must fail')
    if '        if: always()' not in text or '          if-no-files-found: error' not in text:
        raise ValueError('failed lifecycle evidence must be retained')


class ReferenceRootWorkflowTests(unittest.TestCase):
    def test_workflow_keeps_inputs_hosts_and_budget(self):validate((ROOT/'.github/workflows/reference-root.yml').read_text())
    def test_unverified_inputs_or_relaxed_budget_refuse(self):
        text=(ROOT/'.github/workflows/reference-root.yml').read_text()
        for before,after in (('timeout-minutes: 60','timeout-minutes: 90'),
                             ('continuity_independent_install.py','unverified.py'),
                             ('arch: arm64','arch: x86_64'),('if: always()','if: success()')):
            with self.assertRaises(ValueError):validate(text.replace(before,after))

    def dispatch(self,lane,*,failure=''):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);root=Path(temporary.name)
        (root/'artifact').mkdir();trace=root/'trace';trace.mkdir();output=root/'target/output'
        # This spy records only dispatch. It produces no SDK result or acceptance evidence.
        (root/'artifact/python-run.sh').write_text('''#!/bin/sh
set -eu
printf '%s\\n' "$@" > "$ROOT_DISPATCH_TRACE/$$.args"
case " $* " in
  *" --root-successor-later-cuts retire "*) sleep 0.1 ;;
esac
: > "$ROOT_DISPATCH_TRACE/$$.done"
if [ -n "$ROOT_DISPATCH_FAIL" ]; then
  case " $* " in *" $ROOT_DISPATCH_FAIL "*) echo 'injected dispatch failure' >&2; exit 19 ;; esac
fi
''')
        env=dict(os.environ,ROOT_DISPATCH_TRACE=str(trace),ROOT_DISPATCH_FAIL=failure)
        result=subprocess.run(['bash',str(SCRIPT),lane,'installed path','provider path','native path',str(output)],
                              cwd=root,env=env,capture_output=True,timeout=10,check=False)
        records=[p.read_text().splitlines() for p in trace.glob('*.args')]
        self.assertEqual(len(records),len(list(trace.glob('*.done'))))
        return result,records,output

    @staticmethod
    def selections(records):
        return sorted((flag,row[index+1]) for row in records for index,flag in enumerate(row)
                      if flag.startswith('--root-'))

    def test_continuation_dispatch_preserves_every_scenario(self):
        result,records,_=self.dispatch('continuation');self.assertEqual(result.returncode,0,result.stderr)
        expected=[('--root-successor',mode) for mode in ('peer-root-revocation','peer-root-replacement','peer-root-continuation','replan-plan','replan-decision')]
        expected+=[('--root-successor-process-restart','peer-root-continuation')]
        expected+=[('--root-successor-later-cuts',phase) for phase in ('bind','retire')]
        expected+=[(flag,closure) for flag in ('--root-transition-cuts','--root-transition-cancellation') for closure in ('plan','decision')]
        self.assertEqual(self.selections(records),sorted(expected));self.assertEqual(len(records),12)
        for row in records:self.assertEqual(row[row.index('--implementation-root')+1],'installed path')

    def test_winner_dispatch_requires_compatibility_all_targets_and_both_boundary_groups(self):
        result,records,_=self.dispatch('winner');self.assertEqual(result.returncode,0,result.stderr)
        expected=[('--root-winner-adoption',mode) for mode in ('bound-fresh','bound-reuse','unbound-fresh','unbound-reuse',
                                                            'cross-application','bound-reuse-continue','bound-reuse-restart')]
        expected+=[(flag,mode) for flag in ('--root-winner-cuts','--root-winner-cancellation') for mode in ('bound-fresh','unbound-reuse')]
        self.assertEqual(self.selections(records),sorted(expected));self.assertEqual(len(records),12)
        self.assertEqual(sum(row[0].endswith('/account_authority_compatibility.py') for row in records),1)

    def test_failed_child_waits_for_its_peer_and_stops_later_groups(self):
        result,records,output=self.dispatch('continuation',failure='--root-successor-later-cuts bind')
        self.assertNotEqual(result.returncode,0);self.assertEqual(len(records),8)
        selected=self.selections(records)
        self.assertIn(('--root-successor-later-cuts','retire'),selected)
        self.assertFalse(any(flag=='--root-transition-cuts' for flag,_ in selected))
        self.assertIn(b'injected dispatch failure',(output/'later-root-cuts-bind.stderr').read_bytes())

    def test_unactivated_dispatch_keeps_both_approval_histories_and_restart_boundaries(self):
        result,records,_=self.dispatch('unactivated');self.assertEqual(result.returncode,0,result.stderr)
        expected=[('--root-unactivated-retirement',mode) for mode in ('planned','adopted','planned-restart','adopted-restart')]
        expected+=[(flag,kind) for flag in ('--root-unactivated-cuts','--root-unactivated-cancellation') for kind in ('planned','adopted')]
        self.assertEqual(self.selections(records),sorted(expected));self.assertEqual(len(records),8)

    def test_unknown_cohort_cannot_default_to_a_smaller_suite(self):
        result,records,output=self.dispatch('missing');self.assertEqual(result.returncode,2)
        self.assertEqual(records,[]);self.assertFalse(output.exists())


if __name__=='__main__':unittest.main()
