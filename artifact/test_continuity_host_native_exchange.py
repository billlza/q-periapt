"""False completion and wrong-producer counterexamples for native exchange receipts."""
import copy
import hashlib
from pathlib import Path
import unittest
from continuity_host_native_exchange import CUT_STAGES, LABELS, REFUSALS, expected_exit, verify


class NativeExchangeReceiptTests(unittest.TestCase):
    def setUp(self):
        self.binaries={'/native/device':'a'*64,'/native/session':'b'*64,'/tests/crash-probe':'c'*64}
        self.application=Path('/installed')
        self.valid={'schema_version':2,'kind':'qperiapt.native_reference_exchange','completed':True,
            'native_sha256':self.binaries.copy(),'implementation':'/installed/qperiapt_continuity_reference/publication.py',
            'provider':'48.0.1','confirmed_epoch':1,'control_exchanges':2,'clock':'actual OS time',
            'commands':[{'label':name,'exit':expected_exit(name)} for name in LABELS],
            'refusals':list(REFUSALS),'process_kills':[
                {'stage':stage,'pid':i+100,'exit':-9,'inbox_flags':6,'marker_sha256':hashlib.sha256(f'{i+100} {stage}\n'.encode()).hexdigest()}
                for i,stage in enumerate(CUT_STAGES)]}
        verify(self.valid,self.binaries,self.application)

    def reject(self, change):
        bad=copy.deepcopy(self.valid); change(bad)
        with self.assertRaises(ValueError): verify(bad,self.binaries,self.application)

    def test_green_completion_without_executions_is_rejected(self):
        self.reject(lambda r:r.update(commands=[]))
        self.reject(lambda r:r.update(refusals=[]))
        self.reject(lambda r:r['commands'].pop())
        self.reject(lambda r:r['commands'][8].update(exit=0))

    def test_wrong_source_and_uninstalled_reader_are_rejected(self):
        self.reject(lambda r:r['native_sha256'].update({'/native/session':'c'*64}))
        self.reject(lambda r:r.update(implementation='/checkout/qperiapt_continuity_reference/publication.py'))
        self.reject(lambda r:r.update(provider='unknown'))

    def test_booleans_and_failed_operations_cannot_claim_epoch_completion(self):
        self.reject(lambda r:r.update(confirmed_epoch=True))
        self.reject(lambda r:r.update(control_exchanges=True))
        self.reject(lambda r:r['commands'][0].update(exit=False))
        self.reject(lambda r:r['commands'][-1].update(exit=1))
        self.reject(lambda r:r.update(completed=False))

    def test_missing_kill_wrong_stage_or_clean_exit_cannot_claim_crash_recovery(self):
        self.reject(lambda r:r.update(process_kills=[]))
        self.reject(lambda r:r['process_kills'][1].update(stage='before-effect'))
        self.reject(lambda r:r['process_kills'][1].update(exit=0))
        self.reject(lambda r:r['process_kills'][1].update(marker_sha256='a'*64))
        self.reject(lambda r:r['process_kills'][1].update(inbox_flags=2))


if __name__=='__main__': unittest.main()
