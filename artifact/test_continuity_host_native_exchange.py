"""False completion and wrong-producer counterexamples for native exchange receipts."""
import copy
import hashlib
from pathlib import Path
import unittest
from continuity_host_native_exchange import (CUT_STAGES, CONFIRMATION_CUTS, LABELS, REFUSALS,
                                             CONNECTION_EVENTS, CONNECTION_BOUNDS, expected_exit, verify)


class NativeExchangeReceiptTests(unittest.TestCase):
    def setUp(self):
        self.binaries={'/native/device':'a'*64,'/native/session':'b'*64,'/tests/crash-probe':'c'*64}
        self.application=Path('/installed')
        self.valid={'schema_version':4,'kind':'qperiapt.native_reference_exchange','completed':True,
            'native_sha256':self.binaries.copy(),'implementation':'/installed/qperiapt_continuity_reference/publication.py',
            'provider':'48.0.1','confirmed_epoch':2,'control_exchanges':5,'clock':'actual OS time',
            'commands':[{'label':name,'exit':expected_exit(name)} for name in LABELS],
            'refusals':list(REFUSALS),'process_kills':[
                {'stage':stage,'pid':i+100,'exit':-9,'inbox_flags':6,'marker_sha256':hashlib.sha256(f'{i+100} {stage}\n'.encode()).hexdigest()}
                for i,stage in enumerate(CUT_STAGES)],
            'connection_confirmation':{'schema_version':1,'recovery_failure':True,'raw_traffic_unrecorded':True,
                'exact_retry_unchanged':True,'closed_owner_refused':True,'post_rekey_reopen':True,'process_kills':[
                    {'stage':stage,'pid':i+200,'exit':-9,'marker_sha256':hashlib.sha256(
                        f'{i+200} client-device:registration-store:{stage}\n'.encode()).hexdigest()}
                    for i,stage in enumerate(CONFIRMATION_CUTS)]},
            'connection_operations':{'schema_version':1,'complete':True,'confirmed_epoch':2,'control_exchanges':3,
                'native_commands':12,'events':list(CONNECTION_EVENTS),'boundary_checks':list(CONNECTION_BOUNDS)}}
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

    def test_unrecorded_confirmation_missing_cuts_and_unproven_reopen_are_rejected(self):
        self.reject(lambda r:r.update(schema_version=2))
        self.reject(lambda r:r.pop('connection_confirmation'))
        self.reject(lambda r:r['connection_confirmation'].update(process_kills=[]))
        self.reject(lambda r:r['connection_confirmation'].update(post_rekey_reopen=False))
        self.reject(lambda r:r['connection_confirmation']['process_kills'][0].update(exit=0))
        self.reject(lambda r:r['connection_confirmation']['process_kills'][0].update(pid=100))
        self.reject(lambda r:r['connection_confirmation']['process_kills'][1].update(marker_sha256='a'*64))

    def test_missing_owned_operation_boundary_or_wrong_completion_is_rejected(self):
        self.reject(lambda r:r.update(schema_version=3))
        self.reject(lambda r:r.pop('connection_operations'))
        self.reject(lambda r:r['connection_operations']['events'].pop())
        self.reject(lambda r:r['connection_operations'].update(boundary_checks=[]))
        self.reject(lambda r:r['connection_operations'].update(confirmed_epoch=True))
        self.reject(lambda r:r['connection_operations'].update(control_exchanges=2))
        self.reject(lambda r:r['connection_operations'].update(complete=False))


if __name__=='__main__': unittest.main()
