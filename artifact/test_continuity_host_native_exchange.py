"""False completion and wrong-producer counterexamples for native exchange receipts."""
import copy
from pathlib import Path
import unittest
from continuity_host_native_exchange import LABELS, REFUSALS, verify


class NativeExchangeReceiptTests(unittest.TestCase):
    def setUp(self):
        self.binaries={'/native/device':'a'*64,'/native/session':'b'*64}
        self.application=Path('/installed')
        self.valid={'schema_version':1,'kind':'qperiapt.native_reference_exchange','completed':True,
            'native_sha256':self.binaries.copy(),'implementation':'/installed/qperiapt_continuity_reference/publication.py',
            'provider':'48.0.1','confirmed_epoch':1,'control_exchanges':2,'clock':'actual OS time',
            'commands':[{'label':name,'exit':1 if name in ('missing-inbox','wrong-inbox-journal') else 0} for name in LABELS],
            'refusals':list(REFUSALS)}
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


if __name__=='__main__': unittest.main()
