"""Counterexamples for command-boundary receipts, not cryptographic evidence."""
import copy
from pathlib import Path
import unittest
from continuity_host_cli import verify,LABELS,REFUSALS,FRAMES,CONTROL_PHASES,CONTROL_FRAMES


class CliReceiptTests(unittest.TestCase):
    def setUp(self):
        self.application=Path('/installed');self.binaries={'/native':'a'*64}
        def stats(n,*,native=False):return dict(accepted=n,completed_responses=n,evicted_incomplete=0,
            rejected_busy=0,read_errors=0,operation_errors=0,last_operation_error=None,
            **(dict(queued_requests=0,expired_queued=0) if native else {}))
        self.value=dict(schema_version=1,kind='qperiapt.independent_session_cli',completed=True,
            native_sha256=self.binaries.copy(),provider='48.0.1',clock='actual OS time',
            implementation='/installed/qperiapt_continuity_reference/session_cli.py',confirmed_epoch=7,
            commands=[dict(label=n,exit=1 if n in REFUSALS else 0) for n in LABELS],refusals=list(REFUSALS),
            frames=[dict(label=n,kind=k,request_sha256='b'*64,response_sha256='c'*64) for n,k in FRAMES],
            relay=stats(7),native_service=dict(label='cli-native-service',pid=10,exit=0,stats=stats(8,native=True)),
            inbound=dict(confirmed_epoch=2,effects=3,original_effect_unchanged_on_retry=True,
                relay=stats(4),frames=[dict(label='cli-inbound-wire-'+str(i),kind=k,request_sha256='b'*64,response_sha256='c'*64)
                    for i,k in enumerate((3,4,4,3),1)],
                receivers=[dict(label='cli-inbound-first',pid=11,exit=-9),
                           dict(label='cli-inbound-reopened',pid=12,exit=0,stats=stats(4))]))
        self.value['opposing']=dict(simultaneous=True,effects=2,
            phase_refusals=['wrong-journal','cancelled-reply','tampered-ack'],
            frames=[dict(label=label,kind=3,request_sha256='b'*64,response_sha256='c'*64)
                    for label in ('cli-opposing-native-wire','cli-opposing-python-wire')],
            relays=[stats(1),stats(1)],
            native_service=dict(label='cli-opposing-native-service',pid=13,exit=0,stats=stats(7,native=True)),
            independent_service=dict(label='cli-opposing-independent-service',pid=14,exit=0,stats=stats(1)))
        self.value['opposing_rekey']=dict(target=3,simultaneous=True,effects=2,
            phase_refusals=copy.deepcopy(list(CONTROL_PHASES)),
            frames=[dict(label=n,kind=k,request_sha256='b'*64,response_sha256='c'*64) for n,k in CONTROL_FRAMES],
            relays=[stats(2),stats(3)],
            native_service=dict(label='cli-rekey-native-service',pid=15,exit=0,stats=stats(17,native=True)),
            independent_service=dict(label='cli-rekey-independent-service',pid=16,exit=0,stats=stats(5)))
        verify(self.value,self.binaries,self.application)

    def reject(self,change):
        value=copy.deepcopy(self.value);change(value)
        with self.assertRaises(ValueError):verify(value,self.binaries,self.application)

    def test_missing_command_or_disguised_failure_is_rejected(self):
        self.reject(lambda v:v['commands'].pop())
        self.reject(lambda v:v['commands'][LABELS.index('cli-lost')].update(exit=0))
        self.reject(lambda v:v.update(refusals=[]))

    def test_wrong_implementation_and_incomplete_exchange_are_rejected(self):
        self.reject(lambda v:v.update(implementation='/checkout/session_cli.py'))
        self.reject(lambda v:v.update(native_sha256={}))
        self.reject(lambda v:v['frames'].pop())
        self.reject(lambda v:v['frames'][0].update(kind=True))

    def test_unjoined_or_failed_service_is_rejected(self):
        self.reject(lambda v:v['native_service'].update(exit=1))
        self.reject(lambda v:v['native_service']['stats'].update(completed_responses=7))
        self.reject(lambda v:v['relay'].update(operation_errors=1))
        self.reject(lambda v:v.update(confirmed_epoch=True))

    def test_inbound_receiver_kill_retry_and_effect_evidence_are_required(self):
        self.reject(lambda v:v.pop('inbound'))
        self.reject(lambda v:v['inbound']['receivers'][0].update(exit=0))
        self.reject(lambda v:v['inbound']['receivers'][1]['stats'].update(completed_responses=3))
        self.reject(lambda v:v['inbound'].update(original_effect_unchanged_on_retry=False))
        self.reject(lambda v:v['inbound'].update(effects=True))
        self.reject(lambda v:v['inbound']['frames'].pop())

    def test_opposing_sends_and_fresh_completion_boundaries_are_required(self):
        self.reject(lambda v:v.pop('opposing'))
        self.reject(lambda v:v['opposing'].update(simultaneous=False))
        self.reject(lambda v:v['opposing']['phase_refusals'].pop())
        self.reject(lambda v:v['opposing']['relays'][0].update(operation_errors=1))
        self.reject(lambda v:v['opposing']['native_service']['stats'].update(completed_responses=6))

    def test_simultaneous_rekey_original_receipts_and_phase_refusals_are_required(self):
        self.reject(lambda v:v.pop('opposing_rekey'))
        self.reject(lambda v:v['opposing_rekey'].update(target=4))
        self.reject(lambda v:v['opposing_rekey'].update(simultaneous=False))
        self.reject(lambda v:v['opposing_rekey']['phase_refusals'][0].update(target=5))
        self.reject(lambda v:v['opposing_rekey']['relays'][0].update(operation_errors=1))
        self.reject(lambda v:v['opposing_rekey']['frames'].pop())

if __name__=='__main__':unittest.main()
