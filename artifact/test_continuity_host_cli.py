"""Counterexamples for command-boundary receipts, not cryptographic evidence."""
import copy
from pathlib import Path
import unittest
from continuity_host_cli import verify,LABELS,REFUSALS,FRAMES


class CliReceiptTests(unittest.TestCase):
    def setUp(self):
        self.application=Path('/installed');self.binaries={'/native':'a'*64}
        def stats(n):return dict(accepted=n,completed_responses=n,evicted_incomplete=0,
            rejected_busy=0,read_errors=0,operation_errors=0,last_operation_error=None)
        self.value=dict(schema_version=1,kind='qperiapt.independent_session_cli',completed=True,
            native_sha256=self.binaries.copy(),provider='48.0.1',clock='actual OS time',
            implementation='/installed/qperiapt_continuity_reference/session_cli.py',confirmed_epoch=1,
            commands=[dict(label=n,exit=1 if n in REFUSALS else 0) for n in LABELS],refusals=list(REFUSALS),
            frames=[dict(label=n,kind=k,request_sha256='b'*64,response_sha256='c'*64) for n,k in FRAMES],
            relay=stats(7),native_service=dict(label='cli-native-service',pid=10,exit=0,stats=stats(8)))
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


if __name__=='__main__':unittest.main()
