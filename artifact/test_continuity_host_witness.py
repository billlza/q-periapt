"""Reject omitted or relabelled witness lifecycle evidence."""
import copy
from pathlib import Path
import unittest
from continuity_host_witness import LABELS,FAILED,REFUSALS,verify
from continuity_independent_python import PACKAGE


def fixture():
    def stats(n):
        return dict(accepted=n,completed_responses=n,evicted_incomplete=0,
                    rejected_busy=0,read_errors=0,operation_errors=0,last_operation_error=None)
    def service(label,pid,n):return dict(label=label,pid=pid,exit=0,stats=stats(n))
    return dict(schema_version=1,kind='qperiapt.required_witness_session_cli',completed=True,
        confirmed_epoch=2,effects=3,native_sha256={},provider='48.0.1',
        implementation=str(Path('/installed')/PACKAGE/'session_cli.py'),clock='actual OS time',
        commands=[dict(label=label,exit=1 if label in FAILED else 0) for label in LABELS],
        refusals=list(REFUSALS),witness_keys_unchanged=True,
        genesis=dict(preparation='RequiresWitnessEnrollment',subject=[1]*96,head=[2]*32),
        native_service=service('witness-native-service',1,7),
        independent_service=service('witness-independent-service',2,3),
        witness_services=[dict(label='witness-first',pid=3,exit=-9),service('witness-reopened',4,512)])


class WitnessEvidence(unittest.TestCase):
    def accepted(self,value):verify(value,{},Path('/installed'))

    def test_complete_shape_and_bounded_witness_workload(self):
        self.accepted(fixture())
        for n in (0,1025,True):
            value=fixture();value['witness_services'][1]['stats']['completed_responses']=n
            with self.assertRaises(ValueError):self.accepted(value)

    def test_omitted_refusal_or_claimed_success_is_rejected(self):
        value=fixture();value['commands'].pop()
        with self.assertRaises(ValueError):self.accepted(value)
        for label in FAILED:
            value=fixture()
            next(row for row in value['commands'] if row['label']==label)['exit']=0
            with self.assertRaises(ValueError):self.accepted(value)
        value=fixture();value['refusals'].remove('witness-cli-offline')
        with self.assertRaises(ValueError):self.accepted(value)

    def test_replacement_process_or_missing_kill_is_rejected(self):
        for field,new in [('exit',0),('pid',2),('label','replacement-witness')]:
            value=fixture();value['witness_services'][0][field]=new
            with self.assertRaises(ValueError):self.accepted(value)
        value=fixture();value['witness_keys_unchanged']=False
        with self.assertRaises(ValueError):self.accepted(value)

    def test_local_profile_incomplete_genesis_and_weaker_results_are_rejected(self):
        for field,new in [('confirmed_epoch',1),('effects',2),('clock','fixture time')]:
            value=fixture();value[field]=new
            with self.assertRaises(ValueError):self.accepted(value)
        for change in [dict(preparation='LocalReady'),dict(subject=[1]*95),dict(head=[0]*32),dict(head=[True]*32)]:
            value=fixture();value['genesis'].update(copy.deepcopy(change))
            with self.assertRaises(ValueError):self.accepted(value)


if __name__=='__main__':unittest.main()
