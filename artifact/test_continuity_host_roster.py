"""Reject omitted R phases, invented commitment, resets and missing real traffic."""
import base64
from pathlib import Path
import unittest
from continuity_host_roster import LABELS, FAILED, HTTP, verify


def fixture():
    def identity(n): return base64.urlsafe_b64encode(bytes([n])*32).rstrip(b'=').decode()
    def stats(n): return dict(accepted=n,completed_responses=n,evicted_incomplete=0,
        rejected_busy=0,read_errors=0,operation_errors=0,last_operation_error=None)
    def process(label,pid,n): return dict(label=label,pid=pid,exit=0,stats=stats(n))
    transitions=[]
    for i in (1,2):
        binding=[i]*32
        scope=dict(operation=[i]*32,previous=dict(version=i,digest=[i]*32),target=dict(version=i+1,digest=[i+1]*32),
                   policy=dict(version=i,digest=[10+i]*32),policy_authorization=None if i==1 else [8]*32)
        transitions.append(dict(operation=identity(i),binding=binding,observation=dict(binding=binding,state='Applied'),
            progress=dict(schema='qperiapt-roster-refresh-progress/1',state='Applied',retired=True,binding=binding,scope=scope)))
    return dict(kind='qperiapt.authenticated_surviving_device_roster',completed=True,release_claim_eligible=False,cleanup_errors=[],
        schema_version=2,effects=4,confirmed_epoch=1,sibling_generation=1,successor_generation=2,native_sha256={},provider='48.0.1',
        implementation='/installed/qperiapt_continuity_reference/session_cli.py',clock='actual OS time',
        original_keys_unchanged=True,old_sibling_unchanged=True,session=identity(4),journal=identity(5),original_pending_message=identity(6),policy_pending_message=identity(9),
        commands=[dict(label=k,exit=1 if k in FAILED else 0) for k in LABELS],
        account_requests=[dict(label=k,id=i,action='register' if k.startswith('register-') else 'login' if k=='alice-relogin'
            else 'finish' if k=='probe-finish' else 'request') for i,k in enumerate(HTTP,1)],transitions=transitions,
        policy_transition=policy_fixture(identity,transitions),
        services=[process('survivor-first',1,3),process('survivor-after-add',2,2),process('survivor-after-replacement',3,4)],
        witness_services=[dict(label='witness-first',pid=4,exit=-9),process('witness-reopened',5,5)],
        account_services=[dict(label='account-first',pid=6,exit=-9),process('account-reopened',7,1)],
        independent_service=process('peer-receiver',8,1))


def policy_fixture(identity,transitions):
    proposal=base64.urlsafe_b64encode(b'QPPWNP01'+bytes([7])*288).rstrip(b'=').decode()
    preparation=dict(schema='qperiapt-policy-witness-preparation/1',binding=[7]*32,proposal=proposal,approval=identity(7))
    target=transitions[1]['progress']['scope']['policy']
    return dict(operation=identity(7),statement=identity(8),preparation=preparation,
        observation=dict(binding=[7]*32,state='Applied'),
        progress=dict(schema='qperiapt-policy-witness-progress/1',state='Applied',retired=True,binding=[7]*32,proposal=proposal,target=target),
        request=dict(schema='qperiapt-retained-policy-request/1',scope=dict(operation=[7]*32,journal=[5]*32,
            current_roster=transitions[0]['progress']['scope']['target'],previous_authorization=None,
            original_policy=transitions[0]['progress']['scope']['policy'],previous_policy=transitions[0]['progress']['scope']['policy'])),
        account_approval=dict(operation=[7]*32,statement=[8]*32,target=target),policy_approval=dict(operation=[7]*32,statement=[8]*32))


class RosterEvidence(unittest.TestCase):
    def accepted(self,value): verify(value,{},Path('/installed'))
    def test_complete(self): self.accepted(fixture())

    def test_missing_step_or_converted_failure(self):
        for key in ('commands','account_requests','transitions','services'):
            value=fixture();value[key].pop()
            with self.subTest(key=key), self.assertRaises(ValueError): self.accepted(value)
        for label in FAILED:
            value=fixture();next(row for row in value['commands'] if row['label']==label)['exit']=0
            with self.subTest(label=label), self.assertRaises(ValueError): self.accepted(value)

    def test_unretired_unavailable_or_broken_original_chain(self):
        for key,wrong in [('retired',False),('state','Unavailable'),('binding',[99]*32)]:
            value=fixture();value['transitions'][1]['progress'][key]=wrong
            with self.subTest(key=key), self.assertRaises(ValueError): self.accepted(value)
        value=fixture();value['transitions'][1]['progress']['scope']['previous']['digest']=[99]*32
        with self.assertRaises(ValueError): self.accepted(value)

    def test_required_lifecycle_and_traffic_evidence(self):
        for key,wrong in [('completed',False),('release_claim_eligible',True),('effects',True),
                          ('original_keys_unchanged',False),('cleanup_errors',['child running']),('confirmed_epoch',0)]:
            value=fixture();value[key]=wrong
            with self.subTest(key=key), self.assertRaises(ValueError): self.accepted(value)
        for group in ('witness_services','account_services'):
            value=fixture();value[group][0]['exit']=0
            with self.subTest(group=group), self.assertRaises(ValueError): self.accepted(value)
        value=fixture();value['services'][2]['stats']['completed_responses']=0
        with self.assertRaises(ValueError): self.accepted(value)

    def test_policy_approval_and_roster_composition_are_required(self):
        for key,wrong in [('state','Unavailable'),('retired',False),('proposal','wrong'),('binding',[0]*32)]:
            value=fixture();value['policy_transition']['progress'][key]=wrong
            with self.subTest(key=key),self.assertRaises(ValueError):self.accepted(value)
        for part in ('account_approval','policy_approval'):
            value=fixture();value['policy_transition'][part]['statement']=[99]*32
            with self.subTest(part=part),self.assertRaises(ValueError):self.accepted(value)
        for part in ('current_roster','previous_policy'):
            value=fixture();value['policy_transition']['request']['scope'][part]=dict(version=99,digest=[99]*32)
            with self.subTest(part=part),self.assertRaises(ValueError):self.accepted(value)
        value=fixture();value['transitions'][1]['progress']['scope']['policy_authorization']=None
        with self.assertRaises(ValueError):self.accepted(value)


if __name__=='__main__': unittest.main()
