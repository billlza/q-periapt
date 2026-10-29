"""Reject omitted R/P/G phases, invented commitment and substituted recovery."""
import base64
from pathlib import Path
import unittest
from continuity_host_roster import LABELS, FAILED, HTTP, verify


def fixture():
    def identity(n): return base64.urlsafe_b64encode(bytes([n])*32).rstrip(b'=').decode()
    def stats(n,*,native=False): return dict(accepted=n,completed_responses=n,evicted_incomplete=0,
        rejected_busy=0,read_errors=0,operation_errors=0,last_operation_error=None,
        **(dict(queued_requests=0,expired_queued=0) if native else {}))
    def process(label,pid,n,*,native=False): return dict(label=label,pid=pid,exit=0,stats=stats(n,native=native))
    transitions=[]
    for i in (1,2):
        binding=[i]*32
        scope=dict(operation=[i]*32,previous=dict(version=i,digest=[i]*32),target=dict(version=i+1,digest=[i+1]*32),
                   policy=dict(version=i,digest=[10+i]*32),policy_authorization=None if i==1 else [8]*32)
        transitions.append(dict(operation=identity(i),binding=binding,observation=dict(binding=binding,state='Applied'),
            progress=dict(schema='qperiapt-roster-refresh-progress/1',state='Applied',retired=True,binding=binding,scope=scope)))
    return dict(kind='qperiapt.authenticated_surviving_device_roster',completed=True,release_claim_eligible=False,cleanup_errors=[],
        schema_version=6,effects=4,confirmed_epoch=1,sibling_generation=1,successor_generation=2,native_sha256={},provider='48.0.1',
        implementation='/installed/qperiapt_continuity_reference/session_cli.py',clock='actual OS time',
        original_keys_unchanged=True,old_sibling_unchanged=True,session=identity(4),journal=identity(5),original_pending_message=identity(6),policy_pending_message=identity(9),
        commands=[dict(label=k,exit=1 if k in FAILED else 0) for k in LABELS],
        account_requests=[dict(label=k,id=i,action='register' if k.startswith('register-') else 'login' if k in ('alice-relogin','ip-relogin')
            else 'finish' if k=='probe-finish' else 'request') for i,k in enumerate(HTTP,1)],transitions=transitions,
        policy_transition=policy_fixture(identity,transitions),
        credential_transition=credential_fixture(identity,transitions),
        independent_reapproval=dict(original_operation=[70]*32,issued_operation=[38]*32,journal=[32]*32,
            same_identity=True,request_sha256="a"*64,signing_key_sha256="b"*64),
        independent_policy_transition=peer_policy_fixture(identity),
        independent_credential_transition=peer_credential_fixture(identity),
        services=[process('survivor-first',1,3,native=True),process('survivor-after-add',2,2,native=True),process('survivor-after-replacement',3,4,native=True)],
        witness_services=[dict(label='witness-first',pid=4,exit=-9),process('witness-reopened',5,5,native=True)],
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


def credential_fixture(identity,transitions):
    p=policy_fixture(identity,transitions);operation=[12]*32;statement=[13]*32;journal=[5]*32
    target=dict(version=4,digest=[4]*32);enrollment=[21]*32
    previous=transitions[1]['progress']['scope']['target']
    proposal=b'QPCRNP03'+bytes([14])*32+bytes([15])*96+bytes(operation)+bytes(statement)+bytes(96)+b'\0'+bytes([8])*32
    return dict(request=dict(schema='qperiapt-retained-credential-request/1',operation=operation,journal=journal,
        enrollment=enrollment,root_revision=1,original_owner=[22]*32,original_policy=p['request']['scope']['original_policy'],
        current_policy=p['progress']['target'],current_policy_authorization=[8]*32,previous_checkpoint=previous),
        issued=dict(operation=operation,statement=statement,journal=journal,enrollment=enrollment,checkpoint=target,root_revision=1),
        extension=dict(root_revision=1,checkpoint=target,request=dict(enrollment=enrollment,predecessor=previous)),
        preparation=dict(schema='qperiapt-credential-witness-proposal/1',operation=operation,journal=journal,
            proposal=base64.urlsafe_b64encode(proposal).rstrip(b'=').decode()),proposal_binding=[16]*32,
        terminal=dict(state='Committed',operation=operation,statement=statement,target=target),
        activation=dict(state='Active',operation=operation,statement=statement,journal=journal,checkpoint=target),
        returned_owner=dict(same_returned_owner=True,status='Absent',journal=journal,session=[4]*32,message=[23]*32))


def peer_policy_fixture(identity):
    def wire(data): return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
    operation=bytes([30])*32;statement=bytes([31])*32;journal=bytes([32])*32
    approvals=[bytes([n])*3803 for n in (33,34)]
    proposal=b'QPPWNP01'+bytes([35])*32+journal+bytes(64)+operation+statement+bytes(96)
    return dict(operation=identity(30),state='Applied',retired=True,original_key_unchanged=True,original_intent_sha256='a'*64,
        request=dict(schema='qperiapt-retained-policy-request/1',application=[37]*32,enrollment=[38]*32,root_revision=1,
            scope=dict(operation=list(operation),journal=list(journal),current_roster=dict(version=1,digest=[39]*32),
            previous_authorization=None,original_policy=dict(version=1,digest=[1]*32),previous_policy=dict(version=1,digest=[1]*32))),
        preparation=dict(schema='qperiapt-policy-witness-preparation/1',proposal=wire(proposal),binding=[36]*32,
            approval=wire(b'QPPRNB01'+b''.join(len(a).to_bytes(2,'big')+a for a in approvals))),
        account_approval=dict(operation=list(operation),statement=list(statement),approval=wire(approvals[0]),target=dict(version=3,digest=[40]*32)),
        policy_approval=dict(operation=list(operation),statement=list(statement),approval=wire(approvals[1])))


def peer_credential_fixture(identity):
    p=peer_policy_fixture(identity);target=dict(version=2,digest=[41]*32);op=[42]*32;statement=[43]*32;journal=[32]*32
    proposal=b'QPCRNP03'+bytes(32)+bytes(journal)+bytes(64)+bytes(op)+bytes(statement)+bytes(96)+b'\0'+bytes([31])*32
    request=dict(schema='qperiapt-retained-credential-request/1',application=[37]*32,enrollment=[38]*32,root_revision=1,
        operation=op,journal=journal,original_owner=[44]*32,original_policy=p['request']['scope']['original_policy'],
        current_policy=p['account_approval']['target'],current_policy_authorization=[31]*32,
        previous_checkpoint=p['request']['scope']['current_roster'])
    return dict(operation=identity(42),state='Applied',retired=True,original_key_unchanged=True,original_intent_sha256='b'*64,
        request=request,issued=dict(operation=op,statement=statement,journal=journal,enrollment=[38]*32,root_revision=1,checkpoint=target),
        preparation=dict(schema='qperiapt-credential-witness-proposal/1',operation=op,journal=journal,
            proposal=base64.urlsafe_b64encode(proposal).rstrip(b'=').decode()),proposal_binding=[45]*32,
        extension=dict(root_revision=1,checkpoint=target,request=dict(enrollment=[38]*32,predecessor=request['previous_checkpoint'])))


class RosterEvidence(unittest.TestCase):
    def accepted(self,value): verify(value,{},Path('/installed'))
    def test_complete(self): self.accepted(fixture())

    def test_independent_credential_requires_own_original_policy_and_exact_outcome(self):
        for key,wrong in [('state','Unavailable'),('retired',False),('original_key_unchanged',False)]:
            value=fixture();value['independent_credential_transition'][key]=wrong
            with self.subTest(key=key),self.assertRaises(ValueError):self.accepted(value)
        for key,wrong in [('journal',[5]*32),('current_policy_authorization',None),('enrollment',[99]*32),
                          ('current_policy',dict(version=1,digest=[1]*32))]:
            value=fixture();value['independent_credential_transition']['request'][key]=wrong
            with self.subTest(key=key),self.assertRaises(ValueError):self.accepted(value)

    def test_independent_policy_requires_exact_original_approvals_and_terminal(self):
        for key,wrong in [('state','Unavailable'),('retired',False),('original_key_unchanged',False)]:
            value=fixture();value['independent_policy_transition'][key]=wrong
            with self.subTest(key=key),self.assertRaises(ValueError):self.accepted(value)
        for part in ('account_approval','policy_approval'):
            value=fixture();value['independent_policy_transition'][part]['statement']=[99]*32
            with self.subTest(part=part),self.assertRaises(ValueError):self.accepted(value)
        value=fixture();value['independent_policy_transition']['preparation']['approval']=fixture()['policy_transition']['preparation']['approval']
        with self.assertRaises(ValueError):self.accepted(value)

    def test_independent_policy_cannot_substitute_native_owner_or_statement(self):
        value=fixture();value['independent_policy_transition']['request']['scope']['journal']=[5]*32
        with self.assertRaises(ValueError):self.accepted(value)
        value=fixture();value['independent_policy_transition']['preparation']['proposal']=fixture()['policy_transition']['preparation']['proposal']
        with self.assertRaises(ValueError):self.accepted(value)

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

    def test_credential_requires_original_policy_and_current_roster_lineage(self):
        for key,wrong in [('journal',[99]*32),('enrollment',[99]*32),('operation',[99]*32),
                          ('current_policy_authorization',None),('previous_checkpoint',dict(version=2,digest=[2]*32)),
                          ('original_policy',dict(version=2,digest=[12]*32)),('current_policy',dict(version=1,digest=[11]*32))]:
            value=fixture();value['credential_transition']['request'][key]=wrong
            with self.subTest(key=key),self.assertRaises(ValueError):self.accepted(value)

    def test_credential_proposal_cannot_substitute_operation_or_policy(self):
        for offset in (0,136,168,296,297):
            value=fixture();p=value['credential_transition']['preparation']
            data=bytearray(base64.urlsafe_b64decode(p['proposal']+'='*((-len(p['proposal']))%4)))
            data[offset]^=1;p['proposal']=base64.urlsafe_b64encode(data).rstrip(b'=').decode()
            with self.subTest(offset=offset),self.assertRaises(ValueError):self.accepted(value)

    def test_credential_terminal_and_direct_owner_are_required(self):
        for key,wrong in [('state','Pending'),('statement',[99]*32),('target',dict(version=3,digest=[3]*32))]:
            value=fixture();value['credential_transition']['terminal'][key]=wrong
            with self.subTest(key=key),self.assertRaises(ValueError):self.accepted(value)
        for key,wrong in [('same_returned_owner',False),('status','Reserved'),('session',[99]*32),('journal',[99]*32),
                          ('message',[True]*32),('message',[0]*32)]:
            value=fixture();value['credential_transition']['returned_owner'][key]=wrong
            with self.subTest(key=key,wrong=wrong),self.assertRaises(ValueError):self.accepted(value)

    def test_reapproval_requires_successor_and_original_identity(self):
        for field, wrong in [('original_operation',[38]*32),('issued_operation',[99]*32),
                             ('journal',[99]*32),('same_identity',False),('request_sha256','invalid')]:
            value=fixture();value['independent_reapproval'][field]=wrong
            with self.subTest(field=field),self.assertRaises(ValueError):self.accepted(value)

    def test_installed_receipt_cannot_omit_g_or_reuse_the_old_schema(self):
        value=fixture();value['schema_version']=2
        with self.assertRaises(ValueError):self.accepted(value)
        value=fixture();value['commands']=[row for row in value['commands'] if not row['label'].startswith('g-')]
        with self.assertRaises(ValueError):self.accepted(value)


if __name__=='__main__': unittest.main()
