"""Reject false elapsed-time claims; fixtures are public-record shapes only."""
import base64
import copy
import unittest
from continuity_host_account_expiry import REFUSALS,retain,verify


class ElapsedAccountReceiptTests(unittest.TestCase):
    def setUp(self):
        self.observed=dict(native_until=4600,peer_until=4601,started_at=1020,observed_at=4602,
                           elapsed_seconds=3582.4,policy_until=8200,operations_refused=REFUSALS.copy(),
                           original_account_reauthenticated=True)
        waiting=dict(pid=1,started_at=1020,target=4602,policy_until=8200,native_until=4600,peer_until=4601,
                     services=dict(account=2,probe=3,witness=4))
        self.value=dict(expiry=copy.deepcopy(self.observed),account_services=[dict(pid=2)],witness_services=[dict(pid=4)])
        self.docs={'EXPIRY_OBSERVATION.json':self.observed,'EXPIRY_WAIT.json':waiting,
                   'EXPIRY_PROGRESS.json':dict(waiting,phase='expired-and-refused',**self.observed),
                   'policy-request.json':dict(valid_from=1000,valid_until=8200),'native-plan.json':dict(valid_until=2200)}
        for label,start in [('native',1000),('peer',1001)]:
            self.docs[label+'-invitation.json']=dict(valid_from=start,valid_until=start+3600)
            body=b'QPCERT01'+bytes(56)+start.to_bytes(8,'big')+(start+3600).to_bytes(8,'big')+bytes(2017)
            certificate=len(body).to_bytes(4,'big')+body+b'unit-shape-only'
            self.docs[label+'-issued.json']=dict(certificate=base64.urlsafe_b64encode(certificate).rstrip(b'=').decode())
        self.data={'peer-expiry-refused.stderr':b'ValueError: witness current authority denied\n',
                   'native-expiry-refused.stderr':b'Error: Validity\n'}
        self.requests={'expiry-old-login':dict(route='/api/me')}
        self.responses={'expiry-old-login':dict(status=401),'expiry-relogin':dict(authenticated='original_software_test_passkey')}
        self.accepted()

    def accepted(self):
        retain(self.value,self.docs.__getitem__,self.data.__getitem__,self.requests,self.responses)

    def test_both_credentials_must_reach_expiry_by_elapsed_time(self):
        for change in [dict(observed_at=4600),dict(peer_until=5000),dict(started_at=4600),
                       dict(elapsed_seconds=0),dict(elapsed_seconds=3706),dict(observed_at=9999),
                       dict(elapsed_seconds=float('nan')),dict(elapsed_seconds=float('inf')),dict(started_at=True)]:
            with self.subTest(change=change),self.assertRaises(ValueError):verify(dict(self.observed,**change))

    def test_live_policy_and_original_authentication_are_required(self):
        for change in [dict(policy_until=5200),dict(original_account_reauthenticated=False),
                       dict(operations_refused=REFUSALS[:1])]:
            with self.subTest(change=change),self.assertRaises(ValueError):verify(dict(self.observed,**change))

    def test_generic_io_failure_cannot_prove_expiry_refusal(self):
        for name in self.data:
            original=self.data[name];self.data[name]=b'OSError: disk unavailable\n'
            with self.subTest(name=name),self.assertRaises(ValueError):self.accepted()
            self.data[name]=original
        self.data['peer-expiry-refused.stderr']=b'ValueError: expired or premature authority\n'
        with self.assertRaises(ValueError):self.accepted()

    def test_invitation_cannot_disagree_with_issued_certificate(self):
        name='peer-issued.json';original=self.docs[name]
        self.docs[name]=self.docs['native-issued.json']
        with self.assertRaises(ValueError):self.accepted()
        self.docs[name]=original
        self.docs['peer-invitation.json']['valid_until']+=1
        with self.assertRaises(ValueError):self.accepted()

    def test_policy_and_publication_are_bound_to_original_records(self):
        self.docs['policy-request.json']['valid_from']+=1
        with self.assertRaises(ValueError):self.accepted()
        self.docs['policy-request.json']['valid_from']-=1
        self.docs['native-plan.json']['valid_until']=5000
        with self.assertRaises(ValueError):self.accepted()

    def test_wait_and_service_identity_cannot_be_replaced(self):
        self.docs['EXPIRY_WAIT.json']['services']['account']=22
        with self.assertRaises(ValueError):self.accepted()
        self.docs['EXPIRY_WAIT.json']['services']['account']=2
        self.docs['EXPIRY_PROGRESS.json']['phase']='waiting'
        with self.assertRaises(ValueError):self.accepted()

    def test_fresh_account_registration_is_not_original_login(self):
        self.responses['expiry-relogin']['authenticated']='registered_software_test_passkey'
        with self.assertRaises(ValueError):self.accepted()


if __name__=='__main__':unittest.main()
