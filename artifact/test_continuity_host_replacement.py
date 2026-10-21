"""Mutation checks for authenticated replacement acceptance boundaries."""
import base64
from pathlib import Path
import unittest
from continuity_independent_python import PACKAGE
from continuity_host_replacement import LABELS, FAILED, HTTP, REFUSALS, action, verify
from continuity_host_replacement_evidence import verify_http_recovery


def fixture():
    def stats(n, errors=0):
        return dict(accepted=n+errors, completed_responses=n, evicted_incomplete=0,
                    rejected_busy=0, read_errors=0, operation_errors=errors,
                    last_operation_error='other error' if errors else None)
    def service(label, pid, n, errors=0): return dict(label=label, pid=pid, exit=0, stats=stats(n, errors))
    def identity(n): return base64.urlsafe_b64encode(bytes([n])*32).rstrip(b'=').decode()
    return dict(schema_version=1, kind='qperiapt.authenticated_device_replacement', completed=True,
        release_claim_eligible=False, cleanup_errors=[], effects=5, confirmed_epoch=1,
        old_generation=1, new_generation=2, native_sha256={}, provider='48.0.1',
        implementation=str(Path('/installed') / PACKAGE / 'session_cli.py'), clock='actual OS time',
        old_state_unchanged=True, native_identity_unchanged=True, witness_keys_unchanged=True,
        original_bootstrap_recovered=True, old_journal=identity(1), new_journal=identity(2),
        native_journal=identity(3), old_session=identity(4), new_session=identity(5),
        commands=[dict(label=k, exit=1 if k in FAILED else 0) for k in LABELS],
        account_requests=[dict(label=k,id=i,action=action(k)) for i,k in enumerate(HTTP,1)],
        refusals=list(REFUSALS), services=[service('old-native-service',1,5,2),
            dict(label='new-native-service',pid=2,exit=-9), service('new-native-service-reopened',3,1)],
        witness_services=[dict(label='witness-first',pid=4,exit=-9),service('witness-reopened',5,124,1)],
        account_services=[dict(label=label,pid=i,exit=code) for i,(label,code) in enumerate([
            ('account-first',-9),('account-after-invitation-loss',-9),('account-after-issuance-loss',0)],6)],
        independent_service=service('new-independent-service',9,1), relay=stats(2,1),
        frames=[dict(label='replacement-wire-'+str(i), kind=k, request_sha256='a'*64 if i<3 else 'b'*64,
            outcome='refused' if i==1 else 'response') for i,k in enumerate((1,1,2),1)])


class ReplacementEvidence(unittest.TestCase):
    def accepted(self, value): verify(value, {}, Path('/installed'))

    def test_complete_replacement(self): self.accepted(fixture())

    def test_omitted_step_or_converted_failure(self):
        for key in ('commands','account_requests','refusals','services','frames'):
            value=fixture();value[key].pop()
            with self.subTest(key=key), self.assertRaises(ValueError): self.accepted(value)
        for label in FAILED:
            value=fixture();next(r for r in value['commands'] if r['label']==label)['exit']=0
            with self.subTest(label=label), self.assertRaises(ValueError): self.accepted(value)

    def test_forged_effects_generation_or_reused_owner(self):
        for key, wrong in [('effects',4),('effects',True),('new_generation',1),('confirmed_epoch',0),
                           ('new_journal',fixture()['old_journal']),('new_session',fixture()['old_session']),
                           ('native_identity_unchanged',False),('cleanup_errors',['unfinished child']),
                           ('release_claim_eligible',True)]:
            value=fixture();value[key]=wrong
            with self.subTest(key=key), self.assertRaises(ValueError): self.accepted(value)

    def test_actual_postrestart_traffic_required(self):
        value=fixture();value['services'][2]['stats']['completed_responses']=0
        with self.assertRaises(ValueError): self.accepted(value)
        value=fixture();value['services'][2]['stats']['accepted']=True
        with self.assertRaises(ValueError): self.accepted(value)

    def test_original_bootstrap_and_process_kills_required(self):
        value=fixture();value['frames'][1]['request_sha256']='c'*64
        with self.assertRaises(ValueError): self.accepted(value)
        for group in ('account_services','witness_services'):
            for key, wrong in [('exit',0),('pid',3)]:
                value=fixture();value[group][0][key]=wrong
                with self.subTest(group=group,key=key), self.assertRaises(ValueError): self.accepted(value)

    def test_login_correlation_and_original_authenticator_required(self):
        for key, wrong in [('action','register'),('id',True),('label','new-account')]:
            value=fixture();value['account_requests'][17][key]=wrong
            with self.subTest(key=key), self.assertRaises(ValueError): self.accepted(value)


def http_fixture():
    responses, requests = {}, {}
    for names, body, route in [
            (('replacement-invitation-lost','replacement-invitation','replacement-invitation-retry'),b'invitation','replace-device'),
            (('new-issue-lost','new-issue','new-issue-retry','new-issue-final'),b'new exact issuance','issue'),
            (('old-issue','old-issue-after-replacement','old-issue-final'),b'old exact issuance','issue')]:
        for name in names:
            responses[name] = body
            requests[name] = dict(account='bob',route='/api/enrollment/'+route,body={'operation':[1,2]})
    return responses, requests


class HttpRecoveryEvidence(unittest.TestCase):
    def test_exact_recovery(self): verify_http_recovery(*http_fixture())

    def test_original_issuance_cannot_change(self):
        for label in ('replacement-invitation-retry','old-issue-after-replacement','old-issue-final','new-issue-final'):
            responses, requests=http_fixture();responses[label]+=b' '
            with self.subTest(label=label), self.assertRaises(ValueError): verify_http_recovery(responses,requests)

    def test_unknown_reply_cannot_be_replaced_by_new_request(self):
        for field, wrong in [('account','mallory'),('route','/api/enrollment/invite'),('body',{'operation':[3,4]})]:
            responses,requests=http_fixture();requests['replacement-invitation'][field]=wrong
            with self.subTest(field=field), self.assertRaises(ValueError): verify_http_recovery(responses,requests)


if __name__ == '__main__': unittest.main()
