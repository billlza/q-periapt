"""Counterexamples for witnessed account execution receipts."""
import base64
import copy
import hashlib
from pathlib import Path
import unittest
import test_continuity_host_witness as witness
from continuity_host_witness import verify
from continuity_host_witness_credential import LABELS,FAILED


class WitnessAccountReceiptTests(unittest.TestCase):
    def setUp(self):
        b64=lambda b:base64.urlsafe_b64encode(b).rstrip(b'=').decode()
        raw=lambda n:[n]*32
        self.value=witness.fixture();self.value.update(schema_version=2,session=b64(bytes(raw(11))),original_lost_message=b64(bytes(raw(12))))
        subject=bytes(raw(3)+raw(4)+raw(5));self.value['genesis']['subject']=list(subject)
        target={'version':2,'digest':raw(8)};policy={'version':1,'digest':raw(9)}
        issued=dict(enrollment=raw(1),operation=raw(2),journal=raw(3),root_revision=1,statement=raw(4),
                    checkpoint=target,grant=b64(b'QPRNB001'+b'x'*8))
        request=dict(schema='qperiapt-retained-credential-request/1',enrollment=raw(1),operation=raw(2),journal=raw(3),
                     root_revision=1,previous_checkpoint={'version':1,'digest':raw(10)},original_policy=policy,
                     current_policy=policy,current_policy_authorization=None)
        proposal=b'QPCRNP01'+bytes(raw(6))+subject+bytes(raw(2))+bytes(raw(4))+bytes(96)
        domain=b'Q-PERIAPT-ANCHOR-CREDENTIAL-PROPOSAL/v1'
        binding=hashlib.sha3_256(len(domain).to_bytes(8,'big')+domain+len(proposal).to_bytes(8,'big')+proposal).digest()
        self.value['account_credential']=dict(completed=True,retired=True,original_key_unchanged=True,state='Applied',
            session=self.value['session'],message=self.value['original_lost_message'],journal=b64(bytes(raw(3))),operation=b64(bytes(raw(2))),
            request=request,issued=issued,companion=dict(issued,enrollment=raw(6),operation=raw(7),journal=raw(8)),
            preparation=dict(schema='qperiapt-credential-witness-proposal/1',journal=raw(3),operation=raw(2),proposal=b64(proposal)),
            proposal_binding=list(binding),original_intent_sha256='ab'*32,
            commands=[dict(label=n,exit=1 if n in FAILED else 0) for n in LABELS])
        self.accepted(self.value)

    def accepted(self,value):verify(value,{},Path('/installed'),account_credential=True)

    def reject(self,change):
        value=copy.deepcopy(self.value);change(value['account_credential'])
        with self.assertRaises(ValueError):self.accepted(value)

    def test_original_subject_grant_and_selected_lineage_are_bound(self):
        self.reject(lambda g:g.update(session=g['message']))
        self.reject(lambda g:g['issued'].update(operation=[20]*32))
        self.reject(lambda g:g['request'].update(current_policy_authorization=[20]*32))
        self.reject(lambda g:g['request'].update(root_revision=True))

    def test_exact_proposal_and_applied_result_are_required(self):
        self.reject(lambda g:g.update(proposal_binding=[20]*32))
        self.reject(lambda g:g.update(state='Prepared'))
        self.reject(lambda g:g.update(original_key_unchanged=False))

    def test_unapproved_permission_and_output_loss_cannot_be_hidden(self):
        self.reject(lambda g:g['commands'].pop(LABELS.index('wg-pending-blocks-session')))
        self.reject(lambda g:g['commands'][LABELS.index('wg-unapproved-commit')].update(exit=0))
        self.reject(lambda g:g['commands'][LABELS.index('wg-witness-lost-output')].update(exit=0))
        self.reject(lambda g:g['commands'][-1].update(exit=True))


if __name__=='__main__':unittest.main()
