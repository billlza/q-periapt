"""Counterexamples for account CLI receipts, not signature validation."""
import base64
import copy
import unittest
from continuity_host_cli_credential import verify, LABELS, FAILED


class AccountCliReceiptTests(unittest.TestCase):
    def setUp(self):
        raw = lambda n: [n]*32
        b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode()
        target = {'version':2,'digest':raw(8)}
        issued = dict(enrollment=raw(1), operation=raw(2), journal=raw(3), root_revision=1,
                      statement=raw(4), checkpoint=target, grant=b64(b'QPRNB001'+b'x'*8))
        companion = dict(issued, enrollment=raw(5), operation=raw(6), journal=raw(7))
        policy = {'version':1,'digest':raw(9)}
        request = dict(schema='qperiapt-retained-credential-request/1', enrollment=raw(1),
                       operation=raw(2), journal=raw(3), root_revision=1, original_policy=policy,
                       current_policy=policy, current_policy_authorization=None,
                       previous_checkpoint={'version':1,'digest':raw(10)})
        pending = dict(status='Pending', operation=bytes(raw(2)).hex(), statement=bytes(raw(4)).hex(),
                       target=((2).to_bytes(8,'big')+bytes(raw(8))).hex(), binding='ab'*32,
                       time_floor=0, expired_observation=None)
        self.value = {'account_credential':dict(completed=True, original_pending_message_retained=True,
            operation=b64(bytes(raw(2))), journal=b64(bytes(raw(3))), session=b64(bytes(raw(11))),
            message=b64(bytes(raw(12))), request=request, issued=issued, companion=companion,
            pending=pending, committed=dict(pending,status='Committed'),
            commands=[dict(label=n,exit=1 if n in FAILED else 0) for n in LABELS])}
        verify(self.value)

    def reject(self, change):
        value=copy.deepcopy(self.value);change(value['account_credential'])
        with self.assertRaises(ValueError):verify(value)

    def test_original_owner_and_companion_are_bound(self):
        self.reject(lambda g:g['companion'].update(journal=g['issued']['journal']))
        self.reject(lambda g:g['issued'].update(operation=[20]*32))
        self.reject(lambda g:g['request'].update(current_policy_authorization=[20]*32))
        self.reject(lambda g:g['request'].update(root_revision=True))

    def test_target_and_terminal_outcome_cannot_be_replaced(self):
        self.reject(lambda g:g['committed'].update(status='Pending'))
        self.reject(lambda g:g['pending'].update(target='00'*40))
        self.reject(lambda g:g.update(original_pending_message_retained=False))

    def test_missing_commands_and_disguised_failures_are_rejected(self):
        self.reject(lambda g:g['commands'].pop())
        self.reject(lambda g:g['commands'][1].update(exit=0))
        self.reject(lambda g:g['commands'][-1].update(exit=True))


if __name__ == '__main__':unittest.main()
