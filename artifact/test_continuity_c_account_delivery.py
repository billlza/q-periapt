"""Reject relabelled complete-account delivery receipts and peer/message substitutions."""
import json
from pathlib import Path
import tempfile
import unittest

import continuity_c_account_delivery as delivery
import continuity_c_account_witness as witness


class AccountDeliveryTests(unittest.TestCase):
    def test_delivered_member_requires_its_original_session_and_device(self):
        session, message, device = b's' * 32, b'm' * 32, b'd' * 16
        data = b'account-delivered:1:1\n' + session.hex().encode() + b'\n' + message.hex().encode() + b'\n' + device.hex().encode() + b'\n'
        self.assertEqual(delivery.delivered(data, session, device), message)
        for s, d in ((b'x' * 32, device), (session, b'x' * 16)):
            with self.subTest(session=s, device=d), self.assertRaisesRegex(ValueError, 'binding differs'):
                delivery.delivered(data, s, d)
        for value in (data[:-1], data + data, data.replace(b'1:1', b'1:0'), data.replace(message.hex().encode(), b'0' * 64)):
            with self.subTest(value=value), self.assertRaises(ValueError):
                delivery.delivered(value, session, device)

    def test_receiver_requires_canonical_bounded_listener(self):
        self.assertEqual(delivery.listening(b'listening:1234\nserved:2:0:1:0\n'), [b'served:2:0:1:0'])
        for value in (b'', b'listening:0\n', b'listening:65536\n', b'listening:0123\n', b'listening:1234', b'listening:1234\r\n'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                delivery.listening(value)

    def test_original_identifiers_cannot_be_aliased_or_noncanonical(self):
        self.assertEqual(delivery.identifier(b'12' * 32), bytes.fromhex('12' * 32))
        for value in (b'0' * 64, b'AB' * 32, b'12' * 31, b'12' * 33, b'../other', b'12' * 32 + b'\n'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                delivery.identifier(value)

    def test_all_nine_foreign_phases_require_only_encrypted_admissions(self):
        # This is parser-only metadata, not an executed witness transcript.
        data = ''.join(f'{name} {index} {index + 1} 0\n' for index, name in enumerate(delivery.PHASES)).encode()
        self.assertEqual(len(delivery.tls.phases(data, expected_phases=delivery.PHASES)), 9)
        for value in (data[:-1], data.replace(b'batch 1 2 0', b'batch 1 2 1'), data.replace(b'batch 1 2 0', b'batch 1 1 0'),
                      data.replace(b'batch 1 2 0', b'batch 2 3 0'), data.split(b'\n', 1)[1]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                delivery.tls.phases(value, expected_phases=delivery.PHASES)

    def test_wrong_target_missing_or_ignored_execution_is_rejected(self):
        stdout = (f'test {delivery.TEST} ... ok\n' + 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out;\n').encode()
        with tempfile.TemporaryDirectory() as folder:
            for value in (b'', stdout + stdout, stdout.replace(b'8 filtered', b'5 filtered'), stdout.replace(b'0 ignored', b'1 ignored'),
                          stdout.replace(delivery.TEST.encode(), witness.TEST.encode())):
                with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'completely'):
                    delivery.verify_execution(value, Path(folder))

    def test_same_total_cannot_hide_work_moved_across_original_phases(self):
        # Synthetic metadata only. Keep 307 total while moving one admission
        # from bootstrap to batch: the generic monotonic parser still accepts it.
        data = (b'bootstrap 0 120 0\nbatch 120 126 0\nrefusal 126 147 0\nunknown 147 199 0\nstatus 199 203 0\n'
                b'delivery0 203 240 0\nretained0 240 254 0\ndelivery1 254 293 0\nretained1 293 307 0\n')
        self.assertEqual(delivery.tls.phases(data, expected_phases=delivery.PHASES)['retained1']['after_last_admission'], 307)
        with self.assertRaisesRegex(ValueError, 'phase workload differs'):
            delivery.phase_workload(data, 'C')

    def test_carrier_language_census_and_completion_cannot_be_relabelled(self):
        stdout = (f'test {delivery.TEST} ... ok\n' + 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out;\n').encode()
        base = dict(schema_version=2, account_layout='peer', language='C', completed=True, carrier='q-periapt-anchor/1', witness_admissions=307,
                    batch='11' * 32, release_claim_eligible=False)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); (root/'initiator').mkdir()
            for row, language in ((base, 'Swift'), (base, 'Kotlin'), (list(base), 'C'), (dict(base, completed=1), 'C'),
                    (dict(base, witness_admissions=265), 'C'), (dict(base, witness_admissions=283), 'C'), (dict(base, carrier='signed-tcp'), 'C'),
                    (dict(base, release_claim_eligible=True), 'C'), (dict(base, schema_version=True), 'C')):
                (root/'initiator/account-delivery-result.json').write_text(json.dumps(row))
                with self.subTest(row=row, language=language), self.assertRaisesRegex(ValueError, 'scope or census'):
                    delivery.verify_execution(stdout, root, language=language)

    def test_own_account_requires_its_own_executed_target_and_report_scope(self):
        stdout = (f'test {delivery.OWN_DELIVERY_TEST} ... ok\n' + 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out;\n').encode()
        peer = dict(schema_version=2, account_layout='peer', language='C', completed=True, carrier='q-periapt-anchor/1',
                    witness_admissions=307, batch='11' * 32, release_claim_eligible=False)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); (root/'initiator').mkdir(); (root/'initiator/account-delivery-result.json').write_text(json.dumps(peer))
            with self.assertRaisesRegex(ValueError, 'scope or census'):
                delivery.verify_own_execution(stdout, root)
            with self.assertRaisesRegex(ValueError, 'completely'):
                delivery.verify_execution(stdout, root)
