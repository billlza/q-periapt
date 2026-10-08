"""Synthetic framing regressions; native consumers separately verify signatures and report MACs."""
import json
from pathlib import Path
import tempfile
import unittest

import continuity_device_retirement as retirement
from continuity_c_witness import commit


def fixture(path: Path):
    path.mkdir()
    witness_id, key, subject = b'w' * 32, b'k' * 1985, b's' * 96
    binding = commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-AUTHORITY/v1", witness_id + key)
    replacement = b"QPDRPL01" + binding + b"synthetic replacement proposal"
    replacement_id = commit(b"Q-PERIAPT-CONTINUITY-DEVICE-REPLACEMENT-CANDIDATE/v1", replacement)
    head, state = b'h' * 48, b't' * 32
    old_body = b"QPDRTR01" + binding + replacement_id + subject + head + b'\x00' * 33 + state + b'n' * 96
    inventory = b"QPRCLP01" + binding + replacement_id + subject + state + head + b'i' * 32 + b'\x00' * 33
    report_id = b'r' * 32
    expected = b"QPRRPT01" + inventory + report_id
    wire = lambda body: len(body).to_bytes(4, 'big') + body + b'\x11' * 3373
    report = {name: bytes([index + 1]).hex() * 32 for index, name in enumerate(retirement.IDENTITIES)}
    report['report_id'] = report_id.hex()
    report.update(retirement.COUNTS)
    report.update({name: True for name in retirement.FLAGS})
    values = {'witness-request-count': (300).to_bytes(8, 'big'), 'witness-id': witness_id, 'witness-public': key, 'witness-subject': subject,
              'retirement-proposal': replacement, 'retirement-receipt': wire(old_body),
              'retirement-inventory': inventory, 'retirement-inventory-receipt': wire(inventory),
              'retirement-report-proposal': expected, 'retirement-report-receipt': wire(expected),
              'retirement-ack': wire(b"QPRACK01" + expected[8:]),
              'retirement-host-report': b"QPRDMD01" + inventory + b'\x00' + b'synthetic full metadata',
              'retirement-report-reopened': report_id, 'retirement-verified': report_id,
              'signer-terminal': b"QPSRET01", 'result.json': json.dumps(report).encode(),
              'successor-enrollment-trace': b"native\n", 'successor-traffic-trace': b"native\n"}
    for role, payload in [('old', b'retiring device effect before unavailable receipt'),
                          ('new', b'persisted before process exit')]:
        values[role + '-effect'] = bytes.fromhex(report[role + '_session'] + report[role + '_message']) + payload
    for index, stage in enumerate(retirement.STAGES, 100):
        values['retirement-process-' + stage] = index.to_bytes(8, 'big')
    values['retirement-host-report-verified'] = values['retirement-host-report']
    for name, data in values.items():
        (path / name).write_bytes(data)


class RetirementEvidenceTests(unittest.TestCase):
    def test_foreign_trace_keeps_exact_test_and_readback_requirements(self):
        stdout = (f"test {retirement.FOREIGN_TEST} ... ok\n"
                  "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out;\n").encode()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); fixture(root / "source")
            with self.assertRaisesRegex(ValueError, "foreign successor enrollment"):
                retirement.export_foreign(stdout, root / "source", root / "rejected", language="C")
            (root / 'source/successor-enrollment-trace').write_bytes(b''.join(
                f'{stage} {pid}\n'.encode() for pid, stage in enumerate(retirement.SUCCESSOR_STAGES, 200)))
            (root / 'source/successor-traffic-trace').write_bytes(b'bootstrap 400\nmessage 401\n')
            result = retirement.export_foreign(stdout, root / "source", root / "export", language="C")
            self.assertEqual(result["consumer_language"], "C")
            self.assertEqual(result["public_readbacks"], retirement.verify(root / "source")["public_readbacks"])
            self.assertIn("ten C successor processes", result["scope"])
            self.assertEqual(result["successor_process_ids"], list(range(200, 210)))
            self.assertEqual(result["traffic_process_ids"], [400, 401])
            for bad in (b"", stdout.replace(b"1 passed", b"0 passed"), stdout + stdout,
                        stdout.replace(b" ... ok", b" ... ignored"),
                        stdout.replace(b"3 filtered", b"28 filtered"),
                        stdout + b"test unrelated ... ok\n",
                        stdout + b"test fixture::unrelated ... FAILED\n",
                        stdout + b"test fixture::unrelated ... ignored\n",
                        stdout + b"test result: FAILED. 0 passed; 1 failed;\n"):
                with self.subTest(stdout=bad), self.assertRaisesRegex(ValueError, "exact workload"):
                    retirement.export_foreign(bad, root / "source", root / "rejected", language="C")
            with self.assertRaisesRegex(ValueError, "language"):
                retirement.export_foreign(stdout, root / "source", root / "rejected", language="other")

    def test_complete_public_readback_and_export(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); fixture(root / 'source')
            result = retirement.export(root / 'source', root / 'export')
            self.assertEqual(result, retirement.verify(root / 'export'))
            self.assertEqual(set(result['public_readbacks']), retirement.FILES)
            self.assertEqual(len(result['recovery_process_ids']), 8)
            self.assertFalse(result['release_claim_eligible'])

    def test_report_version_two_retains_inventory_and_unknown_versions_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'source'; fixture(root)
            paths = [root / 'retirement-host-report', root / 'retirement-host-report-verified']
            body = paths[0].read_bytes()[8:]
            for tag in (b'QPRDMD01', b'QPRDMD02'):
                for path in paths: path.write_bytes(tag + body)
                retirement.verify(root)
            for path in paths: path.write_bytes(b'QPRDMD03' + body)
            with self.assertRaises(ValueError): retirement.verify(root)

    def test_successor_sequence_requires_all_distinct_processes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'source'; fixture(root)
            original = b''.join(f'{stage} {pid}\n'.encode()
                                for pid, stage in enumerate(retirement.SUCCESSOR_STAGES, 200))
            path = root / 'successor-enrollment-trace'
            for bad in (b'', original.replace(b'key 200\n', b''), original + b'extra 999\n',
                        original.replace(b'create 201', b'create 200'),
                        original.replace(b'key 200', b'key 100'),
                        original.replace(b'key 200', b'key 0'),
                        original.replace(b'accept-retry', b'accept')):
                path.write_bytes(bad)
                with self.subTest(trace=bad), self.assertRaisesRegex(ValueError, 'successor enrollment'):
                    retirement.verify(root)

    def test_foreign_traffic_cannot_be_native_missing_or_reuse_a_process(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'source'; fixture(root)
            (root / 'successor-enrollment-trace').write_bytes(b''.join(
                f'{stage} {pid}\n'.encode() for pid, stage in enumerate(retirement.SUCCESSOR_STAGES, 200)))
            path = root / 'successor-traffic-trace'
            for bad in (b'native\n', b'', b'bootstrap 400\n', b'message 401\nbootstrap 400\n',
                        b'bootstrap 400\nmessage 400\n', b'bootstrap 100\nmessage 401\n',
                        b'bootstrap 200\nmessage 401\n'):
                path.write_bytes(bad)
                with self.subTest(trace=bad), self.assertRaisesRegex(ValueError, 'successor traffic'):
                    retirement.verify(root)

    def test_every_record_is_required(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'source'; fixture(root)
            for p in list(root.iterdir()):
                original = p.read_bytes(); p.unlink()
                with self.subTest(missing=p.name), self.assertRaises(ValueError):
                    retirement.verify(root)
                p.write_bytes(original)

    def test_wrong_receipt_scope_effect_or_recovery_identity_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'source'; fixture(root)
            for name in ['witness-id', 'witness-public', 'witness-subject', 'retirement-proposal',
                         'retirement-receipt', 'retirement-inventory', 'retirement-inventory-receipt',
                         'retirement-report-proposal', 'retirement-report-receipt', 'retirement-ack',
                         'retirement-host-report', 'retirement-host-report-verified', 'retirement-report-reopened', 'retirement-verified',
                         'old-effect', 'new-effect', 'signer-terminal']:
                p = root / name; original = p.read_bytes(); p.write_bytes(bytes([original[0] ^ 1]) + original[1:])
                with self.subTest(changed=name), self.assertRaises(ValueError): retirement.verify(root)
                p.write_bytes(original)
            p = root / 'retirement-process-verify'; p.write_bytes((100).to_bytes(8, 'big'))
            with self.assertRaisesRegex(ValueError, 'independent recovery'): retirement.verify(root)

    def test_success_flags_do_not_accept_wrong_accounting(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'source'; fixture(root)
            p = root / 'result.json'; original = json.loads(p.read_text())
            for name in retirement.COUNTS:
                changed = dict(original); changed[name] = True
                p.write_text(json.dumps(changed))
                with self.subTest(count=name), self.assertRaises(ValueError): retirement.verify(root)
            for name in retirement.FLAGS:
                changed = dict(original); changed[name] = False
                p.write_text(json.dumps(changed))
                with self.subTest(flag=name), self.assertRaises(ValueError): retirement.verify(root)


if __name__ == '__main__':
    unittest.main()
