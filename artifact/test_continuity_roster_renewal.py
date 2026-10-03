"""Structural reader controls; synthetic signatures here are never security evidence."""
import json
from pathlib import Path
import tempfile
import unittest

import continuity_roster_renewal as renewal
from continuity_c_witness import commit


def fixture(path):
    path.mkdir()
    def write(name, data):
        (path / name).write_bytes(data)
    def u(value):
        return value.to_bytes(8, 'big')
    def wire(body):
        return len(body).to_bytes(4, 'big') + body + bytes(3373)
    key = b'k' * 1952 + b'\x02' + b'c' * 32
    account = commit(b'Q-PERIAPT-CONTINUITY-ACCOUNT-CANDIDATE/v1', key)
    cert = b'QPCERT01' + account + b'd' * 16 + u(1) + u(149) + u(3750) + b'f' * 32 + key
    credential = commit(b'Q-PERIAPT-CONTINUITY-CREDENTIAL-CANDIDATE/v1', cert)
    owner = commit(b'Q-PERIAPT-CONTINUITY-BOOTSTRAP-CANDIDATE/v1/storage-owner', account + cert[40:64] + credential)
    subject = b'j' * 32 + owner + b'p' * 32
    for name, data in {'local-root': key, 'local-account': account, 'local-certificate': wire(cert),
                       'witness-subject': subject, 'original-journal': b'j' * 32, 'recovered-journal': b'j' * 32,
                       'original-outbox': b'original bootstrap ciphertext', 'restored-outbox': b'original bootstrap ciphertext',
                       'witness-id': b'w' * 32, 'witness-public': key}.items():
        write(name, data)
    for version in (2, 3, 4):
        body = b'QPROST01' + account + u(version) + u(149) + u(210 if version == 2 else 750)
        body += (0 if version == 4 else 1).to_bytes(2, 'big')
        if version != 4:
            body += cert[40:64] + credential
        digest = commit(b'Q-PERIAPT-CONTINUITY-ROSTER-CANDIDATE/v1', body)
        write(f'renewal-roster-{version}', wire(body))
        write(f'renewal-digest-{version}', digest)
        if version == 3:
            write('admitted-checkpoint', digest)
            write('recovered-checkpoint', digest)
        if version == 4:
            write('revoked-checkpoint', digest)
    authority = commit(b'Q-PERIAPT-CONTINUITY-ANCHOR-AUTHORITY/v1', b'w' * 32 + key)
    before, after = u(1) + u(9) + b'a' * 32, u(1) + u(10) + b'b' * 32
    operation = b'\x02' + before + after
    command = commit(b'Q-PERIAPT-CONTINUITY-ANCHOR-COMMAND/v1', authority + subject + operation)
    for name in ('before-head', 'expired-head', 'refreshed-head'):
        write(name, before + b'l' * 32)
    for name in ('recovered-head', 'retried-head'):
        write(name, after + command)
    for index in range(5):
        query = index in (0, 4)
        op = b'\x01' + bytes(96) if query else operation
        cmd = commit(b'Q-PERIAPT-CONTINUITY-ANCHOR-COMMAND/v1', authority + subject + op)
        rq = b'QPANRQ01' + authority + subject + cmd + bytes([index + 1]) * 32 + op
        prefix = f'trace-{index:03}'
        write(prefix + '.request', wire(rq))
        write(prefix + '.time', u(210))
        if index in (1, 2):
            write(prefix + '.rejection', b'Rejected(Validity)')
        else:
            rs = b'QPANRS01' + authority + subject + commit(b'Q-PERIAPT-CONTINUITY-ANCHOR-REQUEST/v1', rq) + cmd
            rs += bytes([1 if query else 2]) + (before if index == 0 else after) + b'\x01' + (b'l' * 32 if index == 0 else command)
            write(prefix + '.reply', wire(rs))
    for index, mode in enumerate(('expired', 'recover', 'revoke')):
        write(mode + '-pid', u(200 + index))
        write(mode + '-process.stdout', b'test service_peer_process ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out;\n')
    report = dict(schema=1, parent_pid=100, initial_time=150, expired_time=210, trace_count=5,
                  device_exit_codes=[0, 0, 0], carrier='signed-tcp', clock='injected-protocol-time')
    write('public-roster-result.json', json.dumps(report).encode())
    return report


class RosterRenewalEvidenceTests(unittest.TestCase):
    def test_valid_closure_is_reverified_after_export(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture(root / 'public')
            result = renewal.export(root / 'public', root / 'exported')
            self.assertEqual(result['logical_advances'], 1)
            self.assertEqual(result['rejected_attempts'], 2)
            self.assertEqual(renewal.verify(root / 'exported'), result)
            self.assertFalse(any('key' in name or name.endswith('.redb') for name in result['public_readbacks']))

    def test_tampered_identity_operation_time_or_readback_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'public'
            fixture(root)
            for name, offset in [('witness-subject', 0), ('original-journal', 0), ('restored-outbox', 0),
                                 ('local-root', 0), ('local-certificate', 44), ('renewal-roster-2', 63),
                                 ('renewal-digest-3', 0), ('admitted-checkpoint', 0), ('recovered-checkpoint', 0),
                                 ('revoked-checkpoint', 0), ('refreshed-head', 0), ('retried-head', 0),
                                 ('trace-001.request', 140), ('trace-002.request', 250), ('trace-002.time', 7),
                                 ('trace-003.reply', 254), ('recover-process.stdout', 0)]:
                original = (root / name).read_bytes()
                changed = bytearray(original); changed[offset] ^= 1
                (root / name).write_bytes(changed)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    renewal.verify(root)
                (root / name).write_bytes(original)

    def test_missing_extra_and_duplicate_dispositions_fail(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'public'
            fixture(root)
            original = (root / 'trace-001.rejection').read_bytes()
            (root / 'trace-001.rejection').unlink()
            with self.assertRaises(ValueError):
                renewal.verify(root)
            (root / 'trace-001.rejection').write_bytes(original)
            for name in ('wrap.key', 'trace-001.reply', 'trace-005.request'):
                (root / name).write_bytes(b'unexpected')
                with self.subTest(name=name), self.assertRaises(ValueError):
                    renewal.verify(root)
                (root / name).unlink()
            (root / 'trace-004.request').unlink()
            (root / 'trace-004.request').symlink_to(root / 'trace-000.request')
            with self.assertRaises(ValueError):
                renewal.verify(root)

    def test_result_cannot_relabel_expiry_or_skip_separate_processes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'public'
            report = fixture(root)
            for name, value in [('schema', True), ('trace_count', True), ('trace_count', 4),
                                ('expired_time', 209), ('clock', 'wall-clock'), ('carrier', 'tls'),
                                ('device_exit_codes', [False, 0, 0]), ('device_exit_codes', [0, 77, 0]),
                                ('parent_pid', 200)]:
                (root / 'public-roster-result.json').write_text(json.dumps(dict(report, **{name: value})))
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    renewal.verify(root)
            (root / 'public-roster-result.json').write_text(json.dumps(report))
            (root / 'recover-pid').write_bytes((200).to_bytes(8, 'big'))
            with self.assertRaises(ValueError):
                renewal.verify(root)


if __name__ == '__main__':
    unittest.main(warnings='error')
