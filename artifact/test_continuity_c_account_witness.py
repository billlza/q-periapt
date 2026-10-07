"""Incomplete witness-phase accounting cannot qualify a foreign cleanup run."""
import json
from pathlib import Path
import tempfile
import unittest

import continuity_c_account_witness as account


def identity_metadata(same_account):
    # Parser-only public encodings with dummy signatures: no cryptographic/runtime claim.
    keys = [bytes([65 + index]) * 1952 + b'\x02' + bytes([81 + index]) * 32 for index in range(2)]
    roots = [keys[0], keys[0] if same_account else keys[1], keys[0] if same_account else keys[1]]
    devices = [bytes([index + 1]) * 16 for index in range(3)]
    result = {}
    for index, root in enumerate(roots):
        pin = account.witness.commit(b'Q-PERIAPT-CONTINUITY-ACCOUNT-CANDIDATE/v1', root)
        members = range(3) if same_account else (range(1) if index == 0 else range(1, 3))
        body = b'QPROST01' + pin + (1).to_bytes(8, 'big') + (1).to_bytes(8, 'big') + (100).to_bytes(8, 'big') + len(members).to_bytes(2, 'big')
        body += b''.join(devices[i] + (1).to_bytes(8, 'big') + bytes([11 + i]) * 32 for i in members)
        for name, data in {'account':pin, 'device':devices[index], 'root':root, 'roster-version':(1).to_bytes(8, 'big'),
                           'roster-digest':account.witness.commit(b'Q-PERIAPT-CONTINUITY-ROSTER-CANDIDATE/v1', body),
                           'roster':len(body).to_bytes(4, 'big') + body + b's' * 3373}.items():
            result[f'account-identity-{index}-{name}'] = data
    return result


def metadata_reader(values):
    def read(name, maximum):
        value = values[name]
        if len(value) > maximum:
            raise ValueError('bounded identity metadata')
        return value
    return read


class AccountWitnessTests(unittest.TestCase):
    def setUp(self):
        # Stage-parser fixture only: no signature or protocol/runtime claim.
        self.rows = [bytes([int(index % 3 != 1)]) + bytes(account.witness.RECORD_BYTES - 1) for index in range(12)]
        self.wire = b"".join(self.rows)
        self.data = "".join(f"{phase} {index * 3} {index * 3 + 3} {index * 3 + 1}\n"
                            for index, phase in enumerate(account.PHASES)).encode()

    def test_every_lost_response_belongs_to_its_original_phase(self):
        result = account.stages(self.data, self.wire)
        self.assertEqual(list(result), list(account.PHASES))
        self.assertEqual([row["lost_exchange"] for row in result.values()], [1, 4, 7, 10])

    def test_missing_repeated_or_relabelled_phases_are_refused(self):
        for data in (b"", self.data.split(b"\n", 1)[1], self.data + b"freeze 0 3 1\n",
                     self.data.replace(b"freeze 3 6 4", b"reservation 3 6 4"),
                     self.data.replace(b"freeze 3 6 4", b"freeze 0 3 1"), self.data[:-1]):
            with self.subTest(data=data), self.assertRaises(ValueError):
                account.stages(data, self.wire)

    def test_unmeasured_or_substituted_losses_are_refused(self):
        rows = list(self.rows); rows[0] = b"\x00" + rows[0][1:]
        more = b"".join(rows)
        rows = list(self.rows); rows[1] = b"\x01" + rows[1][1:]
        missing = b"".join(rows)
        for data, wire in ((self.data, more), (self.data, missing), (self.data, self.wire[:-1]),
                           (self.data.replace(b"retirement 9 12 10", b"retirement 9 13 10"), self.wire),
                           (self.data.replace(b"freeze 3 6 4", b"freeze 3 6 3"), self.wire)):
            with self.subTest(data=data), self.assertRaises(ValueError):
                account.stages(data, wire)

    def test_summary_and_wrong_target_do_not_replace_execution(self):
        correct = (f"test {account.TEST} ... ok\n"
                   "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out;\n").encode()
        with tempfile.TemporaryDirectory() as folder:
            for data in (b"", correct + correct, correct.replace(b"8 filtered", b"5 filtered"),
                         correct.replace(b"0 ignored", b"1 ignored")):
                with self.subTest(data=data), self.assertRaisesRegex(ValueError, "completely"):
                    account.verify_execution(data, Path(folder))

    def test_foreign_language_and_release_scope_cannot_be_relabelled(self):
        stdout = (f"test {account.TEST} ... ok\n"
                  "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out;\n").encode()
        base = dict(schema_version=1, completed=True, language="C", batch="11" * 32, report="22" * 32,
                    witness_exchanges=12, lost_advances=4, release_claim_eligible=False)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for changed, language in ((base, "Swift"), (base, "Kotlin"),
                                      (list(base), "C"),
                                      (dict(base, release_claim_eligible=True), "C"),
                                      (dict(base, lost_advances=True), "C"),
                                      (dict(base, completed=1), "C")):
                (root / "account-witness-result.json").write_text(json.dumps(changed))
                with self.subTest(changed=changed, language=language), self.assertRaisesRegex(ValueError, "scope differs"):
                    account.verify_execution(stdout, root, language=language)

    def test_account_layout_comes_from_the_selected_scope_and_retained_rosters(self):
        for own in (False, True):
            read = metadata_reader(identity_metadata(own))
            self.assertEqual(account.account_identities(read, same_account=own)['account_count'], 1 if own else 2)
            with self.assertRaisesRegex(ValueError, 'layout'):
                account.account_identities(read, same_account=not own)
        with self.assertRaisesRegex(ValueError, 'layout selection'):
            account.account_identities(metadata_reader(identity_metadata(True)), same_account=1)

    def test_substituted_root_device_or_roster_pin_is_refused(self):
        base = identity_metadata(True)
        for key, value in [('account-identity-0-root', b'B' + base['account-identity-0-root'][1:]),
                           ('account-identity-1-device', base['account-identity-0-device']),
                           ('account-identity-0-roster-version', (2).to_bytes(8, 'big')),
                           ('account-identity-0-roster-digest', b'x' * 32),
                           ('account-identity-0-roster', base['account-identity-0-roster'][:-1])]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                account.account_identities(metadata_reader(dict(base, **{key:value})), same_account=True)

    def test_rehashed_roster_cannot_omit_reorder_or_alias_a_required_device(self):
        base = identity_metadata(True);wire = base['account-identity-0-roster'];length = int.from_bytes(wire[:4], 'big');body = wire[4:4 + length]
        rows = [body[offset:offset + 56] for offset in range(66, len(body), 56)]
        bodies = [body[:64] + (2).to_bytes(2, 'big') + b''.join(rows[:2]),
                  body[:66] + b''.join(reversed(rows)),
                  body[:66] + rows[0] + rows[1][:24] + rows[0][24:] + rows[2]]
        for bad in bodies:
            changed = dict(base)
            for index in range(3):
                changed[f'account-identity-{index}-roster'] = len(bad).to_bytes(4, 'big') + bad + b's' * 3373
                changed[f'account-identity-{index}-roster-digest'] = account.witness.commit(b'Q-PERIAPT-CONTINUITY-ROSTER-CANDIDATE/v1', bad)
            with self.subTest(body=bad), self.assertRaises(ValueError):
                account.account_identities(metadata_reader(changed), same_account=True)
