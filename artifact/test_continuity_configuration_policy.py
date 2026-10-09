"""Grammar/linkage controls use dummy signatures; native tests verify crypto."""
import sys
import unittest

import continuity_configuration_policy as policy


def fixture_values(index, account, carrier):
    root = bytes([index + 40]) * 1985
    family = policy.digest(b"Q-PERIAPT-CONTINUITY-POLICY-AUTHORITY-CANDIDATE/v1", root)
    policies = []
    checkpoints = []
    for version, until in ((1, 20), (2, 620)):
        body = (b"QPSESP03" + family + version.to_bytes(8, "big")
                + (10).to_bytes(8, "big") + until.to_bytes(8, "big") + bytes(104))
        policies.append(len(body).to_bytes(4, "big") + body + bytes(3373))
        checkpoints.append(version.to_bytes(8, "big") + policy.digest(
            b"Q-PERIAPT-CONTINUITY-SESSION-POLICY-CANDIDATE/v1", body))
    original, target = checkpoints
    native_pin = (1).to_bytes(8, sys.byteorder) + original[8:]
    roster = (1).to_bytes(8, sys.byteorder) + bytes([index + 50]) * 32
    operation = bytes([index + 60]) * 32
    journal = bytes([5]) * 32
    raw = (operation + journal + bytes([index + 70]) * 32 + bytes([index + 80]) * 64
           + roster + native_pin * 2 + bytes(40) + account + roster)
    for record in (b"public certificate", b"public roster") * 2:
        raw += len(record).to_bytes(4, sys.byteorder) + record + bytes(8192 - len(record))
    body = (b"QPPRNW01" + raw[:160] + bytes([index + 90]) * 32 + family
            + (1).to_bytes(8, "big") + roster[8:] + original * 2 + target + bytes(33) + b"\x01")
    approval = len(body).to_bytes(4, "big") + body + bytes(3373)
    statement = policy.digest(b"Q-PERIAPT-POLICY-RENEWAL-CANDIDATE/v1", body)
    def status(phase):
        return (phase.to_bytes(4, sys.byteorder) + bytes(4) + operation + statement
                + (2).to_bytes(8, sys.byteorder) + target[8:] + bytes(48))
    values = {"policy-request.bin": raw, "policy-request-replayed.bin": raw,
              "policy-after-refusal.bin": raw, "policy-refused.bin": (102).to_bytes(4, sys.byteorder),
              "policy-root.bin": root, "original-policy.bin": policies[0], "target-policy.bin": policies[1],
              "target-version.bin": target[:8], "target-digest.bin": target[8:],
              "policy-approvals.bin": b"QPPRNB01" + (len(approval).to_bytes(2, "big") + approval) * 2,
              "policy-statement.bin": statement, "policy-staged.bin": status(1),
              "policy-stage-replayed.bin": status(1)}
    if carrier == "local":
        values.update({"policy-committed.bin": status(2), "policy-commit-replayed.bin": status(2)})
    else:
        genesis = (2).to_bytes(4, "big") + journal * 2 + bytes([6]) * 64 + bytes([7]) * 32
        proposal = (b"QPPWNP01" + bytes([index + 100]) * 32 + genesis[36:132] + operation + statement
                    + (1).to_bytes(8, "big") * 2 + bytes([index + 110]) * 32
                    + (1).to_bytes(8, "big") + (2).to_bytes(8, "big") + bytes([index + 120]) * 32)
        values.update({"genesis.bin": genesis, "policy-proposal.bin": proposal,
                       "proposal-replayed.bin": proposal, "proposal-recovered.bin": proposal,
                       "witness-applied.bin": (2).to_bytes(4, sys.byteorder),
                       "witness-reconciled.bin": (2).to_bytes(4, sys.byteorder)})
    return family, values


class ConfigurationPolicyTests(unittest.TestCase):
    def test_every_policy_record_is_bounded_and_bound_to_the_original_operation(self):
        account = bytes([1]) * 32
        for carrier in ("local", "signed", "tls"):
            family, data = fixture_values(0, account, carrier)
            self.assertEqual(policy.verify(data, carrier=carrier, account=account, family=family),
                             data["policy-request.bin"][:32].hex())
            for name in data:
                for mutation in (lambda b: b[:-1], lambda b: bytes([b[0] ^ 1]) + b[1:]):
                    with self.subTest(carrier=carrier, name=name, mutation=mutation):
                        changed = dict(data, **{name: mutation(data[name])})
                        with self.assertRaises(ValueError):
                            policy.verify(changed, carrier=carrier, account=account, family=family)

    def test_replayed_records_cannot_agree_on_a_different_scope(self):
        account = bytes([1]) * 32
        for carrier in ("local", "signed", "tls"):
            family, data = fixture_values(0, account, carrier)
            for offset in (32, 96, 160, 200, 240, 280, 312, 316, 320, 352, 392, 500):
                with self.subTest(carrier=carrier, offset=offset):
                    raw = bytearray(data["policy-request.bin"]); raw[offset] ^= 1
                    changed = dict(data)
                    for name in ("policy-request.bin", "policy-request-replayed.bin", "policy-after-refusal.bin"):
                        changed[name] = bytes(raw)
                    with self.assertRaises(ValueError):
                        policy.verify(changed, carrier=carrier, account=account, family=family)

    def test_statement_issuers_and_established_session_restriction_are_required(self):
        account = bytes([1]) * 32
        family, data = fixture_values(0, account, "local")
        for offset in (10 + 4 + 8, 10 + 4 + 425, 10 + 3803 + 2 + 4 + 8):
            with self.subTest(offset=offset):
                approvals = bytearray(data["policy-approvals.bin"]); approvals[offset] ^= 1
                with self.assertRaises(ValueError):
                    policy.verify(dict(data, **{"policy-approvals.bin": bytes(approvals)}),
                                  carrier="local", account=account, family=family)
