"""Synthetic public-reader controls are not cryptographic or device execution."""
from pathlib import Path
import tempfile
import shutil
import unittest

import continuity_android_policy_renewal as renewal
import continuity_configuration_policy as policy
from test_continuity_configuration_policy import fixture_values


def fixture(root, profile):
    lines = []
    for index, carrier in enumerate(("local", "signed", "tls")):
        base = root / (carrier + "-" + profile); (base / "inputs").mkdir(parents=True)
        authority = bytes([index + 1]) * 1985
        account = policy.digest(b"Q-PERIAPT-CONTINUITY-ACCOUNT-CANDIDATE/v1", authority)
        family, values = fixture_values(index, account, carrier, byteorder="big")
        raw = values["policy-request.bin"]; journal = raw[32:64]; signer = bytes([index + 8]) * 32
        intent = bytes([2]) * 16 + (1).to_bytes(8, "big") + family + (10).to_bytes(8, "big") + (40).to_bytes(8, "big")
        body = b"QPENRQ01" + signer + account + intent[:24] + intent[56:72] + family + bytes([index + 16]) * 1985
        request = len(body).to_bytes(4, "big") + body + bytes(3373)
        identity = signer + journal
        session, message = bytes([index + 20]) * 32, bytes([index + 30]) * 32
        effect = session + message + b"persisted before process exit"
        files = {label: b"recorded" for label, _ in renewal.cases(carrier)}
        files.update({"original.request": request, "activated.request": request,
                      "original.identity": identity, "expired-identity": identity, "policy-renewed-identity": identity, "final.identity": identity,
                      "prepared": (1).to_bytes(4, "big") + journal + bytes(128) if carrier == "local" else values["genesis.bin"],
                      "inputs/enrollment-root": authority, "inputs/enrollment-intent": intent,
                      "policy-connected": session, "policy-message-unknown": session + message, "policy-message-acknowledged": session + message,
                      "policy-effect-before": effect, "policy-effect-after": effect,
                      "policy-request": raw, "policy-request-replayed": raw, "inputs/renewal-request": raw, "inputs/renewal-operation": raw[:32],
                      "inputs/policy-root": values["policy-root.bin"], "inputs/protocol-policy": values["original-policy.bin"],
                      "inputs/policy-target/protocol-policy": values["target-policy.bin"], "inputs/policy-target/policy-version": values["target-version.bin"],
                      "inputs/policy-target/policy-digest": values["target-digest.bin"], "inputs/renewal-approvals": values["policy-approvals.bin"],
                      "retained-approvals": values["policy-approvals.bin"], "inputs/renewal-statement": values["policy-statement.bin"],
                      "policy-staged": values["policy-staged.bin"], "policy-stage-replayed": values["policy-stage-replayed.bin"],
                      "policy-target-created": b"\x01", "expired-activation": (104).to_bytes(4, "big"),
                      "policy-unselected-refused": (1).to_bytes(4, "big"), "receiver-policy": values["target-policy.bin"],
                      "receiver-policy-adopted": (19).to_bytes(8, "big"),
                      "policy-expiry-observation": b"".join(n.to_bytes(8, "big") for n in (20, 21, 22, 620)),
                      "receiver-target-created.stdout": b"QPC_CONFIGURATION_POLICY_TARGET\n", "receiver-target-created.stderr": b""})
        for label, code in (("bad-approval", 102), ("bad-scope", 103), ("cancelled-stage", 302)):
            files.update({label: code.to_bytes(4, "big"), label + "-status": bytes(160), label + "-request": raw})
        terminal = (2).to_bytes(4, "big") + values["policy-staged.bin"][4:]
        files.update({"policy-terminal": terminal, "policy-resolved": terminal if carrier == "local" else (216).to_bytes(4, "big")})
        if carrier == "local": files.update({"policy-committed": terminal, "policy-commit-replayed": terminal})
        else:
            proposal = values["policy-proposal.bin"]; target = values["target-version.bin"] + values["target-digest.bin"]
            files.update({"policy-proposal": proposal, "policy-proposal-replayed": proposal, "policy-proposal-recovered": proposal,
                          "inputs/renewal-proposal": proposal, "policy-reserved": (1).to_bytes(4, "big") + bytes(4) + proposal + target,
                          "policy-retired": (2).to_bytes(4, "big") + (1).to_bytes(4, "big") + proposal + target,
                          "policy-unmanaged-refused": (211).to_bytes(4, "big"), "policy-unknown": (218).to_bytes(4, "big")})
            for name in ("policy-applied", "policy-applied-replayed", "policy-close-applied", "policy-commit-replayed"):
                files[name] = (2).to_bytes(4, "big")
            request = bytearray(3674); request[204] = 11
            transcript = bytearray(7334); transcript[0] = 1; transcript[205] = 12
            files.update({"policy-lost-commit-request": request, "policy-lost-commit-reply": bytes(3659), "policy-historical-transcript": transcript})
        def record_at(offset):
            length = int.from_bytes(raw[offset:offset + 4], "big")
            return raw[offset + 4:offset + 4 + length]
        files.update({"inputs/family": family, "inputs/trusted-account": account,
                      "inputs/trusted-roster-version": raw[352:360], "inputs/trusted-roster-digest": raw[360:392],
                      "inputs/grant-certificate": record_at(392), "inputs/grant-roster": record_at(392 + 8196),
                      "inputs/policy-version": raw[200:208], "inputs/policy-digest": raw[208:240],
                      "inputs/witness-carrier": carrier.encode()})
        if carrier != "local":
            files.update({"inputs/authority-id": bytes([51]) * 32, "inputs/authority-application": bytes([52]) * 32,
                          "inputs/authority-checkpoint": bytes([51]) * 32 + (1).to_bytes(8, "big") + bytes([53]) * 32,
                          "inputs/witness-id": bytes([54]) * 32, "inputs/witness-public": authority})
        count = len(renewal.cases(carrier)); files["policy-process-count"] = count.to_bytes(8, "big")
        for label, mode in renewal.cases(carrier):
            files[label + ".stdout"] = f"{profile}:{mode}:passed\n".encode(); files[label + ".stderr"] = b""
        for name, data in files.items():
            p = base / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(data)
        lines.append(f"qualified policy renewal {carrier}/{profile}: {count} foreign processes; expired P0, independent P2, original identity session message and one effect")
    lines += ["test " + renewal.TESTS[profile] + " ... ok", "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 23 filtered out;"]
    return ("\n".join(lines) + "\n").encode()


class AndroidPolicyRenewalReaderTests(unittest.TestCase):
    def test_both_trust_profiles_require_every_carrier_and_process(self):
        for profile in renewal.TESTS:
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as t:
                root = Path(t); stdout = fixture(root, profile)
                self.assertEqual(sum(r["foreign_processes"] for r in renewal.verify_execution(stdout, root, profile).values()), 117)
                with self.assertRaises(ValueError): renewal.verify_execution(stdout.replace(b"1 passed", b"0 passed"), root, profile)

    def test_public_export_is_complete_and_can_be_reverified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / "source"; destination = root / "exported"
            stdout = fixture(source, "fixed")
            for carrier in ("local", "signed", "tls"):
                label = carrier + "-fixed"
                for name in renewal.public(carrier):
                    target = destination / label / name; target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source / label / name, target)
            self.assertEqual(renewal.verify_execution(stdout, source, "fixed"),
                             renewal.verify_execution(stdout, destination, "fixed"))

    def test_terminal_identity_approvals_and_business_effect_cannot_be_substituted(self):
        for name in ("final.identity", "policy-message-acknowledged", "policy-effect-after", "retained-approvals", "bad-scope-status", "policy-retired", "policy-close-applied"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as t:
                root = Path(t); stdout = fixture(root, "fixed"); path = root / "tls-fixed" / name
                data = path.read_bytes(); path.write_bytes(bytes([data[0] ^ 1]) + data[1:])
                with self.assertRaises(ValueError): renewal.verify_execution(stdout, root, "fixed")

    def test_expiry_and_no_new_commit_are_observed_requirements(self):
        for name, offset, value in (("policy-expiry-observation", 15, 19), ("receiver-policy-adopted", 7, 21),
                                    ("policy-historical-transcript", 205, 11), ("policy-historical-transcript", 205, 13),
                                    ("policy-unselected-refused", 3, 0)):
            with self.subTest(name=name, value=value), tempfile.TemporaryDirectory() as t:
                root = Path(t); stdout = fixture(root, "recoverable"); path = root / "signed-recoverable" / name
                data = bytearray(path.read_bytes()); data[offset] = value; path.write_bytes(data)
                with self.assertRaises(ValueError): renewal.verify_execution(stdout, root, "recoverable")


if __name__ == "__main__": unittest.main()
