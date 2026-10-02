"""Incomplete, misbound and extra device-owner receipts must not qualify a package."""
from pathlib import Path
import json
import tempfile
import unittest

import continuity_c_device as device


def output(name, filtered):
    return (f"test {name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; {filtered} filtered out;\n").encode()


def put(root, name, data):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def command(root, name, data):
    put(root, name + ".stdout", data)
    put(root, name + ".stderr", b"")


def fixture(root):
    session, message = "11" * 32, "00" * 16 + "22" * 16
    report = dict(schema_version=1, completed=True, session=session, message=message,
                  local_roles=2, owner_capacity=64, independent_readbacks=2,
                  independent_identity_refusals=4, sdk_revocation_refused=True,
                  physical_reopen_changed_files=6, release_claim_eligible=False)
    put(root, "c-device-parent-public-result.json", json.dumps(report).encode())
    for role in ("initiator", "responder"):
        command(root, f"{role}/c-device-lifecycle", b"device-parent-lifecycle-passed:busy=1\n")
        command(root, f"{role}/c-device-reopen-control", b"device-open-close-passed\n")
        for name in ("wrong-local-id", "wrong-signer"):
            command(root, f"{role}/c-device-{name}", b"device-rejected:103\n")
    for name, data in {"bootstrap-client": session + "\n", "next": message + "\n",
                       "unknown": "delivery-unknown-committed\n", "replay": "consumed\n",
                       "final-status": "3\n", "revoked": "device-rejected:603\n"}.items():
        command(root, "initiator/c-device-" + name, data.encode())
    command(root, "responder/c-device-bootstrap-server", f"listening:12345\nserved:1:0:0:0\n{session}\n{'0' * 64}\n".encode())
    command(root, "responder/c-device-crash-server", b"listening:12345\n")
    command(root, "responder/c-device-replay-server", f"listening:12345\nserved:2:0:1:0\n{session}\n{message}\n".encode())
    put(root, "responder/peer/application-" + message, bytes.fromhex(session + message) + b"persisted before process exit")
    return report


class DeviceTests(unittest.TestCase):
    def test_complete_trace_and_selected_public_record_count(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fixture(root)
            result = device.verify_execution(output(device.TEST, 7), root)
            self.assertEqual(len(result["public_readbacks"]), 2)
            self.assertEqual(len(result["command_logs"]), 34)

    def test_runtime_receipts_cannot_omit_identity_lifetime_or_original_delivery(self):
        mutations = {
            "responder/c-device-wrong-signer.stdout": b"device-rejected:0\n",
            "initiator/c-device-lifecycle.stdout": b"device-parent-lifecycle-passed:busy=65\n",
            "initiator/c-device-unknown.stdout": b"consumed\n",
            "initiator/c-device-revoked.stdout": b"device-rejected:0\n",
            "responder/c-device-replay-server.stdout": b"listening:0\n",
            "responder/peer/application-" + "00" * 16 + "22" * 16: b"wrong original transaction",
            "initiator/c-device-extra.stderr": b"unaccounted failure",
        }
        for name, data in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                fixture(root)
                put(root, name, data)
                with self.assertRaises(ValueError):
                    device.verify_execution(output(device.TEST, 7), root)

    def test_invalid_census_and_incomplete_execution_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            report = fixture(root)
            good = output(device.TEST, 7)
            for bad in (b"", good + good, output(device.TEST, 6), good.replace(b"0 ignored", b"1 ignored")):
                with self.subTest(stdout=bad), self.assertRaises(ValueError):
                    device.verify_execution(bad, root)
            for field, value in (("completed", 1), ("owner_capacity", 63), ("independent_identity_refusals", 2),
                                 ("physical_reopen_changed_files", 7), ("sdk_revocation_refused", False)):
                put(root, "c-device-parent-public-result.json", json.dumps(dict(report, **{field: value})).encode())
                with self.subTest(field=field), self.assertRaises(ValueError):
                    device.verify_execution(good, root)

    def test_witness_refusals_and_both_roles_are_mandatory(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            report = dict(schema_version=1, completed=True, local_roles=2, witness_profiles=2,
                          missing_witness_refused=True, wrong_pin_refused=True, bad_signature_refused=True,
                          missing_tls_key_refused=True, release_claim_eligible=False)
            put(root, "c-device-parent-witness-public-result.json", json.dumps(report).encode())
            for name, code in {"missing-witness": 216, "wrong-witness": 211, "bad-signature": 218, "missing-tls-key": 500}.items():
                command(root, "initiator/witness-parent-" + name, f"device-rejected:{code}\n".encode())
            for role in ("initiator", "responder"):
                for carrier in ("signed-tcp", "mutual-tls"):
                    command(root, f"{role}/witness-parent-{carrier}", b"device-parent-lifecycle-passed:busy=1\n")
            good = output(device.WITNESS_TEST, 10)
            result = device.verify_witness_execution(good, root)
            self.assertEqual(len(result["public_readbacks"] | result["command_logs"]), 17)
            for name, data in [("initiator/witness-parent-bad-signature.stdout", b"device-rejected:0\n"),
                               ("responder/witness-parent-mutual-tls.stdout", b""),
                               ("initiator/witness-parent-extra.stderr", b"unaccounted failure")]:
                path = root / name
                original = path.read_bytes() if path.exists() else None
                put(root, name, data)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    device.verify_witness_execution(good, root)
                if original is None:
                    path.unlink()
                else:
                    path.write_bytes(original)


if __name__ == "__main__":
    unittest.main(warnings="error")
