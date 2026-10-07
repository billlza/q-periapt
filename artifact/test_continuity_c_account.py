"""Incomplete or misbound account traces cannot qualify an installed package."""
from pathlib import Path
import json
import tempfile
import unittest

import continuity_c_account as account

STDOUT = (f"test {account.TEST} ... ok\n"
          "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out;\n").encode()


def put(root, name, data):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def fixture(root):
    def command(name, data):
        put(root, "initiator/c-account-" + name + ".stdout", data)
        put(root, "initiator/c-account-" + name + ".stderr", b"")
    def state(name, value):
        command(name, f"account-status:{value}\n{'0' * 64}\n".encode())
    report = dict(schema_version=2, language="C", completed=True, devices=3, recipients=2, accounts=2,
                  admission_refusals=6, shape_controls=4, application_readbacks=5, busy_owners=3,
                  unknown_commit_reconciled=True, cancelled_original_reconciled=True,
                  unary_refused=True, reversed_targets_reconciled=True, cancellation_ms=12,
                  release_claim_eligible=False)
    put(root, "initiator/c-account-result.json", json.dumps(report).encode())
    for name, value in [("initiator", 5), ("responder", 6), ("responder-2", 6)]:
        put(root, name + "/local-account", bytes([value]) * 32)
    sessions = ["11" * 32, "22" * 32]
    devices = ["33" * 16, "44" * 16]
    command("connect", ("\n".join(sessions) + "\n").encode())
    command("next", ("55" * 32 + "\n").encode())
    command("still-next", ("55" * 32 + "\n").encode())
    for index, code in enumerate((106, 1, 1, 302, 2, 211)):
        command(f"refusal-{index}", f"account-refused:{code}\n".encode())
        state(f"absent-{index}", 0)
    command("unknown", b"account-refused:311\n")
    command("changed-input", b"account-refused:211\n")
    command("unary-refused", b"account-refused:215\n")
    state("committed-unknown", 2)
    state("committed-delivered", 2)
    command("next-cancel", ("66" * 32 + "\n").encode())
    command("cancel-active", b"account-refused:302\naccount-cancel-active:12:3\n")
    state("cancel-committed", 2)
    for index, name in enumerate(("responder", "responder-2")):
        put(root, name + "/local-device", bytes.fromhex(devices[index]))
        for after, byte in [(False, 7 + index), (True, 9 + index)]:
            message = bytes([byte]) * 32
            data = f"account-delivered:1:1\n{sessions[index]}\n{message.hex()}\n{devices[index]}\n".encode()
            command(("after-cancel-" if after else "deliver-") + str(index), data)
            put(root, name + "/application-" + message.hex(), bytes.fromhex(sessions[index]) + message + account.PAYLOAD)
            if not after:
                for label in ("retained", "reversed"):
                    command(f"{label}-{index}", data.replace(b"account-delivered:1:1", b"account-delivered:1:0"))


class AccountEvidenceTests(unittest.TestCase):
    def test_complete_public_trace_has_exact_command_and_readback_census(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture(root)
            result = account.verify_execution(STDOUT, root)
            self.assertEqual(len(result["command_logs"]), 62)
            self.assertEqual(len(result["public_readbacks"]), 10)
            self.assertEqual(result["scope"], account.SCOPE)
            self.assertFalse(result["release_claim_eligible"])

    def test_missing_partial_and_wrong_source_execution_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture(root)
            for bad in (b"", STDOUT + STDOUT, STDOUT.replace(b"8 filtered out", b"7 filtered out"),
                        STDOUT.replace(b"1 passed", b"0 passed")):
                with self.subTest(stdout=bad), self.assertRaises(ValueError):
                    account.verify_execution(bad, root)

    def test_misbound_or_extra_receipts_fail(self):
        replacements = {
            "responder-2/local-device": bytes.fromhex("33" * 16),
            "responder-2/local-account": bytes([8]) * 32,
            "initiator/c-account-absent-0.stdout": f"account-status:2\n{'0' * 64}\n".encode(),
            "initiator/c-account-still-next.stdout": ("99" * 32 + "\n").encode(),
            "initiator/c-account-unary-refused.stdout": b"account-refused:311\n",
            "initiator/c-account-unknown.stderr": b"unexpected failure",
            "initiator/c-account-reversed-0.stdout": b"account-delivered:1:0\n",
            "initiator/c-account-cancel-active.stdout": b"account-refused:302\naccount-cancel-active:11:3\n",
            "responder/application-" + (bytes([7]) * 32).hex(): b"wrong effect",
            "initiator/c-account-extra.stderr": b"unaccounted failure",
        }
        for name, value in replacements.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                fixture(root)
                put(root, name, value)
                with self.assertRaises(ValueError):
                    account.verify_execution(STDOUT, root)

    def test_claims_require_exact_flags_types_and_observation_bound(self):
        for name, value in [("schema_version", 1), ("language", "Swift"), ("completed", 1), ("devices", True), ("shape_controls", 3),
                            ("cancellation_ms", 1000), ("cancellation_ms", -1),
                            ("unary_refused", False), ("release_claim_eligible", True)]:
            with self.subTest(name=name, value=value), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                fixture(root)
                path = root / "initiator/c-account-result.json"
                report = json.loads(path.read_bytes())
                report[name] = value
                path.write_text(json.dumps(report))
                with self.assertRaises(ValueError):
                    account.verify_execution(STDOUT, root)
