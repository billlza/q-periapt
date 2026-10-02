"""Reject incomplete public loss accounting; fixtures here are not runtime evidence."""
from pathlib import Path
import hashlib
import tempfile
import unittest

import continuity_c_account_cleanup as cleanup

DOMAIN = b"Q-PERIAPT-CONTINUITY-MESSAGES-CANDIDATE/v2/resolution-ciphertext/v1"


def fixture(root):
    def write(name, data):
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    batch, report, account = "77" * 32, "99" * 32, "88" * 32
    write("cleanup-batch", bytes.fromhex(batch))
    write("cleanup-account", bytes.fromhex(account))
    write("role", b"\x01")
    records = []
    for index, device in enumerate(("22" * 16, "11" * 16)):
        session, context = (f"{0xa0 + index:02x}" * 32, f"{0xb0 + index:02x}" * 32)
        reserved, old = (f"{0xc0 + index:02x}" * 32, f"{0xd0 + index:02x}" * 32)
        for name, value in ((f"cleanup-device-{index}", device), (f"cleanup-session-{index}", session),
                            (f"cleanup-context-{index}", context), (f"cleanup-reserved-{index}", reserved),
                            ("cleanup-old-message-" + device, old)):
            write(name, bytes.fromhex(value))
        write(f"peer-{index}/responder-generation", (1).to_bytes(8, "big"))
        write(f"peer-{index}/responder-account", bytes.fromhex(account))
        wire = b"QPCMSG03" + bytes([index + 1]) * 40
        write("cleanup-old-wire-" + device, wire)
        digest = hashlib.sha3_256(len(DOMAIN).to_bytes(8, "big") + DOMAIN + len(wire).to_bytes(8, "big") + wire).hexdigest()
        incoming = {}
        for position in range(3 + index):
            if position != 1:
                identifier = bytes([10 * index + position + 1]) * 32
                write(f"cleanup-incoming-{index}-{position}", identifier)
                incoming[position] = identifier.hex()
        records.append(dict(index=index, device=device, session=session, context=context,
                            reserved=reserved, old=old, digest=digest, incoming=incoming))
    write("cleanup-connect.stdout", "".join(r["session"] + "\n" for r in records).encode())
    write("cleanup-connect.stderr", b"")
    lines = ["QPC-C-ACCOUNT-LOSS/1", "batch " + batch, "report " + report, "members 2"]
    for number, row in enumerate(sorted(records, key=lambda x: x["device"])):
        index = row["index"]
        lines += [
            f"member {number} {row['device']} {row['context']} {row['session']} 1 1 0 0 0 0 0 1",
            f"reserved {number} {row['reserved']} 29 13",
            f"epoch {number} 0 0 0 1 0 {index + 3} 0 0 0 {'0' * 64} 1 {index + 2} 1",
            f"unconfirmed {number} 0 0 {row['old']} {row['digest']}",
        ]
        for item, (position, identifier) in enumerate(row["incoming"].items()):
            lines.append(f"delivery {number} 0 {item} {identifier} {position} {7 + index + position}")
        lines.append(f"skipped {number} 0 0 1")
    data = ("\n".join(lines) + "\n").encode()
    write("c-account-loss-report", data)
    write("native-account-loss-report", data)
    for name, data in (
        ("cleanup-prepared", b"two-original-members\n"), ("cleanup-observed", b"reserved\n"),
        ("cleanup-revoked", b"operational-policy-disabled\n"),
        ("cleanup-terminal-verified", b"account-retired-independent-closure-refused\n"),
    ):
        write(name, data)


class AccountLossTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        fixture(self.root)

    def replace_reports(self, change):
        # Changing both copies defeats equality alone: retained original inputs
        # must still detect the omitted/misclassified field.
        for name in ("c-account-loss-report", "native-account-loss-report"):
            p = self.root / name
            p.write_text(change(p.read_text()))

    def test_complete_report_retains_both_devices_and_all_loss_classes(self):
        result = cleanup.loss_report(self.root)
        self.assertEqual({k: result[k] for k in ("members", "reserved", "unknown_messages", "unconsumed", "skipped")},
                         dict(members=2, reserved=2, unknown_messages=2, unconsumed=5, skipped=2))
        self.assertIn("cleanup-connect.stderr", result["public_readbacks"])

    def test_matching_native_and_c_reports_cannot_omit_a_member(self):
        prefixes = ("member 1 ", "reserved 1 ", "epoch 1 ", "unconfirmed 1 ", "delivery 1 ", "skipped 1 ")
        self.replace_reports(lambda text: "\n".join(line for line in text.replace("members 2", "members 1").splitlines()
                                                    if not line.startswith(prefixes)) + "\n")
        with self.assertRaises(ValueError):
            cleanup.loss_report(self.root)

    def test_matching_reports_cannot_discard_an_old_unknown_send(self):
        self.replace_reports(lambda text: "\n".join(line for line in text.splitlines()
                                                    if not line.startswith("unconfirmed 0 ")) + "\n")
        with self.assertRaises(ValueError):
            cleanup.loss_report(self.root)

    def test_matching_reports_cannot_discard_or_relabel_incoming_delivery(self):
        self.replace_reports(lambda text: "\n".join(line for line in text.splitlines()
                                                    if not line.startswith("delivery 0 0 1 ")) + "\n")
        with self.assertRaises(ValueError):
            cleanup.loss_report(self.root)

    def test_original_ciphertext_cannot_be_substituted_after_native_readback(self):
        p = self.root / ("cleanup-old-wire-" + "11" * 16)
        p.write_bytes(p.read_bytes()[:-1] + b"\x03")
        with self.assertRaises(ValueError):
            cleanup.loss_report(self.root)

    def test_two_session_labels_cannot_alias_the_same_device(self):
        (self.root / "cleanup-device-1").write_bytes((self.root / "cleanup-device-0").read_bytes())
        with self.assertRaises(ValueError):
            cleanup.loss_report(self.root)

    def test_generation_encoding_cannot_shrink_while_preserving_numeric_value(self):
        (self.root / "peer-0/responder-generation").write_bytes(b"\x01")
        with self.assertRaises(ValueError):
            cleanup.loss_report(self.root)

    def test_sdk_revocation_and_terminal_observations_are_required(self):
        for name in ("cleanup-revoked", "cleanup-terminal-verified"):
            p = self.root / name
            original = p.read_bytes()
            p.write_bytes(b"not-observed\n")
            with self.subTest(name=name), self.assertRaises(ValueError):
                cleanup.loss_report(self.root)
            p.write_bytes(original)
