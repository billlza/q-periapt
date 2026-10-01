"""Metadata/export regression controls; native endpoints authenticate protocol state."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import continuity_c_witness_tls as tls


def fixture(root: Path) -> tuple[bytes, dict]:
    """Synthetic format fixture, never evidence of a real TLS or signed-state run."""
    session, message = "11" * 32, "22" * 32
    report = {"schema_version": 2, "language": "C", "completed": True, "carrier": "q-periapt-anchor/1",
              "session": session, "message": message, "witness_exchanges": 142,
              "rejected_connections": 2, "sdk_revoked_cleanup": True, "release_claim_eligible": False}
    for role in ("initiator", "responder"):
        (root / role).mkdir()
    (root / "c-witness-tls-public-result.json").write_text(json.dumps(report))
    (root / "initiator" / ("application-" + message)).write_bytes(
        bytes.fromhex(session + message) + b"persisted before process exit")
    (root / "responder/c-loss-report").write_text(
        f"QPC-C-LOSS/1\nreport {'33' * 32}\nheader {session} {'44' * 32} {'55' * 32} {'66' * 16} 2 1 0 0 0 0 0 0 1\n"
        f"epoch 0 0 1 1 0 0 0 0 0 {'0' * 64} 0 0 0\n")
    # This verifier checks the exported archive's envelope shape only. Its
    # authentication is an actual C recovery-owner obligation, not this fixture.
    (root / "responder/c-closure-archive").write_bytes(b"QPCSCA01" + bytes(354))
    logs = {
        "initiator/tls-missing-key": "rejected:500\n",
        "initiator/tls-wrong-name": "rejected:218\n",
        "initiator/tls-wrong-subject": "rejected:218\n",
        "initiator/tls-owner-kind": "operational-owner-not-recovery\n",
        "initiator/tls-bootstrap-client": session + "\n",
        "initiator/tls-message-server": f"listening:1234\nserved:2:0:1:1\n{session}\n{message}\n",
        "responder/tls-bootstrap-server": f"listening:2345\nserved:1:0:0:0\n{session}\n{'0' * 64}\n",
        "responder/tls-next": message + "\n", "responder/tls-send": "consumed\n",
        "responder/tls-revoked": "rejected:603\n",
        "responder/tls-cleanup-cancel": "cancelled-cleanup-not-frozen\n",
        "responder/tls-freeze": "", "responder/tls-ack": "",
        "responder/tls-retire": "original-report-closed-retired\n",
        "responder/tls-archive": "archive-closed-metadata-only\n",
    }
    for label, text in logs.items():
        role, name = label.split("/")
        (root / role / ("witness-" + name + ".stdout")).write_text(text)
        (root / role / ("witness-" + name + ".stderr")).write_bytes(b"")
    stdout = (f"test {tls.TEST} ... ok\n"
              "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out;\n").encode()
    return stdout, report


class TlsWitnessEvidenceTests(unittest.TestCase):
    def test_actual_language_is_required_and_cannot_be_relabelled(self):
        for language in ("Swift", "Kotlin"):
            with self.subTest(language=language), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                stdout, report = fixture(root)
                with self.assertRaisesRegex(ValueError, "scope differs"):
                    tls.verify_execution(stdout, root, language=language)
                report["language"] = language
                (root / "c-witness-tls-public-result.json").write_text(json.dumps(report))
                checked = tls.verify_execution(stdout, root, language=language)
                self.assertIn("installed " + language + " operational", checked["scope"])
                with self.assertRaisesRegex(ValueError, "scope differs"):
                    tls.verify_execution(stdout, root)
                other = "Kotlin" if language == "Swift" else "Swift"
                with self.assertRaisesRegex(ValueError, "scope differs"):
                    tls.verify_execution(stdout, root, language=other)
                with self.assertRaisesRegex(ValueError, "unsupported TLS witness language"):
                    tls.verify_execution(stdout, root, language="unknown")
                (root / "responder/c-loss-report").write_text("partial loss accounting")
                with self.assertRaisesRegex(ValueError, "closure accounting"):
                    tls.verify_execution(stdout, root, language=language)

    def test_eligibility_and_execution_cannot_be_promoted_from_report_flags(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            stdout, report = fixture(root)
            tls.verify_execution(stdout, root)
            for changed in (b"", stdout + stdout, stdout.replace(b"7 filtered out", b"2 filtered out")):
                self.assertNotEqual(changed, stdout)
                with self.subTest(stdout=changed), self.assertRaises(ValueError):
                    tls.verify_execution(changed, root)
            for key, value in (("completed", 1), ("sdk_revoked_cleanup", 1), ("release_claim_eligible", True),
                               ("carrier", "signed-tcp"), ("schema_version", True), ("witness_exchanges", True),
                               ("rejected_connections", True), ("session", "0" * 64), ("message", "../key")):
                changed = copy.deepcopy(report)
                changed[key] = value
                (root / "c-witness-tls-public-result.json").write_text(json.dumps(changed))
                with self.subTest(field=key), self.assertRaises(ValueError):
                    tls.export_public(stdout, root, root / "export")
                self.assertFalse((root / "export").exists())

    def test_receiver_accounting_and_command_readbacks_are_required(self):
        for name, value in (("initiator/application-" + "22" * 32, b"lost receiver bytes"),
                            ("responder/c-loss-report", b"incomplete accounting"),
                            ("responder/c-closure-archive", b"wrong archive"),
                            ("responder/witness-tls-revoked.stdout", b"accepted\n"),
                            ("initiator/witness-tls-bootstrap-client.stderr", b"failed"),
                            ("initiator/witness-extra.stdout", b"unexpected")):
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                stdout, _ = fixture(root)
                tls.verify_execution(stdout, root)
                (root / name).write_bytes(value)
                with self.subTest(file=name), self.assertRaises(ValueError):
                    tls.export_public(stdout, root, root / "export")
                self.assertFalse((root / "export").exists())

    def test_export_selects_public_snapshots_without_private_runtime_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            stdout, _ = fixture(root)
            (root / "responder/witness-tls-key").write_bytes(b"private fixture bytes")
            exported = tls.export_public(stdout, root, root / "export")
            self.assertEqual(len(exported), 34)
            self.assertFalse((root / "export/responder/witness-tls-key").exists())
            result = tls.verify_execution(stdout, root / "export")
            self.assertFalse(result["release_claim_eligible"])
            self.assertFalse(result["independent_implementation_qualified"])
            self.assertFalse(result["full_tls_fault_matrix_qualified"])


if __name__ == "__main__":
    unittest.main(warnings="error")
