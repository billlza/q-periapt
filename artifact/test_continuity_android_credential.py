"""Reader counterexamples only; synthetic bytes are not protocol evidence."""
from pathlib import Path
import tempfile
import unittest
import continuity_android_credential as credential
from test_continuity_android_witness import fixture as witness_fixture


def fixture(root: Path) -> bytes:
    stdout = witness_fixture(root, managed=True).replace(b"android_witness::managed_first_registration", credential.TEST.encode())
    for carrier in ("signed", "tls"):
        for trust in ("fixed", "recoverable"):
            base = root / (carrier + "-" + trust)
            for name, operation in credential.CASES:
                (base / (name + ".stdout")).write_bytes(f"{trust}:{operation}:passed\n".encode())
                (base / (name + ".stderr")).write_bytes(b"")
            values = {name: (code).to_bytes(4, "big") for name, code in (("credential-refused", 102),
                ("credential-closed", 202), ("credential-unmanaged", 211), ("credential-unknown", 218),
                ("credential-activation-unmanaged", 211))}
            identity = b"i" * 32 + b"j" * 32
            for name in ("credential-original-identity", "credential-current-activation", "credential-renewed-identity"): values[name] = identity
            values["credential-absent"] = bytes(116)
            pending = (1).to_bytes(4, "big") + b"o" * 32 + b"s" * 32 + bytes(48)
            for name in ("credential-staged", "credential-stage-replayed"): values[name] = pending
            committed = (2).to_bytes(4, "big") + pending[4:68] + (2).to_bytes(8, "big") + b"d" * 32 + bytes(8)
            (base / "inputs").mkdir()
            values["inputs/renewal-version"], values["inputs/renewal-digest"] = committed[68:76], committed[76:108]
            for name in ("credential-recovered", "credential-terminal-replayed"): values[name] = committed
            proposal = bytearray(296); proposal[:8] = b"QPCRNP01"; proposal[136:200] = pending[4:68]
            for name in ("credential-proposal", "credential-proposal-replayed"): values[name] = proposal
            request, reply = bytearray(3674), bytearray(3659); request[204] = 5; reply[204] = 8
            values["credential-commit-request"], values["credential-commit-reply"] = bytes(request), bytes(reply)
            request[204] = 6
            values["credential-refusal-transcript"] = b""
            values["credential-history-transcript"] = b"\1" + request + reply
            values["credential-dispatch-observation"] = (1).to_bytes(4, "big") * 2 + bytes(4)
            values["credential-connected"] = b"x" * 32
            values["credential-peer-unassociated"] = (201).to_bytes(4,"big")
            values["credential-peer-associated"] = bytes([134])*32 + (1).to_bytes(8,"big") + b"b" * 32
            values["credential-uncertain"] = b"x" * 32 + b"m" * 32
            values["credential-acknowledged"] = values["credential-uncertain"]
            values["credential-effect-before"] = values["credential-uncertain"] + b"persisted before process exit"
            values["credential-effect-after"] = values["credential-effect-before"]
            values["credential-effect-count"] = (1).to_bytes(4, "big")
            values["credential-peer-admit.stdout"] = b"credential-peer-admitted\n"
            values["credential-peer-admit.stderr"] = b""
            for mode, body in (("bootstrap", f"served:1:0:0:0\n{(b'x'*32).hex()}\n{'00'*32}\n"), ("crash-after", ""),
                               ("message", f"served:2:0:1:0\n{(b'x'*32).hex()}\n{(b'm'*32).hex()}\n")):
                values["traffic-credential-"+mode+".stdout"] = ("listening:12345\n" + body).encode()
                values["traffic-credential-"+mode+".stderr"] = b""
            for name, value in values.items(): (base / name).write_bytes(value)
            stdout += f"qualified credential renewal {carrier}/{trust}: same identity and journal, original operation, lost committed reply, historical recovery, current authority activation\n".encode()
            stdout += f"qualified credential traffic {carrier}/{trust}: original session and message, receiver effect before exit, renewal, exact retry, one business effect\n".encode()
    return stdout


class CredentialReaderTests(unittest.TestCase):
    def test_complete_and_missing_profile(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); stdout = fixture(root)
            result = credential.verify_execution(stdout, root)
            self.assertEqual(sum(v["foreign_processes"] for v in result.values()), 130)
            self.assertTrue(all(v["original_session_traffic_qualified"] for v in result.values()))
            with self.assertRaises(ValueError): credential.verify_execution(stdout.replace(b"qualified credential renewal tls/fixed", b"missing"), root)

    def test_original_identity_operation_and_outcome_cannot_be_replaced(self):
        for name in ("credential-renewed-identity", "credential-current-activation", "credential-stage-replayed",
                     "credential-terminal-replayed", "credential-proposal-replayed", "credential-unknown", "credential-closed", "inputs/renewal-digest",
                     "credential-connected", "credential-acknowledged", "credential-effect-after", "credential-effect-count",
                     "credential-peer-unassociated", "credential-peer-associated"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); stdout = fixture(root); path = root / "signed-fixed" / name
                original = path.read_bytes(); path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
                with self.assertRaises(ValueError): credential.verify_execution(stdout, root)

    def test_historical_mutation_missing_commit_and_diagnostics_are_rejected(self):
        for name, offset, value in (("credential-history-transcript", 205, 5), ("credential-commit-reply", 204, 0),
                                    ("credential-commit-request", 204, 6), ("credential-dispatch-observation", 3, 2)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); stdout = fixture(root); path = root / "tls-recoverable" / name
                original = bytearray(path.read_bytes()); original[offset] = value; path.write_bytes(original)
                with self.assertRaises(ValueError): credential.verify_execution(stdout, root)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); stdout = fixture(root); (root / "tls-fixed/credential-unknown.stderr").write_bytes(b"JNI diagnostic")
            with self.assertRaises(ValueError): credential.verify_execution(stdout, root)

    def test_receiver_outcome_cannot_be_substituted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); stdout = fixture(root); path = root / "signed-fixed/traffic-credential-message.stdout"
            path.write_bytes(path.read_bytes().replace(b"served:2:0:1:0", b"served:2:0:0:0"))
            with self.assertRaises(ValueError): credential.verify_execution(stdout,root)


if __name__ == "__main__": unittest.main()
