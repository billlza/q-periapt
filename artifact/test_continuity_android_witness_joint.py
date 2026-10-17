"""Retained actual witness G/T routes and adversarial public-readback controls."""
from pathlib import Path
import shutil
import tempfile
import unittest
import zipfile
import continuity_android_witness_joint as joint
import rust_sdk_profile as sdk


class WitnessJointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory(); cls.addClassCleanup(temp.cleanup); cls.root = Path(temp.name)
        archive = sdk.ROOT / "research/sdk-alpha1/evidence/20261014-android-witness-joint/CAPTURE.zip"
        with zipfile.ZipFile(archive) as bundle:
            for name in bundle.namelist():
                if not name.startswith(("host/", "device/")): continue
                path = cls.root / name
                if not path.is_relative_to(cls.root) or ".." in Path(name).parts: raise ValueError("archive member")
                path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(bundle.read(name))

    def verify(self, directory, label, surface="host"):
        carrier, profile, outcome = label.split("-")
        return joint.verify_execution((self.root / surface / label / "execution.stdout").read_bytes(),
                                      directory, carrier, profile, outcome == "applied", catalog=joint.contract.WITNESS_JOINT_TESTS)

    def mutate(self, label, name, change):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "public"; shutil.copytree(self.root / "host" / label / "public", root)
            path = root / "-".join(label.split("-")[:2]) / name
            path.write_bytes(change(path.read_bytes()))
            with self.assertRaises(ValueError): self.verify(root, label)

    def test_all_host_and_accepted_phone_routes(self):
        for surface, labels in (("host", joint.TESTS), ("device", ("signed-recoverable-closed", "tls-recoverable-applied"))):
            for label in labels:
                with self.subTest(surface=surface, label=label):
                    value = self.verify(self.root / surface / label / "public", label, surface)
                    applied = label.endswith("applied")
                    self.assertEqual(value["foreign_processes"], 49 if applied else 42)
                    self.assertEqual(value["terminal"], "applied" if applied else "closed")
                    self.assertEqual(value["original_message_retried"], applied)

    def test_batch_requires_every_route_and_preserves_each_public_readback(self):
        # Assemble parser input from retained single-route receipts. This is a
        # validator control; the actual concurrent run is qualified separately.
        lines = []
        for label in joint.TESTS:
            lines.extend(line for line in (self.root / "host" / label / "execution.stdout").read_bytes().splitlines()
                         if not line.startswith(b"test result:"))
        lines.append(b"test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 42 filtered out;")
        stdout = b"\n".join(lines) + b"\n"
        for label in joint.TESTS:
            carrier, profile, outcome = label.split("-")
            directory = self.root / "host" / label / "public"
            result = joint.verify_execution(stdout, directory, carrier, profile, outcome == "applied", batch=True,
                                            catalog=joint.contract.WITNESS_JOINT_TESTS)
            self.assertEqual(result, self.verify(directory, label))
        passed = ("test " + next(iter(joint.TESTS.values())) + " ... ok").encode()
        for damaged in (stdout.replace(passed, b"", 1), stdout + passed + b"\n",
                        stdout.replace(passed, passed.replace(b"ok", b"FAILED"), 1),
                        stdout.replace(b"8 passed; 0 failed", b"7 passed; 1 failed", 1)):
            with self.subTest(damaged=damaged[-100:]), self.assertRaises(ValueError):
                joint.verify_execution(damaged, self.root / "host/signed-fixed-applied/public",
                                       "signed", "fixed", True, batch=True, catalog=joint.contract.WITNESS_JOINT_TESTS)

    def test_batch_cannot_reuse_a_journal_witness_or_operation(self):
        cases = {label: self.root / "host" / label / "public" for label in joint.TESTS}
        joint.verify_batch_identities(cases)
        with self.assertRaises(ValueError): joint.verify_batch_identities(dict(list(cases.items())[:-1]))
        for name in ("original.identity", "inputs/witness-id", "inputs/credential-operation"):
            with tempfile.TemporaryDirectory() as temp:
                copied = Path(temp) / "public"
                shutil.copytree(cases["signed-fixed-closed"], copied)
                (copied / "signed-fixed" / name).write_bytes((cases["signed-fixed-applied"] / "signed-fixed" / name).read_bytes())
                with self.subTest(name=name), self.assertRaises(ValueError):
                    joint.verify_batch_identities(dict(cases, **{"signed-fixed-closed": copied}))

    def test_witness_binding_subject_and_joint_domain_are_exact(self):
        for label, name, offsets in (("signed-fixed-applied", "joint-proposal", (7,8,40,136,168,296,297)),
                                     ("tls-fixed-closed", "joint-cancellation", (7,8,40,136,168,248,249))):
            for offset in offsets:
                def flip(data, at=offset):
                    value = bytearray(data); value[at] ^= 1; return bytes(value)
                with self.subTest(label=label, offset=offset): self.mutate(label, name, flip)

    def test_explicit_close_is_distinct_from_passive_history(self):
        label = "signed-fixed-applied"
        def replace_close(data):
            value = bytearray(data); at = next(i for i in range(0, len(value), 7334) if value[i + 205] == 7)
            value[at + 205] = 5; return bytes(value)
        self.mutate(label, "joint-explicit-close-transcript", replace_close)
        sample = (self.root / "host" / label / "public/signed-fixed/joint-explicit-close-transcript").read_bytes()[:7334]
        for opcode in (5,7):
            def append_command(data, operation=opcode):
                frame = bytearray(sample); frame[0] = 1; frame[205] = operation; return data + bytes(frame)
            with self.subTest(opcode=opcode): self.mutate(label, "joint-commit-recovery-transcript", append_command)

    def test_missing_closed_receipt_is_not_cached_terminal_evidence(self):
        label = "tls-fixed-closed"
        self.mutate(label, "joint-expired-history-transcript", lambda _: b"")
        self.mutate(label, "joint-history-0", lambda data: (2).to_bytes(4, "big") + data[4:])
        self.mutate(label, "joint-final-request", lambda data: data[:168] + bytes([1]) + data[169:])
        self.mutate(label, "joint-reserved-activate-refused", lambda _: bytes(4))

    def test_unknown_commit_and_original_effect_cannot_be_invented(self):
        label = "tls-recoverable-applied"
        for name in ("joint-commit-unknown", "joint-close-loses-to-applied", "joint-request-reused"):
            self.mutate(label, name, lambda data: bytes(4) + data[4:])
        self.mutate(label, "policy-effect-after", lambda data: data + b"duplicate")
        self.mutate(label, "joint-proposal-recovered.stderr", lambda _: b"witness unavailable")
        self.mutate(label, "joint-expiry-observation", lambda data: data[:24] + bytes(8))


if __name__ == "__main__": unittest.main()
