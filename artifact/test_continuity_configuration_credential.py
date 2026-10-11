"""Mutations of actual public C records; these tests do not verify signatures."""
from pathlib import Path
import hashlib
import tempfile
import unittest
import zipfile

import continuity_first_account as account

FIXTURE = Path(__file__).resolve().parent / "fixtures/first-credential-public-v1.zip"
FIXTURE_SHA256 = "b4ff5b8aa153e50278579077556c818c977e0b5c83ab4a6618907d982ce0157d"


def fixture(root):
    if hashlib.sha256(FIXTURE.read_bytes()).hexdigest() != FIXTURE_SHA256:
        raise ValueError("credential public fixture identity differs")
    with zipfile.ZipFile(FIXTURE) as archive:
        for name in archive.namelist():
            if name.startswith("public/"):
                parts = Path(name).parts
                if len(parts) != 3 or parts[1] not in {"signed-fixed", "signed-recoverable", "tls-fixed", "tls-recoverable"}:
                    raise ValueError("credential fixture path differs")
                target = root / parts[1] / parts[2]
                target.parent.mkdir(exist_ok=True)
                target.write_bytes(archive.read(name))
        return archive.read("execution.stdout")


class FirstCredentialTests(unittest.TestCase):
    def verify(self, output, root):
        return account.verify_execution(output, root, language="C", credential=True)

    def test_actual_matrix_preserves_original_identity_and_recovers_without_new_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = fixture(root)
            result = self.verify(output, root)
            self.assertEqual(len(result["scenarios"]), 4)
            self.assertTrue(result["credential_renewal_qualified"])
            self.assertFalse(result["policy_renewal_composition"])
            self.assertFalse(result["release_claim_eligible"])
            for observation in result["expiry_observations"].values():
                self.assertEqual(observation["new_commits"], 1)
                self.assertEqual(observation["historical_new_commits"], 0)
                self.assertGreater(observation["historical_exchanges"], 0)

    def test_another_registration_cannot_supply_renewal_or_recovery_material(self):
        for name in ("credential-original-identity.bin", "after-traffic.bin", "credential-renewal.bin",
                     "credential-proposal.bin", "credential-commit-request.bin", "credential-commit-reply.bin",
                     "credential-history-transcript.bin", "renewed-certificate.bin", "credential-recovered.bin"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); output = fixture(root)
                (root / "signed-fixed" / name).write_bytes((root / "tls-fixed" / name).read_bytes())
                with self.assertRaises(ValueError): self.verify(output, root)

    def test_a_valid_commit_frame_cannot_be_relabelled_as_historical_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = fixture(root); case = root / "signed-fixed"
            frame = b"\x01" + (case / "credential-commit-request.bin").read_bytes() + (case / "credential-commit-reply.bin").read_bytes()
            (case / "credential-history-transcript.bin").write_bytes(frame)
            (case / "credential-dispatch-observation.bin").write_bytes((1).to_bytes(4, "big") * 2 + bytes(4))
            with self.assertRaisesRegex(ValueError, "dispatched a credential commit"): self.verify(output, root)

    def test_errors_padding_and_clock_observations_cannot_be_success_shaped(self):
        for name in ("credential-expired.bin", "credential-expired-request.bin", "credential-closed.bin",
                     "credential-unmanaged.bin", "credential-unknown.bin", "credential-expiry-observation.bin"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); output = fixture(root); path = root / "signed-fixed" / name
                path.write_bytes(bytes(len(path.read_bytes())))
                with self.assertRaises(ValueError): self.verify(output, root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = fixture(root); path = root / "signed-fixed/credential-recovered.bin"
            raw = bytearray(path.read_bytes()); raw[68] = 1; path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "padding"): self.verify(output, root)

    def test_required_execution_phases_and_private_inventory_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = fixture(root)
            for changed in (output.replace(b"1 passed", b"0 passed"), output + output,
                            output.replace(b"fresh_request_refused=true", b"fresh_request_refused=false")):
                with self.assertRaises(ValueError): self.verify(changed, root)
            (root / "tls-fixed/authority.key").write_bytes(b"reader control only")
            with self.assertRaisesRegex(ValueError, "inventory"): self.verify(output, root)

    def test_c_execution_is_not_foreign_credential_qualification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = fixture(root)
            with self.assertRaisesRegex(ValueError, "not qualified"):
                account.verify_execution(output, root, language="Swift", credential=True)
