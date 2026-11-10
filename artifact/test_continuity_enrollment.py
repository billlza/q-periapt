"""Synthetic public structures test reader controls, never signature security."""
from pathlib import Path
import tempfile
import unittest

import continuity_enrollment as enrollment
from continuity_c_witness import commit


def u64(value):
    return value.to_bytes(8, "big")


def wire(body):
    # Deliberately synthetic signatures: native public API tests supply real ones.
    return len(body).to_bytes(4, "big") + body + bytes(3373)


def fixture(path):
    path.mkdir()
    for ordinal, role in enumerate(enrollment.ROLES, 1):
        folder = path / role
        folder.mkdir()
        key = bytes([ordinal]) * 1952 + b"\x02" + bytes([ordinal + 8]) * 32
        root = bytes([ordinal + 40]) * 1952 + b"\x03" + bytes([ordinal + 55]) * 32
        account = commit(b"Q-PERIAPT-CONTINUITY-ACCOUNT-CANDIDATE/v1", root)
        identity = bytes([ordinal + 70]) * 32
        device, generation = bytes([ordinal]) * 16, u64(1)
        validity, family = u64(100) + u64(300), b"y" * 32
        metadata = account + device + generation + validity + family
        request = wire(b"QPENRQ01" + identity + metadata + key)
        cert = b"QPCERT01" + metadata + key
        credential = commit(b"Q-PERIAPT-CONTINUITY-CREDENTIAL-CANDIDATE/v1", cert)
        roster = b"QPROST01" + account + u64(1) + validity + b"\x00\x01" + device + generation + credential
        journal = bytes([ordinal + 80]) * 32
        session, forward, reverse = b"s" * 32, b"f" * 32, b"r" * 32
        files = {
            "request": request, "reopened-request": request, "signer-id": identity,
            "public-key": key, "local-account": account, "local-root": root,
            "local-device": device, "local-generation": generation,
            "enrollment-validity": validity, "family": family,
            "local-certificate": wire(cert), "local-roster": wire(roster),
            "local-roster-version": u64(1),
            "local-roster-digest": commit(b"Q-PERIAPT-CONTINUITY-ROSTER-CANDIDATE/v1", roster),
            "accepted-journal": journal, "active-journal": journal, "reopened-journal": journal,
            "session": session, "forward-message": forward, "reverse-message": reverse,
            "forward-effect": session + forward + enrollment.FORWARD_PAYLOAD,
            "reverse-effect": session + reverse + enrollment.REVERSE_PAYLOAD,
            "lease-observation": u64(200 + ordinal) + u64(100),
        }
        for name, data in files.items():
            (folder / name).write_bytes(data)


class EnrollmentEvidenceTests(unittest.TestCase):
    def test_complete_public_binding_survives_export(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture(root / "public")
            result = enrollment.export(root / "public", root / "exported")
            self.assertEqual(enrollment.verify(root / "exported"), result)
            self.assertEqual(len(result["public_readbacks"]), 2 * len(enrollment.FILES))
            self.assertEqual(set(result["roles"]), set(enrollment.ROLES))
            for ordinal, role in enumerate(enrollment.ROLES, 1):
                values = result["roles"][role]
                self.assertEqual(values["journal"], (bytes([ordinal + 80]) * 32).hex())
                self.assertEqual(values["generation"], 1)
                self.assertEqual(values["lease_child_pid"], 200 + ordinal)
                self.assertEqual(values["lease_parent_pid"], 100)
            self.assertIn("signatures verified by native APIs", result["scope"])

    def test_every_required_file_is_mandatory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "public"
            fixture(root)
            for role in enrollment.ROLES:
                for name in sorted(enrollment.FILES):
                    path = root / role / name
                    original = path.read_bytes()
                    path.unlink()
                    with self.subTest(role=role, name=name), self.assertRaises(ValueError):
                        enrollment.verify(root)
                    path.write_bytes(original)

    def test_changed_bound_inputs_and_durable_readbacks_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "public"
            fixture(root)
            for role in enrollment.ROLES:
                for name in sorted(enrollment.FILES - {"lease-observation"}):
                    path = root / role / name
                    original = path.read_bytes()
                    changed = bytearray(original)
                    changed[0] ^= 1
                    path.write_bytes(changed)
                    with self.subTest(role=role, name=name), self.assertRaises(ValueError):
                        enrollment.verify(root)
                    path.write_bytes(original)

    def test_replacing_both_requests_does_not_bypass_original_binding(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "public"
            fixture(root)
            folder = root / "initiator"
            original = (folder / "request").read_bytes()
            # Change each request field in BOTH copies; the independent retained
            # identity/intent/key or credential still has to match the request.
            for offset in (4 + 8, 4 + 40, 4 + 72, 4 + 88, 4 + 96, 4 + 112, 4 + 144):
                changed = bytearray(original)
                changed[offset] ^= 1
                for name in ("request", "reopened-request"):
                    (folder / name).write_bytes(changed)
                with self.subTest(offset=offset), self.assertRaises(ValueError):
                    enrollment.verify(root)
            for name in ("request", "reopened-request"):
                (folder / name).write_bytes(b"x")
            with self.assertRaises(ValueError):
                enrollment.verify(root)

    def test_checkpoint_hash_alone_cannot_replace_exact_roster_membership(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "public"
            fixture(root)
            folder = root / "initiator"
            original = (folder / "local-roster").read_bytes()
            size = int.from_bytes(original[:4], "big")
            body = original[4:4 + size]
            variants = {
                "other_device": body[:66] + b"z" * 16 + body[82:],
                "other_generation": body[:82] + u64(2) + body[90:],
                "other_credential": body[:90] + b"c" * 32,
                "revoked": body[:64] + b"\x00\x00",
                "duplicate_device": body[:64] + b"\x00\x02" + body[66:] * 2,
                "no_validity_overlap": body[:48] + u64(300) + u64(400) + body[64:],
            }
            for name, changed in variants.items():
                (folder / "local-roster").write_bytes(wire(changed))
                (folder / "local-roster-digest").write_bytes(
                    commit(b"Q-PERIAPT-CONTINUITY-ROSTER-CANDIDATE/v1", changed))
                with self.subTest(name=name), self.assertRaises(ValueError):
                    enrollment.verify(root)

    def test_self_consistent_peer_effects_still_need_the_same_connection(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "public"
            fixture(root)
            folder = root / "responder"
            originals = {name: (folder / name).read_bytes() for name in
                         ("session", "forward-message", "reverse-message", "forward-effect", "reverse-effect")}
            for name in ("session", "forward-message", "reverse-message"):
                for leaf, data in originals.items():
                    (folder / leaf).write_bytes(data)
                (folder / name).write_bytes(b"n" * 32)
                session = (folder / "session").read_bytes()
                for direction, payload in (("forward", enrollment.FORWARD_PAYLOAD),
                                           ("reverse", enrollment.REVERSE_PAYLOAD)):
                    message = (folder / (direction + "-message")).read_bytes()
                    (folder / (direction + "-effect")).write_bytes(session + message + payload)
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, "peers disagree"):
                    enrollment.verify(root)

    def test_zero_identities_invalid_metadata_and_unproven_lease_fail(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "public"
            fixture(root)
            folder = root / "initiator"
            cases = [(name, bytes(width)) for name, width in (
                ("signer-id", 32), ("local-device", 16), ("family", 32),
                ("local-generation", 8), ("local-roster-version", 8),
                ("accepted-journal", 32), ("session", 32), ("forward-message", 32), ("reverse-message", 32))]
            cases += [("local-generation", u64(2**64 - 1)),
                      ("enrollment-validity", u64(300) + u64(100)),
                      ("enrollment-validity", u64(100) + u64(2**64 - 1)),
                      ("lease-observation", u64(100) + u64(100)),
                      ("lease-observation", u64(0) + u64(100)),
                      ("lease-observation", u64(200) + u64(0)),
                      ("lease-observation", b"short")]
            for name, changed in cases:
                path = folder / name
                original = path.read_bytes()
                path.write_bytes(changed)
                with self.subTest(name=name, value=changed), self.assertRaises(ValueError):
                    enrollment.verify(root)
                path.write_bytes(original)
            for name in ("accepted-journal", "active-journal", "reopened-journal"):
                (folder / name).write_bytes(bytes(32))
            with self.assertRaises(ValueError):
                enrollment.verify(root)

    def test_private_extra_symlink_and_nested_inputs_are_never_exported(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            root = parent / "public"
            fixture(root)
            for relative in ("wrap.key", "initiator/signer.key", "responder/enrollment.redb", "public-result.json"):
                path = root / relative
                path.write_bytes(b"not a real secret")
                with self.subTest(relative=relative), self.assertRaises(ValueError):
                    enrollment.export(root, parent / "must-not-exist")
                self.assertFalse((parent / "must-not-exist").exists())
                path.unlink()
            extra = root / "responder" / "nested"
            extra.mkdir()
            with self.assertRaises(ValueError):
                enrollment.verify(root)
            extra.rmdir()
            target = root / "initiator" / "reopened-request"
            target.unlink()
            target.symlink_to(root / "initiator" / "request")
            with self.assertRaises(ValueError):
                enrollment.verify(root)


if __name__ == "__main__":
    unittest.main(warnings="error")
