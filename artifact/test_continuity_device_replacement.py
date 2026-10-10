"""Synthetic readback controls; actual signatures are exercised by the native SDK."""
from pathlib import Path
import json
import tempfile
import unittest

import continuity_device_replacement as replacement
from continuity_c_recovery import ciphertext_digest
from continuity_c_witness import commit
from test_continuity_enrollment import u64, wire


def fixture(path: Path, change=""):
    path.mkdir()
    for ordinal, role in enumerate(replacement.ROLES, 1):
        folder = path / role; folder.mkdir()
        key = bytes([ordinal]) * 1952 + b"\x02" + bytes([ordinal + 8]) * 32
        if role == "new" and change == "component": key = b"\x01" * 1952 + key[1952:]
        root = bytes([42 + (role == "new" and change == "account")]) * 1952 + b"\x03" + b"9" * 32
        account = commit(b"Q-PERIAPT-CONTINUITY-ACCOUNT-CANDIDATE/v1", root)
        identity = bytes([ordinal + 70]) * 32
        device = b"d" * 16
        generation = u64(1 if role == "new" and change == "generation" else ordinal)
        validity, family = u64(100) + u64(300), b"y" * 32
        metadata = account + device + generation + validity + family
        request = wire(b"QPENRQ01" + identity + metadata + key)
        cert = b"QPCERT01" + metadata + key
        credential = commit(b"Q-PERIAPT-CONTINUITY-CREDENTIAL-CANDIDATE/v1", cert)
        roster = b"QPROST01" + account + u64(ordinal) + validity + b"\x00\x01" + device + generation + credential
        journal = bytes([81 if role == "new" and change == "journal" else ordinal + 80]) * 32
        files = {"request": request, "reopened-request": request, "signer-id": identity,
                 "public-key": key, "local-account": account, "local-root": root,
                 "local-device": device, "local-generation": generation, "enrollment-validity": validity,
                 "family": family, "local-certificate": wire(cert), "local-roster": wire(roster),
                 "local-roster-version": u64(ordinal),
                 "local-roster-digest": commit(b"Q-PERIAPT-CONTINUITY-ROSTER-CANDIDATE/v1", roster),
                 "accepted-journal": journal, "active-journal": journal, "reopened-journal": journal}
        for name, data in files.items(): (folder / name).write_bytes(data)
        (path / (role + "-journal")).write_bytes(journal)
        (path / (role + "-signing-id")).write_bytes(identity)
    report = {**replacement.COUNTS, **{name: True for name in replacement.FLAGS},
              "old_session": "11" * 32, "new_session": "22" * 32,
              "old_message": "33" * 32, "new_message": "44" * 32}
    (path / "result.json").write_text(json.dumps(report))
    for name in ("request", "reopened-request"):
        (path / name).write_bytes((path / "new/request").read_bytes())
    for role, payload in (("old", b"old device effect with unavailable receipt"), ("new", b"fresh replacement session")):
        (path / (role + "-effect")).write_bytes(bytes.fromhex(report[role + "_session"] + report[role + "_message"]) + payload)
    loss = b"l" * 32
    for name in ("loss-id", "loss-complete", "loss-verified"): (path / name).write_bytes(loss)
    (path / "loss-report").write_text("SessionClosure { session: " + str(list(bytes.fromhex(report["old_session"]))) +
        ", report: SessionClosureId(" + str(list(loss)) + ") }\n")
    ciphertext = b"retained original unconfirmed ciphertext"
    (path / "old-ciphertext").write_bytes(ciphertext)
    (path / "loss-ciphertext-digest").write_bytes(bytes.fromhex(ciphertext_digest(ciphertext)))


class DeviceReplacementTests(unittest.TestCase):
    def test_complete_readback_survives_export(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); fixture(root / "public")
            checked = replacement.export(root / "public", root / "exported")
            self.assertEqual(replacement.verify(root / "exported"), checked)
            self.assertEqual(len(checked["public_readbacks"]), 49)
            self.assertFalse(checked["required_witness_qualified"])
            self.assertFalse(checked["release_claim_eligible"])

    def test_every_file_and_bound_alias_is_required(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "public"; fixture(root)
            for path in list(root.rglob("*")):
                if not path.is_file(): continue
                data = path.read_bytes(); path.unlink()
                with self.subTest(missing=path.relative_to(root)), self.assertRaises((ValueError, FileNotFoundError)):
                    replacement.verify(root)
                path.write_bytes(data)
            for name in ("old-effect", "new-effect", "old-journal", "new-signing-id", "request",
                         "loss-report", "loss-complete", "old-ciphertext", "loss-ciphertext-digest"):
                path = root / name; data = path.read_bytes(); path.write_bytes(bytes([data[0] ^ 1]) + data[1:])
                with self.subTest(changed=name), self.assertRaises(ValueError): replacement.verify(root)
                path.write_bytes(data)

    def test_coherent_wrong_lineage_and_reused_owner_are_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            for change in ("component", "account", "generation", "journal"):
                root = Path(folder) / change; fixture(root, change)
                with self.subTest(change=change), self.assertRaises(ValueError): replacement.verify(root)

    def test_counters_flags_and_identity_cannot_claim_another_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "public"; fixture(root)
            path = root / "result.json"; original = json.loads(path.read_text())
            for name in (*replacement.FLAGS, *replacement.COUNTS, *replacement.IDENTITIES):
                changed = dict(original)
                changed[name] = False if name in replacement.FLAGS else True if name in replacement.COUNTS else "00" * 32
                path.write_text(json.dumps(changed))
                with self.subTest(field=name), self.assertRaises(ValueError): replacement.verify(root)
            path.write_text(json.dumps(original | {"extra": True}))
            with self.assertRaises(ValueError): replacement.verify(root)


if __name__ == "__main__":
    unittest.main()
