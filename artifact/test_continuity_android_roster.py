"""Archived real records and adversarial mutations of the public roster readers."""
from pathlib import Path, PurePosixPath
import tempfile
import unittest
import zipfile

import continuity_android_contract as contract
import continuity_android_roster as roster
import continuity_android_policy_roster as policy_roster
import continuity_android_policy_renewal as policy
import continuity_android_roster_witness as witness

from rust_sdk_profile import ROOT


def extract(archive: Path, prefix: str, target: Path) -> None:
    with zipfile.ZipFile(archive) as bundle:
        for name in bundle.namelist():
            if not name.startswith(prefix): continue
            relative = PurePosixPath(name.removeprefix(prefix))
            if not relative.parts: continue
            if relative.is_absolute() or ".." in relative.parts: raise ValueError("unsafe archive member")
            path = target.joinpath(*relative.parts); path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(bundle.read(name))


class InventoryTests(unittest.TestCase):
    def test_exact_catalog_and_missing_replaced_duplicate_tests(self):
        names = sorted(contract.TESTS)
        encode = lambda rows: ("\n".join(name + ": test" for name in rows) + f"\n\n{len(contract.TESTS)} tests, 0 benchmarks\n").encode()
        contract.verify_catalog(encode(names))
        for rows in (names[:-1], names[:-1] + ["replacement"], names[:-1] + [names[0]]):
            with self.assertRaises(ValueError): contract.verify_catalog(encode(rows))

    def test_batch_requires_every_named_test_and_no_ignored_case(self):
        names = sorted(policy_roster.TESTS)
        text = "\n".join("test " + name + " ... ok" for name in names)
        text += f"\ntest result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; {len(contract.TESTS)-10} filtered out;\n"
        contract.verify_batch(text.encode(), policy_roster.TESTS)
        for changed in (text.replace(names[0], "replacement"), text.replace("10 passed", "9 passed"), text.replace("0 ignored", "1 ignored")):
            with self.assertRaises(ValueError): contract.verify_batch(changed.encode(), policy_roster.TESTS)


class PublicRosterTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)

    def peer(self):
        archive = ROOT / "research/sdk-alpha1/evidence/20261012-android-peer-roster/CAPTURE.zip"
        extract(archive, "host/", self.base)
        return (self.base / "execution.stdout").read_bytes()

    def test_real_peer_admission_revocation_and_export(self):
        stdout = self.peer()
        records = roster.verify_local(stdout, self.base, remote=True, catalog=contract.ROSTER_TESTS)
        self.assertEqual(sum(row["foreign_processes"] for row in records.values()), 46)
        export = self.base / "public"
        for profile in records:
            for name in roster.local_public(True):
                path = export / profile / name; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((self.base / profile / name).read_bytes())
        self.assertEqual(roster.verify_local(stdout, export, remote=True, catalog=contract.ROSTER_TESTS), records)

    def test_mutated_remote_slot_and_revocation_are_rejected(self):
        stdout = self.peer()
        for name in ("remote-roster-reopened", "remote-roster-revoked", "roster-effect-after", "pending-resolution"):
            path = self.base / "fixed" / name; original = path.read_bytes()
            changed = bytearray(original); changed[-1] ^= 1; path.write_bytes(changed)
            with self.assertRaises(ValueError): roster.verify_local(stdout, self.base, remote=True, catalog=contract.ROSTER_TESTS)
            path.write_bytes(original)

    def test_real_selected_local_policy_staging_and_mutations(self):
        archive = ROOT / "research/sdk-alpha1/evidence/20261012-local-policy-roster/CAPTURE.zip"
        extract(archive, "host/debug-fixed/", self.base)
        policy_roster.verify_local_records(self.base)
        for name in ("roster-refreshed", "roster-no-policy-fallback", "roster-pending-resolution", "roster-activated-identity"):
            path = self.base / name; original = path.read_bytes()
            changed = bytearray(original); changed[0] ^= 1; path.write_bytes(changed)
            with self.assertRaises(ValueError): policy_roster.verify_local_records(self.base)
            path.write_bytes(original)

    def witnessed(self, terminal):
        archive = ROOT / "research/sdk-alpha1/evidence/20261012-android-policy-roster/CAPTURE.zip"
        extract(archive, "host/roster_signed_fixed_" + terminal + "/", self.base)
        witness.verify_records(self.base, terminal == "closed", selected=True)

    def test_real_witness_terminals_cannot_be_interchanged(self):
        for terminal in ("applied", "closed"):
            with self.subTest(terminal=terminal):
                self.witnessed(terminal)
                with self.assertRaises(ValueError):
                    witness.verify_records(self.base, terminal != "closed", selected=True)

    def test_witness_history_rejects_fresh_commit_and_close(self):
        self.witnessed("applied")
        path = self.base / "roster-historical-transcript"
        original = path.read_bytes()
        for opcode in (16, 18):
            with self.subTest(opcode=opcode):
                changed = bytearray(original); changed[205] = opcode
                path.write_bytes(changed)
                with self.assertRaises(ValueError): witness.verify_records(self.base, False, selected=True)
        path.write_bytes(original)
        witness.verify_records(self.base, False, selected=True)

    def test_witness_policy_binding_and_refusal_state_are_required(self):
        self.witnessed("applied")
        for name, offset in (("inputs/renewal-statement", 0), ("inputs/policy-target/policy-digest", 0),
                             ("roster-original-expired-absent", -1), ("roster-registry-required", -1),
                             ("roster-retired", 7), ("roster-lost-terminal-request", 204)):
            with self.subTest(name=name):
                path = self.base / name; original = path.read_bytes()
                changed = bytearray(original); changed[offset] ^= 1; path.write_bytes(changed)
                with self.assertRaises(ValueError): witness.verify_records(self.base, False, selected=True)
                path.write_bytes(original)

    def test_full_policy_reader_requires_the_original_missing_input(self):
        evidence = ROOT / "research/sdk-alpha1/evidence/20261012-android-policy-roster"
        route = self.base / "signed-fixed"
        prefix = "host/roster_signed_fixed_applied/"
        extract(evidence / "CAPTURE.zip", prefix, route)
        with self.assertRaisesRegex(ValueError, "renewal-operation"):
            policy.verify_route(self.base, "fixed", "signed", with_roster=True)
        extract(evidence / "PUBLIC_INPUT_SUPPLEMENT.zip", prefix, route)
        result = policy.verify_route(self.base, "fixed", "signed", with_roster=True)
        self.assertEqual(result["foreign_processes"], 68)
        self.assertTrue(result["policy_expired"])
        self.assertEqual(result["business_effects"], 1)
