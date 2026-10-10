"""Negative controls for reference byte/accounting evidence and dependency isolation."""
from pathlib import Path
import copy
import json
import tempfile
import tomllib
import unittest

from artifact.bounded_process import capture_output
from artifact import spqr_reference as ref

ROOT = Path(__file__).resolve().parents[1]


class ReferenceTests(unittest.TestCase):
    def test_wire_accepts_exact_control_and_chunk_shapes(self):
        self.assertEqual(ref.wire_header(bytes.fromhex("01010100")), (1, 1, 0))
        for kind in (1,2,3,5,6):
            self.assertEqual(ref.wire_header(bytes([1,1,1,kind,0]) + bytes(32)), (1,1,kind))

    def test_chunk64_requires_its_explicit_experiment_profile(self):
        wire = bytes([1,1,1,1,0]) + bytes(64)
        self.assertEqual(ref.wire_header(wire, chunk_bytes=64), (1,1,1))
        with self.assertRaises(ref.ReferenceError): ref.wire_header(wire)
        with self.assertRaises(ref.ReferenceError): ref.wire_header(wire[:-32], chunk_bytes=64)
        for value in (True, 0, 16, 128, "64"):
            with self.subTest(profile=value), self.assertRaises(ref.ReferenceError):
                ref.wire_header(wire, chunk_bytes=value)

    def test_wire_rejects_overflow_aliases_unknown_types_and_trailing_data(self):
        malformed = [b"", bytes.fromhex("01000100"), bytes.fromhex("01010000"),
                     bytes.fromhex("0181000100"), bytes.fromhex("01010107"),
                     bytes.fromhex("0101010000"), b"\x01" + b"\xff"*10 + b"\x02\x01\x00",
                     bytes.fromhex("0101010100") + bytes(31), bytes.fromhex("01010101808004") + bytes(32)]
        for wire in malformed:
            with self.subTest(wire=wire.hex()), self.assertRaises(ref.ReferenceError):
                ref.wire_header(wire)

    def test_json_and_integer_admission_reject_ambiguous_values(self):
        for data in ('{"schema":1,"schema":2}', '{"number":NaN}', '{"number":Infinity}', '{"number":1e999}', b'{"text":"\xff"}'):
            with self.assertRaises(ref.ReferenceError): ref.decode_json(data)
        for value in (True,False,1.0,"1",None):
            with self.assertRaises(ref.ReferenceError): ref.integer(value,0,5,"test")
        self.assertFalse(ref.identical({"v":True},{"v":1}))

    def test_schedules_account_for_every_packet_and_keep_real_disruption(self):
        for name in ref.SCENARIOS:
            actions = ref.schedule(name)
            sends = [n for action,n in actions if action == "send"]
            consumed = [n for action,n in actions if action in ("receive","drop")]
            self.assertEqual(sends,list(range(ref.MESSAGES)))
            self.assertEqual(sorted(consumed),sends)
            if name == "reordered": self.assertNotEqual(consumed,sends)
            if name == "lossy": self.assertEqual(sum(a=="drop" for a,_ in actions),205)
            if name == "duplicates": self.assertEqual(sum(a=="duplicate" for a,_ in actions),158)

    def test_incomplete_or_symlink_trace_is_not_success(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/"trace.jsonl"
            path.write_text('{}\n')
            with self.assertRaises(ref.ReferenceError): ref.verify_trace(path,"one_way")
            link = Path(folder)/"link.jsonl"
            link.symlink_to(path)
            with self.assertRaises(ref.ReferenceError): ref.snapshot(link,1024)

    def test_snapshot_rejects_ancestor_link_parent_traversal_and_oversized_input(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            real = root/"real"
            real.mkdir()
            data = real/"input"
            data.write_bytes(b"evidence")
            alias = root/"alias"
            alias.symlink_to(real, target_is_directory=True)
            for path, maximum in ((alias/"input",1024),(real/".."/"real"/"input",1024),(data,2)):
                with self.subTest(path=path,maximum=maximum), self.assertRaises(ref.ReferenceError):
                    ref.snapshot(path,maximum)
            self.assertEqual(ref.snapshot(data,1024),b"evidence")

    def test_reference_stays_separate_from_sdk_graph(self):
        manifest = ROOT/"research/continuity-spqr-reference/Cargo.toml"
        text = tomllib.loads(manifest.read_text())
        self.assertFalse(text["package"]["publish"])
        self.assertEqual(text["package"]["license"],"AGPL-3.0-only")
        self.assertEqual(text["dependencies"]["spqr"]["rev"],ref.REVISION)
        self.assertEqual(text["workspace"]["members"],["."])
        output = capture_output(["cargo","metadata","--manifest-path",str(ROOT/"Cargo.toml"),"--locked","--format-version","1","--no-deps"],
                                timeout_seconds=60,maximum_stdout_bytes=1024*1024,maximum_stderr_bytes=65536)
        self.assertEqual(output.returncode,0,output.stderr)
        for package in json.loads(output.stdout)["packages"]:
            self.assertNotIn(package["name"],("spqr","q-periapt-spqr-reference"))
            self.assertTrue(all(d["name"] not in ("spqr","q-periapt-spqr-reference") for d in package["dependencies"]))
        names = {p["name"] for p in tomllib.loads((ROOT/"Cargo.lock").read_text())["package"]}
        self.assertTrue(names.isdisjoint({"spqr","q-periapt-spqr-reference"}))


class SnapshotProjectionTests(unittest.TestCase):
    def fixture(self):
        def varint(value):
            out = bytearray()
            while value >= 128:
                out.append((value & 127) | 128)
                value >>= 7
            out.append(value)
            return bytes(out)
        rows = []
        for sequence in range(ref.MESSAGES):
            wire = b"\x01\x01" + varint(sequence + 1) + b"\x00"
            rows.append({"event":"send", "sequence":sequence, "sender":0, "wire":wire.hex(), "state":{"epoch":0}})
            rows.append({"event":"receive", "sequence":sequence, "receiver":1, "state":{"epoch":0}})
        report = {"schema":1, "scenario":"one_way", "upstream_revision":ref.REVISION, "public_test_entropy":True,
                  "threat":ref.SNAPSHOT_THREAT, "interpretation":ref.SNAPSHOT_INTERPRETATION, "cases":[]}
        for cut in ref.CUTS:
            for owner in (0,1):
                report["cases"].append({"cut_before_send":cut, "owner":owner, "snapshot_chain_epoch":0,
                    "snapshot_braid_state":"KeysUnsampled" if owner == 0 else "NoHeaderReceived",
                    "stolen_pending_dk_epoch":None, "recovered_pending_epoch":None,
                    "predicted_sequences":list(range(cut,ref.MESSAGES)), "not_derived_sequences":[],
                    "wrong_key_control_mismatch_at":cut})
        return report, b"\n".join(json.dumps(row).encode() for row in rows)

    def test_projection_covers_each_cut_owner_and_future_message(self):
        report, trace = self.fixture()
        result = ref.verify_compromise(json.dumps(report).encode(), trace, "one_way")
        self.assertEqual(len(result["cases"]),12)
        self.assertTrue(all(case["predicted"] == ref.MESSAGES-case["cut_before_send"] and case["not_derived"] == 0 for case in result["cases"]))

    def test_projection_rejects_changed_scope_private_fields_and_missing_cases(self):
        report, trace = self.fixture()
        for field, value in (("interpretation","secure after recovery"),("public_test_entropy",False),
                             ("schema",True),("private_root","00"*32),("cases",report["cases"][:-1])):
            altered = copy.deepcopy(report)
            altered[field] = value
            with self.subTest(field=field), self.assertRaises(ref.ReferenceError):
                ref.verify_compromise(json.dumps(altered).encode(), trace, "one_way")

    def test_projection_rejects_wrong_epoch_completion_and_key_accounting(self):
        report, trace = self.fixture()
        for field, value in (("owner",1),("cut_before_send",True),("snapshot_chain_epoch",1),
                             ("stolen_pending_dk_epoch",1),
                             ("recovered_pending_epoch",{"epoch":1,"public_ciphertext_complete_at":100}),
                             ("predicted_sequences",list(range(1,ref.MESSAGES))),
                             ("not_derived_sequences",[0]),("wrong_key_control_mismatch_at",1)):
            altered = copy.deepcopy(report)
            altered["cases"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ref.ReferenceError):
                ref.verify_compromise(json.dumps(altered).encode(), trace, "one_way")


if __name__ == "__main__":
    unittest.main(warnings="error")
