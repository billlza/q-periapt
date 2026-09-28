"""Negative controls for reference byte/accounting evidence and dependency isolation."""
from pathlib import Path
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

    def test_wire_rejects_overflow_aliases_unknown_types_and_trailing_data(self):
        malformed = [b"", bytes.fromhex("01000100"), bytes.fromhex("01010000"),
                     bytes.fromhex("0181000100"), bytes.fromhex("01010107"),
                     bytes.fromhex("0101010000"), b"\x01" + b"\xff"*10 + b"\x02\x01\x00",
                     bytes.fromhex("0101010100") + bytes(31), bytes.fromhex("01010101808004") + bytes(32)]
        for wire in malformed:
            with self.subTest(wire=wire.hex()), self.assertRaises(ref.ReferenceError):
                ref.wire_header(wire)

    def test_json_and_integer_admission_reject_ambiguous_values(self):
        for data in ('{"schema":1,"schema":2}', '{"number":NaN}', '{"number":Infinity}'):
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


if __name__ == "__main__":
    unittest.main(warnings="error")
