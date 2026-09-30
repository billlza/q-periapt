"""Fault receipts and complete loss accounting must reject incomplete evidence."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import continuity_c_faults as f


class ContinuityCFaultTests(unittest.TestCase):
    def test_command_timeout_reaps_its_process_group_and_cannot_report_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = Path(sys.executable).resolve()
            matrix = f.Matrix(root, root, "unit", {}, binary, binary, binary, binary)
            ready, late = root / "ready", root / "late"
            child = ("from pathlib import Path; import time; "
                     f"Path({str(ready)!r}).write_text('ready'); time.sleep(3); "
                     f"Path({str(late)!r}).write_text('escaped')")
            parent = ("import subprocess,sys,time; "
                      f"subprocess.Popen([sys.executable,'-c',{child!r}]); time.sleep(30)")
            with patch.object(f, "COMMAND_TIMEOUT", 2), self.assertRaises(subprocess.TimeoutExpired):
                matrix.command([binary, "-c", parent], "deadline")
            self.assertTrue(ready.is_file(), "owned descendant did not start")
            time.sleep(1.5)
            self.assertFalse(late.exists(), "owned descendant outlived timeout cleanup")
            record = json.loads((root / "c-fault-unit-deadline.json").read_text())
            self.assertIs(record["completed"], False)
            self.assertIs(record["timed_out"], True)

    def test_matrix_cannot_omit_a_cut_or_replace_a_real_reserved_outcome(self):
        cases = []
        for phase in ("send", "begin", "ack"):
            for cut, side in ((0, "before"), (1, "before"), (1, "after")):
                state = {"begin": "pending" if side == "after" else "open",
                         "ack": "closed" if side == "after" else "pending"}
                cases.append({"phase": phase, "cut": cut, "side": side, "syncs": 1, "completed": True,
                              "status": (2 if cut == 0 else int(side == "after")) if phase == "send" else 1,
                              "observed_phase": state.get(phase)})
        self.assertEqual(f.coverage(cases), {p: {"syncs": 1, "cases": 3} for p in ("send", "begin", "ack")})
        for changed in (cases[:-1], cases + [cases[0]], cases[:3], []):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                f.coverage(changed)
        for field, value in (("cut", True), ("completed", 1), ("status", True), ("syncs", 65)):
            changed = copy.deepcopy(cases); changed[1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                f.coverage(changed)
        changed = copy.deepcopy(cases); changed[2]["status"] = 2
        with self.assertRaises(ValueError):
            f.coverage(changed)

    def test_original_identity_plan_rejects_substitute_epoch_and_noncanonical_shape(self):
        original = {"session": "11" * 32, "context": "22" * 32, "peer_account": "33" * 32,
                    "peer_device": "44" * 16, "message": "00" * 16 + "55" * 16}
        self.assertEqual(f.plan(json.dumps(original).encode()), original)
        for changed in (dict(original, message="77" * 32), dict(original, session=True),
                        dict(original, peer_device="44" * 32), dict(original, extra="unexpected"), []):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                f.plan(json.dumps(changed).encode())

    def test_only_exact_real_sync_sequences_qualify(self):
        calibrated = b"armed 0 0\nbefore 1 0\nafter 1 0\nbefore 2 0\nafter 2 0\ndone 2 0\n"
        self.assertEqual(f.events(calibrated, 0, "before"), 2)
        self.assertEqual(f.events(b"armed 1 0\nbefore 1 0\n", 1, "before"), 1)
        self.assertEqual(f.events(b"armed 1 1\nbefore 1 0\nafter 1 0\n", 1, "after"), 1)
        for data in (b"", calibrated[:-1], calibrated.replace(b"after 1 0\n", b""),
                     calibrated.replace(b"after 1 0", b"after 1 -1"), calibrated.replace(b"done 2 0", b"done 65 0"),
                     calibrated.replace(b"before 2 0", b"before 1 0"), calibrated + b"extra\n"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                f.events(data, 0, "before")
        for cut, side in ((True, "before"), (65, "before"), (-1, "after"), (1, "unknown")):
            with self.subTest(cut=cut, side=side), self.assertRaises(ValueError):
                f.events(calibrated, cut, side)
        with self.assertRaises(ValueError):
            f.events(b"armed 1 1\nbefore 1 0\n", 1, "after")

    def test_reserved_input_must_survive_as_original_lengths_and_id(self):
        original = {"session": "11" * 32, "context": "22" * 32, "peer_account": "33" * 32,
                    "peer_device": "44" * 16, "message": "00" * 16 + "55" * 16}
        report = "66" * 32
        rows = ["QPC-C-LOSS/1", "report " + report,
                f"header {original['session']} {original['context']} {original['peer_account']} "
                f"{original['peer_device']} 2 1 0 0 0 0 0 1 1",
                f"reserved 0 {original['message']} 29 13", f"epoch 0 0 0 0 0 0 0 0 0 {'0' * 64} 0 0 0"]
        data = ("\n".join(rows) + "\n").encode()
        self.assertEqual(f.loss_report(data, original, 1), report)
        for changed in (data.replace(b" 29 13", b" 0 0"), data.replace(rows[3].encode() + b"\n", b""),
                        data.replace(original["message"].encode(), b"77" * 32), data + b"reserved 1 omitted\n"):
            with self.subTest(data=changed), self.assertRaises(ValueError):
                f.loss_report(changed, original, 1)
        for status, wire in ((0, None), (2, None), (True, None), (1, b"QPCMSG03unexpected")):
            with self.subTest(status=status, wire=wire), self.assertRaises(ValueError):
                f.loss_report(data, original, status, wire)


if __name__ == "__main__":
    unittest.main(warnings="error")
