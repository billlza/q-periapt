"""Fault receipts and complete loss accounting must reject incomplete evidence."""
import copy
import hashlib
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
    def test_swift_faults_require_explicit_library_and_bind_actual_tool_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            paths = []
            for name in ("client", "helper", "probe", "smoke", "library"):
                path = root / name
                path.write_bytes(name.encode())
                paths.append(path)
            for language, library in (("Rust", None), ("Swift", None), ("C", paths[4]), ("Swift", Path("relative"))):
                with self.subTest(language=language, library=library), self.assertRaises(ValueError):
                    f.Matrix(root, root, "unit", {}, *paths[:4], language=language, expected_library=library)
            matrix = f.Matrix(root, root, "unit", {"DYLD_INSERT_LIBRARIES": "unexpected",
                "QPC_TEST_SYNC_CUT": "1", "QPERIAPT_EXPECTED_CONTINUITY_LIBRARY": "wrong",
                "QPERIAPT_INSTALLED_CLIENT_LANGUAGE": "C"}, *paths[:4], language="Swift", expected_library=paths[4])
            self.assertNotIn("DYLD_INSERT_LIBRARIES", matrix.runtime)
            self.assertNotIn("QPC_TEST_SYNC_CUT", matrix.runtime)
            self.assertEqual(matrix.runtime["QPERIAPT_EXPECTED_CONTINUITY_LIBRARY"], str(paths[4]))
            self.assertEqual(matrix.runtime["QPERIAPT_INSTALLED_CLIENT_LANGUAGE"], "Swift")
            self.assertEqual(matrix.receipt("send-1-after").name, "swift-fault-unit-send-1-after.events")
            result = {"schema_version": 2, "language": "Swift", "completed": True,
                      "binaries": matrix.binaries, "binary_sha256": matrix.identities}
            self.assertEqual(f.verified_tools(result, language="Swift")["installed_library"], paths[4])
            for changed in (dict(result, language="C"), dict(result, schema_version=2.0),
                            dict(result, completed=False), dict(result, binary_sha256={})):
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    f.verified_tools(changed, language="Swift")
            paths[4].write_bytes(b"substituted native library")
            with self.assertRaisesRegex(ValueError, "tool changed"):
                f.verified_tools(result, language="Swift")

    def test_public_replay_requires_positive_accounting_and_original_unknown_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = {"session": "11" * 32, "context": "22" * 32, "peer_account": "33" * 32,
                        "peer_device": "44" * 16, "message": "00" * 16 + "55" * 16}
            report = "66" * 32
            cases = []
            for phase in ("send", "begin", "ack"):
                for cut, side in ((0, "before"), (1, "before"), (1, "after")):
                    status = (2 if cut == 0 else int(side == "after")) if phase == "send" else 1
                    state = ("pending" if side == "after" else "open") if phase == "begin" else ("closed" if side == "after" else "pending")
                    wire = b"QPCMSG03retained-wire"
                    digest = hashlib.sha3_256(len(f.DOMAIN).to_bytes(8, "big") + f.DOMAIN
                        + len(wire).to_bytes(8, "big") + wire).hexdigest()
                    rows = ["QPC-C-LOSS/1", "report " + report,
                        f"header {original['session']} {original['context']} {original['peer_account']} "
                        f"{original['peer_device']} 2 1 0 0 0 0 0 {int(status == 1)} 1"]
                    if status == 1:
                        rows.append(f"reserved 0 {original['message']} 29 13")
                    rows.append(f"epoch 0 0 0 {int(status == 2)} 0 0 0 0 0 {'0' * 64} {int(status == 2)} 0 0")
                    if status == 2:
                        rows.append(f"unconfirmed 0 0 {original['message']} {digest}")
                    loss = ("\n".join(rows) + "\n").encode()
                    files = {"fault-plan.json": json.dumps(original).encode(),
                        "fault-native-status": (b"absent\n", b"reserved\n", b"committed\n")[status],
                        "c-loss-report": loss, "c-closure-archive": b"QPCSCA01" + bytes(354),
                        "native-closure-archive": b"QPCSCA01" + bytes(354)}
                    if status == 2:
                        files["fault-wire"] = wire
                    if phase != "send":
                        files["fault-closure-phase"] = (state + " " + ("" if state == "open" else report) + "\n").encode()
                    label = f"{phase}-{cut}-{side}"
                    target = root / label / "responder"
                    target.mkdir(parents=True)
                    public = {}
                    for name, data in files.items():
                        (target / name).write_bytes(data)
                        public["responder/" + name] = hashlib.sha256(data).hexdigest()
                    cases.append(dict(original, phase=phase, cut=cut, side=side, status=status,
                        syncs=1, completed=True, observed_phase=state, public_readbacks=public,
                        report=report, loss_report_sha256=hashlib.sha256(loss).hexdigest()))
            result = {"schema_version": 2, "language": "Swift", "completed": True,
                "release_claim_eligible": False, "scope": f.SCOPE.replace("installed C ", "installed Swift "),
                "cases": cases, "coverage": f.coverage(cases)}
            self.assertTrue(f.verify_public(result, root, language="Swift")["reserved_positive_case_executed"])
            with self.assertRaisesRegex(ValueError, "scope differs"):
                f.verify_public(result, root, language="C")
            changed = copy.deepcopy(result); changed["cases"].pop()
            with self.assertRaises(ValueError):
                f.verify_public(changed, root, language="Swift")
            path = root / "send-1-after/responder/c-loss-report"
            previous = path.read_bytes(); path.write_bytes(previous.replace(b" 29 13", b" 0 0"))
            changed = copy.deepcopy(result)
            changed["cases"][2]["public_readbacks"]["responder/c-loss-report"] = hashlib.sha256(path.read_bytes()).hexdigest()
            changed["cases"][2]["loss_report_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "complete original loss accounting"):
                f.verify_public(changed, root, language="Swift")
            path.write_bytes(previous)
            path = root / "ack-1-after/responder/fault-closure-phase"
            path.write_bytes(("closed " + "77" * 32 + "\n").encode())
            changed = copy.deepcopy(result)
            changed["cases"][-1]["public_readbacks"]["responder/fault-closure-phase"] = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "original report"):
                f.verify_public(changed, root, language="Swift")

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
