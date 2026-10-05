"""Synthetic public-readback counterexamples, not signature/runtime evidence."""
from pathlib import Path
import tempfile
import unittest

import continuity_witnessed_commit_error as error
from continuity_c_witness import commit, RECORD_BYTES
from continuity_roster_renewal import envelope
from test_continuity_enrollment import u64, wire
from test_continuity_witnessed_renewal import fixture as renewal_fixture


def fixture(directory):
    directory.mkdir()
    lines = []
    with tempfile.TemporaryDirectory() as temporary:
        for expired in (False, True):
            source = Path(temporary) / str(expired)
            renewal_fixture(source, policy_validity=(29, 150) if expired else (99, 250))
            for carrier in ("tcp", "tls"):
                case = carrier + ("-expired" if expired else "-live")
                folder = directory / case;folder.mkdir()
                original = {p.name:p.read_bytes() for p in (source / (carrier + "-applied")).iterdir()}
                files = {n:v for n,v in original.items() if n in error.MATERIALS}
                files["error-image-digests"] = original["renewal-image-digests"]
                trace = original["renewal-tls-transcript" if carrier == "tls" else "renewal-witness-transcript"]
                rows = [trace[n:n + RECORD_BYTES] for n in range(0,len(trace),RECORD_BYTES)]
                rq = bytearray(envelope(rows[5][1:3675], b"QPANRQ01", 297));rq[168:200] = b"N" * 32
                rs = bytearray(envelope(rows[5][3675:], b"QPANRS01", 282));rs[136:168] = commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-REQUEST/v1", bytes(rq))
                frames = rows[:2] + [rows[3], b"\0" + rows[4][1:], rows[5], b"\1" + wire(bytes(rq)) + wire(bytes(rs)), rows[6]]
                files["error-witness-transcript"] = b"".join(frames)
                files["error-tcp-transcript"] = b"" if carrier == "tls" else files["error-witness-transcript"]
                files["error-observer-request"] = rows[5][1:3675]
                files["error-observer-reply"] = rows[5][3675:]
                files["error-cut-prefix"] = b"" if carrier == "tls" else (3659).to_bytes(4,"big") + rows[4][3675:5475]
                values = [(29 if expired else 99),(150 if expired else 250),300,110,111,112,
                          150 if expired else 113,151 if expired else 114,2,4,5,7,7,0,4000 if carrier == "tls" else 0]
                files["error-observations"] = b"QPCEER01" + bytes([carrier == "tls",expired,218,2]) + b"".join(map(u64,values))
                mapped = {"error-original-active":"renewal-original-active", "error-original-status":"renewal-original-status",
                    "error-stage":"renewal-stage", "error-prepare":"renewal-prepare", "error-pending":"renewal-stage",
                    "error-recovered":"renewal-terminal", "error-repeat":"renewal-terminal", "error-final-status":"renewal-final-status"}
                for label in error.LABELS:
                    if label == "error-return": value = b"credential-witness-commit-refused:218\n"
                    elif label == "error-activation": value = b"enrollment-activation-refused:104\n" if expired else b""
                    else: value = original[f"witness-enrollment-{mapped.get(label,label)}.stdout"]
                    files[f"witness-enrollment-{label}.stdout"] = value
                    files[f"witness-enrollment-{label}.stderr"] = b""
                assert set(files) == error.FILES
                for name,value in files.items(): (folder / name).write_bytes(value)
    for case in error.CASES:
        lines.append(f"WITNESSED_COMMIT_ERROR case={case} returned=218 owner_closed=true normal_exit=true original_pending=true "
                     f"committed=true policy_expired={str(case.endswith('expired')).lower()}")
    return ("\n".join(lines) + "\ntest " + error.TEST + " ... ok\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out;\n").encode()


class CommitErrorEvidenceTests(unittest.TestCase):
    def test_complete_public_closure_and_selected_language(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);stdout=fixture(root/"runtime")
            for language in ("C","Swift","Kotlin"):
                report=error.export(stdout,root/"runtime",root/language,language=language)
                self.assertEqual(len(report["public_readbacks"]),260)
                self.assertFalse(report["release_claim_eligible"])
                self.assertEqual(report,error.verify(stdout,root/language,language=language))
            serial=stdout.replace(b"test "+error.TEST.encode()+b" ... ok\n",b"")
            serial=b"test "+error.TEST.encode()+b" ... "+serial.split(b"test result:")[0]+b"ok\n"+stdout[stdout.index(b"test result:"):]
            self.assertEqual(error.verify(serial,root/"runtime"),error.verify(stdout,root/"runtime"))

    def test_original_bindings_pending_image_and_fresh_observation_cannot_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);stdout=fixture(root/"runtime");folder=root/"runtime/tcp-expired"
            for name,offset in {"protocol-policy":60,"policy-digest":0,"policy-root":0,"witness-public":0,
                "credential-renewal":12,"credential-proposal-original":295,"error-image-digests":32,
                "error-observer-request":168,"error-observer-reply":300,"error-cut-prefix":100}.items():
                path=folder/name;original=path.read_bytes();changed=bytearray(original);changed[offset]^=1;path.write_bytes(changed)
                with self.subTest(name=name),self.assertRaises(ValueError):error.verify(stdout,root/"runtime")
                path.write_bytes(original)

    def test_unknown_error_live_handle_signal_exit_or_wrong_policy_window_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);stdout=fixture(root/"runtime")
            for case in error.CASES:
                path=root/"runtime"/case/"error-observations";original=path.read_bytes()
                changes=[b"",original[:-1],original+b"x",original[:10]+b"\2"+original[11:],original[:11]+b"\0"+original[12:]]
                for index,value in [(4,300),(5,149 if case.endswith('live') else 150),(6,149 if case.endswith('expired') else 250),
                                    (9,3),(10,6),(11,8),(12,8),(13,9),(14,0 if case.startswith('tls') else 1)]:
                    changed=bytearray(original);changed[12+index*8:20+index*8]=u64(value);changes.append(bytes(changed))
                for value in changes:
                    path.write_bytes(value)
                    with self.subTest(case=case,value=value),self.assertRaises(ValueError):error.verify(stdout,root/"runtime")
                path.write_bytes(original)

    def test_missing_loss_reordered_commit_or_extra_ack_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);stdout=fixture(root/"runtime");folder=root/"runtime/tcp-live"
            path=folder/"error-witness-transcript";original=path.read_bytes();rows=[original[n:n+RECORD_BYTES] for n in range(0,len(original),RECORD_BYTES)]
            changes=[]
            delivered=bytearray(original);delivered[3*RECORD_BYTES]=1;changes.append(bytes(delivered))
            for a,b in [(2,3),(3,4),(4,5),(5,6)]:
                reordered=rows.copy();reordered[a],reordered[b]=reordered[b],reordered[a];changes.append(b"".join(reordered))
            changes.append(original+rows[-1])
            for value in changes:
                path.write_bytes(value);(folder/"error-tcp-transcript").write_bytes(value)
                with self.assertRaises(ValueError):error.verify(stdout,root/"runtime")

    def test_missing_output_wrong_error_and_unrelated_private_files_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);stdout=fixture(root/"runtime");folder=root/"runtime/tls-live"
            path=folder/"witness-enrollment-error-return.stdout";original=path.read_bytes()
            for value in (b"",original.replace(b"218",b"215"),original+b"extra\n"):
                path.write_bytes(value)
                with self.assertRaises(ValueError):error.verify(stdout,root/"runtime")
            path.write_bytes(original)
            extra=folder/"wrap.key";extra.write_bytes(b"synthetic extra")
            with self.assertRaises(ValueError):error.verify(stdout,root/"runtime")
            extra.unlink();path=folder/"error-tcp-transcript";path.write_bytes(b"unexpected plaintext")
            with self.assertRaises(ValueError):error.verify(stdout,root/"runtime")

    def test_incomplete_native_execution_or_case_census_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);stdout=fixture(root/"runtime")
            for value in (stdout+stdout,stdout.replace(b"0 failed",b"1 failed"),stdout.replace(b"0 ignored",b"1 ignored"),
                          stdout.replace(b"10 filtered",b"7 filtered"),stdout.replace(b"normal_exit=true",b"normal_exit=false")):
                self.assertNotEqual(value, stdout)
                with self.assertRaises(ValueError):error.verify(value,root/"runtime")
            (root/"runtime/tcp-live/unexpected.stdout").write_bytes(b"")
            with self.assertRaises(ValueError):error.verify(stdout,root/"runtime")


if __name__ == "__main__":unittest.main()
