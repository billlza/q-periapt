"""Synthetic parser counterexamples; these do not verify signatures or execution."""
from pathlib import Path
import tempfile
import unittest

import continuity_witnessed_cancellation as cancellation
from continuity_c_witness import commit, RECORD_BYTES
from continuity_roster_renewal import envelope
from test_continuity_enrollment import u64, wire
from test_continuity_witnessed_renewal import fixture as renewal_fixture


def frame(authority, subject, initial, index, kind, outcome, data, delivered=1):
    op = bytes([kind]) + data
    command = commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-COMMAND/v1", authority + subject + op)
    rq = b"QPANRQ01" + authority + subject + command + bytes([index + 1]) * 32 + op
    rs = (b"QPANRS01" + authority + subject + commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-REQUEST/v1", rq)
          + command + bytes([outcome]) + initial + bytes(33))
    return bytes([delivered]) + wire(rq) + wire(rs)


def fixture(directory, *, tls_failure=False):
    directory.mkdir()
    lines = []
    with tempfile.TemporaryDirectory() as temporary:
        source = Path(temporary)
        for validity, interval in (("live", (100, 400)), ("expired", (29, 150))):
            renewal_fixture(source / validity, policy_validity=interval)
        for case in cancellation.CASES:
            carrier, validity, cut = case.split("-")
            tls, expired, ack = carrier == "tls", validity == "expired", cut == "ack"
            interval = (29, 150) if expired else (100, 400)
            folder = directory / case; folder.mkdir()
            original = {p.name:p.read_bytes() for p in (source / validity / (carrier + "-closed")).iterdir()}
            files = {k:v for k,v in original.items() if k in cancellation.MATERIALS}
            proposal = original["credential-proposal"]
            descriptor = b"QPCRNC01" + proposal[8:248]
            authority, subject, initial = descriptor[8:40], descriptor[40:136], descriptor[200:]
            binding = commit(b"Q-PERIAPT-ANCHOR-CREDENTIAL-CANCELLATION/v1", descriptor)
            files["credential-cancellation"] = files["credential-cancellation-original"] = descriptor
            files["cancel-image-digests"] = initial[16:] * 3
            trace = original["renewal-tls-transcript" if tls else "renewal-witness-transcript"]
            admission = envelope(trace[RECORD_BYTES + 1:RECORD_BYTES + 3675], b"QPANRQ01", 297)[201:]
            commands = [(1, 1, bytes(96)), (4, 5, admission)]
            middle = [(6,10), (6,10)] + ([(6,9), (8,11), (8,11)] if ack else [(6,9), (6,9), (8,11)])
            commands += [(k,o,binding + bytes(64)) for k,o in middle]
            if not expired: commands += [(1,1,bytes(96)), (4,5,admission)]
            cut_index = 5 if ack else 4
            failed = tls and tls_failure
            rows = [frame(authority, subject, initial, n, k, o, data, 0 if not tls and n == cut_index else 1)
                    for n,(k,o,data) in enumerate(commands) if not (failed and n == cut_index)]
            files["cancel-witness-transcript"] = b"".join(rows)
            files["cancel-tcp-transcript"] = b"" if tls else b"".join(rows)
            now = 150 if expired else 110
            values = [*interval, 300, now, now + 1, now + 2, 2, len(commands), int(failed), cut_index, 7,
                      cut_index if failed else 2**64 - 1, 9]
            files["cancel-observations"] = b"QPGCFL01" + bytes([tls,expired,8 if ack else 6,4 if ack else 1]) + b"".join(u64(n) for n in values)
            mapped = {"cancel-original-active":"renewal-original-active", "cancel-original-status":"renewal-original-status",
                      "cancel-stage":"renewal-stage", "cancel-pending":"renewal-stage", "cancel-final-status":"renewal-final-status",
                      "cancel-cut-status":"renewal-terminal" if ack else "renewal-stage",
                      "cancel-recover":"renewal-terminal", "cancel-repeat":"renewal-terminal"}
            for label in cancellation.LABELS:
                if label in ("cancel-reserve", "cancel-reserve-reopened"):
                    value = b"credential-witness-cancel-reserved\n"
                elif label == "cancel-commit-refused":
                    value = f"credential-witness-commit-refused:{104 if expired else 215}\n".encode()
                elif label == "cancel-cut": value = b""
                elif label == "cancel-activation":
                    value = b"enrollment-activation-refused:104\n" if expired else original["witness-enrollment-renewal-original-active.stdout"]
                else: value = original[f"witness-enrollment-{mapped.get(label, label)}.stdout"]
                files[f"witness-enrollment-{label}.stdout"] = value
                files[f"witness-enrollment-{label}.stderr"] = b""
            assert set(files) == cancellation.FILES
            for name, value in files.items(): (folder / name).write_bytes(value)
            lines.append(f"WITNESSED_CANCELLATION case={case} original_reservation=true no_target=true no_sdk_prepare=true "
                         f"killed_owner=true local_cut_phase={4 if ack else 1} closed=true policy_expired={str(expired).lower()}")
    return ("\n".join(lines) + "\ntest " + cancellation.TEST + " ... ok\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out;\n").encode()


class CancellationEvidenceTests(unittest.TestCase):
    def test_complete_scope_and_tls_server_completion_or_cut_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for failed in (False, True):
                runtime = root / str(failed); stdout = fixture(runtime, tls_failure=failed)
                for language in ("C", "Swift", "Kotlin"):
                    checked = cancellation.export(stdout, runtime, root / (str(failed) + language), language=language)
                    self.assertEqual(len(checked["public_readbacks"]), len(cancellation.FILES) * 8)
                    self.assertFalse(checked["release_claim_eligible"])
                    self.assertEqual(checked, cancellation.verify(stdout, runtime, language=language))
                    tls = checked["cases"]["tls-expired-ack"]["carrier"]
                    self.assertEqual(tls["failed_admissions"], int(failed))
                    self.assertIn("peer consumption unproven", tls["tls_records_mean"])

    def test_original_scope_descriptor_and_image_corruption_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "runtime"; stdout = fixture(root)
            for name, offset in {"credential-operation":0, "credential-statement":0, "policy-digest":0,
                    "enrollment-root":0, "witness-public":0, "credential-cancellation":72,
                    "credential-cancellation-original":247, "cancel-image-digests":95, "credential-renewal":12}.items():
                path = root / "tcp-live-status" / name; old = path.read_bytes()
                value = bytearray(old); value[offset] ^= 1; path.write_bytes(value)
                with self.subTest(name=name), self.assertRaises(ValueError): cancellation.verify(stdout, root)
                path.write_bytes(old)
            for name in ("credential-cancellation", "credential-cancellation-original"):
                path = root / "tcp-live-status" / name
                path.write_bytes(path.read_bytes() + bytes(48))
            with self.assertRaises(ValueError): cancellation.verify(stdout, root)

    def test_time_cut_phase_signal_and_admission_counterexamples_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "runtime"; stdout = fixture(root, tls_failure=True)
            path = root / "tls-expired-ack/cancel-observations"; old = path.read_bytes()
            # Signed interval, actual expiry, monotonic time, reservation window,
            # total count, optional failure, cut ordinal, recovery end and kill.
            for field, value in ((0,30),(1,151),(2,301),(3,149),(4,149),(5,301),
                                 (6,3),(7,8),(8,0),(9,4),(10,6),(11,4),(12,0)):
                changed = bytearray(old); changed[12+field*8:20+field*8] = u64(value); path.write_bytes(changed)
                with self.subTest(field=field), self.assertRaises(ValueError): cancellation.verify(stdout, root)
                path.write_bytes(old)
            changed = bytearray(old); changed[11] = 1; path.write_bytes(changed)
            with self.assertRaises(ValueError): cancellation.verify(stdout, root)

    def test_rebound_device_mutation_and_ack_before_closed_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "runtime"; stdout = fixture(root)
            folder = root / "tcp-live-status"; path = folder / "cancel-witness-transcript"; old = path.read_bytes()
            descriptor = (folder / "credential-cancellation").read_bytes()
            authority, subject, initial = descriptor[8:40], descriptor[40:136], descriptor[200:]
            binding = commit(b"Q-PERIAPT-ANCHOR-CREDENTIAL-CANCELLATION/v1", descriptor)
            for index, kind, outcome, data in ((2,5,8,binding), (2,7,9,binding), (4,8,11,binding),
                                              (6,6,9,binding), (3,6,10,b"X" * 32)):
                replacement = frame(authority, subject, initial, index, kind, outcome, data + bytes(64), 0 if index == 4 else 1)
                changed = old[:index*RECORD_BYTES] + replacement + old[(index+1)*RECORD_BYTES:]
                for name in ("cancel-witness-transcript", "cancel-tcp-transcript"): (folder / name).write_bytes(changed)
                with self.subTest(index=index,kind=kind), self.assertRaises(ValueError): cancellation.verify(stdout, root)
                for name in ("cancel-witness-transcript", "cancel-tcp-transcript"): (folder / name).write_bytes(old)

    def test_wrong_loss_location_challenge_reuse_and_plaintext_fallback_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "runtime"; stdout = fixture(root)
            folder = root / "tcp-live-status"; old = (folder / "cancel-witness-transcript").read_bytes()
            changed = bytearray(old); changed[4*RECORD_BYTES] = 1; changed[5*RECORD_BYTES] = 0
            duplicate = old[:3*RECORD_BYTES] + old[2*RECORD_BYTES:3*RECORD_BYTES] + old[4*RECORD_BYTES:]
            for value in (changed, duplicate, old[:-1]):
                for name in ("cancel-witness-transcript", "cancel-tcp-transcript"): (folder / name).write_bytes(value)
                with self.assertRaises(ValueError): cancellation.verify(stdout, root)
            for name in ("cancel-witness-transcript", "cancel-tcp-transcript"): (folder / name).write_bytes(old)
            (root / "tls-expired-status/cancel-tcp-transcript").write_bytes(old)
            with self.assertRaises(ValueError): cancellation.verify(stdout, root)

    def test_missing_case_private_file_and_unsuccessful_cut_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "runtime"; stdout = fixture(root)
            for value in (stdout + stdout, stdout.replace(b"1 passed", b"0 passed"),
                          stdout.replace(b"7 filtered", b"6 filtered"), stdout.replace(b"killed_owner=true", b"killed_owner=false")):
                with self.assertRaises(ValueError): cancellation.verify(value, root)
            for name, value in (("witness-enrollment-cancel-cut.stdout", b"credential-phase:4\n"),
                                ("witness-enrollment-cancel-cut.stderr", b"timeout\n"), ("wrap.key", b"private")):
                path = root / "tcp-live-status" / name; exists = path.exists(); old = path.read_bytes() if exists else None
                path.write_bytes(value)
                with self.assertRaises(ValueError): cancellation.verify(stdout, root)
                if exists: path.write_bytes(old)
                else: path.unlink()
            (root / "tls-expired-ack/cancel-observations").unlink()
            with self.assertRaises(ValueError): cancellation.verify(stdout, root)


if __name__ == "__main__": unittest.main()
