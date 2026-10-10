"""Synthetic public-reader counterexamples, not signature/runtime qualification."""
from pathlib import Path
import tempfile
import unittest

import continuity_witnessed_policy_expiry as expiry
import continuity_witnessed_renewal as renewal
from continuity_c_witness import commit, RECORD_BYTES
from continuity_roster_renewal import envelope
from test_continuity_enrollment import u64, wire
from test_continuity_witnessed_renewal import fixture as renewal_fixture


def encode(points, *, applied):
    return (b"QPCEPX01" + u64(29) + u64(150) + u64(100) + u64(300) + bytes([applied, len(points)])
            + b"".join(bytes([len(name)]) + name.encode() + u64(now) + u64(elapsed) + u64(count)
                       for name, now, elapsed, count in points))


def fixture(directory):
    renewal_fixture(directory, policy_validity=(29, 150))
    lines = []
    for case in expiry.CASES:
        folder = directory / case
        original = {p.name:p.read_bytes() for p in folder.iterdir()}
        applied, tls = case.endswith("applied"), case.startswith("tls")
        files = {name:value for name, value in original.items() if name in expiry.MATERIALS}
        files["expiry-image-digests"] = original["renewal-image-digests"]
        policy = envelope(original["protocol-policy"], b"QPSESP03", 200)
        files["expiry-sdk-binding"] = policy[96:164]
        for name in ("enrollment-policy-refusal", "enrollment-policy-refusal-before-recovery"):
            files[name] = b"candidate validity interval denied"
        source = original["renewal-tls-transcript" if tls else "renewal-witness-transcript"]
        rows = [source[n:n + RECORD_BYTES] for n in range(0, len(source), RECORD_BYTES)]
        before = rows[:2] + ([rows[3], b"\0" + rows[4][1:], rows[5]] if applied else [])
        files["expiry-commit-cut-observations"] = (b"QPCECK01" + bytes([tls,9,1,0]) + u64(109)
            + u64(4000 if tls else 0)) if applied else b""
        if applied:
            rq = bytearray(envelope(rows[5][1:3675], b"QPANRQ01", 297)); rq[168:200] = b"N" * 32
            rs = bytearray(envelope(rows[5][3675:], b"QPANRS01", 282))
            rs[136:168] = commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-REQUEST/v1", bytes(rq))
            after = [b"\1" + wire(bytes(rq)) + wire(bytes(rs)), rows[6]]
        else:
            after = rows[2:7]
        files["expiry-witness-transcript"] = b"".join(before + after)
        files["expiry-tcp-transcript"] = b"" if tls else files["expiry-witness-transcript"]
        for prefix, row in (("withheld", rows[4]), ("setup-status", rows[5])):
            files[f"expiry-{prefix}-request"] = row[1:3675] if applied else b""
            files[f"expiry-{prefix}-reply"] = row[3675:] if applied else b""
        count = len(before)
        points = [("prepared", 110, 1000, count), ("expired", 150, 41000, count)]
        for label, delta in zip(expiry.CALLS, ([0,0,2,0,0,0,0] if applied else [0,0,1,1,3,0,0]), strict=True):
            points.append((label, 150, 41000, count));count += delta
            points.append((label, 150, 41000, count))
        files["expiry-observations"] = encode(points, applied=applied)
        mapped = {"expiry-original-active":"renewal-original-active", "expiry-original-status":"renewal-original-status",
                  "expiry-stage":"renewal-stage", "expiry-prepare":"renewal-prepare", "expiry-pending-status":"renewal-stage",
                  "expiry-prepare-reopened":"renewal-prepare-reopened", "expiry-history":"renewal-terminal" if applied else "renewal-stage",
                  "expiry-retry":"renewal-terminal", "expiry-terminal-history":"renewal-terminal", "expiry-final-status":"renewal-final-status"}
        for label in expiry.LABELS:
            if label == "expiry-commit-cut":
                value = b""
            elif label in ("expiry-activation-before", "expiry-activation-after"):
                value = b"enrollment-activation-refused:104\n"
            elif label == "expiry-transition":
                value = original["witness-enrollment-renewal-terminal.stdout"] if applied else b"credential-witness-commit-refused:104\n"
            else:
                value = original[f"witness-enrollment-{mapped.get(label, label)}.stdout"]
            files[f"witness-enrollment-{label}.stdout"] = value
            files[f"witness-enrollment-{label}.stderr"] = b""
        assert set(files) == expiry.FILES
        for path in folder.iterdir(): path.unlink()
        for name, value in files.items(): (folder / name).write_bytes(value)
        lines.append(f"WITNESSED_POLICY_EXPIRY case={case} policy_until=150 observed=150 credential_until=300 "
                     f"sdk_present=true original_policy=true no_new_commit=true foreign_commit_killed={str(applied).lower()}")
    return ("\n".join(lines) + "\ntest " + expiry.TEST + " ... ok\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out;\n").encode()


class PolicyExpiryEvidenceTests(unittest.TestCase):
    def test_complete_scope_export_and_selected_language(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); stdout = fixture(root / "runtime")
            for language in ("C", "Swift", "Kotlin"):
                report = expiry.export(stdout, root / "runtime", root / language, language=language)
                self.assertEqual(len(report["public_readbacks"]), 312)
                self.assertFalse(report["release_claim_eligible"])
                self.assertEqual(report, expiry.verify(stdout, root / language, language=language))
            serial = stdout.replace(b"test " + expiry.TEST.encode() + b" ... ok\n", b"")
            serial = b"test " + expiry.TEST.encode() + b" ... " + serial.split(b"test result:")[0] + b"ok\n" + stdout[stdout.index(b"test result:"):]
            self.assertEqual(expiry.verify(serial, root / "runtime"), expiry.verify(stdout, root / "runtime"))

    def test_changed_policy_grant_pin_proposal_sdk_and_applied_cut_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); stdout = fixture(root / "runtime")
            for name, offset in {"protocol-policy":60, "policy-digest":0, "policy-root":0, "witness-public":0,
                    "credential-renewal":12, "credential-proposal-original":295, "expiry-image-digests":95,
                    "expiry-sdk-binding":0, "expiry-withheld-request":168, "expiry-setup-status-reply":300,
                    "enrollment-policy-refusal":0,"expiry-commit-cut-observations":9}.items():
                path = root / "runtime/tcp-applied" / name; original = path.read_bytes()
                value = bytearray(original); value[offset] ^= 1; path.write_bytes(value)
                with self.subTest(name=name), self.assertRaises(ValueError): expiry.verify(stdout, root / "runtime")
                path.write_bytes(original)

    def test_no_expiry_or_expired_successor_or_relabelled_windows_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); stdout = fixture(root / "runtime")
            path = root / "runtime/tcp-applied/expiry-observations"; original = path.read_bytes()
            points = [("prepared",110,1000,5),("expired",150,41000,5)]
            count = 5
            for name, delta in zip(expiry.CALLS,[0,0,2,0,0,0,0],strict=True):
                points.append((name,150,41000,count));count += delta;points.append((name,150,41000,count))
            changes = [(1,("expired",149,40000,4)), (1,("expired",300,191000,4)),
                       (0,("prepared",150,41000,4)),(1,("expired",150,1000,4)),
                       (2,(expiry.CALLS[0],150,41000,6)),(7,(expiry.CALLS[2],150,41000,5)),
                       (15,(expiry.CALLS[-1],150,41000,8))]
            for index, replacement in changes:
                values = points.copy();values[index] = replacement;path.write_bytes(encode(values,applied=True))
                with self.subTest(index=index,replacement=replacement), self.assertRaises(ValueError):
                    expiry.verify(stdout,root / "runtime")
            for changed in (original + b"x", original[:-1], original[:40] + b"\0" + original[41:]):
                path.write_bytes(changed)
                with self.assertRaises(ValueError): expiry.verify(stdout,root / "runtime")

    def test_late_commit_terminal_before_mutation_and_ack_reordering_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); stdout = fixture(root / "runtime")
            path = root / "runtime/tcp-applied/expiry-witness-transcript"; original = path.read_bytes()
            rows = [original[n:n+RECORD_BYTES] for n in range(0,len(original),RECORD_BYTES)]
            for left,right in ((2,3),(2,4),(4,5)):
                changed = rows.copy();changed[left],changed[right] = changed[right],changed[left]
                value = b"".join(changed);path.write_bytes(value)
                (path.parent / "expiry-tcp-transcript").write_bytes(value)
                with self.subTest(left=left,right=right), self.assertRaises(ValueError): expiry.verify(stdout,root / "runtime")

    def test_failed_summary_private_extra_missing_file_and_tls_fallback_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); stdout = fixture(root / "runtime")
            for changed in (stdout+stdout, stdout.replace(b"0 failed",b"1 failed"), stdout.replace(b"0 ignored",b"1 ignored"),
                            stdout.replace(b"10 filtered",b"5 filtered"),stdout.replace(b"observed=150",b"observed=149")):
                self.assertNotEqual(changed, stdout)
                with self.assertRaises(ValueError): expiry.verify(changed,root / "runtime")
            folder = root / "runtime/tls-applied"
            extra = folder / "wrap.key";extra.write_bytes(b"private")
            with self.assertRaises(ValueError): expiry.verify(stdout,root / "runtime")
            extra.unlink();path = folder / "expiry-tcp-transcript";path.write_bytes(b"plaintext fallback")
            with self.assertRaises(ValueError): expiry.verify(stdout,root / "runtime")
            path.unlink()
            with self.assertRaises(ValueError): expiry.verify(stdout,root / "runtime")

    def test_delivered_commit_missing_cut_or_unqualified_kill_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); stdout = fixture(root / "runtime")
            for carrier in ("tcp", "tls"):
                folder = root / "runtime" / (carrier + "-applied")
                path = folder / "expiry-witness-transcript"; original = path.read_bytes()
                changed = bytearray(original); changed[3 * RECORD_BYTES] = 1; path.write_bytes(changed)
                if carrier == "tcp": (folder / "expiry-tcp-transcript").write_bytes(changed)
                with self.assertRaises(ValueError): expiry.verify(stdout,root / "runtime")
                path.write_bytes(original)
                if carrier == "tcp": (folder / "expiry-tcp-transcript").write_bytes(original)
                path = folder / "expiry-commit-cut-observations"; original = path.read_bytes()
                for value in (b"", original[:-1], original + b"x", original[:9] + b"\0" + original[10:],
                              original[:10] + b"\2" + original[11:], original[:12] + u64(151) + original[20:],
                              original[:20] + u64(0 if carrier == "tls" else 1)):
                    path.write_bytes(value)
                    with self.subTest(carrier=carrier,value=value), self.assertRaises(ValueError):
                        expiry.verify(stdout,root / "runtime")
                path.write_bytes(original)


if __name__ == "__main__": unittest.main()
