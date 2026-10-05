"""Synthetic parser controls; real signatures and foreign execution are separate."""
from pathlib import Path
import shutil
import tempfile
import unittest

import continuity_witnessed_renewal as renewal
from continuity_c_witness import commit
from test_continuity_enrollment import u64, wire


def fixture(directory, *, policy_validity=(100, 400)):
    directory.mkdir()
    for ordinal, case in enumerate(renewal.CASES, 1):
        folder = directory / case; folder.mkdir()
        closed, tls = case.endswith("closed"), case.startswith("tls")
        key = b"d" * 1952 + b"\x02" + b"k" * 32
        root = b"a" * 1952 + b"\x03" + b"r" * 32
        policy_root = b"p" * 1952 + b"\x02" + b"s" * 32
        witness = b"w" * 1952 + b"\x03" + b"t" * 32
        family = commit(b"Q-PERIAPT-CONTINUITY-POLICY-AUTHORITY-CANDIDATE/v1", policy_root)
        account = commit(b"Q-PERIAPT-CONTINUITY-ACCOUNT-CANDIDATE/v1", root)
        instance, journal, signer, operation = (bytes([ordinal + n]) * 32 for n in (1, 10, 20, 30))
        authority = commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-AUTHORITY/v1", instance + witness)
        device, generation, interval = b"i" * 16, u64(1), u64(100) + u64(200)
        metadata = account + device + generation + interval + family
        request = wire(b"QPENRQ01" + signer + metadata + key)
        old = b"QPCERT01" + metadata + key
        new = old[:72] + u64(300) + old[80:]
        old_id = commit(b"Q-PERIAPT-CONTINUITY-CREDENTIAL-CANDIDATE/v1", old)
        new_id = commit(b"Q-PERIAPT-CONTINUITY-CREDENTIAL-CANDIDATE/v1", new)
        old_roster = b"QPROST01" + account + u64(1) + interval + b"\0\1" + device + generation + old_id
        new_roster = b"QPROST01" + account + u64(2) + u64(100) + u64(300) + b"\0\1" + device + generation + new_id
        old_checkpoint = u64(1) + commit(b"Q-PERIAPT-CONTINUITY-ROSTER-CANDIDATE/v1", old_roster)
        next_checkpoint = u64(2) + commit(b"Q-PERIAPT-CONTINUITY-ROSTER-CANDIDATE/v1", new_roster)
        suite = commit(b"Q-PERIAPT-CONTINUITY-BOOTSTRAP-SUITE-CANDIDATE/v1",
                       b"ML-KEM-768+X25519/ContextBound;ML-DSA-65+P-256/SHA-256;HKDF-SHA-256;HMAC-SHA-256")
        policy = (b"QPSESP03" + family + u64(1) + u64(policy_validity[0]) + u64(policy_validity[1]) + suite
                  + b"z" * 32 + (1).to_bytes(4, "big") + b"q" * 32 + b"\1\1" + authority + b"\0\1")
        policy_id = commit(b"Q-PERIAPT-CONTINUITY-SESSION-POLICY-CANDIDATE/v1", policy)
        statement = (b"QPCRNW01" + operation + account + device + generation + family
                     + commit(b"Q-PERIAPT-CREDENTIAL-RENEWAL-KEY/v1", key) + old_id * 2 + new_id
                     + policy_id + old_checkpoint + next_checkpoint + b"\1")
        statement_id = commit(b"Q-PERIAPT-CREDENTIAL-RENEWAL-STATEMENT/v1", statement)
        owner = commit(b"Q-PERIAPT-CONTINUITY-BOOTSTRAP-CANDIDATE/v1/storage-owner", account + device + generation + old_id)
        subject = journal + owner + policy_id
        initial, target = u64(1) + u64(1) + b"g" * 32, u64(1) + u64(2) + b"h" * 32
        proposal = b"QPCRNP01" + authority + subject + operation + statement_id + initial + target
        binding = commit(b"Q-PERIAPT-ANCHOR-CREDENTIAL-PROPOSAL/v1", proposal)
        grant = b"QPRNB001" + b"".join(len(v).to_bytes(2, "big") + v for v in
            (wire(statement), wire(old), wire(old), wire(new), wire(old_roster), wire(new_roster)))
        files = {"enrollment-root":root, "enrollment-intent":device + generation + family + interval,
            "enrollment-request":request, "enrollment-reopened-request":request, "grant-certificate":wire(old),
            "grant-roster":wire(old_roster), "trusted-account":account, "trusted-roster-version":u64(1),
            "trusted-roster-digest":old_checkpoint[8:], "family":family, "policy-root":policy_root,
            "policy-version":u64(1), "policy-digest":policy_id, "protocol-policy":wire(policy),
            "witness-id":instance, "witness-public":witness, "witness-subject":subject,
            "enrollment-genesis-subject":subject, "enrollment-genesis-digest":initial[16:],
            "credential-renewal":grant, "credential-operation":operation, "credential-statement":statement_id,
            "renewal-version":u64(2), "renewal-digest":next_checkpoint[8:], "credential-proposal":proposal,
            "credential-proposal-original":proposal, "renewal-image-digests":initial[16:] * 2 + (initial[16:] if closed else target[16:])}
        def status(phase):
            return (f"credential-phase:{phase}\n{operation.hex()}\n{statement_id.hex()}\ncredential-head:{0 if phase == 1 else 2}\n"
                    f"{bytes(32).hex() if phase == 1 else next_checkpoint[8:].hex()}\ncredential-observed:0\n").encode()
        outputs = {"key":b"enrollment-key\n", "renewal-stage":status(1), "pending-no-sdk-history":status(1),
            "pending-no-sdk-commit":b"credential-witness-commit-refused:702\n", "runtime-unavailable":b"enrollment-activation-refused:702\n"}
        for label, phase in (("create",1),("request",2),("request-retry",2),("accept",3),("storage",3),
                             ("renewal-original-status",5),("renewal-final-status",5)):
            outputs[label] = f"enrollment-phase:{phase}\n{signer.hex()}\n{(bytes(32) if phase < 3 else journal).hex()}\n".encode()
        for label in ("renewal-original-active", "renewal-current-activation"):
            outputs[label] = b"enrollment-active\n" + (b"v" * 32).hex().encode() + b"\n"
        for label in ("renewal-prepare", "renewal-prepare-reopened"): outputs[label] = b"credential-witness-prepared\n"
        for label in ("renewal-terminal", "history", "retry"): outputs[label] = status(4 if closed else 2)
        for label, value in outputs.items():
            files[f"witness-enrollment-{label}.stdout"] = value
            files[f"witness-enrollment-{label}.stderr"] = b""
        old_authority, new_authority = (commit(b"Q-PERIAPT-CONTINUITY-AUTHORITY-CANDIDATE/v1", account + point + family)
                                        for point in (old_checkpoint, next_checkpoint))
        commit_id = commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-COMMAND/v1", authority + subject + b"\5" + binding + bytes(64))
        records = []
        terminal_head = initial if closed else target
        def append(op, outcome, observed):
            command = commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-COMMAND/v1", authority + subject + op)
            rq = b"QPANRQ01" + authority + subject + command + bytes([len(records) + 1]) * 32 + op
            last = b"\1" + commit_id if observed == target else bytes(33)
            rs = (b"QPANRS01" + authority + subject + commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-REQUEST/v1", rq)
                  + command + bytes([outcome]) + observed + last)
            records.append(b"\1" + wire(rq) + wire(rs))
        append(b"\1" + bytes(96), 1, initial)
        append(b"\4" + old_authority + bytes(64), 5, initial)
        for _ in range(2): append(b"\6" + binding + bytes(64), 7, initial)
        append(bytes([7 if closed else 5]) + binding + bytes(64), 9 if closed else 8, terminal_head)
        append(b"\6" + binding + bytes(64), 9 if closed else 8, terminal_head)
        append(b"\10" + binding + bytes(64), 11, terminal_head)
        append(b"\4" + (old_authority if closed else new_authority) + bytes(64), 5, terminal_head)
        files["renewal-witness-transcript"] = b"" if tls else b"".join(records)
        files["renewal-tls-transcript"] = b"".join(records) if tls else b""
        files["renewal-carrier-observations"] = b"".join(u64(v) for v in
            ([0,2,4,8,0,0,0,0] if tls else [0,0,0,0,0,2,4,8]))
        assert set(files) == renewal.FILES
        for name, value in files.items(): (folder / name).write_bytes(value)
    lines = [f"C_WITNESSED_RENEWAL carrier={case.split('-')[0]} terminal={case.split('-')[1]} "
             "original_proposal=true original_owner=true no_sdk_historical=true current_activation=true" for case in renewal.CASES]
    return ("\n".join(lines) + "\ntest " + renewal.TEST + " ... ok\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out;\n").encode()


class WitnessedRenewalEvidenceTests(unittest.TestCase):
    def test_complete_public_binding_exports_all_cases_and_no_private_material(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); stdout = fixture(root / "runtime")
            result = renewal.export(stdout, root / "runtime", root / "public")
            self.assertEqual(len(result["public_readbacks"]), 272)
            self.assertFalse(result["release_claim_eligible"])
            self.assertEqual(result, renewal.verify(stdout, root / "public"))
            serial = stdout.replace(b"test " + renewal.TEST.encode() + b" ... ok\n", b"")
            serial = b"test " + renewal.TEST.encode() + b" ... " + serial.split(b"test result:")[0] + b"ok\n" + stdout[stdout.index(b"test result:"):]
            self.assertEqual(renewal.verify(serial, root / "runtime"), result)

    def test_individually_corrupted_scope_history_and_dispatch_evidence_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); stdout = fixture(root / "runtime")
            changes = {"credential-operation":0, "credential-statement":0, "policy-digest":0,
                "enrollment-root":0, "policy-root":0, "witness-public":0, "credential-proposal":72,
                "credential-proposal-original":295, "renewal-image-digests":95, "credential-renewal":12,
                "renewal-witness-transcript":1+168, "renewal-carrier-observations":55}
            for name, offset in changes.items():
                path = root / "runtime/tcp-applied" / name; original = path.read_bytes()
                changed = bytearray(original); changed[offset] ^= 1; path.write_bytes(changed)
                with self.subTest(name=name), self.assertRaises(ValueError): renewal.verify(stdout, root / "runtime")
                path.write_bytes(original)
            path = root / "runtime/tls-closed/renewal-witness-transcript"; path.write_bytes(b"unexpected plaintext")
            with self.assertRaises(ValueError): renewal.verify(stdout, root / "runtime")

    def test_missing_cases_failed_outputs_and_extra_private_file_cannot_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); stdout = fixture(root / "runtime")
            for changed in (stdout.replace(b"1 passed", b"0 passed"), stdout.replace(b"0 ignored", b"1 ignored"),
                            stdout.replace(b"terminal=closed", b"terminal=applied"), stdout + stdout,
                            stdout + b"test result: FAILED. 0 passed; 1 failed;\n"):
                with self.assertRaises(ValueError): renewal.verify(changed, root / "runtime")
            extra = root / "runtime/tcp-applied/wrap.key"; extra.write_bytes(b"must not export")
            with self.assertRaises(ValueError): renewal.verify(stdout, root / "runtime")
            extra.unlink(); shutil.rmtree(root / "runtime/tls-closed")
            with self.assertRaises(ValueError): renewal.verify(stdout, root / "runtime")

    def test_terminal_status_cannot_precede_the_actual_commit_or_close(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); stdout = fixture(root / "runtime")
            for case in ("tcp-applied", "tcp-closed"):
                path = root / "runtime" / case / "renewal-witness-transcript"
                original = path.read_bytes(); width = 7334
                rows = [original[n:n + width] for n in range(0, len(original), width)]
                rows[4], rows[5] = rows[5], rows[4]
                path.write_bytes(b"".join(rows))
                with self.assertRaisesRegex(ValueError, "precedes its unique mutation"):
                    renewal.verify(stdout, root / "runtime")
                path.write_bytes(original)

    def test_tls_counters_cannot_replace_signed_operations_or_relabel_the_no_sdk_interval(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); stdout = fixture(root / "runtime")
            path = root / "runtime/tls-applied/renewal-carrier-observations"
            original = path.read_bytes()
            for counters in ([0,14,1014,1015,0,0,0,0], [0,4,6,8,0,0,0,0]):
                path.write_bytes(b"".join(u64(v) for v in counters))
                with self.assertRaises(ValueError): renewal.verify(stdout, root / "runtime")
            path.write_bytes(original)
            trace = root / "runtime/tls-applied/renewal-tls-transcript"
            trace.write_bytes(trace.read_bytes()[:-1])
            with self.assertRaises(ValueError): renewal.verify(stdout, root / "runtime")

    def test_grant_container_refuses_missing_oversized_and_trailing_fields(self):
        good = b"QPRNB001" + (b"\0\1x" * 6)
        self.assertEqual(renewal.grant_fields(good), [b"x"] * 6)
        for wrong in (good[:-1], good + b"x", b"badtag00" + good[8:], b"QPRNB001\0\0" + good[11:],
                      b"QPRNB001\x20\x01" + b"x" * 8193 + good[11:]):
            with self.assertRaises(ValueError): renewal.grant_fields(wrong)
