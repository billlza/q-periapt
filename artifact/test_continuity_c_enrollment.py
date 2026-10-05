"""Synthetic parser controls; real signatures and execution are separate gates."""
from pathlib import Path
import json
import tempfile
import unittest

import continuity_c_enrollment as enrollment
from continuity_c_witness import commit
from test_continuity_enrollment import fixture as native_fixture, wire, u64

STDOUT = ("C_ENROLLMENT_COMPLETE original_identity=true lease_retained=true original_session=true roster_refresh=true delivery_exact=true\n"
          "test " + enrollment.TEST + " ... ok\n"
          "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out;\n").encode()


def fixture(root):
    native_fixture(root / "native")
    original = root / "native/initiator"
    client, server = root / "enrolled", root / "responder"
    client.mkdir(); server.mkdir()
    read = lambda name: (original / name).read_bytes()
    signing, journal = read("signer-id"), read("accepted-journal")
    files = {"enrollment-intent": read("local-device") + read("local-generation") + read("family") + read("enrollment-validity"),
             "enrollment-lease-observation": u64(200) + u64(100), "family": read("family"),
             "enrollment-held": b"1", "release-enrollment": b"1",
             "enrollment-genesis-subject": bytes(96), "enrollment-genesis-digest": bytes(32)}
    for destination, source in {"enrollment-root": "local-root", "trusted-account": "local-account",
                               "enrollment-request": "request", "enrollment-reopened-request": "reopened-request",
                               "grant-certificate": "local-certificate", "grant-roster": "local-roster",
                               "trusted-roster-version": "local-roster-version", "trusted-roster-digest": "local-roster-digest"}.items():
        files[destination] = read(source)
    old = read("local-roster")
    body = old[4:4 + int.from_bytes(old[:4], "big")]
    renewal = body[:40] + u64(2) + body[48:]
    files.update({"renewal-version": u64(2), "renewal-roster": wire(renewal),
                  "renewal-digest": commit(b"Q-PERIAPT-CONTINUITY-ROSTER-CANDIDATE/v1", renewal)})
    statuses = {"create": 1, "request": 2, "request-retry": 2, "after-reject": 2,
                "accept": 3, "storage": 3, "active": 5, "refresh": 6, "final-status": 5, "after-missing-registration": 5}
    commands = {label: f"enrollment-phase:{phase}\n".encode() + signing.hex().encode() + b"\n"
                + (bytes(32) if phase <= 2 else journal).hex().encode() + b"\n"
                for label, phase in statuses.items()}
    session, message = b"s" * 32, b"m" * 32
    commands.update(key=b"enrollment-key\n", reject=b"enrollment-signature-refused\n", cancel=b"enrollment-cancelled\n",
                    held=b"enrollment-active\n" + b"b" * 64 + b"\n", connect=session.hex().encode() + b"\n",
                    next=message.hex().encode() + b"\n", uncertain=b"delivery-unknown-committed\n", retry=b"consumed\n")
    commands["activate-current"] = commands["held"]
    commands.update({"missing-registration": b"enrollment-open-refused:204\n", "creation-refused": b"enrollment-open-refused:211\n",
                     "key-conflict": b"enrollment-key-refused:211\n"})
    for label, value in commands.items():
        files["enrollment-" + label + ".stdout"] = value
        files["enrollment-" + label + ".stderr"] = b""
    for name, data in files.items(): (client / name).write_bytes(data)
    (server / "session").write_bytes(session)
    (server / ("application-" + message.hex())).write_bytes(session + message + enrollment.PAYLOAD)


def witness_fixture(root, carrier):
    """Public structural controls with synthetic signatures, never execution proof."""
    fixture(root)
    source = root / "enrolled"
    folder = root / "enrolled-witness"; folder.mkdir()
    for path in source.iterdir():
        if path.suffix not in (".stdout", ".stderr"):
            (folder / path.name).write_bytes(path.read_bytes())
    def command(label, data):
        (folder / ("witness-enrollment-" + label + ".stdout")).write_bytes(data)
        (folder / ("witness-enrollment-" + label + ".stderr")).write_bytes(b"")
    for label in ("key", "create", "request", "request-retry", "accept", "storage", "active", "refresh"):
        command(label, (source / ("enrollment-" + label + ".stdout")).read_bytes())
    active = (source / "enrollment-active.stdout").read_bytes()
    activated = (source / "enrollment-held.stdout").read_bytes()
    for label in ("after-missing-required", "after-denial", "renewed-status", "cancelled-status"):
        command(label, active)
    for label in ("activate", "renewed", "cancelled-reopen"): command(label, activated)
    command("missing-required", b"enrollment-activation-refused:216\n")
    command("denied", b"enrollment-activation-refused:218\n")
    command("cancel-activate", b"enrollment-activation-cancelled\n")
    journal = bytes.fromhex(active.splitlines()[2].decode())
    subject, genesis = journal + b"c" * 32 + b"p" * 32, b"g" * 32
    identity, key = b"i" * 32, b"k" * 1952 + b"\x02" + b"l" * 32
    files = {"enrollment-required-refusal": b"authenticated witness is required",
             "enrollment-authority-refusal": b"witness enrollment authority is not current or valid",
             "witness-subject": subject, "enrollment-genesis-subject": subject,
             "enrollment-genesis-digest": genesis, "witness-id": identity, "witness-public": key,
             "enrollment-cancel-query": b"1", "enrollment-tls-admissions": u64(31),
             "enrollment-tls-denial-admissions": u64(11) + u64(22),
             "witness-tls-peer": b"synthetic server certificate", "witness-tls-cert": b"synthetic client certificate",
             "witness-tls-name": b"localhost"}
    if carrier == "signed-tcp":
        authority = commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-AUTHORITY/v1", identity + key)
        def roster_authority(version, name):
            return commit(b"Q-PERIAPT-CONTINUITY-AUTHORITY-CANDIDATE/v1",
                (folder / "trusted-account").read_bytes() + u64(version)
                + (folder / name).read_bytes() + (folder / "family").read_bytes())
        previous = roster_authority(1, "trusted-roster-digest")
        current = roster_authority(2, "renewal-digest")
        initial, target = u64(1) * 2 + genesis, u64(1) + u64(2) + b"h" * 32
        rows = []
        def append(operation, outcome, head, last=None, delivered=1):
            command_id = commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-COMMAND/v1", authority + subject + operation)
            request = b"QPANRQ01" + authority + subject + command_id + bytes([len(rows) + 1]) * 32 + operation
            reply = (b"QPANRS01" + authority + subject + commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-REQUEST/v1", request)
                     + command_id + bytes([outcome]) + head + bytes([bool(last)]) + (last or bytes(32)))
            rows.append(bytes([delivered]) + wire(request) + wire(reply))
            return command_id
        query = b"\x01" + bytes(96)
        append(query, 1, initial)
        append(b"\x04" + previous + bytes(64), 5, initial)
        advance = b"\x02" + initial + target
        last = commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-COMMAND/v1", authority + subject + advance)
        append(advance, 2, target, last)
        append(b"\x04" + current + bytes(64), 6, target, last)
        append(b"\x04" + current + bytes(64), 5, target, last)
        append(query, 1, target, last, delivered=0)
        files["witness-cancelled-prefix"] = (3659).to_bytes(4, "big") + rows[-1][3675:5475]
        append(b"\x04" + current + bytes(64), 5, target, last)
        files["enrollment-witness-transcript"] = b"".join(rows)
    for name, value in files.items(): (folder / name).write_bytes(value)
    return ("C_ENROLLMENT_WITNESS_COMPLETE carrier=" + carrier + " journal=" + journal.hex()
            + " next_account=" + activated.splitlines()[1].decode() + "\n"
            + "test " + enrollment.WITNESS_TESTS[carrier] + " ... ok\n"
            + "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out;\n").encode()


class CEnrollmentEvidenceTests(unittest.TestCase):
    def test_public_closure_exports_no_private_material(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); fixture(root)
            (root / "enrolled/wrap.key").write_bytes(b"must not export")
            result = enrollment.export(STDOUT, root, root / "exported")
            self.assertEqual(len(result["public_readbacks"]), 64)
            self.assertEqual(enrollment.verify_execution(STDOUT, root / "exported"), result)
            self.assertFalse((root / "exported/enrolled/wrap.key").exists())

    def test_each_public_readback_is_mandatory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); fixture(root)
            result = enrollment.verify_execution(STDOUT, root)
            for name in result["public_readbacks"]:
                path = root / name; original = path.read_bytes(); path.unlink()
                with self.subTest(name=name), self.assertRaises(ValueError):
                    enrollment.verify_execution(STDOUT, root)
                path.write_bytes(original)

    def test_wrong_original_identity_and_false_success_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); fixture(root)
            paths = ["enrolled/enrollment-reopened-request", "enrolled/grant-certificate", "enrolled/enrollment-root",
                     "enrolled/enrollment-refresh.stdout", "enrolled/enrollment-final-status.stdout",
                     "enrolled/renewal-roster", "enrolled/renewal-digest", "enrolled/family", "responder/session"]
            for name in paths:
                path = root / name; original = path.read_bytes()
                changed = bytearray(original); changed[0] ^= 1; path.write_bytes(changed)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    enrollment.verify_execution(STDOUT, root)
                path.write_bytes(original)
            for label, bad in [("uncertain.stdout", b"consumed\n"), ("retry.stderr", b"unexpected failure\n"),
                               ("activate-current.stdout", b"enrollment-active\n" + b"c" * 64 + b"\n")]:
                path = root / "enrolled" / ("enrollment-" + label); original = path.read_bytes(); path.write_bytes(bad)
                with self.subTest(label=label), self.assertRaises(ValueError):
                    enrollment.verify_execution(STDOUT, root)
                path.write_bytes(original)
            with self.assertRaises(ValueError):
                enrollment.verify_execution(STDOUT.replace(b"1 passed", b"0 passed"), root)
            (root / "responder/application-unexpected").write_bytes(b"second effect")
            with self.assertRaises(ValueError): enrollment.verify_execution(STDOUT, root)

    def test_lease_contender_must_be_a_different_process(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); fixture(root)
            (root / "enrolled/enrollment-lease-observation").write_bytes(u64(100) * 2)
            with self.assertRaises(ValueError): enrollment.verify_execution(STDOUT, root)


class CWitnessEnrollmentEvidenceTests(unittest.TestCase):
    def test_each_carrier_requires_its_public_closure(self):
        for carrier, count in (("signed-tcp", 59), ("mutual-tls", 55)):
            with self.subTest(carrier=carrier), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); stdout = witness_fixture(root, carrier)
                result = enrollment.export_witness(stdout, root, root / "exported", carrier)
                self.assertEqual(len(result["public_readbacks"]), count)
                self.assertEqual(enrollment.verify_witness(stdout, root / "exported", carrier), result)
                self.assertFalse((root / "exported/enrolled-witness/enrollment-lease-observation").exists())
                for name in result["public_readbacks"]:
                    path = root / name; saved = path.read_bytes(); path.unlink()
                    with self.subTest(name=name), self.assertRaises(ValueError):
                        enrollment.verify_witness(stdout, root, carrier)
                    path.write_bytes(saved)

    def test_contradictory_summary_refusal_or_scope_is_not_success(self):
        for carrier in enrollment.WITNESS_TESTS:
            with self.subTest(carrier=carrier), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); stdout = witness_fixture(root, carrier)
                first, rest = stdout.split(b"\n", 1)
                variants = [rest, first + b"\n" + stdout, stdout.replace(b"journal=", b"journal=00"),
                            stdout.replace(b"next_account=", b"next_account=ff"), stdout.replace(carrier.encode(), b"other"),
                            stdout.replace(b"1 passed", b"0 passed")]
                for field in (b"journal=", b"next_account="):
                    original = first.split(field)[1][:64]
                    variants.append(stdout.replace(field + original, field + b"f" * 64))
                for output in variants:
                    with self.subTest(summary=output[:60]), self.assertRaises(ValueError):
                        enrollment.verify_witness(output, root, carrier)
                changes = {"witness-enrollment-denied.stdout": b"enrollment-active\n" + b"b" * 64 + b"\n",
                           "enrollment-authority-refusal": b"transport unavailable",
                           "witness-enrollment-renewed.stdout": b"enrollment-active\n" + b"c" * 64 + b"\n",
                           "witness-enrollment-missing-required.stdout": b"enrollment-activation-refused:218\n"}
                if carrier == "signed-tcp":
                    changes.update({"enrollment-genesis-digest": b"z" * 32, "witness-cancelled-prefix": bytes(1804),
                                    "witness-id": b"z" * 32, "enrollment-witness-transcript": b""})
                else:
                    changes.update({"enrollment-tls-denial-admissions": u64(22) + u64(11),
                                    "enrollment-tls-admissions": u64(12), "witness-tls-name": b"another-host"})
                for name, value in changes.items():
                    path = root / "enrolled-witness" / name; saved = path.read_bytes(); path.write_bytes(value)
                    with self.subTest(name=name), self.assertRaises(ValueError):
                        enrollment.verify_witness(stdout, root, carrier)
                    path.write_bytes(saved)


class RenewalExecutionTests(unittest.TestCase):
    def test_missing_cases_and_impossible_expiry_cannot_qualify(self):
        output = ("C_CREDENTIAL_RENEWAL original_registration=true same_signer=true same_journal=true pending_readback=true committed_readback=true expired_committed_preserved=true expired_owner_refused=true admitted_signature_failure_closed_owner=true\n"
                  "C_PEER_CREDENTIAL_RENEWAL original_tls_session=true actual_expiry=true wrong_pin_and_operation_refused=true cached_child_fenced=true persisted_grant=true exact_outbox_readback=true\n"
                  "C_CREDENTIAL_EXPIRY actual_wall_clock=true target_until=150 observed_at=151 no_policy_status=true same_registration=true separate_root_operation=true\n"
                  "C_POLICY_CONTINUATION local_only=true joint_stage_readback=true joint_commit_readback=true current_owner=true same_signer=true same_wrapping_key=true same_journal=true credential_successor_carries_t1=true original_policy_inputs_unchanged=true\n"
                  "C_HISTORICAL_POLICY_RECOVERY actual_P1_expiry=true expired_current_refused=true SDK_and_TLS_unavailable=true committed_preserved=true uncommitted_remains_pending=true same_original_owners=true\n"
                  "C_SECOND_POLICY_ADOPTION explicit_nonnull_t1=true approved_wrong_predecessor_refused=true g2_t2_committed=true same_original_owner=true current_activation=true immutable_p0=true retained_p1=true independent_p2=true\n"
                  + "".join("test " + name + " ... ok\n" for name in sorted(enrollment.RENEWAL_TESTS))
                  + "test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out;\n").encode()
        self.assertTrue(enrollment.verify_renewal_execution(output)["completed"])
        first = sorted(enrollment.RENEWAL_TESTS)[0].encode()
        for invalid in (output.replace(first, b"other_case"),
                        output + b"test " + first + b" ... ok\n",
                        output + b"test another_case ... FAILED\n",
                        output + b"test another_case ... FAILED with details\n",
                        output + b"test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 4 filtered out;\n",
                        output.replace(b"0 ignored", b"1 ignored"),
                        output.replace(b"observed_at=151", b"observed_at=149"),
                        output.replace(b"expired_committed_preserved=true", b"expired_committed_preserved=false"),
                        output.replace(b"credential_successor_carries_t1=true", b"credential_successor_carries_t1=false"),
                        output.replace(b"uncommitted_remains_pending=true", b"uncommitted_remains_pending=false"),
                        output.replace(b"approved_wrong_predecessor_refused=true", b"approved_wrong_predecessor_refused=false"),
                        output.replace(b"exact_outbox_readback=true", b"exact_outbox_readback=false")):
            with self.subTest(output=invalid), self.assertRaises(ValueError):
                enrollment.verify_renewal_execution(invalid)


class ForeignEnrollmentEvidenceTests(unittest.TestCase):
    def test_language_cannot_be_inferred_from_the_common_native_test_name(self):
        for carrier in ("local", "signed-tcp", "mutual-tls"):
            for language, marker in (("Swift", b"old-registration-released original-device-live\n"),
                                     ("Kotlin", b"old-registration-collected original-device-live\n")):
                with self.subTest(carrier=carrier, language=language), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    if carrier == "local":
                        fixture(root); stdout = STDOUT; prefix = "enrolled"
                        verify = lambda path, selected: enrollment.verify_execution(stdout, path, language=selected)
                    else:
                        stdout = witness_fixture(root, carrier); prefix = "enrolled-witness"
                        verify = lambda path, selected: enrollment.verify_witness(stdout, path, carrier, language=selected)
                    verify(root, "C")
                    with self.assertRaises(ValueError): verify(root, language)
                    path = root / prefix / (language.lower() + "-enrollment-transfer")
                    path.write_bytes(marker)
                    result = verify(root, language)
                    self.assertEqual(result["language"], language)
                    self.assertTrue(result["original_owner_transfer"])
                    self.assertIn(language, result["scope"])
                    self.assertIn(str(path.relative_to(root)), result["public_readbacks"])
                    if carrier == "local":
                        exported = enrollment.export(stdout, root, root / "export", language=language)
                    else:
                        exported = enrollment.export_witness(stdout, root, root / "export", carrier, language=language)
                    self.assertEqual(exported, result)
                    self.assertEqual(verify(root / "export", language), result)
                    path.write_bytes(b"device-created\n")
                    with self.assertRaises(ValueError): verify(root, language)
                    with self.assertRaises(ValueError): verify(root, "unknown")

    def test_missing_or_changed_lifecycle_cohort_refuses_before_foreign_execution(self):
        import hashlib
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); outside = root / "outside"; output = root / "output"
            output.mkdir(); build = outside / "build/debug"; (build / "deps").mkdir(parents=True)
            receipts = {}
            for target in ("enrollment", "enrollment_witness"):
                binary = build / "deps" / (target + "-exact"); binary.write_bytes(target.encode())
                receipts[target] = dict(sha256=hashlib.sha256(binary.read_bytes()).hexdigest(), bytes=binary.stat().st_size)
                message = dict(reason="compiler-artifact", target=dict(name=target, kind=["test"],
                    src_path=str(outside / "c-consumer/tests" / (target + ".rs"))), executable=str(binary))
                (output / ("c-" + target.replace("_", "-") + "-build-debug.stdout")).write_text(json.dumps(message) + "\n")
            native = dict(enrollment=dict(binary=receipts["enrollment"]), enrollment_witness={
                carrier:dict(binary=receipts["enrollment_witness"]) for carrier in ("signed-tcp", "mutual-tls")},
                witnessed_credential_renewal=dict(binary=receipts["enrollment_witness"]))
            def forbidden(*args, **kwargs): self.fail("unqualified foreign harness executed")
            with self.assertRaisesRegex(ValueError, "lacks witnessed_policy_expiry"):
                enrollment.qualify_foreign(outside, output, "debug", {}, native, forbidden, language="Swift")
            native["witnessed_policy_expiry"] = dict(binary=receipts["enrollment"])
            with self.assertRaisesRegex(ValueError, "C-qualified original harness"):
                enrollment.qualify_foreign(outside, output, "debug", {}, native, forbidden, language="Swift")
            native["witnessed_policy_expiry"] = dict(binary=receipts["enrollment_witness"])
            with self.assertRaisesRegex(ValueError, "lacks witnessed_cancellation"):
                enrollment.qualify_foreign(outside, output, "debug", {}, native, forbidden, language="Swift")
            native["witnessed_cancellation"] = dict(binary=receipts["enrollment"])
            with self.assertRaisesRegex(ValueError, "C-qualified original harness"):
                enrollment.qualify_foreign(outside, output, "debug", {}, native, forbidden, language="Swift")
            native["witnessed_cancellation"] = dict(binary=receipts["enrollment_witness"])
            with self.assertRaisesRegex(ValueError, "lacks witnessed_commit_error"):
                enrollment.qualify_foreign(outside, output, "debug", {}, native, forbidden, language="Swift")
            native["witnessed_commit_error"] = dict(binary=receipts["enrollment"])
            with self.assertRaisesRegex(ValueError, "C-qualified original harness"):
                enrollment.qualify_foreign(outside, output, "debug", {}, native, forbidden, language="Swift")
            native["witnessed_commit_error"] = dict(binary=receipts["enrollment_witness"])
            with self.assertRaisesRegex(ValueError, "lacks witnessed_policy_continuation"):
                enrollment.qualify_foreign(outside, output, "debug", {}, native, forbidden, language="Swift")
            native["witnessed_policy_continuation"] = dict(binary=receipts["enrollment"])
            with self.assertRaisesRegex(ValueError, "C-qualified original harness"):
                enrollment.qualify_foreign(outside, output, "debug", {}, native, forbidden, language="Swift")

    def test_policy_witness_requires_both_complete_carriers(self):
        lines = ["C_WITNESSED_POLICY_CONTINUATION carrier=" + carrier
            + " original_329_byte_proposal=true independent_G_T_approval=true committed_readback=true original_owner=true current_activation=true credential_successor_carries_t1=true"
            for carrier in ("tcp", "tls")]
        output = ("\n".join(lines) + "\ntest " + enrollment.POLICY_WITNESS_TEST + " ... ok\n"
            + "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out;\n").encode()
        for language in ("C", "Swift", "Kotlin"):
            result = enrollment.verify_policy_witness_execution(output, language=language)
            self.assertEqual(result["language"], language)
            self.assertTrue(result["credential_successor_carries_t1"])
            self.assertFalse(result["release_claim_eligible"])
        variants = [output.replace((line + "\n").encode(), b"") for line in lines]
        variants += [output + (lines[0] + "\n").encode(), output.replace(b"carrier=tls", b"carrier=tcp"),
                     output + b"test another_case ... FAILED\n",
                     output + b"test another_case ... FAILED with details\n",
                     output + b"test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out;\n",
                     output.replace(b"current_activation=true", b"current_activation=false"),
                     output.replace(b" credential_successor_carries_t1=true", b""),
                     output.replace(b"credential_successor_carries_t1=true", b"credential_successor_carries_t1=false"),
                     output.replace(b"0 failed", b"1 failed"), output.replace(b"0 ignored", b"1 ignored"),
                     output.replace(enrollment.POLICY_WITNESS_TEST.encode(), b"another_case")]
        for invalid in variants:
            with self.subTest(output=invalid), self.assertRaises(ValueError):
                enrollment.verify_policy_witness_execution(invalid)

    def test_changed_native_harness_refuses_before_executing_foreign_client(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); outside = root / "outside"; output = root / "output"
            output.mkdir(); build = outside / "build/debug"; (build / "deps").mkdir(parents=True)
            consumer = outside / "c-consumer"
            binary = build / "deps/enrollment-exact"; binary.write_bytes(b"x")
            message = dict(reason="compiler-artifact", target=dict(name="enrollment", kind=["test"],
                src_path=str(consumer / "tests/enrollment.rs")), executable=str(binary))
            (output / "c-enrollment-build-debug.stdout").write_text(json.dumps(message) + "\n")
            def forbidden(*args, **kwargs):
                self.fail("changed harness was executed")
            with self.assertRaisesRegex(ValueError, "harness changed before execution"):
                enrollment.qualify_foreign(outside, output, "debug", {},
                    {"enrollment": {"binary": {"sha256": "0" * 64, "bytes": 1}}}, forbidden, language="Swift")
            for language, collector in (("C", ""), ("Kotlin", ""), ("Swift", "G1"), ("Kotlin", "unknown")):
                with self.subTest(language=language, collector=collector), self.assertRaisesRegex(ValueError, "unqualified"):
                    enrollment.qualify_foreign(outside, output, "debug", {}, {}, forbidden, language=language, collector=collector)


if __name__ == "__main__": unittest.main()
