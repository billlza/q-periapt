"""Synthetic parser controls; real signatures and execution are separate gates."""
from pathlib import Path
import tempfile
import unittest

import continuity_c_enrollment as enrollment
from continuity_c_witness import commit
from test_continuity_enrollment import fixture as native_fixture, wire, u64

STDOUT = ("C_ENROLLMENT_COMPLETE original_identity=true lease_retained=true original_session=true roster_refresh=true delivery_exact=true\n"
          "test " + enrollment.TEST + " ... ok\n"
          "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out;\n").encode()


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
            + "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out;\n").encode()


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


if __name__ == "__main__": unittest.main()
