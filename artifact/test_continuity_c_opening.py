"""Reject altered original-query identity and cancellation readback evidence."""
import json
from pathlib import Path
import tempfile
import unittest

import continuity_c_opening as opening
import continuity_kotlin_consumer as kotlin
from evidence_io import EvidenceIOError


def queries(authority=b'a' * 32):
    operation = b'\1' + bytes(96)
    records = []
    for index, delivered in enumerate((1, 1, 0, 1)):
        subject = (b't' if index == 1 else b's') * 96
        command = opening.commit(b'Q-PERIAPT-CONTINUITY-ANCHOR-COMMAND/v1', authority + subject + operation)
        rq = b'QPANRQ01' + authority + subject + command + bytes([index + 1]) * 32 + operation
        state = (1).to_bytes(8, 'big') * 2 + b'h' * 32 + bytes(33)
        rs = b'QPANRS01' + authority + subject + opening.commit(b'Q-PERIAPT-CONTINUITY-ANCHOR-REQUEST/v1', rq) + command + b'\1' + state
        request = len(rq).to_bytes(4, 'big') + rq + bytes(3373)
        reply = len(rs).to_bytes(4, 'big') + rs + bytes(3373)
        records.append(bytes([delivered]) + request + reply)
    prefix = (3659).to_bytes(4, 'big') + records[2][3675:5475]
    return authority, b''.join(records), prefix


class ConstructorTranscriptTests(unittest.TestCase):
    def test_constructor_language_and_complete_readbacks_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "initiator").mkdir()
            identity, key = b'i' * 32, b'k' * 1985
            authority = opening.commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-AUTHORITY/v1", identity + key)
            _, data, prefix = queries(authority)
            files = {"opening-witness-transcript": data, "initiator/witness-id": identity,
                     "initiator/witness-public": key, "initiator/witness-cancelled-prefix": prefix,
                     "initiator/opening-tcp-held": b"1", "initiator/opening-tls-held": b"1",
                     "initiator/opening-tls-closed": b"1", "initiator/opening-tls-client-hello": b"\x16\x03\x03\x00\x01x"}
            report = {"schema_version": 2, "language": "C", "completed": True,
                      "failed_handles_closed": True, "same_installation_reopened": True,
                      "tcp_socket_closed": True, "tls_socket_closed": True,
                      "tcp_cancel_ms": 12, "tls_cancel_ms": 13, "tcp_exchanges": 4,
                      "pre_cancel_cases": 6, "snapshot_open_cases": 6, "release_claim_eligible": False}
            commands = {}
            for carrier in ("local", "tcp", "tls"):
                for kind, number in (("operational", 1), ("recovery", 2)):
                    commands[f"opening-{carrier}-pre-{kind}"] = f"prepared-pre-cancel:{number}\n"
                    if carrier != "local": commands[f"opening-{carrier}-ready-{kind}"] = f"prepared-open:{number}\n"
            for carrier in ("tcp", "tls"):
                commands[f"opening-{carrier}-reopen"] = "prepared-open:1\n"
                commands[f"opening-{carrier}-cancel"] = f"prepared-cancelled:218:{report[carrier + '_cancel_ms']}\n"
            for label, value in commands.items():
                files[f"initiator/witness-{label}.stdout"] = value.encode()
                files[f"initiator/witness-{label}.stderr"] = b""
            for name, value in files.items(): (root / name).write_bytes(value)
            path = root / "c-opening-public-result.json"
            path.write_text(json.dumps(report))
            stdout = (f"test {opening.TEST} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out;\n").encode()
            opening.verify_execution(stdout, root)
            for language in ("Swift", "Kotlin"):
                with self.subTest(language=language):
                    report["language"] = "C"; path.write_text(json.dumps(report))
                    with self.assertRaisesRegex(ValueError, "outcome or scope"):
                        opening.verify_execution(stdout, root, language=language)
                    report["language"] = language; path.write_text(json.dumps(report))
                    self.assertIn("installed " + language + " constructor", opening.verify_execution(stdout, root, language=language)["scope"])
                    with self.assertRaisesRegex(ValueError, "outcome or scope"):
                        opening.verify_execution(stdout, root)
                    other = "Kotlin" if language == "Swift" else "Swift"
                    with self.assertRaisesRegex(ValueError, "outcome or scope"):
                        opening.verify_execution(stdout, root, language=other)
                    with self.assertRaisesRegex(ValueError, "unsupported constructor language"):
                        opening.verify_execution(stdout, root, language="unknown")
                    leaf = "initiator/witness-opening-tls-cancel.stdout"
                    (root / leaf).write_text("prepared-cancelled:302:13\n")
                    with self.assertRaisesRegex(ValueError, "command result"):
                        opening.verify_execution(stdout, root, language=language)
                    (root / leaf).write_bytes(files[leaf])
                    if language == "Kotlin":
                        with self.assertRaisesRegex(EvidenceIOError, "cannot safely open evidence file"):
                            kotlin.verify_opening_interruption(stdout, root)
                        receipt = (b"QPC-JVM-INTERRUPT/1\n"
                                   b"control-interrupted native-218 joined flag-retained owner-closed\n")
                        for carrier in ("tcp", "tls"):
                            (root / ("initiator/kotlin-opening-controller-interrupted-" + carrier)).write_bytes(receipt)
                        checked = kotlin.verify_opening_interruption(stdout, root)
                        self.assertTrue(checked["controller_interruption"])
                        for carrier in ("tcp", "tls"):
                            path = root / ("initiator/kotlin-opening-controller-interrupted-" + carrier)
                            self.assertIn(path.relative_to(root).as_posix(), checked["public_readbacks"])
                            for invalid in (receipt[:-1], receipt.replace(b"218", b"302"),
                                            receipt.replace(b"flag-retained", b"flag-cleared"),
                                            receipt.replace(b"owner-closed", b"owner-busy")):
                                path.write_bytes(invalid)
                                with self.assertRaisesRegex(ValueError, "interruption receipt"):
                                    kotlin.verify_opening_interruption(stdout, root)
                            path.write_bytes(receipt)

    def test_original_query_loss_is_valid_without_a_committed_advance_claim(self):
        authority, data, prefix = queries()
        self.assertEqual(opening.query_transcript(data, authority, prefix), 4)
        with self.assertRaises(ValueError):
            opening.transcript(data, authority)

    def test_changed_query_head_attempt_or_held_prefix_is_rejected(self):
        authority, data, prefix = queries()
        mutations = []
        for offset in (0, 1, 10, 140, 173, 3675 + 4 + 136, 2 * opening.RECORD_BYTES + 3675 + 4 + 217):
            changed = bytearray(data)
            changed[offset] ^= 1
            mutations.append(bytes(changed))
        mutations.extend((data[:-1], data + data[:opening.RECORD_BYTES]))
        for changed in mutations:
            with self.subTest(offset=next((i for i, (a,b) in enumerate(zip(data, changed)) if a!=b), len(changed))), self.assertRaises(ValueError):
                opening.query_transcript(changed, authority, prefix)
        for changed in (prefix[:-1], prefix + b'x', b'\0' + prefix[1:-1] + b'x'):
            with self.subTest(prefix=changed[:4]), self.assertRaises(ValueError):
                opening.query_transcript(data, authority, changed)


if __name__ == '__main__':
    unittest.main()
