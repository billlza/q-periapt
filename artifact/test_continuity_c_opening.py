"""Reject altered original-query identity and cancellation readback evidence."""
import unittest

import continuity_c_opening as opening


def queries():
    authority = b'a' * 32
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
