"""Peer observer evidence never substitutes server bytes for client completion."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from continuity_browser_session_records import KINDS, transport_requests


class PeerTransportEvidence(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.public = Path(temporary.name)
        self.origin = 'http://127.0.0.1:12345'
        self.frames, self.receipts, self.requests = [], [], []
        for number, kind in enumerate(KINDS, 1):
            identity = 6 if number == 7 else number
            request = b'QPCXCH01' + bytes([kind, identity]) + b'r' * 100
            response = b'QPCXCH01' + bytes([kind + 128, identity]) + b's' * 4000
            self.requests.append(request)
            (self.public / f'{number:03}.request').write_bytes(request)
            (self.public / f'{number:03}.response').write_bytes(response)
            request_sha, response_sha = (hashlib.sha256(data).hexdigest() for data in (request, response))
            self.frames.append({'sequence': number, 'kind': kind, 'withheld': number == 6,
                                'request_sha256': request_sha, 'response_sha256': response_sha})
            row = {'url': self.origin + ('/exchange/drop-once' if number == 6 else '/exchange'),
                   'request_sha256': request_sha, 'request_bytes': len(request),
                   'result': 'rejected' if number == 6 else 'fulfilled'}
            row.update({'error_code': 'Network'} if number == 6 else
                       {'response_sha256': response_sha, 'response_bytes': len(response)})
            self.receipts.append(row)
        aborted = {'url': self.origin + '/exchange', 'failure': {'errorText': 'net::ERR_ABORTED'}}
        self.loss = {'url': self.origin + '/exchange/drop-once', 'failure': {'errorText': 'net::ERR_EMPTY_RESPONSE'}}
        self.value = {'phase': 'activate', 'transport_receipts': copy.deepcopy(self.receipts[:6]),
                      'requests': [aborted, self.loss], 'request_diagnostics': [
                          {**aborted, 'response_status': 200, 'body_hex': self.requests[0].hex()},
                          {**self.loss, 'response_status': None, 'body_hex': self.requests[5].hex()}]}

    def read(self, value=None, frames=None):
        return transport_requests(self.value if value is None else value, self.public, self.origin, [],
                                  self.frames if frames is None else frames)

    def test_complete_bytes_explain_only_matching_abort_and_keep_real_loss(self):
        original = copy.deepcopy(self.value)
        self.assertEqual(self.read(), [self.loss])
        self.assertEqual(self.value, original)
        self.assertEqual(self.read(frames=self.frames[:6]), [self.loss], 'live activation has only six frames')

    def test_missing_duplicate_or_rejected_normal_completion_refuses(self):
        for mutate in (lambda rows: rows.pop(0), lambda rows: rows.append(copy.deepcopy(rows[0])),
                       lambda rows: rows[0].update(result='rejected', error_code='Cancelled')):
            value = copy.deepcopy(self.value); mutate(value['transport_receipts'])
            with self.subTest(value=value['transport_receipts']), self.assertRaises(ValueError): self.read(value)

    def test_response_length_hash_request_origin_or_extra_fields_refuse(self):
        for key, changed in [('response_bytes', 2000), ('response_bytes', True), ('response_sha256', '00' * 32),
                             ('request_sha256', '00' * 32), ('request_bytes', True),
                             ('url', 'http://example.invalid/exchange'), ('unexpected', 1)]:
            value = copy.deepcopy(self.value); value['transport_receipts'][0][key] = changed
            with self.subTest(key=key), self.assertRaises(ValueError): self.read(value)

    def test_changed_wire_wrong_kind_or_duplicate_frame_refuses(self):
        for mutate in (lambda rows: rows.append(copy.deepcopy(rows[0])),
                       lambda rows: rows[0].update(kind=3), lambda rows: rows[0].update(withheld=True)):
            frames = copy.deepcopy(self.frames); mutate(frames)
            with self.subTest(frames=frames[:1]), self.assertRaises(ValueError): self.read(frames=frames)
        (self.public / '001.response').write_bytes(b'truncated')
        with self.assertRaises(ValueError): self.read()

    def test_unrelated_http_failure_or_cancel_is_not_explained(self):
        for failure, status in [('net::ERR_ABORTED', 503), ('net::ERR_FAILED', 200),
                                ('net::ERR_CONTENT_LENGTH_MISMATCH', 200)]:
            value = copy.deepcopy(self.value)
            value['requests'][0]['failure'] = {'errorText': failure}
            value['request_diagnostics'][0].update(failure={'errorText': failure}, response_status=status)
            self.assertEqual(self.read(value), value['requests'])

    def test_forged_or_duplicate_observer_body_refuses(self):
        value = copy.deepcopy(self.value); value['request_diagnostics'][0]['body_hex'] = (b'x' * 110).hex()
        with self.assertRaises(ValueError): self.read(value)
        value = copy.deepcopy(self.value)
        value['requests'].insert(0, copy.deepcopy(value['requests'][0]))
        value['request_diagnostics'].insert(0, copy.deepcopy(value['request_diagnostics'][0]))
        with self.assertRaises(ValueError): self.read(value)

    def test_actual_loss_requires_rejection_and_exact_observer_request(self):
        for mutate in (lambda value: value['transport_receipts'][-1].update(result='fulfilled'),
                       lambda value: value['transport_receipts'][-1].update(error_code='Timeout'),
                       lambda value: value['request_diagnostics'][-1].update(response_status=200),
                       lambda value: value['request_diagnostics'][-1].update(body_hex=self.requests[0].hex()),
                       lambda value: value['request_diagnostics'].pop()):
            value = copy.deepcopy(self.value); mutate(value)
            with self.subTest(value=value['transport_receipts'][-1]), self.assertRaises(ValueError): self.read(value)

    def test_original_retry_matches_reopened_frame_and_cannot_borrow_lost_receipt(self):
        value = {'phase': 'resume', 'transport_receipts': copy.deepcopy(self.receipts[6:]),
                 'requests': [], 'request_diagnostics': []}
        self.assertEqual(self.read(value), [])
        value['transport_receipts'][0] = copy.deepcopy(self.receipts[5])
        with self.assertRaises(ValueError): self.read(value)
        value['transport_receipts'] = copy.deepcopy(self.receipts[:2])
        with self.assertRaises(ValueError): self.read(value)

    def test_legacy_reader_does_not_silently_accept_new_peer_receipts(self):
        with self.assertRaises(ValueError):
            transport_requests(self.value, self.public, self.origin, [])


if __name__ == '__main__': unittest.main()
