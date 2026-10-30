"""Read back the retained installed-browser/native communication transcript."""
from pathlib import Path
import hashlib
from urllib.parse import urlsplit

from rust_sdk_profile import require, snapshot
from evidence_io import parse_strict_json_bytes

LABELS = ('native-key', 'native-begin', 'native-request', 'browser-open', 'browser-create',
          'native-accept', 'native-prepare', 'native-publication-id', 'native-publish', 'native-inbox',
          'browser-activate', 'browser-resume', 'native-read-first', 'native-read-lost',
          'native-read-last', 'browser-close')
KINDS = (1, 2, 3, 4, 4, 3, 3, 3)
MESSAGES = {'first': b'installed browser epoch zero',
            'lost': b'original browser delivery with lost ACK',
            'last': b'installed browser after full peer restart'}


def identity(value):
    return type(value) is list and len(value) == 32 and all(type(x) is int and 0 <= x <= 255 for x in value)


def transport_requests(value, public, origin, witness_frames):
    """Explain only fulfilled, exact signed Witness replies; retain raw events."""
    endpoint = urlsplit(origin)
    require(endpoint.scheme == 'http' and endpoint.hostname == '127.0.0.1' and endpoint.port
            and not endpoint.username and not endpoint.password and not endpoint.path
            and not endpoint.query and not endpoint.fragment, 'browser fixture origin differs')
    receipts = value.get('transport_receipts')
    require(type(receipts) is list and len(receipts) <= 1024, 'client transport receipts absent or oversized')
    admitted, seen = {}, set()
    for row in receipts:
        require(type(row) is dict and row.get('url') == origin + '/witness'
                and row.get('result') in ('fulfilled', 'rejected')
                and type(row.get('request_bytes')) is int and row['request_bytes'] == 3674,
                'client witness receipt scope differs')
        digest = row.get('request_sha256')
        require(type(digest) is str and len(digest) == 64 and digest not in seen,
                'duplicate or invalid client request receipt')
        seen.add(digest)
        frames = [frame for frame in witness_frames if frame['request_sha256'] == digest]
        require(len(frames) == 1, 'client request does not identify one real witness exchange')
        frame = frames[0]
        request = snapshot(public / f"witness-{frame['sequence']:03}.request")
        require(request.sha256 == digest and len(request.data) == row['request_bytes']
                and frame.get('request_dual_signature_verified') is True, 'client request bytes differ')
        common = {'url', 'request_sha256', 'request_bytes', 'result'}
        if row['result'] == 'rejected':
            require(set(row) == common | {'error_code'} and row['error_code'] == 'HttpStatus'
                    and value['phase'] in ('witness-unenrolled', 'witness-offline'),
                    'unexpected rejected client witness exchange')
            continue
        require(set(row) == common | {'response_sha256', 'response_bytes'}
                and type(row['response_bytes']) is int and row['response_bytes'] == 3659,
                'fulfilled client receipt shape differs')
        response = snapshot(public / f"witness-{frame['sequence']:03}.response")
        require(response.sha256 == row['response_sha256'] == frame.get('response_sha256')
                and len(response.data) == row['response_bytes'] and frame.get('http_status') == 200
                and frame.get('result') == 'verified-reply' and frame.get('phase') == 'normal'
                and frame.get('reply_dual_signature_verified') is True, 'client did not receive the exact verified reply')
        admitted[digest] = row
    requests, details = value['requests'], value.get('request_diagnostics')
    require(type(requests) is list and type(details) is list and len(details) == len(requests)
            and len(requests) <= 1024, 'request diagnostics inventory differs')
    unexplained, matched = [], set()
    for request, detail in zip(requests, details):
        require(request == {'url': detail['url'], 'failure': detail['failure']}, 'request diagnostics identity differs')
        if (request['url'] != origin + '/witness' or request['failure'] != {'errorText': 'net::ERR_ABORTED'}
                or detail.get('response_status') != 200):
            unexplained.append(request)
            continue
        encoded = detail.get('body_hex')
        require(type(encoded) is str and len(encoded) == 7348, 'failed observer request bytes absent or oversized')
        raw = bytes.fromhex(encoded)
        digest = hashlib.sha256(raw).hexdigest()
        require(digest in admitted and digest not in matched and len(raw) == 3674,
                'failed observer event lacks a unique fulfilled client reply')
        matched.add(digest)
    return unexplained


def verify_forward(report: dict, public: Path) -> None:
    require(type(report.get('schema_version')) is int and report['schema_version'] in (1, 2, 3, 4)
            and report.get('completed') is True and report.get('release_claim_eligible') is False,
            'browser/native scope or completion differs')
    require(report.get('relay_failures') == [] and not report.get('cleanup_failures'), 'fixture failed')
    before, after = report['before_restart'], report['after_restart']
    for key in ('journal', 'session'):
        require(identity(before[key]) and before[key] == after[key], 'original ' + key + ' changed')
    failure = before['failure']
    require(failure.get('code') == 'PeerTransport' and failure.get('closed') is True
            and failure.get('ownerClosed') is True, 'lost reply did not preserve the closed error owner')
    for result in (before, after):
        leases = result.get('leases')
        require(type(leases) is list and leases and all(type(row.get('count')) is int and row['count'] >= 0
                and type(row.get('elapsed_ms')) in (int, float) and row['elapsed_ms'] >= 0 for row in leases)
                and leases[-1]['count'] == 0, 'Worker lease release was not observed')
    require(type(after['before']) is int and after['before'] == 2 and type(after['after']) is int
            and after['after'] == 3, 'unknown delivery was not reconciled from Committed to Acknowledged')
    require(all(after[key] == '1' for key in ('confirmed_epoch', 'sending_epoch', 'receiving_epoch')),
            'reopened epoch differs')
    ids = [before['first'], before['lost'], after['last']]
    require(all(identity(value) for value in ids) and len({bytes(value) for value in ids}) == 3,
            'application operation IDs differ')
    first, second = report['native_first'], report['native_second']
    require(first['exit'] == -9 and second['exit'] == 0 and type(first['pid']) is int
            and type(second['pid']) is int and first['pid'] > 0 and second['pid'] > 0
            and first['pid'] != second['pid'], 'full native process replacement absent')
    require(second['stats']['completed_responses'] == 2 and second['stats']['operation_errors'] == 0,
            'reopened native service did not execute both real replies')
    for name, lines in (('native-first', 1), ('native-reopened', 2)):
        require(not snapshot(public / 'logs' / (name + '.stderr')).data
                and len(snapshot(public / 'logs' / (name + '.stdout')).data.splitlines()) == lines,
                'native process terminal streams differ')
    frames = report['frames']
    require(type(frames) is list and len(frames) == len(KINDS), 'exchange inventory differs')
    for index, (row, kind) in enumerate(zip(frames, KINDS), 1):
        require(type(row['sequence']) is int and row['sequence'] == index and type(row['kind']) is int
                and row['kind'] == kind and row['withheld'] is (index == 6), 'exchange order or loss differs')
        for direction, expected_kind in (('request', kind), ('response', kind + 128)):
            captured = snapshot(public / f'{index:03}.{direction}')
            require(captured.sha256 == row[direction + '_sha256'] and 10 <= len(captured.data) <= 32768
                    and captured.data[:8] == b'QPCXCH01' and captured.data[8] == expected_kind,
                    'retained real exchange differs')
    require(frames[5]['request_sha256'] == frames[6]['request_sha256']
            and frames[5]['response_sha256'] == frames[6]['response_sha256'],
            'original request or confirmed reply changed after restart')
    commands = report['commands']
    require(type(commands) is list and [row['label'] for row in commands] == list(LABELS), 'command inventory differs')
    for row in commands:
        require(type(row['exit']) is int and row['exit'] == 0, 'command did not succeed')
        for stream in ('stdout', 'stderr'):
            captured = snapshot(public / 'logs' / (row['label'] + '.' + stream))
            require(captured.sha256 == row[stream + '_sha256'] and (stream != 'stderr' or not captured.data),
                    'command stream differs')
            if stream == 'stdout' and row['label'] in ('browser-activate', 'browser-resume'):
                # Parse the same hash-checked bytes, not a second file read or an
                # unbound summary. Equal forged before/after IDs are not evidence.
                phase = row['label'][len('browser-'):]
                text = captured.data.decode('utf-8')
                require(text.count('### Result\n') == 1 and '### Error' not in text,
                        'browser phase result missing or failed')
                value = parse_strict_json_bytes(
                    text.split('### Result\n', 1)[1].split('\n### ', 1)[0].encode(),
                    label='retained browser phase ' + phase)
                require(type(value) is dict and value.get('status') == 'INSTALLED_SESSION_PHASE'
                        and value.get('phase') == phase and type(value.get('result')) is dict,
                        'retained browser phase identity differs')
                require(value['result'] == (before if phase == 'activate' else after),
                        'browser summary differs from retained phase result')
                if report['schema_version'] == 4:
                    origin = report['browser_origin']
                    remaining = transport_requests(value, public, origin, report['required_witness']['frames'])
                    require(not value['http_errors'], 'unexpected browser HTTP failure')
                    if phase == 'activate':
                        require(remaining == [{'url': origin + '/exchange/drop-once',
                            'failure': {'errorText': 'net::ERR_EMPTY_RESPONSE'}}], 'actual lost reply differs')
                        require(all(row['type'] == 'error' and row['location']['url'] == origin + '/exchange/drop-once'
                                    and 'ERR_EMPTY_RESPONSE' in row['message'] for row in value['diagnostics']),
                                'unrelated browser errors')
                    else:
                        require(not remaining and not value['diagnostics'], 'unexplained browser recovery failure')
    for label, expected in MESSAGES.items():
        require(snapshot(public / ('effect-' + label + '.bin')).data == expected,
                'native application effect differs')
    request = snapshot(public / 'browser-enrollment.request').data
    require(len(request) == 5506 and request[4:12] == b'QPENRQ01',
            'actual browser enrollment request missing')


def verify(report: dict, public: Path) -> None:
    from continuity_browser_reverse_records import verify as verify_reverse
    require(type(report.get('schema_version')) is int and report['schema_version'] in (2, 3, 4),
            'bidirectional qualification requires its current transcript schema')
    verify_forward(report, public)
    witness_context = ((report['browser_origin'], report['required_witness']['frames'])
                       if report['schema_version'] == 4 else None)
    verify_reverse(report['reverse_application'], public, report['before_restart']['session'], witness_context=witness_context)
    if report['schema_version'] in (3, 4):
        from continuity_browser_witness_records import verify as verify_witness
        require(report.get('policy_profile') == 'required-witness', 'required witness profile missing')
        require(report.get('native_build_profile') in ('debug','release'), 'native witness build profile missing')
        verify_witness(report['required_witness'], public, report['before_restart'])
    else:
        require('required_witness' not in report and report.get('policy_profile') != 'required-witness',
                'witness evidence requires its dedicated transcript schema')
