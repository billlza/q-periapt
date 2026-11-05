"""Bind browser peer Fetch completion to the actual phase's retained wire frames."""
import re

from rust_sdk_profile import require, snapshot


def peer_receipts(value, public, origin, frames, kinds):
    """Return only complete peer replies; the deliberate lost reply stays a failure."""
    phase = value['phase']
    expected = set(range(1, 7) if phase == 'activate' else range(7, 9) if phase == 'resume' else ())
    require(type(frames) is list and all(type(row) is dict for row in frames), 'peer frame inventory differs')
    selected = [frame for frame in frames if frame.get('sequence') in expected]
    require(len(selected) == len(expected) and {frame['sequence'] for frame in selected} == expected,
            'phase peer frame inventory differs')
    rows = value['transport_receipts']
    require(all(type(row) is dict for row in rows), 'client receipt shape differs')
    rows = [row for row in rows if row.get('url') in (origin + '/exchange', origin + '/exchange/drop-once')]
    admitted, seen = {}, set()
    for row in rows:
        digest = row.get('request_sha256')
        require(type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest) is not None
                and type(row.get('request_bytes')) is int and 10 <= row['request_bytes'] <= 32768,
                'client peer request shape differs')
        dropped = row['url'] == origin + '/exchange/drop-once'
        matches = [frame for frame in selected if frame.get('request_sha256') == digest
                   and frame.get('withheld') is dropped]
        require(len(matches) == 1, 'client request does not identify one peer exchange in this phase')
        frame = matches[0]; number = frame['sequence']
        require(type(number) is int and number not in seen and type(frame.get('kind')) is int
                and frame['kind'] == kinds[number - 1] and dropped is (number == 6),
                'peer sequence, kind or deliberate loss differs')
        seen.add(number)
        request = snapshot(public / f'{number:03}.request')
        response = snapshot(public / f'{number:03}.response')
        require(request.sha256 == digest and len(request.data) == row['request_bytes']
                and request.data[:9] == b'QPCXCH01' + bytes([frame['kind']]), 'client peer request bytes differ')
        require(10 <= len(response.data) <= 32768 and response.sha256 == frame.get('response_sha256')
                and response.data[:9] == b'QPCXCH01' + bytes([frame['kind'] + 128]),
                'retained peer response bytes differ')
        common = {'url', 'request_sha256', 'request_bytes', 'result'}
        if dropped:
            require(phase == 'activate' and set(row) == common | {'error_code'}
                    and row['result'] == 'rejected' and row['error_code'] == 'Network',
                    'lost peer reply was not rejected by the real Fetch')
            details = value.get('request_diagnostics')
            require(type(details) is list and all(type(detail) is dict for detail in details),
                    'peer loss observer evidence absent')
            loss = [detail for detail in details if detail.get('url') == row['url']]
            require(len(loss) == 1 and loss[0].get('failure') == {'errorText': 'net::ERR_EMPTY_RESPONSE'}
                    and loss[0].get('response_status') is None and loss[0].get('body_hex') == request.data.hex(),
                    'lost peer reply observer does not identify the original request')
            continue
        require(row['result'] == 'fulfilled' and set(row) == common | {'response_sha256', 'response_bytes'}
                and type(row['response_bytes']) is int and row['response_bytes'] == len(response.data)
                and row['response_sha256'] == response.sha256, 'client did not receive the complete original peer reply')
        require(digest not in admitted, 'duplicate fulfilled peer receipt')
        admitted[digest] = row
    require(seen == expected, 'client peer receipt inventory is incomplete')
    return admitted
