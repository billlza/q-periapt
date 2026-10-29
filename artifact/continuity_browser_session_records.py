"""Read back the retained installed-browser/native communication transcript."""
from pathlib import Path

from rust_sdk_profile import require, snapshot

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


def verify_forward(report: dict, public: Path) -> None:
    require(type(report.get('schema_version')) is int and report['schema_version'] in (1, 2)
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
    for label, expected in MESSAGES.items():
        require(snapshot(public / ('effect-' + label + '.bin')).data == expected,
                'native application effect differs')
    request = snapshot(public / 'browser-enrollment.request').data
    require(len(request) == 5506 and request[4:12] == b'QPENRQ01',
            'actual browser enrollment request missing')


def verify(report: dict, public: Path) -> None:
    from continuity_browser_reverse_records import verify as verify_reverse
    require(type(report.get('schema_version')) is int and report['schema_version']==2,
            'bidirectional qualification requires its current transcript schema')
    verify_forward(report, public)
    verify_reverse(report['reverse_application'], public, report['before_restart']['session'])
