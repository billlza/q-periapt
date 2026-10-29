"""Read back browser required-Witness scope and exact public transitions.

The runtime fixture independently verifies dual signatures. This reader checks
the captured framing, commitments, transitions, failures and process identities.
"""
import base64
import hashlib
from pathlib import Path

from continuity_c_witness import commit, head
from rust_sdk_profile import require, snapshot

COMMANDS = ('witness-init', 'native-witness-enroll', 'browser-witness-prepare',
            'browser-witness-missing', 'browser-witness-unenrolled',
            'browser-wrong-head-witness-enroll', 'browser-witness-enroll',
            'browser-witness-offline', 'witness-original-pin')
DOMAIN = b'Q-PERIAPT-CONTINUITY-ANCHOR-'
sha = lambda data: hashlib.sha256(data).hexdigest()


def fixed(value, size):
    require(type(value) is list and len(value) == size and all(type(x) is int and 0 <= x <= 255 for x in value)
            and any(value), 'witness public identity shape')
    return bytes(value)


def verify(report: dict, public: Path, original: dict) -> None:
    original_journal = original['journal']
    require(type(report.get('schema_version')) is int and report['schema_version'] == 1
            and report.get('completed') is True, 'required witness workload incomplete')
    pin = report['pin']; identity = fixed(pin['identity'], 32)
    encoded = pin['key']; require(type(encoded) is str, 'witness public key encoding')
    key = base64.b64decode(encoded + '=' * (-len(encoded) % 4), altchars=b'-_', validate=True)
    require(len(key) == 1985 and base64.urlsafe_b64encode(key).rstrip(b'=').decode() == encoded,
            'witness public key width or canonical encoding')
    authority = commit(DOMAIN + b'AUTHORITY/v1', identity + key)
    require(report['reopened_pin'] == pin and report['key_hashes_after'] == report['key_hashes_before']
            and len(report['key_hashes_before']) == 2, 'witness restart replaced its identity or keys')
    prepared = report['browser_preparation']
    require(prepared['requires_witness'] is True and prepared['journal'] == original_journal,
            'required policy or original browser journal differs')
    subject = fixed(prepared['subject'], 96)
    require(subject[:32] == fixed(original_journal, 32), 'witness subject replaced original journal')
    genesis = fixed(prepared['head'], 32)
    require(report['browser_enrollment'] == {'enrollment': 'Recorded', 'journal': original_journal, 'head': prepared['head']},
            'separate browser genesis approval was not retained')
    require(original.get('activation_resume') == {'phase': 4, 'journal': original_journal},
            'original activation was not resumed from its durable selection')
    native = report['native_genesis']; enrolled = report['native_enrollment']
    require(native['preparation'] == 'RequiresWitnessEnrollment' and fixed(native['subject'], 96)[:32] == fixed(enrolled['journal'], 32)
            and enrolled['enrollment'] == 'Recorded' and enrolled['head'] == native['head']
            and enrolled['journal'] != original_journal, 'native witnessed enrollment differs')
    for kind, expected in [('missing', 'AnchorRequired'), ('unenrolled', 'WitnessTransport'), ('offline', 'WitnessTransport')]:
        row = report[kind]; failure = row['failure']
        require(row['kind'] == kind and failure['code'] == expected and failure['closed'] is True
                and failure['ownerClosed'] is True, 'witness refusal allowed a live or downgraded owner')
        require(row['starting_status'] == {'phase': {'missing': 3, 'unenrolled': 4, 'offline': 5}[kind],
                                          'journal': original_journal}, 'witness refusal started from another durable state')
        leases = row['leases']
        require(type(leases) is list and leases and all(type(r['count']) is int and r['count'] >= 0 for r in leases)
                and leases[-1]['count'] == 0, 'refused browser owner retained its lease')
    from evidence_io import parse_strict_json_bytes
    from urllib.parse import urlsplit
    endpoint = None
    for kind in ('missing', 'unenrolled', 'offline'):
        name = 'witness-' + kind
        captured = parse_strict_json_bytes(snapshot(public / (name + '.json')).data, label=name)
        stdout = snapshot(public / 'logs' / ('browser-' + name + '.stdout')).data.decode()
        require(stdout.count('### Result\n') == 1 and '### Error' not in stdout,
                'witness browser phase output failed')
        returned = parse_strict_json_bytes(stdout.split('### Result\n', 1)[1].split('\n### ', 1)[0].encode(), label=name)
        require(returned == captured and captured['status'] == 'INSTALLED_SESSION_PHASE'
                and captured['phase'] == name and captured['result'] == report[kind],
                'witness refusal phase differs from actual browser output')
        if kind == 'missing':
            require(not captured['http_errors'] and not captured['requests'] and not captured['diagnostics'],
                    'missing carrier unexpectedly reached a transport')
            continue
        status = 502 if kind == 'unenrolled' else 503
        errors = captured['http_errors']
        require(len(errors) == 1 and errors[0]['status'] == status, 'actual witness HTTP failure missing')
        url = errors[0]['url']; parsed = urlsplit(url)
        require(parsed.scheme == 'http' and parsed.hostname == '127.0.0.1' and parsed.port
                and parsed.path == '/witness' and not parsed.query and not parsed.fragment
                and not parsed.username and not parsed.password, 'witness fixture endpoint differs')
        if endpoint is None: endpoint = url
        require(url == endpoint and f'HttpStatus (HTTP {status})' in report[kind]['failure']['message'],
                'witness failure did not preserve its selected carrier')
        require(len(captured['requests']) <= 1 and all(r == {'url': url, 'failure': {'errorText': 'net::ERR_ABORTED'}}
                for r in captured['requests']) and len(captured['diagnostics']) <= 1
                and all(r['type'] == 'error' and r['location']['url'] == url and str(status) in r['message']
                        for r in captured['diagnostics']), 'unrelated browser failure was suppressed')
    services = report['services']
    require([s['label'] for s in services] == ['witness-unenrolled', 'witness-active', 'witness-reopened']
            and [s['exit'] for s in services] == [0, -9, 0]
            and all(type(s['pid']) is int and s['pid'] > 0 for s in services)
            and len({s['pid'] for s in services}) == 3 and report['crash'] == services[1],
            'complete original witness process restart is absent')
    require(services[0]['stats']['operation_errors'] == 1 and services[2]['stats']['operation_errors'] == 0,
            'witness terminal server errors differ')
    endpoints = []
    for service in services:
        raw = snapshot(public / 'logs' / (service['label'] + '.stdout')).data.splitlines()
        require(len(raw) == (1 if service['exit'] == -9 else 2)
                and not snapshot(public / 'logs' / (service['label'] + '.stderr')).data, 'witness terminal streams differ')
        ready = parse_strict_json_bytes(raw[0], label='witness readiness')
        require(ready['service'] == 'Listening' and ready['carrier'] == 'ContinuityAnchor/TCP', 'witness readiness missing')
        endpoints.append(ready['address'])
        if service['exit'] == 0:
            stopped = parse_strict_json_bytes(raw[1], label='witness terminal')
            require(stopped['service'] == 'Stopped' and stopped['stats'] == service['stats'], 'witness stop receipt differs')
    require(len(set(endpoints)) == 1, 'witness restart replaced its selected endpoint')
    commands = report['commands']
    require([row['label'] for row in commands] == list(COMMANDS), 'witness command inventory differs')
    for row in commands:
        expected = 1 if row['label'] == 'browser-wrong-head-witness-enroll' else 0
        require(type(row['exit']) is int and row['exit'] == row['expected_exit'] == expected, 'witness command outcome differs')
        for stream in ('stdout', 'stderr'):
            data = snapshot(public / 'logs' / (row['label'] + '.' + stream)).data
            require(sha(data) == row[stream + '_sha256'], 'witness command stream hash differs')
            if expected:
                require((not data) if stream == 'stdout' else b'Witness enrollment differs from independent approval' in data,
                        'wrong-head refusal has another cause')
            elif stream == 'stderr': require(not data, 'unexpected witness command diagnostics')
    frames = report['frames']; require(type(frames) is list and 4 <= len(frames) <= 1024, 'witness exchange inventory')
    state, last = (1, 1, genesis), None
    challenges = set(); refusals = []; operations = set()
    for number, row in enumerate(frames, 1):
        require(type(row['sequence']) is int and row['sequence'] == number and row['request_dual_signature_verified'] is True,
                'witness request verification or sequence differs')
        request = snapshot(public / f'witness-{number:03}.request')
        require(request.sha256 == row['request_sha256'] and len(request.data) == 3674
                and request.data[:4] == (297).to_bytes(4, 'big'), 'witness request envelope differs')
        body = request.data[4:301]
        require(body[:8] == b'QPANRQ01' and body[8:40] == authority and body[40:136] == subject, 'witness request scope differs')
        command, challenge, operation = body[136:168], body[168:200], body[200:]
        require(command == fixed(row['command'], 32) == commit(DOMAIN + b'COMMAND/v1', authority + subject + operation)
                and any(challenge) and challenge not in challenges and sha(challenge) == row['challenge_sha256'],
                'witness original command or fresh challenge differs')
        challenges.add(challenge); kind = operation[0]
        require(type(row['operation']) is int and row['operation'] == kind, 'witness operation differs')
        if row['result'] != 'verified-reply':
            expected = ('no-reply', 'unenrolled', 502) if number == 1 else ('connection-refused', 'offline', 503)
            require((row['result'], row['phase'], row['http_status']) == expected
                    and not (public / f'witness-{number:03}.response').exists()
                    and 'response_sha256' not in row and 'reply_dual_signature_verified' not in row,
                    'unavailable witness fabricated a receipt')
            if number == 1: require(row['error'] == 'truncated witness reply', 'unenrolled boundary differs')
            else: require(type(row['errno']) is int and row['errno'] > 0, 'offline socket failure missing')
            refusals.append(row['result']); continue
        require(row['phase'] == 'normal' and row['http_status'] == 200 and row['reply_dual_signature_verified'] is True,
                'witness reply was not independently checked')
        response = snapshot(public / f'witness-{number:03}.response')
        require(response.sha256 == row['response_sha256'] and len(response.data) == 3659
                and response.data[:4] == (282).to_bytes(4, 'big'), 'witness reply envelope differs')
        reply = response.data[4:286]
        require(reply[:8] == b'QPANRS01' and reply[8:40] == authority and reply[40:136] == subject
                and reply[136:168] == commit(DOMAIN + b'REQUEST/v1', body) and reply[168:200] == command,
                'witness response does not bind this exact request')
        outcome, observed = reply[200], head(reply[201:249])
        has_last, last_id = reply[249], reply[250:282]
        require((has_last == 0 and not any(last_id) and observed[:2] == (1, 1))
                or (has_last == 1 and any(last_id) and observed[:2] != (1, 1)), 'witness last-command presence differs')
        last_id = last_id if has_last else None
        require(row['outcome'] == outcome and row['head'] == {'fence': observed[0], 'revision': observed[1], 'digest': list(observed[2])},
                'witness observed head differs')
        if kind == 1:
            require(operation[1:] == bytes(96) and outcome == 1 and (observed, last_id) == (state, last),
                    'query changed the original witness head')
        elif kind == 4:
            require(any(operation[1:33]) and not any(operation[33:]) and outcome == 5
                    and (observed, last_id) == (state, last), 'current account authority was not admitted')
        else:
            require(kind in (2, 3), 'unexpected witness operation')
            previous, target = head(operation[1:49]), head(operation[49:97])
            require((target[0] == previous[0] and target[1] == previous[1] + 1 and target[2] != previous[2]) if kind == 2
                    else (target[0] == previous[0] + 1 and target[1:] == previous[1:]), 'witness transition shape differs')
            require(outcome == (3 if (state, last) == (target, command) else 2)
                    and ((state, last) == (target, command) or state == previous)
                    and (observed, last_id) == (target, command), 'witness transition skipped or repeated state')
            state, last = target, command
        operations.add(kind)
    require(refusals == ['no-reply', 'connection-refused'] and {1, 2, 4} <= operations,
            'required witness admission, unavailable states or durable advances were omitted')
