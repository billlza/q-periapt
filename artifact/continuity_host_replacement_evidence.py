"""Reconcile public replacement receipts with the original process outputs."""
import base64
from pathlib import PurePosixPath
from continuity_independent_python import require
from evidence_io import parse_strict_json_bytes


def verify_http_recovery(responses, requests):
    # Neither a recovered invitation nor issuance may silently become a new operation.
    for names in [('replacement-invitation', 'replacement-invitation-retry'),
                  ('old-issue', 'old-issue-after-replacement', 'old-issue-final'),
                  ('new-issue', 'new-issue-retry', 'new-issue-final')]:
        require(all(responses[k] == responses[names[0]] for k in names), 'replacement HTTP original response')
    for names in [('replacement-invitation-lost','replacement-invitation','replacement-invitation-retry'),
                  ('new-issue-lost','new-issue','new-issue-retry','new-issue-final')]:
        first = requests[names[0]]
        require(all(all(requests[k][field] == first[field] for field in ('account','route','body')) for k in names),
                'replacement HTTP original request')
    require(requests['replacement-invitation']['route'] == '/api/enrollment/replace-device'
            and requests['new-issue']['route'] == '/api/enrollment/issue', 'replacement actual host routes')


def retain(value, private, public, snapshot, labels, failed):
    public.mkdir()
    def copy(name):
        item = snapshot(private / name)
        (public / name).write_bytes(item.data)
        return item
    def document(name): return parse_strict_json_bytes(copy(name).data, label=name)
    def result(label): return document(label + '.stdout')
    def same(*names):
        items = [copy(name).data for name in names]
        require(all(item == items[0] for item in items), 'replacement original bytes: ' + names[0])
    copy('RESULT.json')
    for label in labels:
        out, err = copy(label + '.stdout'), copy(label + '.stderr')
        require(bool(err.data) == (label in failed), 'replacement diagnostic disposition')
        if label in failed: require(not out.data, 'replacement refusal emitted result')
        if label in ('replacement-witness-lost-commit', 'native-peer-roster-lost-output'):
            require(b'broken pipe' in err.data.lower(), 'replacement commit output was not lost')
    responses, requests = {}, {}
    for row in value['account_requests']:
        label = row['label']
        request, response = document(label + '.http-request.json'), document(label + '.http-response.json')
        require(set(request) == {'id','command'} and set(response) == {'id','result'}
                and request['id'] == response['id'] == row['id']
                and request['command']['action'] == row['action'], 'replacement HTTP correlation')
        command, reply = request['command'], response['result']
        requests[label] = command
        if row['action'] in ('register', 'login'):
            require(reply == {'authenticated': 'registered_software_test_passkey' if row['action'] == 'register'
                             else 'original_software_test_passkey'}, 'replacement original authentication')
            continue
        if row['action'] == 'finish':
            require(reply == {'finished': True}, 'replacement probe completion'); continue
        require(set(reply) == {'status','body','content_type'}, 'replacement HTTP response schema')
        status = 401 if label.endswith('-old-login') else 204 if label.endswith('-approve') else 200
        require(type(reply['status']) is int and reply['status'] == status, 'replacement HTTP status')
        lost = label in ('replacement-invitation-lost', 'new-issue-lost')
        require(command['disconnect_before_body'] is lost, 'replacement HTTP disconnect')
        if lost or status == 204: require(reply['body'] == '', 'replacement lost HTTP body')
        responses[label] = reply['body'].encode()
    require(not copy('account-probe.stderr').data, 'replacement probe diagnostics')
    verify_http_recovery(responses, requests)
    for label in ('old', 'new'):
        issued = copy(label + '-issued.json').data
        require(issued == responses[label + '-issue'], 'replacement accepted actual HTTP issuance')
        invitation = document(label + '-invitation.json')
        expected = 'original-invitation' if label == 'old' else 'replacement-invitation'
        require(invitation == parse_strict_json_bytes(responses[expected], label='HTTP invitation'), 'replacement actual invitation')
        require(invitation['generation'] == (1 if label == 'old' else 2)
                and invitation['device'] == value['device'], 'replacement same device, new generation')
        require(requests[label + '-approve']['body'] == {'operation': invitation['operation'],
                'request': base64.urlsafe_b64encode(copy(label + '-request.bin').data).rstrip(b'=').decode()},
                'replacement explicit proof approval')
        current = document(label + '-current.json')
        require(current == parse_strict_json_bytes(responses[label + '-current'], label='HTTP current roster'),
                'replacement actual current roster')
    same('old-authority.json', 'new-authority.json')
    identities = document('signing-identities.json')
    require(set(identities) == {'old','new'} and all(identities['old'][k] != identities['new'][k]
            for k in ('signing_id','public_sha256')), 'replacement fresh signing identity')
    decision = result('replacement-witness-prepare')
    require(result('replacement-witness-status') == value['witness_decision'] ==
            {'binding': decision['binding'], 'status': 'Committed'}, 'replacement committed witness decision')
    require(parse_strict_json_bytes(snapshot(private / 'replacement-decision/device-replacement-decision.json').data,
                                    label='retained witness decision') == decision, 'replacement retained witness proposal')
    target = document('native-peer-roster-retry-target.json')
    require(result('native-peer-roster-retry') == {'peer_roster': target['roster']['checkpoint']}
            and target == document('new-current.json'), 'replacement exact installed peer roster')
    same('native-peer-roster-lost-output-target.json','native-peer-roster-retry-target.json')
    same('native-before-replacement.stdout','native-final-status.stdout','native-original-status.stdout')
    same('native-before-invalid-publication.stdout','native-after-invalid-publication.stdout')
    same('native-publication-id.stdout','native-publication-id-after-refusal.stdout')
    require(not list((private / 'rejected-publication').iterdir()), 'refused publication artifact')
    for label in ('old','new'):
        sid = value[label + '_session']
        require(result(label + '-connect') == {'session': sid, 'peer_confirmation': 'Recorded'}
                and result(label + '-connect-retry') == result(label + '-connect'), 'replacement exact session')
    require(result('new-after-service-restart') == result('new-connect'), 'replacement restarted session')
    require(result('old-lost-status') == {'status': 'Committed', 'session': value['old_session'],
            'message': result('old-lost-next')['message']}, 'replacement unknown old delivery')
    require(result('new-rekey') == {'session': value['new_session'], 'epoch': 1, 'exchanges': 2}, 'replacement rekey')
    require(result('native-reverse-send') == {'consumption':'Confirmed'}, 'replacement reverse delivery')
    for label, message_label, sid in [('old-first-send','old-first-next',value['old_session']),
            ('new-message-send','new-message-next',value['new_session']),
            ('new-after-restart-send','new-after-restart-next',value['new_session'])]:
        require(result(label) == {'session': sid, 'message': result(message_label)['message'], 'consumption': 'Confirmed'},
                'replacement confirmed message')
    for name, body in [('old-first-effect', b'before authenticated replacement'),
            ('old-lost-effect', b'old consumed effect with lost ACK'), ('old-effect-retained', b'old consumed effect with lost ACK'),
            ('new-effect', b'after authenticated replacement'), ('reverse-effect', b'original native owner to replacement generation'),
            ('after-restart-effect', b'new traffic after both service restarts')]:
        require(copy(name + '.bin').data == body, 'replacement durable effect: ' + name)
    for row in value['frames']:
        for side in ('request',) if row['outcome'] == 'refused' else ('request','response'):
            item = copy(row['label'] + '.' + side)
            require(item.sha256 == row[side + '_sha256'] and 10 <= len(item.data) <= 32768
                    and item.data[:9] == b'QPCXCH01' + bytes([row['kind'] + (128 if side == 'response' else 0)]),
                    'replacement retained original wire frame')
    same('replacement-wire-1.request','replacement-wire-2.request')
    for name in ('old-cached-frame-refusal.txt','old-cached-frame-after-restart-refusal.txt'):
        require(bool(copy(name).data), 'replacement cached frame refusal')
    for name in ('old-lost.request','old-lost.response'): copy(name)
    for group in ('services','witness_services','account_services','receiver'):
        rows = [value['independent_service']] if group == 'receiver' else value[group]
        for row in rows:
            lines = copy(row['label'] + '.stdout').data.splitlines()
            require(not copy(row['label'] + '.stderr').data, 'replacement service diagnostics')
            if group == 'account_services':
                require(len(lines) == 1 and lines[0].startswith(b'Reference account application: http://localhost:'),
                        'replacement account listening'); continue
            require(len(lines) == (1 if row['exit'] == -9 else 2)
                    and parse_strict_json_bytes(lines[0], label='replacement listening')['service'] == 'Listening',
                    'replacement service readiness')
            if row['exit'] == 0:
                require(parse_strict_json_bytes(lines[1], label='replacement stop') == {'service':'Stopped','stats':row['stats']},
                        'replacement service shutdown')
    for prefix in ('old-state', 'witness-keys'):
        before, after = document(prefix + '-before.json'), document(prefix + '-after.json')
        require(type(before) is dict and bool(before) and before == after, 'replacement retained state hashes')
        for name, digest in before.items():
            relative = PurePosixPath(name)
            require(not relative.is_absolute() and '..' not in relative.parts and '\\' not in name,
                    'replacement state hash path')
            require(snapshot(private / relative).sha256 == digest, 'replacement original private state changed')
