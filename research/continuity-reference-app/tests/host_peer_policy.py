"""Independent original P CLI against actual account, publisher and witness."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
import os
import time
from native_exchange_fixture import b64, save
from qperiapt_continuity_reference.enrollment_exchange import encoded
from qperiapt_continuity_reference.wire import require


def adopt(root, peer, probe, witness, paths, run, selected, session):
    operation = b64(os.urandom(32))
    key_hash = hashlib.sha256(peer.key_file.read_bytes()).hexdigest()

    def cli(label, action, *extra, success=True, lost_stdout=False, witnessed=True):
        args = [*peer.policy_command, action, '--operation=' + operation, *extra]
        if witnessed: args += ['--witness-address', *witness.address]
        return run(args, 'ip-' + label, success=success, lost_stdout=lost_stdout)

    request_file = root / 'ip-request.json'
    request = cli('request', 'request', '--output', request_file)
    require(json.loads(request_file.read_bytes()) == request
            and request['application'] == peer.invitation['application']
            and request['enrollment'] == peer.invitation['operation']
            and request['scope']['journal'] == list(peer.journal)
            and request['scope']['current_roster'] == peer.current['roster']['checkpoint'],
            'independent request lost its original protected identity')
    request_retry = root / 'ip-request-retry.json'
    require(cli('request-retry', 'request', '--output', request_retry) == request
            and request_retry.read_bytes() == request_file.read_bytes(), 'independent request changed on retry')
    cli('missing-witness', 'request', '--output', root / 'ip-no-witness.json', witnessed=False, success=False)
    require(not (root / 'ip-no-witness.json').exists(), 'required witness silently became local')
    publisher, db, owner = paths['publisher'], root / 'publisher.redb', selected['publisher']
    target_id, old = b64(os.urandom(32)), selected['publication']
    publication = root / 'ip-target-publication.json'
    save(publication, dict(json.loads((root / 'policy-request.json').read_bytes()), valid_until=int(time.time()) + 3600))
    target_dir = root / 'ip-target'; target_dir.mkdir(mode=0o700)
    run([publisher, 'issue', db, owner, target_id, publication, target_dir], 'ip-target-issue')
    selection = root / 'ip-selected-policies.json'
    run([publisher, 'renewal-policies', db, owner, old, old, target_id, selection], 'ip-policies')
    policies = json.loads(selection.read_bytes())
    body = {'retained': request, 'original_extension': None, 'current_extension': None,
            **{k: policies[k] for k in ('original', 'previous', 'target')}}
    probe.login('bob', 'ip-relogin')
    preview = probe.request('bob', 'ip-account-preview', '/api/enrollment/policy-approval/preview', body)
    require(preview['state'] == 'Absent' and preview['review']['witness_required'] is True, 'independent P review differs')
    probe.request('bob', 'ip-account-lost', '/api/enrollment/policy-approval', body, lost=True)
    status = probe.request('bob', 'ip-account-status', '/api/enrollment/policy-approval/status', body)
    approved = probe.request('bob', 'ip-account-retry', '/api/enrollment/policy-approval', body, raw=True)
    require(status['state'] == 'Issued' and encoded(status['response'], 131072) == approved,
            'independent P issuer changed original result')
    issued = json.loads(approved)
    account_file = root / 'ip-account-approval.bin'; save(account_file, encoded(issued['approval'], 65536))
    policy_file = root / 'ip-policy-approval.bin'
    authority = run([publisher, 'renewal-approve', db, owner, request_file, root / 'peer-current.json',
                     old, old, target_id, policy_file], 'ip-policy-approve')
    require(authority['state'] == 'Issued' and authority['result']['statement'] == issued['statement'],
            'independent P roots approved different statements')
    inputs = ['--account-approval', account_file, '--policy-approval', policy_file,
              '--policy-pins', target_dir / 'policy-pins.json', '--policy-materials', target_dir / 'policy-materials.json']
    # A target requires both roots. Valid account approval in both slots is not sufficient.
    wrong = [*inputs]; wrong[3] = account_file
    cli('wrong-root', 'prepare', *wrong, '--output', root / 'ip-wrong-root.json', success=False)
    require(not (root / 'ip-wrong-root.json').exists() and not (peer.session_dir / 'intent').exists(),
            'wrong policy root reserved or exported a target')
    occupied = root / 'ip-occupied.json'; save(occupied, b'original policy export retained')
    cli('lost-export', 'prepare', *inputs, '--output', occupied, success=False)
    require(occupied.read_bytes() == b'original policy export retained', 'independent export overwrote original file')
    intent_hash = hashlib.sha256((peer.session_dir / 'intent').read_bytes()).hexdigest()
    preparation_file = root / 'ip-preparation.json'
    preparation = cli('recover-preparation', 'recover-preparation', '--output', preparation_file)
    require(preparation == json.loads(preparation_file.read_bytes()), 'independent original export differs')
    again = root / 'ip-preparation-retry.json'
    require(cli('prepare-retry', 'prepare', *inputs, '--output', again) == preparation
            and again.read_bytes() == preparation_file.read_bytes()
            and hashlib.sha256((peer.session_dir / 'intent').read_bytes()).hexdigest() == intent_hash,
            'independent retry changed sealed target')
    require(cli('unapproved-status', 'status') == 'Unavailable', 'independent unapproved P gained permission')
    cli('unapproved-commit', 'commit', success=False)
    peer.next(session, 'ip-pending-blocks-session', success=False)
    trust = root / 'ip-witness-trust.json'
    save(trust, {'schema': 'qperiapt-witness-policy-renewal-trust/1', 'account': peer.current,
        'device': peer.invitation['device'], 'generation': peer.invitation['generation'],
        'subject': b64(bytes(peer.prepared['subject'])), 'proposal_binding': preparation['binding'], 'request': request,
        **{k: policies[k] for k in ('original', 'previous', 'target')}})
    run(witness.command('policy-prepare', trust, preparation_file), 'ip-witness-lost-output', success=False, lost_stdout=True)
    require(run(witness.command('policy-prepare', trust, preparation_file), 'ip-witness-retry') ==
            {'binding': preparation['binding'], 'state': 'Prepared'}, 'independent witness original preparation absent')
    cli('commit-lost-output', 'commit', success=False, lost_stdout=True)
    require(cli('recover', 'recover') == 'Applied' and cli('status', 'status') == 'Applied',
            'independent P exact terminal recovery failed')
    cli('retired-export', 'recover-preparation', '--output', root / 'ip-retired.json', success=False)
    require(not (root / 'ip-retired.json').exists() and not (peer.session_dir / 'intent').exists(),
            'independent P retirement retained export authority')
    require(hashlib.sha256(peer.key_file.read_bytes()).hexdigest() == key_hash, 'independent P replaced wrapping key')
    return {'operation': operation, 'request': request, 'preparation': preparation, 'state': 'Applied',
            'account_approval': issued, 'policy_approval': authority['result'], 'original_intent_sha256': intent_hash,
            'original_key_unchanged': True, 'retired': True}
