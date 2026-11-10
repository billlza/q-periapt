"""Authenticated original independent G after P, with real output loss."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
import os
from native_exchange_fixture import b64, save
from qperiapt_continuity_reference.enrollment_exchange import encoded
from qperiapt_continuity_reference.local_renewal_protocol import Proposal
from qperiapt_continuity_reference.wire import require


def renew(root, peer, probe, witness, run, session):
    operation = b64(os.urandom(32)); key_hash = hashlib.sha256(peer.key_file.read_bytes()).hexdigest()
    def cli(label, action, *extra, success=True, lost_stdout=False, witnessed=True):
        args = [*peer.credential_command, action, '--operation=' + operation, *extra]
        if witnessed: args += ['--witness-address', *witness.address]
        return run(args, 'ig-' + label, success=success, lost_stdout=lost_stdout)
    request_file = root / 'ig-request.json'; request = cli('request', 'request', '--output', request_file)
    policies = json.loads((root / 'ip-selected-policies.json').read_bytes())
    policy = json.loads((root / 'ip-policy-approve.stdout').read_bytes())['result']
    pins = policies['target']['pins']
    require(request == json.loads(request_file.read_bytes()) and request['journal'] == list(peer.journal)
            and request['previous_checkpoint'] == peer.current['roster']['checkpoint']
            and request['current_policy'] == {'version': pins['policy_version'], 'digest': pins['policy_digest']}
            and request['current_policy_authorization'] == policy['statement'], 'independent G lost original P or identity')
    require(cli('request-retry', 'request', '--output', root / 'ig-request-retry.json') == request,
            'independent G request changed on retry')
    cli('missing-witness', 'request', '--output', root / 'ig-no-witness.json', witnessed=False, success=False)
    extension = {'request_id': list(os.urandom(32)), 'enrollment': peer.invitation['operation'],
                 'previous_extension': None, 'predecessor': peer.current['roster']['checkpoint'],
                 'valid_until': peer.invitation['valid_until'] + 3600}
    extended = probe.request('bob', 'ig-extension', '/api/enrollment/extend-credential', extension)
    target = probe.request('bob', 'ig-current', '/api/enrollment/root')
    require(extended['checkpoint'] == target['roster']['checkpoint'], 'independent G extension target differs')
    body = {'retained': request, 'original_extension': None, 'previous_extension': None,
            'successor_extension': extension['request_id'], 'target_checkpoint': extended['checkpoint']}
    require(probe.request('bob', 'ig-absent', '/api/enrollment/credential-grant/status', body) == {'state': 'Absent'},
            'independent G unexpectedly exists')
    probe.request('bob', 'ig-lost', '/api/enrollment/credential-grant', body, lost=True)
    observed = probe.request('bob', 'ig-issued-status', '/api/enrollment/credential-grant/status', body)
    issued_bytes = probe.request('bob', 'ig-retry', '/api/enrollment/credential-grant', body, raw=True)
    require(observed['state'] == 'Issued' and encoded(observed['response'], 131072) == issued_bytes,
            'independent G issuer replaced original result')
    issued = json.loads(issued_bytes)
    issued_file = root / 'ig-issued.json'; current_file = root / 'ig-current.json'
    save(issued_file, issued_bytes); save(current_file, target); save(root / 'ig-approval.json', body)
    for name, wrong in [('journal', list(os.urandom(32))), ('statement', list(os.urandom(32)))]:
        path = root / ('ig-wrong-' + name + '.json'); save(path, dict(issued, **{name: wrong}))
        cli('wrong-' + name, 'prepare', '--issued', path, '--current', current_file,
            '--output', root / ('ig-wrong-' + name + '-output.json'), success=False)
        require(not (peer.session_dir / 'intent').exists(), 'invalid G envelope reserved a target')
    args = ['--issued', issued_file, '--current', current_file]
    occupied = root / 'ig-occupied.json'; save(occupied, b'original credential export retained')
    cli('lost-export', 'prepare', *args, '--output', occupied, success=False)
    require(occupied.read_bytes() == b'original credential export retained', 'independent G overwrote original export')
    intent_hash = hashlib.sha256((peer.session_dir / 'intent').read_bytes()).hexdigest()
    prep_file = root / 'ig-preparation.json'
    prep = cli('recover-preparation', 'recover-preparation', '--output', prep_file)
    require(cli('prepare-retry', 'prepare', *args, '--output', root / 'ig-preparation-retry.json') == prep
            and hashlib.sha256((peer.session_dir / 'intent').read_bytes()).hexdigest() == intent_hash,
            'independent G retry replaced original target')
    require(cli('unapproved-status', 'status') == 'Unavailable', 'independent G acquired unapproved permission')
    cli('unapproved-commit', 'commit', success=False)
    peer.next(session, 'ig-pending-blocks-session', success=False)
    proposal = Proposal.decode(encoded(prep['proposal'], 4096))
    require(proposal.subject == bytes(peer.prepared['subject']) and proposal.policy == bytes(policy['statement'])
            and proposal.operation == bytes(issued['operation']) and proposal.statement == bytes(issued['statement']),
            'independent G proposal lost original policy or issuer binding')
    trust = root / 'ig-witness-trust.json'
    save(trust, {'schema': 'qperiapt-witness-credential-renewal-trust/1', 'account': target,
        'enrollment': peer.invitation['operation'], 'operation': issued['operation'], 'statement': issued['statement'],
        'subject': b64(bytes(peer.prepared['subject'])), 'proposal_binding': list(proposal.binding),
        'lineage': {'kind': 'independent', 'statement': list(proposal.policy)},
        'original': policies['original'], 'policy': policies['target']})
    run(witness.command('credential-prepare', trust, prep_file, issued_file), 'ig-witness-lost-output', success=False, lost_stdout=True)
    require(run(witness.command('credential-prepare', trust, prep_file, issued_file), 'ig-witness-retry') ==
            {'binding': list(proposal.binding), 'state': 'Prepared'}, 'independent G witness retry differs')
    cli('commit-lost-output', 'commit', success=False, lost_stdout=True)
    require(cli('recover', 'recover') == 'Applied' and cli('status', 'status') == 'Applied', 'independent G terminal differs')
    cli('retired-export', 'recover-preparation', '--output', root / 'ig-retired.json', success=False)
    cli('reused-request', 'request', '--output', root / 'ig-reused.json', success=False)
    require(not (root / 'ig-retired.json').exists() and not (root / 'ig-reused.json').exists()
            and not (peer.session_dir / 'intent').exists(), 'independent G retired operation was reused')
    require(hashlib.sha256(peer.key_file.read_bytes()).hexdigest() == key_hash, 'independent G changed wrapping key')
    peer.current = target
    return {'operation': operation, 'request': request, 'issued': issued, 'extension': extended,
            'preparation': prep, 'proposal_binding': list(proposal.binding), 'state': 'Applied', 'retired': True,
            'original_key_unchanged': True, 'original_intent_sha256': intent_hash}
