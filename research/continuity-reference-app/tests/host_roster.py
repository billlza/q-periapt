#!/usr/bin/env python3
"""HTTP-authorized sibling replacement, surviving native R and original session.

Real software WebAuthn, account/device/witness processes and independent TCP
consumer; actual time, no account-root fixture and no physical-device claim.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

parser = argparse.ArgumentParser(description=__doc__)
for name in ('account-host', 'account-client', 'sdk-authority', 'publisher', 'witness',
             'native-device', 'native-session', 'native-outgoing', 'implementation-root', 'provider-root', 'output'):
    parser.add_argument('--' + name, type=Path, required=True)
args = parser.parse_args()
implementation = args.implementation_root.resolve(strict=True)
sys.path.insert(0, str(implementation))
from qperiapt_continuity_reference.provider import load_provider
provider, backend = load_provider(args.provider_root)
from qperiapt_continuity_reference.enrollment_exchange import encoded
from qperiapt_continuity_reference.wire import require
sys.path.insert(0, str(Path(__file__).resolve().parent))
from native_exchange_fixture import b64, save
from native_network_driver import NativeService, DropResponse
from independent_inbound_cli import Receiver
from witness_cli_exchange import WitnessHost
from host_replacement_process import Commands, AccountHost, AccountProbe, policy, fingerprints
from host_replacement_device import Native, Independent, authority, invite, approve, issued

root = args.output
require(root.is_absolute() and not root.exists(), 'fresh absolute private test output required')
root.mkdir(mode=0o700)
run = Commands(root)
paths = {name: getattr(args, name).resolve(strict=True) for name in
         ('account_host', 'account_client', 'sdk_authority', 'publisher', 'witness', 'native_device', 'native_session', 'native_outgoing')}
binaries = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths.values()}
result = {'schema_version': 1, 'kind': 'qperiapt.authenticated_surviving_device_roster', 'completed': False,
          'release_claim_eligible': False, 'native_sha256': binaries, 'provider': provider.__version__, 'clock': 'actual OS time',
          'implementation': str(implementation / 'qperiapt_continuity_reference/session_cli.py')}
host = probe = witness = receiver = None
services, transitions = [], []


def refresh(native, target, label):
    policy_input = {'pins': json.loads((root / 'policy-pins.json').read_bytes()),
                    'materials': json.loads((root / 'policy-materials.json').read_bytes())}
    selection = root / (label + '-inputs.json')
    save(selection, {'schema': 'qperiapt-roster-refresh-inputs/1', 'target': target,
                     'original': policy_input, 'policy': policy_input})
    history = root / (label + '-history.json'); save(history, policy_input)
    operation = b64(os.urandom(32)); request_file = root / (label + '-request.json')
    occupied = root / (label + '-occupied.json'); save(occupied, b'original export retained')
    run([native.binary, 'roster-prepare', *native.common, operation, selection, witness.endpoint(), occupied],
        label + '-lost-export', success=False)
    require(occupied.read_bytes() == b'original export retained', 'export overwrote original file')
    request = run([native.binary, 'roster-recover-preparation', *native.common, operation, history, request_file],
                  label + '-recover-original')
    require(json.loads(request_file.read_bytes()) == request, 'recovered request file differs')
    pending = run([native.binary, 'roster-commit', *native.common, request_file, selection, witness.endpoint()], label + '-unapproved')
    require(pending == {'binding': request['binding'], 'state': 'Unavailable'}, 'unapproved target was not unavailable')
    run([native.binary, 'activate', *native.active_args], label + '-pending-activation', success=False)
    approved = root / (label + '-trust.json')
    save(approved, {'schema': 'qperiapt-witness-roster-refresh-trust/1', 'account': target,
        'device': native.invitation['device'], 'generation': native.invitation['generation'],
        'subject': b64(bytes(native.prepared['subject'])), 'proposal_binding': request['binding'], 'policy': policy_input})
    run(witness.command('roster-prepare', approved, request_file), label + '-witness-lost-output', success=False, lost_stdout=True)
    require(run(witness.command('roster-prepare', approved, request_file), label + '-witness-retry') ==
            {'binding': request['binding'], 'state': 'Prepared'}, 'original witness preparation differs')
    run([native.binary, 'roster-commit', *native.common, request_file, selection, witness.endpoint()],
        label + '-commit-lost-output', success=False, lost_stdout=True)
    observed = run([native.binary, 'roster-observe', *native.common, request_file, history, witness.endpoint()], label + '-observe')
    require(observed == {'binding': request['binding'], 'state': 'Applied'}, 'original R outcome not recovered')
    progress = run([native.binary, 'roster-status', *native.common], label + '-status')
    require(progress['state'] == 'Applied' and progress['retired'] is True, 'R retirement absent')
    run([native.binary, 'activate', *native.active_args], label + '-old-current', success=False)
    native.current = target; native.current_path = root / (label + '-current.json'); save(native.current_path, target)
    native.local_inputs = [native.current_path, root / 'policy-pins.json', root / 'policy-materials.json']
    native.active_args = [*native.common, *native.local_inputs, witness.endpoint()]
    activated = run([native.binary, 'activate', *native.active_args], label + '-activate')
    require(bytes(activated['journal']) == native.journal, 'R changed original journal')
    transitions.append({'operation': operation, 'binding': request['binding'], 'progress': progress, 'observation': observed})


try:
    witness = WitnessHost(root, paths['witness'], run)
    family, start, selected = policy(root, paths['sdk_authority'], paths['publisher'], witness, run)
    host = AccountHost(root, paths['account_host'], family, run); host.start('account-first')
    probe = AccountProbe(root, paths['account_client'], host.origin)
    for account in ('alice', 'bob'):
        probe.register(account); probe.request(account, account + '-root', '/api/enrollment/root/prepare', {})
    native = Native(root, paths['native_device'], paths['native_session'], probe, witness, run, start)
    initial = native.status('survivor-initial')
    keys = {p: p.read_bytes() for p in (native.directory / 'device.key', root / 'native-wrap.key')}
    save(root / 'protected-before.json', {str(p.relative_to(root)):hashlib.sha256(v).hexdigest() for p,v in keys.items()})
    witness_keys = witness.keys()
    auth, _ = authority(probe, 'bob', 'peer-authority')
    peer = Independent(root, 'peer', invite(probe, 'bob', 'peer-invitation'), auth, implementation, args.provider_root, witness, run)
    approve(probe, 'bob', peer.invitation, peer.proof, 'peer-approve')
    peer.accept(issued(probe, 'bob', peer.invitation, 'peer-issue'), probe.request('bob', 'peer-current', '/api/enrollment/root'))
    peer.prepare(native)
    witness.enroll('peer', peer.prepared, peer.current, bytes(peer.invitation['device']), peer.journal, encoded(peer.issued['certificate'],65536))
    service = NativeService(root, 'survivor-first', paths['native_session'], native.inputs(peer)); services.append(service)
    sid = peer.connect(service.address, 'connect')
    save(root / 'associated-data.bin', b'original session across own roster')
    message = peer.next(sid, 'lost-next')
    relay = DropResponse(service.address)
    peer.deliver(sid, message, b'pending before sibling addition', relay.address, 'lost-send', success=False)
    lost = relay.finish(); save(root / 'lost.request', lost['request']); save(root / 'lost.response', lost['response'])
    require(peer.cli('pending-status', ['message-status','--session='+sid,'--message='+message])['status'] == 'Committed', 'lost ACK became confirmed')
    native.read(sid,message,b'pending before sibling addition','pending-effect')
    service.stop()
    auth, _ = authority(probe,'alice','sibling-authority')
    sibling = Independent(root,'sibling',invite(probe,'alice','sibling-invitation'),auth,implementation,args.provider_root,witness,run)
    approve(probe,'alice',sibling.invitation,sibling.proof,'sibling-approve')
    sibling_issue = issued(probe,'alice',sibling.invitation,'sibling-issue')
    target = probe.request('alice','added-current','/api/enrollment/root')
    sibling.accept(sibling_issue,target)
    sibling_files = fingerprints(sibling.directory)
    refresh(native,target,'addition')
    service = NativeService(root,'survivor-after-add',paths['native_session'],native.inputs(peer)); services.append(service)
    peer.deliver(sid,message,None,service.address,'resume-original-after-add',resume=True)
    native.read(sid,message,b'pending before sibling addition','original-effect-after-add')
    service.stop()
    replacement = {'request_id':list(os.urandom(32)), 'enrollment':sibling.invitation['operation'], 'predecessor':target['roster']['checkpoint']}
    probe.request('alice','sibling-replace-lost','/api/enrollment/replace-device',replacement,lost=True)
    host.stop(kill=True); host.start('account-reopened')
    probe.request('alice','expired-login','/api/me',status=401); probe.login('alice','alice-relogin')
    invitation = probe.request('alice','sibling-replace-recovered','/api/enrollment/replace-device',replacement)
    require(invitation['device'] == sibling.invitation['device'] and invitation['generation'] == 2, 'replacement changed sibling identity')
    successor = Independent(root,'successor',invitation,auth,implementation,args.provider_root,witness,run)
    approve(probe,'alice',invitation,successor.proof,'successor-approve')
    successor_issue = issued(probe,'alice',invitation,'successor-issue')
    target = probe.request('alice','replacement-current','/api/enrollment/root')
    successor.accept(successor_issue,target)
    require(successor.public != sibling.public and successor.journal != sibling.journal, 'sibling replacement reused identity state')
    refresh(native,target,'replacement')
    witness.service.stop(kill=True); witness.start('witness-reopened')
    service = NativeService(root,'survivor-after-replacement',paths['native_session'],native.inputs(peer)); services.append(service)
    require(peer.connect(service.address,'original-bootstrap-retry') == sid, 'R replaced the original session')
    require(peer.cli('rekey',['rekey','--session='+sid,'--target','1','--address',*service.address]) ==
            {'session':sid,'epoch':1,'exchanges':2}, 'original session rekey after R failed')
    fresh = peer.next(sid,'fresh-next')
    peer.deliver(sid,fresh,b'after sibling replacement',service.address,'fresh-send')
    native.read(sid,fresh,b'after sibling replacement','fresh-effect')
    inbox = root / 'peer-inbox'; inbox.mkdir(mode=0o700)
    peer.cli('inbox',['provision-inbox','--session='+sid,'--inbox-directory',inbox])
    receiver = Receiver(root,'peer-receiver',peer.command,sid,inbox,witness_address=witness.address)
    def outgoing(label, action):
        path = root / (label+'.json'); save(path,dict(native.inputs(peer),schema='qperiapt-native-outgoing/1',action=action))
        return run([paths['native_outgoing'],path,sid],label)
    reverse = outgoing('reverse-next',{'operation':'next'})['message']
    require(outgoing('reverse-send',{'operation':'deliver_tcp','message':reverse,'plaintext':list(b'surviving original owner'),
            'associated_data':[],'address':f'{receiver.address[0]}:{receiver.address[1]}'}) == {'consumption':'Confirmed'}, 'reverse delivery failed')
    receiver.stop()
    peer.cli('read-reverse',['read-inbox','--session='+sid,'--inbox-directory',inbox,'--message='+b64(bytes(reverse)),'--output',root/'reverse.bin'])
    require((root/'reverse.bin').read_bytes() == b'surviving original owner', 'reverse effect differs')
    require(native.status('survivor-final') == initial and all(p.read_bytes()==v for p,v in keys.items()), 'survivor identity changed')
    save(root / 'protected-after.json', {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in keys})
    require(fingerprints(sibling.directory) == sibling_files, 'old sibling installation was changed')
    require(witness.keys() == witness_keys, 'witness keys changed')
    require(issued(probe,'alice',sibling.invitation,'sibling-history') == sibling_issue, 'old sibling issuance lost')
    for s in services:
        if s.result is None: s.stop()
    witness.close(); host.close(); probe.finish()
    require({str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths.values()} == binaries, 'native bytes changed')
    result.update(completed=True, session=sid, confirmed_epoch=1, journal=b64(native.journal),
        transitions=transitions, effects=3, original_pending_message=message, original_keys_unchanged=True,
        sibling_generation=1, successor_generation=2, old_sibling_unchanged=True,
        services=[s.result for s in services], witness_services=[s.result for s in witness.services], account_services=host.services,
        independent_service=receiver.result,
        scope='Two own-account R transitions from real authenticated HTTP addition/replacement. Original native keys, journal, session and pending effect retained; witness/operator and commit stdout loss, account/witness restarts, original rekey and bidirectional traffic. Sibling acceptance only, not sibling runtime activation. No human Passkey, cross-host, mobile or PCS claim.')
except BaseException as error:
    result['failure'] = str(error)
    raise
finally:
    errors = []
    for close in ([probe.close] if probe else []) + ([host.close] if host else []) + ([witness.close] if witness else []) + \
                 ([receiver.stop] if receiver is not None and receiver.result is None else []) + [s.stop for s in services if s.result is None]:
        try: close()
        except BaseException as error: errors.append(str(error))
    result.update(commands=run.rows, account_requests=[] if probe is None else probe.rows, cleanup_errors=errors)
    if errors: result['completed'] = False
    save(root / 'RESULT.json', result)
    if errors: raise RuntimeError('roster fixture cleanup failed: ' + '; '.join(errors))
print(json.dumps(result))
