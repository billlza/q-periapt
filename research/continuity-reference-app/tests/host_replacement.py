#!/usr/bin/env python3
"""Authenticated account -> device generation replacement -> independent TCP traffic.

Real native account, device, witness and policy CLIs plus the independent Python
consumer. The account authenticator is an isolated software WebAuthn fixture;
this is not human/hardware Passkey or physical-device acceptance.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time

parser = argparse.ArgumentParser(description=__doc__)
for name in ('account-host', 'account-client', 'sdk-authority', 'publisher', 'witness',
             'native-device', 'native-session', 'native-outgoing', 'implementation-root', 'provider-root', 'output'):
    parser.add_argument('--' + name, type=Path, required=True)
args = parser.parse_args()
implementation = args.implementation_root.resolve(strict=True)
sys.path.insert(0, str(implementation))
from qperiapt_continuity_reference.provider import load_provider
provider, backend = load_provider(args.provider_root)
from qperiapt_continuity_reference.network import TcpTransport
from qperiapt_continuity_reference.connection_run import Cancellation
from qperiapt_continuity_reference.enrollment_exchange import encoded
from qperiapt_continuity_reference.wire import require
sys.path.insert(0, str(Path(__file__).resolve().parent))
from native_exchange_fixture import b64, save
from native_network_driver import NativeService, DropResponse
from independent_inbound_cli import Receiver
from witness_cli_exchange import WitnessHost
from host_replacement_process import Commands, AccountHost, AccountProbe, RecordingRelay, policy, fingerprints
from host_replacement_device import Native, Independent, authority, invite, approve, issued

root = args.output
require(root.is_absolute() and not root.exists(), 'fresh absolute private test output required')
root.mkdir(mode=0o700)
run = Commands(root)
paths = {name: getattr(args, name).resolve(strict=True) for name in
         ('account_host', 'account_client', 'sdk_authority', 'publisher', 'witness', 'native_device', 'native_session', 'native_outgoing')}
binaries = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths.values()}
result = {'schema_version': 1, 'kind': 'qperiapt.authenticated_device_replacement', 'completed': False,
          'release_claim_eligible': False, 'native_sha256': binaries, 'provider': provider.__version__,
          'implementation': str(implementation / 'qperiapt_continuity_reference/session_cli.py'), 'clock': 'actual OS time'}
host = probe = witness = receiver = recording = None
services = []
refusals = []


def current(probe, label):
    return probe.request('bob', label, '/api/enrollment/root')


def restart(label, account):
    host.stop(kill=True); host.start(label)
    probe.request(account, label + '-old-login', '/api/me', status=401)
    probe.login(account, label + '-login')


def refused_cli(peer, label, args):
    peer.cli(label, args, success=False); refusals.append(peer.label + '-' + label)


try:
    witness = WitnessHost(root, paths['witness'], run)
    family, start, selected_policy = policy(root, paths['sdk_authority'], paths['publisher'], witness, run)
    host = AccountHost(root, paths['account_host'], family, run); host.start('account-first')
    probe = AccountProbe(root, paths['account_client'], host.origin)
    for account in ('alice', 'bob'):
        probe.register(account)
        probe.request(account, account + '-prepare-root', '/api/enrollment/root/prepare', {})
    native = Native(root, paths['native_device'], paths['native_session'], probe, witness, run, start)
    original_authority, _ = authority(probe, 'bob', 'original-authority')
    original_invitation = invite(probe, 'bob', 'original-invitation')
    old = Independent(root, 'old', original_invitation, original_authority, implementation, args.provider_root, witness, run)
    approve(probe, 'bob', old.invitation, old.proof, 'old-approve')
    original_issuance = issued(probe, 'bob', old.invitation, 'old-issue')
    old.accept(original_issuance, current(probe, 'old-current')); old.prepare(native)
    old_snapshot = fingerprints(old.directory, old.session_dir)
    witness.enroll('old', old.prepared, old.current, bytes(old.invitation['device']), old.journal, encoded(old.issued['certificate'], 65536))
    # A target cannot create a previously unknown peer account by itself.
    native.admit(old.current, 'native-unknown-peer', success=False); refusals.append('native-unknown-peer')
    old_service = NativeService(root, 'old-native-service', paths['native_session'], native.inputs(old)); services.append(old_service)
    old_sid = old.connect(old_service.address, 'connect')
    require(old.connect(old_service.address, 'connect-retry') == old_sid, 'old session identity changed')
    save(root / 'associated-data.bin', b'authenticated replacement')
    first = old.next(old_sid, 'first-next')
    old.deliver(old_sid, first, b'before authenticated replacement', old_service.address, 'first-send')
    native.read(old_sid, first, b'before authenticated replacement', 'old-first-effect')
    pending = old.next(old_sid, 'lost-next')
    relay = DropResponse(old_service.address)
    old.deliver(old_sid, pending, b'old consumed effect with lost ACK', relay.address, 'lost-send', success=False)
    lost = relay.finish()
    save(root / 'old-lost.request', lost['request']); save(root / 'old-lost.response', lost['response'])
    require(old.cli('lost-status', ['message-status', '--session=' + old_sid, '--message=' + pending])['status'] == 'Committed',
            'lost ACK was mislabeled as confirmed')
    native.read(old_sid, pending, b'old consumed effect with lost ACK', 'old-lost-effect')
    require(TcpTransport(old_service.address)(lost['request'], time.monotonic() + 10, Cancellation()) == lost['response'],
            'old exact retry baseline differs')
    old_retained = fingerprints(old.directory, old.session_dir)
    save(root / 'old-state-before.json', {str(Path(p).relative_to(root)): h for p, h in old_retained.items()})
    native_identity = native.status('native-before-replacement')
    witness_keys = witness.keys(); save(root / 'witness-keys-before.json', witness_keys)

    # The actual account host chooses generation2 and signs its exact current roster.
    replacement_request = {'request_id': list(os.urandom(32)), 'enrollment': old.invitation['operation'],
                           'predecessor': old.current['roster']['checkpoint']}
    save(root / 'replacement-request.json', replacement_request)
    probe.request('bob', 'replacement-invitation-lost', '/api/enrollment/replace-device', replacement_request, lost=True)
    restart('account-after-invitation-loss', 'bob')
    next_invitation = probe.request('bob', 'replacement-invitation', '/api/enrollment/replace-device', replacement_request)
    require(probe.request('bob', 'replacement-invitation-retry', '/api/enrollment/replace-device', replacement_request) == next_invitation,
            'invitation recovery changed the original decision')
    require(next_invitation['device'] == old.invitation['device'] and next_invitation['generation'] == 2
            and next_invitation['root'] == old.invitation['root'], 'host changed replacement identity or root')
    next_authority, _ = authority(probe, 'bob', 'replacement-authority')
    require(next_authority == original_authority, 'account authority changed during replacement')
    new = Independent(root, 'new', next_invitation, next_authority, implementation, args.provider_root, witness, run)
    require(new.signing_id != old.signing_id and new.public != old.public, 'replacement reused the old signing owner or key')
    save(root / 'signing-identities.json', {label: {'signing_id': b64(peer.signing_id),
        'public_sha256': hashlib.sha256(peer.public).hexdigest()} for label, peer in [('old', old), ('new', new)]})
    approve(probe, 'bob', new.invitation, new.proof, 'new-approve')
    issued(probe, 'bob', new.invitation, 'new-issue-lost', lost=True)
    restart('account-after-issuance-loss', 'bob')
    next_issuance = issued(probe, 'bob', new.invitation, 'new-issue')
    require(issued(probe, 'bob', new.invitation, 'new-issue-retry') == next_issuance, 'issuance recovery changed bytes')
    require(issued(probe, 'bob', old.invitation, 'old-issue-after-replacement') == original_issuance, 'old issuance history changed')
    next_root = current(probe, 'new-current')
    new.accept(next_issuance, next_root); new.prepare(native)
    require(new.journal != old.journal, 'replacement reset the old journal identity')
    before_unadmitted = fingerprints(new.directory, new.session_dir)
    new_service = NativeService(root, 'new-native-service', paths['native_session'], native.inputs(new)); services.append(new_service)
    new.connect(new_service.address, 'before-witness', success=False); refusals.append('new-before-witness')
    require(fingerprints(new.directory, new.session_dir) == before_unadmitted, 'unadmitted successor changed its original state')
    trust = {'schema': 'qperiapt-witness-device-replacement-trust/1', 'successor': {
        'schema': 'qperiapt-witness-enrollment-trust/1', 'account': next_root,
        'device': new.invitation['device'], 'generation': 2, 'journal': list(new.journal),
        'genesis_head': new.prepared['head'], 'certificate': new.issued['certificate'],
        'policy': {'pins': json.loads((root / 'policy-pins.json').read_bytes()),
                   'materials': json.loads((root / 'policy-materials.json').read_bytes())}},
        'predecessors': [{'subject': b64(bytes(old.prepared['subject'])), 'checkpoint': old.current['roster']['checkpoint'],
                          'policy': {'pins': json.loads((root / 'policy-pins.json').read_bytes()),
                                     'materials': json.loads((root / 'policy-materials.json').read_bytes())}}]}
    save(root / 'replacement-trust.json', trust); save(root / 'replacement-preparation.json', new.prepared)
    decision_dir = root / 'replacement-decision'; decision_dir.mkdir(mode=0o700)
    decision = run(witness.command('replacement-prepare', root / 'replacement-trust.json', root / 'replacement-preparation.json', decision_dir),
                   'replacement-witness-prepare')
    decision_file = decision_dir / 'device-replacement-decision.json'
    require(json.loads(decision_file.read_bytes()) == decision, 'retained witness decision differs')
    run(witness.command('replacement-commit', root / 'replacement-trust.json', root / 'replacement-preparation.json', decision_file),
        'replacement-witness-lost-commit', success=False, lost_stdout=True)
    observed = run(witness.command('replacement-status', decision_file), 'replacement-witness-status')
    require(observed == {'binding': decision['binding'], 'status': 'Committed'}, 'witness commit was not recovered')
    refused_cli(old, 'retired-next', ['next', '--session=' + old_sid])
    old.deliver(old_sid, pending, None, old_service.address, 'retired-resume', success=False, resume=True)
    require(fingerprints(old.directory, old.session_dir) == old_retained, 'retired old installation was modified or recreated')

    # The surviving native journal must explicitly adopt the signed peer change.
    recording = RecordingRelay(root, new_service.address)
    new.connect(recording.address, 'before-peer-roster', success=False); refusals.append('new-before-peer-roster')
    require(len(recording.rows) == 1 and recording.rows[0]['outcome'] == 'refused', 'missing actual pre-admission refusal')
    native.admit(next_root, 'native-peer-roster-lost-output', success=False, lost=True)
    native.admit(next_root, 'native-peer-roster-retry')
    native.admit(old.current, 'native-peer-roster-rollback', success=False); refusals.append('native-peer-roster-rollback')
    require(old_service.process.poll() is None, 'old-context service was not live for the replay check')
    try:
        TcpTransport(old_service.address)(lost['request'], time.monotonic() + 10, Cancellation())
    except (OSError, ValueError) as error:
        save(root / 'old-cached-frame-refusal.txt', str(error).encode()); refusals.append('old-cached-frame')
    else:
        raise ValueError('retired generation released a cached session response')
    new_sid = new.connect(recording.address, 'connect')
    relay_stats = recording.close()
    require([r['kind'] for r in recording.rows] == [1, 1, 2]
            and [r['outcome'] for r in recording.rows] == ['refused', 'response', 'response']
            and recording.rows[0]['request_sha256'] == recording.rows[1]['request_sha256'],
            'peer roster admission did not recover the exact original bootstrap')
    require(new_sid != old_sid and new.connect(new_service.address, 'connect-retry') == new_sid, 'replacement session identity differs')
    message = new.next(new_sid, 'message-next')
    new.deliver(new_sid, message, b'after authenticated replacement', new_service.address, 'message-send')
    native.read(new_sid, message, b'after authenticated replacement', 'new-effect')
    require(new.cli('rekey', ['rekey', '--session=' + new_sid, '--target', '1', '--address', *new_service.address]) ==
            {'session': new_sid, 'epoch': 1, 'exchanges': 2}, 'new generation rekey failed')
    inbox = root / 'new-independent-inbox'; inbox.mkdir(mode=0o700)
    new.cli('inbox', ['provision-inbox', '--session=' + new_sid, '--inbox-directory', inbox])
    receiver = Receiver(root, 'new-independent-service', new.command, new_sid, inbox, witness_address=witness.address)
    def native_action(label, action):
        path = root / (label + '.json'); save(path, dict(native.inputs(new), schema='qperiapt-native-outgoing/1', action=action))
        return run([paths['native_outgoing'], path, new_sid], label)
    reverse_message = bytes(native_action('native-reverse-next', {'operation': 'next'})['message'])
    reverse_body = b'original native owner to replacement generation'
    require(native_action('native-reverse-send', {'operation': 'deliver_tcp', 'message': list(reverse_message),
            'plaintext': list(reverse_body), 'associated_data': [], 'address': f'{receiver.address[0]}:{receiver.address[1]}'}) ==
            {'consumption': 'Confirmed'}, 'reverse delivery failed')
    receiver.stop()
    new.cli('read-reverse', ['read-inbox', '--session=' + new_sid, '--inbox-directory', inbox,
                           '--message=' + b64(reverse_message), '--output', root / 'reverse-effect.bin'])
    require((root / 'reverse-effect.bin').read_bytes() == reverse_body, 'independent durable reverse effect differs')
    new_service.stop(kill=True); witness.service.stop(kill=True); witness.start('witness-reopened')
    reopened = NativeService(root, 'new-native-service-reopened', paths['native_session'], native.inputs(new)); services.append(reopened)
    require(new.connect(reopened.address, 'after-service-restart') == new_sid, 'restart changed new session')
    after_restart = new.next(new_sid, 'after-restart-next')
    require(int.from_bytes(encoded(after_restart, 32, 32)[:8], 'big') == 1, 'restart lost the confirmed rekey epoch')
    new.deliver(new_sid, after_restart, b'new traffic after both service restarts', reopened.address, 'after-restart-send')
    native.read(new_sid, after_restart, b'new traffic after both service restarts', 'after-restart-effect')
    require(old_service.process.poll() is None, 'old-context service not live after witness restart')
    try:
        TcpTransport(old_service.address)(lost['request'], time.monotonic() + 10, Cancellation())
    except (OSError, ValueError) as error:
        save(root / 'old-cached-frame-after-restart-refusal.txt', str(error).encode()); refusals.append('old-cached-frame-after-restart')
    else:
        raise ValueError('service restart revived the old cached response')
    refused_cli(old, 'retired-after-restart', ['next', '--session=' + old_sid])
    require(fingerprints(old.directory, old.session_dir) == old_retained, 'old files changed after restart refusal')
    require(native.status('native-final-status') == native_identity, 'surviving native installation identity changed')
    require(witness.keys() == witness_keys, 'witness restart changed original protected keys')
    save(root / 'witness-keys-after.json', witness.keys())
    save(root / 'old-state-after.json', {str(Path(p).relative_to(root)): h
        for p, h in fingerprints(old.directory, old.session_dir).items()})
    require(issued(probe, 'bob', new.invitation, 'new-issue-final') == next_issuance, 'account result changed after traffic')
    require(issued(probe, 'bob', old.invitation, 'old-issue-final') == original_issuance, 'account lost old issuance')
    native.read(old_sid, pending, b'old consumed effect with lost ACK', 'old-effect-retained')
    for service in services:
        if service.result is None: service.stop()
    witness.close(); host.close(); probe.finish()
    require({str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths.values()} == binaries, 'native executable changed')
    result.update(completed=True, old_session=old_sid, new_session=new_sid, confirmed_epoch=1,
        old_journal=b64(old.journal), new_journal=b64(new.journal), native_journal=b64(native.journal),
        old_generation=1, new_generation=2, device=old.invitation['device'], witness_decision=observed,
        old_state_unchanged=True, native_identity_unchanged=True, witness_keys_unchanged=True,
        effects=5, original_bootstrap_recovered=True, frames=recording.rows, relay=relay_stats, services=[s.result for s in services], witness_services=[s.result for s in witness.services],
        account_services=host.services, independent_service=receiver.result,
        scope='Software Passkey authentication via real native HTTP host; original account survives two process kills and lost invite/issue replies. Independent fresh generation2, actual witness commit with lost stdout, explicit peer-roster admission, old cached/retired traffic denied, original native owner receives new-session messages and replies after rekey, witness/native restart preserves identities. No human Passkey, cross-host, mobile/package or PCS claim.')
except BaseException as error:
    result['failure'] = str(error)
    raise
finally:
    errors = []
    for close in ([recording.close] if recording else []) + ([probe.close] if probe else []) + ([host.close] if host else []) + ([witness.close] if witness else []) + \
                 ([receiver.stop] if receiver is not None and receiver.result is None else []) + \
                 [s.stop for s in services if s.result is None]:
        try: close()
        except BaseException as error: errors.append(str(error))
    result.update(commands=run.rows, refusals=refusals, account_requests=[] if probe is None else probe.rows, cleanup_errors=errors)
    if errors: result['completed'] = False
    save(root / 'RESULT.json', result)
    if errors: raise RuntimeError('replacement fixture cleanup failed: ' + '; '.join(errors))
print(json.dumps(result))
