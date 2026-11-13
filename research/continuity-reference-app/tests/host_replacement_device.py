"""Real native and independent device commands under HTTP-authorized invitations."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import json
import os
import sys
import time
from native_exchange_fixture import b64, save, wire
from host_replacement_process import fingerprints
from qperiapt_continuity_reference.enrollment_client import EnrollmentClient
from qperiapt_continuity_reference.enrollment_exchange import HostAuthority, HostInvitation, encoded
from qperiapt_continuity_reference.publication import Publication
from qperiapt_continuity_reference.wire import require


def authority(probe, account, label):
    identity = probe.request(account, label + '-identity', '/api/me')
    current = probe.request(account, label + '-root', '/api/enrollment/root')
    return {'schema': 'qperiapt-host-authority/1',
            'application': list(encoded(identity['application_id'], 32, 32)),
            'root_revision': current['revision'], 'root': current['public_key'], 'family': current['family']}, current


def invite(probe, account, label):
    return probe.request(account, label, '/api/enrollment/invite', {'request_id': list(os.urandom(32))})


def approve(probe, account, invitation, proof, label):
    probe.request(account, label, '/api/enrollment/approve',
                  {'operation': invitation['operation'], 'request': b64(proof)}, status=204)


def issued(probe, account, invitation, label, *, lost=False):
    return probe.request(account, label, '/api/enrollment/issue', {'operation': invitation['operation']}, lost=lost, raw=True)


class Native:
    def __init__(self, root, binary, session, probe, witness, run, start, *, defer_preparation=False):
        self.root, self.binary, self.session, self.run, self.witness = root, binary, session, run, witness
        self.label = 'native'
        self.directory = root / 'native-device'; self.directory.mkdir(mode=0o700)
        self.invitation = invite(probe, 'alice', 'native-invitation')
        save(root / 'native-invitation.json', self.invitation)
        self.common = [self.directory, root / 'native-wrap.key', root / 'native-invitation.json']
        run([binary, 'provision-key', root / 'native-wrap.key'], 'native-key', json_output=False)
        run([binary, 'begin', *self.common], 'native-begin')
        run([binary, 'request', *self.common, root / 'native-request.bin'], 'native-request')
        approve(probe, 'alice', self.invitation, (root / 'native-request.bin').read_bytes(), 'native-approve')
        self.issued_raw = issued(probe, 'alice', self.invitation, 'native-issue')
        self.issued = json.loads(self.issued_raw); save(root / 'native-issued.json', self.issued_raw)
        _, self.current = authority(probe, 'alice', 'native-authority')
        save(root / 'native-current.json', self.current)
        self.current_path = root / 'native-current.json'
        self.original_policy = None
        self.policy_input = None
        self.local_inputs = [self.current_path, root / 'policy-pins.json', root / 'policy-materials.json']
        accepted = run([binary, 'accept', *self.common, root / 'native-issued.json', *self.local_inputs], 'native-accept')
        self.journal = bytes(accepted['journal'])
        if not defer_preparation:
            self.prepare_and_publish(start)

    def prepare_and_publish(self, start):
        root, binary, session, run, witness = self.root, self.binary, self.session, self.run, self.witness
        self.prepared = run([binary, 'prepare', *self.common, *self.local_inputs], 'native-prepare')
        witness.enroll('native', self.prepared, self.current, bytes(self.invitation['device']), self.journal,
                       encoded(self.issued['certificate'], 65536))
        witness.start('witness-first')
        self.active_args = [*self.common, *self.local_inputs, witness.endpoint()]
        publication = run([binary, 'publication-next', *self.active_args], 'native-publication-id')['publication']
        self.context_directory = os.urandom(32)
        invalid = {'schema': 'qperiapt-native-publication-plan/1', 'directory': list(self.context_directory),
                   'valid_from': self.invitation['valid_from'] - 1, 'valid_until': min(start + 1200, self.invitation['valid_until'])}
        save(root / 'native-invalid-plan.json', invalid)
        rejected = root / 'rejected-publication'; rejected.mkdir(mode=0o700)
        before = fingerprints(self.directory)
        private_keys = {p: p.read_bytes() for p in (self.directory / 'device.key', root / 'native-wrap.key')}
        previous_status = self.status('native-before-invalid-publication')
        run([binary, 'publish', *self.active_args, b64(bytes(publication)), root / 'native-invalid-plan.json', rejected],
            'native-refuse-precredential-publication', success=False)
        after_status = self.status('native-after-invalid-publication')
        save(root / 'invalid-publication-state.json', {'before_files': before, 'after_files': fingerprints(self.directory),
                                                     'before_status': previous_status, 'after_status': after_status})
        require(not list(rejected.iterdir()) and after_status == previous_status
                and all(p.read_bytes() == value for p, value in private_keys.items()),
                'invalid publication changed original identity/key or released an artifact')
        require(run([binary, 'publication-next', *self.active_args], 'native-publication-id-after-refusal')['publication'] == publication,
                'invalid publication reserved an ordinal')
        save(root / 'native-plan.json', dict(invalid, valid_from=int(time.time())))
        self.published = root / 'published'; self.published.mkdir(mode=0o700)
        run([binary, 'publish', *self.active_args, b64(bytes(publication)), root / 'native-plan.json', self.published], 'native-publish')
        self.publication = Publication.decode((self.published / 'publication.json').read_bytes())
        run([session, 'provision-inbox', root / 'inbox.redb', b64(self.journal)], 'native-inbox')
        self.original_status = self.status('native-original-status')

    def status(self, label):
        return self.run([self.binary, 'status', *self.common], label)

    def inputs(self, peer):
        result = {'device_directory': str(self.directory), 'wrapping_key': str(self.root / 'native-wrap.key'),
                'invitation': str(self.root / 'native-invitation.json'), 'current_root': str(self.current_path),
                'policy_pins': str(self.local_inputs[1]), 'policy_materials': str(self.local_inputs[2]),
                'witness_endpoint': self.witness.endpoint(), 'peer_trust': str(peer.trust_path), 'bundle': str(peer.bundle_path)}
        if self.original_policy is not None:
            result['original_policy'] = str(self.original_policy)
        return result

    def admit(self, target, label, *, success=True, lost=False):
        path = self.root / (label + '-target.json'); save(path, target)
        value = self.run([self.binary, 'admit-peer-roster', *self.active_args, path], label, success=success, lost_stdout=lost)
        if success:
            require(value == {'peer_roster': target['roster']['checkpoint']}, 'peer current-target observation differs')
        return value

    def read(self, sid, message, expected, label):
        path = self.root / (label + '.bin')
        self.run([self.session, 'read-inbox', self.root / 'inbox.redb', b64(self.journal), sid, message, path], label)
        require(path.read_bytes() == expected, 'native durable application delivery differs')


class Independent:
    def __init__(self, root, label, invitation, authority, implementation, provider, witness, run):
        self.root, self.label, self.invitation = root, label, invitation
        self.witness, self.run = witness, run
        self.directory, self.session_dir = root / (label + '-client'), root / (label + '-session')
        self.directory.mkdir(mode=0o700); self.session_dir.mkdir(mode=0o700)
        self.client_id, self.key = os.urandom(32), os.urandom(32)
        self.key_file = root / (label + '-wrap.key'); save(self.key_file, self.key)
        save(root / (label + '-invitation.json'), invitation)
        save(root / (label + '-authority.json'), authority)
        owner = EnrollmentClient.begin(self.directory, self.client_id, self.key, wire(authority), wire(invitation), int(time.time()))
        try:
            self.proof = owner.request(int(time.time()))
        finally:
            owner.close()
        save(root / (label + '-request.bin'), self.proof)
        offer = HostInvitation.decode(wire(invitation), HostAuthority.from_trusted(wire(authority)))
        self.signing_id, public = offer.intent.verify_request(self.proof, int(time.time()))
        self.public = public.raw
        self.command = [sys.executable, '-I', '-S', '-B', '-c',
            f'import sys; sys.path.insert(0,{str(implementation)!r}); from qperiapt_continuity_reference.session_cli import main; raise SystemExit(main())',
            '--provider-root', provider, '--directory', self.directory, '--client-id', self.client_id.hex(), '--key-file', self.key_file]
        self.policy_command = [sys.executable, '-I', '-S', '-B', '-c',
            f'import sys; sys.path.insert(0,{str(implementation)!r}); from qperiapt_continuity_reference.policy_cli import main; raise SystemExit(main())',
            '--provider-root', provider, '--directory', self.directory, '--client-id', self.client_id.hex(), '--key-file', self.key_file]
        self.credential_command = [sys.executable, '-I', '-S', '-B', '-c',
            f'import sys; sys.path.insert(0,{str(implementation)!r}); from qperiapt_continuity_reference.credential_cli import main; raise SystemExit(main())',
            '--provider-root', provider, '--directory', self.directory, '--client-id', self.client_id.hex(), '--key-file', self.key_file]

    def accept(self, issued_raw, current):
        self.issued_raw, self.issued, self.current = issued_raw, json.loads(issued_raw), current
        self.issued_path = self.root / (self.label + '-issued.json'); save(self.issued_path, issued_raw)
        save(self.root / (self.label + '-current.json'), current)
        owner = EnrollmentClient.open(self.directory, self.client_id, self.key)
        try:
            self.journal = owner.accept(wire(self.invitation), issued_raw, wire(current),
                (self.root / 'policy-pins.json').read_bytes(), (self.root / 'policy-materials.json').read_bytes(), int(time.time()))
        finally:
            owner.close()

    def cli(self, label, args, *, success=True, selected=True):
        extra = ['--witness-address', *self.witness.address] if selected and args[0] not in ('prepare', 'provision-inbox', 'read-inbox', 'recover-inbox') else []
        return self.run([*self.command, *args, *extra], self.label + '-' + label, success=success)

    def prepare(self, native):
        self.trust_path = self.root / (self.label + '-trust.json')
        self.bundle_path = self.root / (self.label + '-bundle.bin')
        save(self.trust_path, {'schema': 'qperiapt-native-peer-trust/1', 'directory': list(native.context_directory),
            'initiator': {'current': self.current, 'device': self.invitation['device'], 'generation': self.invitation['generation']},
            'responder': {'current': native.current, 'device': native.invitation['device'], 'generation': native.invitation['generation']}})
        save(self.bundle_path, native.publication.bundle(encoded(self.issued['certificate'], 65536),
                                                        encoded(self.current['roster']['bytes'], 65536)).wire)
        self.plan = self.root / (self.label + '-publication.json')
        save(self.plan, {'schema': 'qperiapt-independent-publication/1', 'session_directory': str(self.session_dir),
            'peer_trust': str(self.trust_path), 'publication': str(native.published / 'publication.json'),
            'credential': {'kind': 'enrollment', 'path': str(self.issued_path)},
            'policy_pins': str(self.root / 'policy-pins.json'), 'policy_materials': str(self.root / 'policy-materials.json')})
        self.prepared = self.cli('prepare', ['prepare', '--inputs', self.plan])
        require(self.prepared['preparation'] == 'RequiresWitnessEnrollment' and
                bytes(self.prepared['subject'][:32]) == self.journal, 'independent original genesis differs')
        return self.prepared

    def connect(self, address, label, *, success=True):
        result = self.cli(label, ['connect', '--address', *address], success=success)
        if success:
            require(set(result) == {'session', 'peer_confirmation'} and result['peer_confirmation'] == 'Recorded', 'peer confirmation absent')
            return result['session']
        return None

    def next(self, sid, label, *, success=True):
        result = self.cli(label, ['next', '--session=' + sid], success=success)
        return result['message'] if success else None

    def deliver(self, sid, message, body, address, label, *, success=True, resume=False):
        args = [('resume' if resume else 'deliver'), '--session=' + sid, '--message=' + message,
                '--associated-data', self.root / 'associated-data.bin', '--address', *address]
        if not resume:
            path = self.root / (self.label + '-' + label + '.bin'); save(path, body)
            args.extend(['--plaintext', path])
        result = self.cli(label, args, success=success)
        if success:
            require(result == {'session': sid, 'message': message, 'consumption': 'Confirmed'}, 'independent delivery confirmation')
