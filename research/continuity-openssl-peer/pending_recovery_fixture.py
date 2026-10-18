"""Actual original witnessed owner and a separate privileged test-controller lane."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
import os
from pathlib import Path
import tempfile
from fixture_inputs import load, load_witness_pin
from peer.durable import owner_binding
from peer.journal import Scope
from peer.pending_recovery import PendingWriteRecovery
from peer.pending_recovery_protocol import Proposal
from peer.wire import SigningKey, ldh, require
from peer.witness import Client, TcpTransport
from run import Counterpart
from session_driver import SessionDriver
from signing_fixture import write
from witness_fixture import Bridge


class Fixture:
    def __init__(self, args, label):
        self.out = args.output.resolve() / label; self.out.mkdir(); (self.out / 'native').mkdir()
        self.private = Path(tempfile.mkdtemp(prefix='qperiapt-pending-recovery-')).resolve()
        require(not self.private.is_relative_to(self.out), 'private pending fixture inside capture')
        (self.out / 'private-fixture-path').write_text(str(self.private) + '\n')
        self.native = Counterpart(args.native.resolve(), self.out / 'native', required_witness=True, local_lifecycle=True)
        self.bridge = None; self.driver = None; self.refusals = []
        try:
            self.signer = SigningKey(); require(self.native.transfer(self.signer.public().raw) == b'\1ready', 'native readiness')
            self.public = self.out / 'native/public'; self.pin = load_witness_pin(self.public)
            _, _, self.context = load(self.public, 150, witness_pin=self.pin)
            self.scope = Scope(os.urandom(32), owner_binding(self.context), self.context.digest); self.key = os.urandom(32)
            config = self.private / 'configuration'
            with os.fdopen(os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
                stream.write(self.key + self.scope.wire()); stream.flush(); os.fsync(stream.fileno())
            signer = self.private / 'signer'; write(signer, self.signer)
            self.path = self.private / 'session'; self.path.mkdir(mode=0o700)
            self.bridge = Bridge(self.native, self.out)
            self.driver = SessionDriver(self.out, args.provider_root.resolve(), self.public, config, self.path, signer,
                                        witness_address=self.bridge.address[0] + ':' + str(self.bridge.address[1]))
            genesis = self.value('provision', 'witness_provision', now=150)
            self.call('enrollment', 30, genesis, b'enrolled')
            initial = self.value('initial', 'initial', now=150)
            reply = self.call('bootstrap-reply', 4, initial)
            final = self.value('finish', 'finish', (reply,), now=150)
            self.session = self.call('complete', 5, final)
            require(self.value('activate', 'activate') == self.session, 'original session')
            self.call('native-activate', 6, expected=self.session)
        except BaseException:
            self.close(); raise

    def worker(self, name, action, arguments=(), **options):
        return self.driver.run(name, action, arguments, **options)

    def value(self, name, action, arguments=(), **options):
        return bytes.fromhex(self.worker(name, action, arguments, **options))

    def call(self, name, command, payload=b'', expected=None, status=1):
        return self.bridge.call(name, command, payload, expected, status)

    def clock(self, now):
        self.call('clock-' + str(now), 33, now.to_bytes(8, 'big'), b'witness clock set')

    def owner(self, observer=None):
        client = Client(self.pin, self.context.witness.subject(self.scope.identity), self.signer, TcpTransport(self.bridge.address))
        return PendingWriteRecovery.open(self.path, self.scope, self.key, self.context, client=client, observer=observer)

    def request(self, name, now):
        attempts = len(self.bridge.records)
        summary = self.worker(name, 'pending_recovery_request_files', (name.encode(),), now=now)
        parts = tuple((self.out / (name + '.' + kind)).read_bytes() for kind in ['proposal', 'metadata', 'signed'])
        for kind, value in zip(['proposal', 'metadata', 'signed'], parts, strict=True):
            require(summary[kind] == {'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest()}, 'retained request bytes')
        require(len(self.bridge.records) == attempts, 'preparation dispatched a witness request')
        require(self.context.initiator.open(parts[2], 26, 393) == parts[0], 'historical request signature')
        Proposal.decode(parts[0]).check_metadata(parts[1])
        return parts

    def confirmation_arguments(self, name):
        proposal, metadata = ((self.out / (name + '.' + kind)).read_bytes() for kind in ['proposal', 'metadata'])
        return ((name + '.proposal').encode(), (name + '.metadata').encode(),
                hashlib.sha256(proposal).digest() + hashlib.sha256(metadata).digest())

    def confirm(self, name, original, now, **options):
        return self.worker(name, 'pending_recovery_confirm_files', self.confirmation_arguments(original), now=now, **options)

    def approve(self, name, request):
        binding = ldh(b'Q-PERIAPT-CONTINUITY-PENDING-WRITE-RECOVERY/v1', request[0])
        return self.call(name, 36, request[0] + request[1], binding + (4).to_bytes(8, 'big') * 2)

    def renew(self, label, index, now):
        prefix = 'local-renewal-' + str(index)
        materials = tuple((self.public / n).read_bytes() for n in [prefix + '-operation', prefix, 'pin-' + prefix + '-target'])
        proposal = self.value(label + '-prepare', 'local_renewal_prepare', materials, now=now)
        self.call(label + '-independent-prepare', 34, proposal, b'Prepared')
        require(self.worker(label + '-commit', 'local_renewal_commit', (materials[0],), now=now) == 'Applied', 'joint credential renewal')
        return proposal

    def refuses(self, name, action, reason):
        from cryptography.exceptions import InvalidSignature
        try: action()
        except (ValueError, OSError, InvalidSignature) as error:
            require(reason in str(error), 'wrong pending refusal: ' + name + ': ' + str(error))
            self.refusals.append({'case': name, 'error': str(error)})
        else: raise ValueError('missing pending refusal: ' + name)

    def close(self):
        if self.driver is not None: (self.out / 'WORKERS.json').write_text(json.dumps(self.driver.operations, indent=2) + '\n')
        (self.out / 'NATIVE.json').write_text(json.dumps(self.native.commands, indent=2) + '\n')
        (self.out / 'REFUSALS.json').write_text(json.dumps(self.refusals, indent=2) + '\n')
        if self.bridge is not None:
            (self.out / 'WITNESS.json').write_text(json.dumps(self.bridge.records, indent=2) + '\n')
            self.bridge.close()
        self.native.close()
