"""Fresh process-owned registration against an independently configured native issuer."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from fixture_inputs import load, load_witness_pin
from qperiapt_continuity_reference.registration import Registration
from qperiapt_continuity_reference.registration_protocol import Intent
from qperiapt_continuity_reference.witness import TcpTransport
from qperiapt_continuity_reference.wire import require
from run import Counterpart
from session_driver import SessionDriver
from witness_fixture import Bridge


class Fixture:
    def __init__(self, args, label, *, account_members=None):
        self.out = args.output / label; self.out.mkdir(); (self.out / 'native').mkdir()
        self.native = Counterpart(args.native, self.out / 'native', registration=True,
                                  local_lifecycle=account_members is None, required_witness=label == 'witness',
                                  account_members=account_members)
        self.bridge = None; self.driver = None; self.refusals = []; self.observations = {}
        try:
            deadline = time.monotonic() + 30
            size = int.from_bytes(self.native.read(4, deadline), 'big'); require(size == 2058, 'trusted native registration intent frame')
            prelude = self.native.read(size, deadline); require(prelude[0] == 1, 'native independent intent status')
            self.intent = Intent.from_trusted(prelude[1:]); (self.out / 'REGISTRATION_INTENT.bin').write_bytes(prelude[1:])
            self.private = Path(tempfile.mkdtemp(prefix='qperiapt-owned-registration-')).resolve(); self.private.chmod(0o700)
            (self.out / 'private-fixture-path').write_text(str(self.private) + '\n')
            self.path = self.private / 'enrollment'; self.path.mkdir(mode=0o700)
            self.session_path = self.private / 'session'; self.session_path.mkdir(mode=0o700)
            self.key, self.identity = os.urandom(32), os.urandom(32)
            config = self.private / 'configuration'
            with os.fdopen(os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as file:
                file.write(self.key + self.identity + self.intent.wire()); file.flush(); os.fsync(file.fileno())
            self.public = self.out / 'native/public'
            self.driver = SessionDriver(self.out, args.provider_root, self.public, config, self.path,
                                        worker_script='registration_worker.py')
            self.worker('initial-intent-cut', 'provision', now=150, cut='registration-store:committed:intent')
            first = self.worker('original-provision-recovered', 'recover_initial', now=150)
            require(first['phase'] == 'Preparing', 'original initial enrollment')
            self.worker('original-request-cut', 'registration_request', now=150, cut='registration:request-committed')
            self.request = self.value('original-request', 'registration_request', now=150)
            require(self.value('exact-request-retry', 'registration_request', now=150) == self.request, 'original signed request bytes')
            signing, public = self.intent.verify_request(self.request, 150)
            require((first['signing_id'], first['public_key']) == (signing.hex(), public.raw.hex()), 'precommitted original signer survived cuts')
            (self.out / 'REQUEST.bin').write_bytes(self.request)
            ready = self.native.transfer(self.request); (self.out / 'ISSUANCE_READY.bin').write_bytes(ready)
            require(ready == b'\1ready', 'real native approved enrollment')
            if label == 'witness':
                self.bridge = Bridge(self.native, self.out)
                self.driver.witness_address = self.bridge.address[0] + ':' + str(self.bridge.address[1])
            self.pin = load_witness_pin(self.public) if self.bridge else None
            self.pins, self.materials, self.context = load(self.public, 150, witness_pin=self.pin)
            require(self.context.initiator == public, 'native certificate names original signing owner')
            require(self.call('original-issuance-retry', 38, self.request) == self.materials.initiator_credential,
                    'native retained issuance reply')
            self.observations.update(signing_id=signing.hex(), public_sha256=hashlib.sha256(public.raw).hexdigest(),
                                     request_sha256=hashlib.sha256(self.request).hexdigest())
        except BaseException:
            self.close(); raise

    def worker(self, name, action, arguments=(), **options): return self.driver.run(name, action, arguments, **options)

    def value(self, name, action, arguments=(), **options): return bytes.fromhex(self.worker(name, action, arguments, **options))

    def call(self, name, command, data=b'', expected=None, status=1):
        return (self.bridge.call(name, command, data, expected, status) if self.bridge else
                self.native.command(name, command, data, status, expected))

    def transport(self): return TcpTransport(self.bridge.address) if self.bridge else None

    def owner(self, observer=None): return Registration.open(self.path, self.identity, self.key, self.intent, observer=observer)

    def refuses(self, name, function, reason):
        from cryptography.exceptions import InvalidSignature, InvalidTag
        try: function()
        except (ValueError, OSError, InvalidSignature, InvalidTag) as error:
            require(reason in str(error), 'wrong registered refusal: ' + name + ': ' + str(error))
            self.refusals.append({'case': name, 'error': str(error), 'type': type(error).__name__})
        else: raise ValueError('missing registered refusal: ' + name)

    def pending_request(self, name, now):
        before = len(self.bridge.records)
        result = self.worker(name, 'pending_recovery_request_files', (name.encode(),), now=now)
        values = tuple((self.out / (name + '.' + suffix)).read_bytes() for suffix in ['proposal', 'metadata', 'signed'])
        require(len(self.bridge.records) == before, 'registered pending request dispatched a witness operation')
        for suffix, value in zip(['proposal', 'metadata', 'signed'], values, strict=True):
            require(result[suffix] == {'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest()}, 'registered retained request files')
        return values

    def confirmation_arguments(self, name):
        values = [(self.out / (name + '.' + suffix)).read_bytes() for suffix in ['proposal', 'metadata']]
        return ((name + '.proposal').encode(), (name + '.metadata').encode(), b''.join(hashlib.sha256(v).digest() for v in values))

    def close(self):
        if self.driver is not None: (self.out / 'WORKERS.json').write_text(json.dumps(self.driver.operations, indent=2) + '\n')
        (self.out / 'NATIVE.json').write_text(json.dumps(self.native.commands, indent=2) + '\n')
        (self.out / 'REFUSALS.json').write_text(json.dumps(self.refusals, indent=2) + '\n')
        (self.out / 'OBSERVATIONS.json').write_text(json.dumps(self.observations, indent=2) + '\n')
        if self.bridge is not None:
            (self.out / 'WITNESS.json').write_text(json.dumps(self.bridge.records, indent=2) + '\n'); self.bridge.close()
        self.native.close()
