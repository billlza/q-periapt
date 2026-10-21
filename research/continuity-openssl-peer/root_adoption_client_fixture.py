"""Real-file client migration checks, using explicit native-issued test identities."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import signal
import time
from qperiapt_continuity_reference.account_authority import AccountAuthority
from qperiapt_continuity_reference.client_root_adoption import RootAdoption
from qperiapt_continuity_reference.enrollment_client import EnrollmentClient
from qperiapt_continuity_reference.pending_recovery_protocol import Proposal
from qperiapt_continuity_reference.wire import ldh, require
from qperiapt_continuity_reference.witness import Pin

STAGES = ('stage-synced:intent', 'published:intent', 'committed:intent', 'stage-synced:head',
          'published:head', 'committed:head', 'removed:intent', 'committed:removal')
PHASES = {'configuration': ('client-config:', 1), 'child': ('client-root-child:', 1),
          'registration': ('client-device:registration-store:', 1), 'ready': ('client-config:', 2)}


@dataclass(frozen=True)
class Inputs:
    client_path: Path
    identity: bytes
    key: bytes
    registry_path: Path
    registry_key: bytes
    registry_identity: bytes
    family: bytes
    pin: Pin

    def registry(self):
        return AccountAuthority.open(self.registry_path, self.registry_key, self.registry_identity, self.family, self.pin)

    def client(self, registry=None, observer=None):
        return EnrollmentClient.open(self.client_path, self.identity, self.key, account_authority=registry, observer=observer)

    def adoption(self, registry):
        return RootAdoption.open(self.client_path, self.identity, self.key, registry)


def process_cut(client, registry, inputs, cut, output):
    phase, stage = cut; prefix, occurrence = PHASES[phase]
    client.close(); registry.close()
    marker = output / 'original-root-adoption-cut.json'
    pid = os.fork()
    if pid == 0:
        observed = 0
        def stop(value):
            nonlocal observed
            if value != prefix + stage: return
            observed += 1
            if observed != occurrence: return
            with os.fdopen(os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
                json.dump({'phase': phase, 'stage': stage, 'pid': os.getpid()}, stream)
                stream.flush(); os.fsync(stream.fileno())
            os.kill(os.getpid(), signal.SIGKILL)
        try:
            registry = inputs.registry(); client = inputs.client(observer=stop)
            owner = client.begin_root_adoption(registry, 170)
            owner.commit(170)
        except BaseException:
            import traceback
            traceback.print_exc(); os._exit(71)
        os._exit(72)
    deadline = time.monotonic() + 30
    while True:
        finished, status = os.waitpid(pid, os.WNOHANG)
        if finished: break
        if time.monotonic() >= deadline:
            os.kill(pid, signal.SIGKILL); os.waitpid(pid, 0)
            raise TimeoutError('root adoption process cut: ' + phase + '/' + stage)
        time.sleep(.01)
    require(os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL,
            'migration process did not reach original cut: ' + str(status))
    require(json.loads(marker.read_bytes()) == {'phase': phase, 'stage': stage, 'pid': pid}, 'wrong migration cut marker')
    orphans = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
               for path in inputs.client_path.rglob('.stage-*') if path.name != '.stage-head'}
    registry = inputs.registry()
    try:
        if phase == 'configuration' and stage == STAGES[0]:
            client = inputs.client(); owner = client.begin_root_adoption(registry, 170)
        else:
            owner = inputs.adoption(registry)
        return registry, owner, orphans
    except BaseException:
        registry.close(); raise


def refuse_substitution(owner, inputs, registry, refuse):
    _, image = owner._image(); intent, admission = image.effective(owner._intent)
    paths = (inputs.client_path, image.child.path)
    def snapshot():
        return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for path in paths for p in path.rglob('*') if p.is_file()}
    owner.close(); before = snapshot()
    refuse('migration-missing-registry', lambda: RootAdoption.open(inputs.client_path, inputs.identity, inputs.key, None),
           'original account registry required')
    alternate_path = inputs.registry_path.parent / 'alternate-registry'; alternate_path.mkdir(mode=0o700)
    key, identity = os.urandom(32), os.urandom(32)
    with os.fdopen(os.open(alternate_path.parent / 'alternate-registry-key', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as out:
        out.write(key + identity); out.flush(); os.fsync(out.fileno())
    alternate = AccountAuthority.provision(alternate_path, key, identity, inputs.family, inputs.pin)
    try:
        alternate.associate(owner._authority.application, admission.pin(intent), admission.certificate, admission.roster)
        refuse('migration-substituted-registry', lambda: inputs.adoption(alternate), 'original root registry lease required')
    finally:
        alternate.close()
    require(snapshot() == before, 'rejected root adoption changed original files')
    refuse('incomplete-parent-root-adoption', lambda: inputs.client(registry), 'original root adoption remains pending')
    require(snapshot() == before, 'normal open changed original prepared adoption')


def migrate(client, registry, inputs, transport, refuse, bridge, output, cut=None, expiry=None, call=None):
    before = client.status(); owner = None; orphans = {}
    try:
        if cut is not None:
            require(bridge is None, 'process-cut fixture is local; no fork with bridge thread')
            registry, owner, orphans = process_cut(client, registry, inputs, cut, output)
        else:
            owner = client.begin_root_adoption(registry, 170, transport=transport())
            refuse_substitution(owner, inputs, registry, refuse)
            owner = inputs.adoption(registry)
            if expiry == 'local':
                require(bridge is None, 'local expiry fixture must not have a witness')
                owner.close()
                def stop(stage):
                    if stage == 'client-root-child:committed:removal':
                        raise OSError('child binding committed; parent result unknown')
                owner = RootAdoption.open(inputs.client_path, inputs.identity, inputs.key, registry, observer=stop)
                refuse('local-parent-binding-result-unknown', lambda: owner.commit(170), 'parent result unknown')
                owner = inputs.adoption(registry)
            elif bridge is not None:
                bridge.arm(expiry or 'after', 2)
                refuse('parent-binding-result-unknown', lambda: owner.commit(170, transport=transport()), 'truncated witness reply')
                owner = inputs.adoption(registry)
            if expiry is not None and expiry != 'local':
                require(bridge is not None and call is not None, 'expiry fixture requires actual witness')
                call('adoption-witness-expiry', 33, (210).to_bytes(8, 'big'), b'witness clock set')
                requests = len(bridge.records)
                request = owner.pending_write_request(210, transport=transport()); proposal = Proposal.decode(request.proposal)
                require(len(bridge.records) == requests, 'pending adoption inspection dispatched')
                expected = ldh(b'Q-PERIAPT-CONTINUITY-PENDING-WRITE-RECOVERY/v1', request.proposal) + (4).to_bytes(8, 'big') * 2
                call('approve-parent-binding-recovery', 36, request.proposal + request.metadata, expected)
                call('complete-parent-binding-recovery', 37, request.signed_request, proposal.target.wire())
                require(owner.confirm_pending_write(request.proposal, request.metadata, 210, transport=transport())
                        == proposal.target.wire(), 'parent original pending confirmation')
        now = 210 if expiry is not None else 170
        client = owner.commit(now, transport=transport()); owner = None
        require(client.status() == before, 'parent adoption changed original registration')
        for path, expected in orphans.items():
            require(hashlib.sha256(Path(path).read_bytes()).hexdigest() == expected, 'root adoption discarded orphan')
        client.close(); owner = inputs.adoption(registry)
        require(owner.status()['root_ready'], 'parent adoption not durable')
        client = owner.commit(now, transport=transport()); owner = None
        return client, registry
    except BaseException:
        client.close(); registry.close(); raise
    finally:
        if owner is not None: owner.close()


def resume_expired(client, transport, refuse, public, message_id, witnessed):
    """Parent readiness is metadata; actual traffic still requires fresh G authority."""
    with client.session(210, transport=transport()) as child:
        refuse('completed-parent-binding-is-not-traffic-permission', lambda: child.resume(message_id, now=210),
               'witness current authority denied' if witnessed else 'expired or premature authority')
    # A failed borrowed operation closes the client. Reopen only its same state.
    operation = (public / 'local-renewal-1-operation').read_bytes()
    grant = (public / 'local-renewal-1').read_bytes(); target = (public / 'pin-local-renewal-1-target').read_bytes()
    return operation, grant, target
