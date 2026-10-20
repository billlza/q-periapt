"""Create/open only the child installation selected by accepted registration."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import replace
from .durable import Session, owner_binding
from .journal import Scope
from .kem import hkdf
from .private_files import PrivateDirectory
from .registered_owner import BorrowedOwner, _Signer, SESSION, CONNECTION, LOCAL_RENEWAL, JOINT_RENEWAL, PENDING, ROSTER, POLICY
from .registration_inputs import Inputs
from .registration_protocol import DOMAIN
from .registration_state import Child, signer
from .witness import Client
from .witness_session import WitnessSession
from .wire import require


def selected(parent, image, context):
    require(image.admission is not None, 'registration is not accepted')
    scope = Scope(image.admission.journal, owner_binding(context), context.digest)
    key = hkdf(parent._key, parent._journal.scope.identity, DOMAIN + b'child-key/' + scope.wire())
    return scope, key


def validate_context(parent, image, context):
    require(image.admission is not None and context.family == parent._intent.family, 'registered policy family differs')
    public = signer(image.seed).public(); local = context.devices[0]
    intent, admission = image.effective(parent._intent)
    intent.admit_device(local, public)
    certificate = admission.validate(intent, public)
    require(local.pin == admission.pin(intent) and local.credential == certificate.digest
            and context.policy_digest == admission.policy[8:], 'registration original context admission differs')


def prepare(parent, path, inputs, now):
    require(parent._child is None, 'close borrowed child before registration maintenance')
    snapshot, image = parent._image()
    require(image.admission is not None and not image.active, 'registration is not pending child preparation')
    _, admission = image.effective(parent._intent)
    original = parent._journal._admit().path
    require(path != original and not path.is_relative_to(original) and not original.is_relative_to(path),
            'registration and session directories must be separate')
    # A real directory lease checks the caller's canonical path before recording it.
    lease = PrivateDirectory(path)
    try: lease.check()
    finally: lease.close()
    if image.child is None:
        context = inputs.current(now); validate_context(parent, image, context)
        normalized = Inputs(inputs.pins, replace(inputs.materials, initiator_credential=admission.certificate,
                                                  initiator_roster=admission.roster), inputs.witness)
        image.child = Child(path, context.digest, normalized)
        snapshot, image = parent._save(snapshot, image, 'child-intent-committed')
    else:
        context = inputs.original(image.child.context, now); validate_context(parent, image, context)
        normalized = Inputs(inputs.pins, replace(inputs.materials, initiator_credential=admission.certificate,
                                                  initiator_roster=admission.roster), inputs.witness)
        require(image.child.path == path and image.child.inputs.encode() == normalized.encode(), 'different pending registration child')
    scope, key = selected(parent, image, context)
    lease = PrivateDirectory(path)
    try:
        has_head, has_intent = lease.read('head') is not None, lease.read('intent') is not None
        require(lease.read('authority') is None, 'registration preparation found advanced authority')
    finally: lease.close()
    if context.witness is None:
        owner = (Session.open(path, scope, key, context, creation=True, observer=parent._child_observer) if has_head or has_intent
                 else Session.create(path, scope, key, context, _Signer(parent), now, observer=parent._child_observer))
        owner.close(); result = scope.wire()
    else:
        genesis = (WitnessSession.recover_genesis(path, scope, key, context, parent._child_observer) if has_head or has_intent
                   else WitnessSession.provision(path, scope, key, context, _Signer(parent), now, parent._child_observer))
        result = genesis.wire()
    parent._observe('child-prepared')
    return result


def open_child(parent, kind, now, *, operation=None, transport=None):
    require(parent._child is None, 'registration already has a borrowed child')
    snapshot, image = parent._image(); require(image.child is not None, 'registration child was not prepared')
    if kind == 'connection':
        require(image.confirmation is not None and image.active, 'no recorded authenticated peer confirmation')
    require(kind == 'session' or image.active, 'maintenance requires an original active registration')
    context = image.child.inputs.original(image.child.context, now); validate_context(parent, image, context)
    scope, key = selected(parent, image, context); path = image.child.path
    if context.witness is None:
        require(transport is None, 'local registration does not accept a witness carrier'); client = None
    else:
        require(transport is not None, 'required witness carrier is missing')
        client = Client(context.witness.pin, context.witness.subject(scope.identity), _Signer(parent), transport)
    owner = None
    try:
        if kind in ('session','connection'):
            owner = (Session.open(path, scope, key, context, observer=parent._child_observer) if client is None else
                     WitnessSession.open(path, scope, key, context, client=client, observer=parent._child_observer))
            allowed = CONNECTION if kind == 'connection' else SESSION
            if kind == 'connection':
                require(owner.connection_identity(now)==image.confirmation.session, 'confirmed original session differs')
            if not image.active:
                image.active = True; parent._save(snapshot, image, 'activation-committed')
        elif kind == 'credential':
            if client is None:
                from .local_credential import LocalCredentialRenewal
                owner = LocalCredentialRenewal.open(path, scope, key, context, operation, observer=parent._child_observer); allowed = LOCAL_RENEWAL
            else:
                from .local_renewal import LocalRenewal
                owner = LocalRenewal.open(path, scope, key, context, operation, client=client, observer=parent._child_observer); allowed = JOINT_RENEWAL
        elif kind == 'policy':
            require(client is None, 'required policy renewal needs its witness coordinator')
            from .local_policy import LocalPolicyRenewal
            owner = LocalPolicyRenewal.open(path, scope, key, context, operation, image.child.inputs,
                                            observer=parent._child_observer); allowed = POLICY
        elif kind == 'roster':
            from .roster_refresh import RosterRefresh
            owner = RosterRefresh.open(path, scope, key, context, operation, client=client,
                                       observer=parent._child_observer); allowed = ROSTER
        elif kind == 'pending':
            from .pending_recovery import PendingWriteRecovery
            require(client is not None, 'pending recovery requires original witness')
            owner = PendingWriteRecovery.open(path, scope, key, context, client=client, observer=parent._child_observer); allowed = PENDING
        else: raise ValueError('unknown registered child owner')
        parent._alive(); child = BorrowedOwner(parent, owner, allowed); parent._child = child
        return child
    except BaseException:
        if owner is not None: owner.close()
        raise
