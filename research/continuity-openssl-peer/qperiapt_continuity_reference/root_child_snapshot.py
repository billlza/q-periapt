"""Restricted authenticated child observation for one original root operation.

No live lease, witness client, signature, Advance, publication or traffic owner
is created. Original G/R/P inspectors validate their own retained transaction.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
import hashlib
from .account_authority import _RecoveryAccess
from .account_binding import Binding, SIZE
from .durable import Session
from .local_authority_control import admit_snapshot, read as read_control
from .pending_recovery_views import encode as public_view
from .state_codec import decode
from .wire import require
from .witness import Head
from .witness_journal import WitnessJournal


@dataclass(frozen=True, repr=False)
class Observation:
    subject: bytes
    local_head: Head
    local_metadata: bytes
    pending_kind: str | None
    local_phase: str
    intent_digest: bytes | None
    expected: Head | None
    target: Head | None
    target_metadata: bytes | None
    authority_digest: bytes | None
    root_bound: bool


class _View(WitnessJournal):
    def __init__(self, path, scope, key, context, access, allow_unbound):
        require(type(access) is _RecoveryAccess and type(allow_unbound) is bool,
                'original root metadata access required')
        access.check()
        require(context.witness is not None, 'root child inspection requires original witnessed journal')
        Session._scope(context, scope)
        access.check_scope(context.devices[0].pin.account, context.family, context.witness.pin)
        self._access, self._allow_unbound = access, allow_unbound
        super().__init__(path, scope, key, Session._validator(context), context.witness, None)

    def _check_root(self):
        require(self._directory is not None, 'closed root child inspection')
        self._access.check()

    def _decode(self, wire):
        self._check_root(); prefix = self._image_prefix(); offset = len(prefix)
        require(self.image_overhead <= len(wire) <= self.max_payload + self.image_overhead + SIZE,
                self.image_capacity_error)
        if wire[:8] == prefix[:6] + b'02':
            require(wire[:offset] == prefix[:6] + b'02' + prefix[8:], 'root child header scope')
            require(Binding.read(wire[offset:offset + SIZE]) == self._access.binding, 'root child original binding differs')
            offset += SIZE
        else:
            require(self._allow_unbound and wire[:offset] == prefix, 'root child expected original bound image')
        require(len(wire) >= offset + 24, 'root child header and authentication tag')
        snapshot = self._decode_envelope(wire, wire[:offset + 8], int.from_bytes(wire[offset:offset + 8], 'big'))
        self._check_root(); return snapshot

    def _seal(self, *_arguments): raise ValueError('root child inspection cannot seal or publish')
    def _commit(self, *_arguments): raise ValueError('root child inspection cannot commit')
    def _recover(self, *_arguments): raise ValueError('root child inspection cannot reconcile')
    def _advance(self, *_arguments): raise ValueError('root child inspection cannot advance')
    def _query(self, *_arguments): raise ValueError('root child inspection has no witness client')
    def _authorize(self, *_arguments): raise ValueError('root child inspection grants no authority')


def _metadata(journal, snapshot, context, *, ordinary):
    state = decode(snapshot.payload, context)
    try:
        if ordinary: admit_snapshot(journal, state)
        return public_view(state, journal.scope, Head(1, snapshot.revision, snapshot.digest))
    finally:
        state.close()


def inspect(journal, context):
    """Read and validate every original formal byte, without reconciling any one."""
    require(type(journal) is _View, 'restricted original root child view required')
    directory = journal._admit(); wire = directory.read('head'); pending = directory.read('intent')
    require(wire is not None, 'missing original root child image')
    snapshot = journal._decode(wire); control = read_control(journal)
    expected = target = target_metadata = kind = None
    phase = 'HeadOnly'
    ordinary = pending is None or pending.startswith(b'QPREFI01')
    if pending is not None and ordinary:
        revision, prior, target_wire, result = journal._decode_intent(pending)
        require(revision > 0, 'root inspection cannot complete inactive creation')
        expected, target = Head(1, revision, prior), Head(1, result.revision, result.digest)
        require(Head(1, snapshot.revision, snapshot.digest) in (expected, target), 'root ordinary intent differs from original head')
        kind = 'ordinary'
        phase = 'TargetPublished' if snapshot.digest == target.digest else 'IntentRetained'
        if wire[:8] == b'QPREFW01' and target_wire[:8] == b'QPREFW02':
            require(snapshot.payload == result.payload and Head(1, snapshot.revision, snapshot.digest) == expected,
                    'root binding intent changes original business state')
            kind = 'root-binding'
        require(wire[:8] != b'QPREFW02' or target_wire[:8] == b'QPREFW02', 'root binding cannot be removed')
        target_metadata = _metadata(journal, result, context, ordinary=True)
    elif not ordinary or (control is not None and not control.ready()):
        if (pending is not None and pending[:8] in (b'QPRFLI01', b'QPRFLI02')) or (pending is None and control.phase in (1, 2, 3)):
            from .local_renewal import inspect_retained
            kind = 'credential'
        elif (pending is not None and pending.startswith(b'QPRFRI01')) or (pending is None and control.roster is not None and not control.roster.ready()):
            from .account_snapshot import shared
            require(shared(context) and context.policy_version > 0, 'root roster inspection requires original common account')
            from .roster_refresh import inspect_retained
            kind = 'roster'
        elif (pending is not None and pending.startswith(b'QPRFPI01')) or (pending is None and control.policy is not None and not control.policy.ready()):
            from .witness_policy import inspect_retained
            kind = 'policy'
        else:
            raise ValueError('unknown original root child coordination')
        retained, _control, intent = inspect_retained(journal, context)
        require(retained == snapshot, 'root child inspection changed its original head')
        retained_control = control if kind == 'credential' else (control.roster if kind == 'roster' else control.policy)
        if (retained_control is not None and retained_control.phase in (1, 2, 3)
                and (intent is None or retained_control.proposal == intent.proposal)):
            phase = {1:'Prepared', 2:'AppliedRecorded', 3:'ClosedRecorded'}[retained_control.phase]
        else:
            phase = 'IntentRetained'
        if intent is not None:
            expected, target = intent.proposal.expected, intent.proposal.target
            target_metadata = _metadata(journal, journal._decode(intent.target), context, ordinary=False)
        else:
            expected, target = retained_control.proposal.expected, retained_control.proposal.target
        ordinary = False
    metadata = _metadata(journal, snapshot, context, ordinary=ordinary)
    if target_metadata is None and target == Head(1, snapshot.revision, snapshot.digest):
        target_metadata = metadata
    authority = directory.read('authority')
    require(directory.read('head') == wire and directory.read('intent') == pending, 'root child changed during inspection')
    result = Observation(journal.subject, Head(1, snapshot.revision, snapshot.digest), metadata, kind, phase,
        None if pending is None else hashlib.sha256(pending).digest(), expected, target, target_metadata,
        None if authority is None else hashlib.sha256(authority).digest(), wire[:8] == b'QPREFW02')
    journal._check_root(); return result


def original_child(parent, image, now):
    from .registration_session import selected_parts, validate_context
    require(image.child is not None, 'original root recovery has no child journal')
    context = image.child.inputs.original(image.child.context, now)
    validate_context(parent, image, context)
    scope, key = selected_parts(parent._key, parent._registration.scope.identity, image, context)
    journal = _View(image.child.path, scope, key, context, parent._access, parent._adoption_pending)
    try:
        observation = inspect(journal, context); parent._alive(); return observation
    finally:
        journal.close()
