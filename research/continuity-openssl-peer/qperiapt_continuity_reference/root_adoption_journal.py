"""Private adapters for explicitly adopting an original unbound journal.

They retain the live registry guard while authenticating the legacy source.
Normal factories never select these adapters. Adoption changes only the image
header and revision; all original business bytes and authority records survive.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from contextlib import contextmanager
import hashlib
from . import account_binding
from .journal import Journal, LocalSessionJournal, locked
from .witness_journal import WitnessJournal
from .wire import require


class _Adopting:
    def _decode(self, wire):
        if wire[:8] == self._image_prefix()[:8]:
            return self._decode_unbound_source(wire)
        return super()._decode(wire)

    def _opening_head(self, wire, pending):
        source = self._decode(wire)
        if pending is not None:
            require(pending.startswith(b'QPREFI01'), 'finish original authority coordination before root binding')
            _revision, _prior, target = self._intent_parts(pending)
            if wire[:8] != self._image_prefix()[:8]:
                require(target[:8] != self._image_prefix()[:8], 'root binding cannot be removed')
            elif target[:8] != self._image_prefix()[:8]:
                # Shared normal-open check: exact original source, bound target,
                # authenticated intent and unchanged business state.
                return Journal._opening_head(self, wire, pending)
        return source

    @locked
    def bind(self, admit):
        """Reconcile the original transition, then bind under current admission.

        The internal caller supplies admission for the actual decoded session
        and current local/witness authority; this is never a traffic facade.
        """
        try:
            require(self._root_lease is not None, 'root adoption requires a live original registry')
            snapshot = self._recover(False)
            admit(self, snapshot)
            directory = self._admit()
            wire = directory.read('head')
            require(wire is not None and self._decode(wire) == snapshot, 'root adoption original image changed')
            if wire[:8] == self._image_prefix()[:8]:
                snapshot = self._commit(snapshot.revision, snapshot.digest, snapshot.payload)
                admit(self, snapshot)
            # Read back with the strict normal decoder, never the legacy reader.
            wire = self._admit().read('head')
            require(wire is not None and self._decode_with_root(wire, self._root_lease) == snapshot
                    and self._admit().read('intent') is None, 'root binding durable readback')
            self._check_root()
            return snapshot
        except BaseException:
            self.close()
            raise


class _Local(_Adopting, LocalSessionJournal):
    pass


class _Witness(_Adopting, WitnessJournal):
    pass


class _OriginalSuccessor(_Witness):
    """Only the approved initial image or its exact binding-only successor.

    AES-SIV deterministically reconstructs the original revision-one envelope.
    Validate both source and intent target before recovery can write or advance
    the witness. Advanced business state is reopened through the normal client.
    """
    def __init__(self, *args, expected_genesis, **kwargs):
        require(type(expected_genesis) is bytes and len(expected_genesis) == 128,
                'original successor genesis required')
        self._expected_genesis = expected_genesis
        super().__init__(*args, **kwargs)

    def _decode(self, wire):
        if self._root_lease is None: return self._decode_with_root(wire, None)
        return super()._decode(wire)

    def _decode_with_root(self, wire, lease):
        snapshot = super()._decode_with_root(wire, lease)
        original = wire[:8] == self._image_prefix()[:8]
        require(snapshot.revision == (1 if original else 2), 'successor activation found advanced state')
        require(self.subject == self._expected_genesis[:96]
                and self._admit().read('authority') is None, 'successor activation subject or authority differs')
        header = account_binding.header(self._image_prefix(), 1, None)
        genesis = header + self._cipher.encrypt(snapshot.payload, [header])
        require(hashlib.sha256(genesis).digest() == self._expected_genesis[96:],
                'successor activation differs from approved genesis')
        return snapshot


def _new(path, scope, key, context, root_lease, client, observer, expected_genesis=None):
    from .durable import Session
    require(root_lease is not None, 'root adoption requires a live original registry')
    Session._scope(context, scope, root_lease)
    if context.witness is None:
        require(client is None and expected_genesis is None, 'local root adoption has no witness carrier or successor genesis')
        return _Local(path, scope, key, Session._validator(context), observer, root_lease=root_lease)
    else:
        require(client is not None and client.signer is not None and client.signer.public() == context.initiator,
                'root adoption requires original witness signer')
        arguments = (path, scope, key, Session._validator(context), context.witness, client, observer)
        if expected_genesis is not None:
            return _OriginalSuccessor(*arguments, root_lease=root_lease, expected_genesis=expected_genesis)
        return _Witness(*arguments, root_lease=root_lease)


def _admit(owner, snapshot, context, now):
    from .identity_state import admit_local, local_binding
    from .local_authority_control import admit_snapshot
    from .state_codec import decode
    state = decode(snapshot.payload, context)
    try:
        admit_snapshot(owner, state)
        if now is not None:
            admit_local(state, context, now)
            if context.witness is not None:
                owner._authorize(snapshot, local_binding(state, context))
    finally:
        state.close()


def adopt(path, scope, key, context, now, *, root_lease, client=None, observer=None):
    """Bind with current authority; original ordinary intents retain their bytes."""
    require(type(now) is int and 0 <= now < 2**64, 'root adoption time')
    journal = _new(path, scope, key, context, root_lease, client, observer)
    try:
        journal.bind(lambda owner, snapshot: _admit(owner, snapshot, context, now))
        return root_lease.binding
    finally:
        journal.close()


def finish(path, scope, key, context, now, *, root_lease, client=None, observer=None, registration_bound=False,
           expected_genesis=None):
    """Complete parent metadata after an exact retained child binding.

    A fully bound head with no intent needs authenticated readback and, where
    required, a fresh witness Query. This may finish after credential expiry;
    it cannot start a new binding or release traffic without current admission.
    """
    require(type(now) is int and 0 <= now < 2**64, 'root adoption time')
    require(type(registration_bound) is bool, 'root adoption registration phase')
    journal = _new(path, scope, key, context, root_lease, client, observer, expected_genesis)
    try:
        directory = journal._admit(); wire = directory.read('head'); pending = directory.read('intent')
        require(wire is not None, 'missing original root adoption child')
        bound = wire[:8] == journal._image_prefix()[:6] + b'02'
        require(not registration_bound or (bound and pending is None), 'completed registration lost child root binding')
        if bound and pending is None:
            snapshot = journal._recover(False)
            # Ordinary adoption may finish metadata after expiry. Successor
            # activation must recheck current authority even on exact retry.
            _admit(journal, snapshot, context, None if expected_genesis is None else now)
        else:
            snapshot = journal.bind(lambda owner, value: _admit(owner, value, context, now))
        require(journal._decode_with_root(journal._admit().read('head'), root_lease) == snapshot,
                'original child root binding readback')
        journal._check_root(); return root_lease.binding
    finally:
        journal.close()


@contextmanager
def preflight(path, scope, key, context, now, *, root_lease, client=None, observer=None, expected_genesis=None):
    """Keep the original unbound child lease until parent preparation is durable."""
    from .durable import Session
    require(type(now) is int and 0 <= now < 2**64, 'root adoption time')
    require(root_lease is not None, 'root adoption requires a live original registry')
    Session._scope(context, scope, root_lease)
    if context.witness is None:
        require(client is None and expected_genesis is None, 'local root adoption has no witness carrier or successor genesis')
        journal, snapshot = LocalSessionJournal._open(path, scope, key, Session._validator(context), observer=observer)
    else:
        require(client is not None and client.signer is not None and client.signer.public() == context.initiator,
                'root adoption requires original witness signer')
        if expected_genesis is None:
            journal, snapshot = WitnessJournal._open(path, scope, key, Session._validator(context), context.witness, client, observer)
        else:
            journal = _OriginalSuccessor(path, scope, key, Session._validator(context), context.witness, client, observer,
                                         expected_genesis=expected_genesis)
            try: snapshot = journal._recover(False)
            except BaseException: journal.close(); raise
    try:
        _admit(journal, snapshot, context, now); root_lease.check()
        yield
        root_lease.check()
    finally:
        journal.close()
