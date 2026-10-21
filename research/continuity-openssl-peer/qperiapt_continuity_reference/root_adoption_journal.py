"""Private adapters for explicitly adopting an original unbound journal.

They retain the live registry guard while authenticating the legacy source.
Normal factories never select these adapters. Adoption changes only the image
header and revision; all original business bytes and authority records survive.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
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


def adopt(path, scope, key, context, now, *, root_lease, client=None, observer=None):
    """Bind the original child under its live root, without returning a Session.

    Existing ordinary intents retain their exact bytes. G/R/P coordination must
    finish through its original owner first. Expired unknown ordinary writes
    use PendingWriteRecovery, including an already retained adoption intent.
    """
    from .durable import Session
    from .identity_state import admit_local, local_binding
    from .local_authority_control import admit_snapshot
    from .state_codec import decode
    require(root_lease is not None, 'root adoption requires a live original registry')
    Session._scope(context, scope, root_lease)
    if context.witness is None:
        require(client is None, 'local root adoption has no witness carrier')
        journal = _Local(path, scope, key, Session._validator(context), observer, root_lease=root_lease)
    else:
        require(client is not None and client.signer is not None and client.signer.public() == context.initiator,
                'root adoption requires original witness signer')
        journal = _Witness(path, scope, key, Session._validator(context), context.witness, client,
                           observer, root_lease=root_lease)
    def admit(owner, snapshot):
        state = decode(snapshot.payload, context)
        try:
            admit_snapshot(owner, state)
            admit_local(state, context, now)
            if context.witness is not None:
                owner._authorize(snapshot, local_binding(state, context))
        finally:
            state.close()
    try:
        journal.bind(admit)
        return root_lease.binding
    finally:
        journal.close()
