"""Explicit inactive creation and live witnessed session admission."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from .bootstrap import Initiator
from .durable import Session
from .state_codec import State, encode
from .witness_journal import WitnessJournal
from .wire import require


class WitnessSession(Session):
    @classmethod
    def provision(cls, path, scope, key, context, signer, now, observer=None, *, root_lease=None):
        require(context.witness is not None, "required witness profile missing")
        cls._scope(context, scope,root_lease)
        state = State.initial(Initiator._prepare_for_journal(context, signer, now), now)
        try:
            return WitnessJournal.provision(path, scope, key, encode(state), cls._validator(context),
                                            context.witness, observer,root_lease=root_lease)
        finally:
            state.close()

    @classmethod
    def recover_genesis(cls, path, scope, key, context, observer=None, *, root_lease=None):
        require(context.witness is not None, "required witness profile missing")
        cls._scope(context, scope,root_lease)
        return WitnessJournal.recover_genesis(path, scope, key, cls._validator(context), context.witness, observer,root_lease=root_lease)

    @classmethod
    def open(cls, path, scope, key, context, *, client, observer=None,root_lease=None):
        require(context.witness is not None, "required witness profile missing")
        cls._scope(context, scope,root_lease)
        require(client.signer is not None and client.signer.public() == context.initiator, "witness signer is not original session owner")
        journal, snapshot = WitnessJournal._open(path, scope, key, cls._validator(context), context.witness, client, observer,root_lease=root_lease)
        return cls(journal, context, observer, snapshot)
