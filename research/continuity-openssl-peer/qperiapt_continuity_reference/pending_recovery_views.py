"""Complete public projection of this single-bootstrap/session journal profile."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from .bootstrap import digest as bootstrap_digest
from .identity_state import IdentityState
from .pending_recovery_protocol import MAX_METADATA, number
from .resolution import ciphertext_digest
from .traffic import DOMAIN, message_id
from .wire import digest, ldh, require


def items(values):
    return number(len(values)) + b"".join(values)


def optional(value):
    return b"\0" if value is None else b"\1" + value


def record(identity, context, phase, authorities, tag, metadata):
    return (identity + context + bytes([phase]) + items(authorities) + number(0) + number(0)
            + bytes([tag]) + metadata)


def epoch_view(owner, state, epoch):
    traffic = owner.epochs[epoch]
    result = b"".join(number(n) for n in (epoch, traffic._send_floor, traffic._sent,
                                          traffic._receive_floor, traffic._received))
    result += optional(number(traffic._receive_limit) if traffic._receive_limit is not None else None)
    resolution = owner.resolutions.get(epoch)
    result += bytes([resolution.phase]) + resolution.identity if resolution is not None else b"\0"
    result += items([message_id(owner.session, 1, i, epoch) + ciphertext_digest(wire)
                     for i, (_intent, wire) in sorted(traffic._outbox.items())])
    result += items([message_id(owner.session, 2, i, epoch) + number(i) + number(len(plain))
                     for i, (_intent, plain) in sorted(traffic._inbox.items()) if plain is not None])
    result += items([number(i) for i in sorted(traffic._skipped)])
    result += items([message_id(owner.session, 2, i, epoch) + number(i)
                     for i, (_intent, plain) in sorted(traffic._inbox.items()) if plain is None])
    pending = state.pending if epoch == owner.sending else None
    reservation = (pending.identity + number(len(pending.plaintext)) + number(len(pending.ad)) + b"\0"
                   if pending is not None else None)
    return result + optional(reservation) + bytes([traffic._send_closed])


def encode(state, scope, head):
    context = state.operation._context; op = state.operation
    local = state.local_authority or IdentityState.initial(context, role=0)
    peer = state.peer_authority or IdentityState.initial(context, role=1)
    authorities = [digest(b"AUTHORITY", v.original.pin.account + v.listing.checkpoint() + context.family)
                   for v in (local, peer)]
    # This profile has one bootstrap per original journal. Its immutable scope
    # identity is the host initiation correlation; all projected object IDs are
    # deterministic and never allocate a new business operation after expiry.
    operation = ldh(b"Q-PERIAPT-CONTINUITY-VAULT-INITIATION-CANDIDATE/v1", scope.identity)
    phase = 19 if state.traffic is not None else (7 if op._reply is not None else 6)
    flights = [bootstrap_digest(b"initial-wire", op._initial),
               bootstrap_digest(b"reply-wire", op._reply) if op._reply is not None else None,
               bootstrap_digest(b"final-wire", op._final) if op._final is not None else None, op._session_id]
    bootstrap = (operation + context.digest + bytes([0, phase]) + optional(scope.identity)
                 + b"".join(optional(v) for v in flights) + b"\0")
    records = {operation: record(operation, context.digest, phase, authorities, 1, bootstrap)}
    if state.traffic is not None:
        owner = state.traffic; remote = peer.original.pin
        pending = owner.scope().target if owner.plan is not None or owner.request is not None else None
        session = (operation + owner.session + b"\1" + remote.account + remote.device + number(remote.generation)
                   + number(owner.confirmed) + number(owner.sending) + number(owner.receiving)
                   + optional(number(pending) if pending is not None else None) + b"\1\0"
                   + items([epoch_view(owner, state, e) for e in owner.epochs]))
        identity = ldh(DOMAIN + b"record", owner.session)
        require(identity not in records, "projected record identity collision")
        records[identity] = record(identity, context.digest, 19, authorities, 3, session)
    for role, identity_state in enumerate((local, peer)):
        original = identity_state.original; identity = ldh(b"Q-PERIAPT-CONTINUITY-JOURNAL-ROSTER/v1", original.pin.account)
        require(identity not in records, "projected roster identity collision")
        # A distinct public-history tag identifies the reference representation;
        # the shared inspector leaves public history opaque for domain checking.
        history = (b"QPIRHS01" + bytes([role]) + original.credential + identity_state.current.digest
                   + original.key.raw + number(identity_state.current.validity.start)
                   + number(identity_state.current.validity.end) + identity_state.encode())
        roster = original.pin.account + identity_state.listing.checkpoint() + number(len(history)) + history
        records[identity] = record(identity, context.digest, 20, [authorities[role]], 4, roster)
    result = head.wire() + local.original.pin.account + number(0) + items([records[k] for k in sorted(records)])
    require(len(result) <= MAX_METADATA, "pending recovery public view capacity")
    return result
