"""Canonical authenticated-local snapshots, never a network import capability."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from __future__ import annotations

from dataclasses import dataclass
import hmac
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .account_state import AccountState
    from .account_record import AccountRecord
    from .policy_record import Record as PolicyRecord

from .authority import Context
from .bootstrap import Initiator, digest, mac
from .journal import MAX_STATE
from .kem import HybridPrivate
from .epoch_state import EpochState
from .epoch_codec import encode_epochs, decode_epochs
from .epoch_validation import validate
from .traffic_codec import encode_traffic, decode_traffic
from .snapshot_fields import SendPlan, encode_pending, decode_pending
from .wire import Reader, require
from .identity_state import IdentityState, bind
from .local_renewal_record import Record
from .storage_budget import MAX_LOCAL_METADATA, MAX_LOCAL_STATE


@dataclass(repr=False)
class State:
    operation: Initiator
    traffic: EpochState | None = None
    pending: SendPlan | None = None
    format_version: int = 5
    peer_authority: IdentityState | None = None
    local_authority: IdentityState | None = None
    local_renewal: Record | None = None
    account_authority: AccountState | None = None
    account_renewal: AccountRecord | None = None
    policy_renewal: PolicyRecord | None = None
    policy_journal: bytes | None = None

    @classmethod
    def initial(cls, operation, now):
        from .account_snapshot import initialize, shared
        state = cls(operation)
        try:
            if shared(operation._context):
                initialize(state, now)
            return state
        except BaseException:
            state.close()
            raise

    def close(self):
        self.operation.close()
        if self.traffic is not None:
            self.traffic.close()
        self.pending = None


def encode(state: State) -> bytes:
    if state.policy_renewal is not None:
        from .policy_snapshot import encode as encode_policy
        return encode_policy(state)
    require(state.policy_journal is None, "policy journal requires its record")
    if state.format_version in (9, 10):
        from .account_snapshot import encode as encode_account
        return encode_account(state)
    require(state.account_authority is None and state.account_renewal is None,
            "shared account requires snapshot version nine")
    op = state.operation
    require(not op._closed, "closed snapshot owner")
    phase = 3 if state.traffic is not None else (2 if op._reply is not None else 1)
    require(state.format_version in (1, 2, 3, 4, 5, 6, 7, 8), "snapshot format version")
    tag = {1: b"QPREFS01", 2: b"QPREFS02", 3: b"QPREFS03", 4: b"QPREFS04", 5: b"QPREFS05", 6: b"QPREFS06", 7: b"QPREFS07", 8: b"QPREFS08"}[state.format_version]
    result = bytearray(tag + op._context.digest + bytes([phase]))
    peer_bytes = state.peer_authority.encode() if state.peer_authority is not None else b""
    if state.format_version >= 5:
        result.append(state.peer_authority is not None)
        if state.peer_authority is not None:
            require(phase == 3, "peer authority requires established state")
            result.extend(peer_bytes)
    else:
        require(state.peer_authority is None, "peer authority requires snapshot version five")
    local_bytes = state.local_authority.encode() if state.local_authority is not None else b""
    coordination = b""
    if state.format_version == 6:
        require(phase == 3 and state.local_authority is not None and op._context.witness is not None,
                "local authority requires established witnessed format six")
        result.extend(local_bytes)
    elif state.format_version in (7, 8):
        require(phase == 3 and op._context.witness is None and state.local_renewal is not None,
                "local coordination requires established local-only format seven or eight")
        current = state.local_authority or IdentityState.initial(op._context, role=0)
        state.local_renewal.validate(current)
        coordination = state.local_renewal.encode()
        result.append(state.local_authority is not None)
        result.extend(local_bytes + coordination)
    else:
        require(state.local_authority is None, "local authority requires snapshot version six")
    if state.format_version not in (7, 8):
        require(state.local_renewal is None, "local coordination requires snapshot version seven")
    metadata = len(peer_bytes) + len(local_bytes) + len(coordination) + (1 if state.format_version in (7, 8) else 0)
    # Version seven has two current identity records plus one bounded pending
    # grant/terminal record. Deduct every byte from business space; the existing
    # versions retain their previous bound and 64-KiB control reservation.
    metadata_limit = MAX_LOCAL_METADATA if state.format_version in (7, 8) else 73728
    require(metadata <= metadata_limit, "peer metadata capacity")
    result.extend(op._initial)
    if phase == 1:
        require(op._reply_key is not None and op._first_secret is not None and state.pending is None,
                "waiting snapshot state")
        result.extend(op._reply_key._checkpoint() + op._first_secret)
    else:
        require(op._reply is not None and op._final is not None and op._session_id is not None,
                "completed snapshot state")
        result.extend(op._reply + op._final + op._session_id)
        if phase == 2:
            require(op._root is not None and state.pending is None, "pending confirmed root")
            result.extend(op._root)
        else:
            require(op._root is None and state.traffic is not None, "root transfer marker")
            owner = state.traffic
            if state.format_version == 1:
                validate(owner, state.pending)
                require(owner.confirmed == owner.sending == owner.receiving == 0
                        and owner.plan is None and owner.last is None and owner.request is None and not owner.resolutions,
                        "legacy snapshot requires epoch zero")
                result.extend(encode_traffic(owner.traffic(0), legacy_root=owner.root))
                result.extend(encode_pending(state.pending))
            else:
                result.extend(encode_epochs(owner, state.pending, with_request=state.format_version >= 3,
                                            with_resolution=state.format_version >= 4,
                                            extra_metadata=0 if state.format_version == 8 else metadata))
    # V8 grants identity coordination its own bounded allocation. Only the
    # actual metadata bytes may sit outside the unchanged base state budget.
    base_size = len(result) - (metadata if state.format_version == 8 else 0)
    require(base_size <= MAX_STATE and len(result) <= MAX_LOCAL_STATE, "snapshot aggregate capacity")
    return bytes(result)


def decode(payload: bytes, context: Context) -> State:
    if payload[:8] == b"QPREFS11":
        from .policy_snapshot import decode as decode_policy
        return decode_policy(payload, context)
    if payload[:8] in (b"QPREFS09", b"QPREFS10"):
        from .account_snapshot import decode as decode_account
        return decode_account(payload, context)
    require(len(payload) <= MAX_LOCAL_STATE, "snapshot aggregate capacity")
    reader = Reader(payload)
    tag = reader.take(8)
    require(tag in (b"QPREFS01", b"QPREFS02", b"QPREFS03", b"QPREFS04", b"QPREFS05", b"QPREFS06", b"QPREFS07", b"QPREFS08") and reader.take(32) == context.digest, "snapshot schema/context")
    require(tag == b"QPREFS08" or len(payload) <= MAX_STATE, "legacy snapshot aggregate capacity")
    phase = reader.integer(1)
    require(phase in (1, 2, 3), "snapshot phase")
    peer_authority = None
    if tag in (b"QPREFS05", b"QPREFS06", b"QPREFS07", b"QPREFS08"):
        present = reader.integer(1)
        require(present in (0, 1), "peer authority presence")
        if present:
            require(phase == 3, "peer authority requires established state")
            peer_authority = IdentityState.read(reader, context)
    local_authority = None
    if tag == b"QPREFS06":
        require(phase == 3 and context.witness is not None, "local authority requires established witnessed state")
        local_authority = IdentityState.read(reader, context, role=0)
        require(local_authority.renewal is not None, "local authority requires original root renewal")
    local_renewal = None
    if tag in (b"QPREFS07", b"QPREFS08"):
        require(phase == 3 and context.witness is None, "local coordination requires established local-only state")
        present = reader.integer(1); require(present in (0, 1), "local identity presence")
        if present:
            local_authority = IdentityState.read(reader, context, role=0)
            require(local_authority.renewal is not None, "local authority requires original root renewal")
        local_renewal = Record.read(reader, context)
    op = Initiator.__new__(Initiator)
    op._context, op._closed = context, False
    op._initial = reader.take(5817)
    body = context.initiator.open(op._initial, 5, 2440)
    require(body[:40] == b"QPBSI001" + context.digest, "snapshot initial scope")
    op._reply_key = op._first_secret = op._reply = op._final = op._session_id = op._root = None
    state = State(op, format_version={b"QPREFS01": 1, b"QPREFS02": 2, b"QPREFS03": 3, b"QPREFS04": 4, b"QPREFS05": 5, b"QPREFS06": 6, b"QPREFS07": 7, b"QPREFS08": 8}[tag], peer_authority=peer_authority, local_authority=local_authority, local_renewal=local_renewal)
    try:
        if phase == 1:
            op._reply_key = HybridPrivate._restore(reader.take(96))
            op._first_secret = reader.take(32)
            require(body[72:1288] == op._reply_key.public(), "snapshot reply-key binding")
            t0 = digest(b"initial-core", body[:-32])
            confirmation = context.sdk.initial_confirmation(op._first_secret, t0)
            require(hmac.compare_digest(mac(confirmation, t0), body[-32:]), "snapshot initial confirmation")
        else:
            op._reply, op._final, op._session_id = reader.take(4633), reader.take(136), reader.take(32)
            reply = context.responder.open(op._reply, 6, 1256)
            h0, h1 = digest(b"initial-wire", op._initial), digest(b"reply-wire", op._reply)
            require(reply[:72] == b"QPBSR001" + context.digest + h0
                    and op._final[:104] == b"QPBSF001" + context.digest + h0 + h1
                    and op._session_id == digest(b"session-id", op._final[:104]), "snapshot completed transcript")
            if phase == 2:
                op._root = reader.take(32)
            else:
                if state.format_version == 1:
                    state.traffic = EpochState.initial(decode_traffic(reader, context, op._session_id, legacy=True))
                    state.pending = decode_pending(reader)
                    validate(state.traffic, state.pending)
                else:
                    state.traffic, state.pending = decode_epochs(reader, context, op._session_id,
                                                                 with_request=state.format_version >= 3,
                                                                 with_resolution=state.format_version >= 4)
        reader.finish()
        bind(state, context)
        require(encode(state) == payload, "noncanonical snapshot")
        return state
    except BaseException:
        state.close()
        raise
