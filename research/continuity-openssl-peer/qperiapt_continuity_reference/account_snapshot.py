"""Conditional common-account envelope around the unchanged session payload."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import replace

from .account_record import AccountRecord
from .account_state import AccountState
from .storage_budget import (MAX_ACCOUNT_COORDINATION, MAX_ACCOUNT_RECORD,
                             MAX_SHARED_STATE, MAX_STATE, MAX_ACCOUNT_STATE,
                             MAX_ACCOUNT_ROSTER_COORDINATION)
from .wire import Reader, require


def shared(context):
    return (context.devices is not None
            and context.devices[0].pin.account == context.devices[1].pin.account)


def initial_account(context):
    require(shared(context), "common account requires matching account identities")
    local, peer = context.devices
    require(local.pin.root == peer.pin.root, "common account root differs")
    account = AccountState.initial(local.pin, context.family, context.policy_digest,
                                   local.roster_wire, local.pin.checkpoint())
    # The original owning head must also authorize the established peer. Never
    # advance a local head from the other role's independently cached snapshot.
    require(account.view(local, local=True).active() and account.view(peer).active(),
            "original common account roster does not authorize both roles")
    return account


def initialize(state, now=None):
    require(shared(state.operation._context), "not a shared-account session")
    require(state.format_version == 5 and state.local_authority is None
            and state.peer_authority is None and state.local_renewal is None
            and state.account_authority is None and state.account_renewal is None,
            "shared-account initialization requires original unadvanced state")
    context = state.operation._context
    account = initial_account(context)
    if now is not None:
        account.view(context.devices[0], local=True).check(now)
        account.view(context.devices[1]).check(now)
    state.account_authority, state.account_renewal = account, AccountRecord()
    state.format_version = 9


def encode(state, *, policy=None):
    from .state_codec import encode as encode_base
    context = state.operation._context
    require(state.format_version in (9, 10) and shared(context)
            and state.account_authority is not None and state.account_renewal is not None,
            "shared-account snapshot requires its complete authority and record")
    require(state.local_authority is None and state.peer_authority is None
            and state.local_renewal is None, "shared-account snapshot has competing role records")
    account, record = state.account_authority, state.account_renewal
    require((state.format_version == 10) == (record.roster is not None), "roster requires explicit snapshot format")
    if record.roster is not None:
        record.roster.check_policy(context, policy)
    require(account.authority == context.devices[0].pin and account.family == context.family
            and account.policy == context.policy_digest, "shared-account original scope differs")
    account.view(context.devices[1])
    record.validate(account, context.devices[0])
    if state.traffic is None:
        require(record == AccountRecord() and account.encode() == initial_account(context).encode(),
                "account changes require an established original session")
    if context.witness is not None:
        require(record.pending is None and record.expired is None,
                "local account disposition cannot bypass required witness")
    base = encode_base(replace(state, format_version=5, account_authority=None, account_renewal=None))
    account_wire, record_wire = account.encode(), record.encode()
    result = ((b"QPREFS10" if state.format_version == 10 else b"QPREFS09") + len(base).to_bytes(4, "big") + base
              + len(account_wire).to_bytes(4, "big") + account_wire
              + len(record_wire).to_bytes(4, "big") + record_wire)
    require(len(base) <= MAX_STATE and len(result) <= (MAX_SHARED_STATE if state.format_version == 10 else MAX_ACCOUNT_STATE),
            "shared-account snapshot capacity")
    return result


def decode(payload, context, *, policy=None):
    from .identity_state import bind
    from .state_codec import decode as decode_base
    require(shared(context) and len(payload) <= MAX_SHARED_STATE, "shared-account snapshot scope or capacity")
    reader = Reader(payload)
    tag = reader.take(8)
    require(tag in (b"QPREFS09", b"QPREFS10") and (tag == b"QPREFS10" or len(payload) <= MAX_ACCOUNT_STATE),
            "shared-account snapshot schema or legacy capacity")

    def field(maximum):
        size = reader.integer(4)
        require(0 < size <= maximum, "shared-account snapshot field capacity")
        return reader.take(size)

    base = field(MAX_STATE)
    require(base[:8] == b"QPREFS05", "shared-account base format")
    state = decode_base(base, context)
    try:
        require(state.local_authority is None and state.peer_authority is None
                and state.local_renewal is None, "shared-account base has competing role records")
        account = AccountState.read(field(MAX_ACCOUNT_RECORD), context.devices[0].pin,
                                    context.family, context.policy_digest)
        record = AccountRecord.read(field(MAX_ACCOUNT_ROSTER_COORDINATION if tag == b"QPREFS10" else MAX_ACCOUNT_COORDINATION), context.devices[0],
                                    context.family, context.policy_digest, account)
        reader.finish()
        state.format_version = 10 if tag == b"QPREFS10" else 9
        state.account_authority, state.account_renewal = account, record
        bind(state, context)
        require(encode(state, policy=policy) == payload, "noncanonical shared-account snapshot")
        return state
    except BaseException:
        state.close()
        raise


def base_size(payload):
    require(payload[:8] in (b"QPREFS09", b"QPREFS10") and len(payload) >= 12, "shared-account snapshot prefix")
    size = int.from_bytes(payload[8:12], "big")
    require(0 < size <= MAX_STATE and size <= len(payload) - 12, "shared-account business size")
    return size
