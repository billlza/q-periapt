"""Explicit P envelope around the unchanged original session and G/R payloads."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import replace
from .identity import Device
from .policy_record import Record
from .storage_budget import MAX_SHARED_STATE, MAX_POLICY_RECORD, MAX_POLICY_STATE
from .wire import Reader, digest, require
from .witness import fixed


def original(context):
    policy = context.original_policy
    require(policy is not None and context.devices is not None,
            "policy continuation needs original authenticated metadata")
    require(policy.checkpoint() == context.policy_version.to_bytes(8, "big") + context.policy_digest
            and policy.sdk == context.sdk and policy.family == context.family
            and policy.validity == context.intervals[0], "original policy context differs")
    return policy


def current_device(state, context):
    from .identity_state import local_view
    view = local_view(state, context)
    if view is None:
        return context.devices[0]
    pin = replace(view.original.pin, roster_version=view.listing.version, roster_digest=view.listing.digest)
    return Device(view.current.key, pin, view.current.digest, view.current.validity,
                  view.listing.validity, digest(b"AUTHORITY", pin.account + pin.checkpoint() + context.family),
                  view.listing.wire)


def validate(state, context, journal=None):
    policy = original(context)
    require(state.traffic is not None and state.policy_renewal is not None,
            "policy continuation needs its original established state")
    fixed(state.policy_journal, 32)
    if journal is not None:
        require(state.policy_journal == journal, "policy record belongs to another actual journal")
    state.policy_renewal.validate(policy, context.devices[0], state.policy_journal, current_device(state, context))
    roster = None if state.account_renewal is None else state.account_renewal.roster
    history = state.policy_renewal.roster_history
    require((history is not None) == (roster is not None and roster.authorization is not None),
            "policy record requires exact roster history")
    if roster is not None:
        roster.check_policy(context, state.policy_renewal)
    if context.witness is not None:
        require(state.policy_renewal.pending is None and state.policy_renewal.expired is None
                and state.policy_renewal.floor == 0, "witness policy cannot use local-only disposition")


def encode(state):
    from .state_codec import encode as encode_base
    context = state.operation._context
    validate(state, context)
    inner = replace(state, policy_renewal=None, policy_journal=None)
    if state.format_version in (9, 10):
        from .account_snapshot import encode as encode_account
        base = encode_account(inner, policy=state.policy_renewal)
    else:
        base = encode_base(inner)
    require(base[:8] in (b"QPREFS05", b"QPREFS06", b"QPREFS07", b"QPREFS08", b"QPREFS09", b"QPREFS10"),
            "policy continuation base schema")
    record = state.policy_renewal.encode()
    require(state.policy_renewal != Record(), "empty policy wrapper")
    wire = b"QPREFS11" + state.policy_journal + len(base).to_bytes(4, "big") + base + len(record).to_bytes(4, "big") + record
    require(len(base) <= MAX_SHARED_STATE and len(record) <= MAX_POLICY_RECORD and len(wire) <= MAX_POLICY_STATE,
            "policy snapshot capacity")
    return wire


def decode(payload, context):
    from .state_codec import decode as decode_base
    from .identity_state import bind
    require(type(payload) is bytes and len(payload) <= MAX_POLICY_STATE, "policy snapshot capacity")
    policy = original(context)
    r = Reader(payload)
    require(r.take(8) == b"QPREFS11", "policy snapshot tag")
    journal = fixed(r.take(32), 32)
    size = r.integer(4)
    require(0 < size <= MAX_SHARED_STATE, "policy base capacity")
    base = r.take(size)
    require(base[:8] in (b"QPREFS05", b"QPREFS06", b"QPREFS07", b"QPREFS08", b"QPREFS09", b"QPREFS10"),
            "policy snapshot cannot nest wrappers or use legacy base")
    size = r.integer(4)
    require(0 < size <= MAX_POLICY_RECORD, "policy record capacity")
    record = Record.decode_retained(r.take(size), policy, context.devices[0])
    r.finish()
    if base[:8] in (b"QPREFS09", b"QPREFS10"):
        from .account_snapshot import decode as decode_account
        state = decode_account(base, context, policy=record)
    else:
        state = decode_base(base, context)
    try:
        record.validate(policy, context.devices[0], journal, current_device(state, context))
        state.policy_renewal = record
        state.policy_journal = journal
        bind(state, context)
        require(encode(state) == payload, "noncanonical policy snapshot")
        return state
    except BaseException:
        state.close()
        raise


def base_payload(payload):
    require(payload[:8] == b"QPREFS11" and len(payload) >= 48, "policy snapshot prefix")
    size = int.from_bytes(payload[40:44], "big")
    require(0 < size <= MAX_SHARED_STATE and size <= len(payload) - 48, "policy snapshot base size")
    return payload[44:44 + size]


def admit(state, context, now):
    if state.policy_renewal is None:
        context.intervals[0].check(now)
    else:
        validate(state, context)
        state.policy_renewal.admit(original(context), now)


def authorization(state):
    active = None if state.policy_renewal is None else state.policy_renewal.active
    return None if active is None else active.approval.statement
