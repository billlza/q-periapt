"""Bounded untrusted interval hints for the original-input verifier, never grants."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from .wire import Interval, Reader, require


def signed_start(wire, offset, body_size=None):
    require(type(wire) is bytes and len(wire) <= 4 + 16384 + 3373, 'historical signed input bound')
    r = Reader(wire); size = r.integer(4)
    require(size <= 16384 and (body_size is None or size == body_size), 'historical signed body size')
    body = r.take(size); r.take(3373); r.finish()
    r = Reader(body); r.take(offset)
    return Interval.read(r).start


def proof_start(wire):
    require(type(wire) is bytes and len(wire) <= 8192, 'historical proof bound')
    r = Reader(wire); r.integer(2); leaf = r.take(r.integer(2))
    r = Reader(leaf); r.take(9)
    return Interval.read(r).start


def snapshot_start(materials):
    # The ordinary manifest verifier requires each selected leaf's interval to
    # lie inside the manifest interval. Its start is thus covered by leaf starts.
    # Tags, signatures, checkpoints, containment and interval intersection are
    # still checked by authenticate; no parsed hint is accepted as authority.
    return max(signed_start(materials.policy, 48, 200),
               signed_start(materials.initiator_credential, 64, 2097),
               signed_start(materials.responder_credential, 64, 2097),
               signed_start(materials.initiator_roster, 48),
               signed_start(materials.responder_roster, 48),
               proof_start(materials.classical_proof), proof_start(materials.pq_proof))
