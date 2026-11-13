"""Actual full business journal shared by local and witnessed account scenarios."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from local_budget_controls import inventory
from qperiapt_continuity_reference.storage_budget import MAX_STATE
from qperiapt_continuity_reference.wire import require


def fill(f):
    parent = f.owner()
    try:
        with parent.session(170, transport=f.transport()) as owner:
            def current():
                with owner._owner._state(operational=False) as (_, state):
                    return inventory(state)
            plain = bytes(range(256)) * 64
            first_id = owner.next_id(now=170)
            first_wire = owner.send(first_id, plain, b"", now=170)
            for _ in range(63):
                owner.send(owner.next_id(now=170), plain, b"", now=170)
            offer = owner.prepare_rekey_offer(now=170)
            response = f.call("full-rekey-response", 14, offer)
            final = owner.accept_rekey_response(response, now=170)
            receipt = f.call("full-rekey-receipt", 15, final)
            require(owner.accept_rekey_receipt(receipt, now=170) == 1, "full common epoch")
            cap = MAX_STATE - 65536
            rows = 64
            while current()["traffic_bytes"] < cap:
                before = current()["traffic_bytes"]
                remaining = cap - before
                require(remaining >= 153 and rows < 128, "full common row bound")
                size = min(16384, remaining - 153)
                if 0 < remaining - 153 - size < 153:
                    size -= 153
                require(0 <= size <= 16384, "full common plaintext bound")
                last_id = owner.next_id(now=170)
                last_plain = b"g" * size
                last_wire = owner.send(last_id, last_plain, b"", now=170)
                if rows == 64:
                    ack_id, ack_wire, ack_plain = last_id, last_wire, last_plain
                rows += 1
                require(current()["traffic_bytes"] - before == size + 153, "actual common row size")
            original = current()
            require(original["traffic_bytes"] == cap and original["outboxes"] == rows == 123, "full original business allowance")
        return {"plain": plain, "first_id": first_id, "first_wire": first_wire,
                "last_id": last_id, "last_wire": last_wire, "last_plain": last_plain,
                "ack_id": ack_id, "ack_wire": ack_wire, "ack_plain": ack_plain,
                "inventory": original, "traffic_bytes": cap, "rows": rows}
    finally:
        parent.close()
