"""Original parent/child root fences, separate from the frozen encrypted head."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass, replace
import hashlib
import hmac
from .account_authority import _RecoveryAccess
from .account_binding import Binding, SIZE
from .account_root_record import RetainedPlan
from .registration import RegistrationJournal
from .wire import Reader, require

DOMAIN = b'Q-PERIAPT-INDEPENDENT-ROOT-FENCE/v1/'
TAG = b'QPRFRT01'
MAX_BYTES = 71000
RECEIPT_BYTES = 3449


def _optional(value):
    require(value is None or type(value) is bytes and len(value) == 32, 'root fence digest')
    return b'\0' if value is None else b'\1' + value


def _read_optional(reader):
    present = reader.integer(1)
    require(present in (0, 1), 'root fence optional digest')
    return reader.take(32) if present else None


def _digest(wire):
    return None if wire is None else hashlib.sha256(wire).digest()


@dataclass(frozen=True, repr=False)
class Fence:
    kind: int
    scope: bytes
    binding: Binding
    image: bytes
    pending: bytes | None
    authority: bytes | None
    operation: bytes
    plan: bytes
    decision: bytes
    receipt: bytes | None

    def wire(self, journal):
        require(self.kind in (1, 2) and len(self.scope) == 96 and len(self.image) == 32
                and len(self.operation) == len(self.plan) == 32 and 0 < len(self.decision) <= 65536,
                'root fence shape')
        receipt = b'' if self.receipt is None else self.receipt
        require(len(receipt) in (0, RECEIPT_BYTES), 'root fence retirement size')
        body = (TAG + bytes([self.kind]) + self.scope + self.binding.wire() + self.image
                + _optional(self.pending) + _optional(self.authority) + self.operation + self.plan
                + len(self.decision).to_bytes(4, 'big') + self.decision
                + len(receipt).to_bytes(2, 'big') + receipt)
        wire = body + hmac.digest(journal._intent_key, DOMAIN + body, 'sha256')
        require(len(wire) <= MAX_BYTES, 'root fence capacity')
        return wire


def _expectations(access, pin):
    require(type(access) is _RecoveryAccess, 'original root metadata access required')
    _, phase, original, decision = access.observation()
    plan = RetainedPlan(pin, original)
    require(decision, 'original root freeze is not bound')
    descriptor = plan.check_decision(decision)
    access.check_scope(access.binding.account, descriptor.family, pin)
    return phase, plan, decision, descriptor


def read(journal, access, pin, kind):
    """Authenticate the fence and every exact original formal record it binds."""
    access.check(); directory = journal._admit(); wire = directory.read('root-fence')
    if wire is None: return None
    require(430 <= len(wire) <= MAX_BYTES, 'root fence capacity')
    body, tag = wire[:-32], wire[-32:]
    require(hmac.compare_digest(tag, hmac.digest(journal._intent_key, DOMAIN + body, 'sha256')),
            'root fence authentication')
    r = Reader(body); require(r.take(8) == TAG, 'root fence schema')
    actual_kind, scope, binding, image = r.integer(1), r.take(96), Binding.read(r.take(SIZE)), r.take(32)
    pending, authority = _read_optional(r), _read_optional(r)
    operation, plan_binding = r.take(32), r.take(32)
    count = r.integer(4); require(0 < count <= 65536, 'root fence decision capacity'); decision = r.take(count)
    count = r.integer(2); require(count in (0, RECEIPT_BYTES), 'root fence retirement size')
    receipt = r.take(count) if count else None; r.finish()
    result = Fence(actual_kind, scope, binding, image, pending, authority, operation, plan_binding, decision, receipt)
    require(result.kind == kind and result.scope == journal.scope.wire() and result.binding == access.binding
            and result.operation == access.operation, 'root fence original owner or operation differs')
    _, plan, selected, _ = _expectations(access, pin)
    require(result.plan == plan.binding and result.decision == selected, 'root fence original approved decision differs')
    if receipt is not None: plan.verify_retirement(decision, receipt)
    require(result.image == _digest(directory.read('head')) and result.pending == _digest(directory.read('intent'))
            and result.authority == _digest(directory.read('authority')), 'root fence original state changed')
    access.check(); return result


def retain(journal, access, pin, kind, *, receipt=None, observation=None):
    phase, plan, decision, descriptor = _expectations(access, pin)
    require(phase != 'Closed', 'closed root operation cannot retain retirement')
    if receipt is not None: plan.verify_retirement(decision, receipt)
    directory = journal._admit()
    if kind == 1:
        require(observation is not None, 'root child authenticated observation required')
        selected = [row for row in descriptor.subjects if row.subject == observation.subject]
        require(len(selected) == 1, 'root freeze omits original child')
        observed = selected[0].head
        require(observed == observation.local_head or (observation.intent_digest is not None
                and observation.local_phase != 'ClosedRecorded' and observed == observation.target),
                'root frozen head is neither original local head nor retained target')
    else:
        require(kind == 2 and observation is None and directory.read('intent') is None,
                'root parent fence requires reconciled original registration')
    head = directory.read('head'); require(head is not None, 'root fence original head absent')
    wanted = Fence(kind, journal.scope.wire(), access.binding, _digest(head), _digest(directory.read('intent')),
                   _digest(directory.read('authority')), access.operation, plan.binding, decision, receipt)
    previous = read(journal, access, pin, kind)
    if previous is not None:
        require(replace(previous, receipt=None) == replace(wanted, receipt=None), 'root fence cannot retarget original state')
        if previous.receipt is not None or receipt is None: return previous
    directory.publish('root-fence', wanted.wire(journal),
                      fixed_slot='root-fence-pending' if receipt is None else 'root-fence-retired')
    current = read(journal, access, pin, kind)
    require(current == wanted, 'root fence durable readback')
    return current


class _Parent(RegistrationJournal):
    def __init__(self, path, scope, key, validate, access, pin, observer):
        self._access, self._pin = access, pin
        super().__init__(path, scope, key, validate, observer)

    def _check_root(self):
        super()._check_root(); self._access.check()

    def _admit_root_fence(self):
        read(self, self._access, self._pin, 2)


def open_parent(path, scope, key, validate, access, pin, observer):
    owner = _Parent(path, scope, key, validate, access, pin, observer)
    try:
        owner.read(); return owner
    except BaseException:
        owner.close(); raise
