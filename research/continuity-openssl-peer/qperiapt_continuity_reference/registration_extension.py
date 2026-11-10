"""Adopt an explicit extension only before a child context has been selected."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from .authority import authenticate_policy
from .enrollment_extension import monotonic
from .identity import verify_device
from .registration_state import Admission, Extension, signer
from .wire import require


def adopt(parent, approval, issued, roster, pin, policy, now):
    snapshot, image = parent._image()
    require(image.admission is not None, 'registration is not accepted')
    require(image.child is None and not image.active, 'registration child was already prepared')
    original = parent._intent
    granted, cert = issued.verify(approval, original)
    public = signer(image.seed).public()
    require(cert.key == public, 'extension changes original signing key')
    signed_policy = authenticate_policy(policy.pins, policy.materials, now, witness_pin=policy.witness)
    require(signed_policy.family == original.family, 'extension policy family differs')
    parent._check_policy_keys(public, policy.pins, policy.witness)
    head = signed_policy.version.to_bytes(8, 'big') + signed_policy.digest
    device = verify_device(pin, issued.certificate, roster, original.family, now)
    granted.admit_device(device, public)
    previous_intent, previous = image.effective(original)
    monotonic(pin.checkpoint(), issued.checkpoint, 'extension current issuance')
    monotonic(pin.checkpoint(), previous.checkpoint, 'extension current roster')
    if image.extension is not None and approval.identity == image.extension.approval.identity:
        saved = image.extension
        require(approval == saved.approval and issued.checkpoint == saved.issued_checkpoint
                and cert.digest == saved.admission.validate(previous_intent, public).digest
                and head == saved.admission.policy, 'different committed credential extension')
        parent._alive(); return previous.journal
    expected = None if image.extension is None else image.extension.approval.identity
    require(approval.previous == expected, 'extension does not follow the retained predecessor')
    if image.extension is not None:
        require(approval.enrollment == image.extension.approval.enrollment, 'extension changes original enrollment operation')
    require(approval.until > previous_intent.validity.end, 'extension must increase retained credential validity')
    monotonic(approval.predecessor, previous.checkpoint, 'extension approved roster')
    monotonic(head, previous.policy, 'extension policy')
    image.extension = Extension(approval, previous_intent.validity.end, previous.checkpoint, previous.policy,
                                issued.checkpoint, issued.roster,
                                Admission(pin.checkpoint(), head, previous.journal, issued.certificate, roster))
    _, saved = parent._save(snapshot, image, 'extension-adopted')
    parent._alive(); return saved.extension.admission.journal
