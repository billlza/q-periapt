"""Distinct scope, owner lifetime and missing-state controls for registration."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import replace
import hashlib
import os
from qperiapt_continuity_reference.registration import Registration
from qperiapt_continuity_reference.registration_inputs import Inputs
from qperiapt_continuity_reference.registration_protocol import request_body
from qperiapt_continuity_reference.wire import SigningKey, require


def before_accept(f):
    initial = (f.path / 'head').read_bytes()
    f.refuses('wrong-independent-intent', lambda: Registration.open(f.path, f.identity, f.key,
              replace(f.intent, device=b'x' * 16)), 'journal identity/owner/context')
    f.refuses('wrong-wrapping-key', lambda: Registration.open(f.path, f.identity, bytes(32), f.intent), '')
    require(f.refusals[-1]['type'] == 'InvalidTag', 'wrong wrapping key did not fail authentication')
    owner = f.owner()
    try:
        wrong = replace(f.pins.initiator, roster_digest=b'x' * 32)
        f.refuses('response-cannot-choose-current-roster', lambda: owner.accept(f.materials.initiator_credential,
                  f.materials.initiator_roster, wrong, f.pins, f.materials, 150, witness_pin=f.pin), 'roster checkpoint')
    finally: owner.close()
    require((f.path / 'head').read_bytes() == initial, 'rejected trust input mutated registration')
    other = SigningKey(); forged = other.sign(14, request_body(f.intent, os.urandom(32), other.public()))
    f.call('different-valid-request-is-not-issuance-retry', 38, forged, status=2)
    f.call('tampered-original-proof', 38, f.request[:-1] + bytes([f.request[-1] ^ 1]), status=2)


def before_prepare(f):
    owner = f.owner(); before = (f.path / 'head').read_bytes()
    try:
        f.refuses('registration-child-directory-alias', lambda: owner.prepare(f.path, Inputs(f.pins, f.materials, f.pin), 150),
                  'directories must be separate')
    finally: owner.close()
    require((f.path / 'head').read_bytes() == before, 'alias admission mutated registration')


def lifetime(f):
    owner = f.owner(); child = owner.session(170, transport=f.transport()); retained = child.next_id
    owner.close()
    f.refuses('closed-parent-revokes-child', lambda: child.next_id(now=170), 'closed registration')
    reopened = f.owner()
    try:
        f.refuses('new-parent-does-not-revive-old-child', lambda: retained(now=170), 'closed registration')
        with reopened.session(170, transport=f.transport()) as current: current.next_id(now=170)
    finally: reopened.close()
    failing = f.owner(); child = failing.session(170, transport=f.transport())
    real_close = child._owner.close
    def failure_after_cleanup():
        real_close()
        raise OSError('injected error after real child cleanup')
    child._owner.close = failure_after_cleanup
    try:
        f.refuses('child-cleanup-error-is-not-success', failing.close, 'injected error after real child cleanup')
        f.refuses('cleanup-error-cannot-revive-parent', lambda: failing.session(170, transport=f.transport()), 'closed registration owner')
        replacement = f.owner()
        try: replacement.status()
        finally: replacement.close()
    finally: failing.close()


def callback_close(f, identity):
    owner = None
    def observer(stage):
        if stage == 'protocol:send-committed':
            f.refuses('nested-registration-call-refused', owner.status, 'operation already in progress')
            owner.close()
    owner = f.owner(observer)
    try:
        with owner.session(170, transport=f.transport()) as child:
            f.refuses('close-after-commit-withholds-ciphertext', lambda: child.send(identity, b'closed callback original', b'registered', now=170),
                      'closed journal')
    finally: owner.close()


def missing_active(f):
    # Displace only this synthetic active fixture's exact original head; retain
    # it outside the child directory, and restore the same inode/bytes afterward.
    path = f.session_path / 'head'; saved = f.private / 'displaced-original-head'
    before = path.read_bytes(); inode = path.stat().st_ino; os.rename(path, saved)
    try:
        f.worker('missing-active-child-refused', 'next_id', now=210, refusal='missing original witnessed image' if f.bridge else 'missing active image')
        require(not path.exists() and saved.read_bytes() == before, 'missing active child was recreated')
    finally: os.rename(saved, path)
    require(path.stat().st_ino == inode and path.read_bytes() == before, 'original head restoration differs')
    f.observations['missing_child_control'] = {'head_sha256': hashlib.sha256(before).hexdigest(), 'same_inode_restored': True,
                                             'scope': 'Controlled fixture displacement/restoration, not a production repair or reset.'}
