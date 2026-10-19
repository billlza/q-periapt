"""Borrowed protocol operations under the original registration lifetime lease."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from .registration_state import signer
from .wire import require

SIGNING = frozenset({'prepare_rekey_offer', 'respond_rekey_offer', 'accept_rekey_response', 'finish_rekey',
                     'prepare_rekey_request', 'respond_rekey_request', 'advance_rekey_control',
                     'receive_rekey_control', 'start_rekey_control'})
SESSION = SIGNING | frozenset({'initial', 'finish', 'activate', 'next_id', 'send', 'resume', 'receive', 'consume',
    'connection_identity',
    'acknowledgement', 'accept_acknowledgement', 'status', 'upgrade_format', 'storage_format',
    'acknowledgement_for_epoch', 'accept_rekey_receipt', 'rekey_outbox', 'rekey_progress', 'rekey_request_status',
    'replay_rekey_control', 'begin_closed_epoch_resolution', 'acknowledge_closed_epoch_resolution',
    'closed_epoch_resolution_status', 'admit_peer_credential_renewal', 'admit_peer_roster', 'peer_authority_status'})
CONNECTION = SESSION - frozenset({'initial', 'finish', 'activate'})
LOCAL_RENEWAL = frozenset({'stage', 'status', 'commit', 'reconcile_expired'})
JOINT_RENEWAL = frozenset({'prepare', 'status', 'recover', 'commit', 'close_proposal'})
PENDING = frozenset({'request', 'confirm'})


class _Signer:
    """Internal signer capability; it never exposes its encrypted seed or key file."""
    def __init__(self, parent): self._parent = parent

    def public(self):
        with self._parent._lock:
            _, image = self._parent._image()
            require(image.admission is not None, 'registration has no accepted identity')
            return signer(image.seed).public()

    def sign(self, purpose, body):
        with self._parent._lock:
            require(purpose in (5, 7, 9, 10, 11, 12, 13, 26), 'registration device signature purpose')
            _, image = self._parent._image()
            require(image.admission is not None, 'registration has no accepted identity')
            value = signer(image.seed).sign(purpose, body)
            self._parent._alive()
            return value


class BorrowedOwner:
    def __init__(self, parent, owner, allowed):
        self._parent, self._owner, self._allowed = parent, owner, allowed

    def __enter__(self):
        self._parent._alive(); require(self._owner is not None, 'closed registered child'); return self

    def __exit__(self, *_error): self.close()

    def __getattr__(self, name):
        if name not in self._allowed: raise AttributeError(name)
        def invoke(*args, **kwargs):
            parent = self._parent
            with parent._lock:
                require(not parent._busy, 'registration operation already in progress')
                parent._busy = True
                try:
                    parent._alive(); require(self._owner is not None, 'closed registered child')
                    if name in SIGNING:
                        require('signer' not in kwargs, 'registered signing owner cannot be substituted')
                        kwargs['signer'] = _Signer(parent)
                    value = getattr(self._owner, name)(*args, **kwargs)
                    parent._alive(); require(self._owner is not None, 'closed registered child')
                    return value
                except BaseException:
                    parent._close_after_error(); raise
                finally: parent._busy = False
        return invoke

    def _close(self):
        owner, self._owner = self._owner, None
        if owner is not None: owner.close()

    def close(self):
        with self._parent._lock:
            self._close()
            if self._parent._child is self: self._parent._child = None
