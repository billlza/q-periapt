"""Record authenticated READY under the original enrollment/child lifetime."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from .connection_confirmation import Confirmation
from .registration_session import open_child
from .wire import require


def confirm(parent, session, proof, now, transport):
    require(parent._child is None, 'close borrowed child before connection confirmation')
    target=Confirmation(session,proof); target.wire()
    snapshot,image=parent._image()
    require(image.active and image.child is not None, 'connection confirmation requires original opened child')
    if image.confirmation is not None:
        require(image.confirmation==target, 'different original peer confirmation')
    child=open_child(parent,'session' if image.confirmation is None else 'connection',now,transport=transport)
    try:
        # This internal coordinator already holds the parent operation guard.
        # Keep the same borrowed child attached so reentrant close revokes it.
        # The raw owner never escapes this module; each boundary rechecks it.
        owner=child._owner
        def alive():
            parent._alive()
            require(parent._child is child and child._owner is owner and owner is not None,
                    'connection child closed during confirmation')
        alive()
        if image.confirmation is None:
            require(owner.activate(now)==session, 'peer confirmation session differs')
            alive(); owner.accept_acknowledgement(proof,now); alive()
            image.confirmation=target
            _,image=parent._save(snapshot,image,'connection-confirmed')
            alive()
            require(owner.connection_identity(now)==session, 'confirmed original session differs')
        alive(); return session
    finally:
        child.close()
