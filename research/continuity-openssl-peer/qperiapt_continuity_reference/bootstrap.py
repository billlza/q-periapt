"""Independent volatile initiator with exact successful-reply replay.

No ciphertext dispatch, prekey consumption or durable session admission is
authorized by these objects. A pending root has no application traffic API.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from __future__ import annotations

import hmac
import os

from .authority import Context
from .kem import HybridPrivate, hkdf
from .wire import SigningKey, ldh, require

DOMAIN = b"Q-PERIAPT-CONTINUITY-BOOTSTRAP-CANDIDATE/v1/"
KDF = b"Q-PERIAPT-CONTINUITY-BOOTSTRAP-KDF-CANDIDATE/v1/"


def digest(label: bytes, value: bytes) -> bytes:
    return ldh(DOMAIN + label, value)


def mac(key: bytes, value: bytes) -> bytes:
    return hmac.digest(key, value, "sha256")


class Initiator:
    def __init__(self, context: Context, signer: SigningKey, now: int):
        require(context.witness is None, "volatile owner cannot release required-witness traffic")
        self._initialize(context, signer, now)

    @classmethod
    def _prepare_for_journal(cls, context, signer, now):
        owner = cls.__new__(cls)
        owner._initialize(context, signer, now)
        return owner

    def _initialize(self, context, signer, now):
        context.check(now)
        require(signer.public() == context.initiator, "initiator signing owner")
        self._context = context
        self._reply_key = HybridPrivate()
        prefix = b"QPBSI001" + context.digest + os.urandom(32) + self._reply_key.public()
        ciphertext, self._first_secret = context.sdk.encapsulate(
            context.responder_prekey, digest(b"kem-initial", prefix))
        core = prefix + ciphertext
        t0 = digest(b"initial-core", core)
        self._initial = signer.sign(5, core + mac(context.sdk.initial_confirmation(self._first_secret, t0), t0))
        self._reply: bytes | None = None
        self._final: bytes | None = None
        self._session_id: bytes | None = None
        self._root: bytes | None = None
        self._closed = False

    def initial(self, now: int) -> bytes:
        self._context.check(now)
        require(not self._closed, "closed initiator")
        return self._initial

    def finish(self, reply: bytes, now: int) -> bytes:
        self._context.check(now)
        require(not self._closed, "closed initiator")
        if self._reply is not None:
            require(reply == self._reply, "conflicting successful reply")
            require(self._final is not None, "missing completed final")
            return self._final
        body = self._context.responder.open(reply, 6, 1256)
        h0 = digest(b"initial-wire", self._initial)
        require(body[:72] == b"QPBSR001" + self._context.digest + h0, "reply transcript scope")
        require(self._reply_key is not None and self._first_secret is not None, "missing pending secret")
        second = self._reply_key.decapsulate(self._context.sdk, body[104:1224],
                                            digest(b"kem-reply", body[:104]))
        t1 = digest(b"reply-core", body[:1224])
        ikm = self._first_secret + second
        responder = hkdf(ikm, t1, KDF + b"confirmation-responder")
        require(hmac.compare_digest(mac(responder, t1), body[1224:]), "responder confirmation")
        initiator = hkdf(ikm, t1, KDF + b"confirmation-initiator")
        prefix = b"QPBSF001" + self._context.digest + h0 + digest(b"reply-wire", reply)
        final = prefix + mac(initiator, digest(b"final-core", prefix))
        session_id = digest(b"session-id", prefix)
        seed = hkdf(ikm, t1, KDF + b"handshake-seed")
        root = hkdf(seed, session_id, KDF + b"session-root/" + self._context.digest)
        # Publish completion only after all authentication and derivation succeed.
        self._reply, self._final, self._session_id, self._root = reply, final, session_id, root
        self._reply_key, self._first_secret = None, None
        return final

    def session_id(self) -> bytes:
        require(not self._closed and self._session_id is not None, "no completed pending session")
        return self._session_id

    def activate_volatile_traffic(self, now: int):
        """Transfer the root into the explicitly non-durable experiment state."""
        from .traffic import VolatileTraffic
        require(not self._closed and self._root is not None and self._session_id is not None,
                "no untransferred pending root")
        traffic = VolatileTraffic(self._context, self._session_id, self._root, now)
        self._root = None
        return traffic

    def close(self) -> None:
        self._closed = True
        self._reply_key = self._first_secret = self._root = None
