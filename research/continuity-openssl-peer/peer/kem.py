"""Independent ContextBound combiner and SDK purpose derivation over OpenSSL."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .wire import lp, require


def hkdf(secret: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(hashes.SHA256(), 32, salt, info).derive(secret)


@dataclass(frozen=True)
class SdkBinding:
    version: int
    policy_digest: bytes
    root_digest: bytes

    def __post_init__(self) -> None:
        require(0 < self.version < (1 << 32), "SDK version")
        require(len(self.policy_digest) == len(self.root_digest) == 32, "SDK digest size")

    def state(self) -> bytes:
        return self.version.to_bytes(4, "big") + self.policy_digest

    def wire(self) -> bytes:
        return self.root_digest + self.state()

    def combine(self, pq: bytes, dh: bytes, ciphertext: bytes,
                public: bytes, context: bytes) -> bytes:
        require(len(pq) == len(dh) == 32 and any(dh), "invalid component secret")
        require(len(ciphertext) == 1120 and len(public) == 1216 and 0 < len(context) <= 65536,
                "ContextBound input shape")
        wrapped = lp(b"Q-PERIAPT-POLICY-CONTEXT/v1") + lp(self.policy_digest) + lp(context)
        fields = (b"Q-PERIAPT-HYBRID-KEM/v1", b"ML-KEM-768+X25519",
                  self.version.to_bytes(4, "big"), pq, dh, ciphertext[:1088], public[:1184],
                  ciphertext[1088:], public[1184:], wrapped)
        return hashlib.sha3_256(b"".join(lp(field) for field in fields)).digest()

    def initial_confirmation(self, secret: bytes, context: bytes) -> bytes:
        label = b"ContinuityBootstrapCandidate/v1/initial"
        info = (b"QPeriapt-SDK-Key-v1" + (1).to_bytes(4, "big") + (2).to_bytes(4, "big")
                + self.state() + self.root_digest + (3).to_bytes(4, "big")
                + len(label).to_bytes(2, "big") + label
                + len(context).to_bytes(4, "big") + context + (32).to_bytes(2, "big"))
        return hkdf(secret, b"QPeriapt-SDK-HKDF-SHA256-v1", info)

    def encapsulate(self, public: bytes, context: bytes) -> tuple[bytes, bytes]:
        require(len(public) == 1216, "hybrid public key length")
        pq, ciphertext = mlkem.MLKEM768PublicKey.from_public_bytes(public[:1184]).encapsulate()
        ephemeral = x25519.X25519PrivateKey.generate()
        dh = ephemeral.exchange(x25519.X25519PublicKey.from_public_bytes(public[1184:]))
        wire = ciphertext + ephemeral.public_key().public_bytes_raw()
        return wire, self.combine(pq, dh, wire, public, context)


class HybridPrivate:
    def __init__(self):
        self._pq = mlkem.MLKEM768PrivateKey.generate()
        self._dh = x25519.X25519PrivateKey.generate()

    def public(self) -> bytes:
        return self._pq.public_key().public_bytes_raw() + self._dh.public_key().public_bytes_raw()

    def decapsulate(self, sdk: SdkBinding, wire: bytes, context: bytes) -> bytes:
        require(len(wire) == 1120, "hybrid ciphertext length")
        pq = self._pq.decapsulate(wire[:1088])
        dh = self._dh.exchange(x25519.X25519PublicKey.from_public_bytes(wire[1088:]))
        return sdk.combine(pq, dh, wire, self.public(), context)
