"""Independent candidate envelope codec; no Q-Periapt engine imports."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, utils

IDENTITY = b"Q-PERIAPT-CONTINUITY-IDENTITY-CANDIDATE/v1"
ORDER = int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
MAX_U64 = (1 << 64) - 1


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def lp(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def ldh(domain: bytes, value: bytes) -> bytes:
    return hashlib.sha3_256(lp(domain) + lp(value)).digest()


def digest(name: bytes, value: bytes) -> bytes:
    return ldh(b"Q-PERIAPT-CONTINUITY-" + name + b"-CANDIDATE/v1", value)


class Reader:
    def __init__(self, value: bytes):
        self.value = value
        self.offset = 0

    def take(self, count: int) -> bytes:
        require(0 <= count <= len(self.value) - self.offset, "truncated record")
        result = self.value[self.offset:self.offset + count]
        self.offset += count
        return result

    def integer(self, count: int) -> int:
        return int.from_bytes(self.take(count), "big")

    def finish(self) -> None:
        require(self.offset == len(self.value), "trailing record bytes")


@dataclass(frozen=True)
class Interval:
    start: int
    end: int

    @classmethod
    def read(cls, reader: Reader) -> Interval:
        start, end = reader.integer(8), reader.integer(8)
        require(0 <= start < end < MAX_U64, "invalid interval")
        return cls(start, end)

    def check(self, now: int) -> None:
        require(type(now) is int and self.start <= now < self.end, "expired or premature authority")

    def contains(self, other: Interval) -> bool:
        return self.start <= other.start and other.end <= self.end


def generation(value: int) -> int:
    require(0 < value < MAX_U64, "invalid generation")
    return value


def nonzero(value: bytes) -> bytes:
    require(any(value), "zero commitment or identity")
    return value


@dataclass(frozen=True, repr=False)
class VerificationKey:
    raw: bytes

    def __post_init__(self) -> None:
        require(len(self.raw) == 1985, "hybrid public key length")
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), self.raw[1952:])
        require(key.public_bytes(serialization.Encoding.X962,
                                 serialization.PublicFormat.CompressedPoint) == self.raw[1952:],
                "noncanonical P-256 key")
        mldsa.MLDSA65PublicKey.from_public_bytes(self.raw[:1952])

    def shares_component(self, other: VerificationKey) -> bool:
        return self.raw[:1952] == other.raw[:1952] or self.raw[1952:] == other.raw[1952:]

    def open(self, wire: bytes, purpose: int, body_size: int | None = None) -> bytes:
        require(len(wire) <= 4 + 16384 + 3373, "signed envelope capacity")
        reader = Reader(wire)
        size = reader.integer(4)
        require(size <= 16384 and (body_size is None or size == body_size), "signed body size")
        body = reader.take(size)
        pq = reader.take(3309)
        r, s = reader.integer(32), reader.integer(32)
        reader.finish()
        require(0 < r < ORDER and 0 < s <= ORDER // 2, "noncanonical ECDSA signature")
        bound = IDENTITY + bytes([purpose]) + size.to_bytes(4, "big") + body
        classic = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), self.raw[1952:])
        classic.verify(utils.encode_dss_signature(r, s), bound, ec.ECDSA(hashes.SHA256()))
        mldsa.MLDSA65PublicKey.from_public_bytes(self.raw[:1952]).verify(pq, bound, IDENTITY)
        return body


class SigningKey:
    """OpenSSL private owners; Python temporary bytes do not promise erasure."""
    def __init__(self):
        self._pq = mldsa.MLDSA65PrivateKey.generate()
        self._ec = ec.generate_private_key(ec.SECP256R1())

    def public(self) -> VerificationKey:
        return VerificationKey(self._pq.public_key().public_bytes_raw()
            + self._ec.public_key().public_bytes(serialization.Encoding.X962,
                                               serialization.PublicFormat.CompressedPoint))

    def sign(self, purpose: int, body: bytes) -> bytes:
        require(1 <= purpose <= 26 and len(body) <= 16384, "unsupported signed envelope")
        length = len(body).to_bytes(4, "big")
        bound = IDENTITY + bytes([purpose]) + length + body
        pq = self._pq.sign(bound, IDENTITY)
        r, s = utils.decode_dss_signature(self._ec.sign(bound, ec.ECDSA(hashes.SHA256())))
        return length + body + pq + r.to_bytes(32, "big") + min(s, ORDER - s).to_bytes(32, "big")
