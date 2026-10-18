"""Independent four-flight rekey computations; no persistence or release owner.

The caller must separately enforce settled history, reservations, exact outboxes,
directional cutovers, the aggregate send budget and commit-before-release.
These functions grant no output
permission and do not claim that an attacker has lost knowledge of retained keys.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
import hmac

from .authority import Context
from .kem import HybridPrivate, hkdf
from .wire import MAX_U64, ldh, require

DOMAIN = b"Q-PERIAPT-CONTINUITY-REKEY-CANDIDATE/v1/"
PROFILE_TEXT = (b"ML-KEM-768+X25519/ContextBound;ML-DSA-65+P-256/SHA-256;"
                b"accountable-epoch-ratchet/v6;messages/v3;retained-epochs=4;"
                b"settled-prefix-attestation/v1;application-send-budget/v1;control-request/v1")
FLIGHTS = ((b"QPRKOF01", 9, 1369), (b"QPRKRP01", 10, 1337),
           (b"QPRKFN01", 11, 257), (b"QPRKRC01", 12, 289))


def digest(label: bytes, value: bytes) -> bytes:
    return ldh(DOMAIN + label, value)


def genesis(session: bytes, context: bytes) -> bytes:
    require(len(session) == len(context) == 32, "rekey genesis scope")
    return digest(b"genesis", session + context)


def confirmation(root: bytes, label: bytes, core: bytes) -> bytes:
    require(len(root) == 32, "rekey root size")
    key_label = b"responder" if label == b"response" else label
    key = hkdf(root, None, DOMAIN + key_label + b"-confirmation")
    return hmac.digest(key, digest(label + b"-core", core), "sha256")


@dataclass(frozen=True)
class RekeyScope:
    context: Context
    session: bytes
    prior: int
    predecessor: bytes

    def __post_init__(self):
        require(len(self.session) == len(self.predecessor) == 32
                and type(self.prior) is int and 0 <= self.prior < MAX_U64 - 1, "rekey scope")
        if self.prior == 0:
            require(self.predecessor == genesis(self.session, self.context.digest), "rekey genesis predecessor")

    @property
    def target(self):
        return self.prior + 1

    def role(self, flight):
        require(type(flight) is int and 0 <= flight <= 3, "rekey flight")
        proposer = 1 if self.target % 2 else 2
        return proposer if flight in (0, 2) else 3 - proposer

    def prefix(self, flight):
        role = self.role(flight)
        return (FLIGHTS[flight][0] + digest(b"offer-profile", PROFILE_TEXT) + self.context.digest
                + self.session + self.prior.to_bytes(8, "big") + self.target.to_bytes(8, "big")
                + bytes([role]) + self.predecessor)

    def open(self, flight, wire):
        identity = self.context.initiator if self.role(flight) == 1 else self.context.responder
        _, purpose, size = FLIGHTS[flight]
        body = identity.open(wire, purpose, size)
        require(body[:153] == self.prefix(flight), "rekey transcript scope")
        if flight in (2, 3):
            require(int.from_bytes(body[-40:-32], "big") <= self.context.send_budget, "rekey closing budget")
        return body

    def offer_body(self, public):
        require(len(public) == 1216, "rekey public key size")
        return self.prefix(0) + public

    def response_body(self, offer, ciphertext, shared, old_root):
        self.open(0, offer)
        require(len(ciphertext) == 1120 and len(shared) == len(old_root) == 32, "rekey response material")
        core = self.prefix(1) + digest(b"offer-wire", offer) + ciphertext
        root = hkdf(shared, old_root, DOMAIN + b"pending-root/HKDF-SHA256/" + digest(b"response-core", core))
        return core + confirmation(root, b"response", core), root

    def verify_response(self, offer, response, key: HybridPrivate, old_root):
        public = self.open(0, offer)[153:]
        require(public == key.public(), "rekey reply key owner")
        body = self.open(1, response)
        require(body[153:185] == digest(b"offer-wire", offer), "rekey offer hash")
        shared = key.decapsulate(self.context.sdk, body[185:-32], digest(b"response-kem", offer))
        expected, root = self.response_body(offer, body[185:-32], shared, old_root)
        require(hmac.compare_digest(expected, body), "rekey response confirmation")
        return root

    def _transcript(self, offer, response, root):
        self.open(0, offer)
        body = self.open(1, response)
        require(body[153:185] == digest(b"offer-wire", offer)
                and hmac.compare_digest(body[-32:], confirmation(root, b"response", body[:-32])),
                "rekey response transcript")
        return digest(b"offer-wire", offer) + digest(b"response-wire", response)

    def final_body(self, offer, response, root, closing):
        require(type(closing) is int and 0 <= closing <= self.context.send_budget, "rekey local closing budget")
        core = self.prefix(2) + self._transcript(offer, response, root) + closing.to_bytes(8, "big")
        return core + confirmation(root, b"final", core)

    def verify_final(self, offer, response, final, root):
        body = self.open(2, final)
        closing = int.from_bytes(body[-40:-32], "big")
        require(hmac.compare_digest(body, self.final_body(offer, response, root, closing)), "rekey final confirmation")
        return closing

    def receipt_body(self, offer, response, final, root, closing):
        self.verify_final(offer, response, final, root)
        require(type(closing) is int and 0 <= closing <= self.context.send_budget, "rekey local closing budget")
        core = (self.prefix(3) + self._transcript(offer, response, root)
                + digest(b"final-wire", final) + closing.to_bytes(8, "big"))
        return core + confirmation(root, b"receipt", core)

    def verify_receipt(self, offer, response, final, receipt, root):
        body = self.open(3, receipt)
        closing = int.from_bytes(body[-40:-32], "big")
        require(hmac.compare_digest(body, self.receipt_body(offer, response, final, root, closing)),
                "rekey receipt confirmation")
        return closing

    def traffic_material(self, offer, response, root):
        self._transcript(offer, response, root)
        return hkdf(root, self.session, DOMAIN + b"epoch-traffic/HKDF-SHA256/ChaCha20Poly1305/"
                    + self.context.digest + self.target.to_bytes(8, "big")
                    + digest(b"traffic-transcript", offer + response), 128)

    def completed(self, offer, response, final, receipt, root):
        self.verify_receipt(offer, response, final, receipt, root)
        return digest(b"completed-epoch", offer + response + final + receipt)
