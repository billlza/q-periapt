#!/usr/bin/env python3
"""Self-contained format and adapter-model checks for the ContextBound bridge.

This checks independently encoded source vectors and deliberately small interface
models. It does not execute Rust, prove a primitive assumption, or replay a native
journal. Native source identities are checked separately by audit_source.py.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path


DOMAIN = b"Q-PERIAPT-HYBRID-KEM/v1"
POLICY_DOMAIN = b"Q-PERIAPT-POLICY-CONTEXT/v1"
REKEY_DOMAIN = b"Q-PERIAPT-CONTINUITY-REKEY-CANDIDATE/v1/"
SUITE = b"ML-KEM-768+X25519"
FIELDS = (
    "domain", "suite", "policy_version", "ss_mlkem", "ss_x25519",
    "ct_mlkem", "pk_mlkem", "ct_x25519", "pk_x25519", "context",
)


def lp(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def encode(fields: tuple[bytes, ...]) -> bytes:
    if len(fields) != 10:
        raise ValueError("ContextBound hash input must contain ten fields")
    return b"".join(lp(value) for value in fields)


def decode(encoded: bytes) -> tuple[bytes, ...]:
    fields = []
    cursor = 0
    for _ in FIELDS:
        if cursor + 8 > len(encoded):
            raise ValueError("truncated length")
        length = int.from_bytes(encoded[cursor:cursor + 8], "big")
        cursor += 8
        if length > len(encoded) - cursor:
            raise ValueError("truncated field")
        fields.append(encoded[cursor:cursor + length])
        cursor += length
    if cursor != len(encoded):
        raise ValueError("trailing bytes")
    return tuple(fields)


def source_digest(label: bytes, payload: bytes) -> bytes:
    return hashlib.sha3_256(lp(REKEY_DOMAIN + label) + lp(payload)).digest()


def root_init(previous: bytes, contribution: bytes, core: bytes) -> bytes:
    prk = hmac.digest(previous, contribution, "sha256")
    info = REKEY_DOMAIN + b"pending-root/HKDF-SHA256/" + source_digest(b"response-core", core)
    return hmac.digest(prk, info + b"\x01", "sha256")


def byte_spec(spec: dict) -> bytes:
    if set(spec) == {"ascii"}:
        return spec["ascii"].encode("ascii")
    if set(spec) == {"hex"}:
        return bytes.fromhex(spec["hex"])
    if set(spec) == {"byte", "count"}:
        if type(spec["byte"]) is not int or type(spec["count"]) is not int:
            raise ValueError("noninteger repeat specification")
        if not 0 <= spec["byte"] <= 255 or spec["count"] < 0:
            raise ValueError("invalid byte repetition")
        return bytes([spec["byte"]]) * spec["count"]
    raise ValueError("unsupported byte specification")


class TupleTable:
    """Labels represent fixed distinct draws of an ideal table, not key bytes."""

    def __init__(self) -> None:
        self.entries: dict[bytes, str] = {}

    def call(self, origin: str, fields: tuple[bytes, ...]) -> str:
        del origin  # Provenance is a separate ledger, not a hash-table key.
        key = encode(fields)
        if key not in self.entries:
            self.entries[key] = f"ideal-value-{len(self.entries) + 1}"
        return self.entries[key]


class ReservationLedger:
    """Distinct origin/result handles do not assert distinct cryptographic bytes.

    Independent tapes, keys, ciphertexts and secrets may coincide numerically.
    These labels only prevent an external operation ID from merging new draws.
    """

    def __init__(self) -> None:
        self.entries: dict[int, tuple[bytes, bytes, str]] = {}
        self.results: dict[int, str] = {}

    def reserve(self, operation_id: bytes, complete_binding: bytes) -> int:
        origin = len(self.entries) + 1
        self.entries[origin] = (operation_id, complete_binding, f"tape-{origin}")
        return origin

    def execute(self, origin: int, operation_id: bytes, complete_binding: bytes) -> str:
        saved_id, saved_binding, tape = self.entries[origin]
        if (saved_id, saved_binding) != (operation_id, complete_binding):
            raise ValueError("bound invocation mismatch")
        if origin not in self.results:
            self.results[origin] = f"result-from-{tape}"
        return self.results[origin]


class ComponentRouter:
    """Model of the CCA adapter's interface routing, not a KEM implementation."""

    def __init__(self) -> None:
        self.challenge_ct: bytes | None = None
        self.ordinary_calls: list[tuple[bool, bytes]] = []

    def create_challenge(self, ciphertext: bytes) -> None:
        if self.challenge_ct is not None:
            raise ValueError("one component challenge")
        self.challenge_ct = ciphertext

    def decapsulate(self, owner: str, pq_ct: bytes, classical_ct: bytes, context: bytes) -> str:
        del classical_ct, context  # They do not alter the PQ oracle prohibition.
        if owner != "selected-g":
            return "locally-known-key"
        if self.challenge_ct is not None and pq_ct == self.challenge_ct:
            return "cached-component-challenge"
        self.ordinary_calls.append((self.challenge_ct is not None, pq_ct))
        return "component-decapsulation-oracle"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, default=Path(__file__).with_name("fixtures.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    fixtures = json.loads(args.fixtures.read_text(encoding="utf-8"))
    checks: list[dict] = []

    def check(name: str, predicate: bool, **details) -> None:
        if predicate is not True:
            raise AssertionError(name)
        checks.append({"name": name, "passed": True, **details})

    vectors = []
    for case in fixtures["legacy_core_vectors"]:
        fields = tuple(byte_spec(spec) for spec in case["fields"])
        wire = encode(fields)
        digest = hashlib.sha3_256(wire).hexdigest()
        check(case["name"], digest == case["sha3_256"] and decode(wire) == fields,
              input_bytes=len(wire), sha3_256=digest)
        vectors.append(fields)
    check("unframed-boundary-collision-witness",
          b"".join(vectors[3]) == b"".join(vectors[4]) and encode(vectors[3]) != encode(vectors[4]))

    # A byte-format fixture with native field widths. The synthetic offer below
    # is not claimed to be a valid signed protocol flight or a KEM execution.
    offer = byte_spec(fixtures["native_widths"]["synthetic_offer"])
    policy = bytes([0x55]) * 32
    application = source_digest(b"response-kem", offer)
    wrapped = lp(POLICY_DOMAIN) + lp(policy) + lp(application)
    native = (
        DOMAIN, SUITE, (7).to_bytes(4, "big"), bytes([0x11]) * 32,
        bytes([0x22]) * 32, bytes([0x42]) * 1088, bytes([0x37]) * 1184,
        bytes([0x33]) * 32, bytes([0x44]) * 32, wrapped,
    )
    native_wire = encode(native)
    offsets = []
    cursor = 0
    for name, value in zip(FIELDS, native):
        offsets.append({"field": name, "length_prefix_offset": cursor,
                        "data_offset": cursor + 8, "bytes": len(value)})
        cursor += 8 + len(value)
    check("native-widths-and-hidden-MLKEM-field-position",
          len(wrapped) == 115 and len(native_wire) == 2639
          and offsets[3]["data_offset"] == 76
          and native_wire[76:108] == native[3]
          and decode(native_wire) == native,
          wrapped_context_bytes=len(wrapped), hash_input_bytes=len(native_wire), fields=offsets)
    check("native-widths-pinned-independent-vector",
          hashlib.sha3_256(native_wire).hexdigest() == fixtures["native_widths"]["sha3_256"],
          sha3_256=hashlib.sha3_256(native_wire).hexdigest(),
          provenance="independent format fixture; not a native execution")
    check("complete-offer-byte-dependence",
          source_digest(b"response-kem", offer) != source_digest(b"response-kem", offer[:-1] + bytes([offer[-1] ^ 1])),
          observation="fixture mutates the last byte, representing a change outside the body")

    table = TupleTable()
    first = table.call("g1-a1", native)
    check("same-effective-tuple-across-origin-labels-is-one-entry",
          table.call("g1-a1", native) == first
          and table.call("g9-a8", native) == first and len(table.entries) == 1)
    for index, name in enumerate(FIELDS):
        changed = list(native)
        value = changed[index]
        changed[index] = value[:-1] + bytes([value[-1] ^ 1])
        check(f"field-distinction-{name}", table.call("g1-a1", tuple(changed)) != first)
    bad_origin_table = {"g1-a1": "draw-one", "g9-a8": "draw-two"}
    check("origin-indexed-cache-mutation-rejected",
          bad_origin_table["g1-a1"] != bad_origin_table["g9-a8"]
          and table.call("g1-a1", native) == table.call("g9-a8", native),
          mutant="key the private hash answer by origin alone")
    changed_other = list(native)
    changed_other[4] = bytes([0x23]) * 32
    omitted_other = lambda values: encode(tuple(values[:4]) + (b"",) + tuple(values[5:]))
    check("omitted-other-secret-cache-mutation-rejected",
          encode(native) != encode(tuple(changed_other))
          and omitted_other(native) == omitted_other(changed_other),
          mutant="drop the traditional shared-secret field from the effective table key")

    ledger = ReservationLedger()
    binding = b"policy/owner/full-offer/context"
    origin = ledger.reserve(b"operation-1", binding)
    value = ledger.execute(origin, b"operation-1", binding)
    check("exact-retry-retains-origin-and-result",
          ledger.execute(origin, b"operation-1", binding) == value and len(ledger.entries) == 1)
    new_origin = ledger.reserve(b"operation-1", binding)
    check("fresh-draw-is-distinct-despite-reused-operation-id",
          new_origin != origin and ledger.execute(new_origin, b"operation-1", binding) != value,
          interpretation="distinct source/result handles, without a claim of different output bytes")
    for name, op, bound in (("operation", b"operation-2", binding),
                            ("full-binding", b"operation-1", binding + b"changed")):
        rejected = False
        try:
            ledger.execute(origin, op, bound)
        except ValueError:
            rejected = True
        check(f"bound-retry-rejects-changed-{name}", rejected)

    router = ComponentRouter()
    check("prechallenge-decapsulation-keeps-normal-interface",
          router.decapsulate("selected-g", b"earlier", b"x1", b"ctx") == "component-decapsulation-oracle")
    check("prechallenge-query-may-equal-eventual-ciphertext",
          router.decapsulate("selected-g", b"target-pq-ciphertext", b"x1", b"ctx")
          == "component-decapsulation-oracle")
    router.create_challenge(b"target-pq-ciphertext")
    for classical_ct, context in ((b"x1", b"ctx1"), (b"x2", b"ctx1"), (b"x1", b"ctx2")):
        check("target-PQ-ciphertext-with-hybrid-suffix-" + (classical_ct + context).hex(),
              router.decapsulate("selected-g", b"target-pq-ciphertext", classical_ct, context)
              == "cached-component-challenge")
    check("nontarget-PQ-ciphertext-uses-decap-oracle",
          router.decapsulate("selected-g", b"other", b"x1", b"ctx1") == "component-decapsulation-oracle")
    check("other-owner-keeps-own-computation",
          router.decapsulate("other-g", b"target-pq-ciphertext", b"x1", b"ctx1") == "locally-known-key")
    check("CCA-prohibition-never-forwarded-after-challenge",
          (True, b"target-pq-ciphertext") not in router.ordinary_calls
          and (False, b"target-pq-ciphertext") in router.ordinary_calls)

    contribution = hashlib.sha3_256(native_wire).digest()
    r0, r1, core0, core1 = bytes([0x61]) * 32, bytes([0x62]) * 32, b"core-0", b"core-1"
    root0 = root_init(r0, contribution, core0)
    root1 = root_init(r1, contribution, core0)
    root2 = root_init(r0, contribution, core1)
    check("same-CB-tuple-does-not-imply-same-root-allocation",
          len({root0, root1, root2}) == 3,
          roots=[root0.hex(), root1.hex(), root2.hex()],
          observation="algebraic counterexample outside the fixed-next-rekey profile; no native attack claimed")

    receipt = {
        "schema": "q-periapt.contextbound-adapter-check.v1",
        "status": "passed", "check_count": len(checks), "checks": checks,
        "claim_type": "independent Python encoding and finite adapter-model checks",
        "native_execution": False,
        "limitations": ["No Rust test or cryptographic security game is executed by this checker.",
                        "The root-allocation witness distinguishes an algebraic obligation from the native profile proof."],
        "inputs": {"fixture_sha256": hashlib.sha256(args.fixtures.read_bytes()).hexdigest(),
                   "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": receipt["status"], "check_count": len(checks), "output": str(args.output)}))


if __name__ == "__main__":
    main()
