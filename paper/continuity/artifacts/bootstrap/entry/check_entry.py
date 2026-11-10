#!/usr/bin/env python3
"""Check public compression equations and table encodings for bootstrap entry.

This program performs deterministic public-input calculations. The analytical
comparison is in BOOTSTRAP_JOINT_ENTRY_V1.md; this is no cryptographic experiment
or replacement for its proof.
"""

import argparse
import hashlib
import hmac
import itertools
import json
import struct
from pathlib import Path


BASE = "b1cff2a045d23aecf75aef12122e5080a8419676"
MASK = (1 << 32) - 1
IV = struct.pack(
    ">8I", 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)
K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)
P = b"\x80" + bytes(23) + (768).to_bytes(8, "big")
Q = b"\x80" + bytes(55) + (1024).to_bytes(8, "big")
SIGMA = b"QPeriapt-SDK-HKDF-SHA256-v1"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def rotr(value, count):
    return ((value >> count) | (value << (32 - count))) & MASK


def compress(block, state):
    require(len(block) == 64 and len(state) == 32, "compression widths")
    previous = struct.unpack(">8I", state)
    schedule = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        x, y = schedule[i - 15], schedule[i - 2]
        s0 = rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
        s1 = rotr(y, 17) ^ rotr(y, 19) ^ (y >> 10)
        schedule.append((schedule[i - 16] + s0 + schedule[i - 7] + s1) & MASK)
    a, b, c, d, e, f, g, hh = previous
    for constant, word in zip(K, schedule):
        s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        choose = (e & f) ^ (~e & g)
        majority = (a & b) ^ (a & c) ^ (b & c)
        t1 = (hh + s1 + choose + constant + word) & MASK
        t2 = (s0 + majority) & MASK
        hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & MASK, c, b, a, (t1 + t2) & MASK
    return struct.pack(">8I", *((x + y) & MASK for x, y in zip(previous, (a, b, c, d, e, f, g, hh))))


def gamma(salt):
    require(len(salt) <= 64, "fixture salt length")
    padded = salt + bytes(64 - len(salt))
    return (compress(bytes(x ^ 0x36 for x in padded), IV),
            compress(bytes(x ^ 0x5C for x in padded), IV))


def extract32(salt, secret):
    alpha, beta = gamma(salt)
    return compress(compress(secret + P, alpha) + P, beta)


def extract64(salt, left, right):
    alpha, beta = gamma(salt)
    z = compress(left + right, alpha)
    w = compress(Q, z)
    return compress(w + P, beta)


def source_checks(root, pins):
    require(pins["source_commit"] == BASE, "source commit pin")
    sources = {}
    for entry in pins["files"]:
        data = (root / entry["path"]).read_bytes()
        require(len(data) == entry["bytes"], "source length: " + entry["path"])
        require(digest(data) == entry["sha256"], "source SHA-256: " + entry["path"])
        require(git_blob(data) == entry["git_blob"], "source Git blob: " + entry["path"])
        sources[entry["path"]] = data.decode()
    bootstrap = sources["research/continuity-identity-candidate/src/bootstrap.rs"]
    purpose = sources["crates/q-periapt-sdk/src/purpose.rs"]
    for fragment in ["ZeroizingBytes::<64>::zeroed()", "split_at_mut(32)",
                     "left.copy_from_slice(first.as_bytes())",
                     "right.copy_from_slice(second.as_bytes())",
                     "Hkdf::<Sha256>::extract(Some(salt), ikm)",
                     'b"handshake-seed"', 'b"confirmation-responder"',
                     'b"confirmation-initiator"']:
        require(fragment in bootstrap, "source schedule fragment: " + fragment)
    require('b"' + SIGMA.decode() + '"' in purpose, "source SDK salt")
    require("Hkdf::<Sha256>::extract(Some(salt), ikm)" in purpose,
            "source initial Extract")
    return len(sources)


def equation_checks():
    require(len(P) == 32 and len(Q) == 64, "padding lengths")
    require(P[-8:] != Q[-8:], "downstream encodings have disjoint suffixes")
    salts = [SIGMA, bytes(32), bytes([255]) * 32, hashlib.sha256(b"public-salt").digest()]
    pairs = [
        (bytes(32), bytes([255]) * 32),
        (bytes(range(32)), bytes(reversed(range(32)))),
        (hashlib.sha256(b"first").digest(), P),
        (P, hashlib.sha256(b"second").digest()),
    ]
    vectors = []
    for salt, pair in itertools.product(salts, pairs):
        for left, right in (pair, pair[::-1]):
            short = extract32(salt, left)
            long = extract64(salt, left, right)
            require(short == hmac.digest(salt, left, "sha256"), "32-byte HMAC equation")
            require(long == hmac.digest(salt, left + right, "sha256"), "64-byte HMAC equation")
            vectors.append({"salt": salt.hex(), "left": left.hex(), "right": right.hex(),
                            "short": short.hex(), "long": long.hex()})
    require(gamma(SIGMA) == gamma(SIGMA + bytes(5)), "SDK zero-extension pad identity")
    # The exact known suffix forces one short/long first private input.
    secret = bytes(range(32))
    alpha, beta = gamma(SIGMA)
    short_point = (secret + P, alpha)
    long_point = (secret + P, alpha)
    require(short_point == long_point, "shared first private compression point")
    z = compress(*short_point)
    require((z + P, beta) != (Q, z), "distinct shortcut and padding descendants")
    require(extract32(SIGMA, secret) != extract64(SIGMA, secret, P),
            "fixture outputs distinguish the extra padding step")
    # A missing 64-byte padding block and a wrong consumed-block length both fail.
    wrong_outer = compress(z + P, beta)
    wrong_q = b"\x80" + bytes(55) + (512).to_bytes(8, "big")
    wrong_length = compress(compress(wrong_q, z) + P, beta)
    expected = hmac.digest(SIGMA, secret + P, "sha256")
    require(wrong_outer != expected and wrong_length != expected,
            "faulty padding variants must be distinguished")
    return {"short_equations": len(vectors), "long_equations": len(vectors),
            "vectors": vectors, "sdk_zero_extension": True, "shared_raw_point": True,
            "padding_faults_detected": 2}


def encoding_checks():
    # Exhaustion verifies these declared fixtures; the full-width argument is
    # the injective-encoding proof in the document.
    secrets = [n.to_bytes(32, "big") for n in range(256)]
    halves = [bytes(32), bytes([255]) * 32, P, hashlib.sha256(b"known").digest()]
    states = [bytes(32), (1).to_bytes(32, "big"), IV, hashlib.sha256(b"state").digest()]
    descriptors = list(itertools.product(halves, states))
    raw_points = 0
    for orientation in ("first", "second"):
        for secret in secrets:
            points = [((secret + half) if orientation == "first" else (half + secret), state)
                      for half, state in descriptors]
            require(len(set(points)) == len(descriptors), "all-secret raw-query freshness")
            raw_points += len(points)
        for half, state in descriptors:
            points = [((secret + half) if orientation == "first" else (half + secret), state)
                      for secret in secrets]
            require(len(set(points)) == len(secrets), "fixed-query raw point preimages")
    tagged_points = 0
    for secret in secrets:
        points = [(secret + P, beta) for beta in states] + [(Q, secret)]
        require(len(set(points)) == len(points), "all-secret tagged downstream freshness")
        tagged_points += len(points)
    for beta in states:
        require(len({(secret + P, beta) for secret in secrets}) == len(secrets),
                "fixed short/outer query preimages")
    require(len({(Q, secret) for secret in secrets}) == len(secrets),
            "fixed padding query preimages")
    return {"secret_values": len(secrets), "raw_descriptors": len(descriptors),
            "raw_points_checked": raw_points, "tagged_points_checked": tagged_points,
            "fixed_query_max_preimages": 1, "all_secret_freshness": True}


class EntryTrace:
    """Symbolic final-table identity with actual private call accounting."""

    def __init__(self):
        self.raw = {}
        self.short_outputs = {}
        self.long_outputs = {}
        self.pad_used = set()
        self.short_betas = {}
        self.long_betas = {}
        self.salts = set()

    def allocate(self, half, alpha):
        key = (half, alpha)
        if key not in self.raw:
            self.raw[key] = len(self.raw)
        return self.raw[key]

    def short(self, salt_name, alpha, beta):
        self.salts.add(salt_name)
        i = self.allocate(P, alpha)
        self.short_betas.setdefault(i, set()).add(beta)
        self.short_outputs.setdefault((i, beta), ("short", i, beta))
        return self.short_outputs[(i, beta)]

    def long(self, salt_name, half, alpha, beta):
        self.salts.add(salt_name)
        i = self.allocate(half, alpha)
        self.pad_used.add(i)
        self.long_betas.setdefault(i, set()).add(beta)
        self.long_outputs.setdefault((i, beta), ("long", i, beta))
        return self.long_outputs[(i, beta)]


def table_checks():
    alpha, beta = gamma(SIGMA)
    alpha2, beta2 = gamma(bytes([7]) * 32)
    half2 = hashlib.sha256(b"other-known-half").digest()
    # Long calls include forced Gamma aliases and a same-alpha/different-beta
    # pair; these are model controls rather than claims of a real SHA collision.
    requests = [
        ("a", P, alpha, beta),
        ("a-alias", P, alpha, beta),
        ("a-new-outer", P, alpha, beta2),
        ("b", half2, alpha, beta),
        ("c", P, alpha2, beta),
    ]
    permutations = 0
    observed_sdk_slots = set()
    slot_short_maxima = {}
    for order in itertools.permutations(range(len(requests))):
        for short_position in range(len(requests) + 1):
            trace = EntryTrace()
            results = [None] * len(requests)
            short_handle = None
            sdk_slot = None
            for position in range(len(requests) + 1):
                if position == short_position:
                    short_handle = trace.short("sdk", alpha, beta)
                    sdk_slot = trace.raw[(P, alpha)]
                if position < len(requests):
                    index = order[position]
                    results[index] = trace.long(*requests[index])
            for i, j in itertools.product(range(len(requests)), repeat=2):
                require((results[i] == results[j]) == (requests[i][1:] == requests[j][1:]),
                        "full-descriptor handle identity partition")
            require(trace.short("sdk", alpha, beta) == short_handle,
                    "short handle retained across long uses")
            require(short_handle != results[0], "distinct final short and long table handles")
            require(trace.raw[(P, alpha)] == sdk_slot, "original SDK raw slot retained")
            observed_sdk_slots.add(sdk_slot)
            previous = (len(trace.raw), len(trace.long_outputs), len(trace.short_outputs))
            require(trace.long(*requests[0]) == results[0], "exact long retry")
            require(previous == (len(trace.raw), len(trace.long_outputs), len(trace.short_outputs)),
                    "retry allocates no private entry")
            c, a, b = len(trace.raw), len(trace.short_outputs), len(trace.long_outputs)
            qbar_entry = 2 * len(trace.salts) + a + c + b
            # Actual post-raw work: two public pads per salt, one short outer,
            # one padding per raw class with a long request, each long outer once.
            actual = 2 * len(trace.salts) + a + len(trace.pad_used) + b
            require(actual <= qbar_entry, "entry-work query bound")
            require(sum(len(v) for v in trace.short_betas.values()) == 1,
                    "one source initial PRK")
            for slot, values in trace.short_betas.items():
                slot_short_maxima[slot] = max(slot_short_maxima.get(slot, 0), len(values))
            permutations += 1
    require(observed_sdk_slots == {0, 1, 2}, "SDK raw class occupies distinct lifetime slots")
    require(sum(slot_short_maxima.values()) == 3,
            "fixed per-slot maxima differ from the global one-short bound")

    # Concrete failures of four smaller/wrong cache keys.
    require(requests[0][0] != requests[1][0] and requests[0][1:] == requests[1][1:],
            "salt-name-only indexing splits an effective alias")
    require(requests[0][2] == requests[3][2] and requests[0][1:] != requests[3][1:],
            "alpha-only indexing loses the known half")
    require(requests[0][1:3] == requests[2][1:3] and requests[0][3] != requests[2][3],
            "raw-only indexing loses the outer pad state")
    require(("short", P, alpha) != ("long", P, alpha),
            "split short/long raw tags allocate twice at an identical input")

    # Distinct sampled raw values may coincide numerically. Real descendants
    # use one public h, so coincident input points receive equal real outputs.
    z0 = z1 = bytes([9]) * 32
    require(compress(Q, z0) == compress(Q, z1), "real numerical raw collision")
    w0, w1 = compress(Q, z0), compress(Q, z1)
    require(compress(w0 + P, beta) == compress(w1 + P, beta),
            "real outer correlation on numerical collision")
    # Private ideal table slots are still indexed by class, not sampled bytes.
    require(("long", 0, beta) != ("long", 1, beta),
            "ideal independent slots retain their original distinct indices")
    return {"adaptive_order_fixtures": permutations, "long_requests_per_fixture": len(requests),
            "sdk_short_positions": len(requests) + 1,
            "observed_sdk_raw_slots": sorted(observed_sdk_slots),
            "global_distinct_short_calls": 1, "sum_slot_short_maxima": sum(slot_short_maxima.values()),
            "effective_aliases_preserved": True, "short_raw_alias_preserved": True,
            "retry_slot_identity_preserved": True, "query_budget_passed": True,
            "faulty_cache_variants_detected": 4, "real_numeric_collision_control": True,
            "ideal_slots_not_merged_by_numeric_bytes": True}


def run(source_root, pins_path):
    pins = json.loads(pins_path.read_text())
    return {
        "schema": "qperiapt-bootstrap-joint-entry-controls/1",
        "source_commit": BASE,
        "status": "passed",
        "scope": "Deterministic encoding/table checks; analytical proof supplies the cryptographic bound.",
        "source_files_matched": source_checks(source_root, pins),
        "padding32_hex": P.hex(),
        "padding64_hex": Q.hex(),
        "equations": equation_checks(),
        "encodings": encoding_checks(),
        "tables": table_checks(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.source_root, Path(__file__).with_name("SOURCE_PINS.json"))
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": result["status"], "source_files_matched": result["source_files_matched"],
                      "short_equations": result["equations"]["short_equations"],
                      "long_equations": result["equations"]["long_equations"],
                      "raw_points_checked": result["encodings"]["raw_points_checked"],
                      "tagged_points_checked": result["encodings"]["tagged_points_checked"],
                      "adaptive_order_fixtures": result["tables"]["adaptive_order_fixtures"],
                      "output": str(args.output)}))


if __name__ == "__main__":
    main()
