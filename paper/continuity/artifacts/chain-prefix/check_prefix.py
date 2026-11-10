#!/usr/bin/env python3
"""Exact finite controls for the online chain-leaf interface and source pin."""
from __future__ import annotations

from collections import defaultdict
import hashlib
import hmac
import itertools
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def chain(seed: bytes, index: int, domain: bytes) -> tuple[bytes, bytes]:
    require(0 <= index < 2**64 - 1, "native chain index bound")
    info = domain + b"chain" + index.to_bytes(8, "big")
    prk = hmac.digest(bytes(32), seed, "sha256")
    first = hmac.digest(prk, info + b"\x01", "sha256")
    second = hmac.digest(prk, first + info + b"\x02", "sha256")
    return first, second


def distribution(policy: dict[tuple[int, ...], bool], alphabet: int,
                 length: int, retrospective: bool = False) -> dict:
    """Enumerate the exact independent-pair ideal, including a real suffix.

    Observations contain earlier returned keys, the mark, the disclosed
    successor and a deterministic suffix. Prefix seeds remain private.
    The suffix is an arbitrary concrete known computation, not a PRF model.
    """
    fibres: dict[tuple, list[int]] = defaultdict(lambda: [0] * alphabet)
    marked = 0
    for assignment in itertools.product(range(alphabet), repeat=2 * length):
        previous = []
        for index in range(length):
            successor, key = assignment[2 * index:2 * index + 2]
            choose = (key == 0 or index == length - 1) if retrospective else policy[tuple(previous)]
            if choose:
                suffix = ((successor + 1) % alphabet,
                          (successor * successor + index) % alphabet)
                observation = (index, tuple(previous), successor, suffix)
                fibres[observation][key] += 1
                marked += 1
                break
            previous.append(key)
    uniform = all(len(set(counts)) == 1 for counts in fibres.values())
    return {"uniform": uniform, "marked_assignments": marked,
            "observed_fibres": len(fibres),
            "assignments": alphabet ** (2 * length)}


def source_checks() -> dict:
    identity = json.loads((ROOT / "source_identity.json").read_text())
    for entry in identity["files"]:
        data = (ROOT / entry["snapshot"]).read_bytes()
        require(hashlib.sha256(data).hexdigest() == entry["sha256"],
                "source digest changed: " + entry["snapshot"])
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        require(blob == entry["git_blob_sha1"], "source Git identity changed")
    messages = (ROOT / "sources/messages.rs.txt").read_text()
    traffic = (ROOT / "sources/traffic.rs.txt").read_text()
    contract = (ROOT / "sources/contract.rs.txt").read_text()
    anchors = {
        "fixed_index_encoding": "info.extend_from_slice(&index.to_be_bytes());" in messages,
        "zero_salt_extract": "Hkdf::<Sha256>::new(None, seed.as_bytes())" in messages,
        "two_output_blocks": "ZeroizingBytes::<64>::zeroed()" in messages,
        "native_index_ceiling": "if index == u64::MAX" in messages,
        "first_send_step": "step(&self.send, self.sent)?" in traffic,
        "send_counter_advances_once": "self.send = next;\n        self.sent += 1;" in traffic,
        "receive_skips_compute_first": "while self.received < header.index" in traffic,
        "receive_skip_key_retained": "self.skipped.insert(self.received, message);" in traffic,
        "exact_outbox_resume": "return Ok(saved.wire.clone());" in messages,
        "zero_message_nonce": traffic.count("&Nonce::from([0; 12])") == 2,
        "receive_transaction_private": "Candidate state is transaction-private and dropped on any error." in traffic,
        "domain_present": 'pub const MESSAGE_DOMAIN: &[u8] = b"' in contract,
    }
    require(all(anchors.values()), "native source anchor failed")
    domain = contract.split('pub const MESSAGE_DOMAIN: &[u8] = b"', 1)[1].split('"', 1)[0].encode()
    require(len(domain) == 43, "native message domain width")
    for index in [0, 1, 255, 256, 2**32, 2**64 - 2]:
        info = domain + b"chain" + index.to_bytes(8, "big")
        require((len(info), len(info) + 1, 32 + len(info) + 1) == (56, 57, 89),
                "chain Expand lengths")
    seed = hashlib.sha256(b"finite-chain-control").digest()
    next_seed, key0 = chain(seed, 0, domain)
    next2, key1 = chain(next_seed, 1, domain)
    next3, key2 = chain(next2, 2, domain)
    recovered_seed = seed
    recovered_keys = []
    for index in range(3):
        recovered_seed, key = chain(recovered_seed, index, domain)
        recovered_keys.append(key)
    require(recovered_keys == [key0, key1, key2] and recovered_seed == next3,
            "exposed-prefix-seed recovery counterexample")
    try:
        chain(seed, 2**64 - 1, domain)
    except ValueError:
        index_rejected = True
    else:
        index_rejected = False
    require(index_rejected, "reserved index must fail")
    return {"files": len(identity["files"]), "anchors": anchors,
            "fixed_width_indices_checked": 6,
            "exposed_prefix_seed_recovers_selected_key": True,
            "reserved_index_rejected": True,
            "exact_recomputation_matches": chain(seed, 0, domain) == (next_seed, key0)}


def alias_and_origin_controls() -> dict:
    # A canonical material/direction/index identity survives independent
    # endpoint labels and crash/retry attempts. Distinct material is separate.
    ledger = {}
    private_encryptions = {}
    computed = set()
    selected = None
    def step(material: str, direction: int, index: int, mark: bool = False):
        nonlocal selected
        identity = (material, direction, index)
        if mark:
            require(selected is None and identity not in computed,
                    "mark must precede every alias's first private computation")
            selected = identity
        computed.add(identity)
        if identity not in ledger:
            ledger[identity] = (len(ledger) + 1, len(ledger) + 17)
        return ledger[identity]
    first = step("a", 1, 0)
    require(step("a", 1, 0) == first, "exact alias step consistency")
    try:
        step("a", 1, 0, True)
    except ValueError:
        prior_computation_rejected = True
    else:
        prior_computation_rejected = False
    require(prior_computation_rejected, "receive-before-send mark control")
    require(step("b", 1, 0) != first, "distinct material must retain its own entry")
    target = step("a", 1, 1, True)
    require(step("a", 1, 1) == target, "selected endpoint alias consistency")
    original = ("a", 1, 1, "original-send")
    calls = 0
    for outcome in ["failed-before-commit", "retry", "committed", "resume"]:
        if original not in private_encryptions:
            calls += 1
            private_encryptions[original] = b"original-ciphertext"
        require(private_encryptions[original] == b"original-ciphertext", "encryption replay")
    require(calls == 1, "private encryption origin must precede durability")
    return {"alias_step_consistency": True, "prior_computation_rejected": True,
            "distinct_material_identity": True, "private_encryption_calls": calls,
            "four_commit_retry_outcomes_share_one_origin": True}


def main() -> None:
    prefixes = [tuple(x) for n in range(3) for x in itertools.product(range(2), repeat=n)]
    results = []
    for mask in range(1 << len(prefixes)):
        policy = {p: bool(mask & (1 << i)) for i, p in enumerate(prefixes)}
        result = distribution(policy, 2, 3)
        require(result["uniform"], "online-mark target key lost ideal independence")
        results.append(result)
    # Larger alphabets retain numerical coincidences in the complete sample
    # space. Policies depend on earlier keys and may terminate without a mark.
    larger = []
    for mask in range(8):
        policy = {tuple(p): (False if n == 0 else
                            bool(mask & (1 << p[0])) if n == 1 else True)
                  for n in range(3) for p in itertools.product(range(4), repeat=n)}
        result = distribution(policy, 4, 3)
        require(result["uniform"], "larger ideal alphabet control")
        larger.append(result)
    bad = distribution({}, 2, 3, retrospective=True)
    require(not bad["uniform"], "retrospective selection counterexample was not detected")
    output = {
        "schema": "qperiapt-chain-prefix-controls/1", "status": "passed",
        "all_binary_online_marking_policies": len(results),
        "binary_assignments_examined": sum(r["assignments"] for r in results),
        "larger_alphabet_policies": len(larger),
        "larger_alphabet_assignments_examined": sum(r["assignments"] for r in larger),
        "all_observed_selected_key_fibres_uniform": True,
        "retrospective_marking_breaks_ideal_independence": True,
        "source": source_checks(), "origins": alias_and_origin_controls(),
        "scope": "Exact finite ideal-distribution and interface controls, source identities and anchors; the full compression-oracle comparison is the mathematical theorem.",
        "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
