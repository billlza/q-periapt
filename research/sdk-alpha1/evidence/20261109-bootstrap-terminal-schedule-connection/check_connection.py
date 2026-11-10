#!/usr/bin/env python3
"""Finite controls for the analytical terminal schedule connection.

Uses standard-library hashes for source equations and a separately labelled
forced compression oracle for the descriptor-alias counterexample. Does not
execute Rust, native cryptographic providers, or a quantum attack experiment.
"""

from __future__ import annotations

import argparse
from collections import Counter
from fractions import Fraction
import hashlib
import hmac
import itertools
import json
from pathlib import Path


PACKET = Path(__file__).resolve().parent
DB = b"Q-PERIAPT-CONTINUITY-BOOTSTRAP-KDF-CANDIDATE/v1/"
DM = b"Q-PERIAPT-CONTINUITY-MESSAGES-CANDIDATE/v2/"
DH = b"Q-PERIAPT-CONTINUITY-BOOTSTRAP-CANDIDATE/v1/"
IV = bytes.fromhex(
    "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def validate_pins(source_root: Path) -> dict:
    pins = json.loads((PACKET / "SOURCE_PINS.json").read_text())
    for item in pins["files"]:
        data = (source_root / item["path"]).read_bytes()
        require(len(data) == item["bytes"], f"byte length: {item['path']}")
        require(git_blob(data) == item["git_blob"], f"Git blob: {item['path']}")
        require(sha256(data) == item["sha256"], f"SHA-256: {item['path']}")
    return {
        "checked_files": len(pins["files"]),
        "base_commit": pins["base_commit"],
        "base_tree": pins["base_tree"],
        "source_pins_sha256": sha256((PACKET / "SOURCE_PINS.json").read_bytes()),
    }


def mac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def expand(prk: bytes, info: bytes, count: int, primitive=mac) -> list[bytes]:
    blocks = []
    previous = b""
    for counter in range(1, count + 1):
        previous = primitive(prk, previous + info + bytes([counter]))
        blocks.append(previous)
    return blocks


def hash_frame(label: bytes, data: bytes) -> bytes:
    domain = DH + label
    framed = len(domain).to_bytes(8, "big") + domain + len(data).to_bytes(8, "big") + data
    return hashlib.sha3_256(framed).digest()


def transcript(ctx: bytes, initial: bytes, reply: bytes) -> tuple[bytes, bytes]:
    prefix = b"QPBSF001" + ctx + hash_frame(b"initial-wire", initial) + hash_frame(b"reply-wire", reply)
    return prefix, hash_frame(b"session-id", prefix)


def root_and_blocks(seed: bytes, sid: bytes, ctx: bytes, primitive=mac):
    ib = DB + b"session-root/" + ctx
    ia = DM + b"initial/HKDF-SHA256/ChaCha20Poly1305" + ctx
    root = expand(primitive(sid, seed), ib, 1, primitive)[0]
    activation_prk = primitive(sid, root)
    blocks = expand(activation_prk, ia, 5, primitive)
    return root, activation_prk, blocks


def source_equations() -> dict:
    # Synthetic public byte strings exercise the equations. No claim of a
    # verified signature, accepted wire, or provider execution is made.
    ctx = bytes(range(32))
    initial = b"control/complete-initial-wire"
    reply_body = b"control/same-reply-body"
    reply_a = reply_body + b"/signature-a"
    reply_b = reply_body + b"/signature-b"
    first = bytes(range(32, 64))
    second = bytes(range(64, 96))
    core = hash_frame(b"reply-core", reply_body)
    prk = mac(core, first + second)
    seed, kr, ki = [
        expand(prk, DB + label, 1)[0]
        for label in (b"handshake-seed", b"confirmation-responder", b"confirmation-initiator")
    ]
    f_a, sid_a = transcript(ctx, initial, reply_a)
    f_b, sid_b = transcript(ctx, initial, reply_b)
    root_a, activation_prk, blocks_a = root_and_blocks(seed, sid_a, ctx)
    root_b, _, blocks_b = root_and_blocks(seed, sid_b, ctx)
    ib = DB + b"session-root/" + ctx
    ia = DM + b"initial/HKDF-SHA256/ChaCha20Poly1305" + ctx
    require((len(DB), len(DM), len(ib), len(ia)) == (48, 43, 93, 111), "source domain/info lengths")
    require(len(f_a) == len(f_b) == 104, "Final prefix length")
    require(sid_a != sid_b and root_a != root_b, "retained synthetic full-wire control")
    require([len(ia) + 1] + [32 + len(ia) + 1] * 4 == [112, 144, 144, 144, 144], "activation message lengths")
    require(len(b"".join(blocks_a)) == 160, "activation byte length")
    role_i_send_ack = b"".join(blocks_a)[96:128]
    role_r_receive_ack = b"".join(blocks_a)[32:][64:96]
    require(role_i_send_ack == role_r_receive_ack == blocks_a[3], "role mapping to block 4")
    replacement = bytes([0xA7]) * 32
    correct = blocks_a[:]
    correct[3] = replacement
    wrong_fifth = mac(activation_prk, replacement + ia + b"\x05")
    require(correct[4] == blocks_a[4], "ACK-only override preserves block 5")
    require(wrong_fifth != blocks_a[4], "feeding ACK override into block 5 is detected")
    return {
        "input_scope": "synthetic public bytes; no signature or provider execution",
        "final_prefix_bytes": len(f_a),
        "root_info_bytes": len(ib),
        "activation_info_bytes": len(ia),
        "activation_message_bytes": [112, 144, 144, 144, 144],
        "same_body_alias": {
            "sid_a": sid_a.hex(), "sid_b": sid_b.hex(),
            "root_a": root_a.hex(), "root_b": root_b.hex(),
            "ack_a": blocks_a[3].hex(), "ack_b": blocks_b[3].hex(),
        },
        "ack_override": {
            "preserved_block_5": correct[4].hex(),
            "incorrect_recomputed_block_5": wrong_fifth.hex(),
            "incorrect_variant_detected": True,
        },
        "confirmation_controls": {
            "mac_r": mac(kr, core).hex(),
            "mac_i_a": mac(ki, hash_frame(b"final-core", f_a)).hex(),
            "mac_i_b": mac(ki, hash_frame(b"final-core", f_b)).hex(),
        },
    }


def finite_root_run(mode: str, oracle: tuple[int, ...], coins: tuple[int, int], public_bit: int):
    # Allocate two named handles and an exact alias of the first. Handle
    # allocation does not reveal any function of its root-table value.
    handles = {"a": 0, "b": 1, "a-copy": 0}
    values = {0: coins[0], 1: coins[1]} if mode == "eager" else {}
    next_coin = 0

    def materialize(index):
        nonlocal next_coin
        if index not in values:
            values[index] = coins[next_coin]
            next_coin += 1
        return values[index]

    first_query = oracle[public_bit]
    opened_index = first_query  # Depends on a public-oracle answer.
    opened = materialize(opened_index)
    next_query = oracle[(opened + public_bit) % 4]
    selected = 1 - opened_index
    protected = (next_query ^ public_bit) == 0  # Chosen after both allocations.
    selected_value = materialize(selected)
    selected_open = -1 if protected else selected_value
    activation = oracle[selected_value]
    exact_retry = oracle[materialize(selected)]
    require(exact_retry == activation, "exact retry reused its root")
    require(handles["a-copy"] == handles["a"], "copy preserves logical handle")
    return (
        public_bit, first_query, opened_index, opened, next_query,
        protected, selected_open, activation, exact_retry,
    ), values[0] == values[1]


def deferred_sampling() -> dict:
    counters = {}
    counts = {}
    for mode in ("eager", "first_exposure"):
        views = Counter()
        numeric_collisions = 0
        protected_cases = 0
        for oracle in itertools.product(range(2), repeat=4):
            for coins in itertools.product(range(4), repeat=2):
                for bit in range(2):
                    view, same_value = finite_root_run(mode, oracle, coins, bit)
                    views[view] += 1
                    numeric_collisions += same_value
                    protected_cases += view[5]
        counters[mode] = views
        counts[mode] = {
            "executions": sum(views.values()),
            "distinct_available_views": len(views),
            "numeric_root_collisions": numeric_collisions,
            "protected_first_activations": protected_cases,
        }
    require(counters["eager"] == counters["first_exposure"], "complete finite joint distributions")
    require(counts["eager"]["numeric_root_collisions"] > 0, "numeric coincidences retained")
    require(0 < counts["eager"]["protected_first_activations"] < counts["eager"]["executions"], "both registration branches exercised")
    return {"key_space": 4, "oracle_domain": 4, "oracle_range": 2, "counts": counts, "joint_distributions_equal": True}


def pre_registration_leak_counterexample() -> dict:
    # If a root-dependent bit is visible before selection, an unopened-
    # handle model is inapplicable. Select a root only when its parity is 0.
    real_bad = 0
    fresh_bad = 0
    total = 0
    for old in range(4):
        for fresh in range(4):
            registered = old % 2 == 0
            real_bad += registered and old % 2 == 1
            fresh_bad += registered and fresh % 2 == 1
            total += 1
    require(real_bad == 0 and Fraction(fresh_bad, total) == Fraction(1, 4), "leakage control distinguishes naive deferred resampling")
    return {
        "event": "registered and used root has odd parity",
        "real_probability": str(Fraction(real_bad, total)),
        "incorrect_fresh_after_selection_probability": str(Fraction(fresh_bad, total)),
        "premise_violation_detected": True,
    }


def pad(salt: bytes, byte: int) -> bytes:
    require(len(salt) == 32, "32-byte salt")
    return bytes(x ^ byte for x in salt + bytes(32))


class ForcedCompression:
    """Finite programmed witness; not actual SHA-256 compression."""

    def __init__(self, first_salt: bytes, second_salt: bytes):
        alpha = bytes([0x31]) * 32
        beta = bytes([0x92]) * 32
        self.fixed = {
            (pad(salt, 0x36), IV): alpha
            for salt in (first_salt, second_salt)
        }
        self.fixed.update({
            (pad(salt, 0x5C), IV): beta
            for salt in (first_salt, second_salt)
        })
        self.observed = {}

    def __call__(self, block: bytes, state: bytes) -> bytes:
        require(len(block) == 64 and len(state) == 32, "compression input width")
        key = (block, state)
        value = self.fixed.get(key)
        if value is None:
            value = hashlib.sha256(b"finite-compression-control/" + block + state).digest()
        previous = self.observed.setdefault(key, value)
        require(previous == value, "one shared consistent oracle")
        return value

    def digest(self, data: bytes) -> bytes:
        padded = data + b"\x80"
        padded += bytes((56 - len(padded) % 64) % 64)
        padded += (8 * len(data)).to_bytes(8, "big")
        state = IV
        for offset in range(0, len(padded), 64):
            state = self(padded[offset:offset + 64], state)
        return state

    def mac(self, key: bytes, data: bytes) -> bytes:
        require(len(key) == 32, "all control HMAC keys are 32 bytes")
        inner = self.digest(pad(key, 0x36) + data)
        return self.digest(pad(key, 0x5C) + inner)


def forced_descriptor_alias() -> dict:
    ctx = bytes(range(32))
    initial = b"control/same-initial"
    reply_a = b"control/same-reply-body/signature-a"
    reply_b = b"control/same-reply-body/signature-b"
    _, sid_a = transcript(ctx, initial, reply_a)
    _, sid_b = transcript(ctx, initial, reply_b)
    require(sid_a != sid_b, "distinct full-wire salts for forced collision")
    oracle = ForcedCompression(sid_a, sid_b)
    gamma_a = (oracle(pad(sid_a, 0x36), IV), oracle(pad(sid_a, 0x5C), IV))
    gamma_b = (oracle(pad(sid_b, 0x36), IV), oracle(pad(sid_b, 0x5C), IV))
    require(gamma_a == gamma_b, "forced full pad-state collision")
    seed = bytes([0x6D]) * 32
    root_a, _, blocks_a = root_and_blocks(seed, sid_a, ctx, oracle.mac)
    root_b, _, blocks_b = root_and_blocks(seed, sid_b, ctx, oracle.mac)
    require(root_a == root_b and blocks_a == blocks_b, "alias preserves root and all activation blocks")
    require(pad(sid_a, 0x36) != pad(sid_b, 0x36), "different witness inputs")
    # Exhaust all four 1-bit pad answers for two salts. Equality of the full
    # descriptor implies the inner-pad collision for every assignment.
    full_aliases = 0
    inner_only = 0
    for a0, b0, a1, b1 in itertools.product(range(2), repeat=4):
        alias = (a0, b0) == (a1, b1)
        require(not alias or a0 == a1, "descriptor alias yields inner witness")
        full_aliases += alias
        inner_only += a0 == a1 and b0 != b1
    require((full_aliases, inner_only) == (4, 4), "finite descriptor enumeration")
    return {
        "oracle_scope": "deliberately forced finite compression oracle; not a SHA-256 collision",
        "sid_a": sid_a.hex(), "sid_b": sid_b.hex(),
        "inner_input_a": (pad(sid_a, 0x36) + IV).hex(),
        "inner_input_b": (pad(sid_b, 0x36) + IV).hex(),
        "equal_inner_output": gamma_a[0].hex(),
        "root": root_a.hex(), "ack": blocks_a[3].hex(),
        "all_five_blocks_equal": True,
        "finite_pad_assignments": 16,
        "complete_alias_assignments": full_aliases,
        "inner_only_collision_assignments": inner_only,
        "observed_compression_inputs": len(oracle.observed),
    }


def common_table_distribution() -> dict:
    # The observer receives every sibling block and the used ACK. Repeat the
    # ACK in the view to exercise the same-class/endpoints cache as well.
    normal = Counter()
    overridden = Counter()
    for blocks in itertools.product(range(4), repeat=5):
        view = blocks + (blocks[3],)
        normal[view] += 4  # Same denominator as the independent replacement.
        for replacement in range(4):
            used = blocks[:3] + (replacement,) + blocks[4:]
            overridden[used + (replacement,)] += 1
    require(normal == overridden, "full joint sibling/ACK distributions")
    return {
        "block_alphabet_size": 4,
        "normal_block_tuples": 4 ** 5,
        "replacement_executions": 4 ** 6,
        "distinct_available_views": len(normal),
        "joint_distributions_equal": True,
    }


def historical_recipe_stop() -> dict:
    # One fixed public derivation J -> O; a captured image under J contains
    # an operation token under O, whose original source reconstructs root a.
    acquired = {"old-image"}
    live = {"old-image"}
    keys = set()
    graph = {
        "old-image": ("J", {"token"}, set()),
        "token": ("O", set(), {"root-a"}),
    }

    def closure(proposed_keys):
        known_keys = set(proposed_keys)
        if "J" in known_keys:
            known_keys.add("O")
        records = set(acquired)
        sources = set()
        changed = True
        while changed:
            before = (len(records), len(sources))
            for record in tuple(records):
                guard, children, originals = graph[record]
                if guard in known_keys:
                    records.update(children)
                    sources.update(originals)
            changed = before != (len(records), len(sources))
        if "root-a" in sources:
            sources.add("ack-a")
        return sources

    require("ack-a" not in closure(keys), "unopened captured image has no recipe")
    protected = {"ack-a"}
    live.clear()  # Does not alter acquisitions.
    latched_bad = True
    requested = "J"
    would_expose = bool(protected & closure(keys | {requested}))
    returned = None if would_expose else requested
    require(would_expose and returned is None and latched_bad, "pre-return stop preserves latched event")
    require("old-image" in acquired and not live, "past acquisition survives local deletion")
    # A pre-registration opening is refused by the same recipe predicate.
    require("ack-a" in closure({"J"}), "earlier matching-key opening refuses protection")
    return {
        "captured_then_deleted": True,
        "matching_key_would_expose": sorted(closure({"J"})),
        "protected_key_return_stopped": would_expose,
        "returned_key": returned,
        "earlier_bad_event_preserved": latched_bad,
        "pre_registration_opening_refuses_protection": True,
    }


def source_order_checks(source_root: Path) -> dict:
    prefix = source_root / "research/continuity-identity-candidate/src"
    bootstrap = (prefix / "bootstrap.rs").read_text()
    messages = (prefix / "durable/messages.rs").read_text()
    traffic = (prefix / "durable/messages/traffic.rs").read_text()
    responder = bootstrap[bootstrap.index("fn prepared_response("):bootstrap.index("fn finish_initiator(")]
    finish_start = bootstrap.index("fn finish_initiator(")
    finish = bootstrap[finish_start:bootstrap.index("#[cfg(test)]", finish_start)]
    require(responder.index("let reply = envelope(") < responder.index("let session = pending("), "complete Reply before root")
    require(finish.index("verify_mac(keys.responder") < finish.index("let session = pending("), "Reply confirmation before root")
    require("root: Some(derive(seed.as_bytes(), &id, &label)?)" in bootstrap, "root retained by pending")
    for method, status in (("activate_initiator_messages", "FinalCommitted"), ("activate_responder_messages", "Complete")):
        section = messages[messages.index(f"pub async fn {method}"):]
        section = section[:section.index("\n    }")]
        require(section.index(f"record.phase != DurableStatus::{status}") < section.index("State::new("), f"activation gate: {method}")
        require(section.index("retire_session_root()?") < section.index("State::new("), f"original root: {method}")
    require("ZeroizingBytes::<160>::zeroed()" in messages, "one five-block activation")
    require("let ack_a = key(material.get(64..96)" in traffic, "ACK block relative to traffic suffix")
    require("(a, b, ack_a, ack_b)" in traffic and "(b, a, ack_b, ack_a)" in traffic, "role ACK correspondence")
    return {"inspected_sequence_checks": 10, "root_before_activation": True, "ready_uses_block_4_at_both_roles": True}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[4])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = {
        "schema": "q-periapt/bootstrap-terminal-schedule-connection-controls/v1",
        "status": "pass",
        "evidence_kind": "executed finite controls and source checks; analytical theorem retained separately",
        "checker_sha256": sha256(Path(__file__).read_bytes()),
        "pins": validate_pins(args.source_root),
        "source_order": source_order_checks(args.source_root),
        "source_equations": source_equations(),
        "deferred_sampling": deferred_sampling(),
        "pre_registration_leak_counterexample": pre_registration_leak_counterexample(),
        "forced_descriptor_alias": forced_descriptor_alias(),
        "common_table_distribution": common_table_distribution(),
        "historical_recipe_stop": historical_recipe_stop(),
    }
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded)
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
