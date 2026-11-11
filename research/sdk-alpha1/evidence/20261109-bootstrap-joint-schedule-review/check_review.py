#!/usr/bin/env python3
"""Public calculations for the bootstrap assessment; no native crypto execution."""

import argparse
import hashlib
import hmac
import itertools
import json
import re
import struct
from pathlib import Path


BASE = "a4c089570c787522210d16226219c0cc8aa9b05e"
ENGINE = "research/continuity-identity-candidate/src/"
MASK = (1 << 32) - 1
IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
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


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK


def compress(block, state):
    require(len(block) == 64 and len(state) == 32, "compression input widths")
    old = struct.unpack(">8I", state)
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        x, y = w[i - 15], w[i - 2]
        s0 = rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
        s1 = rotr(y, 17) ^ rotr(y, 19) ^ (y >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & MASK)
    a, b, c, d, e, f, g, hh = old
    for ki, wi in zip(K, w):
        s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ (~e & g)
        t1 = (hh + s1 + ch + ki + wi) & MASK
        s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (s0 + maj) & MASK
        hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & MASK, c, b, a, (t1 + t2) & MASK
    return struct.pack(">8I", *((x + y) & MASK for x, y in zip(old, (a, b, c, d, e, f, g, hh))))


def padding(consumed):
    return b"\x80" + bytes((55 - consumed) % 64) + (8 * consumed).to_bytes(8, "big")


def mac(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def expand(prk, info, length):
    require(0 <= length <= 255 * 32, "HKDF output bound")
    previous, result = b"", b""
    for i in range(1, (length + 31) // 32 + 1):
        previous = mac(prk, previous + info + bytes([i]))
        result += previous
    return result[:length]


def framed_hash(domain, data):
    framed = len(domain).to_bytes(8, "big") + domain + len(data).to_bytes(8, "big") + data
    return hashlib.sha3_256(framed).digest()


def disclosure_closure(initial):
    """Declared finite record/replay rules, not a cryptographic leakage oracle."""
    known = set(initial)
    phase_payloads = {
        "I10": {"token_g"},
        "I11": {"token_g", "token_e0"},
        "I12": {"token_g", "token_e0", "rnd"},
        "I_waiting": {"sk_reply", "S0"},
        "I_processing": {"sk_reply", "S0", "public_C1"},
        "I_final": {"K_B"},
        "R_executing": set(),
        "R13": {"S0", "token_e1"},
        "R14": {"S0", "token_e1", "rnd"},
        "R_prepared": {"K_B", "KI"},
        "R_complete": {"K_B"},
        "marker3": set(),
        "messages_epoch0": {"R0", "chainI", "chainR", "ackI", "ackR"},
        "rejected": set(),
        "cancelled": set(),
        "prekeys_live": {"token_selected_pq", "token_selected_x"},
        "prekeys_reusable": {"token_selected_pq", "token_selected_x"},
        "prekey_pq_leaf": {"token_selected_pq"},
        "prekey_x_leaf": {"token_selected_x"},
        "prekeys_consumed": set(),
        "prekeys_abandoned": set(),
        "prekeys_retired": set(),
    }
    while True:
        before = set(known)
        if "J" in known:
            known.update({"O", "G"})
        if "pending_I11" in known:
            known.add("image_I11")
        for name, payload in phase_payloads.items():
            if {"image_" + name, "J"} <= known:
                known.update(payload)
        for token, value in (("token_g", "sk_reply"), ("token_e0", "S0"),
                             ("token_e1", "S1"),
                             ("token_selected_pq", "selected_pq_owner"),
                             ("token_selected_x", "selected_x_owner")):
            if {token, "O"} <= known:
                known.add(value)
        if {"signer_file", "G"} <= known:
            known.add("identity")
        if {"sk_reply", "public_C1"} <= known:
            known.add("S1")
        if {"selected_pq_owner", "selected_x_owner", "public_C0"} <= known:
            known.add("S0")
        if "S0" in known:
            known.add("K0")
        if {"S0", "S1", "reply_core"} <= known:
            known.update({"P_B", "seed", "KR", "KI"})
        if {"seed", "transcript"} <= known:
            known.add("K_B")
        if {"K_B", "transcript"} <= known:
            known.update({"R0", "chainI", "chainR", "ackI", "ackR"})
        if known == before:
            return known


def run(source_root, pins_path):
    pins = json.loads(pins_path.read_text())
    require(pins["source_commit"] == BASE, "source identity")
    sources = {}
    for entry in pins["files"]:
        data = (source_root / entry["path"]).read_bytes()
        require(git_blob(data) == entry["git_blob"], "base blob: " + entry["path"])
        require(sha(data) == entry["sha256"], "SHA-256: " + entry["path"])
        sources[entry["path"]] = data.decode()
    bootstrap = sources[ENGINE + "bootstrap.rs"]
    tests = sources[ENGINE + "durable/messages/tests.rs"]
    bdomain = re.search(r'b"(Q-PERIAPT-CONTINUITY-BOOTSTRAP-KDF[^\"]+)"', bootstrap).group(1).encode()
    hdomain = re.search(r'b"(Q-PERIAPT-CONTINUITY-BOOTSTRAP-CANDIDATE[^\"]+)"', bootstrap).group(1).encode()
    mdomain = re.search(r'MESSAGE_DOMAIN: &\[u8\] = b"([^\"]+)"', sources[ENGINE + "contract.rs"]).group(1).encode()
    labels = [b"handshake-seed", b"confirmation-responder", b"confirmation-initiator"]
    infos = [bdomain + x for x in labels]
    root_info = bdomain + b"session-root/" + bytes([4]) * 32
    initial_info = mdomain + b"initial/HKDF-SHA256/ChaCha20Poly1305" + bytes([11]) * 32
    sdk_info_length = 107 + len(b"ContinuityBootstrapCandidate/v1/initial") + 32
    lengths = {"bootstrap_info": list(map(len, infos)), "root_info": len(root_info),
               "activation_info": len(initial_info), "sdk_initial_info": sdk_info_length,
               "activation_hmac_messages": [len(initial_info) + 1] + [len(initial_info) + 33] * 4}
    require(lengths == {"bootstrap_info": [62, 70, 70], "root_info": 93,
                        "activation_info": 111, "sdk_initial_info": 178,
                        "activation_hmac_messages": [112, 144, 144, 144, 144]}, "source information lengths")

    vectors = []
    def vector(name, value, source):
        require('"' + value.hex() + '"' in source, "retained source vector: " + name)
        vectors.append({"name": name, "hex": value.hex()})
    prk = mac(bytes([3]) * 32, bytes([1]) * 32 + bytes([2]) * 32)
    seed, kr, ki = [expand(prk, info, 32) for info in infos]
    for name, value in (("seed", seed), ("KR", kr), ("KI", ki), ("MACR", mac(kr, bytes([3]) * 32))):
        vector(name, value, bootstrap)
    bhash = lambda label, data: framed_hash(hdomain + label, data)
    final_prefix = b"QPBSF001" + bytes([4]) * 32 + bhash(b"initial-wire", b"initial-test") + bhash(b"reply-wire", b"reply-test")
    sid = bhash(b"session-id", final_prefix)
    vector("sid", sid, bootstrap)
    vector("K_B", expand(mac(sid, seed), root_info, 32), bootstrap)
    material = expand(mac(bytes([9]) * 32, bytes([7]) * 32), initial_info, 160)
    blocks = [material[i:i + 32] for i in range(0, 160, 32)]
    vector("activation_first_96", material[:96], tests)
    chain_info = mdomain + b"chain"
    next0 = expand(mac(bytes(32), blocks[1]), chain_info + bytes(8), 64)
    vector("chain_step_0", next0, tests)
    vector("chain_step_1", expand(mac(bytes(32), next0[:32]), chain_info + (1).to_bytes(8, "big"), 64), tests)
    ack_prefix = b"QPCMACK1" + bytes([9]) * 32 + bytes([2]) + bytes(8)
    vector("role_1_ack_for_direction_2", ack_prefix + mac(blocks[4], mdomain + b"acknowledgement" + ack_prefix), tests)
    role1 = {"send_ack": blocks[3], "receive_ack": blocks[4]}
    role2 = {"send_ack": blocks[4], "receive_ack": blocks[3]}
    require(role1["send_ack"] == role2["receive_ack"], "READY direction-1 ACK assignment")

    # Independently evaluate the stated three post-pad compression calls.
    iv = struct.pack(">8I", *IV)
    p32, p64 = padding(96), padding(128)
    require(len(p32) == 32 and len(p64) == 64, "consumed-pad lengths")
    padding_checks = []
    for salt, s0, s1 in ((bytes([3]) * 32, bytes([1]) * 32, bytes([2]) * 32),
                         (bytes(32), bytes(range(32)), p32),
                         (bytes(range(32)), bytes(32), bytes([255]) * 32)):
        padded_key = salt + bytes(32)
        alpha = compress(bytes(x ^ 0x36 for x in padded_key), iv)
        beta = compress(bytes(x ^ 0x5C for x in padded_key), iv)
        z = compress(s0 + s1, alpha)
        u = compress(p64, z)
        result = compress(u + p32, beta)
        require(result == mac(salt, s0 + s1), "64-byte Extract compression equation")
        padding_checks.append(result.hex())
    sigma = b"QPeriapt-SDK-HKDF-SHA256-v1"
    r0 = sigma + bytes(32 - len(sigma))
    require(mac(sigma, bytes(range(32))) == mac(r0, bytes(range(32))), "SDK zero-extension")
    chosen_s0, chosen_s1 = bytes(range(32)), padding(96)
    sdk_inner_block = chosen_s0 + padding(64 + len(chosen_s0))
    bootstrap_first_block = (chosen_s0 + chosen_s1)[:64]
    require(sdk_inner_block == bootstrap_first_block, "shared first private block")
    require(sdk_inner_block != chosen_s0 + bytes(32), "changed suffix separates the private point")
    require(p32 != p64, "32-byte and 64-byte padding are different")

    public = {"public_C0", "public_C1", "reply_core", "transcript"}
    cases = [
        ("generation_only", {"image_I10", "J"}, (False, True, False, False, False)),
        ("initial_kem", {"image_I11", "J"}, (True, True, True, True, False)),
        ("initial_signing", {"image_I12", "J"}, (True, True, True, True, False)),
        ("waiting", {"image_I_waiting", "J"}, (True, True, True, True, False)),
        ("processing", {"image_I_processing", "J"}, (True, True, True, True, False)),
        ("initiator_final", {"image_I_final", "J"}, (False, False, True, True, False)),
        ("responder_executing", {"image_R_executing", "J"}, (False, False, False, False, False)),
        ("responder_kem", {"image_R13", "J"}, (True, True, True, True, False)),
        ("responder_signing", {"image_R14", "J"}, (True, True, True, True, False)),
        ("responder_prepared", {"image_R_prepared", "J"}, (False, False, True, True, False)),
        ("responder_complete", {"image_R_complete", "J"}, (False, False, True, True, False)),
        ("marker3_alone", {"image_marker3", "J"}, (False, False, False, False, False)),
        ("complete_messages_epoch0", {"image_marker3", "image_messages_epoch0", "J"}, (False, False, False, True, False)),
        ("rejected", {"image_rejected", "J"}, (False, False, False, False, False)),
        ("cancelled", {"image_cancelled", "J"}, (False, False, False, False, False)),
        ("whole_image_prekeys", {"image_R_executing", "image_prekeys_live", "J"}, (True, False, False, False, False)),
        ("one_pq_leaf", {"image_prekey_pq_leaf", "J"}, (False, False, False, False, False)),
        ("one_classical_leaf", {"image_prekey_x_leaf", "J"}, (False, False, False, False, False)),
        ("both_selected_owners", {"selected_pq_owner", "selected_x_owner"}, (True, False, False, False, False)),
        ("one_direct_leaf_token", {"token_selected_pq", "O"}, (False, False, False, False, False)),
        ("consumed_prekey_only", {"image_prekeys_consumed", "J"}, (False, False, False, False, False)),
        ("abandoned_prekey_only", {"image_prekeys_abandoned", "J"}, (False, False, False, False, False)),
        ("retired_prekey_only", {"image_prekeys_retired", "J"}, (False, False, False, False, False)),
        ("reusable_prekey_record_with_marker3", {"image_prekeys_reusable", "image_marker3", "J"}, (True, False, False, False, False)),
        ("signer_file_and_journal_key", {"signer_file", "J"}, (False, False, False, False, True)),
        ("journal_key_only", {"J"}, (False, False, False, False, False)),
        ("encrypted_initial_only", {"image_I11"}, (False, False, False, False, False)),
        ("wrong_key", {"image_I11", "wrong_J"}, (False, False, False, False, False)),
        ("direct_generation_token", {"token_g", "O"}, (False, True, False, False, False)),
        ("initial_root_only", {"R0"}, (False, False, False, False, False)),
        ("bootstrap_root_only", {"K_B"}, (False, False, True, True, False)),
        ("both_contributions", {"S0", "S1"}, (True, True, True, True, False)),
    ]
    closure_rows = []
    for name, inputs, expected in cases:
        result = disclosure_closure(public | inputs)
        observed = tuple(x in result for x in ("S0", "S1", "K_B", "ackI", "identity"))
        require(observed == expected, "phase/disclosure case: " + name)
        closure_rows.append({"case": name, "inputs": sorted(inputs), "projection": list(observed)})

    # An independent closed guard formula for one image/pending/token/signer DAG.
    atoms = ("image_I11", "pending_I11", "token_g", "token_e0", "J", "O", "signer_file", "G")
    for bits in itertools.product((False, True), repeat=len(atoms)):
        acquired = {a for a, enabled in zip(atoms, bits) if enabled}
        image_readable = "J" in acquired and bool(acquired & {"image_I11", "pending_I11"})
        operation_key = bool(acquired & {"J", "O"})
        got_g = image_readable or ("token_g" in acquired and operation_key)
        got_e0 = image_readable or ("token_e0" in acquired and operation_key)
        got_identity = "signer_file" in acquired and bool(acquired & {"J", "G"})
        expected = (got_e0, got_g, got_e0 and got_g, got_e0 and got_g, got_identity)
        got = disclosure_closure(public | acquired)
        require(tuple(x in got for x in ("S0", "S1", "K_B", "ackI", "identity")) == expected,
                "guard formula / fixed-point agreement")

    prekey_atoms = ("token_selected_pq", "token_selected_x", "J", "O")
    for bits in itertools.product((False, True), repeat=len(prekey_atoms)):
        acquired = {a for a, enabled in zip(prekey_atoms, bits) if enabled}
        expected_s0 = {"token_selected_pq", "token_selected_x"} <= acquired and bool(acquired & {"J", "O"})
        got = disclosure_closure(public | acquired)
        require(("S0" in got) == expected_s0 and "S1" not in got,
                "two selected prekey components are jointly required")

    before = disclosure_closure(public | {"image_I11"})
    after = disclosure_closure(public | {"image_I11", "J"})
    require(before <= after and "ackI" not in before and "ackI" in after, "late-key disclosure")
    # Local deletion leaves the acquired set unchanged; another aggregate may carry the same source.
    require(disclosure_closure(public | {"image_I11", "J"}) == after, "retained copy after deletion")
    pending_before = disclosure_closure(public | {"pending_I11"})
    require("image_I11" in pending_before and "S0" not in pending_before,
            "pending target ciphertext extraction needs no intent authentication key")
    require(disclosure_closure(public | {"pending_I11", "J"}) >= after, "intact pending target")

    # Forced alias fixture: the declared ideal is indexed by the effective descriptor.
    sid_a, sid_b = bytes([1]) * 32, bytes([2]) * 32
    forced_gamma = {sid_a: ("alpha", "beta"), sid_b: ("alpha", "beta")}
    descriptors = {(forced_gamma[s], root_info) for s in (sid_a, sid_b)}
    require(len(descriptors) == 1 and sid_a != sid_b, "pad-state alias reuse")
    require(len({(s, root_info) for s in (sid_a, sid_b)}) == 2, "salt-only cache negative control")

    # Finite interface controls for the mixed activation service. Public chosen
    # blocks represent one fixed sample of its protected independent table.
    entries = {}
    def allocate(descriptor, protected, root):
        if descriptor in entries:
            require(entries[descriptor]["protected"] == protected, "immutable protection mark")
            return entries[descriptor]
        entry = {"protected": protected, "root": root, "activation": None}
        entries[descriptor] = entry
        return entry
    def activation(entry, salt, info):
        if entry["activation"] is None:
            entry["activation"] = (b"".join(bytes([0xA0 + i]) * 32 for i in range(5))
                                   if entry["protected"] else expand(mac(salt, entry["root"]), info, 160))
        return entry["activation"]
    def reveal_root(entry):
        if entry["protected"]:
            raise ValueError("protected recipe stop before root return")
        return entry["root"]
    activation_root_info = bdomain + b"session-root/" + bytes([11]) * 32
    protected_desc = (forced_gamma[sid_a], activation_root_info)
    protected = allocate(protected_desc, True, bytes([17]) * 32)
    protected_blocks = activation(protected, sid_a, initial_info)
    alias = allocate((forced_gamma[sid_b], activation_root_info), True, bytes([17]) * 32)
    require(alias is protected and activation(alias, sid_b, initial_info) == protected_blocks,
            "protected aliases share the mark, handle and five blocks")
    unprotected_desc = (("other_alpha", "other_beta"), activation_root_info)
    unprotected = allocate(unprotected_desc, False, bytes([7]) * 32)
    known_root = reveal_root(unprotected)
    unprotected_blocks = activation(unprotected, bytes([9]) * 32, initial_info)
    require(unprotected_blocks == expand(mac(bytes([9]) * 32, known_root), initial_info, 160),
            "disclosed current-game root retains real activation")
    require(protected_blocks != unprotected_blocks,
            "independent blocks at disclosed root fail the real derivation relation")
    ready_prefix = b"QPCMACK1" + bytes([9]) * 32 + bytes([1]) + bytes(8)
    ready_input = mdomain + b"acknowledgement" + ready_prefix
    real_tag = mac(unprotected_blocks[96:128], ready_input)
    known_root_blocks = expand(mac(bytes([9]) * 32, known_root), initial_info, 160)
    require(real_tag == mac(known_root_blocks[96:128], ready_input), "known-root ACK relation")
    require(real_tag != mac(protected_blocks[96:128], ready_input),
            "independent blocks at a disclosed root break the ACK relation")
    try:
        allocate(unprotected_desc, True, known_root)
    except ValueError:
        pass
    else:
        raise ValueError("unprotected descriptor was promoted")
    try:
        reveal_root(protected)
    except ValueError:
        pass
    else:
        raise ValueError("protected root escaped before stop")
    require("ackI" not in disclosure_closure(public | {"R0"}), "R0-only disclosure stays outside ACK recipe")
    require("ackI" in disclosure_closure(public | {"image_R13", "J"}),
            "cumulative captured plan and key trigger the protected recipe stop")
    return {
        "schema": 1, "source_commit": BASE, "source_files_verified": len(sources),
        "checker_sha256": sha(Path(__file__).read_bytes()),
        "source_pins_sha256": sha(pins_path.read_bytes()),
        "scope": "public synthetic calculations and declared finite disclosure/alias model; no native Rust, KEM, CI, or external review execution",
        "information_lengths": lengths, "source_vectors": vectors,
        "extract64_compression_checks": padding_checks,
        "padding32_hex": p32.hex(), "padding64_hex": p64.hex(),
        "closure_projection": ["S0", "S1", "K_B", "ackI", "identity"],
        "closure_cases": closure_rows, "guard_subsets_checked": 2 ** len(atoms),
        "selected_prekey_subsets_checked": 2 ** len(prekey_atoms),
        "history_controls": ["late matching key", "retained copy after local deletion",
                             "pending ciphertext extraction without intent key", "intact pending target"],
        "alias_controls": ["SDK salt zero extension", "shared 32/64-byte first private point", "forced Gamma alias reuse", "salt-only indexing differs"],
        "protected_activation_controls": ["first allocation fixes protection", "descriptor aliases share handle and blocks",
                                          "unprotected current-game root reveal uses real activation",
                                          "independent blocks at a disclosed root fail the derivation relation",
                                          "disclosed-root ACK tag retains its real derivation relation",
                                          "unprotected entry cannot be promoted", "stop before protected root return",
                                          "R0-only disclosure differs from ACK recipe", "retained plan plus key enters cumulative ACK recipe"],
        "result": "pass",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[4])
    parser.add_argument("--pins", type=Path, default=Path(__file__).with_name("SOURCE_PINS.json"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    encoded = json.dumps(run(args.source_root, args.pins), indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded)
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
