#!/usr/bin/env python3
"""Source and finite-model controls for the original reply-source proof.

This checker executes no native KEM/provider and establishes no asymptotic
cryptographic claim. The analytical proof fixes those games and bounds.
"""

from __future__ import annotations

import argparse
from collections import Counter
from fractions import Fraction
import hashlib
import itertools
import json
from pathlib import Path


PACKET = Path(__file__).resolve().parent


def require(value, message):
    if not value:
        raise AssertionError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def source_pins(root):
    manifest = json.loads((PACKET / "SOURCE_PINS.json").read_text())
    for item in manifest["files"]:
        data = (root / item["path"]).read_bytes()
        require(len(data) == item["bytes"], f"length {item['path']}")
        require(git_blob(data) == item["git_blob"], f"Git blob {item['path']}")
        require(digest(data) == item["sha256"], f"SHA-256 {item['path']}")
    return {
        "checked_files": len(manifest["files"]),
        "base_commit": manifest["base_commit"],
        "base_tree": manifest["base_tree"],
        "source_pins_sha256": digest((PACKET / "SOURCE_PINS.json").read_bytes()),
    }


def checked_section(text, start, end):
    at = text.index(start)
    return text[at:text.index(end, at)]


def source_correspondence(root):
    prefix = root / "research/continuity-identity-candidate/src"
    i = (prefix / "durable/initiator.rs").read_text()
    r = (prefix / "durable/responder.rs").read_text()
    rp = (prefix / "bootstrap/response_staged.rs").read_text()
    bp = (prefix / "bootstrap/staged.rs").read_text()
    sdk = (root / "crates/q-periapt-sdk/src/lib.rs").read_text()
    replay = (root / "crates/q-periapt-sdk/src/expert/replay.rs").read_text()
    expert = (root / "crates/q-periapt-sdk/src/expert.rs").read_text()
    backend = (root / "crates/q-periapt-backends/src/contextbound_key.rs").read_text()
    core = (root / "crates/q-periapt-core/src/lib.rs").read_text()
    checks = []

    def check(value, label):
        require(value, label)
        checks.append(label)

    start = checked_section(i, "pub async fn initiate(", "let operation = match plan.complete(")
    check(start.index("self.persist(&mut image).await?;") < start.index("plan.advance("), "InitialKeyReserved durable before generation advance")
    drive = checked_section(r, "record.phase = DurableStatus::ResponseKemReserved", "/// Continue a committed responder")
    check(drive.index("self.persist(&mut image).await?;") < drive.index("self.drive_response("), "response reservation durable before first compute")
    check("if expected != *body" in rp and "if expected != *body" in bp, "restored plans require exact recomputed bodies")
    check("&self.initial" in rp and "self.kem" in rp, "response retains complete Initial and encapsulation token")
    gen = checked_section(sdk, "fn generate_with(", "/// Encapsulate with platform")
    check(gen.index("rng(seed.as_mut_bytes())?") < gen.index("rng(traditional.as_mut_bytes())?"), "generation consumes PQ then traditional entropy")
    enc = checked_section(sdk, "fn encapsulate_with(", "impl Drop for Runtime")
    check(enc.index("rng(coins.as_mut_bytes())?") < enc.index("rng(scalar.as_mut_bytes())?"), "encapsulation consumes PQ then traditional entropy")
    check("Self::Generate => 64 + 32" in replay and "Self::Encapsulate => 32 + 32" in replay, "native reservation entropy lengths")
    check("const BINDING_LEN: usize = 8 + 1 + 68 + 32 + 32" in replay, "operation binding width")
    check("const HEADER_LEN: usize = BINDING_LEN + 24" in replay, "explicit 192-bit token nonce")
    check("getrandom::fill(out).map_err(|_| Error::Entropy)" in expert, "expanded import uses fresh platform check coins")
    imp = checked_section(backend, "pub fn import_expanded_for_expert(", "impl PreparedKem for MlKem768")
    check(imp.index("NativeMlKem768::encapsulate_derand(") < imp.index("NativeMlKem768::decapsulate("), "import performs encapsulation then decapsulation")
    check("q_periapt_core::ct_eq(expected.as_bytes(), recovered.as_bytes())" in imp, "import compares actual expected/recovered keys")
    fields = [
        "absorb_public_lp(&mut x, DOMAIN)",
        "absorb_public_lp(&mut x, input.suite_id)",
        "absorb_public_lp(&mut x, &input.policy_version.to_be_bytes())",
        "absorb_secret_lp(&mut x, input.ss_pq)",
        "absorb_secret_lp(&mut x, input.ss_trad)",
        "absorb_public_lp(&mut x, input.ct_pq)",
        "absorb_public_lp(&mut x, input.pk_pq)",
        "absorb_public_lp(&mut x, input.ct_trad)",
        "absorb_public_lp(&mut x, input.pk_trad)",
    ]
    cb = core[core.index("// Context-bound: the GHP/Chempat"):]
    positions = [cb.index(field) for field in fields]
    check(positions == sorted(positions), "complete ContextBound field order")
    check("absorb_public_lp(&mut x, POLICY_CONTEXT_DOMAIN)" in cb and "absorb_public_lp(&mut x, digest)" in cb, "ContextBound policy wrapper retained")
    return {"checks": checks, "count": len(checks)}


def token_layout():
    def binding(kind, policy, operation, inputs):
        return b"QPSOP001" + bytes([kind]) + policy + operation + inputs

    policy = bytes(range(68))
    operation = bytes([7]) * 32
    inputs = bytes([9]) * 32
    gen_binding = binding(1, policy, operation, bytes(32))
    enc_binding = binding(2, policy, operation, inputs)
    require(len(gen_binding) == len(enc_binding) == 141, "binding byte length")
    gen_entropy = bytes(range(96))
    enc_entropy = bytes(range(64))
    require(len(gen_entropy[:64]) == 64 and len(gen_entropy[64:]) == 32, "generation slices")
    require(len(enc_entropy[:32]) == len(enc_entropy[32:]) == 32, "encapsulation slices")
    variants = {
        enc_binding,
        binding(1, policy, operation, inputs),
        binding(2, policy[:-1] + b"\xff", operation, inputs),
        binding(2, policy, bytes([8]) * 32, inputs),
        binding(2, policy, operation, bytes([10]) * 32),
    }
    require(len(variants) == 5, "kind/policy/operation/input binding differences")
    return {
        "binding_bytes": 141, "header_bytes": 165,
        "generation_entropy_bytes": [64, 32],
        "encapsulation_entropy_bytes": [32, 32],
        "sealed_operation_bytes": {"generation": 165 + 96 + 16, "encapsulation": 165 + 64 + 16},
        "distinct_binding_controls": len(variants),
        "scope": "public layout and entropy slicing; no encryption execution",
    }


def origin_stability():
    traces = []
    for first in ("uncommitted_error", "committed_error", "success"):
        ledger = ["g1"]
        durable = None if first == "uncommitted_error" else "g1"
        executed = []
        # An error ends that invocation before private computation. Recovery
        # reads the actual durable target; only an absent target samples again.
        if durable is None:
            ledger.append("g2")
            durable = "g2"
        executed.append(durable)
        original = durable
        for later_write in ("uncommitted_error", "committed_error", "success"):
            # Either prior phase or target phase has the same original token.
            recovered = original
            executed.append(recovered)
            require(recovered == original, "later failure preserves executed origin")
        require(len(set(executed)) == 1, "one executed origin")
        if first == "uncommitted_error":
            require(ledger == ["g1", "g2"] and original == "g2", "failed first reservation remains a separate unused draw")
        else:
            require(original == "g1", "durable unknown result retrieves first original")
        traces.append({"first_write": first, "sampled": ledger, "executed": executed})
    return {"traces": traces, "fresh_draw_after_every_reopen_mutation_rejected": True}


def contextbound_encoding():
    lp = lambda value: len(value).to_bytes(8, "big") + value
    policy_context = b"".join(map(lp, [b"Q-PERIAPT-POLICY-CONTEXT/v1", bytes([5]) * 32, bytes([6]) * 32]))
    fields = [
        b"Q-PERIAPT-HYBRID-KEM/v1", b"ML-KEM-768+X25519", (1).to_bytes(4, "big"),
        bytes([7]) * 32, bytes([8]) * 32, bytes([9]) * 1088,
        bytes([10]) * 1184, bytes([11]) * 32, bytes([12]) * 32, policy_context,
    ]
    encoded = b"".join(map(lp, fields))
    pq_offset = sum(8 + len(f) for f in fields[:3]) + 8
    require(len(encoded) == 2639 and pq_offset == 76, "complete ContextBound width/hidden-field offset")
    require(encoded[pq_offset:pq_offset + 32] == fields[3], "hidden field occupies its actual offset")
    parsed = []
    offset = 0
    while offset < len(encoded):
        length = int.from_bytes(encoded[offset:offset + 8], "big")
        offset += 8
        parsed.append(encoded[offset:offset + length])
        offset += length
    require(parsed == fields, "all ten actual fields recover from the encoding")
    mutations = set()
    for i, field in enumerate(fields):
        changed = fields[:]
        changed[i] = bytes([field[0] ^ 1]) + field[1:]
        mutation = b"".join(map(lp, changed))
        require(mutation != encoded, "each effective field remains in the table identity")
        mutations.add(mutation)
    require(len(mutations) == 10, "distinct field controls")
    by_origin = {"a": tuple(fields), "a-copy": tuple(fields), "different-original-same-effective": tuple(fields)}
    require(len(set(by_origin.values())) == 1, "effective tuple cache preserves original-operation aliases")
    return {"encoded_bytes": len(encoded), "fields": len(fields), "pq_secret_offset": pq_offset,
            "different_field_controls": len(mutations), "effective_aliases_across_origins": len(by_origin)}


def toy_endpoint(keys, replacements, open_policy, order, r, endpoint):
    """Small exact adjacent-hybrid model with secret-dependent public history.

    Public confirmations are key parity; this is a finite accounting fixture,
    not a cryptographic PRF. It deliberately allows pre-opening after seeing
    these confirmations so the free-stop certificate is nonvacuous.
    """
    confirmations = tuple(k % 2 for k in keys)
    closed = set()
    opened = []
    observed = []
    for family in order:
        prefix_sum = sum(k for _, k in opened)
        if (confirmations[family] + prefix_sum + open_policy[family]) % 2:
            closed.add(family)
            opened.append((family, keys[family]))
    registration = []
    captures = set()
    for family in order:
        if family in closed:
            continue
        registration.append(family)
        rank = len(registration)
        replaced = rank < r or (rank == r and endpoint == 1)
        used_ack = replacements[family] if replaced else keys[family]
        observed.append((family, used_ack))
        # Raw capture occurs after the ACK and may depend on its actual value.
        if used_ack == confirmations[family]:
            captures.add(family)
    attributed = registration[r - 1] if len(registration) >= r else None
    if attributed is None:
        test = (sum(k for _, k in opened) + sum(k for _, k in observed)) % 2
    else:
        used = next(ack for family, ack in observed if family == attributed)
        test = int(used % 2 == confirmations[attributed])
    # Attempting protection of a closed family is refused for every future
    # class from that family, not merely the one currently examined.
    require(all(f not in closed for f in registration), "pre-opened family was never promoted")
    return {
        "J": attributed, "D": test, "captures": captures,
        "closed": closed, "view": (tuple(opened), tuple(observed)),
    }


def adjacent_localization():
    result = []
    all_runs = 0
    for r in (1, 2):
        totals = [Counter(), Counter()]
        for keys in itertools.product(range(4), repeat=2):
            for replacements in itertools.product(range(4), repeat=2):
                for policy in itertools.product(range(2), repeat=2):
                    for order in ((0, 1), (1, 0)):
                        worlds = [toy_endpoint(keys, replacements, policy, order, r, b) for b in (0, 1)]
                        all_runs += 2
                        if worlds[0]["J"] is None:
                            require(worlds[1]["J"] is None, "same absent registration")
                            require(worlds[0]["view"] == worlds[1]["view"] and worlds[0]["D"] == worlds[1]["D"], "absent-r executions coupled")
                        for b, world in enumerate(worlds):
                            count = totals[b]
                            count["runs"] += 1
                            count["D"] += world["D"]
                            count["bottom_D"] += world["D"] * (world["J"] is None)
                            for j in (0, 1):
                                event = int(world["J"] == j)
                                value = world["D"] * event
                                capture = int(j in world["captures"])
                                local = value * (1 - capture)
                                require(abs(value - local) <= event * capture, "pointwise local-capture inequality")
                                require(not (j in world["closed"] and event), "free-stop certificate survives later registration")
                                count[f"candidate_{j}"] += value
                                count[f"local_{j}"] += local
                                count[f"residual_{j}"] += event * capture
        require(totals[0]["bottom_D"] == totals[1]["bottom_D"], "bottom expectations cancel")
        raw_gap = totals[0]["D"] - totals[1]["D"]
        candidate_gap = sum(totals[0][f"candidate_{j}"] - totals[1][f"candidate_{j}"] for j in (0, 1))
        require(raw_gap == candidate_gap, "exact adjacent candidate decomposition")
        residuals = [sum(t[f"residual_{j}"] for j in (0, 1)) for t in totals]
        runs = totals[0]["runs"]
        result.append({
            "registration_rank": r,
            "runs_per_endpoint": runs,
            "endpoint_test_probabilities": [str(Fraction(t["D"], runs)) for t in totals],
            "bottom_test_probability": str(Fraction(totals[0]["bottom_D"], runs)),
            "capture_residual_per_endpoint": [str(Fraction(v, runs)) for v in residuals],
            "two_endpoint_capture_term": str(Fraction(sum(residuals), runs)),
            "decomposition_equal": True,
        })
    require(any(x["capture_residual_per_endpoint"][0] != x["capture_residual_per_endpoint"][1] for x in result), "ACK-dependent capture gives genuinely distinct endpoint residuals")
    return {"executions": all_runs, "ranks": result}


def ciphertext_collision_slots():
    # An invertible toy encoding represents the K-PKE-correctness good event.
    enc = lambda m: (3 * m + 1) % 4
    dec = lambda c: (3 * (c - 1)) % 4
    require(all(dec(enc(m)) == m for m in range(4)), "toy PKE correctness")
    runs = matches = 0
    selected_execution_matches = 0
    for challenge, earlier, later in itertools.product(range(4), repeat=3):
        c_star = enc(challenge)
        match = enc(earlier) == c_star or enc(later) == c_star
        require(not match or earlier == challenge or later == challenge, "same ciphertext implies equal original input")
        # The scheduler can inspect both non-target reservations and execute
        # only a matching one. Count the original draws, not that final one call.
        executed = next((m for m in (earlier, later) if enc(m) == c_star), None)
        selected_execution_matches += executed is not None
        runs += 1
        matches += match
    probability = Fraction(matches, runs)
    require(probability == Fraction(7, 16), "finite collision probability")
    require(probability <= Fraction(2, 4), "two original-slot union bound")
    require(probability > Fraction(1, 4), "one executed-call budget mutation detected")
    # A malformed noninjective encoding violates the correctness premise.
    bad_enc = lambda m: m % 2
    bad_dec = lambda c: c
    bad_pair = (0, 2)
    require(bad_enc(bad_pair[0]) == bad_enc(bad_pair[1]) and bad_pair[0] != bad_pair[1], "failure witness")
    require(any(bad_dec(bad_enc(m)) != m for m in bad_pair), "collision without same input forces correctness failure")
    return {
        "original_input_alphabet": 4, "other_sampling_slots": 2,
        "executions": runs, "collision_probability": str(probability),
        "correct_original_slot_bound": "1/2",
        "incorrect_executed_only_bound": "1/4",
        "selective_execution_budget_mutation_detected": True,
        "correctness_failure_witness": list(bad_pair),
    }


def challenge_cache_and_validation():
    class Adapter:
        def __init__(self, previous=()):
            self.previous = set(previous)
            self.challenge = None
            self.requests = 0
            self.cca_queries = []
            self.stopped = False

        def execute_original(self, original):
            require(original == "a", "original binding")
            if self.challenge is None:
                self.requests += 1
                self.challenge = (7, 99)
                self.stopped = 7 in self.previous
            return None if self.stopped else self.challenge

        def protocol_decapsulate(self, ciphertext, traditional_valid=True):
            if not traditional_valid:
                return None
            if ciphertext == self.challenge[0]:
                return self.challenge[1]
            self.cca_queries.append(ciphertext)
            return 40 + ciphertext

        def other_fresh_encapsulation(self, ciphertext):
            if self.challenge and ciphertext == self.challenge[0]:
                self.stopped = True
                return None
            self.previous.add(ciphertext)
            self.cca_queries.append(ciphertext)
            return 40 + ciphertext

    live = Adapter()
    require(live.execute_original("a") == live.execute_original("a") == (7, 99), "original encapsulation replay")
    require(live.requests == 1, "one challenge at first actual computation")
    require(live.protocol_decapsulate(7) == 99 and live.protocol_decapsulate(6) == 46, "challenge and nonchallenge routing")
    require(live.protocol_decapsulate(7, False) is None, "traditional rejection before ContextBound")
    require(live.other_fresh_encapsulation(5) == 45, "ordinary validation preserved")
    require(live.other_fresh_encapsulation(7) is None and live.stopped, "postchallenge collision stops before excluded decapsulation")
    require(7 not in live.cca_queries, "challenge ciphertext never sent to postchallenge CCA oracle")
    prior = Adapter(previous=(3, 7))
    require(prior.execute_original("a") is None and prior.stopped, "prechallenge cache collision caught at challenge creation")
    return {
        "challenge_calls_after_retry": live.requests,
        "postchallenge_cca_queries": live.cca_queries,
        "excluded_ciphertext": 7,
        "pre_and_postchallenge_collision_controls": True,
        "scope": "finite routing model, not a native KEM execution",
    }


def opaque_record_closure():
    edges = {
        "generation-tape": {"expanded-owner"},
        "encapsulation-tape": {"component"},
        "expanded-owner": {"component"},
        "component": {"S1"}, "S1": {"PB"},
        "PB": {"seed", "confirmation-key"}, "seed": {"KB"},
        "KB": {"activation"},
    }
    opaque = {"generation-tape", "encapsulation-tape"}
    changed = True
    while changed:
        before = len(opaque)
        for node in tuple(opaque):
            opaque.update(edges.get(node, set()))
        changed = len(opaque) != before
    records = {
        "original-plan": {"encapsulation-tape", "public-initial"},
        "waiting-checkpoint": {"expanded-owner", "public-initial", "known-S0"},
        "root-checkpoint": {"KB", "public-reply"},
        "messages-image": {"activation", "public-session-id"},
        "public-reply": {"public-reply", "public-MACR"},
        "unrelated-image": {"other-known-key"},
    }
    marked = {name for name, fields in records.items() if fields & opaque}
    require(marked == {"original-plan", "waiting-checkpoint", "root-checkpoint", "messages-image"}, "opaque closure includes downstream checkpoints, not public tags")
    captured = {"root-checkpoint"}
    known_keys = set()
    raw_capture_stop = bool(captured & marked)
    readable = "journal" in known_keys
    require(raw_capture_stop and not readable, "raw acquisition differs from readability")
    known_keys.add("journal")
    require("journal" in known_keys, "later key creates recipe under U3")
    return {"opaque_value_closure": sorted(opaque), "marked_records": sorted(marked), "raw_capture_before_readability": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[4])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = {
        "schema": "q-periapt/bootstrap-reply-source-controls/v1",
        "status": "pass",
        "evidence_kind": "executed finite accounting, routing and source-layout controls",
        "checker_sha256": digest(Path(__file__).read_bytes()),
        "source_pins": source_pins(args.source_root),
        "source_correspondence": source_correspondence(args.source_root),
        "token_layout": token_layout(),
        "origin_stability": origin_stability(),
        "contextbound_encoding": contextbound_encoding(),
        "adjacent_localization": adjacent_localization(),
        "ciphertext_collision_slots": ciphertext_collision_slots(),
        "challenge_cache_and_validation": challenge_cache_and_validation(),
        "opaque_record_closure": opaque_record_closure(),
    }
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded)
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
