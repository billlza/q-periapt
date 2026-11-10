#!/usr/bin/env python3
"""Independent finite controls for the signature-bridge argument.

These checks enumerate small classical distributions and explicit countermodels.
They do not execute ML-DSA or a quantum oracle and are not a formal proof.
"""

from collections import Counter
from fractions import Fraction
from itertools import product
from math import comb
import json


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def pair_collision_selection():
    # Five opened draws in a four-element randomizer space always contain a pair.
    histories = 0
    for draws in product(range(4), repeat=5):
        pair = next((i, j) for j in range(5) for i in range(j) if draws[i] == draws[j])
        require(draws[pair[0]] == draws[pair[1]], "selected slots differ")
        # Both executed slots share one effective input, hence one oracle query.
        require(len({draws[pair[0]], draws[pair[1]]}) == 1, "pair cache miss")
        histories += 1

    # A naive per-slot simulation instead calls a random-function wrapper twice.
    # Its hidden inputs agree with probability 1/4; otherwise the result bits
    # agree with probability 1/2. Enumerate this independently.
    equal = total = 0
    for table in product(range(2), repeat=4):
        for u, v in product(range(4), repeat=2):
            equal += table[u] == table[v]
            total += 1
    naive_equality = Fraction(equal, total)
    discrepancy = 1 - naive_equality
    incorrect_execute_only_charge = Fraction(comb(2, 2), 4)
    require(naive_equality == Fraction(5, 8), "wrong naive distribution")
    require(discrepancy > incorrect_execute_only_charge, "counterexample lost")
    return {
        "opened_draw_histories": histories,
        "correct_pair_cache_equality": "1",
        "naive_per_slot_equality": str(naive_equality),
        "naive_discrepancy": str(discrepancy),
        "invalid_execute_only_collision_charge": str(incorrect_execute_only_charge),
    }


def hidden_input_accounting():
    total = 4 ** 3
    repeated_all = repeated_by_descriptor = repeated_by_family = 0
    descriptors = ("x", "y", "x")
    families = (0, 1, 0)
    for draws in product(range(4), repeat=3):
        repeated_all += len(set(draws)) < 3
        repeated_by_descriptor += len(set(zip(draws, descriptors))) < 3
        repeated_by_family += len(set(zip(families, draws))) < 3
    require(Fraction(repeated_all, total) == Fraction(5, 8), "wrong full collision")
    require(Fraction(repeated_by_descriptor, total) == Fraction(1, 4), "descriptor accounting")
    require(Fraction(repeated_by_family, total) == Fraction(1, 4), "family accounting")
    require(Fraction(repeated_all, total) <= Fraction(comb(3, 2), 4), "birthday bound")
    return {
        "hidden_draw_histories": total,
        "all_same_descriptor_and_family": str(Fraction(repeated_all, total)),
        "descriptor_partitioned": str(Fraction(repeated_by_descriptor, total)),
        "family_partitioned": str(Fraction(repeated_by_family, total)),
    }


def descriptor_and_owner_controls():
    # Distinct raw messages may share a public descriptor. Raw-message freshness
    # still changes on every first private slot execution, including lost output.
    ledger = {"raw-a"}
    ordinary_queries = {"raw-a"}
    require("raw-b" not in ledger and "raw-b" not in ordinary_queries, "raw freshness")
    ledger.add("raw-b")  # first Execute(raw-b), even if the signature is cached/lost
    require("raw-b" in ledger and "raw-b" not in ordinary_queries, "alias ledger")
    require(ordinary_queries <= ledger, "oracle-message inclusion")

    # Exact declared key aliases share the family, while equal verification keys
    # alone do not identify a private PRF family.
    owner_to_family = {"owner-a": 0, "alias-a": 0, "owner-b": 1}
    pk = {0: "same-public-key", 1: "same-public-key"}
    private_outputs = {0: 0, 1: 1}
    correct = [private_outputs[owner_to_family[o]] for o in owner_to_family]
    merged_by_pk = [private_outputs[0] for _ in owner_to_family]
    require(correct == [0, 0, 1], "declared aliases")
    require(correct != merged_by_pk, "equal-pk countermodel lost")
    # The manuscript's actual-key ledger pools exact signing-state identities,
    # not all equal public keys. Independently coincident exact states may have
    # different generation lineages. The ideal success circuit uses the more
    # permissive lineage ledger and does not inspect the secret-state equality.
    lineage_ledgers = {0: {"raw-a", "raw-b"}, 1: {"raw-c"}, 2: {"raw-d"}}
    actual_state = {0: "state-a", 1: "state-b", 2: "state-a"}
    actual_ledgers = {
        state: set().union(*(lineage_ledgers[h] for h in lineage_ledgers if actual_state[h] == state))
        for state in set(actual_state.values())
    }
    checked_implications = 0
    for family in lineage_ledgers:
        require(lineage_ledgers[family] <= actual_ledgers[actual_state[family]], "actual-state inclusion")
        for message in ("raw-a", "raw-b", "raw-c", "raw-d", "fresh"):
            actual_fresh = message not in actual_ledgers[actual_state[family]]
            lineage_fresh = message not in lineage_ledgers[family]
            require(not actual_fresh or lineage_fresh, "freshness relaxation")
            checked_implications += 1
    require("raw-c" not in actual_ledgers["state-a"], "equal pk must not pool different actual states")
    require("raw-d" in actual_ledgers["state-a"], "coincident exact states must pool")
    return {
        "raw_ledger_updates_on_cached_execution": True,
        "ordinary_query_messages_are_ledger_subset": True,
        "declared_alias_outputs": correct,
        "incorrect_equal_pk_merge_outputs": merged_by_pk,
        "actual_state_freshness_is_distinct_from_equal_pk_pooling": True,
        "actual_state_freshness_implies_lineage_freshness_cases": checked_implications,
    }


def corruption_control():
    # A secure deterministic signature may append its random tape without
    # affecting EUF. This exposes the following consistency test after a foreign
    # owner reveals its PRF key: c == F_K(original visible r, descriptor).
    accepted = total = 0
    for table in product(range(2), repeat=4):
        for visible_r, hidden_u in product(range(4), repeat=2):
            accepted += table[visible_r] == table[hidden_u]
            total += 1
    simulated = Fraction(accepted, total)
    require(simulated == Fraction(5, 8), "corruption countermodel")
    require(simulated < 1, "foreign key exposure was accidentally simulated")
    return {
        "finite_assignments": total,
        "real_reservation_consistency": "1",
        "ordinary_oracle_substitution_consistency": str(simulated),
        "distinguishing_gap": str(1 - simulated),
        "required_resolution": "global stop, fixed target, or guessed-family lift",
    }


def shared_oracle_coupling_control():
    # Tiny prefix-consistent XOF: two keygen inputs return three bits; two hedge
    # inputs return two bits. The keygen prefix is (rho,K), and the hedge prefix
    # at input K is R. In both cases the old independent tail is retained.
    joint = Counter()
    cases = 0
    for g0, g1 in product(range(8), repeat=2):
        for f0, f1 in product(range(4), repeat=2):
            for xi, rho, key, random_function_bit in product(range(2), repeat=4):
                gs = [g0, g1]
                fs = [f0, f1]
                gs[xi] = (rho << 2) | (key << 1) | (gs[xi] & 1)
                fs[key] = (random_function_bit << 1) | (fs[key] & 1)
                require((gs[xi] >> 1) == ((rho << 1) | key), "keygen prefix")
                require((fs[key] >> 1) == random_function_bit, "hedge prefix")
                joint[(xi, *gs, *fs)] += 1
                cases += 1
    require(len(joint) == 2 * 8 * 8 * 4 * 4, "uniform oracle support")
    require(set(joint.values()) == {8}, "secret-selected slice biases the oracle")

    # Query address families have different lengths. For every fixed address,
    # averaging over independent xi,K gives at most 1/2 difference-set mass.
    addresses = [("keygen", 0), ("keygen", 1), ("hedge", 0), ("hedge", 1), ("other", 0)]
    masses = {}
    for family, value in addresses:
        hits = sum(
            (family == "keygen" and value == xi) or
            (family == "hedge" and value == key)
            for xi, key in product(range(2), repeat=2)
        )
        mass = Fraction(hits, 4)
        require(mass <= Fraction(1, 2), "disjoint-domain query mass")
        masses[f"{family}:{value}"] = str(mass)
    return {
        "coupling_assignments": cases,
        "joint_oracle_outcomes": len(joint),
        "multiplicity_per_outcome": 8,
        "fixed_address_average_difference_mass": masses,
        "quantum_execution_claimed": False,
    }


def unequal_cap_control():
    # Simulator-side public descriptor hashing can add an oracle call. A common
    # observable cap can therefore change completion even with perfect coupling.
    cap = 1
    reservation_calls = 1
    ordinary_simulation_calls = 2
    require(reservation_calls <= cap < ordinary_simulation_calls, "cap countermodel")
    return {
        "common_cap": cap,
        "reservation_calls": reservation_calls,
        "ordinary_simulation_calls": ordinary_simulation_calls,
        "same_cap_coupling_requires_extra_argument": True,
    }


if __name__ == "__main__":
    print(json.dumps({
        "status": "passed",
        "scope": "finite classical controls and countermodels; no native or quantum execution",
        "pair_collision_selection": pair_collision_selection(),
        "hidden_input_accounting": hidden_input_accounting(),
        "descriptor_owner_ledger": descriptor_and_owner_controls(),
        "foreign_corruption": corruption_control(),
        "shared_oracle_coupling": shared_oracle_coupling_control(),
        "unequal_global_cap": unequal_cap_control(),
    }, indent=2, sort_keys=True))
