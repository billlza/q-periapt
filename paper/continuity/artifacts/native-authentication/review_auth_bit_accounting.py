#!/usr/bin/env python3
"""Finite controls for Boolean authentication-event composition.

These controls check bookkeeping identities and scope countermodels. They do
not execute a protocol or establish its cryptographic comparison bounds.
"""
from fractions import Fraction
from itertools import product
import json


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def main():
    checked = 0
    for eligible, attributed, bad, projection_mask, stop_mask in product(
        (False, True), (False, True), (False, True), range(4), range(4)
    ):
        indices = (0, 1) if attributed else (None,)
        for selected in indices:
            qualifiers = [eligible and attributed and selected == j for j in range(2)]
            free_stops = [bool(stop_mask & (1 << j)) for j in range(2)]
            if any(qualifiers[j] and free_stops[j] for j in range(2)):
                continue  # The definition of a free stop excludes this combination.
            charged = [bool(projection_mask & (1 << j)) for j in range(2)]
            local = [int(qualifiers[j] and bad and not charged[j] and not free_stops[j]) for j in range(2)]
            failure = int(eligible and bad)
            unattributed_failure = int(eligible and not attributed and bad)
            projected_failure = int(eligible and attributed and charged[selected] and bad) if attributed else 0
            require(failure == unattributed_failure + projected_failure + sum(local), "Boolean decomposition")
            residual_attr = int(eligible and not attributed)
            residual_proj = int(eligible and attributed and charged[selected]) if attributed else 0
            require(failure <= residual_attr + residual_proj + sum(local), "residual upper bound")
            checked += 1

    # Agreement on both confidentiality score events leaves unrelated bits free.
    real = [(Fraction(1, 2), +1, 1), (Fraction(1, 2), -1, 1)]
    ideal = [(Fraction(1, 2), +1, 0), (Fraction(1, 2), -1, 0)]
    event = lambda law, index, value: sum((p for p, *outcome in law if outcome[index] == value), Fraction(0))
    score_gaps = [abs(event(real, 0, sign) - event(ideal, 0, sign)) for sign in (-1, +1)]
    auth_gap = abs(event(real, 1, 1) - event(ideal, 1, 1))
    require(score_gaps == [0, 0] and auth_gap == 1, "event-distinguishers countermodel")

    joint_conditional = []
    for denominator in (2, 4, 16, 256):
        eligibility = Fraction(1, denominator)
        joint = eligibility
        conditional = joint / eligibility
        require(conditional == 1 and joint < conditional, "qualification countermodel")
        joint_conditional.append({"eligibility": str(eligibility), "joint_failure": str(joint), "conditional_failure": str(conditional)})

    gap_controls = []
    for numerator in range(9):
        epsilon = Fraction(numerator, 8)
        bit_gap = epsilon
        signed_gap = abs((2 * epsilon - 1) - (-1))
        require(signed_gap == 2 * bit_gap, "bit-versus-signed cost")
        gap_controls.append({"bit_gap": str(bit_gap), "signed_gap": str(signed_gap)})

    selected_bad = {"selected_root": False, "other_root": True}
    require(not selected_bad["selected_root"] and any(selected_bad.values()), "root scope countermodel")

    result = {
        "status": "passed",
        "scope": "Finite Boolean bookkeeping controls and explicit countermodels; no protocol, primitive or quantum execution.",
        "candidate_count": 2,
        "compatible_pointwise_assignments": checked,
        "old_score_event_gaps": [str(x) for x in score_gaps],
        "distinct_auth_event_gap": str(auth_gap),
        "qualification_countermodels": joint_conditional,
        "bit_signed_cost_controls": gap_controls,
        "other_root_failure_does_not_imply_selected_root_failure": True,
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
