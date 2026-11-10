#!/usr/bin/env python3
"""Independent expected-result checks for the guarded-origin model.

This file leaves the reviewed checker unchanged. Expectations are stated
explicitly for selected graph shapes; agreement of the two algorithms alone
is not accepted as the oracle. No cryptographic security assertion is made.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path


BASE = Path(__file__).resolve().parent
SOURCE = BASE / "check_exposure.py"
spec = importlib.util.spec_from_file_location("reviewed_exposure_model", SOURCE)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
Model, Record, History = module.Model, module.Record, module.History

results = []


def expect_case(name, model, acquired, keys, expected, direct=None, expected_keys=None):
    direct = set() if direct is None else set(direct)
    forward, available, derived_keys = model.forward(set(acquired), set(keys), direct)
    normalized, witnesses = model.normalized(set(acquired), set(keys), direct)
    if forward != set(expected) or normalized != set(expected):
        raise RuntimeError(f"{name}: expected={expected}, forward={forward}, normalized={normalized}")
    if expected_keys is not None and derived_keys != set(expected_keys):
        raise RuntimeError(f"{name}: expected keys={expected_keys}, observed={derived_keys}")
    results.append({"case": name, "expected": sorted(expected), "forward": sorted(forward),
                    "normalized": sorted(normalized), "derived_keys": sorted(derived_keys),
                    "witnesses": witnesses, "status": "passed"})


cycle = Model([Record("inner", "a", origins=("o",)), Record("image", "b", ("inner",))],
              (("a", "b"), ("b", "a")))
expect_case("unseeded_key_cycle_stays_unknown", cycle, {"image"}, set(), set(), expected_keys=set())
expect_case("either_cycle_seed_enables_both_guards_a", cycle, {"image"}, {"a"}, {"o"}, expected_keys={"a", "b"})
expect_case("either_cycle_seed_enables_both_guards_b", cycle, {"image"}, {"b"}, {"o"}, expected_keys={"a", "b"})
expect_case("direct_source_does_not_backderive_key", cycle, set(), set(), {"o"}, direct={"o"}, expected_keys=set())

self_loop = Model([Record("token", "a", origins=("o",))], (("a", "a"),))
expect_case("unseeded_self_loop_stays_unknown", self_loop, {"token"}, set(), set(), expected_keys=set())
expect_case("seeded_self_loop_terminates", self_loop, {"token"}, {"a"}, {"o"}, expected_keys={"a"})

chain = Model([Record("token", "c", origins=("o",))], (("b", "c"), ("a", "b")))
expect_case("reverse_ordered_key_edges_reach_fixpoint", chain, {"token"}, {"a"}, {"o"}, expected_keys={"a", "b", "c"})

diamond = Model([
    Record("leaf", "leaf-key", origins=("o",)),
    Record("left", "left-key", ("leaf",)),
    Record("right", "right-key", ("leaf",)),
    Record("outer", "outer-key", ("left", "right")),
])
expect_case("diamond_left_route_suffices", diamond, {"outer"}, {"outer-key", "left-key", "leaf-key"}, {"o"})
expect_case("diamond_right_route_suffices", diamond, {"outer"}, {"outer-key", "right-key", "leaf-key"}, {"o"})
expect_case("diamond_all_outer_guards_without_leaf_key_fail", diamond, {"outer"}, {"outer-key", "left-key", "right-key"}, set())
expect_case("diamond_shared_leaf_does_not_remove_branch_guard", diamond, {"outer"}, {"outer-key", "leaf-key"}, set())
expect_case("direct_leaf_capture_has_only_leaf_guard", diamond, {"leaf"}, {"leaf-key"}, {"o"})

two_routes = Model([
    Record("left-token", "b", origins=("o",)), Record("left-image", "a", ("left-token",)),
    Record("right-token", "d", origins=("o",)), Record("right-image", "c", ("right-token",)),
])
expect_case("partial_keys_from_distinct_routes_cannot_be_spliced", two_routes,
            {"left-image", "right-image"}, {"a", "d"}, set())
expect_case("one_completed_route_survives_other_partial_route", two_routes,
            {"left-image", "right-image"}, {"a", "b", "d"}, {"o"})

history_model = Model([Record("token", "wrap", origins=("o",)), Record("image", "journal", ("token",))],
                      (("journal", "wrap"),))
for name, events, expected_prefixes in [
    ("deleted_standalone_token_remains_inside_live_immutable_image",
     [("delete_local", "token"), ("acquire", "image"), ("disclose_key", "journal")],
     [set(), set(), {"o"}]),
    ("captured_image_survives_deletion_of_both_local_objects",
     [("acquire", "image"), ("delete_local", "token"), ("delete_local", "image"), ("disclose_key", "journal")],
     [set(), set(), set(), {"o"}]),
]:
    history = History(history_model)
    observed = []
    for event, expected in zip(events, expected_prefixes, strict=True):
        result = history.step(*event)
        if result != expected:
            raise RuntimeError(f"{name}: event={event}, expected={expected}, observed={result}")
        observed.append(sorted(result))
    results.append({"case": name, "events": events, "expected_prefixes": [sorted(x) for x in expected_prefixes],
                    "observed_prefixes": observed, "status": "passed"})

try:
    Model([Record("self", "k", ("self",), ("o",))])
except ValueError as error:
    if str(error) != "cyclic record containment":
        raise
    results.append({"case": "record_self_containment_rejected", "expected_error": "cyclic record containment",
                    "observed_error": str(error), "status": "passed"})
else:
    raise RuntimeError("self-containment was admitted")

result = {
    "scope": "independent expected-result checks of finite typed derivability; no native or computational-security claim",
    "status": "passed",
    "reviewed_checker_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
    "review_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    "cases": results,
    "count": len(results),
}
(BASE / "review_results.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps({"status": result["status"], "count": result["count"],
                  "reviewed_checker_sha256": result["reviewed_checker_sha256"]}))
