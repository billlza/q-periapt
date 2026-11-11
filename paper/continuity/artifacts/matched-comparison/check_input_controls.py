#!/usr/bin/env python3
"""Directed incorrect-report controls for the manuscript projection."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path


SOURCE = Path(__file__).resolve().with_name("analyze_matched.py")
if not SOURCE.is_file() or SOURCE.is_symlink():
    raise ValueError("invalid manuscript analysis source")
SPEC = importlib.util.spec_from_file_location("matched_analysis", SOURCE)
if SPEC is None or SPEC.loader is None:
    raise ValueError("manuscript analysis source has no loader")
ANALYSIS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ANALYSIS)
analyze, decode = ANALYSIS.analyze, ANALYSIS.decode
read_sources, require = ANALYSIS.read_sources, ANALYSIS.require


def main() -> None:
    original = read_sources()["report"]
    require(len(analyze(original)) == 49, "unchanged report failed")
    controls = []

    def reject(label, mutate):
        candidate = copy.deepcopy(original)
        mutate(candidate)
        try:
            analyze(candidate)
        except (ValueError, TypeError, KeyError) as error:
            controls.append({"control": label, "status": "rejected", "reason": str(error)})
        else:
            raise ValueError("incorrect report accepted: " + label)

    reject("missing schedule", lambda d: d["rows"].pop())
    reject("duplicated profile/schedule", lambda d: d["rows"].append(copy.deepcopy(d["rows"][0])))
    reject("total instead of post-capture denominator",
           lambda d: d["rows"][0]["exposure"][0].update(admitted_after_capture=688))
    reject("duplicate derived request",
           lambda d: d["rows"][0]["exposure"][0]["derived_requests"].append(63))
    reject("pre-capture request counted as exposed",
           lambda d: d["rows"][0]["exposure"][0]["derived_requests"].insert(0, 0))
    reject("capture owners exchanged", lambda d: d["rows"][0]["exposure"].reverse())
    reject("uncommitted demand silently removed",
           lambda d: d["rows"][0]["application"].update(uncommitted=[0, 0]))
    reject("free retry transmission", lambda d: d["rows"][0]["frame_counts"].update(retry=0))
    reject("boolean count accepted as integer",
           lambda d: d["rows"][0]["frame_counts"].update(retry=True))
    reject("reference physical persistence fabricated",
           lambda d: d["rows"][14]["persistence"].update(physical_sync_data=[0, 0]))
    reject("reference payload envelope omitted from bytes",
           lambda d: d["rows"][14]["transport"].update(emitted_bytes=d["rows"][14]["component_bytes"]))
    reject("one-way suspension relabeled as recovery",
           lambda d: d["rows"][6].update(final_confirmed_epochs=[1, 1]))
    for label, raw in (("duplicate JSON key", '{"rows": [], "rows": []}'),
                       ("non-finite JSON", '{"value": NaN}')):
        try:
            decode(raw)
        except ValueError as error:
            controls.append({"control": label, "status": "rejected", "reason": str(error)})
        else:
            raise ValueError("incorrect JSON accepted: " + label)
    print(json.dumps({"schema": 1, "status": "passed", "positive_report_rows": 49,
                      "negative_controls": len(controls), "controls": controls}, indent=2))


if __name__ == "__main__":
    main()
