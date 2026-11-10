#!/usr/bin/env python3
"""Reproduce the schedule comparison from the retained reference corpora."""
from __future__ import annotations

import argparse
from decimal import Decimal, ROUND_HALF_EVEN
import hashlib
import json
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SOURCE_COMMIT = "228c944fc476e3e57d6c08063cacb19bca5b360e"
PINS = {
    "spqr32-traces.json": "2df62d39ffcd2cd0cd3365eb3648532791b009da8c8713eb170196985fed639b",
    "spqr32-snapshots.json": "572dc536d61ae23ed4aa367b1b62a3cd2e164c491e60880e766f67e49422d033",
    "spqr64-corpus.json": "aee184c8415594d58692ee2d63419f741a703aaacfbfff69a6471e68fd19250e",
    "whole-kem-corpus.json": "dd01c8d7a39f9c0486079b9b5b313248bd709badfa333f6ca24d1406d940de88",
}
SCHEDULES = {
    "ping_pong": "Alternating",
    "lossy": "Loss",
    "reordered": "Reordering",
    "duplicates": "Duplication",
    "asymmetric": "9:1",
    "offline_then_exchange": "Offline then exchange",
    "one_way": "One-way",
}
PROFILES = ("spqr32", "spqr64", "whole1", "whole32", "whole64")
CUTS = (0, 1, 7, 63, 255, 1023)
SENDS = 2048


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant: {value}")


def read_sources() -> dict[str, Any]:
    result = {}
    for name, expected in PINS.items():
        path = HERE / "sources" / name
        require(path.is_file() and not path.is_symlink(), f"invalid corpus file: {name}")
        raw = path.read_bytes()
        require(hashlib.sha256(raw).hexdigest() == expected, f"corpus identity changed: {name}")
        result[name] = json.loads(raw, object_pairs_hook=unique_object,
                                  parse_constant=reject_constant)
    return result


def indexed(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result = {}
    for row in rows:
        name = row["scenario"]
        require(name in SCHEDULES and name not in result, "duplicate or unknown schedule")
        result[name] = row
    require(set(result) == set(SCHEDULES), "incomplete schedule set")
    return result


def nonnegative_int(value: Any, label: str) -> int:
    require(type(value) is int and value >= 0, f"invalid count: {label}")
    return value


def analyze(data: dict[str, Any]) -> dict[str, Any]:
    chunk = data["spqr64-corpus.json"]
    require(chunk["profile"] == "experimental_chunk64", "wrong SPQR variant")
    whole = data["whole-kem-corpus.json"]["profiles"]
    require([row["profile"] for row in whole] == [1, 32, 64], "wrong whole-KEM profiles")
    entries = [
        ("spqr32", data["spqr32-traces.json"]["traces"],
         data["spqr32-snapshots.json"]["traces"], "predicted", "predicted_from_pending_epoch"),
        ("spqr64", chunk["result"]["verified_public_traces"],
         chunk["result"]["verified_snapshot_experiments"], "predicted", "predicted_from_pending_epoch"),
    ]
    entries += [(f"whole{p['profile']}", p["traces"], p["snapshots"],
                 "derived", "derived_from_pending_epoch") for p in whole]
    rows = []
    all_cases = []
    for profile, traces_raw, snapshots_raw, derived_name, pending_name in entries:
        traces, snapshots = indexed(traces_raw), indexed(snapshots_raw)
        for scenario in SCHEDULES:
            summary = traces[scenario]["summary"]
            require(summary["scenario"] == scenario, "summary schedule differs")
            require(summary["sent"] == summary["unique_message_keys"] == SENDS,
                    "send/key inventory differs")
            expected_drops = 205 if scenario == "lossy" else 0
            expected_duplicates = 158 if scenario == "duplicates" else 0
            require(summary["dropped"] == expected_drops
                    and summary["delivered"] == SENDS - expected_drops
                    and summary["duplicates_rejected"] == expected_duplicates,
                    "communication opportunities differ")
            wire = nonnegative_int(summary["wire_bytes"], "wire_bytes")
            peak = nonnegative_int(summary["peak_wire_bytes"], "peak_wire_bytes")
            cases = {}
            for case in snapshots[scenario]["cases"]:
                cut, owner = case["cut_before_send"], case["owner"]
                require(type(cut) is int and cut in CUTS
                        and type(owner) is int and owner in (0, 1), "unknown snapshot coordinate")
                require((cut, owner) not in cases, "duplicate snapshot coordinate")
                derived = nonnegative_int(case[derived_name], "derived")
                not_derived = nonnegative_int(case["not_derived"], "not_derived")
                pending = nonnegative_int(case[pending_name], "pending")
                require(derived + not_derived == SENDS - cut, "snapshot accounting differs")
                require(pending <= derived, "pending contribution exceeds derived set")
                normalized = {"profile": profile, "scenario": scenario,
                              "cut_before_send": cut, "owner": owner,
                              "derived": derived, "not_derived": not_derived,
                              "derived_from_pending_epoch": pending}
                cases[cut, owner] = normalized
                all_cases.append(normalized)
            require(set(cases) == {(c, o) for c in CUTS for o in (0, 1)},
                    "incomplete snapshot inventory")
            chosen = cases[1, 0]
            mean = (Decimal(wire) / SENDS).quantize(Decimal("0.001"), rounding=ROUND_HALF_EVEN)
            rows.append({"profile": profile, "scenario": scenario,
                         "wire_bytes": wire, "sent": SENDS,
                         "mean_bytes_per_send": str(mean), "peak_wire_bytes": peak,
                         "derived": chosen["derived"],
                         "derived_from_pending_epoch": chosen["derived_from_pending_epoch"],
                         "not_derived": chosen["not_derived"]})
    require(len(rows) == 35 and len(all_cases) == 420, "configuration inventory differs")
    return {"schema": 1, "source_commit": SOURCE_COMMIT, "source_sha256": PINS,
            "configuration_schedule_pairs": len(rows), "validated_snapshot_cases": len(all_cases),
            "selected_snapshot": {"owner": "A", "owner_index": 0, "cut_before_send": 1,
                                  "future_sends": 2047},
            "scope": "Deterministic reanalysis of recorded component executions; the selected predictor's exact derived counts and component wire bytes.",
            "rows": rows, "all_snapshot_cases": all_cases}


def table(result: dict[str, Any]) -> str:
    by_coordinate = {(r["profile"], r["scenario"]): r for r in result["rows"]}
    lines = [r"% Generated by artifacts/reference-comparison/analyze_reference.py.",
             r"\begin{table}[t]", r"\centering", r"\small",
             r"\setlength{\tabcolsep}{4pt}", r"\begin{tabular}{@{}lrrrrr@{}}",
             r"\toprule", r"Schedule & SPQR 32 & SPQR 64 & KEM 1 & KEM 32 & KEM 64\\",
             r"\midrule", r"\multicolumn{6}{l}{Reconstructed keys among 2,047 future sends}\\"]
    for scenario, label in SCHEDULES.items():
        values = [str(by_coordinate[p, scenario]["derived"]) for p in PROFILES]
        lines.append(label + " & " + " & ".join(values) + r"\\")
    lines += [r"\midrule", r"\multicolumn{6}{l}{Mean component bytes per send}\\"]
    for scenario, label in SCHEDULES.items():
        values = [by_coordinate[p, scenario]["mean_bytes_per_send"] for p in PROFILES]
        lines.append(label + " & " + " & ".join(values) + r"\\")
    lines += [r"\bottomrule", r"\end{tabular}",
              r"\caption{The seven retained schedules at the same snapshot coordinate: endpoint $A$ immediately after its first send. SPQR 32 and 64 identify polynomial-chunk widths in bytes; KEM 1, 32 and 64 identify whole-KEM local-send intervals. Each column uses its recorded construction, authentication graph and retained-state interface. Bytes cover the component wire; reconstructed keys are exact predictor matches.}",
              r"\label{tab:reference-schedules}", r"\end{table}", ""]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="verify the committed deterministic outputs")
    args = parser.parse_args()
    result = analyze(read_sources())
    outputs = {HERE / "analysis.json": json.dumps(result, indent=2) + "\n",
               HERE.parents[1] / "reference-schedule-table.tex": table(result)}
    for path, expected in outputs.items():
        if args.check:
            require(path.read_text() == expected, f"generated output differs: {path.name}")
        else:
            path.write_text(expected)
    print(json.dumps({"status": "passed", "source_files": len(PINS),
                      "configuration_schedule_pairs": 35, "validated_snapshot_cases": 420,
                      "selected_rows": 35, "mode": "check" if args.check else "generate"}))


if __name__ == "__main__":
    main()
