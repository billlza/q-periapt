#!/usr/bin/env python3
"""Independent recalculation and failure controls for retained reference data."""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile


SOURCE_COMMIT = "228c944fc476e3e57d6c08063cacb19bca5b360e"
CURRENT_COMMIT = "358b921ab3469ce49f166633fc9a762ff6ed7e3d"
PROFILE_ORDER = ("spqr32", "spqr64", "whole1", "whole32", "whole64")
SCHEDULES = (
    ("ping_pong", "Alternating"),
    ("lossy", "Loss"),
    ("reordered", "Reordering"),
    ("duplicates", "Duplication"),
    ("asymmetric", "9:1"),
    ("offline_then_exchange", "Offline then exchange"),
    ("one_way", "One-way"),
)
EXPECTED_COORDINATES = {(cut, owner) for cut in (0, 1, 7, 63, 255, 1023) for owner in (0, 1)}


def check(ok: bool, reason: str) -> None:
    if not ok:
        raise RuntimeError(reason)


def integer_round_millibytes(wire: int) -> str:
    quotient, remainder = divmod(wire * 1000, 2048)
    if remainder * 2 > 2048 or (remainder * 2 == 2048 and quotient % 2):
        quotient += 1
    return f"{quotient // 1000}.{quotient % 1000:03d}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = args.artifact_root
    manifest = json.loads((root / "source_identity.json").read_text())
    check(manifest["source_commit"] == SOURCE_COMMIT, "unexpected source commit")
    check(manifest["observed_integration_commit"] == CURRENT_COMMIT, "unexpected integration commit")
    corpus = {}
    identities = []
    for name, identity in manifest["files"].items():
        raw = (root / "sources" / name).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        blob = hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
        check(len(raw) == identity["bytes"], f"file length differs: {name}")
        check(digest == identity["sha256"], f"SHA256 differs: {name}")
        check(blob == identity["git_blob"], f"Git blob differs: {name}")
        for revision in (SOURCE_COMMIT, CURRENT_COMMIT):
            record = subprocess.run(
                ["git", "ls-tree", revision, "--", identity["repository_path"]],
                cwd=args.repository, capture_output=True, text=True, check=True,
            ).stdout.strip()
            check(bool(record) and record.split()[2] == blob,
                  f"repository tree differs at {revision}: {name}")
        identities.append({"name": name, "bytes": len(raw), "sha256": digest, "git_blob": blob})
        corpus[name] = json.loads(raw)
    check(len(identities) == 4, "source file count")

    packet = corpus["spqr64-corpus.json"]["result"]
    groups = [
        ("spqr32", corpus["spqr32-traces.json"]["traces"], corpus["spqr32-snapshots.json"]["traces"], "predicted", "predicted_from_pending_epoch"),
        ("spqr64", packet["verified_public_traces"], packet["verified_snapshot_experiments"], "predicted", "predicted_from_pending_epoch"),
    ]
    for group in corpus["whole-kem-corpus.json"]["profiles"]:
        groups.append((f"whole{group['profile']}", group["traces"], group["snapshots"], "derived", "derived_from_pending_epoch"))
    check(tuple(row[0] for row in groups) == PROFILE_ORDER, "profile inventory")
    expected_rows, expected_cases = {}, {}
    for profile, traces, snapshots, key, pending_key in groups:
        check(len(traces) == len(snapshots) == 7, "schedule cardinality")
        trace_map = {row["scenario"]: row["summary"] for row in traces}
        capture_map = {row["scenario"]: row["cases"] for row in snapshots}
        check(set(trace_map) == set(capture_map) == {s for s, _ in SCHEDULES}, "schedule inventory")
        for scenario, _ in SCHEDULES:
            summary = trace_map[scenario]
            check(summary["scenario"] == scenario, "summary schedule mismatch")
            check(summary["sent"] == summary["unique_message_keys"] == 2048, "send inventory")
            check(summary["dropped"] == (205 if scenario == "lossy" else 0), "drop inventory")
            check(summary["delivered"] == 2048 - summary["dropped"], "delivery inventory")
            check(summary["duplicates_rejected"] == (158 if scenario == "duplicates" else 0), "duplicate inventory")
            cases = capture_map[scenario]
            check(len(cases) == 12, "capture cardinality")
            coords = [(case["cut_before_send"], case["owner"]) for case in cases]
            check(len(set(coords)) == 12 and set(coords) == EXPECTED_COORDINATES, "capture coordinates")
            for case in cases:
                cut, owner = case["cut_before_send"], case["owner"]
                check(case[key] + case["not_derived"] == 2048 - cut, "future-send partition")
                check(0 <= case[pending_key] <= case[key], "pending subset")
                expected_cases[profile, scenario, cut, owner] = (case[key], case["not_derived"], case[pending_key])
            selected = next(case for case in cases if case["cut_before_send"] == 1 and case["owner"] == 0)
            expected_rows[profile, scenario] = (
                selected[key], integer_round_millibytes(summary["wire_bytes"]),
                summary["wire_bytes"], summary["peak_wire_bytes"],
                selected[pending_key], selected["not_derived"],
            )

    analysis = json.loads((root / "analysis.json").read_text())
    check(analysis["configuration_schedule_pairs"] == 35, "derived row cardinality")
    check(analysis["validated_snapshot_cases"] == 420, "derived capture cardinality")
    check(len(analysis["rows"]) == 35 and len(analysis["all_snapshot_cases"]) == 420, "output cardinality")
    observed_rows = {}
    for row in analysis["rows"]:
        coordinate = row["profile"], row["scenario"]
        check(coordinate not in observed_rows, "duplicate output row")
        observed_rows[coordinate] = (
            row["derived"], row["mean_bytes_per_send"], row["wire_bytes"],
            row["peak_wire_bytes"], row["derived_from_pending_epoch"], row["not_derived"],
        )
        check(row["sent"] == 2048, "output sent count")
    check(observed_rows == expected_rows, "independent scalar recalculation disagrees")
    observed_cases = {}
    for row in analysis["all_snapshot_cases"]:
        coordinate = row["profile"], row["scenario"], row["cut_before_send"], row["owner"]
        check(coordinate not in observed_cases, "duplicate output snapshot")
        observed_cases[coordinate] = row["derived"], row["not_derived"], row["derived_from_pending_epoch"]
    check(observed_cases == expected_cases, "independent full snapshot mapping disagrees")

    tex_path = root.parents[1] / "reference-schedule-table.tex"
    tex = tex_path.read_text()
    display_rows = []
    for line in tex.splitlines():
        if any(line.startswith(label + " & ") for _, label in SCHEDULES):
            fields = [field.strip() for field in line[:-2].split("&")]
            display_rows.append(fields)
    check(len(display_rows) == 14, "display row count")
    for offset, scalar in ((0, 0), (7, 1)):
        for index, (scenario, label) in enumerate(SCHEDULES):
            expected = [label] + [str(expected_rows[profile, scenario][scalar]) for profile in PROFILE_ORDER]
            check(display_rows[offset + index] == expected, f"table value mismatch: {scenario} scalar {scalar}")

    spec = importlib.util.spec_from_file_location("reviewed_reference_analyzer", root / "analyze_reference.py")
    check(spec is not None and spec.loader is not None, "unable to import analyzer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    controls = []

    def rejects(label, mutate):
        changed = copy.deepcopy(corpus)
        mutate(changed)
        try:
            module.analyze(changed)
        except ValueError as error:
            controls.append({"name": label, "rejected": True, "reason": str(error)})
        else:
            raise RuntimeError(f"negative control accepted: {label}")

    def cases(d):
        return d["spqr32-snapshots.json"]["traces"][0]["cases"]

    rejects("duplicate snapshot coordinate", lambda d: cases(d).append(copy.deepcopy(cases(d)[0])))
    rejects("missing snapshot coordinate", lambda d: cases(d).pop())
    rejects("altered derived count", lambda d: cases(d)[2].__setitem__("predicted", cases(d)[2]["predicted"] + 1))
    rejects("unknown schedule", lambda d: d["spqr32-traces.json"]["traces"][0].__setitem__("scenario", "unexpected"))
    rejects("wrong summary schedule", lambda d: d["spqr32-traces.json"]["traces"][0]["summary"].__setitem__("scenario", "lossy"))
    rejects("wrong communication opportunities", lambda d: d["spqr32-traces.json"]["traces"][0]["summary"].__setitem__("delivered", 2047))
    rejects("Boolean snapshot owner", lambda d: cases(d)[0].__setitem__("owner", False))

    # This mutation preserves internal arithmetic; the immutable byte pin must reject it.
    with tempfile.TemporaryDirectory(prefix="reference-byte-control-") as directory:
        stage = Path(directory)
        (stage / "sources").mkdir()
        for name in corpus:
            (stage / "sources" / name).write_bytes((root / "sources" / name).read_bytes())
        changed = copy.deepcopy(corpus["spqr32-snapshots.json"])
        selected = changed["traces"][0]["cases"][2]
        selected["predicted"] += 1
        selected["not_derived"] -= 1
        (stage / "sources" / "spqr32-snapshots.json").write_text(json.dumps(changed))
        old_here = module.HERE
        module.HERE = stage
        try:
            try:
                module.read_sources()
            except ValueError as error:
                controls.append({"name": "balanced count change rejected by source pin", "rejected": True, "reason": str(error)})
            else:
                raise RuntimeError("balanced source mutation bypassed the byte pin")
        finally:
            module.HERE = old_here

    out = {
        "status": "passed", "scope": "Independent recalculation of fixed retained results; no new native cryptographic execution.",
        "source_commit": SOURCE_COMMIT, "observed_integration_commit": CURRENT_COMMIT,
        "source_identities": identities, "scenario_profile_pairs": 35, "snapshot_cases": 420,
        "displayed_numeric_cells": 70, "mean_rounding": "independent integer division with nearest-ties-to-even at 0.001 byte",
        "negative_controls": controls,
        "reviewed_files": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in (
            ("analyze_reference.py", root / "analyze_reference.py"),
            ("analysis.json", root / "analysis.json"),
            ("source_identity.json", root / "source_identity.json"),
            ("reference-schedule-table.tex", tex_path),
        )},
    }
    if args.output:
        args.output.write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
