#!/usr/bin/env python3
"""Regenerate the manuscript tables from the hash-bound executed report."""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
PROTOCOL_SOURCE = "358b921ab3469ce49f166633fc9a762ff6ed7e3d"
REPORT_SHA256 = "66d854b5c720a614008bef27593834a395ac41e1766510b28901507f3ba60f6b"
PINS = {
    "matched-report.json.gz": "9e8a34beb079f78fa3d89dfd7d6c6d3026d97c5322c5b0b87609829cbf611d68",
    "results-49.json": "588fd79e8b3fa0d1681bd56dd93162a8f64d20c86c1303e29faf58f1333a0be4",
    "results-49.csv": "19bdb09b98cb4817da4efc7cfada4f081185d2ccdac1d09f8406324ad2a234b6",
    "qualification.json": "956640c95443206e0a1b4c9b663e498ee8c1281be6801d134abde4951648ed6a",
    "public-evidence-audit.json": "e94fb222ceb5f1831a3d300c400d6ac014969741974890510f6da85b3efdaba5",
    "public-manifest.json": "d7602eab190e9b1cd7c48dcce2788f5d0f777af4f303a113c452656d60f45dc1",
    "executables.json": "5fdabca0a7d7eca9e0ab3667024aad447b6392fc97ee8967f12a0469570e77a5",
    "runtime.json": "200105389e589cd985648c00853f6f4bed951cc55ed1c05200eae9a42a6edbc2",
    "variant-preparation.json": "a41489dd437dd306389352d2968d5ebf4a79918871d86e4325095e756a038983",
    "schedule.py.txt": "1d3b361c6d99b0e28c2b0044c99287835f4eba41e9163c0fda2614e954b23b18",
    "validate.py.txt": "80a2eed73944decaa8edde69db1b3523a12475930dd5e4da4821ca52add636bc",
}
PROFILES = ("continuity-32", "continuity-64", "spqr-32", "spqr-64",
            "whole-kem-1", "whole-kem-32", "whole-kem-64")
SCENARIOS = ("alternating", "lossy", "reordered", "duplicates", "asymmetric",
             "offline_then_exchange", "one_way")
LABELS = ("Continuity, $b=32$", "Continuity, $b=64$", "SPQR, chunk 32",
          "SPQR, chunk 64", "Whole KEM, interval 1", "Whole KEM, interval 32",
          "Whole KEM, interval 64")
OPPORTUNITIES = 2048


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


def decode(raw: bytes | str) -> Any:
    return json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)


def count(value: Any, label: str) -> int:
    require(type(value) is int and 0 <= value <= 2**64 - 1, f"invalid count: {label}")
    return value


def pair(value: Any, label: str) -> list[int]:
    require(type(value) is list and len(value) == 2, f"invalid pair: {label}")
    return [count(x, label) for x in value]


def identifiers(value: Any, label: str) -> set[int]:
    require(type(value) is list, f"invalid request set: {label}")
    values = [count(x, label) for x in value]
    require(values == sorted(set(values)) and all(0 < x < OPPORTUNITIES for x in values),
            f"unordered, repeated or pre-capture request: {label}")
    return set(values)


def read_sources() -> dict[str, Any]:
    result = {}
    for name, expected in PINS.items():
        path = HERE / "sources" / name
        require(path.is_file() and not path.is_symlink(), f"invalid source file: {name}")
        raw = path.read_bytes()
        require(hashlib.sha256(raw).hexdigest() == expected, f"source identity changed: {name}")
        if name == "matched-report.json.gz":
            raw = gzip.decompress(raw)
            require(hashlib.sha256(raw).hexdigest() == REPORT_SHA256, "original report identity changed")
            result["report"] = decode(raw)
        elif name.endswith(".json"):
            result[name] = decode(raw)
        else:
            result[name] = raw
    return result


def analyze(report: dict[str, Any]) -> list[dict[str, Any]]:
    require(report["status"] == "passed" and report["execution"] == "native_compiled_and_executed",
            "incomplete executed report")
    require(report["base_commit"] == PROTOCOL_SOURCE, "protocol source differs")
    schedule = report["schedule"]
    require(schedule["kind"] == "matched_directed_opportunities"
            and schedule["capture_before_opportunity"] == 1
            and schedule["payload_bytes"] == 32 and schedule["frame_cap_bytes"] == 8192,
            "common experiment contract differs")
    require(set(schedule["scenarios"]) == set(SCENARIOS), "schedule inventory differs")
    by = {}
    for row in report["rows"]:
        key = row["profile"], row["scenario"]
        require(key not in by, "duplicate profile/schedule coordinate")
        by[key] = row
    require(set(by) == {(p, s) for p in PROFILES for s in SCENARIOS}, "incomplete report inventory")
    output = []
    for profile in PROFILES:
        for scenario in SCENARIOS:
            row = by[profile, scenario]
            native = profile.startswith("continuity-")
            application, exposures, persistence = row["application"], row["exposure"], row["persistence"]
            offered = pair(application["offered"], "offered")
            committed = pair(application["committed"], "committed")
            delivered = pair(application["delivered_by_sender"], "delivered")
            uncommitted = pair(application["uncommitted"], "uncommitted")
            require(sum(offered) == OPPORTUNITIES
                    and offered == pair(schedule["scenarios"][scenario]["owners"], "schedule owners"),
                    "offered opportunity accounting differs")
            require(all(offered[i] == committed[i] + uncommitted[i]
                        and delivered[i] <= committed[i] for i in (0, 1)), "application partition differs")
            require(len(exposures) == 2 and [e["owner"] for e in exposures] == [0, 1],
                    "capture owner inventory differs")
            post_capture = sum(committed) - 1
            future_sets = []
            for exposure in exposures:
                require(count(exposure["capture_before_opportunity"], "capture") == 1
                        and count(exposure["admitted_after_capture"], "denominator") == post_capture,
                        "capture denominator differs")
                derived = identifiers(exposure["derived_requests"], "derived")
                unknown = identifiers(exposure["not_derived_requests"], "predictor remainder")
                delivered_derived = identifiers(exposure["derived_delivered_requests"], "derived delivery")
                require(not derived & unknown and len(derived | unknown) == post_capture
                        and delivered_derived <= derived, "exposure partition differs")
                require(exposure["derived_fraction_of_admitted"] == len(derived) / post_capture,
                        "derived fraction differs")
                future_sets.append(derived | unknown)
            require(future_sets[0] == future_sets[1], "capture experiments have different commitment sets")
            transport = row["transport"]
            frames = {k: count(v, "frame count") for k, v in row["frame_counts"].items()}
            require(count(transport["opportunities"], "opportunities") == OPPORTUNITIES
                    and count(transport["emissions"], "emissions") == sum(frames.values()) <= OPPORTUNITIES,
                    "transmission opportunity budget differs")
            emitted_bytes = count(transport["emitted_bytes"], "emitted bytes")
            if native:
                require(row["capture"]["before_opportunity"] == 1
                        and row["capture"]["pending_entropy"] == [False, False], "native capture differs")
                require(set(frames) <= {"application", "ack", "control", "retry"}
                        and frames.get("application", 0) == sum(committed), "native frame admission differs")
                require(sum(count(v, "frame bytes") for v in row["frame_bytes"].values()) == emitted_bytes,
                        "native frame bytes differ")
                budget = int(profile.rsplit("-", 1)[1])
                require(all(len(e["derived_requests"]) <= 2 * budget - 1 for e in exposures),
                        "current-epoch allocation envelope exceeded")
                revisions = sum(pair(persistence["durable_image_revision_increments"], "image revisions"))
                syncs = sum(pair(persistence["physical_sync_data"], "physical sync calls"))
                require(persistence["component_state_returns"] is None and syncs > 0,
                        "native persistence boundary differs")
                if scenario == "one_way":
                    require(sum(committed) == budget and row["final_confirmed_epochs"] == [0, 0]
                            and all(len(e["derived_requests"]) == budget - 1 for e in exposures),
                            "one-way suspension/recovery distinction differs")
            else:
                require(committed == offered and frames == {"application_with_piggyback": OPPORTUNITIES},
                        "reference component admission differs")
                require(all(persistence[k] is None for k in ("durable_image_revision_increments",
                            "physical_sync_data", "physical_write_bytes")), "reference physical I/O fabricated")
                require(row["outer_envelope_bytes"] == {"length_prefix": 8192, "payload": 65536, "tag": 32768}
                        and count(row["component_bytes"], "component bytes")
                        + sum(row["outer_envelope_bytes"].values()) == emitted_bytes,
                        "reference full-envelope bytes differ")
                count(persistence["component_state_returns"], "component state returns")
                require(all(case["owner"] == i and case["cut_before_send"] == 1
                            and case["predicted_sequences"] == exposures[i]["derived_requests"]
                            for i, case in enumerate(row["capture_cases"]))
                        and len(row["capture_cases"]) == 2, "reference snapshot prediction differs")
                revisions = syncs = None
            output.append({
                "profile": profile, "scenario": scenario, "opportunities": OPPORTUNITIES,
                "offered": sum(offered), "committed": sum(committed), "delivered": sum(delivered),
                "uncommitted": sum(uncommitted), "post_capture_committed": post_capture,
                "derived_owner_A": len(exposures[0]["derived_requests"]),
                "derived_owner_B": len(exposures[1]["derived_requests"]),
                "derived_fraction_A": exposures[0]["derived_fraction_of_admitted"],
                "derived_fraction_B": exposures[1]["derived_fraction_of_admitted"],
                "emitted_bytes": emitted_bytes,
                "application_frames": frames.get("application", frames.get("application_with_piggyback", 0)),
                "ack_frames": frames.get("ack", 0), "control_frames": frames.get("control", 0),
                "retry_application_frames": frames.get("retry", 0),
                "all_exact_frame_retransmissions": sum(count(v, "exact retries") for v in row["exact_frame_retransmissions"].values()),
                "component_state_returns": persistence["component_state_returns"],
                "durable_image_revision_increments": revisions, "physical_sync_data": syncs,
            })
    return output


def table(rows: list[dict[str, Any]]) -> str:
    by = {(r["profile"], r["scenario"]): r for r in rows}
    lines = [r"% Generated by artifacts/matched-comparison/analyze_matched.py.",
             r"\begin{table}[t]", r"\centering", r"\small", r"\setlength{\tabcolsep}{3.5pt}",
             r"\begin{tabular}{@{}lrrrr@{}}", r"\toprule",
             r"Profile & Committed / & Capture $A$ & Capture $B$ & Emitted\\",
             r" & delivered & derived / admitted & derived / admitted & bytes\\", r"\midrule"]
    for profile, label in zip(PROFILES, LABELS):
        row = by[profile, "alternating"]
        values = [f'{row["committed"]:,} / {row["delivered"]:,}',
                  f'{row["derived_owner_A"]:,} / {row["post_capture_committed"]:,}',
                  f'{row["derived_owner_B"]:,} / {row["post_capture_committed"]:,}',
                  f'{row["emitted_bytes"]:,}']
        lines.append(label + " & " + " & ".join(values) + r"\\")
    lines += [r"\bottomrule", r"\end{tabular}",
              r"\caption{Alternating transport with 2,048 directed opportunities and 2,048 offered 32-byte requests. Each exposure denominator counts first commitments after the capture cut; $A/B$ identify the separately captured endpoint. Emitted bytes include actual native frames or the reference component with its executed payload envelope. Uncommitted requests equal 2,048 minus the committed count.}",
              r"\label{tab:matched-opportunities}", r"\end{table}", "",
              r"\begin{table}[t]", r"\centering", r"\small", r"\setlength{\tabcolsep}{4pt}",
              r"\begin{tabular}{@{}rrrrrrrr@{}}", r"\toprule",
              r"Budget & First & ACK & Control & App. & All exact & Image & \texttt{sync\_data}\\",
              r" & app. & & & retries & retries & revisions & calls\\", r"\midrule"]
    for profile in PROFILES[:2]:
        row = by[profile, "alternating"]
        keys = ("application_frames", "ack_frames", "control_frames", "retry_application_frames",
                "all_exact_frame_retransmissions", "durable_image_revision_increments", "physical_sync_data")
        lines.append(profile.rsplit("-", 1)[1] + " & " + " & ".join(f'{row[k]:,}' for k in keys) + r"\\")
    lines += [r"\bottomrule", r"\end{tabular}",
              r"\caption{Native alternating communication and persistence. First application, ACK, control and application-retry columns partition the 2,048 emitted frames. All exact retries also count repeated control frames and overlap that partition. Image revisions and physical sync calls sum both endpoints.}",
              r"\label{tab:matched-accounting}", r"\end{table}", ""]
    return "\n".join(lines)


def outputs(data: dict[str, Any]) -> dict[Path, str]:
    rows = analyze(data["report"])
    require(rows == data["results-49.json"], "new report projection differs from original public audit")
    require(data["report"]["executables"] == data["executables.json"], "executed binaries differ")
    require(data["qualification.json"]["artifact_id"] == 13641008832
            and data["qualification.json"]["rows"] == 49
            and data["qualification.json"]["full_audit_receipt_sha256"] == PINS["public-evidence-audit.json"],
            "qualification/audit chain differs")
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    require(stream.getvalue().encode() == data["results-49.csv"], "CSV projection differs from original audit")
    result = {
        "schema": 1, "status": "passed", "protocol_source": PROTOCOL_SOURCE,
        "research_head": "fec8472060728cc1bb35cf15042c117dda00e336",
        "checkout_merge_commit": "0d12e77d0c7c1cfb4760b654947f2838bb05d4ee",
        "run_id": 42537214047, "artifact_id": 13641008832,
        "source_sha256": PINS, "decompressed_report_sha256": REPORT_SHA256,
        "configuration_schedule_pairs": len(rows), "capture_cases": 2 * len(rows),
        "capture_coordinate": "After opportunity 0's scheduled local/network actions and checkpoint, before opportunity 1 local computation",
        "capture_before_committed": 1,
        "scope": "Reanalysis of the source-bound executed report and retained public-audit projection; native and reference execution identities remain those of the original hosted run.",
        "rows": rows,
    }
    return {HERE / "analysis.json": json.dumps(result, indent=2) + "\n",
            HERE.parent.parent / "matched-opportunity-tables.tex": table(rows)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Reject stale output instead of rewriting it")
    args = parser.parse_args()
    generated = outputs(read_sources())
    for path, text in generated.items():
        if args.check:
            require(path.read_text() == text, f"stale generated artifact: {path.name}")
        else:
            path.write_text(text)
    print(json.dumps({"status": "passed", "rows": 49, "capture_cases": 98,
                      "mode": "check" if args.check else "write", "outputs": [p.name for p in generated]}))


if __name__ == "__main__":
    main()
