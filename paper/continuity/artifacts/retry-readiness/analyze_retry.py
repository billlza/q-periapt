#!/usr/bin/env python3
"""Check the executed retry experiment and regenerate its manuscript table."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
BASE = "358b921ab3469ce49f166633fc9a762ff6ed7e3d"
CHECKOUT = "23f600f5b3ef69d9f0196efdaa66d146e271c9a4"
PROFILES = ("continuity-32", "continuity-64")
SCENARIOS = ("alternating", "lossy", "reordered", "duplicates", "asymmetric",
             "offline_then_exchange", "one_way")
POLICIES = ("immediate", "sender-turns-4")
PINS = {
    "audit_retry_ablation.py.txt": "3398deb63f1803283d2869f7f0be775718da1626cda387efd1af680894422e33",
    "drivers.json": "90d3ccf825fb22d4a42edcf4728d4bb268be419161712841e982861c2c52464b",
    "executable.json": "6fd2dec8f8c11bdd268b59759f0e77e240ed2cb71f8947d0334a42c3152019f2",
    "github-checkout.json": "92f7b7e826bb83ad12e8f2439a841129b52f123a8420e84692a4f03d6bdf1563",
    "github-fixed-base.json": "b843d88da5949d7797cdb7fb776aa77ef8b0a6a3abf99ac17c08ff8a2b7ab6f2",
    "github-run.json": "b53207a627815c6f26ad1021b6225f0585c7d83c10fae383c93828d6a1107168",
    "independent-audit.json": "68d955b7d09a1229b7d4688b7f1d9524218569e3403c7c2211c9cc4a9fa17e47",
    "preparation.json.gz": "a30b7604aadd0094467303acff3f15a4c564a3e061e1b5e7f8679500b24a3a11",
    "provenance-review.json": "485569f51e55c72c542b02c1109a1b03d0b58c0ce866a81195ec8bcafb32f4d1",
    "public-manifest.json": "c67c72b965ad097837a6cecac0f09d871ca09d60df389a57820240e367bdbfb6",
    "remote-sources.json.gz": "cadd8525c25a5e5b848b83ca649ba92abfd6f7ad743e2dc2f03cd2201a0836f7",
    "retry-age-report.json.gz": "5cc5cee4a79a464c6a9530ff9bd768e77c877d110dd4e1e7b6e4a170d1d74a2a",
    "retry_age_driver.rs.txt": "75cd41f4cfd38852622a7b6fade4df7af8b5a4f06673465d98615aee2c3e2b1a",
    "reviewed-analysis.csv": "85c9eeea986268bda4d08a5edae889fe7e09ee18cfb81738c0bfc3ecd56f59fa",
    "reviewed-analysis.json": "f32325bde019300198933214ec20a2c7455c8a7f267ea4b35c2d30c5791f3626",
    "reviewed-results.md": "046a71cbc848eda9e8cf9c8b4fcda437a5c921c85bf5b991518f909394bda5c5",
    "runtime.json": "14e2579981cb2eb4f9720571e9d3ce9ea6de75ddde2682675df808a26932de20",
    "source-and-readiness-controls.log": "feae252a729722159a9d98427cceec546f484977072f6f8d8b2080659bb87531",
    "summarize_retry_ablation.py.txt": "9c869d4a58861b5e9fa5d6be97a730753f07421f7af0315d46010c70a8bee15d"
}
RAW_PINS = {
    "preparation.json.gz": "6eccaf8db02b94bfb88a199d678b79e1f59fc0242c62df4560f4a6c4a01778f2",
    "remote-sources.json.gz": "20f70e32bccad549d598a39d3b3bda2801f94fad37c4109f9501f3471fca63ef",
    "retry-age-report.json.gz": "7771c25ad23271fa2676b81dfe53b1ecfc3ec1ec2301893d4eb914fb56c738ee"
}
HISTORICAL_SHA256 = "588fd79e8b3fa0d1681bd56dd93162a8f64d20c86c1303e29faf58f1333a0be4"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError("non-finite JSON value: " + value)


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)


def count(value):
    require(type(value) is int and 0 <= value <= 2**64 - 1, "invalid integer count")
    return value


def pair(value):
    require(type(value) is list and len(value) == 2, "invalid endpoint pair")
    return [count(x) for x in value]


def request_set(value):
    require(type(value) is list, "invalid request set")
    require(all(type(x) is int and 0 < x < 2048 for x in value), "invalid request id")
    require(value == sorted(set(value)), "repeated or unordered request id")
    return set(value)


def load_sources():
    result = {}
    for name, expected in PINS.items():
        # Names are constants in this source, never paths read from an input manifest.
        path = HERE / "sources" / name
        require(path.is_file() and not path.is_symlink(), "invalid fixed source: " + name)
        raw = path.read_bytes()
        require(digest(raw) == expected, "source digest changed: " + name)
        if name.endswith(".gz"):
            raw = gzip.decompress(raw)
            require(digest(raw) == RAW_PINS[name], "decompressed source changed: " + name)
        result[name] = decode(raw) if name.endswith((".json", ".json.gz")) else raw
    raw = (HERE.parent / "matched-comparison" / "sources" / "results-49.json").read_bytes()
    require(digest(raw) == HISTORICAL_SHA256, "retained matched baseline changed")
    result["historical"] = decode(raw)
    return result


def native_metrics(row):
    application, transport, persistence = row["application"], row["transport"], row["persistence"]
    offered = pair(application["offered"])
    committed = pair(application["committed"])
    delivered = pair(application["delivered_by_sender"])
    uncommitted = pair(application["uncommitted"])
    require(sum(offered) == transport["opportunities"] == 2048, "opportunity budget differs")
    require(all(offered[i] == committed[i] + uncommitted[i]
                and delivered[i] <= committed[i] for i in (0, 1)), "application accounting differs")
    capture = row["capture"]
    require(capture["before_opportunity"] == transport["capture_before_opportunity"] == 1
            and capture["pending_entropy"] == [False, False], "capture cut differs")
    denominator = sum(committed) - 1
    exposures = row["exposure"]
    require(len(exposures) == 2 and [e["owner"] for e in exposures] == [0, 1],
            "capture-owner inventory differs")
    derived = []
    for exposure in exposures:
        known = request_set(exposure["derived_requests"])
        unknown = request_set(exposure["not_derived_requests"])
        delivered_known = request_set(exposure["derived_delivered_requests"])
        require(exposure["capture_before_opportunity"] == 1
                and exposure["admitted_after_capture"] == denominator,
                "exposure denominator differs")
        require(not known & unknown and len(known | unknown) == denominator
                and delivered_known <= known, "exposure partition differs")
        require(exposure["derived_fraction_of_admitted"] == len(known) / denominator,
                "derived fraction differs")
        derived.append(len(known))
    frames, sizes = row["frame_counts"], row["frame_bytes"]
    require(set(frames) == set(sizes) and set(frames) <= {"application", "ack", "control", "retry"},
            "frame classes differ")
    require(sum(map(count, frames.values())) == transport["emissions"] == 2048,
            "frame partition differs")
    require(sum(map(count, sizes.values())) == transport["emitted_bytes"],
            "full-frame byte accounting differs")
    require(frames["application"] == sum(committed), "first-frame accounting differs")
    require(persistence["component_state_returns"] is None
            and persistence["physical_write_bytes"] is None, "persistence boundary differs")
    return {
        "profile": row["profile"], "scenario": row["scenario"],
        "opportunities": 2048, "offered": sum(offered), "committed": sum(committed),
        "delivered": sum(delivered), "uncommitted": sum(uncommitted),
        "post_capture_committed": denominator, "derived_owner_A": derived[0],
        "derived_owner_B": derived[1], "derived_fraction_A": derived[0] / denominator,
        "derived_fraction_B": derived[1] / denominator,
        "emitted_bytes": count(transport["emitted_bytes"]),
        "application_frames": frames["application"], "ack_frames": frames.get("ack", 0),
        "control_frames": frames["control"], "retry_application_frames": frames["retry"],
        "all_exact_frame_retransmissions": sum(map(count, row["exact_frame_retransmissions"].values())),
        "durable_image_revision_increments": sum(pair(persistence["durable_image_revision_increments"])),
        "physical_sync_data": sum(pair(persistence["physical_sync_data"])),
        "component_state_returns": None,
    }


def analyze(sources):
    report = sources["retry-age-report.json.gz"]
    audit = sources["independent-audit.json"]
    provenance = sources["provenance-review.json"]
    reviewed = sources["reviewed-analysis.json"]
    require(report["status"] == "passed" and report["execution"] == "native_compiled_and_executed"
            and report["base_commit"] == BASE and report["research_head"] == CHECKOUT,
            "executed report identity differs")
    require(audit["status"] == "passed" and audit["traces"] == 28
            and audit["base_commit"] == BASE and audit["research_head"] == CHECKOUT,
            "independent recount identity differs")
    require(provenance["status"] == "passed" and provenance["fixed_protocol_commit"] == BASE
            and provenance["actual_checkout"] == CHECKOUT
            and provenance["workflow_run_id"] == 42551086845
            and provenance["source_and_readiness_controls_passed"] == 14
            and provenance["fresh_baseline_rows_equal_to_retained"] == 14,
            "execution provenance differs")
    require(audit["drivers"] == sources["drivers.json"]
            and audit["executable"] == sources["executable.json"]
            and audit["drivers"]["minimum_sender_turns"] == 4, "driver or executable differs")
    coordinates = {(p, s) for p in PROFILES for s in SCENARIOS}
    policies = {p["policy"]: p["rows"] for p in report["policies"]}
    require(len(report["policies"]) == 2 and set(policies) == set(POLICIES), "policy inventory differs")
    comparisons = {(c["profile"], c["scenario"]): c for c in audit["comparisons"]}
    require(len(audit["comparisons"]) == 14 and set(comparisons) == coordinates,
            "paired inventory differs")
    details = {(d["policy"], d["profile"], d["scenario"]): d for d in audit["details"]}
    require(len(audit["details"]) == 28
            and set(details) == {(policy, p, s) for policy in POLICIES for p, s in coordinates},
            "trace detail inventory differs")
    historical = {(r["profile"], r["scenario"]): r for r in sources["historical"]}
    for policy in POLICIES:
        rows = {(r["profile"], r["scenario"]): r for r in policies[policy]}
        require(len(policies[policy]) == 14 and set(rows) == coordinates, "executed row inventory differs")
        for coordinate, row in rows.items():
            metrics = native_metrics(row)
            comparison = comparisons[coordinate]
            expected = comparison["baseline" if policy == "immediate" else "sender_turns_4"]
            require(metrics == expected, "executed metrics differ from independent recount")
            require(not comparison["fresh_baseline_differences_from_retained"], "fresh baseline differs")
            if policy == "immediate":
                require(metrics == historical[coordinate], "retained baseline differs")
            detail = details[(policy, *coordinate)]
            require(detail["trace_sha256"] == row["trace_sha256"]
                    and detail["frame_counts"] == row["frame_counts"]
                    and detail["frame_bytes"] == row["frame_bytes"]
                    and detail["final_confirmed_epochs"] == row["final_confirmed_epochs"],
                    "trace identity or frame recount differs")
            ages = detail["retry_age_histogram"]
            minimum = 0 if policy == "immediate" else 4
            require(all(str(int(k)) == k and int(k) >= minimum for k in ages)
                    and sum(map(count, ages.values())) == metrics["retry_application_frames"],
                    "retry readiness recount differs")
            readiness = row["retry_readiness"]
            require(readiness["minimum_sender_turns"] == minimum
                    and readiness["retry_emissions"] == metrics["retry_application_frames"]
                    and readiness["minimum_observed_sender_turns"] == min(map(int, ages))
                    and readiness["maximum_observed_sender_turns"] == max(map(int, ages)),
                    "reported retry ages differ")
    require(reviewed["status"] == "passed" and reviewed["paired_cases"] == 14
            and reviewed["audit_sha256"] == PINS["independent-audit.json"], "reviewed projection differs")
    projected = {(r["budget"], r["scenario"]): r for r in reviewed["rows"]}
    require(len(reviewed["rows"]) == 14 and set(projected) == {(b, s) for b in (32, 64) for s in SCENARIOS},
            "reviewed row inventory differs")
    output = []
    for profile in PROFILES:
        budget = 32 if profile == PROFILES[0] else 64
        for scenario in SCENARIOS:
            c = comparisons[(profile, scenario)]
            row = projected[(budget, scenario)]
            b, a = c["baseline"], c["sender_turns_4"]
            for prefix, policy, metrics in (("immediate", "immediate", b), ("age4", "sender-turns-4", a)):
                for metric in ("committed", "delivered", "uncommitted", "post_capture_committed", "derived_owner_A",
                               "emitted_bytes", "application_frames", "ack_frames", "control_frames",
                               "retry_application_frames", "all_exact_frame_retransmissions",
                               "durable_image_revision_increments", "physical_sync_data"):
                    require(row[prefix + "_" + metric] == metrics[metric], "reviewed count differs")
                require(row[prefix + "_committed_undelivered"] == metrics["committed"] - metrics["delivered"],
                        "committed-undelivered count differs")
                require(row[prefix + "_retry_emissions_after_delivery"]
                        == details[(policy, profile, scenario)]["retry_emissions_after_prior_logical_delivery"],
                        "post-delivery retry count differs")
            delivered_change = 100 * (a["delivered"] / b["delivered"] - 1)
            bytes_change = 100 * ((a["emitted_bytes"] / a["delivered"])
                                  / (b["emitted_bytes"] / b["delivered"]) - 1)
            require(row["delivered_percent_change"] == delivered_change
                    and row["bytes_per_delivered_percent_change"] == bytes_change,
                    "reviewed percentage differs")
            output.append({"budget": budget, "scenario": scenario, "immediate": b, "age4": a,
                           "delivered_percent_change": delivered_change,
                           "bytes_per_delivered_percent_change": bytes_change})
    return output


def table(rows):
    by = {(r["budget"], r["scenario"]): r for r in rows}
    names = ("Alternating", "Lossy", "Reordered", "Duplicates", "9:1 asymmetric", "Offline then exchange", "One-way")
    lines = ["% Generated by artifacts/retry-readiness/analyze_retry.py.",
             r"\begin{table}[t]", r"\centering", r"\small", r"\setlength{\tabcolsep}{3.5pt}",
             r"\begin{tabular}{@{}lrrrr@{}}", r"\toprule",
             r"Schedule & \multicolumn{2}{c}{Delivered: immediate $\to$ age four} & \multicolumn{2}{c}{$\Delta$ bytes/delivery}\\",
             r"\cmidrule(lr){2-3}\cmidrule(lr){4-5}",
             r" & $b=32$ & $b=64$ & $b=32$ & $b=64$\\", r"\midrule"]
    for scenario, name in zip(SCENARIOS, names):
        a, b = by[(32, scenario)], by[(64, scenario)]
        values = [name]
        for row in (a, b):
            values.append(f"{row['immediate']['delivered']:,} $\\to$ {row['age4']['delivered']:,}")
        values += [f"{row['bytes_per_delivered_percent_change']:+.2f}\\%" for row in (a, b)]
        lines.append(" & ".join(values) + r"\\")
    lines += [r"\bottomrule", r"\end{tabular}",
              r"\caption{Application-retry readiness at the same 2,048 directed opportunities. Each delivery column compares the freshly repeated immediate policy with minimum retry age four in the sender's own opportunities. Byte cost divides all emitted control, ACK, application and retry bytes by actual logical deliveries; positive changes indicate higher cost per delivery.}",
              r"\label{tab:retry-readiness}", r"\end{table}", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rows = analyze(load_sources())
    summary = {"schema": 1, "status": "passed", "paired_cases": 14, "native_executions": 28,
               "source_sha256": PINS, "historical_results_sha256": HISTORICAL_SHA256,
               "generator_sha256": digest(Path(__file__).read_bytes()), "rows": rows}
    outputs = {HERE / "analysis.json": json.dumps(summary, indent=2, sort_keys=True) + "\n",
               ROOT / "retry-readiness-table.tex": table(rows)}
    for path, data in outputs.items():
        if args.check:
            require(path.is_file() and path.read_text() == data, "generated output differs: " + path.name)
        else:
            path.write_text(data)
    print(json.dumps({"status": "passed", "paired_cases": 14, "native_executions": 28,
                      "fresh_baseline_rows_equal_to_retained": 14,
                      "mode": "check" if args.check else "write"}, sort_keys=True))


if __name__ == "__main__":
    main()
