#!/usr/bin/env python3
"""Independently recount retained matched-opportunity traces and retry outcomes.

This reads public traces. It does not rerun Rust or the private-key AEAD audit.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path


PROFILES = ("continuity-32", "continuity-64", "spqr-32", "spqr-64",
            "whole-kem-1", "whole-kem-32", "whole-kem-64")
SCENARIOS = ("alternating", "lossy", "reordered", "duplicates", "asymmetric",
             "offline_then_exchange", "one_way")
N = 2048


def require(ok, message):
    if not ok:
        raise ValueError(message)


def unique_object(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, "duplicate JSON key")
        out[key] = value
    return out


def decode(text):
    return json.loads(text, object_pairs_hook=unique_object,
                      parse_constant=lambda value: (_ for _ in ()).throw(
                          ValueError("nonfinite JSON")))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    require(path.is_file() and not path.is_symlink(), "nonregular evidence input")
    return decode(path.read_text())


def rows(path):
    require(path.is_file() and not path.is_symlink(), "nonregular trace input")
    data = path.read_text()
    require(data.endswith("\n"), "incomplete trace tail")
    return [decode(line) for line in data.splitlines()]


def sender(scenario, opportunity):
    if scenario == "one_way" or (scenario == "offline_then_exchange" and opportunity < 256):
        return 0
    if scenario == "asymmetric":
        return int(opportunity % 10 == 9)
    return opportunity % 2


def native(path, profile, scenario):
    trace = rows(path)
    config = trace[0]
    require(config["event"] == "configuration" and config["profile"] == profile
            and config["scenario"] == scenario and config["opportunities"] == N
            and config["capture_before_opportunity"] == 1, "native configuration")
    budget = int(profile.split("-")[-1])
    commits, emissions, delivered = {}, {}, set()
    frames, wire_bytes, repeated = Counter(), Counter(), Counter()
    first_wire, delivered_before_retry = {}, set()
    retry_outcomes, retry_age = Counter(), Counter()
    outcomes_by_source = defaultdict(list)
    first_emit = {}
    opportunities = []
    prior_checkpoint = None
    captures = []
    for row in trace[1:]:
        event = row["event"]
        if event == "opportunity":
            i = row["opportunity"]
            require(i == len(opportunities) and row["owner"] == sender(scenario, i)
                    and row["request"] == i, "opportunity inventory or owner")
            opportunities.append(i)
        elif event == "capture":
            require(prior_checkpoint == 0 and len(opportunities) == 1
                    and row["before_opportunity"] == 1
                    and row["pending_entropy"] == [False, False], "capture micro-order")
            captures.append(row)
        elif event == "commit":
            request = row["request"]
            require(request not in commits and row["owner"] == sender(scenario, row["opportunity"]),
                    "commit identity")
            require(0 <= row["index"] < budget, "epoch send allocation exceeds budget")
            expected_known = [row["opportunity"] >= 1 and row["epoch"] == 0] * 2
            require(row["known"] == expected_known, "current-epoch predictor labeling")
            commits[request] = row
        elif event == "emit":
            i, identity = row["opportunity"], (row["owner"], row["logical"])
            require(i not in emissions and row["owner"] == sender(scenario, i), "uncharged emission")
            encoded = bytes.fromhex(row["wire"])
            require(0 < len(encoded) <= 8192, "frame cap")
            kind = row["kind"]
            frames[kind] += 1
            wire_bytes[kind] += len(encoded)
            if identity in first_wire:
                require(first_wire[identity] == encoded, "retry changed bytes")
                repeated[kind] += 1
            else:
                first_wire[identity] = encoded
                first_emit[identity] = i
            if kind == "retry":
                require(identity in first_emit and first_emit[identity] < i, "retry without original")
                request = int(row["logical"].rsplit("-", 1)[1])
                if request in delivered:
                    delivered_before_retry.add(i)
                retry_age[i - first_emit[identity]] += 1
            emissions[i] = row
        elif event == "receive":
            source = row["source_opportunity"]
            require(source in emissions, "receive without emission")
            original = emissions[source]
            require(row["wire"] == original["wire"] and row["logical"] == original["logical"]
                    and row["owner"] == 1-original["owner"], "receive identity")
            outcomes_by_source[source].append(row["outcome"])
            if row["kind"] in ("application", "retry"):
                request = int(row["logical"].rsplit("-", 1)[1])
                if row["outcome"] == "delivered":
                    require(request not in delivered, "duplicate logical delivery")
                    delivered.add(request)
                elif row["outcome"] == "duplicate_consumed":
                    require(request in delivered, "duplicate before delivery")
                if row["kind"] == "retry":
                    retry_outcomes[row["outcome"]] += 1
        elif event == "checkpoint":
            prior_checkpoint = row["opportunity"]
            last_checkpoint = row
    require(len(opportunities) == N and len(captures) == 1, "native opportunity/capture completeness")
    final = trace[-1]
    require(final["event"] == "completed" and final["status"] == "passed", "native terminal status")
    require(sum(final["offered"]) == N
            and len(commits) + sum(final["uncommitted"]) == N
            and sum(final["delivered"]) == len(delivered), "native demand partition")
    require(set(commits) >= delivered, "uncommitted delivery")
    future = [c for c in commits.values() if c["opportunity"] >= 1]
    counts = [sum(c["known"][owner] for c in future) for owner in (0, 1)]
    old_epoch = [sum(c["epoch"] == 0 and c["owner"] == owner for c in future) for owner in (0, 1)]
    require(len([c for c in commits.values() if c["opportunity"] < 1]) == 1,
            "one pre-capture commitment")
    require(old_epoch[0] <= budget-1 and old_epoch[1] <= budget
            and counts == [sum(old_epoch)] * 2, "initial-epoch allocation envelope")
    compact = {
        "profile": profile, "scenario": scenario, "opportunities": N, "offered": N,
        "committed": len(commits), "delivered": len(delivered),
        "uncommitted": sum(final["uncommitted"]), "post_capture_committed": len(future),
        "derived_owner_A": counts[0], "derived_owner_B": counts[1],
        "derived_fraction_A": counts[0] / len(future), "derived_fraction_B": counts[1] / len(future),
        "emitted_bytes": sum(wire_bytes.values()),
        "application_frames": frames["application"], "ack_frames": frames["ack"],
        "control_frames": frames["control"], "retry_application_frames": frames["retry"],
        "all_exact_frame_retransmissions": sum(repeated.values()), "component_state_returns": None,
        "durable_image_revision_increments": sum(last_checkpoint["revisions"])-sum(config["initial_revisions"]),
        "physical_sync_data": sum(last_checkpoint["sync_data"]),
    }
    retry_detail = {
        "profile": profile, "scenario": scenario, "trace_sha256": digest(path),
        "frame_counts": dict(frames), "frame_bytes": dict(wire_bytes),
        "retry_reception_outcomes": dict(retry_outcomes),
        "retry_emissions_after_prior_logical_delivery": len(delivered_before_retry),
        "retry_bytes_after_prior_logical_delivery": sum(len(bytes.fromhex(emissions[i]["wire"]))
                                                       for i in delivered_before_retry),
        "retry_age_from_first_emission_opportunities": dict(sorted(retry_age.items())),
        "post_capture_epoch_zero_commits_by_sender": old_epoch,
        "initial_epoch_remaining_allocation_bound": 2*budget-1,
        "final_confirmed_epochs": last_checkpoint["confirmed_epochs"],
        "final_sending_epochs": last_checkpoint["sending_epochs"],
    }
    if scenario == "alternating":
        require(sum(retry_outcomes.values()) == frames["retry"], "alternating retry delivery count")
        require(retry_outcomes["duplicate_consumed"] == len(delivered_before_retry),
                "alternating retry outcome/order disagreement")
    return compact, retry_detail


def reference(directory, profile, scenario):
    name = "ping_pong" if scenario == "alternating" else scenario
    trace = rows(directory / (name+".jsonl"))
    envelopes = rows(directory / (name+".envelopes.jsonl"))
    sends = {r["sequence"]: r for r in trace if r["event"] == "send"}
    receives = [r for r in trace if r["event"] == "receive"]
    require(len(sends) == N and set(sends) == set(range(N)) and len(envelopes) == N,
            "reference first-send inventory")
    total_bytes = 0
    for i, envelope in enumerate(envelopes):
        require(envelope["opportunity"] == i and envelope["owner"] == sender(scenario, i)
                and sends[i]["sender"] == sender(scenario, i), "reference envelope opportunity")
        component = bytes.fromhex(sends[i]["wire"])
        frame = bytes.fromhex(envelope["wire"])
        require(frame[:4] == len(component).to_bytes(4,"big") and frame[4:4+len(component)] == component
                and len(frame) == 4+len(component)+32+16 and len(frame) <= 8192,
                "reference complete-envelope accounting")
        total_bytes += len(frame)
    delivered = {r["sequence"] for r in receives}
    require(len(delivered) == len(receives) and all(r["key_matches"] is True for r in receives),
            "reference logical delivery and key agreement")
    cases = [c for c in read(directory/(name+".compromise.json"))["cases"] if c["cut_before_send"] == 1]
    require(len(cases) == 2 and {c["owner"] for c in cases} == {0,1}, "reference capture inventory")
    derived = []
    for case in sorted(cases, key=lambda c:c["owner"]):
        known = set(case["predicted_sequences"])
        unknown = set(case["not_derived_sequences"])
        require(known.isdisjoint(unknown) and known|unknown == set(range(1,N)),
                "reference post-capture partition")
        derived.append(len(known))
    return {
        "profile": profile, "scenario": scenario, "opportunities": N, "offered": N,
        "committed": N, "delivered": len(delivered), "uncommitted": 0, "post_capture_committed": N-1,
        "derived_owner_A": derived[0], "derived_owner_B": derived[1],
        "derived_fraction_A": derived[0]/(N-1), "derived_fraction_B": derived[1]/(N-1),
        "emitted_bytes": total_bytes, "application_frames": N, "ack_frames": 0,
        "control_frames": 0, "retry_application_frames": 0, "all_exact_frame_retransmissions": 0,
        "component_state_returns": N+len(receives), "durable_image_revision_increments": None,
        "physical_sync_data": None,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("compact_results", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    manifests = read(evidence/"manifest.json")
    require(manifests["status"] == "complete" and len(manifests["files"]) == 126,
            "public manifest inventory")
    for item in manifests["files"]:
        rel = Path(item["path"])
        require(not rel.is_absolute() and ".." not in rel.parts, "manifest path escape")
        path = evidence/rel
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == item["bytes"]
                and digest(path) == item["sha256"], "manifest digest mismatch")
    expected = {(r["profile"], r["scenario"]):r for r in read(args.compact_results)}
    require(set(expected) == {(p,s) for p in PROFILES for s in SCENARIOS}, "49-row inventory")
    details = []
    for profile in PROFILES:
        for scenario in SCENARIOS:
            if profile.startswith("continuity-"):
                row, detail = native(evidence/"native"/(profile+"-"+scenario+".jsonl"), profile, scenario)
                details.append(detail)
            else:
                directory = evidence/profile if profile.startswith("spqr-") else evidence/"whole-kem"/("period-"+profile.rsplit("-",1)[1])
                row = reference(directory, profile, scenario)
            require(row == expected[profile,scenario], "independent compact result differs: "+profile+"/"+scenario)
    report = {
        "schema": 1, "status": "passed", "analysis": "independent public-trace recount",
        "native_traces_recounted": 14, "reference_traces_and_envelopes_recounted": 35,
        "compact_rows_equal": 49, "public_manifest_hashes_verified": 126,
        "capture_before_opportunity": 1, "post_capture_denominator": "first commitments after opportunity 0",
        "script_sha256": digest(Path(__file__)), "compact_results_sha256": digest(args.compact_results),
        "native_retry_analysis": details,
        "interpretation": {
            "retry_outcomes": "Reception events; duplicated network deliveries are counted separately from emission identities.",
            "prior_delivery_retry": "An observed repeated transmission after that request already reached logical delivery; this uses analyst knowledge, not an extra sender oracle.",
            "bound": "Current-epoch first allocations only; at this fixed cut the remaining per-direction capacities sum to 2b-1.",
            "performance": "Observed arbitration costs; no counterfactual throughput or speedup is inferred.",
            "cryptography": "The public recount checks retained outcomes and accounting. Native key reconstruction and reference private-key AEAD audits belong to the original source-bound execution.",
        },
    }
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({k:report[k] for k in ("status","native_traces_recounted","reference_traces_and_envelopes_recounted","compact_rows_equal","public_manifest_hashes_verified")},sort_keys=True))


if __name__ == "__main__":
    main()
