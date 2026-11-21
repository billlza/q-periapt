"""Collect only the public fixture records, or replay the resulting archive."""

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re
import runpy
from statistics import median
import tempfile
import zipfile

from evidence_io import parse_strict_json_bytes


HERE = Path(__file__).resolve().parent
REFERENCE = HERE.parent / "sdk-alpha1/evidence/20261106-installed-throughput/CAPTURE.zip"
REFERENCE_SHA = "febe57f043c78f09a77ec36a2694cdb156b3e184e287ff62871712f54b1ebdde"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def schedule():
    with zipfile.ZipFile(REFERENCE) as z:
        plan = json.loads(z.read("experiment/PROTOCOL.json"))["plan"]
    pilots = [dict(row, label=f"pilot-{row['kind']}-{row['profile']}") for row in plan[:4]]
    return {"pilots": pilots, "measured": plan}


def collect(work, archive):
    expected = schedule()
    measurements = work / "measurements"
    require(expected == json.loads((measurements / "schedule.json").read_text()), "measurement order changed")
    build = json.loads((work / "build-identity.json").read_text())
    original_paths = {kind: exe["path"] for kind, exe in build["binaries"].items()}
    for exe in build["binaries"].values():
        exe["path"] = Path(exe["path"]).name
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("build-identity.json", json.dumps(build, sort_keys=True, indent=2) + "\n")
        z.write(work / "observer/Cargo.lock", "Cargo.lock")
        z.write(measurements / "schedule.json", "schedule.json")
        for row in expected["pilots"] + expected["measured"]:
            label = row["label"]
            run = json.loads((measurements / label / "run.json").read_text())
            kind = row["kind"]
            require(run["command"][0] == original_paths[kind], "executed workload path differs")
            run["command"][0] = build["binaries"][kind]["path"]
            z.writestr(f"{label}/run.json", json.dumps(run, sort_keys=True, indent=2) + "\n")
            for name in ("result.json", "stdout", "stderr"):
                z.write(measurements / label / name, f"{label}/{name}")
            fanout = row["kind"] == "fanout"
            fixture = work / "private" / label / ("installation-account" if fanout else "installation")
            recipients = ["responder", "responder-2"] if fanout else ["responder"]
            for index, recipient in enumerate(recipients):
                effects = fixture / recipient / "measured-effects"
                require(effects.is_dir() and not effects.is_symlink(), "expected synthetic effect directory")
                for f in sorted(effects.iterdir()):
                    require(re.fullmatch("[0-9a-f]{64}", f.name) and f.is_file() and not f.is_symlink(),
                            "unexpected synthetic effect file")
                    key = f"{index}/{f.name}" if fanout else f.name
                    z.write(f, f"{label}/effects/{key}")
            if fanout:
                accounts = [(fixture / owner / "local-account").read_bytes()
                            for owner in ("initiator", *recipients)]
                require(all(len(a) == 32 for a in accounts), "unexpected public account identifier")
                z.writestr(f"{label}/context.json", json.dumps({"owner_accounts": list(map(list, accounts))}))


def validators(directory):
    with zipfile.ZipFile(REFERENCE) as z:
        for name in ("readback-operation-repeat.py", "readback-fanout.py", "readback-throughput.py"):
            (directory / name).write_bytes(z.read("controller/" + name))
    return runpy.run_path(str(directory / "readback-throughput.py"), run_name="historical_validation")


def verify(archive, historical):
    expected = schedule()
    samples = defaultdict(list)
    totals = defaultdict(list)
    controls = 0
    effects_count = 0
    with zipfile.ZipFile(archive) as z:
        require(z.testzip() is None and len(set(z.namelist())) == len(z.namelist()), "archive corruption")
        require(json.loads(z.read("schedule.json")) == expected, "cohort schedule differs")
        build = json.loads(z.read("build-identity.json"))
        require(hashlib.sha256(z.read("Cargo.lock")).hexdigest() == build["cargo_lock_sha256"], "lock changed")
        for row in expected["pilots"] + expected["measured"]:
            label, kind, profile = row["label"], row["kind"], row["profile"]
            stdout = z.read(label + "/stdout")
            run = json.loads(z.read(label + "/run.json"))
            require(run["exit"] == 0 and re.search(rb"^test result: ok\. 1 passed; 0 failed; 0 ignored;", stdout, re.M)
                    and not z.read(label + "/stderr"), f"failed workload {label}")
            require(run["command"] == [build["binaries"][kind]["path"], "--exact", f"measure_installed_{kind}",
                                       "--nocapture", "--test-threads=1"], "workload invocation differs")
            value = parse_strict_json_bytes(z.read(label + "/result.json"), label=label)
            require(value["profile"] == profile, "protection profile mismatch")
            trace = [parse_strict_json_bytes(s, label="operation")
                     for s in re.findall(rb"OPERATION_RESOURCE_SPAN (.+)$", stdout, re.M)]
            phases = [parse_strict_json_bytes(s, label="phase")
                      for s in re.findall(rb"OPERATION_RESOURCE_PHASE (.+)$", stdout, re.M)]
            prefix = label + "/effects/"
            effects = {p[len(prefix):]: z.read(p) for p in z.namelist() if p.startswith(prefix)}
            context = json.loads(z.read(label + "/context.json")) if kind == "fanout" else None
            args = kind, value, trace, phases, effects, context
            historical["validate"](*args)
            controls += len(historical["negative_controls"](*args))
            effects_count += len(effects)
            if row in expected["pilots"]:
                continue
            whole, = [p for p in phases if p["phase"] == "ordinary-workload"]
            delta = {k: whole["witness_after"][k] - whole["witness_before"][k]
                     for k in ("requests", "framed_bytes")}
            group = kind + "-" + profile
            totals[group].append({"ns": whole["elapsed_ns"], "deliveries": whole["confirmed_deliveries"],
                                  "witness_exchanges": delta["requests"], "witness_bytes": delta["framed_bytes"]})
            if kind == "lifecycle":
                samples[group].extend(s["elapsed_ns"] for s in trace if s["operation"] == "send_confirmed"
                                      and s["outcome"]["epoch"] == 1 and s["outcome"]["payload_bytes"] == 1024
                                      and s["outcome"]["associated_data_bytes"] == 32)
    require(controls == 500 and effects_count == 750, "incomplete independent readback")
    groups = {}
    for name, phases in sorted(totals.items()):
        require(len(phases) == 4, "four measured repeats required")
        groups[name] = {"ordinary_intervals": phases,
                        "pooled_deliveries_s": sum(p["deliveries"] for p in phases) * 1e9 / sum(p["ns"] for p in phases)}
        if name in samples:
            latencies = samples[name]
            require(len(latencies) == 32, "ordinary latency stratum differs")
            groups[name]["epoch1_1024B_32B_AD"] = {"n": len(latencies), "median_ms": median(latencies) / 1e6,
                                                  "max_ms": max(latencies) / 1e6}
    return {"scope": "Published 0.2.0 serial macOS workload; four pilots excluded from timings.",
            "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "cargo_lock_sha256": build["cargo_lock_sha256"], "groups": groups,
            "successful_pilots": 4, "successful_measured_cohorts": 16, "failed_or_timed_out_cohorts": 0,
            "altered_observations_rejected": controls, "verified_synthetic_effect_files": effects_count}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--collect", type=Path, metavar="WORK", help="create a new archive from a completed run")
    options = parser.parse_args()
    require(hashlib.sha256(REFERENCE.read_bytes()).hexdigest() == REFERENCE_SHA, "reference capsule mismatch")
    if options.collect:
        collect(options.collect, options.archive)
    with tempfile.TemporaryDirectory() as tmp:
        print(json.dumps(verify(options.archive, validators(Path(tmp))), indent=2, sort_keys=True))
