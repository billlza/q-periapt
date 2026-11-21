"""Check the public stage-4 receipts without an SDK, endpoint state or signing keys."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

HERE = Path(__file__).resolve().parent
CASES = {"legacy-local": (4, 245), "candidate-local": (10, 0), "candidate-witness": (10, 0)}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check_witness(data):
    pairs = {}
    for row in data.decode().splitlines():
        phase, outcome, dropped, command, attempt, fence, revision, root = row.split()
        require(all(re.fullmatch(r"[0-9a-f]{64}", x) for x in (command, attempt, root)), "witness field width")
        pairs.setdefault(int(phase), []).append((outcome, dropped, command, attempt, int(fence), int(revision), root))
    require(set(pairs) == {5, 6}, "expected lost selection and ready advances")
    receipts = {}
    attempts = set()
    for phase, rows in sorted(pairs.items()):
        require(len(rows) == 2, "one original and one replay receipt required")
        original, replay = rows
        require(original[:2] == ("Advanced", "true") and replay[:2] == ("AlreadyAppliedExact", "false"),
                "wrong outcomes or loss schedule")
        require(original[2] == replay[2] and original[4:] == replay[4:], "changed command or head")
        attempts.update((original[3], replay[3]))
        receipts[phase] = {"command": original[2], "fence": original[4], "revision": original[5],
                           "head_digest": original[6]}
    first, second = receipts[5], receipts[6]
    require(first["fence"] == second["fence"] and first["revision"] + 1 == second["revision"] and
            first["command"] != second["command"] and first["head_digest"] != second["head_digest"]
            and len(attempts) == 4, "wrong decision sequence")
    return receipts


def verify(archive):
    with zipfile.ZipFile(archive) as z:
        filenames = z.namelist()
        require(len(filenames) == len(set(filenames)) and z.testzip() is None, "corrupt or duplicate archive member")
        run = json.loads(z.read("run.json"))
        lock = json.loads((HERE / "source-lock.json").read_bytes())
        require(run["reference"] == lock["reference"] and run["rustflags"] == "-Dwarnings"
                and run["source_lock_sha256"] == sha((HERE / "source-lock.json").read_bytes())
                and run["driver_sha256"] == sha((HERE / "run.py").read_bytes()), "wrong source or runner")
        require(sha((HERE / "engine.patch").read_bytes()) == lock["patch_sha256"] and
                all(sha((HERE / "overlay" / p).read_bytes()) == h for p, h in lock["added"].items()),
                "study overlay differs")
        tests = {}
        for item in run["tests"]:
            cfg = item["configuration"]
            name = item["test"]
            log = z.read(item["log"])
            require(item["exit"] == 0 and item["log_sha256"] == sha(log) and name.encode() in log and
                    re.search(rb"test result: ok\. 1 passed; 0 failed; 0 ignored;", log), "exact run missing")
            require(item["executable"] in run["binaries"][cfg], "unknown test executable")
            group = tests.setdefault(cfg, {})
            require(name not in group, "duplicate test")
            group[name] = log
        require({g: len(t) for g, t in tests.items()} ==
                {"reference-debug": 4, "prototype-debug": 10, "prototype-release": 10}, "missing configurations")
        ref = b"\n".join(tests["reference-debug"].values())
        for cut in (b"rekey-key-reserved", b"rekey-response-kem-reserved"):
            require(b"cut=" + cut + b" confirmed_epoch=1 recovered_messages=6 directions=2 private_input=one_snapshot"
                    in ref, "missing original positive control")
        profiles = {}
        for build in ("prototype-debug", "prototype-release"):
            logs = b"\n".join(tests[build].values())
            profiles[build] = results = {}
            for phase, count in ((4, 245), (10, 0)):
                expected = (f"STAGE4_MATCHED phase={phase} reservation_bytes={count} identical_starting_files=true "
                            "identical_offer=true authenticated_pending=true honest_deliveries=6").encode()
                require(expected in logs, "missing paired branch")
            require(b"STAGE4_DECODER phase=4 fixed_tail=stored_reservation result=Parsed" in logs and
                    b"STAGE4_DECODER phase=10 fixed_tail=public_offer result=InvalidPrivateKey" in logs,
                    "missing matched SDK decoder observation")
            for label, (phase, count) in CASES.items():
                prefix = f"{build}/{label}/"
                snapshot = z.read(prefix + "input-cut.txt").decode().strip()
                require(snapshot == (f"current_phase=0 pending_phase={phase} encapsulation_token_bytes={count} "
                                     "exact_offer=true normalized_prior_equal=true wrong_key_rejected=true"),
                        "wrong persisted cut")
                wire = z.read(prefix + "recovered-response.bin")
                body_len = int.from_bytes(wire[:4], "big")
                require(len(wire) == 4714 and len(wire) == 4 + body_len + 3373, "wrong response envelope")
                require(f"profile={label} pending_phase={phase} reservation_bytes={count} signed_wire_bytes={len(wire)} "
                        "honest_deliveries=6 confirmed_epoch=1" in logs.decode(), "incomplete end-to-end trace")
                row = {"pending_phase": phase, "persisted_encapsulation_token_bytes": count,
                       "response_bytes": len(wire), "wire_sha256": sha(wire), "honest_deliveries_after_reopen": 6}
                results[label] = row
                if label != "legacy-local":
                    chosen = z.read(prefix + "selected-body.bin")
                    rejected = z.read(prefix + "discarded-body.bin")
                    require(len(chosen) == len(rejected) == body_len and rejected != chosen and
                            wire[4:4+body_len] == chosen, "wrong selected or discarded body")
                    require(z.read(prefix + "before-ready.bin") == wire, "response changed after process loss")
                    frame = wire[:4] + chosen
                    require(z.read(prefix + "provider-bodies.bin") == frame + frame,
                            "actual provider input differs or an additional signing call occurred")
                    row.update(selected_body_bytes=body_len, provider_calls_for_selected_body=2,
                               provider_calls_for_discarded_body=0, exact_pre_ready_response=True)
                if label == "candidate-witness":
                    row["reconciled_advances"] = check_witness(z.read(prefix + "witness.txt"))
        return {"reference": run["reference"], "exact_test_executions": len(run["tests"]),
                "original_workload_recovered_messages_per_reservation_cut": 6,
                "profiles": profiles, "public_archive_sha256": sha(archive.read_bytes())}


def pack(folder, archive):
    run = json.loads((folder / "run.json").read_bytes())
    names = {"run.json", *(t["log"] for t in run["tests"])}
    for mode in ("prototype-debug", "prototype-release"):
        for case in CASES:
            fields = {"input-cut.txt", "recovered-response.bin"}
            if case != "legacy-local":
                fields.update(("before-ready.bin", "provider-bodies.bin", "selected-body.bin", "discarded-body.bin"))
            if case == "candidate-witness":
                fields.add("witness.txt")
            names.update(f"{mode}/{case}/{f}" for f in fields)
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as z:
        for name in sorted(names):
            path = Path(name)
            require(not path.is_absolute() and ".." not in path.parts and
                    not (folder / path).is_symlink(), "unexpected public record path")
            z.write(folder / path, name)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--pack", type=Path, help="collect completed runs and public observations into a new archive")
    args = parser.parse_args()
    if args.pack:
        pack(args.pack, args.archive)
    print(json.dumps(verify(args.archive), indent=2, sort_keys=True))
