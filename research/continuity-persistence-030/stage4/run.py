"""Materialize and run the isolated native stage-4 study with Rust 1.98.1."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
PKG = Path("research/continuity-identity-candidate")
INPUTS = ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "crates", str(PKG), "LICENSE", "LICENSES"]
LOCK = json.loads((HERE / "source-lock.json").read_text())
LIB = "q_periapt_continuity_identity_candidate"
TESTS = "durable::messages::tests::"
SIGNER = "crypto::persistence::tests::restored_device_owner_replays_exact_reserved_signature"
OLD_CUT = TESTS + "killed_rekey_response_reuses_encapsulation_and_signature_before_publication"
REFERENCE = [OLD_CUT, SIGNER] + [
    TESTS + "reservation_disclosure::disclosed_" + name + "_reservation_exposes_traffic_computed_after_restart"
    for name in ("encapsulation", "key")
]
PAIRED = TESTS + "stage4_matched::same_snapshot_offer_and_wrapping_key"
REGRESSION = [PAIRED, SIGNER, OLD_CUT] + [TESTS + "rekey_response_" + name for name in (
    "agrees_with_real_decapsulation_and_replays_without_advancing_traffic",
    "rejects_unauthenticated_conflicting_and_revoked_offers",
    "sync_faults_reconcile_every_observed_barrier",
    "rejects_corrupt_pending_root_and_cached_signature",
)]
PROCESS = ["stage4::" + name for name in ("legacy_input_snapshot",
           "local_selected_response_survives_process_cuts", "witnessed_selected_response_survives_both_lost_advances")]


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def record(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def source_archive(path):
    subprocess.run(["git", "archive", "-o", str(path), LOCK["reference"], "--", *INPUTS],
                   cwd=REPO, check=True, timeout=180)


def check_inputs(work):
    with tempfile.TemporaryDirectory() as tmp:
        expected = Path(tmp) / "pinned.tar"
        source_archive(expected)
        if digest(expected) != digest(work / "input.tar"):
            raise ValueError("input tar differs from the pinned Git tree")
    with tarfile.open(work / "input.tar") as tar:
        expected = {Path(m.name): hashlib.sha256(tar.extractfile(m).read()).hexdigest()
                    for m in tar if m.isfile()}
    for label in ("reference", "prototype"):
        root = work / label
        members = dict(expected)
        if label == "prototype":
            for name, pair in LOCK["modified"].items():
                if members[PKG / name] != pair["baseline"]:
                    raise ValueError(f"baseline mismatch: {name}")
                members[PKG / name] = pair["prototype"]
            members.update({PKG / name: h for name, h in LOCK["added"].items()})
        if {p.relative_to(root) for p in root.rglob("*") if p.is_file()} != set(members):
            raise ValueError(f"source inventory differs in {label}")
        for path, h in members.items():
            if digest(root / path) != h:
                raise ValueError(f"source mismatch: {label}/{path}")
    if digest(HERE / "engine.patch") != LOCK["patch_sha256"]:
        raise ValueError("patch digest mismatch")


def prepare(work):
    work.mkdir(mode=0o700)
    source_archive(work / "input.tar")
    for name in ("reference", "prototype"):
        dest = work / name
        dest.mkdir()
        with tarfile.open(work / "input.tar") as tar:
            tar.extractall(dest, filter="data")
    pkg = work / "prototype" / PKG
    with (HERE / "engine.patch").open("rb") as delta:
        subprocess.run(["patch", "-p1", "-F", "0", "-s"], cwd=pkg, stdin=delta, check=True, timeout=60)
    for name, h in LOCK["added"].items():
        src = HERE / "overlay" / name
        if digest(src) != h or (pkg / name).exists():
            raise ValueError(f"unexpected overlay source: {name}")
        (pkg / name).parent.mkdir(exist_ok=True, parents=True)
        shutil.copyfile(src, pkg / name)
    check_inputs(work)


def binaries(data):
    result = {}
    for line in data.splitlines():
        event = json.loads(line)
        if event.get("executable"):
            result[event["target"]["name"]] = Path(event["executable"])
    return result


def execute(work, out):
    check_inputs(work)
    out.mkdir(mode=0o700)
    builds = {}
    runs = []
    base_env = {k: v for k, v in os.environ.items() if not k.startswith(
        ("QPERIAPT_", "QPC_", "CARGO_ENCODED_RUSTFLAGS", "DYLD_", "LD_"))}
    base_env.update(RUSTFLAGS="-Dwarnings")
    common = ["--locked", "--offline", "--all-features", "-j", "3"]
    for tree, profile, cache in (("reference", "debug", "build-reference"),
                                 ("prototype", "debug", "build-prototype"),
                                 ("prototype", "release", "build-final-release")):
        tag = tree + "-" + profile
        public = out / tag
        public.mkdir()
        pkg = work / tree / PKG
        env = dict(base_env, CARGO_TARGET_DIR=str(work / cache))
        args = common + (["--release"] if profile == "release" else [])
        targets = ["--lib"] if tree == "reference" else ["--lib", "--test", "owned_connection"]
        cmds = [["test", *args, *targets, "--no-run", "--message-format=json"]]
        if tree == "prototype":
            cmds.append(["build", *args, "--example", "stage4_kem", "--message-format=json"])
        built = {}
        for index, cmd in enumerate(cmds):
            with (public / f"build-{index}.stderr").open("xb") as errors:
                run = subprocess.run(["cargo", "+1.98.1", *cmd], cwd=pkg, env=env,
                                     stdout=subprocess.PIPE, stderr=errors, check=True, timeout=1800)
            built.update(binaries(run.stdout))
        builds[tag] = {k: digest(v) for k, v in built.items()}
        plan = [(LIB, n) for n in (REFERENCE if tree == "reference" else REGRESSION)]
        if tree == "prototype":
            env.update(QPERIAPT_STAGE4_KEM=str(built["stage4_kem"]), QPERIAPT_STAGE4_EVIDENCE=str(public))
            plan.extend(("owned_connection", n) for n in PROCESS)
        for i, (target, name) in enumerate(plan):
            binary = built[target]
            if digest(binary) != builds[tag][target]:
                raise ValueError(f"binary changed during run: {tag}/{target}")
            args = [str(binary), "--exact", name, "--nocapture", "--test-threads=1"]
            log = public / f"test-{i:02}.log"
            with log.open("xb") as stream:
                result = subprocess.run(args, cwd=pkg, env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=360)
            item = {"configuration": tag, "test": name, "executable": target, "exit": result.returncode,
                    "log": str(log.relative_to(out)), "log_sha256": digest(log)}
            runs.append(item)
            print(tag, name, result.returncode, flush=True)
            if result.returncode or b"1 passed; 0 failed; 0 ignored;" not in log.read_bytes():
                record(out / "failure.json", item)
                raise RuntimeError(f"exact test failed or was absent: {log}")
    check_inputs(work)
    record(out / "run.json", {
        "reference": LOCK["reference"], "source_lock_sha256": digest(HERE / "source-lock.json"),
        "driver_sha256": digest(Path(__file__).resolve()), "engine_lock_sha256": LOCK["engine_lock_sha256"],
        "rustc": subprocess.check_output(["rustc", "+1.98.1", "-Vv"], text=True),
        "platform": platform.platform(), "machine": platform.machine(), "binaries": builds, "tests": runs,
        "rustflags": base_env["RUSTFLAGS"],
    })


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("prepare").add_argument("work", type=Path)
    run = sub.add_parser("run")
    run.add_argument("work", type=Path)
    run.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.action == "prepare":
        prepare(args.work.resolve())
    else:
        execute(args.work.resolve(), args.output.resolve())
