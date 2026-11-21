"""Run the archived macOS workload against the distributed 0.2.0 Cargo packages."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tomllib
import zipfile


EVIDENCE = Path(__file__).resolve().parents[1] / "sdk-alpha1/evidence/20261106-installed-throughput"
CAPSULE = "febe57f043c78f09a77ec36a2694cdb156b3e184e287ff62871712f54b1ebdde"
RELEASE_SUMS = "41728e1d81d8036af2838754748451759e1696707cfcb1dd95e2238e453bda11"
OLD_ENGINE = "q-periapt-continuity-identity-candidate"
ENGINE = "q-periapt-continuity"
CARGO = ["cargo", "+1.98.1"]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_record(path, data):
    with path.open("x") as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write("\n")


def registry_lock(data):
    return sorted((p["name"], p["version"], p["source"], p["checksum"])
                  for p in tomllib.loads(data)["package"]
                  if "source" in p and not p["name"].startswith("q-periapt-"))


def build(assets, work):
    work.mkdir(mode=0o700)
    project = work / "observer"
    packages = project / "packages"
    packages.mkdir(parents=True)
    sums = assets / "SHA256SUMS"
    capsule = EVIDENCE / "CAPTURE.zip"
    if sha(sums) != RELEASE_SUMS or sha(capsule) != CAPSULE:
        raise ValueError("release manifest or historical observer identity mismatch")
    expected = {name: digest for digest, name in (s.split() for s in sums.read_text().splitlines())}
    used = {}
    with zipfile.ZipFile(capsule) as archive:
        for original in archive.namelist():
            if original.startswith("inputs/") and original.endswith(".crate"):
                name = Path(original).name.replace(OLD_ENGINE + "-0.0.0", ENGINE + "-0.2.0")
                package = assets / name
                used[name] = sha(package)
                if used[name] != expected[name]:
                    raise ValueError(f"release package mismatch for {name}")
                with tarfile.open(package) as tar:
                    tar.extractall(packages, filter="data")
            if original.startswith("observer/source/"):
                target = project / original.removeprefix("observer/source/")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(original))
    # The published engine has the same library import and a new package name.
    # Its native provider and the observer's memory sampler must use a compatible cc.
    old_dir = OLD_ENGINE + "-0.0.0"
    new_dir = ENGINE + "-0.2.0"
    manifest = project / "Cargo.toml"
    source = manifest.read_text().replace(old_dir, new_dir)
    source = source.replace(OLD_ENGINE + '={version="=0.0.0"',
                            OLD_ENGINE + '={package="' + ENGINE + '",version="=0.2.0"')
    source = source.replace(OLD_ENGINE + " = { path", ENGINE + " = { path")
    release_lock = (packages / new_dir / "Cargo.lock").read_text()
    cc_version, = [p["version"] for p in tomllib.loads(release_lock)["package"] if p["name"] == "cc"]
    source = source.replace('cc="=1.5.1"', f'cc="={cc_version}"')
    manifest.write_text(source)
    for test in ("journal_lifecycle.rs", "journal_fanout.rs"):
        fixture = project / "tests" / test
        fixture.write_text(fixture.read_text().replace(old_dir, new_dir))
    lock = project / "Cargo.lock"
    original_lock = lock.read_text()
    # Preserve all dependency versions of the distributed engine. Only the JSON
    # observer and its formatting dependencies are missing from the released lock.
    observer_only = {"itoa", "serde_json", "zmij"}
    extra = [section for section in original_lock.split("[[package]]")[1:]
             if tomllib.loads(section)["name"] in observer_only]
    if len(extra) != len(observer_only):
        raise ValueError("historical observer dependency inventory changed")
    seed_lock = release_lock + "".join("[[package]]" + section for section in extra)
    lock.write_text(seed_lock)
    env = dict(os.environ, RUSTFLAGS="-Dwarnings", CARGO_TARGET_DIR=str(work / "build"))
    with (work / "resolution.log").open("x") as log, (work / "resolution.stderr").open("x") as err:
        subprocess.run(CARGO + ["metadata", "--offline", "--format-version=1"],
                       cwd=project, env=env, stdout=log, stderr=err, check=True, timeout=300)
    # socket2 is an engine-only dev-dependency in the published manifest. Cargo
    # omits it when the engine is consumed as a library by this workload.
    expected_registry = [entry for entry in registry_lock(seed_lock) if entry[0] != "socket2"]
    if registry_lock(lock.read_text()) != expected_registry:
        raise ValueError("resolved dependencies differ from the release and observer locks")
    args = CARGO + ["test", "--release", "--locked", "--offline", "--test", "journal_fanout",
                    "--test", "journal_lifecycle", "--no-run", "--message-format=json", "-j", "2"]
    with (work / "build.jsonl").open("x") as stdout, (work / "build.stderr").open("x") as stderr:
        subprocess.run(args, cwd=project, env=env, stdout=stdout, stderr=stderr, check=True, timeout=1800)
    binaries = {}
    for line in (work / "build.jsonl").read_text().splitlines():
        event = json.loads(line)
        if event.get("executable") and event["target"]["name"] in {"journal_lifecycle", "journal_fanout"}:
            path = Path(event["executable"])
            binaries[event["target"]["name"].removeprefix("journal_")] = {"path": str(path), "sha256": sha(path)}
    if set(binaries) != {"lifecycle", "fanout"}:
        raise ValueError("both workload executables are required")
    write_record(work / "build-identity.json", {
        "packages": used, "binaries": binaries, "cargo_lock_sha256": sha(lock),
        "pinned_third_party_packages": len(expected_registry),
        "engine_cargo_lock_sha256": hashlib.sha256(release_lock.encode()).hexdigest(),
        "observer_only_dependencies": sorted(observer_only),
        "observer_capsule_sha256": CAPSULE, "release_sums_sha256": RELEASE_SUMS,
        "compiler": subprocess.check_output(["rustc", "+1.98.1", "-Vv"], text=True),
        "host": subprocess.check_output(["sw_vers"], text=True),
        "hardware": subprocess.check_output(["sysctl", "hw.model", "machdep.cpu.brand_string",
                                            "hw.ncpu", "hw.memsize"], text=True),
        "build_command": args, "rustflags": env["RUSTFLAGS"],
    })


def measure(work):
    identity = json.loads((work / "build-identity.json").read_text())
    public = work / "measurements"
    public.mkdir()
    plan = json.loads((EVIDENCE / "PROTOCOL.json").read_text())["plan"]
    pilots = [dict(row, label=f"pilot-{row['kind']}-{row['profile']}") for row in plan[:4]]
    write_record(public / "schedule.json", {"pilots": pilots, "measured": plan})
    for row in pilots + plan:
        kind, profile = row["kind"], row["profile"]
        out = public / row["label"]
        out.mkdir()
        private = work / "private" / row["label"]
        private.mkdir(mode=0o700, parents=True)
        target = identity["binaries"][kind]
        if sha(Path(target["path"])) != target["sha256"]:
            raise ValueError("workload binary identity changed")
        env = {k: v for k, v in os.environ.items() if not k.startswith(("QPC_", "QPERIAPT_", "DYLD_", "LD_"))}
        env.update(QPC_JOURNAL_PROFILE=profile, QPC_JOURNAL_OUTPUT=str(out / "result.json"),
                   QPERIAPT_PUBLIC_SERVICE_EVIDENCE=str(private / "installation"))
        if kind == "fanout":
            env["QPC_FANOUT_LAYOUT"] = "peer"
        args = [target["path"], "--exact", f"measure_installed_{kind}", "--nocapture", "--test-threads=1"]
        before = os.getloadavg()
        with (out / "stdout").open("x") as stdout, (out / "stderr").open("x") as stderr:
            run = subprocess.run(args, cwd=work / "observer", env=env, stdout=stdout, stderr=stderr, timeout=300)
        write_record(out / "run.json", {"command": args, "exit": run.returncode,
                                        "load_before": before, "load_after": os.getloadavg()})
        run.check_returncode()
        result = json.loads((out / "result.json").read_text())
        if not re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", (out / "stdout").read_text()):
            raise ValueError("exact workload did not run")
        if (not result["completed"] or result["profile"] != profile or
                result["kind"] != f"qperiapt.installed_{kind}_throughput" or len(result["phases"]) != 3):
            raise ValueError("wrong workload result")
        print(row["label"], flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    prepare = commands.add_parser("build")
    prepare.add_argument("assets", type=Path, help="abi2-platforms-v0.2.0 release assets")
    for command in (prepare, commands.add_parser("measure")):
        command.add_argument("work", type=Path, help="fresh private build/measurement directory")
    options = parser.parse_args()
    if options.action == "build":
        build(options.assets.resolve(), options.work.resolve())
    else:
        measure(options.work.resolve())
