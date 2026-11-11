"""Read the retained receipts only; do not execute tools or download inputs."""
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import zipfile

ROOT = Path(__file__).resolve().parent
load = lambda name: json.loads((ROOT / name).read_text())
digest = lambda data: hashlib.sha256(data).hexdigest()
seconds = lambda a, b: (datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds()
contract = load("SOURCE_CONTRACT.json")
source, diagnostic = contract["source"], contract["diagnostic"]
for filename, expected in (("SOURCE_COMMIT_API.json", source), ("DIAGNOSTIC_COMMIT_API.json", diagnostic)):
    actual = load(filename)
    assert actual["sha"] == expected["commit"] and actual["tree"]["sha"] == expected["tree"]
    assert [p["sha"] for p in actual["parents"]] == [expected["parent"]]
    for role in ("author", "committer"):
        assert actual[role]["name"] == "月溅星河"
        assert actual[role]["email"] == "149552943+billlza@users.noreply.github.com"
workflow = (ROOT / "WORKFLOW.yml").read_bytes()
assert len(workflow) == diagnostic["bytes"] and digest(workflow) == diagnostic["sha256"]
assert hashlib.sha1(b"blob " + str(len(workflow)).encode() + b"\0" + workflow).hexdigest() == diagnostic["git_blob"]
for name in ("ci_apt.sh", "ci_protoc.py"):
    data = (ROOT / "source" / name).read_bytes()
    assert digest(data) == source["pins"]["artifact/" + name]["sha256"]
integration = load("SDK_INTEGRATION_API.json")
assert integration["sha"] == contract["integration"]["commit"]
assert integration["commit"]["tree"]["sha"] == contract["integration"]["tree"]
assert [p["sha"] for p in integration["parents"]] == [source["commit"]]
assert sorted(f["filename"] for f in integration["files"]) == sorted(contract["integration"]["changed_paths"])
assert all(f["status"] == "modified" and f["filename"].endswith(".md") for f in integration["files"])

run, jobs, artifacts = load("RUN_API.json"), load("JOBS_API.json")["jobs"], load("ARTIFACTS_API.json")["artifacts"]
assert run["id"] == contract["run"]["id"] and run["run_attempt"] == 1
assert run["head_sha"] == diagnostic["commit"] and run["head_branch"] == contract["run"]["branch"]
assert run["event"] == "push" and run["status"] == "completed" and run["conclusion"] == "success"
assert len(jobs) == len(artifacts) == 5
common = {"source.txt", "runner.txt", "native-consumer.log"}
native_extra = {"protoc-time.txt", "protoc-receipt.json", "compiler-capabilities.log", "apt-time.txt", "apt-install.log", "cross-consumers.log"}
arm_extra = {"apt-time.txt", "apt-install.log", "valgrind-version.txt", "memcheck.log"}
conditional = {"Prepare the fixed protobuf compiler and real schema": "ubuntu-24.04",
               "Check exported protobuf, OpenSSL, and WASM tools": "ubuntu-24.04",
               "Install authenticated Ubuntu cross dependencies": "ubuntu-24.04",
               "Compile and execute both cross targets": "ubuntu-24.04",
               "Install authenticated ARM Memcheck dependencies": "ubuntu-24.04-arm"}
members, results = [], []
for runner, job_id in contract["runner_jobs"].items():
    job = next(j for j in jobs if j["id"] == job_id)
    assert job["name"] == f"Build tools ({runner})" and job["conclusion"] == "success" and job["status"] == "completed"
    for step in job["steps"]:
        expected = "success" if step["name"] not in conditional or conditional[step["name"]] == runner else "skipped"
        assert step["conclusion"] == expected, (runner, step)
    artifact = next(a for a in artifacts if a["name"] == f"linux-build-bootstrap-{runner}-{run['id']}-1")
    assert artifact["workflow_run"]["head_sha"] == diagnostic["commit"] and artifact["workflow_run"]["id"] == run["id"]
    data = (ROOT / "artifacts" / (runner + ".zip")).read_bytes()
    assert len(data) == artifact["size_in_bytes"] and "sha256:" + digest(data) == artifact["digest"]
    expected_files = common | (native_extra if runner == "ubuntu-24.04" else arm_extra if runner == "ubuntu-24.04-arm" else set())
    with zipfile.ZipFile(ROOT / "artifacts" / (runner + ".zip")) as archive:
        assert archive.testzip() is None and set(archive.namelist()) == expected_files
        assert len(archive.infolist()) == len(expected_files)
        raw = {name: archive.read(name) for name in sorted(expected_files)}
    receipts = {name: value.decode() for name, value in raw.items()}
    members.extend({"runner": runner, "path": name, "bytes": len(value), "sha256": digest(value)} for name, value in raw.items())
    assert receipts["source.txt"] == source["commit"] + "\n" + source["tree"] + "\n"
    environment = dict(line.split("=", 1) for line in receipts["runner.txt"].splitlines() if "=" in line)
    version = runner.removeprefix("ubuntu-").removesuffix("-arm")
    assert environment["VERSION_ID"].strip('"') == version
    assert ("Linux aarch64" if runner.endswith("-arm") else "Linux x86_64") in receipts["runner.txt"]
    original_log = (ROOT / "jobs" / (runner + ".log")).read_bytes()
    assert "Version: " + environment["ImageVersion"] in original_log.decode()
    consumer = receipts["native-consumer.log"]
    assert "witness_tls_peer.c.o" in consumer and "[100%] Built target native-tools-consumer" in consumer
    assert re.search(r"1/1 Test #1: native-tools-consumer .*Passed", consumer)
    assert "100% tests passed" in consumer and "out of 1" in consumer
    header = re.search(r"OPENSSL_HEADER (.+)", consumer).group(1)
    runtime = re.search(r"OPENSSL_RUNTIME (.+)", consumer).group(1)
    assert header == runtime
    item = {"runner": runner, "job_id": job_id, "artifact_id": artifact["id"],
            "artifact_bytes": len(data), "artifact_sha256": digest(data),
            "job_log_bytes": len(original_log), "job_log_sha256": digest(original_log),
            "source_commit": source["commit"], "source_tree": source["tree"],
            "image_os": environment["ImageOS"], "image_version": environment["ImageVersion"],
            "cmake": re.search(r"cmake version (.+)", consumer).group(1),
            "pkg_config": re.search(r'Found PkgConfig: .+ \(found version "([^"]+)"\)', consumer).group(1),
            "openssl_header": header, "openssl_runtime": runtime, "consumer_tests_passed": 1,
            "job_seconds": seconds(job["started_at"], job["completed_at"]),
            "steps": [{"name": s["name"], "conclusion": s["conclusion"], "started_at": s["started_at"],
                       "completed_at": s["completed_at"], "seconds": seconds(s["started_at"], s["completed_at"])} for s in job["steps"]]}
    if "apt-install.log" in receipts:
        apt = receipts["apt-install.log"]
        mirror = "https://mirrors.ocf.berkeley.edu/ubuntu-ports" if runner.endswith("-arm") else "https://mirrors.edge.kernel.org/ubuntu"
        architecture = "arm64" if runner.endswith("-arm") else "amd64"
        assert apt.startswith(f"APT source: {mirror}; suite=noble; architecture={architecture}\n")
        pockets = re.findall(r"^Get:\d+ (\S+) (\S+) InRelease", apt, re.MULTILINE)
        assert set(pockets) == {(mirror, p) for p in ("noble", "noble-updates", "noble-security", "noble-backports")}
        assert not re.search(r"^E:|^Err:|NO_PUBKEY|BADSIG|EXPKEYSIG|not signed|cannot be authenticated", apt, re.MULTILINE)
        item["apt"] = {"mirror": mirror, "architecture": architecture, "accepted_inrelease_pockets": 4,
                       "wall_seconds": float(re.fullmatch(r"wall_seconds=(\d+\.\d+)\n", receipts["apt-time.txt"]).group(1)),
                       "warnings": [l for l in apt.splitlines() if l.startswith(("W:", "N:"))],
                       "download_summaries": [l for l in apt.splitlines() if l.startswith("Fetched ")]}
    if runner == "ubuntu-24.04":
        protoc = json.loads(receipts["protoc-receipt.json"])
        assert protoc["bytes"] == 1585982 and protoc["version"] == "libprotoc 3.21.12"
        assert protoc["sha256"] == "3a4c1e5f2516c639d3079b1586e703fc7bcfa2136d58bda24d1d54f949c315e8"
        assert protoc["url"] == "https://github.com/protocolbuffers/protobuf/releases/download/v21.12/protoc-21.12-linux-x86_64.zip"
        assert protoc["descriptor_sha256"] == load("local/protoc-receipt.json")["descriptor_sha256"]
        assert protoc["protoc"] == protoc["directory"] + "/bin/protoc" and protoc["include"] == protoc["directory"] + "/include"
        capability = receipts["compiler-capabilities.log"]
        assert f"PROTOC={protoc['protoc']}\nPROTOC_INCLUDE={protoc['include']}\n" in capability
        assert capability.endswith("PROTOBUF_OPENSSL_WASM_OK\n")
        item["protoc"] = dict(protoc, wall_seconds=float(receipts["protoc-time.txt"].split("=")[1]))
        item["clang"] = re.search(r"Ubuntu clang version (.+)", capability).group(1)
        cross = receipts["cross-consumers.log"]
        assert cross.splitlines().count("CROSS_CONSUMER_OK") == 2
        item["cross_targets"] = {}
        for target in ("aarch64", "riscv64"):
            item["cross_targets"][target] = {"compiler": re.search(r"^" + target + r"-linux-gnu-gcc (.+)", cross, re.MULTILINE).group(1),
                                             "qemu": re.search(r"^qemu-" + target + r" version (.+)", cross, re.MULTILINE).group(1), "executed": True}
    if runner == "ubuntu-24.04-arm":
        assert "ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)" in receipts["memcheck.log"]
        item["memcheck"] = {"version": receipts["valgrind-version.txt"].strip(), "errors": 0, "contexts": 0}
    results.append(item)

assert len(members) == 25
controls = load("local/apt-controls.json")
assert controls["passed"] == 13 and len(controls["records"]) == 13
assert controls["helper_sha256"] == source["pins"]["artifact/ci_apt.sh"]["sha256"]
assert "Ran 15 tests" in (ROOT / "local/protoc-controls.log").read_text()
report = {"schema": 1, "run_id": run["id"], "attempt": 1, "result": "success",
          "diagnostic_commit": diagnostic["commit"], "source_commit": source["commit"], "source_tree": source["tree"],
          "sdk_integration": contract["integration"], "jobs_passed": 5, "receipt_files": 25,
          "api_time_resolution_seconds": 1, "runners": results,
          "local_controls": {"protoc_and_workflow": 15, "apt_fixtures": 13}}
(ROOT / "READBACK.json").write_text(json.dumps(report, indent=2) + "\n")
(ROOT / "ARTIFACT_MEMBERS.json").write_text(json.dumps(members, indent=2) + "\n")
print(json.dumps({"jobs_passed": 5, "receipt_files": 25,
                  "runners": [{"runner": r["runner"], "job_seconds": r["job_seconds"],
                               "checkout_seconds": r["steps"][1]["seconds"],
                               "consumer_seconds": r["steps"][3]["seconds"],
                               "protoc_seconds": r.get("protoc", {}).get("wall_seconds"),
                               "apt_seconds": r.get("apt", {}).get("wall_seconds")} for r in results]}))
