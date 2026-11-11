#!/usr/bin/env python3
"""Independently read back the completed source-only checkout qualification."""
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import zipfile
from datetime import datetime

ROOT = Path(__file__).resolve().parent
LOCAL = ROOT.parent / "local"
SOURCE = "7c1c1b6f95747b9ccb877b803bd1ad7cee3cdd9d"
TREE = "3c8aea118257a0919530c66bdf7b618c0d8dfc21"
WORKFLOW = "beaf2773dd2f879dec1ae17724bf860583ed14bf"
WORKFLOW_TREE = "d837c639d324ce4d2131ec8ceb4df0c53edf0329"
BASE = "d2f9035c341db488bf0aba7b440d6548660d62b7"
RUN = 43066759983
ARTIFACT = 13876775935
ZIP_SHA256 = "5470a1db44ae6af62f3d64e0d190b3c9087a2ec3e094190845366c9876619048"

def load(path):
    return json.loads(gzip.decompress(path.read_bytes()) if path.suffix == ".gz" else path.read_bytes())

def git_object(kind, payload):
    return hashlib.sha1(kind.encode() + b" " + str(len(payload)).encode() + b"\0" + payload).hexdigest()

def git_tree(records):
    root = {}
    for path, item in records.items():
        parts = PurePosixPath(path).parts
        assert not path.startswith("/") and ".." not in parts and "/".join(parts) == path
        directory = root
        for part in parts[:-1]:
            directory = directory.setdefault(part, {})
            assert isinstance(directory, dict)
        assert parts[-1] not in directory
        directory[parts[-1]] = (item["mode"], item["sha"])
    def encode(directory):
        payload = bytearray()
        for name, item in sorted(directory.items(), key=lambda pair: (pair[0] + ("/" if isinstance(pair[1], dict) else "")).encode()):
            if isinstance(item, dict):
                mode, sha = "40000", encode(item)
            else:
                mode, sha = item
                assert mode in ("100644", "100755")
            payload.extend(mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(sha))
        return git_object("tree", payload)
    return encode(root)

manifest_bytes = (LOCAL / "MANIFEST.json").read_bytes()
assert hashlib.sha256(manifest_bytes).hexdigest() == "3bcbfb9cee79873f7b845ccd81d4a66bcac5d3df9941abcadbc79b3dcc7adf98"
local_manifest = json.loads(manifest_bytes)
assert len(local_manifest["files"]) == 8
for record in local_manifest["files"]:
    data = (LOCAL / record["file"]).read_bytes()
    assert len(data) == record["bytes"]
    assert hashlib.sha256(data).hexdigest() == record["sha256"]
assert {p.name for p in LOCAL.iterdir()} == {x["file"] for x in local_manifest["files"]} | {"MANIFEST.json"}

source = load(ROOT / "SOURCE_COMMIT.json")
workflow = load(ROOT / "WORKFLOW_COMMIT.json")
assert source["sha"] == SOURCE and source["tree"]["sha"] == TREE
assert [x["sha"] for x in source["parents"]] == [BASE]
assert workflow["sha"] == WORKFLOW and workflow["tree"]["sha"] == WORKFLOW_TREE
assert [x["sha"] for x in workflow["parents"]] == [SOURCE]
for commit in (source, workflow):
    for identity in ("author", "committer"):
        assert commit[identity]["name"] == "月溅星河"
        assert commit[identity]["email"] == "149552943+billlza@users.noreply.github.com"
workflow_bytes = (ROOT / "qualification-workflow.yml").read_bytes()
assert git_object("blob", workflow_bytes) == "e4fd28efc6e7054325779f9c71cd7b1769fa4fe6"

tree_api = load(ROOT / "CANDIDATE_TREE.json.gz")
assert tree_api["sha"] == TREE and tree_api["truncated"] is False
entries = {e["path"]: e for e in tree_api["tree"] if e["type"] == "blob"}
assert len(entries) == 7929 and git_tree(entries) == TREE
baseline = load(LOCAL / "TREE.json")
base_entries = {e["path"]: e for e in baseline["blobs"]}
assert baseline["source_commit"] == BASE and baseline["truncated"] is False
assert git_tree(base_entries) == baseline["tree_sha"]
assert entries.keys() == base_entries.keys()
changes = sorted(p for p in entries if any(entries[p][key] != base_entries[p][key] for key in ("sha", "mode", "size")))
assert changes == [".github/workflows/codeql.yml", "artifact/test_codeql_workflow_contract.py"]
local_candidate = load(LOCAL / "CANDIDATE.json")
assert local_candidate["tree"] == TREE and local_candidate["parent"] == BASE
for record in local_candidate["files"]:
    expected = entries[record["path"]]
    assert (expected["sha"], expected["size"]) == (record["blob"], record["bytes"])

run = load(ROOT / "RUN.json")
jobs = load(ROOT / "JOBS.json")
assert (run["id"], run["head_sha"], run["status"], run["conclusion"], run["run_attempt"]) == (RUN, WORKFLOW, "completed", "success", 1)
assert jobs["total_count"] == len(jobs["jobs"]) == 1
job = jobs["jobs"][0]
assert (job["id"], job["run_id"], job["head_sha"], job["conclusion"]) == (130683671253, RUN, WORKFLOW, "success")
assert all(step["conclusion"] == "success" for step in job["steps"])
artifacts = load(ROOT / "ARTIFACTS.json")
assert artifacts["total_count"] == len(artifacts["artifacts"]) == 1
artifact = artifacts["artifacts"][0]
assert artifact["id"] == ARTIFACT and artifact["workflow_run"]["id"] == RUN
assert artifact["workflow_run"]["head_sha"] == WORKFLOW
assert artifact["name"] == "codeql-checkout-evidence"
archive = ROOT / "codeql-checkout-evidence-43066759983.zip"
archive_data = archive.read_bytes()
assert len(archive_data) == artifact["size_in_bytes"] == 288676
assert hashlib.sha256(archive_data).hexdigest() == ZIP_SHA256
assert artifact["digest"] == "sha256:" + ZIP_SHA256
expected_members = {"CHECKOUT.json", "RETAINED_FILES.json", "OMITTED_ARCHIVES.json", "contracts.log", "git-object-count.txt", "source-census.log"}
with zipfile.ZipFile(archive) as zipped:
    assert zipped.testzip() is None
    assert len(zipped.namelist()) == 6 and set(zipped.namelist()) == expected_members
    members = {name: zipped.read(name) for name in expected_members}
receipt = json.loads(members["CHECKOUT.json"])
assert (receipt["source_commit"], receipt["source_tree"], receipt["workflow_commit"]) == (SOURCE, TREE, WORKFLOW)
assert (receipt["run_id"], receipt["run_attempt"]) == (str(RUN), "1")
assert receipt["partial_clone_filter"] == "blob:none"
for flag in ("index_matches_complete_head", "all_retained_blob_identities_match", "exact_skip_worktree_set", "checkout_clean"):
    assert receipt[flag] is True
retained_list = json.loads(members["RETAINED_FILES.json"])
omitted_list = json.loads(members["OMITTED_ARCHIVES.json"])
retained = {e["path"]: e for e in retained_list}
omitted = {e["path"]: e for e in omitted_list}
omitted_expected = {p for p in entries if p.startswith("research/sdk-alpha1/evidence/") and p.endswith(".zip")}
assert len(omitted_expected) == len(omitted) == len(omitted_list) == receipt["omitted_archives"] == 542
assert omitted.keys() == omitted_expected
assert len(retained) == len(retained_list) == receipt["retained_files"] == 7387
assert retained.keys() == entries.keys() - omitted_expected
assert receipt["tracked_files"] == len(entries)
for path, record in retained.items():
    expected = entries[path]
    assert (record["git_blob"], record["bytes"], record["mode"]) == (expected["sha"], expected["size"], expected["mode"])
for path, record in omitted.items():
    assert record["git_blob"] == entries[path]["sha"]
assert sum(e["bytes"] for e in retained.values()) == receipt["retained_bytes"] == 239527127
rust = {p for p in entries if p.endswith(".rs")}
archived_rust = {p for p in rust if p.startswith("paper/continuity/artifacts/bootstrap/")}
assert len(rust) == receipt["tracked_rust_files"] == 1241 and rust <= retained.keys()
assert len(archived_rust) == 68 and archived_rust <= retained.keys()
pins = {f"paper/continuity/artifacts/bootstrap/{name}/SOURCE_PINS.json" for name in ("ack", "entry", "initial", "reply", "terminal")}
assert pins <= retained.keys()
assert members["source-census.log"].decode().strip() == "1241 tracked Rust sources; 68 authenticated archived sources"
contracts = members["contracts.log"].decode()
assert len(re.findall(r"^test_.* \.\.\. ok$", contracts, flags=re.M)) == 10
assert re.search(r"^Ran 10 tests in 0\.029s$", contracts, flags=re.M)
assert contracts.rstrip().endswith("\nOK")
objects = dict(line.split(": ", 1) for line in members["git-object-count.txt"].decode().splitlines())
assert objects["count"] == "0" and objects["packs"] == "2" and objects["in-pack"] == "8108"
assert receipt["git_object_bytes"] == 100256247
checkout_step = next(s for s in job["steps"] if s["number"] == 3)
duration = (datetime.fromisoformat(checkout_step["completed_at"].replace("Z", "+00:00")) - datetime.fromisoformat(checkout_step["started_at"].replace("Z", "+00:00"))).total_seconds()
assert duration == 16 and 15 < receipt["checkout_elapsed_seconds"] < 17
summary = {
    "schema": 1,
    "source_commit": SOURCE, "source_tree": TREE, "workflow_commit": WORKFLOW,
    "run_id": RUN, "job_id": job["id"], "artifact_id": ARTIFACT,
    "artifact_bytes": len(archive_data), "artifact_sha256": ZIP_SHA256,
    "local_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
    "local_packet_files_verified": 9,
    "full_git_tree_reconstructed": True,
    "candidate_changed_paths": changes,
    "retained_inventory_matches_git_blobs_modes_and_sizes": True,
    "omitted_inventory_matches_exact_historical_zip_set": True,
    "hosted_validator_asserted_complete_index_and_retained_byte_identity": True,
    "tracked_files": len(entries), "retained_files": len(retained), "omitted_archives": len(omitted),
    "retained_bytes": receipt["retained_bytes"],
    "omitted_git_blob_bytes": sum(entries[p]["size"] for p in omitted),
    "tracked_rust_sources": len(rust), "authenticated_archived_rust_sources": len(archived_rust),
    "checkout_elapsed_seconds": receipt["checkout_elapsed_seconds"],
    "checkout_api_step_seconds": duration,
    "git_object_directory_bytes": receipt["git_object_bytes"],
    "workflow_contract_tests_passed": 10,
    "workflow_contract_test_seconds": 0.029,
    "artifact_members": [
        {"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        for name, data in sorted(members.items())
    ],
}
(ROOT / "READBACK.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))
