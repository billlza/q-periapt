#!/usr/bin/env python3
"""Recompute this review's SARIF identities from the original six ZIPs."""

import collections
import hashlib
import json
from pathlib import Path
import zipfile


ROOT = Path(__file__).resolve().parent
SOURCE = {
    "previous": ["b72f7f8e8e6f2526ebab4b825b7d47402ac9835f", "e992a9077e657e63c6b698527d26fe81ad67c535"],
    "current": ["706207d11ddfc6371176698fd302b20d7714bbdb", "81e8aa8047e9e54e9f98ea18fc25c616cb557425"],
}


def identity(result):
    return json.dumps({
        "ruleId": result["ruleId"],
        "locations": [
            [item["physicalLocation"]["artifactLocation"]["uri"],
             item["physicalLocation"].get("region", {})]
            for item in result["locations"]
        ],
        "partialFingerprints": result.get("partialFingerprints"),
    }, sort_keys=True, separators=(",", ":"))


def without_indexes(value):
    # SARIF table offsets differ when files are added. URI, region, rule IDs,
    # messages, flow ordering, and fingerprints remain in this comparison.
    if isinstance(value, dict):
        return {key: without_indexes(item) for key, item in value.items() if key != "index"}
    if isinstance(value, list):
        return [without_indexes(item) for item in value]
    return value


def inspect(metadata, scope):
    results = {}
    artifacts = []
    for artifact in metadata:
        data = (ROOT / (str(artifact["id"]) + ".zip")).read_bytes()
        assert len(data) == artifact["size_in_bytes"]
        assert "sha256:" + hashlib.sha256(data).hexdigest() == artifact["digest"]
        with zipfile.ZipFile(ROOT / (str(artifact["id"]) + ".zip")) as archive:
            members = {name: archive.read(name) for name in archive.namelist()}
        assert members["source-identity.txt"].decode().splitlines() == SOURCE[scope]
        sarif_names = [name for name in members if name.endswith(".sarif")]
        assert len(sarif_names) == 1
        name = sarif_names[0]
        runs = json.loads(members[name])["runs"]
        rows = [result for run in runs for result in run.get("results", [])]
        results[name] = rows
        rules = {
            rule["id"]: rule
            for run in runs
            for component in [run["tool"]["driver"], *run["tool"].get("extensions", [])]
            for rule in component.get("rules", [])
        }
        artifacts.append({
            "id": artifact["id"], "name": name,
            "zip_bytes": len(data), "zip_sha256": hashlib.sha256(data).hexdigest(),
            "source": SOURCE[scope], "result_count": len(rows),
            "rule_counts": dict(sorted(collections.Counter(row["ruleId"] for row in rows).items())),
            "severity_counts": dict(sorted(collections.Counter(
                rules[row["ruleId"]].get("properties", {}).get("security-severity", "unspecified")
                for row in rows
            ).items())),
            "members": {
                key: {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}
                for key, value in sorted(members.items())
            },
        })
    return results, artifacts


def main():
    previous, old_artifacts = inspect(json.loads((ROOT / "previous-artifacts-api.json").read_text()), "previous")
    current, new_artifacts = inspect(json.loads((ROOT / "artifacts-api.json").read_text()), "current")
    report = {"previous_artifacts": old_artifacts, "current_artifacts": new_artifacts, "delta": {}}
    for name in ("python.sarif", "cpp.sarif"):
        old = collections.Counter(identity(row) for row in previous[name])
        new = collections.Counter(identity(row) for row in current[name])
        full_old = collections.Counter(json.dumps(without_indexes(row), sort_keys=True) for row in previous[name])
        full_new = collections.Counter(json.dumps(without_indexes(row), sort_keys=True) for row in current[name])
        report["delta"][name] = {
            "previous": sum(old.values()), "current": sum(new.values()),
            "shared_identities": sum((old & new).values()),
            "added": [json.loads(item) for item in (new - old).elements()],
            "removed": [json.loads(item) for item in (old - new).elements()],
            "complete_results_equal_after_table_index_removal": sum((full_old & full_new).values()),
        }
    python = report["delta"]["python.sarif"]
    assert (python["previous"], python["current"], python["shared_identities"]) == (1404, 1415, 1404)
    assert len(python["added"]) == 11 and not python["removed"]
    assert all(row["ruleId"] == "py/path-injection" and
               all(location[0] == "artifact/ci_protoc.py" for location in row["locations"])
               for row in python["added"])
    added_ids = {json.dumps(row, sort_keys=True, separators=(",", ":")) for row in python["added"]}
    python["new_result_sources"] = []
    for row in current["python.sarif"]:
        if identity(row) not in added_ids:
            continue
        python["new_result_sources"].append({
            "identity": json.loads(identity(row)),
            "reported_sources": [
                {"uri": location["physicalLocation"]["artifactLocation"]["uri"],
                 "region": location["physicalLocation"].get("region"),
                 "message": location.get("message")}
                for location in row.get("relatedLocations", []) if "id" in location
            ],
        })
    assert len(python["new_result_sources"]) == 11
    cpp = report["delta"]["cpp.sarif"]
    assert (cpp["previous"], cpp["current"], cpp["shared_identities"],
            cpp["complete_results_equal_after_table_index_removal"]) == (3, 3, 3, 3)
    assert not cpp["added"] and not cpp["removed"]
    assert not current["actions.sarif"] and not current["java.sarif"]
    (ROOT / "READBACK.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"verified_artifacts": len(old_artifacts) + len(new_artifacts),
                      "python_previous": 1404, "python_current": 1415,
                      "python_preserved_identities": 1404, "new_ci_protoc_path_results": 11,
                      "cpp_results_preserved": 3, "actions_results": 0, "java_results": 0}, sort_keys=True))


if __name__ == "__main__":
    main()
