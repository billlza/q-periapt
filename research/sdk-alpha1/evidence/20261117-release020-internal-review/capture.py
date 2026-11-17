"""Read exact hosted SARIF archives; this census makes no finding dispositions."""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile

SOURCE = "8abbf8d2e73a27af7794528fd92d13fe3be2942d"
RUN = 43964930828
ARCHIVES = {
    "python": (14275579692, "python-analysis.zip", "cea2d0f0e89125af5d0020fe63bd624f99f842785549f1e31cb701147319e016"),
    "c-cpp": (14274434750, "cpp-analysis.zip", "e3a3ffbed82625aabe1b2b37be99236cb706f3b9fe5ff80c29a860856d08f8a0"),
    "java-kotlin": (14275014796, "java-analysis.zip", "6dba384b8e6fdfd7f2c5c1fde07ac28dc1020a5447ac65d4f2b046fa0654d502"),
    "swift": (14282452803, "swift-analysis.zip", "e882172ad6a9d4c5dc22935e366753d691b590b5d8c8506cffa1cffdf30dd93e"),
    "actions": (14274554695, "actions-analysis.zip", "2aa97d3493d4ce2b3051a164922377f5ac5902e4518df9c903d9a29f3c264a2e"),
    "rust-native": (14278636550, "rust-native-profile.zip", "08e6b42c282bde2d1789f08397355745c3e5f0ede0ac0721159db61f30a19375"),
    "rust-wasm": (14276673216, "rust-wasm-profile.zip", "825df99b0ab7db46eb2881951e1266d6c1be408d4cb4c923c6ba34318e79f93d"),
    "rust-macos": (14280018375, "rust-macos-profile.zip", "a2b6b191e8df3a1ceb6092e7812bb1956c0464629ec2654560912dad5da11dc4"),
    "rust-windows": (14278781219, "rust-windows-profile.zip", "04ce7cba5b3d61b4de54df5cfffca74b8070d622a0768fb3359f48307aae5b98"),
}
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--archives", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
sources = {}


def location(value):
    physical = value["physicalLocation"]
    path = physical["artifactLocation"]["uri"]
    line = physical["region"]["startLine"]
    if path not in sources:
        content = subprocess.check_output(["git", "show", SOURCE + ":" + path])
        sources[path] = {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
    return {"path": path, "line": line}


inventories = {}
for language, (artifact, filename, expected) in ARCHIVES.items():
    path = args.archives / filename
    payload = path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != expected:
        raise ValueError("hosted archive digest differs: " + language)
    with zipfile.ZipFile(path) as archive:
        names = [name for name in archive.namelist() if name.endswith(".sarif")]
        if len(names) != 1:
            raise ValueError("missing or ambiguous SARIF: " + language)
        if language.startswith("rust-"):
            profile = json.loads(archive.read("PROFILE.json"))
            if profile["source_commit"] != SOURCE:
                raise ValueError("Rust analysis source differs")
        else:
            identity = archive.read("source-identity.txt").decode().splitlines()
            tree = subprocess.check_output(["git", "rev-parse", SOURCE + "^{tree}"], text=True).strip()
            if identity != [SOURCE, tree]:
                raise ValueError("analysis source/tree differs: " + language)
        sarif = archive.read(names[0])
    document = json.loads(sarif)
    if len(document["runs"]) != 1:
        raise ValueError("unexpected SARIF run count")
    results = document["runs"][0].get("results", [])
    rows = []
    for index, result in enumerate(results):
        if len(result["locations"]) != 1:
            raise ValueError("unexpected primary location count")
        rows.append({"index": index, "rule": result["ruleId"],
                     "location": location(result["locations"][0]),
                     "related": [dict(location(item), id=item["id"])
                                 for item in result.get("relatedLocations", []) if "id" in item],
                     "supplied_code_flows": len(result.get("codeFlows", []))})
    inventories[language] = {
        "artifact_id": artifact, "archive": filename, "archive_sha256": expected,
        "archive_bytes": len(payload), "sarif_member": names[0],
        "sarif_sha256": hashlib.sha256(sarif).hexdigest(),
        "raw_results": len(rows), "rule_counts": dict(collections.Counter(row["rule"] for row in rows)),
        "results": rows,
    }
report = {"schema_version": 1, "kind": "qperiapt.release020_current_analysis_inventory",
          "source_commit": SOURCE, "run_id": RUN, "completed": True,
          "scope": "Archive integrity, exact analysis identity, complete raw result and named related-location census. No finding is disposed by this capture.",
          "analyses": inventories, "location_source_pins": sources,
          "all_findings_disposed": False, "publication_performed": False, "release_claim_eligible": False}
with args.output.open("x") as stream:
    json.dump(report, stream, indent=2, sort_keys=True)
    stream.write("\n")
print(json.dumps({"analyses": len(inventories), "results": sum(x["raw_results"] for x in inventories.values()),
                  "source_files": len(sources), "all_findings_disposed": False}))
