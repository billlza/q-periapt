"""Retain the actually emitted descriptor and schema-2 normative identity lock.

This finite capture selects no final archives or qualification assessments and
does not claim that its authoring checkout is a clean final release commit.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

import continuity_c_abi
import continuity_contract
import continuity_release_manifest as manifest
from evidence_io import read_regular_snapshot

ROOT = Path(__file__).resolve().parents[4]
HERE = Path(__file__).resolve().parent
PRIOR = ROOT / "research/sdk-alpha1/evidence/20261116-release020-admission"
BASE = "8abbf8d2e73a27af7794528fd92d13fe3be2942d"
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--prior-manifest-sha256", required=True)
parser.add_argument("--compiled-evidence", type=Path, required=True)
parser.add_argument("--compiled-descriptor-sha256", required=True)
args = parser.parse_args()


def read(path):
    return read_regular_snapshot(path, maximum=16 * 1024**2, label="normative freeze input")


def ref(relative):
    manifest.relative_path(relative)
    snap = read(ROOT / relative)
    return {"path": relative, "bytes": snap.size, "sha256": snap.sha256}


def write(path, value, *, raw=False):
    data = value if raw else manifest.canonical_json_bytes(value)
    with path.open("xb") as stream:
        stream.write(data)
    return {"path": path.relative_to(ROOT).as_posix(), "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


prior_bytes = read(PRIOR / "MANIFEST.json")
manifest.require(prior_bytes.sha256 == args.prior_manifest_sha256,
                 "prior selected package inventory differs")
prior = json.loads(prior_bytes.data)
manifest.require(prior["source"]["commit"] == BASE and prior["stage"] == "candidate",
                 "prior inventory source/stage differs")
actual = read(args.compiled_evidence / "consumer.stdout")
manifest.require(actual.sha256 == args.compiled_descriptor_sha256,
                 "independently selected compiled output differs")
execution_snapshot = read(args.compiled_evidence / "CONTRACT.json")
execution = json.loads(execution_snapshot.data)
manifest.require(execution["completed"] is True and execution["stage"] == "release"
                 and execution["returncode"] == 0 and "failure" not in execution
                 and read(args.compiled_evidence / "consumer.stderr").data == b"",
                 "compiled contract execution was not complete and diagnostic-free")
budgets_path = "docs/continuity/BUDGETS_V1.json"
budgets = json.loads(read(ROOT / budgets_path).data)
continuity_contract.compare(budgets, json.loads(actual.data), stage="release")
manifest.require(execution["budgets_sha256"] == ref(budgets_path)["sha256"]
                 and execution["contract"] == budgets,
                 "execution selected a different reviewed contract")
before = json.loads(subprocess.check_output(["git", "show", BASE + ":" + budgets_path], cwd=ROOT))
manifest.require(dict(before, frozen_product_contract=True) == budgets,
                 "freeze changed a protocol field or implementation limit")
owner_path = "bindings/c/ContinuityPackageConsumer/abi/qpc-owner-v1.json"
owner = json.loads(read(ROOT / owner_path).data)
owner_before = json.loads(subprocess.check_output(["git", "show", BASE + ":" + owner_path], cwd=ROOT))
manifest.require(dict(owner_before, frozen_product_contract=True) == owner,
                 "freeze changed the owner declaration contract")
checked_owner = continuity_c_abi.load(ROOT / "bindings/c/ContinuityPackageConsumer", stage="release")

# Reuse the reviewed candidate's exact package selection and the existing
# schema-2 projection. No artifact is synthesized from a package definition.
packages = copy.deepcopy(prior["packages"])
manifest.require(len(packages) == 21, "selected package population differs")
for package in packages:
    manifest.require(package["artifacts"] == [] and package["assessments"] == [],
                     "prior capture unexpectedly selected per-build evidence")
    if package["format"] == "distribution":
        package["metadata"] = {"path": "release/0.2.0/distributions/" + package["id"] + ".json"}
    else:
        manifest.require(ref(package["metadata"]["path"]) == package["metadata"],
                         "selected Cargo/npm definition changed")
        if package["workspace"] is not None:
            manifest.require(ref(package["workspace"]["path"]) == package["workspace"],
                             "selected workspace definition changed")
    del package["artifacts"]
    del package["assessments"]
interfaces = copy.deepcopy(prior["interfaces"])
for interface in interfaces.values():
    interface["contract"] = ref(interface["contract"]["path"])
manifest.require(set(interfaces["continuity_c"]["exports"]) == set(checked_owner["functions"]),
                 "selected Continuity exports changed")

spec = importlib.util.spec_from_file_location("prior_capture", PRIOR / "capture.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)  # Only definitions; its candidate main is not invoked.
supporting = (*module.SUPPORTING, "docs/continuity/ADOPTION_0_2.md",
              "docs/continuity/RECOVERY_CONDITIONS_V1.md",
              "docs/continuity/RECOVERY_DEPENDENCIES_V1.md",
              "docs/continuity/COMPUTATIONAL_RECOVERY_V1.md")
compiled = write(ROOT / "docs/continuity/CONTRACT_0_2.json", actual.data, raw=True)
graph = {"schema_version": 2, "kind": "qperiapt.continuity_normative_package_graph",
         "packages": packages, "interfaces": interfaces}
graph_ref = write(ROOT / "docs/continuity/PACKAGE_GRAPH_0_2.json", graph)
lock = {"schema_version": 2, "kind": manifest.LOCK_KIND, "stage": "release", "product_version": "0.2.0",
        "frozen_product_contract": True,
        "normative_files": {role: ref(path) for role, path in module.NORMATIVE.items()},
        "supporting_files": [ref(path) for path in supporting] + [graph_ref],
        "compiled_descriptor": compiled,
        "package_graph_sha256": manifest.package_graph_digest(packages, schema_version=2),
        "interfaces_sha256": manifest.canonical_digest(interfaces)}
lock_ref = write(ROOT / "docs/continuity/SPEC_LOCK_0_2.json", lock)
inputs = manifest.Inputs(ROOT)
for reference in [*lock["normative_files"].values(), *lock["supporting_files"], compiled,
                  *[value["contract"] for value in interfaces.values()]]:
    inputs.read(reference)
report = {
    "schema_version": 1, "kind": "qperiapt.continuity_normative_freeze_capture", "completed": True,
    "scope": "Compiled descriptor equality, unchanged protocol/declaration values, selected package graph and normative input identity; not final release qualification.",
    "prior_source_commit": BASE, "prior_manifest_sha256": prior_bytes.sha256,
    "authoring_checkout_claimed_clean": False, "final_release_source_commit": None,
    "spec_lock": lock_ref, "package_graph": graph_ref, "compiled_descriptor": compiled,
    "compiled_execution": {"report_sha256": execution_snapshot.sha256,
                           "consumer_sha256": execution["consumer_sha256"],
                           "stdout_sha256": actual.sha256, "returncode": 0, "stderr_bytes": 0},
    "capture_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    "packages": len(packages), "implementation_limits": len(budgets["maximums"]),
    "signature_purposes": len(budgets["signature_purposes"]),
    "exports": {name: len(value["exports"]) for name, value in interfaces.items()},
    "protocol_values_unchanged_except_freeze_state": True, "owner_declarations_unchanged": True,
    "selected_final_archives": 0, "selected_final_assessments": 0,
    "release_claim_eligible": False, "publication_performed": False,
}
for reference in inputs.refs.values():
    manifest.require(ref(reference["path"]) == reference, "normative input changed during capture")
write(HERE / "CAPTURE.json", report)
print(json.dumps({key: report[key] for key in ("spec_lock", "compiled_descriptor", "packages",
                  "implementation_limits", "signature_purposes", "exports", "release_claim_eligible")}, indent=2))
