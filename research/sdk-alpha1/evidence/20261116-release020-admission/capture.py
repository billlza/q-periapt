#!/usr/bin/env python3
"""Capture an unfrozen 0.2.0 identity inventory from independently pinned source.

This script prepares candidate distribution identities. It does not invoke any
producer, fabricate assessment receipts, select built artifacts, or freeze a
contract. The existing manifest verifier remains the identity acceptance check.
"""
from __future__ import annotations

import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib


NORMATIVE = {
    "protocol": "docs/continuity/PROTOCOL_V1.md",
    "wire": "docs/continuity/WIRE_V1.md",
    "state": "docs/continuity/STATE_MACHINE_V1.md",
    "storage": "docs/continuity/STORAGE_RECOVERY_V1.md",
    "metadata": "docs/continuity/METADATA_PRIVACY_V1.md",
    "budgets": "docs/continuity/BUDGETS_V1.json",
    "upgrade": "docs/continuity/UPGRADE_MAINTENANCE_V1.md",
}
SUPPORTING = (
    "docs/continuity/PREKEY_SELECTION_V1.md",
    "docs/continuity/SEND_PROGRESS_V1.md",
    "docs/continuity/G1_EFFECT_LIFECYCLE.md",
    "docs/PRIVATE_PUBLICATION_MAINTENANCE.md",
    "docs/SDK_CONNECTION.md",
    "research/continuity-identity-candidate/ENROLLMENT.md",
    "research/continuity-identity-candidate/BOOTSTRAP.md",
    "research/continuity-identity-candidate/CREDENTIAL_RENEWAL.md",
    "research/continuity-identity-candidate/AUTHORITY_REPLACEMENT.md",
    "research/continuity-identity-candidate/ANCHOR_WITNESS.md",
    "research/continuity-identity-candidate/REKEY_OFFERS.md",
    "research/continuity-identity-candidate/MESSAGES.md",
    "research/continuity-identity-candidate/WRITE_INTENTS.md",
    "research/continuity-identity-candidate/PENDING_WRITE_RECOVERY.md",
    "research/continuity-identity-candidate/POLICY_CONTINUATION.md",
    "research/continuity-identity-candidate/FANOUT.md",
    "research/continuity-identity-candidate/CONTROL_PROGRESS.md",
    "research/continuity-reference-app/DIRECTORY_LEASES.md",
    "docs/continuity/SUPPORTED_WORKLOAD_BUDGETS_0_2.md",
    "docs/continuity/COMPATIBILITY_0_2.md",
    "docs/continuity/SOURCE_DISTRIBUTION_0_2.md",
    "docs/continuity/NATIVE_DISTRIBUTION_0_2.md",
    "docs/continuity/SERVICE_DISTRIBUTION_0_2.md",
    "docs/continuity/ANDROID_DISTRIBUTION_0_2.md",
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--source-repository", type=Path,
                        help="Git object repository for a separate source snapshot; defaults to --root")
    parser.add_argument("--output", required=True, help="new file names under this repository-relative directory")
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    repository = (args.source_repository or root).resolve(strict=True)
    sys.path.insert(0, str(root / "artifact"))
    import continuity_release_manifest as contract
    from evidence_io import read_regular_snapshot

    contract.digest(args.source_commit, 40, "selected source commit")
    contract.digest(args.source_tree, 40, "selected source tree")
    output = contract.relative_path(args.output)

    def git(*arguments: str) -> bytes:
        return subprocess.run(
            ["/usr/bin/git", "-C", str(repository), "-c", "core.fsmonitor=false", *arguments],
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
                 "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
                 "GIT_NO_REPLACE_OBJECTS": "1", "GIT_OPTIONAL_LOCKS": "0"},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=30,
        ).stdout

    observed_tree = git("rev-parse", "--verify", args.source_commit + "^{tree}").decode().strip()
    contract.require(observed_tree == args.source_tree, "independently selected commit/tree differ")
    entries = {}
    for entry in git("ls-tree", "-rz", "--full-tree", args.source_commit).split(b"\0"):
        if entry:
            metadata, path = entry.split(b"\t", 1)
            mode, kind, blob = metadata.decode().split()
            entries[path.decode()] = (mode, kind, blob)
    pins = {}

    def source_bytes(path: str) -> bytes:
        contract.relative_path(path)
        mode, kind, expected_blob = entries[path]
        contract.require(mode in {"100644", "100755"} and kind == "blob", "source is not a regular Git blob")
        snap = read_regular_snapshot(root / path, maximum=contract.MAX_DOCUMENT, label="selected source input")
        actual_blob = hashlib.sha1(b"blob " + str(snap.size).encode() + b"\0" + snap.data).hexdigest()
        contract.require(actual_blob == expected_blob, "source bytes differ from selected Git blob: " + path)
        pin = {"path": path, "bytes": snap.size, "sha256": snap.sha256, "git_blob": expected_blob}
        contract.require(path not in pins or pins[path] == pin, "source changed during capture")
        pins[path] = pin
        return snap.data

    def ref(path: str) -> dict:
        source_bytes(path)
        return {key: pins[path][key] for key in ("path", "bytes", "sha256")}

    def write(name: str, value: object) -> dict:
        path = contract.relative_path(output + "/" + name)
        destination = root / path
        for parent in (destination, *destination.parents):
            contract.require(not parent.is_symlink(), "output path crosses a symlink")
            if parent == root:
                break
        destination.parent.mkdir(parents=True, exist_ok=True)
        data = contract.canonical_json_bytes(value)
        with destination.open("xb") as stream:
            stream.write(data)
        return {"path": path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    for path in ("artifact/continuity_release_manifest.py", "artifact/continuity_contract.py",
                 "artifact/evidence_io.py", "artifact/publication_receipt_io.py", "artifact/rust_sdk_profile.py"):
        source_bytes(path)
    workspace = tomllib.loads(source_bytes("Cargo.toml").decode())
    workspace_ref = ref("Cargo.toml")
    definitions = [(name, "sdk", "crates/" + name + "/Cargo.toml") for name in contract.COHORT]
    definitions += [
        ("continuity-engine", "engine", "research/continuity-identity-candidate/Cargo.toml"),
        ("browser-bridge", "browser", "crates/q-periapt-sdk-wasm/Cargo.toml"),
        ("reference-service", "service", "research/continuity-reference-app/Cargo.toml"),
    ]
    packages, cargo_documents = [], {}
    for identifier, role, path in definitions:
        document = tomllib.loads(source_bytes(path).decode())
        package = document["package"]
        inherited = package["version"] == {"workspace": True}
        version = workspace["workspace"]["package"]["version"] if inherited else package["version"]
        row = {"id": identifier, "role": role, "name": package["name"], "version": version, "format": "cargo",
               "metadata": ref(path), "workspace": workspace_ref if inherited else None,
               "dependencies": [], "interfaces": (["sdk_c"] if identifier == "q-periapt-ffi" else
                                                     ["continuity_c"] if role == "engine" else []),
               "artifacts": [], "assessments": []}
        packages.append(row)
        cargo_documents[identifier] = document
    name_to_id = {row["name"]: row["id"] for row in packages}
    order = {row["id"]: position for position, row in enumerate(packages)}
    for row in packages:
        document = cargo_documents[row["id"]]
        dependencies = set()
        for section in (document, *document.get("target", {}).values()):
            for field in ("dependencies", "build-dependencies"):
                for alias, raw_spec in section.get(field, {}).items():
                    spec = {"version": raw_spec} if isinstance(raw_spec, str) else raw_spec
                    contract.require("workspace" not in spec, "capture needs an explicit dependency-inheritance update")
                    name = spec.get("package", alias)
                    if name.startswith("q-periapt-"):
                        contract.require(name in name_to_id, "internal dependency missing from capture inventory")
                        dependencies.add(name_to_id[name])
        row["dependencies"] = sorted(dependencies, key=order.__getitem__)

    npm_path = "crates/q-periapt-sdk-wasm/package/package.json"
    npm = json.loads(source_bytes(npm_path))
    packages.append({"id": "browser-web", "role": "browser", "name": npm["name"], "version": npm["version"],
                     "format": "npm", "metadata": ref(npm_path), "workspace": None,
                     "dependencies": ["browser-bridge"], "interfaces": [], "artifacts": [], "assessments": []})
    sdk_path = "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2-sdk-020.json"
    owner_path = "bindings/c/ContinuityPackageConsumer/abi/qpc-owner-v1.json"
    sdk_abi, owner_abi = json.loads(source_bytes(sdk_path)), json.loads(source_bytes(owner_path))
    interfaces = {
        "sdk_c": {"abi": 2, "package_version": sdk_abi["package"]["semver"], "contract": ref(sdk_path),
                  "exports": sorted(row["name"] for row in sdk_abi["abi"]["exports"])},
        "continuity_c": {"abi": "qpc-owner/1", "package_version": owner_abi["package_version"], "contract": ref(owner_path),
                         "exports": sorted(match[1] for row in owner_abi["declarations"]
                                           if (match := re.fullmatch(r"int32_t (qpc_[a-z0-9_]+) \( .+ \) ;", row)))},
    }
    source = {"commit": args.source_commit, "tree": args.source_tree}
    projections = []

    def literal_identity(path: str) -> tuple[str, str]:
        values = {}
        for statement in ast.parse(source_bytes(path)).body:
            if not isinstance(statement, ast.Assign):
                continue
            for target in statement.targets:
                names = [target.id] if isinstance(target, ast.Name) else (
                    [node.id for node in target.elts] if isinstance(target, ast.Tuple)
                    and all(isinstance(node, ast.Name) for node in target.elts) else [])
                if {"NAME", "VERSION"} & set(names):
                    literal = ast.literal_eval(statement.value)
                    members = [literal] if len(names) == 1 else literal
                    values.update(zip(names, members, strict=True))
        contract.require(type(values.get("NAME")) is str and values.get("VERSION") == "0.2.0",
                         "producer package identity differs")
        return values["NAME"], values["VERSION"]

    def distribution(identifier: str, role: str, name: str, version: str,
                     dependency: str, definitions: list[str], interface: bool = True) -> None:
        identity = {"schema_version": 1, "kind": "qperiapt.continuity_distribution_identity",
                    "name": name, "version": version, "source": source, "dependencies": [dependency],
                    "interfaces": ["continuity_c"] if interface else [], "artifacts": []}
        metadata = write("distributions/" + identifier + ".json", identity)
        packages.append({"id": identifier, "role": role, "name": name, "version": version,
                         "format": "distribution", "metadata": metadata, "workspace": None,
                         "dependencies": identity["dependencies"], "interfaces": identity["interfaces"],
                         "artifacts": [], "assessments": []})
        projections.append({"package": identifier, "metadata": metadata,
                            "definitions": [ref(path) for path in definitions],
                            "built_artifacts_selected": False, "producer_executed_by_capture": False})

    native = "artifact/continuity_native_package.py"
    apple = "artifact/continuity_apple_package.py"
    android = "artifact/continuity_android_distribution.py"
    service = "artifact/continuity_service_package.py"
    distribution("continuity-native", "native", *literal_identity(native), "continuity-engine", [native])
    distribution("continuity-swift", "swift", *literal_identity(apple), "continuity-engine", [apple])
    kotlin_build = "bindings/kotlin/ContinuityPackageConsumer/build.gradle.kts"
    kotlin_settings = "bindings/kotlin/ContinuityPackageConsumer/settings.gradle.kts"
    kotlin_version = re.findall(r'^version = "([^"]+)"$', source_bytes(kotlin_build).decode(), re.M)
    kotlin_name = re.findall(r'^rootProject.name = "([^"]+)"$', source_bytes(kotlin_settings).decode(), re.M)
    contract.require(kotlin_version == ["0.2.0"] and len(kotlin_name) == 1, "Kotlin package identity differs")
    distribution("continuity-kotlin", "kotlin", kotlin_name[0], kotlin_version[0], "continuity-engine",
                 [kotlin_build, kotlin_settings, "artifact/continuity_kotlin_consumer.py"])
    distribution("continuity-android", "android", *literal_identity(android), "continuity-native", [android])
    distribution("continuity-services", "service", *literal_identity(service), "continuity-engine", [service], False)

    lock = {"schema_version": 2, "kind": contract.LOCK_KIND, "stage": "candidate", "product_version": "0.2.0",
            "frozen_product_contract": False, "normative_files": {role: ref(path) for role, path in NORMATIVE.items()},
            "supporting_files": [ref(path) for path in SUPPORTING], "compiled_descriptor": None,
            "package_graph_sha256": contract.package_graph_digest(packages, schema_version=2),
            "interfaces_sha256": contract.canonical_digest(interfaces)}
    manifest = {"schema_version": 1, "kind": contract.MANIFEST_KIND, "stage": "candidate", "product_version": "0.2.0",
                "source": source, "spec_lock": write("SPEC_LOCK.json", lock), "packages": packages,
                "interfaces": interfaces, "release_claim_eligible": False, "publication_performed": False}
    selected = write("MANIFEST.json", manifest)
    result = contract.verify_manifest(root, selected["path"], expected_sha256=selected["sha256"],
                                      source_commit=args.source_commit, source_tree=args.source_tree, stage="candidate")
    verification = write("VERIFICATION.json", result)
    for path in tuple(pins):
        source_bytes(path)
    capture = {"schema_version": 1, "kind": "qperiapt.continuity_candidate_inventory_capture", "completed": True,
               "captured_at": datetime.now(timezone.utc).isoformat(), "source": source,
               "python": sys.version, "manifest": selected, "verification": verification,
               "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               "source_files": sorted(pins.values(), key=lambda row: row["path"]),
               "candidate_distribution_projections": projections,
               "compiled_descriptor_selected": False, "built_artifacts_selected": False,
               "assessment_receipts_selected": False, "frozen_product_contract": False,
               "release_claim_eligible": False, "publication_performed": False,
               "scope": "Selected source bytes match the pinned Git blobs; prepared distribution identities contain no built artifacts or assessments. No whole-checkout, runtime-qualification, security-admission or publication claim."}
    write("CAPTURE.json", capture)
    print(json.dumps({"manifest": selected, "source_files_checked": len(pins), "verification": result}, indent=2))


if __name__ == "__main__":
    main()
