#!/usr/bin/env python3
"""Verify pinned Continuity package, export and specification identities.

This is a read-only consistency check, not release authorization. It never
builds a package, changes a freeze flag, qualifies a platform, or publishes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tomllib

import continuity_contract
from evidence_io import consume_regular_snapshot, parse_strict_json_bytes, read_regular_snapshot
from publication_receipt_io import canonical_json_bytes
from rust_sdk_profile import COHORT

VERSION = "0.2.0"
MANIFEST_KIND = "qperiapt.continuity_release_manifest"
LOCK_KIND = "qperiapt.continuity_spec_lock"
NORMATIVE_ROLES = frozenset({"protocol", "wire", "state", "storage", "metadata", "budgets", "upgrade"})
RELEASE_ROLES = frozenset({"sdk", "engine", "native", "swift", "kotlin", "android", "browser", "service"})
PACKAGE_ROLES = RELEASE_ROLES | {"independent"}
ROLE_FORMATS = {
    "sdk": {"cargo"}, "engine": {"cargo"},
    "native": {"distribution"}, "swift": {"distribution"},
    "kotlin": {"distribution"}, "android": {"distribution"},
    "browser": {"cargo", "npm"}, "service": {"cargo", "distribution"},
    "independent": {"distribution"},
}
GRAPH_FIELDS = ("id", "role", "name", "version", "format", "metadata", "workspace", "dependencies", "interfaces")
MAX_MANIFEST = 1024 * 1024
MAX_DOCUMENT = 2 * 1024 * 1024
MAX_ASSESSMENT = 16 * 1024 * 1024
MAX_ARTIFACT = 256 * 1024 * 1024
MAX_FILES = 1024
MAX_TOTAL_BYTES = 4 * 1024**3
SCOPE = (
    "Pinned manifest, normative-file, package-definition, artifact and export identity consistency. "
    "Assessment records retain their own scope; this check does not execute their validators, "
    "establish a clean checkout, authorize a release, or perform publication."
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def object_with_keys(value: object, keys: set[str] | frozenset[str], label: str) -> dict:
    require(type(value) is dict and set(value) == keys, f"{label} fields differ")
    return value


def digest(value: object, length: int, label: str) -> str:
    require(type(value) is str and re.fullmatch(rf"[0-9a-f]{{{length}}}", value) is not None,
            f"{label} is not an exact lowercase digest")
    return value


def relative_path(value: object) -> str:
    require(type(value) is str and 0 < len(value) <= 1024, "file path is empty or oversized")
    path = PurePosixPath(value)
    require(not path.is_absolute() and path.as_posix() == value and len(path.parts) <= 64
            and all(part not in {".", ".."} and len(part) <= 255
                    and re.fullmatch(r"[A-Za-z0-9_.-]+", part) is not None for part in path.parts),
            "file path must be a canonical relative path without traversal")
    return value


def file_ref(value: object, *, maximum: int) -> dict:
    row = object_with_keys(value, {"path", "bytes", "sha256"}, "file reference")
    relative_path(row["path"])
    require(type(row["bytes"]) is int and 0 < row["bytes"] <= maximum, "file byte bound differs")
    digest(row["sha256"], 64, "file SHA-256")
    return row


def canonical_digest(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def package_graph_digest(packages: list[dict]) -> str:
    """Hash package identities and edges, separately from per-build evidence."""
    return canonical_digest([{key: row[key] for key in GRAPH_FIELDS} for row in packages])


class Inputs:
    """Bounded snapshots; repeated paths must retain exactly the same pin."""

    def __init__(self, root: Path):
        self.root = Path(root).absolute()
        require(self.root.is_dir() and self.root.resolve() == self.root and not self.root.is_symlink(),
                "input root must be an existing canonical directory")
        self.refs: dict[str, dict] = {}
        self.total_bytes = 0
        self.workspace_selections: list[tuple[str, str]] = []

    def read(self, reference: object, *, maximum: int = MAX_DOCUMENT, binary: bool = False):
        ref = file_ref(reference, maximum=maximum)
        previous = self.refs.get(ref["path"])
        require(previous is None or previous == ref, "one file path has conflicting identities")
        if previous is None:
            require(len(self.refs) < MAX_FILES and self.total_bytes + ref["bytes"] <= MAX_TOTAL_BYTES,
                    "input inventory exceeds its file or total-byte bound")
        reader = consume_regular_snapshot if binary else read_regular_snapshot
        observed = reader(self.root / ref["path"], maximum=maximum, label="Continuity release input")
        require((observed.size, observed.sha256) == (ref["bytes"], ref["sha256"]),
                f"file bytes or digest differ: {ref['path']}")
        if previous is None:
            self.refs[ref["path"]] = dict(ref)
            self.total_bytes += ref["bytes"]
        return observed

    def json(self, reference: object, *, maximum: int = MAX_DOCUMENT):
        snapshot = self.read(reference, maximum=maximum)
        return parse_strict_json_bytes(snapshot.data, label=reference["path"])

    def unchanged(self) -> None:
        for ref in tuple(self.refs.values()):
            self.read(ref, maximum=MAX_ARTIFACT, binary=True)
        for package_path, workspace_path in self.workspace_selections:
            require(_nearest_workspace(self, package_path) == workspace_path,
                    "selected Cargo workspace changed during verification")


def _sequence(value: object, maximum: int, label: str, *, nonempty: bool = False) -> list:
    require(type(value) is list and int(nonempty) <= len(value) <= maximum,
            f"{label} is missing or oversized")
    return value


def _names(value: object, maximum: int, label: str) -> list[str]:
    rows = _sequence(value, maximum, label)
    require(all(type(row) is str and re.fullmatch(r"[A-Za-z0-9_.:@/+~-]{1,128}", row) is not None
                for row in rows) and len(set(rows)) == len(rows), f"{label} contains invalid or duplicate names")
    return rows


def _source(value: object) -> dict:
    source = object_with_keys(value, {"commit", "tree"}, "source identity")
    digest(source["commit"], 40, "source commit")
    digest(source["tree"], 40, "source tree")
    return source


def _contract(value: object, *, frozen: bool) -> dict:
    require(type(value) is dict and value.get("frozen_product_contract") is frozen,
            "descriptor freeze state differs from the selected stage")
    # Reuse the existing grammar and profile commitment, without changing that
    # historical candidate validator's mandatory false flag or the input bytes.
    continuity_contract.validate(dict(value, frozen_product_contract=False))
    return value


def _interfaces(value: object, inputs: Inputs, *, frozen: bool) -> dict[str, int]:
    interfaces = object_with_keys(value, {"sdk_c", "continuity_c"}, "interface inventory")
    counts = {}
    for name, expected_abi in (("sdk_c", 2), ("continuity_c", "qpc-owner/1")):
        row = object_with_keys(interfaces[name], {"abi", "package_version", "contract", "exports"}, name)
        require(type(row["abi"]) is type(expected_abi) and row["abi"] == expected_abi,
                f"{name} ABI namespace differs")
        exports = _names(row["exports"], 512, f"{name} exports")
        require(exports and exports == sorted(exports), f"{name} exports must be nonempty and sorted")
        document = inputs.json(row["contract"])
        require(type(document) is dict, f"{name} contract must be an object")
        if name == "sdk_c":
            require(type(document.get("schema")) is int and document["schema"] == 1
                    and document.get("kind") == "qperiapt.c_abi_contract", "SDK C contract identity differs")
            package, abi = document.get("package"), document.get("abi")
            require(type(package) is dict and type(abi) is dict
                    and type(package.get("abi_major")) is int and package["abi_major"] == 2
                    and type(abi.get("major")) is int and abi["major"] == 2
                    and package.get("semver") == row["package_version"] == VERSION,
                    "SDK C version or ABI differs")
            declared = _sequence(abi.get("exports"), 512, "SDK C declared exports", nonempty=True)
            require(all(type(item) is dict and type(item.get("name")) is str
                        and type(item.get("declaration")) is str
                        and re.search(r"\b" + re.escape(item["name"]) + r"\s*\(", item["declaration"])
                        for item in declared), "SDK C export declarations differ")
            observed = [item["name"] for item in declared]
            prefix = "q_periapt_"
        else:
            object_with_keys(document, {"schema_version", "abi", "package_version",
                                       "frozen_product_contract", "declarations"}, "Continuity C contract")
            require(type(document["schema_version"]) is int and document["schema_version"] == 1
                    and document["abi"] == "qpc-owner/1"
                    and document["package_version"] == row["package_version"]
                    and document["frozen_product_contract"] is frozen,
                    "Continuity C identity or freeze state differs")
            require(row["package_version"] in ({VERSION} if frozen else {"0.0.0", VERSION}),
                    "Continuity C package version differs")
            declarations = _sequence(document["declarations"], 1024, "Continuity C declarations", nonempty=True)
            require(all(type(item) is str and 0 < len(item) <= 65536 for item in declarations),
                    "Continuity C declarations are malformed")
            observed = [match[1] for item in declarations
                        if (match := re.fullmatch(r"int32_t (qpc_[a-z0-9_]+) \( .+ \) ;", item))]
            prefix = "qpc_"
        require(len(set(observed)) == len(observed) and sorted(observed) == exports
                and all(item.startswith(prefix) for item in exports), f"{name} export inventory differs")
        counts[name] = len(exports)
    return counts


def _local_metadata(inputs: Inputs, origin: dict, directory: object, leaf: str, label: str) -> str:
    """Resolve a manifest-relative directory, without accepting a symlink route."""
    require(type(directory) is str and 0 < len(directory) <= 1024
            and not PurePosixPath(directory).is_absolute() and "\\" not in directory
            and len(directory.split("/")) <= 64, f"{label} path is not a bounded relative directory")
    current = inputs.root / PurePosixPath(origin["path"]).parent
    for part in directory.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            require(current != inputs.root, f"{label} path escapes the selected root")
            current = current.parent
        else:
            require(re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", part) is not None,
                    f"{label} path component differs")
            current /= part
            require(not current.is_symlink() and current.is_dir(), f"{label} path is not a plain directory")
    return relative_path((current / leaf).relative_to(inputs.root).as_posix())


def _nearest_workspace(inputs: Inputs, package_path: str) -> str | None:
    current = (inputs.root / package_path).parent
    while True:
        candidate = current / "Cargo.toml"
        require(not candidate.is_symlink(), "selected Cargo workspace search crosses a symlink")
        if candidate.exists():
            observed = read_regular_snapshot(candidate, maximum=MAX_DOCUMENT, label="Cargo workspace selection")
            document = tomllib.loads(observed.data.decode("utf-8"))
            if "workspace" in document:
                require(type(document["workspace"]) is dict, "selected Cargo workspace table differs")
                return candidate.relative_to(inputs.root).as_posix()
        if current == inputs.root:
            return None
        current = current.parent


def _cargo_workspace(row: dict, document: dict, inputs: Inputs) -> tuple[dict, dict | None]:
    reference = row["workspace"]
    explicit = document["package"].get("workspace")
    if reference is None:
        require(explicit is None, "explicit Cargo workspace requires a pinned selection")
        table = document.get("workspace", {})
        require(type(table) is dict, "Cargo workspace table differs")
        return table, row["metadata"] if "workspace" in document else None
    selected = tomllib.loads(inputs.read(reference).data.decode("utf-8"))
    require(type(selected.get("workspace")) is dict, "selected Cargo workspace table is absent")
    if explicit is not None:
        require("workspace" not in document, "Cargo package cannot select two workspaces")
        expected = _local_metadata(inputs, row["metadata"], explicit, "Cargo.toml", "selected Cargo workspace")
    else:
        expected = _nearest_workspace(inputs, row["metadata"]["path"])
        inputs.workspace_selections.append((row["metadata"]["path"], reference["path"]))
    require(reference["path"] == expected, "selected Cargo workspace differs from package discovery")
    return selected["workspace"], reference


def _inherited_dependency(member: dict, alias: str, workspace: dict) -> dict:
    require(member.get("workspace") is True
            and set(member) <= {"workspace", "features", "optional", "default-features"},
            "Cargo inherited dependency overrides identity or source fields")
    dependencies = workspace.get("dependencies", {})
    require(type(dependencies) is dict, "Cargo workspace dependency table differs")
    base = dependencies.get(alias)
    base = {"version": base} if type(base) is str else base
    require(type(base) is dict and "workspace" not in base and "optional" not in base,
            "Cargo workspace dependency is unresolved or optional")
    merged = dict(base)
    for key in ("optional", "default-features"):
        if key in member:
            require(type(member[key]) is bool, "Cargo inherited dependency option differs")
            merged[key] = member[key]
    features = []
    for source in (base, member):
        if "features" in source:
            features.extend(_names(source["features"], 256, "Cargo inherited dependency features"))
    if features:
        merged["features"] = sorted(set(features))
    return merged


def _cargo_identity(row: dict, inputs: Inputs, by_name: dict[str, dict]) -> None:
    document = tomllib.loads(inputs.read(row["metadata"]).data.decode("utf-8"))
    package = document.get("package")
    require(type(package) is dict, "Cargo package definition is absent")
    workspace, workspace_origin = _cargo_workspace(row, document, inputs)
    version = package.get("version")
    if version == {"workspace": True}:
        require(type(version["workspace"]) is bool, "Cargo inherited version type differs")
        inherited = workspace.get("package", {})
        require(type(inherited) is dict, "Cargo workspace package table differs")
        version = inherited.get("version")
    require(package.get("name") == row["name"] and version == row["version"],
            f"Cargo package identity differs: {row['id']}")
    sections = [document]
    targets = document.get("target", {})
    require(type(targets) is dict and len(targets) <= 64, "Cargo target inventory differs")
    sections.extend(targets.values())
    observed = set()
    for section in sections:
        require(type(section) is dict, "Cargo dependency section differs")
        for field in ("dependencies", "build-dependencies"):
            dependencies = section.get(field, {})
            require(type(dependencies) is dict and len(dependencies) <= 256, "Cargo dependencies differ")
            for alias, specification in dependencies.items():
                spec = {"version": specification} if type(specification) is str else specification
                require(type(spec) is dict, "Cargo dependency definition differs")
                origin = row["metadata"]
                if "workspace" in spec:
                    require(workspace_origin is not None, "Cargo workspace dependency has no pinned workspace")
                    spec = _inherited_dependency(spec, alias, workspace)
                    origin = workspace_origin
                name = spec.get("package", alias)
                if type(name) is str and name.startswith("q-periapt-"):
                    require(name in by_name, f"Cargo dependency missing from package graph: {name}")
                    target = by_name[name]
                    require(spec.get("version") == "=" + target["version"],
                            f"Cargo dependency version differs: {name}")
                    require(not ({"git", "branch", "rev", "tag", "registry", "registry-index"} & set(spec)),
                            f"Cargo dependency source is outside the selected package graph: {name}")
                    if "path" in spec:
                        observed_path = _local_metadata(inputs, origin, spec["path"], "Cargo.toml", "Cargo dependency")
                        require(observed_path == target["metadata"]["path"], f"Cargo dependency path differs: {name}")
                    observed.add(target["id"])
    require(observed == set(row["dependencies"]), f"Cargo dependency graph differs: {row['id']}")


def _npm_identity(row: dict, document: dict, inputs: Inputs, cargo_names: dict, npm_names: dict) -> None:
    require(row["role"] == "browser" and type(document.get("exports")) is dict
            and "./web" in document["exports"], "browser package omitted its existing /web export")
    web = document["exports"]["./web"]
    if type(web) is dict:
        web = web.get("default")
    require(type(web) is str and web.startswith("./") and len(web) > 2,
            "browser /web export has no runtime target")
    relative_path(web[2:])
    observed = set()
    bridge = cargo_names.get(row["name"])
    if bridge is not None:
        require(bridge["role"] == "browser" and bridge["version"] == row["version"],
                "npm browser bridge identity differs")
        observed.add(bridge["id"])
    # npm optionalDependencies override same-named ordinary dependencies. Peer
    # requirements remain a separate constraint on the selected package version.
    tables = []
    for field in ("dependencies", "optionalDependencies", "peerDependencies"):
        table = document.get(field, {})
        require(type(table) is dict and len(table) <= 256, "npm dependency table differs")
        tables.append(table)
    for dependencies in (tables[0] | tables[1], tables[2]):
        for alias, specification in dependencies.items():
            require(type(specification) is str and 0 < len(specification) <= 512, "npm dependency specification differs")
            name, version = alias, specification
            if specification.startswith("npm:"):
                match = re.fullmatch(r"npm:((?:@[^/@]+/)?[^@]+)@(.+)", specification)
                require(match is not None, "npm dependency alias is malformed")
                name, version = match[1], match[2]
            if name not in npm_names and not name.startswith("q-periapt-") and not specification.startswith("file:"):
                continue
            if specification.startswith("file:"):
                path = _local_metadata(inputs, row["metadata"], specification[5:], "package.json", "npm dependency")
                matches = [candidate for candidate in npm_names.values() if candidate["metadata"]["path"] == path]
                require(len(matches) == 1, "npm dependency path differs from its package identity")
                target = matches[0]
            else:
                require(name in npm_names, f"npm dependency is missing from its ecosystem graph: {name}")
                target = npm_names[name]
                require(version in {target["version"], "=" + target["version"]}, f"npm dependency version differs: {name}")
            observed.add(target["id"])
    require(observed == set(row["dependencies"]), f"npm dependency graph differs: {row['id']}")


def _package_identity(row: dict, inputs: Inputs, cargo_names: dict[str, dict], npm_names: dict[str, dict], source: dict) -> None:
    if row["format"] == "cargo":
        _cargo_identity(row, inputs, cargo_names)
        return
    require(row["workspace"] is None, "non-Cargo package cannot inherit a Cargo workspace")
    document = inputs.json(row["metadata"])
    require(type(document) is dict and document.get("name") == row["name"]
            and document.get("version") == row["version"], f"package metadata identity differs: {row['id']}")
    if row["format"] == "npm":
        _npm_identity(row, document, inputs, cargo_names, npm_names)
    else:
        object_with_keys(document, {"schema_version", "kind", "name", "version", "source",
                                   "dependencies", "interfaces", "artifacts"}, "distribution identity")
        require(type(document["schema_version"]) is int and document["schema_version"] == 1
                and document["kind"] == "qperiapt.continuity_distribution_identity"
                and _source(document["source"]) == source
                and document["dependencies"] == row["dependencies"]
                and document["interfaces"] == row["interfaces"]
                and document["artifacts"] == row["artifacts"], "distribution identity binding differs")


def _packages(value: object, inputs: Inputs, *, stage: str, source: dict, interfaces: dict) -> dict:
    packages = _sequence(value, 64, "package inventory", nonempty=True)
    by_id, by_identity, cargo_names, npm_names = {}, {}, {}, {}
    roles = set()
    for row in packages:
        object_with_keys(row, set(GRAPH_FIELDS) | {"artifacts", "assessments"}, "package")
        require(type(row["id"]) is str and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", row["id"]) is not None
                and row["id"] not in by_id, "package ID is invalid or duplicated")
        _names([row["name"]], 1, "package name")
        require(type(row["role"]) is str and row["role"] in PACKAGE_ROLES
                and type(row["format"]) is str and row["format"] in {"cargo", "npm", "distribution"},
                "package role or format differs")
        require(row["format"] in ROLE_FORMATS[row["role"]], "package role does not match its actual surface format")
        identity = row["format"], row["name"]
        require(identity not in by_identity, "package ecosystem/name identity is duplicated")
        require(type(row["version"]) is str and re.fullmatch(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}", row["version"]),
                "package version is not an exact version")
        if row["role"] == "sdk" or (stage == "release" and row["role"] != "independent"):
            require(row["version"] == VERSION, "product package version differs")
        dependencies = _names(row["dependencies"], 64, "package dependencies")
        require(all(name in by_id for name in dependencies), "package dependency is missing, cyclic or out of build order")
        if row["role"] == "sdk":
            require(row["name"] in COHORT and all(by_id[name]["role"] == "sdk" for name in dependencies),
                    "SDK dependency direction or cohort differs")
        if row["role"] == "engine":
            require(all(by_id[name]["role"] == "sdk" for name in dependencies), "engine dependency direction differs")
        names = _names(row["interfaces"], 2, "package interfaces")
        require(set(names) <= {"sdk_c", "continuity_c"}, "package interface namespace differs")
        if row["role"] == "native":
            require("continuity_c" in names and row["version"] == interfaces["continuity_c"]["package_version"],
                    "native companion and Continuity C package identities differ")
        for name in names:
            require(row["version"] == interfaces[name]["package_version"], "package and interface versions differ")
        for field in ("artifacts", "assessments"):
            refs = _sequence(row[field], 32, f"package {field}", nonempty=stage == "release")
            paths = [file_ref(ref, maximum=MAX_ARTIFACT if field == "artifacts" else MAX_ASSESSMENT)["path"] for ref in refs]
            require(len(set(paths)) == len(paths), f"package {field} contains duplicates")
        by_id[row["id"]] = row
        by_identity[identity] = row
        if row["format"] == "cargo":
            cargo_names[row["name"]] = row
        elif row["format"] == "npm":
            npm_names[row["name"]] = row
        roles.add(row["role"])
    require(sum(row["role"] == "engine" for row in packages) == 1, "package graph must name one Continuity engine")
    if stage == "release":
        require(RELEASE_ROLES <= roles and {row["name"] for row in packages if row["role"] == "sdk"} == set(COHORT),
                "release package graph omits an agreed surface or SDK crate")
        require(any(row["role"] == "browser" and row["format"] == "npm" for row in packages),
                "release browser surface requires its actual npm package")
    assessments = []
    artifacts = 0
    for row in packages:
        _package_identity(row, inputs, cargo_names, npm_names, source)
        for ref in row["artifacts"]:
            inputs.read(ref, maximum=MAX_ARTIFACT, binary=True)
            artifacts += 1
        for ref in row["assessments"]:
            report = inputs.json(ref, maximum=MAX_ASSESSMENT)
            require(type(report) is dict and type(report.get("kind")) is str, "assessment report identity is absent")
            if stage == "release":
                require(report.get("completed") is True and "failure" not in report,
                        "release manifest includes an incomplete assessment")
            assessments.append({"package": row["id"], "path": ref["path"], "sha256": ref["sha256"],
                                "kind": report["kind"], "completed": report.get("completed") is True})
    return {"packages": len(packages), "roles": sorted(roles), "missing_release_roles": sorted(RELEASE_ROLES - roles),
            "artifacts": artifacts, "assessments": assessments}


def verify_manifest(root: Path, manifest_path: str, *, expected_sha256: str,
                    source_commit: str, source_tree: str, stage: str) -> dict:
    """Compare actual bytes with independently supplied manifest/source pins."""
    require(stage in {"candidate", "release"}, "selected stage differs")
    digest(expected_sha256, 64, "selected manifest SHA-256")
    expected_source = _source({"commit": source_commit, "tree": source_tree})
    inputs = Inputs(root)
    path = relative_path(manifest_path)
    snapshot = read_regular_snapshot(inputs.root / path, maximum=MAX_MANIFEST, label="Continuity release manifest")
    require(snapshot.sha256 == expected_sha256, "manifest digest differs from independent selection")
    inputs.read({"path": path, "bytes": snapshot.size, "sha256": snapshot.sha256}, maximum=MAX_MANIFEST)
    manifest = parse_strict_json_bytes(snapshot.data, label="Continuity release manifest")
    object_with_keys(manifest, {"schema_version", "kind", "stage", "product_version", "source", "spec_lock",
                                "packages", "interfaces", "release_claim_eligible", "publication_performed"}, "manifest")
    require(type(manifest["schema_version"]) is int and manifest["schema_version"] == 1
            and manifest["kind"] == MANIFEST_KIND and manifest["stage"] == stage
            and manifest["product_version"] == VERSION, "manifest identity or selected stage differs")
    require(manifest["release_claim_eligible"] is False and manifest["publication_performed"] is False,
            "identity manifest cannot authorize release or claim publication")
    require(_source(manifest["source"]) == expected_source, "manifest source differs from independent selection")
    file_ref(manifest["spec_lock"], maximum=MAX_MANIFEST)
    require(manifest["spec_lock"]["path"] != path, "manifest cannot reference itself as its lock")
    lock = inputs.json(manifest["spec_lock"], maximum=MAX_MANIFEST)
    object_with_keys(lock, {"schema_version", "kind", "stage", "product_version", "frozen_product_contract",
                           "normative_files", "supporting_files", "compiled_descriptor", "package_graph_sha256",
                           "interfaces_sha256"}, "specification lock")
    frozen = stage == "release"
    require(type(lock["schema_version"]) is int and lock["schema_version"] == 1 and lock["kind"] == LOCK_KIND
            and lock["stage"] == stage and lock["product_version"] == VERSION
            and lock["frozen_product_contract"] is frozen, "specification lock identity or freeze state differs")
    normative = object_with_keys(lock["normative_files"], NORMATIVE_ROLES, "normative inventory")
    references = list(normative.values()) + _sequence(lock["supporting_files"], 256, "supporting normative files")
    paths = [file_ref(ref, maximum=MAX_DOCUMENT)["path"] for ref in references]
    require(len(set(paths)) == len(paths) and path not in paths and manifest["spec_lock"]["path"] not in paths,
            "normative inventory repeats a path or includes a self-reference")
    for ref in references:
        inputs.read(ref)
    reviewed = _contract(inputs.json(normative["budgets"]), frozen=frozen)
    compiled = lock["compiled_descriptor"]
    require(compiled is not None or not frozen, "release lock omits the compiled descriptor")
    if compiled is not None:
        require(file_ref(compiled, maximum=MAX_DOCUMENT)["path"] not in paths
                and compiled["path"] not in {path, manifest["spec_lock"]["path"]},
                "compiled descriptor must be a separate retained output")
        require(_contract(inputs.json(compiled), frozen=frozen) == reviewed, "compiled descriptor differs from normative budgets")
    exports = _interfaces(manifest["interfaces"], inputs, frozen=frozen)
    summary = _packages(manifest["packages"], inputs, stage=stage, source=expected_source, interfaces=manifest["interfaces"])
    graph_digest = package_graph_digest(manifest["packages"])
    require(digest(lock["package_graph_sha256"], 64, "locked package graph") == graph_digest,
            "package graph differs from the specification lock")
    interface_digest = canonical_digest(manifest["interfaces"])
    require(digest(lock["interfaces_sha256"], 64, "locked interfaces") == interface_digest,
            "interface identities differ from the specification lock")
    inputs.unchanged()
    return {"schema_version": 1, "kind": "qperiapt.continuity_release_manifest_verification", "completed": True,
            "stage": stage, "source": expected_source, "manifest_sha256": snapshot.sha256,
            "spec_lock_sha256": manifest["spec_lock"]["sha256"], "package_graph_sha256": graph_digest,
            "interfaces_sha256": interface_digest, "compiled_descriptor_matched": compiled is not None,
            "exports": exports, "files": len(inputs.refs), **summary,
            "release_claim_eligible": False, "publication_performed": False, "scope": SCOPE}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--manifest", required=True, help="canonical path relative to --root")
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--stage", choices=("candidate", "release"), required=True)
    args = parser.parse_args(argv)
    result = verify_manifest(args.root, args.manifest, expected_sha256=args.manifest_sha256,
                             source_commit=args.source_commit, source_tree=args.source_tree, stage=args.stage)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
