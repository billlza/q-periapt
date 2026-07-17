#!/usr/bin/env python3
"""Collect and verify third-party Rust license texts for binary distributions."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from typing import Any, NoReturn

from evidence_io import (
    EvidenceIOError,
    load_json_object_snapshot,
    parse_strict_json_bytes,
    read_regular_snapshot,
)


SCHEMA_VERSION = 1
KIND = "qperiapt.third_party_rust_licenses"
ROOT_PACKAGE = "q-periapt-ffi"
INVENTORY_RELATIVE = pathlib.PurePosixPath("THIRD_PARTY/rust/INVENTORY.json")
MAX_METADATA_BYTES = 64 * 1024 * 1024
MAX_LICENSE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_LICENSE_BYTES = 64 * 1024 * 1024
MAX_LICENSE_FILES = 1024
PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
VERSION_RE = re.compile(r"^[0-9A-Za-z.+-]+$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TARGET_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
LICENSE_PREFIXES = (
    "COPYING",
    "COPYRIGHT",
    "LICENSE",
    "LICENCE",
    "NOTICE",
    "UNLICENSE",
)


class ThirdPartyLicenseError(ValueError):
    """Third-party license evidence is incomplete, ambiguous, or changed."""


@dataclass(frozen=True, slots=True)
class LicenseFile:
    source: pathlib.Path
    name: str
    data: bytes
    sha256: str


def fail(message: str) -> NoReturn:
    raise ThirdPartyLicenseError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode(
        "utf-8"
    )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _regular_directory(path: pathlib.Path, label: str) -> pathlib.Path:
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as exc:
        fail(f"cannot inspect {label} {path}: {exc}")
    require(stat.S_ISDIR(metadata.st_mode) and not path.is_symlink(), f"{label} must be a non-symlink directory: {path}")
    return resolved


def _cargo_environment(root: pathlib.Path) -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "LC_ALL": "C",
        "LANG": "C",
        "CARGO_TERM_COLOR": "never",
    }
    for name in (
        "CARGO_HOME",
        "RUSTUP_HOME",
        "CARGO_HTTP_MULTIPLEXING",
        "CARGO_NET_RETRY",
    ):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    require(environment["PATH"] != "", "PATH is required to locate cargo")
    return environment


def _cargo_metadata(root: pathlib.Path, target: str) -> dict[str, Any]:
    require(TARGET_RE.fullmatch(target) is not None, f"invalid Rust target triple: {target!r}")
    cargo = shutil.which("cargo", path=os.environ.get("PATH"))
    require(cargo is not None, "cargo is required to collect third-party licenses")
    try:
        process = subprocess.run(
            [
                cargo,
                "metadata",
                "--locked",
                "--format-version",
                "1",
                "--filter-platform",
                target,
            ],
            cwd=root,
            env=_cargo_environment(root),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        fail("cannot execute cargo metadata")
    except subprocess.CalledProcessError as exc:
        fail(f"cargo metadata failed with exit code {exc.returncode}")
    require(len(process.stdout) <= MAX_METADATA_BYTES, "cargo metadata exceeds size limit")
    try:
        value = parse_strict_json_bytes(process.stdout, label="cargo metadata")
    except EvidenceIOError as exc:
        fail(f"cannot parse cargo metadata: {exc}")
    require(isinstance(value, dict), "cargo metadata root is not an object")
    return value


def _production_dependency_ids(metadata: dict[str, Any]) -> tuple[set[str], dict[str, dict[str, Any]]]:
    raw_packages = metadata.get("packages")
    resolve = metadata.get("resolve")
    require(isinstance(raw_packages, list), "cargo metadata packages are missing")
    require(isinstance(resolve, dict), "cargo metadata resolve graph is missing")
    raw_nodes = resolve.get("nodes")
    require(isinstance(raw_nodes, list), "cargo metadata resolve nodes are missing")

    packages: dict[str, dict[str, Any]] = {}
    for package in raw_packages:
        require(isinstance(package, dict), "cargo metadata package is not an object")
        package_id = package.get("id")
        require(isinstance(package_id, str) and package_id not in packages, "cargo metadata has a missing or duplicate package id")
        packages[package_id] = package

    nodes: dict[str, dict[str, Any]] = {}
    for node in raw_nodes:
        require(isinstance(node, dict), "cargo metadata node is not an object")
        node_id = node.get("id")
        require(isinstance(node_id, str) and node_id not in nodes, "cargo metadata has a missing or duplicate node id")
        nodes[node_id] = node

    roots = [
        package_id
        for package_id, package in packages.items()
        if package.get("name") == ROOT_PACKAGE and package.get("source") is None
    ]
    require(len(roots) == 1, f"cargo metadata must contain exactly one workspace {ROOT_PACKAGE} package")
    pending = [roots[0]]
    seen = {roots[0]}
    while pending:
        current = pending.pop()
        node = nodes.get(current)
        require(node is not None, f"cargo resolve graph lacks node {current}")
        dependencies = node.get("deps")
        require(isinstance(dependencies, list), f"cargo resolve node lacks dependencies: {current}")
        for dependency in dependencies:
            require(isinstance(dependency, dict), f"cargo dependency edge is malformed: {current}")
            dep_id = dependency.get("pkg")
            dep_kinds = dependency.get("dep_kinds")
            require(isinstance(dep_id, str) and dep_id in packages, f"cargo dependency edge has unknown package: {current}")
            require(isinstance(dep_kinds, list) and dep_kinds, f"cargo dependency edge lacks kinds: {current} -> {dep_id}")
            production = False
            for dep_kind in dep_kinds:
                require(isinstance(dep_kind, dict), f"cargo dependency kind is malformed: {current} -> {dep_id}")
                kind = dep_kind.get("kind")
                require(kind in {None, "build", "dev"}, f"cargo dependency kind is unsupported: {kind!r}")
                production = production or kind in {None, "build"}
            if production and dep_id not in seen:
                seen.add(dep_id)
                pending.append(dep_id)
    return seen, packages


def _lock_checksums(root: pathlib.Path) -> dict[tuple[str, str, str], str]:
    try:
        snapshot = read_regular_snapshot(
            root / "Cargo.lock",
            maximum=16 * 1024 * 1024,
            label="Cargo.lock",
        )
        document = tomllib.loads(snapshot.data.decode("utf-8"))
    except (EvidenceIOError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        fail(f"cannot load Cargo.lock: {exc}")
    raw_packages = document.get("package")
    require(isinstance(raw_packages, list), "Cargo.lock package list is missing")
    checksums: dict[tuple[str, str, str], str] = {}
    for package in raw_packages:
        require(isinstance(package, dict), "Cargo.lock package entry is malformed")
        name = package.get("name")
        version = package.get("version")
        source = package.get("source")
        checksum = package.get("checksum")
        if source is None:
            continue
        require(all(isinstance(value, str) and value for value in (name, version, source)), "Cargo.lock external package identity is malformed")
        key = (name, version, source)
        require(key not in checksums, f"Cargo.lock has duplicate external package: {name} {version}")
        if source.startswith("registry+"):
            require(isinstance(checksum, str) and SHA256_RE.fullmatch(checksum) is not None, f"registry package lacks checksum: {name} {version}")
            checksums[key] = checksum
        else:
            require(checksum is None or (isinstance(checksum, str) and SHA256_RE.fullmatch(checksum) is not None), f"external package checksum is malformed: {name} {version}")
            checksums[key] = checksum or ""
    return checksums


def _license_candidates(
    package: dict[str, Any],
    *,
    maximum_files: int,
    maximum_total_bytes: int,
) -> tuple[LicenseFile, ...]:
    manifest_path = pathlib.Path(str(package.get("manifest_path", "")))
    try:
        manifest_snapshot = read_regular_snapshot(
            manifest_path,
            maximum=4 * 1024 * 1024,
            label="dependency Cargo.toml",
        )
    except EvidenceIOError as exc:
        fail(str(exc))
    require(manifest_snapshot.path.name == "Cargo.toml", f"dependency manifest is not Cargo.toml: {manifest_path}")
    package_root = _regular_directory(manifest_path.parent, "dependency package root")

    explicit = package.get("license_file")
    candidates: list[pathlib.Path] = []
    if explicit is not None:
        require(isinstance(explicit, str) and explicit, f"dependency license_file is malformed: {package.get('name')}")
        explicit_path = pathlib.Path(explicit)
        if not explicit_path.is_absolute():
            explicit_path = package_root / explicit_path
        candidates.append(explicit_path)
    else:
        try:
            children = sorted(package_root.iterdir(), key=lambda item: item.name.encode("utf-8"))
        except OSError as exc:
            fail(f"cannot enumerate dependency package root {package_root}: {exc}")
        for child in children:
            upper = child.name.upper()
            if upper.startswith(LICENSE_PREFIXES):
                candidates.append(child)

    name = package.get("name")
    version = package.get("version")
    require(candidates, f"dependency has no distributable license text: {name} {version}")
    require(
        len(candidates) <= maximum_files,
        "third-party license file count exceeds limit",
    )
    files: list[LicenseFile] = []
    names: set[str] = set()
    total_bytes = 0
    for path in candidates:
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(package_root)
        except (OSError, ValueError) as exc:
            fail(f"dependency license escapes package root for {name} {version}: {path}: {exc}")
        require(path.name not in {"", ".", ".."} and "/" not in path.name and "\\" not in path.name, f"dependency license filename is invalid: {path.name!r}")
        folded = path.name.casefold()
        require(folded not in names, f"dependency license filenames collide: {name} {version} {path.name}")
        names.add(folded)
        try:
            snapshot = read_regular_snapshot(
                path,
                maximum=MAX_LICENSE_BYTES,
                label=f"dependency license {name} {version} {path.name}",
            )
        except EvidenceIOError as exc:
            fail(str(exc))
        require(snapshot.size > 0, f"dependency license is empty: {name} {version} {path.name}")
        total_bytes += snapshot.size
        require(
            total_bytes <= maximum_total_bytes,
            "third-party license text total exceeds limit",
        )
        files.append(
            LicenseFile(
                source=resolved,
                name=path.name,
                data=snapshot.data,
                sha256=snapshot.sha256,
            )
        )
    return tuple(sorted(files, key=lambda item: item.name.encode("utf-8")))


def collect(root: pathlib.Path, package_root: pathlib.Path, target: str) -> dict[str, Any]:
    repository = _regular_directory(root, "repository root")
    output_root = _regular_directory(package_root, "binary package root")
    rust_root = output_root / "THIRD_PARTY" / "rust"
    require(not rust_root.exists() and not rust_root.is_symlink(), f"third-party Rust license output already exists: {rust_root}")

    metadata = _cargo_metadata(repository, target)
    dependency_ids, packages = _production_dependency_ids(metadata)
    checksums = _lock_checksums(repository)
    external = [packages[package_id] for package_id in dependency_ids if packages[package_id].get("source") is not None]
    external.sort(key=lambda package: (str(package.get("name")), str(package.get("version")), str(package.get("source"))))
    require(external, "q-periapt-ffi production dependency closure has no external packages")
    require(len(external) <= MAX_LICENSE_FILES, "third-party package count exceeds limit")

    inventory_packages: list[dict[str, Any]] = []
    planned_files: list[tuple[str, tuple[LicenseFile, ...]]] = []
    destination_names: set[str] = set()
    license_file_count = 0
    total_bytes = 0
    for package in external:
        name = package.get("name")
        version = package.get("version")
        source = package.get("source")
        expression = package.get("license")
        require(isinstance(name, str) and PACKAGE_NAME_RE.fullmatch(name) is not None, f"dependency name is invalid: {name!r}")
        require(isinstance(version, str) and VERSION_RE.fullmatch(version) is not None, f"dependency version is invalid: {name} {version!r}")
        require(isinstance(source, str) and source, f"dependency source is missing: {name} {version}")
        require(isinstance(expression, str) and expression.strip() == expression and expression, f"dependency license expression is missing: {name} {version}")
        checksum_key = (name, version, source)
        require(checksum_key in checksums, f"dependency is absent from Cargo.lock: {name} {version}")
        destination_name = f"{name}-{version}"
        folded_destination = destination_name.casefold()
        require(folded_destination not in destination_names, f"dependency output path collision: {destination_name}")
        destination_names.add(folded_destination)
        require(
            license_file_count < MAX_LICENSE_FILES,
            "third-party license file count exceeds limit",
        )
        files = _license_candidates(
            package,
            maximum_files=MAX_LICENSE_FILES - license_file_count,
            maximum_total_bytes=MAX_TOTAL_LICENSE_BYTES - total_bytes,
        )
        license_file_count += len(files)
        require(
            license_file_count <= MAX_LICENSE_FILES,
            "third-party license file count exceeds limit",
        )
        planned_files.append((destination_name, files))
        inventory_files: list[dict[str, Any]] = []
        for license_file in files:
            total_bytes += len(license_file.data)
            require(total_bytes <= MAX_TOTAL_LICENSE_BYTES, "third-party license text total exceeds limit")
            inventory_files.append(
                {
                    "bytes": len(license_file.data),
                    "path": f"THIRD_PARTY/rust/{destination_name}/{license_file.name}",
                    "sha256": license_file.sha256,
                }
            )
        inventory_packages.append(
            {
                "checksum": checksums[checksum_key] or None,
                "license_expression": expression,
                "name": name,
                "source": source,
                "version": version,
                "license_files": inventory_files,
            }
        )

    inventory = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "root_package": ROOT_PACKAGE,
        "target": target,
        "packages": inventory_packages,
    }
    third_party_root = output_root / "THIRD_PARTY"
    if third_party_root.exists() or third_party_root.is_symlink():
        _regular_directory(third_party_root, "binary package third-party root")
    else:
        third_party_root.mkdir(mode=0o755)
    staging_root = third_party_root / "rust.staging"
    require(
        not staging_root.exists() and not staging_root.is_symlink(),
        f"third-party Rust license staging output already exists: {staging_root}",
    )
    staging_root.mkdir(mode=0o755)
    published = False
    try:
        for destination_name, files in planned_files:
            destination = staging_root / destination_name
            destination.mkdir(mode=0o755)
            for license_file in files:
                destination_file = destination / license_file.name
                destination_file.write_bytes(license_file.data)
                os.chmod(destination_file, 0o644)
        staging_inventory = staging_root / "INVENTORY.json"
        staging_inventory.write_bytes(canonical_json(inventory))
        os.chmod(staging_inventory, 0o644)
        staging_root.replace(rust_root)
        published = True
        verify(output_root, expected_target=target)
    except Exception:
        cleanup_root = rust_root if published else staging_root
        if cleanup_root.exists() and not cleanup_root.is_symlink():
            shutil.rmtree(cleanup_root)
        raise
    return inventory


def verify(package_root: pathlib.Path, *, expected_target: str | None = None) -> dict[str, Any]:
    root = _regular_directory(package_root, "binary package root")
    inventory_path = root.joinpath(*INVENTORY_RELATIVE.parts)
    try:
        snapshot = load_json_object_snapshot(
            inventory_path,
            maximum=16 * 1024 * 1024,
            label="third-party Rust license inventory",
        )
    except EvidenceIOError as exc:
        fail(str(exc))
    inventory = snapshot.value
    require(set(inventory) == {"schema_version", "kind", "root_package", "target", "packages"}, "third-party Rust license inventory fields differ")
    require(inventory["schema_version"] == SCHEMA_VERSION and inventory["kind"] == KIND, "third-party Rust license inventory schema differs")
    require(inventory["root_package"] == ROOT_PACKAGE, "third-party Rust license root package differs")
    target = inventory["target"]
    require(isinstance(target, str) and TARGET_RE.fullmatch(target) is not None, "third-party Rust license target is invalid")
    if expected_target is not None:
        require(target == expected_target, f"third-party Rust license target differs: {target} != {expected_target}")
    packages = inventory["packages"]
    require(isinstance(packages, list) and packages, "third-party Rust license package list is empty")
    require(len(packages) <= MAX_LICENSE_FILES, "third-party package count exceeds limit")

    expected_files = {INVENTORY_RELATIVE.as_posix()}
    previous_identity: tuple[str, str, str] | None = None
    license_file_count = 0
    total_bytes = 0
    for package in packages:
        require(isinstance(package, dict), "third-party Rust license package entry is malformed")
        require(set(package) == {"checksum", "license_expression", "name", "source", "version", "license_files"}, "third-party Rust license package fields differ")
        name = package["name"]
        version = package["version"]
        source = package["source"]
        expression = package["license_expression"]
        checksum = package["checksum"]
        require(isinstance(name, str) and PACKAGE_NAME_RE.fullmatch(name) is not None, "third-party package name is invalid")
        require(isinstance(version, str) and VERSION_RE.fullmatch(version) is not None, f"third-party package version is invalid: {name}")
        require(isinstance(source, str) and source, f"third-party package source is invalid: {name} {version}")
        require(isinstance(expression, str) and expression.strip() == expression and expression, f"third-party package license expression is invalid: {name} {version}")
        require(checksum is None or (isinstance(checksum, str) and SHA256_RE.fullmatch(checksum) is not None), f"third-party package checksum is invalid: {name} {version}")
        identity = (name, version, source)
        require(previous_identity is None or identity > previous_identity, "third-party packages are duplicate or not canonically sorted")
        previous_identity = identity
        license_files = package["license_files"]
        require(isinstance(license_files, list) and license_files, f"third-party package has no license files: {name} {version}")
        previous_path: str | None = None
        for item in license_files:
            require(isinstance(item, dict) and set(item) == {"bytes", "path", "sha256"}, f"third-party license file entry is malformed: {name} {version}")
            relative = item["path"]
            size = item["bytes"]
            digest = item["sha256"]
            require(isinstance(relative, str), f"third-party license path is invalid: {name} {version}")
            pure = pathlib.PurePosixPath(relative)
            require(not pure.is_absolute() and ".." not in pure.parts and pure.as_posix() == relative, f"third-party license path is unsafe: {relative!r}")
            require(pure.parts[:3] == ("THIRD_PARTY", "rust", f"{name}-{version}"), f"third-party license path identity differs: {relative}")
            require(previous_path is None or relative > previous_path, f"third-party license paths are duplicate or unsorted: {relative}")
            previous_path = relative
            require(type(size) is int and 0 < size <= MAX_LICENSE_BYTES, f"third-party license byte count is invalid: {relative}")
            license_file_count += 1
            require(
                license_file_count <= MAX_LICENSE_FILES,
                "third-party license file count exceeds limit",
            )
            total_bytes += size
            require(
                total_bytes <= MAX_TOTAL_LICENSE_BYTES,
                "third-party license text total exceeds limit",
            )
            require(isinstance(digest, str) and SHA256_RE.fullmatch(digest) is not None, f"third-party license digest is invalid: {relative}")
            require(relative not in expected_files, f"duplicate third-party license path: {relative}")
            expected_files.add(relative)
            try:
                file_snapshot = read_regular_snapshot(
                    root.joinpath(*pure.parts),
                    maximum=MAX_LICENSE_BYTES,
                    label=f"third-party license {relative}",
                )
            except EvidenceIOError as exc:
                fail(str(exc))
            require(file_snapshot.size == size and file_snapshot.sha256 == digest, f"third-party license bytes differ: {relative}")

    rust_root = root / "THIRD_PARTY" / "rust"
    actual_files: set[str] = set()
    actual_license_file_count = 0
    actual_license_bytes = 0
    try:
        for path in rust_root.rglob("*"):
            metadata = path.lstat()
            require(not path.is_symlink(), f"third-party license tree contains symlink: {path}")
            require(stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode), f"third-party license tree contains unsupported file type: {path}")
            if stat.S_ISREG(metadata.st_mode):
                relative = path.relative_to(root).as_posix()
                actual_files.add(relative)
                if relative != INVENTORY_RELATIVE.as_posix():
                    actual_license_file_count += 1
                    require(
                        actual_license_file_count <= MAX_LICENSE_FILES,
                        "third-party license file count exceeds limit",
                    )
                    actual_license_bytes += metadata.st_size
                    require(
                        actual_license_bytes <= MAX_TOTAL_LICENSE_BYTES,
                        "third-party license text total exceeds limit",
                    )
    except OSError as exc:
        fail(f"cannot enumerate third-party license tree: {exc}")
    require(actual_files == expected_files, f"third-party license file set differs: extra={sorted(actual_files - expected_files)} missing={sorted(expected_files - actual_files)}")
    require(snapshot.file.data == canonical_json(inventory), "third-party Rust license inventory is not canonical JSON")
    return inventory


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create_parser = subparsers.add_parser("create")
    create_parser.add_argument("--root", required=True, type=pathlib.Path)
    create_parser.add_argument("--package-root", required=True, type=pathlib.Path)
    create_parser.add_argument("--target", required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--package-root", required=True, type=pathlib.Path)
    verify_parser.add_argument("--expected-target")
    return parser


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "create":
            inventory = collect(args.root, args.package_root, args.target)
            print(f"THIRD_PARTY_RUST_LICENSES_CREATE_PASS packages={len(inventory['packages'])}")
        else:
            inventory = verify(args.package_root, expected_target=args.expected_target)
            print(f"THIRD_PARTY_RUST_LICENSES_VERIFY_PASS packages={len(inventory['packages'])}")
    except ThirdPartyLicenseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
