#!/usr/bin/env python3
"""Strict, reusable CBOM/SBOM verification for binary release packages."""

from __future__ import annotations

import pathlib
import re
import stat
import tomllib
from typing import Any

from evidence_io import EvidenceIOError, load_json_object_snapshot, read_regular_snapshot


MAX_BOM_BYTES = 16 * 1024 * 1024
EXPECTED_CRYPTO_ASSETS = frozenset(
    {
        "ML-KEM-768",
        "ML-KEM-1024",
        "X25519",
        "ML-DSA-65",
        "ML-DSA-87",
        "SLH-DSA-SHA2-256s",
        "SHA3-256",
        "SHAKE-256",
    }
)


class PackageBomError(ValueError):
    """A packaged CBOM or SBOM is incomplete, unsafe, or inconsistent."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PackageBomError(message)


def _load_json(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        return load_json_object_snapshot(
            path, maximum=MAX_BOM_BYTES, label=label
        ).value
    except EvidenceIOError as exc:
        raise PackageBomError(str(exc)) from exc


def _walk(value: Any, path: str) -> None:
    forbidden_keys = {"generated_at", "serialNumber", "timestamp"}
    forbidden_value = re.compile(
        r"(/Users/|/home/|/private/|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}|"
        r"BEGIN .*PRIVATE KEY|AKIA[0-9A-Z]{16}|(?:api|auth|access|secret)[_-]?token\s*[:=]|"
        r"password\s*[:=])",
        re.IGNORECASE,
    )
    if isinstance(value, dict):
        for key, child in value.items():
            _require(key not in forbidden_keys, f"non-reproducible BOM key at {path}/{key}")
            _walk(child, f"{path}/{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _walk(child, f"{path}/{index}")
    elif isinstance(value, str):
        _require(
            forbidden_value.search(value) is None,
            f"sensitive or nonportable BOM value at {path}",
        )


def _components(document: dict[str, Any], label: str) -> list[dict[str, Any]]:
    _require(document.get("bomFormat") == "CycloneDX", f"{label} is not CycloneDX")
    _require(document.get("specVersion") == "1.6", f"{label} is not CycloneDX 1.6")
    _require(
        type(document.get("version")) is int and document["version"] > 0,
        f"{label} version is invalid",
    )
    metadata = document.get("metadata")
    _require(isinstance(metadata, dict), f"{label} metadata is missing")
    component = metadata.get("component")
    _require(
        isinstance(component, dict)
        and component.get("name") == "q-periapt-hybrid-suite",
        f"{label} component metadata differs",
    )
    components = document.get("components")
    _require(isinstance(components, list) and components, f"{label} components are missing")
    _require(all(isinstance(item, dict) for item in components), f"{label} component is malformed")
    references = [item.get("bom-ref") for item in components if "bom-ref" in item]
    _require(len(references) == len(set(references)), f"{label} has duplicate bom-ref values")
    _walk(document, label)
    return components


def _cargo_lock_components(cargo_lock: pathlib.Path) -> set[tuple[str, str, str]]:
    try:
        snapshot = read_regular_snapshot(
            cargo_lock, maximum=MAX_BOM_BYTES, label="Cargo.lock for release SBOM"
        )
        document = tomllib.loads(snapshot.data.decode("utf-8"))
    except (EvidenceIOError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise PackageBomError(f"cannot parse Cargo.lock for release SBOM: {exc}") from exc
    packages = document.get("package")
    _require(isinstance(packages, list) and packages, "Cargo.lock package list is missing")
    expected: set[tuple[str, str, str]] = set()
    for package in packages:
        _require(isinstance(package, dict), "Cargo.lock package entry is malformed")
        name = package.get("name")
        version = package.get("version")
        _require(isinstance(name, str) and name, "Cargo.lock package name is missing")
        _require(isinstance(version, str) and version, f"Cargo.lock version is missing for {name}")
        identity = (name, version, f"pkg:cargo/{name}@{version}")
        _require(identity not in expected, f"Cargo.lock contains duplicate SBOM identity: {name} {version}")
        expected.add(identity)
    return expected


def verify(package_root: pathlib.Path, *, cargo_lock: pathlib.Path | None) -> dict[str, int]:
    """Verify exact crypto assets and, when supplied, the complete Cargo.lock SBOM."""

    original = pathlib.Path(package_root)
    try:
        metadata = original.lstat()
        root = original.resolve(strict=True)
    except OSError as exc:
        raise PackageBomError(f"cannot inspect release package root {package_root}: {exc}") from exc
    _require(
        stat.S_ISDIR(metadata.st_mode) and not original.is_symlink(),
        "release package root must be a non-symlink directory",
    )
    cbom = _load_json(root / "share/q-periapt/bom/cbom.cdx.json", "release CBOM")
    sbom = _load_json(root / "share/q-periapt/bom/sbom.cdx.json", "release SBOM")
    cbom_components = _components(cbom, "CBOM")
    sbom_components = _components(sbom, "SBOM")

    seen_crypto: set[str] = set()
    for component in cbom_components:
        _require(component.get("type") == "cryptographic-asset", "CBOM component is not a cryptographic asset")
        name = component.get("name")
        _require(isinstance(name, str), "CBOM component name is missing")
        _require(name not in seen_crypto, f"CBOM contains duplicate crypto asset: {name}")
        seen_crypto.add(name)
        crypto = component.get("cryptoProperties")
        _require(isinstance(crypto, dict) and crypto.get("assetType") == "algorithm", f"CBOM cryptoProperties differ for {name}")
        algorithm = crypto.get("algorithmProperties")
        _require(isinstance(algorithm, dict), f"CBOM algorithmProperties are missing for {name}")
        _require(isinstance(algorithm.get("primitive"), str) and algorithm["primitive"], f"CBOM primitive is missing for {name}")
        _require(algorithm.get("parameterSetIdentifier") == name, f"CBOM parameter set differs for {name}")
        _require(isinstance(algorithm.get("cryptoFunctions"), list) and algorithm["cryptoFunctions"], f"CBOM functions are missing for {name}")
        _require(type(algorithm.get("nistQuantumSecurityLevel")) is int, f"CBOM NIST level is missing for {name}")
    _require(seen_crypto == EXPECTED_CRYPTO_ASSETS, "CBOM cryptographic asset inventory differs")

    actual_sbom: set[tuple[str, str, str]] = set()
    for component in sbom_components:
        _require(component.get("type") == "library", "SBOM component is not a library")
        name = component.get("name")
        version = component.get("version")
        purl = component.get("purl")
        _require(isinstance(name, str) and name, "SBOM component name is missing")
        _require(isinstance(version, str) and version, f"SBOM version is missing for {name}")
        expected_purl = f"pkg:cargo/{name}@{version}"
        _require(purl == expected_purl and component.get("bom-ref") == expected_purl, f"SBOM identity differs for {name}")
        identity = (name, version, expected_purl)
        _require(identity not in actual_sbom, f"SBOM contains duplicate package identity: {name} {version}")
        actual_sbom.add(identity)
    if cargo_lock is not None:
        _require(
            actual_sbom == _cargo_lock_components(cargo_lock.resolve(strict=True)),
            "SBOM components do not match Cargo.lock package set",
        )
    return {"cbom_components": len(seen_crypto), "sbom_components": len(actual_sbom)}
