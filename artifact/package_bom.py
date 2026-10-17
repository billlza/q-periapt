#!/usr/bin/env python3
"""Strict, reusable CBOM/SBOM verification for binary release packages."""

from __future__ import annotations

import pathlib
from enum import Enum
import re
import stat
import tomllib
from typing import Any

from evidence_io import EvidenceIOError, load_json_object_snapshot, read_regular_snapshot, parse_strict_json_bytes


MAX_BOM_BYTES = 16 * 1024 * 1024
# Release packages are built with default features, so this is the default
# backend set: the SLH-DSA parameter sets live behind q-periapt-backends'
# off-by-default `slh-dsa` feature and are in no shipped package. What ties the
# CBOM to the implementation rather than to another copy of itself is that the
# CLI derives each row from the backend crates it links, checked by its own
# `the_cbom_lists_exactly_the_algorithms_the_shipped_backends_report` against
# the registries the backends crate's declaration macros generate. This list is
# held to that chain transitively: `verify()` compares it to the CBOM the CLI
# actually emitted into a release package, so a parameter set added to one of
# those macros without a CBOM row fails the Rust guard, and a stale list here
# fails at packaging.
EXPECTED_CRYPTO_ASSETS = frozenset(
    {
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024",
        "X25519",
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
        "SHA3-256",
        "SHAKE-256",
    }
)


class BomProfile(Enum):
    """Closed reviewed inventories; new native packages cannot reuse the old nine."""

    BACKENDS_V0_1_5 = "backends-v0.1.5"
    NATIVE_SDK_020 = "native-sdk-020"


def _native_sdk_algorithms() -> dict[str, tuple[str, frozenset[str], int | None]]:
    rows = {}
    for parameter, level in ((512, 1), (768, 3), (1024, 5)):
        rows[f"ML-KEM-{parameter}"] = ("kem", frozenset(("keygen", "encapsulate", "decapsulate")), level)
    for parameter, level in ((44, 2), (65, 3), (87, 5)):
        rows[f"ML-DSA-{parameter}"] = ("signature", frozenset(("keygen", "sign", "verify")), level)
    rows["X25519"] = ("key-agree", frozenset(("keygen", "keyderive")), 0)
    rows["X25519MLKEM768"] = ("combiner", frozenset(("keygen", "encapsulate", "decapsulate")), None)
    rows["Q-Periapt-ContextBound"] = ("combiner", frozenset(("keyderive",)), None)
    for name in ("SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHAKE-256"):
        rows[name] = ("xof" if name == "SHAKE-256" else "hash", frozenset(("digest",)), None)
    for hash_name in ("SHA-256", "SHA-384"):
        rows[f"HMAC-{hash_name}"] = ("mac", frozenset(("tag",)), None)
        rows[f"HKDF-{hash_name}"] = ("kdf", frozenset(("keyderive",)), None)
    for name in ("AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305"):
        rows[name] = ("ae", frozenset(("encrypt", "decrypt", "tag")), None)
    for curve, signing_hash in (("P256", 256), ("P384", 384), ("P521", 512)):
        for digest in (256, 384, 512):
            functions = ("sign", "verify") if digest == signing_hash else ("verify",)
            rows[f"ECDSA-{curve}-SHA-{digest}"] = ("signature", frozenset(functions), 0)
    rows["Ed25519"] = ("signature", frozenset(("sign", "verify")), 0)
    for digest in (256, 384, 512):
        rows[f"RSA-PSS-SHA-{digest}"] = ("signature", frozenset(("sign", "verify")), 0)
        rows[f"RSA-PKCS1v1.5-SHA-{digest}"] = ("signature", frozenset(("verify",)), 0)
    return rows


NATIVE_SDK_ALGORITHMS = _native_sdk_algorithms()
NATIVE_TLS_SNAPSHOT_SHA256 = "d7ba7c197ae2820495a63b230a007536351c0745dfee050897bd53d494ba0bed"
NATIVE_INVENTORY_SCOPE = (
    "product algorithms and backend catalogue; not a census of transitive provider internals or OS RNG; "
    "not a negotiated-session or security-validation claim"
)


class PackageBomError(ValueError):
    """A packaged CBOM or SBOM is incomplete, unsafe, or inconsistent."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PackageBomError(message)


def _load_json(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        snapshot = load_json_object_snapshot(
            path, maximum=MAX_BOM_BYTES, label=label
        )
    except EvidenceIOError as exc:
        raise PackageBomError(str(exc)) from exc
    _require(
        snapshot.file.data == snapshot.file.data.rstrip() + b"\n",
        f"{label} must end with exactly one terminal LF",
    )
    return snapshot.value


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


def _verify_native_sdk_cbom(document: dict, components: list[dict]) -> None:
    metadata = document["metadata"]
    _require(metadata["component"].get("version") == "0.2.0", "SDK CBOM version differs")
    properties = metadata.get("properties")
    _require(isinstance(properties, list) and len(properties) == 3, "SDK CBOM profile metadata differs")
    facts = {}
    for item in properties:
        _require(isinstance(item, dict) and set(item) == {"name", "value"}, "SDK CBOM property differs")
        _require(isinstance(item["name"], str) and isinstance(item["value"], str), "invalid SDK CBOM property")
        _require(item["name"] not in facts, "duplicate SDK CBOM property")
        facts[item["name"]] = item["value"]
    _require(set(facts) == {"qperiapt:cbom-profile", "qperiapt:configured-tls-provider", "qperiapt:inventory-scope"}, "SDK CBOM property names differ")
    _require(facts["qperiapt:cbom-profile"] == BomProfile.NATIVE_SDK_020.value, "SDK CBOM profile differs")
    _require(facts["qperiapt:inventory-scope"] == NATIVE_INVENTORY_SCOPE, "SDK CBOM scope differs")
    try:
        reference = read_regular_snapshot(pathlib.Path(__file__).parent / "fixtures/sdk-native-020-tls-inventory.json",
                                          maximum=65536, label="reviewed SDK TLS inventory")
        _require(reference.sha256 == NATIVE_TLS_SNAPSHOT_SHA256, "reviewed TLS inventory identity differs")
        expected = parse_strict_json_bytes(reference.data, label="reviewed SDK TLS inventory")
        actual = parse_strict_json_bytes(facts["qperiapt:configured-tls-provider"].encode(), label="SDK TLS inventory")
    except EvidenceIOError as exc:
        raise PackageBomError(str(exc)) from exc
    _require(actual == expected, "SDK configured TLS inventory differs")
    _require({c["name"] for c in components} == set(NATIVE_SDK_ALGORITHMS), "SDK cryptographic asset inventory differs")
    for component in components:
        name = component["name"]
        primitive, functions, level = NATIVE_SDK_ALGORITHMS[name]
        algorithm = component["cryptoProperties"]["algorithmProperties"]
        fields = {"primitive", "parameterSetIdentifier", "executionEnvironment", "implementationPlatform", "cryptoFunctions"}
        if level is not None:
            fields.add("nistQuantumSecurityLevel")
            _require(type(algorithm.get("nistQuantumSecurityLevel")) is int and algorithm["nistQuantumSecurityLevel"] == level,
                     f"SDK quantum category differs for {name}")
        _require(set(algorithm) == fields, f"SDK algorithm fields differ for {name}")
        _require(algorithm["primitive"] == primitive, f"SDK primitive differs for {name}")
        declared = algorithm["cryptoFunctions"]
        _require(all(isinstance(f, str) for f in declared) and len(declared) == len(functions) and set(declared) == functions,
                 f"SDK functions differ for {name}")
        _require(algorithm["executionEnvironment"] == "software-plain-ram" and algorithm["implementationPlatform"] == "generic",
                 f"SDK execution scope differs for {name}")
        _require(component.get("bom-ref") == "crypto/" + name.lower(), f"SDK asset reference differs for {name}")


def verify(package_root: pathlib.Path, *, cargo_lock: pathlib.Path | None,
           profile: BomProfile = BomProfile.BACKENDS_V0_1_5) -> dict[str, int]:
    """Verify exact crypto assets and, when supplied, the complete Cargo.lock SBOM."""

    _require(isinstance(profile, BomProfile), "unknown BOM verification profile")
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
        if profile is BomProfile.BACKENDS_V0_1_5:
            _require(type(algorithm.get("nistQuantumSecurityLevel")) is int, f"CBOM NIST level is missing for {name}")
    if profile is BomProfile.NATIVE_SDK_020:
        _verify_native_sdk_cbom(cbom, cbom_components)
    else:
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
