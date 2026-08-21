#!/usr/bin/env python3
"""Frozen ABI-2 crates.io publication receipt for Q-Periapt 0.1.1.

The receipt is deliberately a remote-observation domain, not an upload log.
Only exact observations from both the crates.io API and sparse index can turn
one crate into ``published_verified``.  An upload with an unknown effect is not
representable here and therefore cannot accidentally become aggregate proof.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, Never

from rust_publish_contract import RUST_PUBLISHABLE_CRATES


CRATES_IO_PUBLICATION_SCHEMA_VERSION = 1
CRATES_IO_PUBLICATION_KIND = "qperiapt.abi2_crates_io_publication_receipt"
CRATES_IO_PUBLICATION_KEY = "crates_io_v0_1_1"
CRATES_IO_REGISTRY = "https://crates.io"
CRATES_IO_SPARSE_INDEX = "https://index.crates.io"
PRODUCT_VERSION = "0.1.1"
ABI_VERSION = 2
MAX_CRATE_SIZE_BYTES = 128 * 1024 * 1024
MAX_TOTAL_CRATE_SIZE_BYTES = 512 * 1024 * 1024

CRATE_STATUS_ABSENT = "absent"
CRATE_STATUS_PUBLISHED_VERIFIED = "published_verified"
PUBLICATION_STATUS_PARTIAL = "partial"
PUBLICATION_STATUS_PUBLISHED_VERIFIED = "published_verified"

# Normal and optional dependencies among the ten public packages.  Dev-only
# dependencies do not constrain publication order.  The tuple order is the
# only permitted upload/resume order.
CRATE_PUBLICATION_TOPOLOGY = (
    ("q-periapt-mlkem-native-sys", ()),
    ("q-periapt-core", ()),
    ("q-periapt-kem", ("q-periapt-core",)),
    ("q-periapt-sig", ("q-periapt-core",)),
    (
        "q-periapt-backends",
        (
            "q-periapt-core",
            "q-periapt-sig",
            "q-periapt-mlkem-native-sys",
        ),
    ),
    ("q-periapt-policy", ("q-periapt-core", "q-periapt-sig")),
    (
        "q-periapt-ffi",
        (
            "q-periapt-core",
            "q-periapt-kem",
            "q-periapt-backends",
            "q-periapt-policy",
        ),
    ),
    (
        "q-periapt-wasm",
        (
            "q-periapt-core",
            "q-periapt-kem",
            "q-periapt-backends",
            "q-periapt-policy",
        ),
    ),
    (
        "q-periapt-rustls",
        (
            "q-periapt-core",
            "q-periapt-kem",
            "q-periapt-backends",
            "q-periapt-policy",
        ),
    ),
    ("q-periapt-cli", ()),
)
PUBLISHABLE_CRATES = tuple(name for name, _dependencies in CRATE_PUBLICATION_TOPOLOGY)
CRATE_DEPENDENCIES = MappingProxyType(dict(CRATE_PUBLICATION_TOPOLOGY))

if PUBLISHABLE_CRATES != RUST_PUBLISHABLE_CRATES:
    raise RuntimeError(
        "crates.io publication topology differs from the Rust package contract"
    )

CRATES_IO_PUBLICATION_BOUNDARY = (
    "ABI 2 Q-Periapt 0.1.1 crates.io publication receipt. Local package "
    "digests provide Level-1 accidental-mismatch detection. A crate is "
    "published_verified only when the official crates.io API and sparse "
    "index both report version 0.1.1, the exact local .crate SHA-256, and "
    "yanked=false. Published crates must form the fixed dependency-safe "
    "prefix; absent suffix entries are not a rollback claim. Upload outcome "
    "unknown is intentionally outside this public receipt and blocks an "
    "aggregate verified result."
)

_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CRATE_FILE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*-0\.1\.1\.crate$")

_TOP_LEVEL_KEYS = frozenset(
    {
        "boundary",
        "crates",
        "identity",
        "kind",
        "observation",
        "schema_version",
        "status",
    }
)
_IDENTITY_KEYS = frozenset(
    {"abi_version", "product_version", "publication_key", "registry"}
)
_OBSERVATION_KEYS = frozenset(
    {"observed_at", "package_contract", "source"}
)
_SOURCE_KEYS = frozenset(
    {
        "canonical_source_tree_sha256",
        "source_parent_commit",
        "tag_commit",
        "tag_tree",
    }
)
_PACKAGE_CONTRACT_KEYS = frozenset(
    {"completed_at", "handoff_sha256", "source_commit", "transcript_sha256"}
)
_CRATE_BASE_KEYS = frozenset(
    {
        "crate_file",
        "crate_sha256",
        "crate_size",
        "dependencies",
        "name",
        "state",
        "version",
    }
)
_CRATE_PUBLISHED_KEYS = _CRATE_BASE_KEYS | frozenset(
    {"crates_io_api", "sparse_index", "verified_at"}
)
_REMOTE_RECORD_KEYS = frozenset({"checksum", "version", "yanked"})


class CratesIoPublicationContractError(ValueError):
    """A crates.io publication receipt violates the frozen public contract."""


def _fail(message: str) -> Never:
    raise CratesIoPublicationContractError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(
        not isinstance(key, str) for key in value
    ):
        _fail(f"{label} must be a JSON object with string keys")
    return value


def _exact_keys(
    value: Mapping[str, object], expected: frozenset[str], label: str
) -> None:
    actual = frozenset(value)
    _require(
        actual == expected,
        f"{label} keys differ: missing={sorted(expected - actual)!r} "
        f"extra={sorted(actual - expected)!r}",
    )


def _sha1(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA1_RE.fullmatch(value) is None:
        _fail(f"{label} must be a lowercase SHA-1")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        _fail(f"{label} must be a lowercase SHA-256")
    return value


def parse_utc_timestamp(value: object, label: str) -> dt.datetime:
    """Parse one exact, second-resolution RFC3339 UTC timestamp."""

    if not isinstance(value, str):
        _fail(f"{label} must be an RFC3339 UTC timestamp")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise CratesIoPublicationContractError(
            f"{label} must be an RFC3339 UTC timestamp"
        ) from exc
    _require(
        parsed.strftime("%Y-%m-%dT%H:%M:%SZ") == value,
        f"{label} must be an RFC3339 UTC timestamp",
    )
    return parsed.replace(tzinfo=dt.UTC)


def _validate_source(source_value: object) -> dict[str, str]:
    source = _object(source_value, "crates.io source identity")
    _exact_keys(source, _SOURCE_KEYS, "crates.io source identity")
    source_parent_commit = _sha1(
        source["source_parent_commit"], "crates.io source parent commit"
    )
    tag_commit = _sha1(source["tag_commit"], "crates.io tag commit")
    tag_tree = _sha1(source["tag_tree"], "crates.io tag tree")
    canonical_source_tree_sha256 = _sha256(
        source["canonical_source_tree_sha256"],
        "crates.io canonical source tree",
    )
    _require(
        source_parent_commit != tag_commit,
        "crates.io tag commit must be the results-only successor, not its source parent",
    )
    return {
        "canonical_source_tree_sha256": canonical_source_tree_sha256,
        "source_parent_commit": source_parent_commit,
        "tag_commit": tag_commit,
        "tag_tree": tag_tree,
    }


def _validate_remote_record(
    value: object,
    *,
    crate_name: str,
    crate_sha256: str,
    label: str,
) -> None:
    record = _object(value, label)
    _exact_keys(record, _REMOTE_RECORD_KEYS, label)
    _require(record["version"] == PRODUCT_VERSION, f"{label} version differs")
    checksum = _sha256(record["checksum"], f"{label} checksum")
    _require(
        checksum == crate_sha256,
        f"{label} checksum differs from {crate_name} local .crate",
    )
    _require(record["yanked"] is False, f"{label} must report yanked=false")


def _validate_crate(
    value: object,
    *,
    index: int,
    expected_name: str,
    expected_dependencies: tuple[str, ...],
    package_completed_at: dt.datetime,
    observed_at: dt.datetime,
) -> str:
    label = f"crates.io crate {index} ({expected_name})"
    crate = _object(value, label)
    state = crate.get("state")
    if state == CRATE_STATUS_ABSENT:
        _exact_keys(crate, _CRATE_BASE_KEYS, label)
    elif state == CRATE_STATUS_PUBLISHED_VERIFIED:
        _exact_keys(crate, _CRATE_PUBLISHED_KEYS, label)
    else:
        _fail(f"{label} has an unknown state: {state!r}")

    _require(crate["name"] == expected_name, f"{label} name/order differs")
    _require(crate["version"] == PRODUCT_VERSION, f"{label} version differs")
    dependencies = crate["dependencies"]
    _require(
        isinstance(dependencies, list)
        and all(isinstance(item, str) for item in dependencies)
        and tuple(dependencies) == expected_dependencies,
        f"{label} dependency topology differs",
    )
    expected_file = f"{expected_name}-{PRODUCT_VERSION}.crate"
    _require(
        crate["crate_file"] == expected_file
        and _CRATE_FILE_RE.fullmatch(expected_file) is not None,
        f"{label} archive name differs",
    )
    _require(
        type(crate["crate_size"]) is int
        and 0 < crate["crate_size"] <= MAX_CRATE_SIZE_BYTES,
        f"{label} archive size is outside the bounded range",
    )
    crate_sha256 = _sha256(crate["crate_sha256"], f"{label} archive")

    if state == CRATE_STATUS_PUBLISHED_VERIFIED:
        _validate_remote_record(
            crate["crates_io_api"],
            crate_name=expected_name,
            crate_sha256=crate_sha256,
            label=f"{label} API record",
        )
        _validate_remote_record(
            crate["sparse_index"],
            crate_name=expected_name,
            crate_sha256=crate_sha256,
            label=f"{label} sparse record",
        )
        verified_at = parse_utc_timestamp(
            crate["verified_at"], f"{label} verified_at"
        )
        _require(
            package_completed_at <= verified_at <= observed_at,
            f"{label} verification timestamp is outside the receipt interval",
        )
    return state


def validate_crates_io_publication_receipt(receipt_value: object) -> None:
    """Validate one schema-1 crates.io receipt without filesystem or network I/O."""

    receipt = _object(receipt_value, "crates.io publication receipt")
    _exact_keys(receipt, _TOP_LEVEL_KEYS, "crates.io publication receipt")
    _require(
        type(receipt["schema_version"]) is int
        and receipt["schema_version"] == CRATES_IO_PUBLICATION_SCHEMA_VERSION,
        "crates.io publication receipt schema differs",
    )
    _require(
        receipt["kind"] == CRATES_IO_PUBLICATION_KIND,
        "crates.io publication receipt kind differs",
    )
    _require(
        receipt["boundary"] == CRATES_IO_PUBLICATION_BOUNDARY,
        "crates.io publication boundary differs",
    )
    identity = _object(receipt["identity"], "crates.io publication identity")
    _exact_keys(identity, _IDENTITY_KEYS, "crates.io publication identity")
    _require(
        identity
        == {
            "abi_version": ABI_VERSION,
            "product_version": PRODUCT_VERSION,
            "publication_key": CRATES_IO_PUBLICATION_KEY,
            "registry": CRATES_IO_REGISTRY,
        },
        "crates.io publication identity differs",
    )

    observation = _object(receipt["observation"], "crates.io observation")
    _exact_keys(observation, _OBSERVATION_KEYS, "crates.io observation")
    observed_at = parse_utc_timestamp(
        observation["observed_at"], "crates.io observed_at"
    )
    source = _validate_source(observation["source"])
    package_contract = _object(
        observation["package_contract"], "crates.io package contract"
    )
    _exact_keys(
        package_contract,
        _PACKAGE_CONTRACT_KEYS,
        "crates.io package contract",
    )
    package_source_commit = _sha1(
        package_contract["source_commit"], "crates.io package source commit"
    )
    _require(
        package_source_commit == source["source_parent_commit"],
        "crates.io package transcript source differs from the source parent",
    )
    _sha256(
        package_contract["transcript_sha256"],
        "crates.io package transcript",
    )
    _sha256(
        package_contract["handoff_sha256"],
        "crates.io package handoff",
    )
    package_completed_at = parse_utc_timestamp(
        package_contract["completed_at"], "crates.io package completed_at"
    )
    _require(
        package_completed_at <= observed_at,
        "crates.io package completion postdates the observation",
    )

    crates = receipt["crates"]
    _require(
        isinstance(crates, list) and len(crates) == len(CRATE_PUBLICATION_TOPOLOGY),
        "crates.io receipt must contain exactly ten crate records",
    )
    states = tuple(
        _validate_crate(
            crates[index],
            index=index,
            expected_name=name,
            expected_dependencies=dependencies,
            package_completed_at=package_completed_at,
            observed_at=observed_at,
        )
        for index, (name, dependencies) in enumerate(CRATE_PUBLICATION_TOPOLOGY)
    )
    published_count = sum(
        state == CRATE_STATUS_PUBLISHED_VERIFIED for state in states
    )
    _require(
        sum(crate["crate_size"] for crate in crates)
        <= MAX_TOTAL_CRATE_SIZE_BYTES,
        "crates.io aggregate archive size exceeds the bounded range",
    )
    _require(
        states
        == (CRATE_STATUS_PUBLISHED_VERIFIED,) * published_count
        + (CRATE_STATUS_ABSENT,) * (len(states) - published_count),
        "crates.io published crates must be one exact topology prefix",
    )
    expected_status = (
        PUBLICATION_STATUS_PUBLISHED_VERIFIED
        if published_count == len(states)
        else PUBLICATION_STATUS_PARTIAL
    )
    _require(
        receipt["status"] == expected_status,
        "crates.io aggregate status differs from the exact verified prefix",
    )


# Stable-specific name used by the release assembler; retain the domain name as
# the primary public API for direct callers.
validate_v0_1_1_publication_receipt = validate_crates_io_publication_receipt
