#!/usr/bin/env python3
"""Frozen ABI-2 crates.io publication receipt for Q-Periapt 0.1.3.

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
CRATES_IO_PUBLICATION_KEY = "crates_io_v0_1_3"
# The 0.1.3 line published, so this key names frozen history.  It is
# byte-identical to the active key above until the 0.1.4 opening renames
# the active family to crates_io_v0_1_4; the frozen key never changes.
CRATES_IO_V0_1_3_PUBLICATION_KEY = "crates_io_v0_1_3"
CRATES_IO_REGISTRY = "https://crates.io"
CRATES_IO_SPARSE_INDEX = "https://index.crates.io"
PRODUCT_VERSION = "0.1.3"
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
    "ABI 2 Q-Periapt 0.1.3 crates.io publication receipt. Local package "
    "digests provide Level-1 accidental-mismatch detection. A crate is "
    "published_verified only when the official crates.io API and sparse "
    "index both report version 0.1.3, the exact local .crate SHA-256, and "
    "yanked=false. Published crates must form the fixed dependency-safe "
    "prefix; absent suffix entries are not a rollback claim. Upload outcome "
    "unknown is intentionally outside this public receipt and blocks an "
    "aggregate verified result."
)

_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CRATE_FILE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*-0\.1\.3\.crate$")

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


def _json_deep_equal(left: object, right: object) -> bool:
    """Compare JSON values recursively without Python bool/int aliasing."""

    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _json_deep_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _json_deep_equal(left_item, right_item)
            for left_item, right_item in zip(left, right, strict=True)
        )
    return left == right


def frozen_crates_io_v0_1_3_receipt() -> dict[str, object]:
    """Return the exact published 0.1.3 crates.io publication receipt."""

    return {
        "boundary": (
            "ABI 2 Q-Periapt 0.1.3 crates.io publication receipt. Local package "
            "digests provide Level-1 accidental-mismatch detection. A crate is "
            "published_verified only when the official crates.io API and sparse "
            "index both report version 0.1.3, the exact local .crate SHA-256, and "
            "yanked=false. Published crates must form the fixed dependency-safe "
            "prefix; absent suffix entries are not a rollback claim. Upload outcome "
            "unknown is intentionally outside this public receipt and blocks an "
            "aggregate verified result."
        ),
        "crates": [
            {
                "crate_file": "q-periapt-mlkem-native-sys-0.1.3.crate",
                "crate_sha256": (
                    "0f01750b43fc419a24739b6fa4139fd0f46f75acb22de7fa143c00740f6cf7fe"
                ),
                "crate_size": 203_720,
                "crates_io_api": {
                    "checksum": (
                        "0f01750b43fc419a24739b6fa4139fd0f46f75acb22de7fa143c00740f6cf7fe"
                    ),
                    "version": "0.1.3",
                    "yanked": False,
                },
                "dependencies": [],
                "name": "q-periapt-mlkem-native-sys",
                "sparse_index": {
                    "checksum": (
                        "0f01750b43fc419a24739b6fa4139fd0f46f75acb22de7fa143c00740f6cf7fe"
                    ),
                    "version": "0.1.3",
                    "yanked": False,
                },
                "state": "published_verified",
                "verified_at": "2026-08-28T09:35:13Z",
                "version": "0.1.3",
            },
            {
                "crate_file": "q-periapt-core-0.1.3.crate",
                "crate_sha256": (
                    "f1b10cca5a308577fe4d2e1c7690b3c9be27e1107d794c856e913b476fe01b88"
                ),
                "crate_size": 38211,
                "crates_io_api": {
                    "checksum": (
                        "f1b10cca5a308577fe4d2e1c7690b3c9be27e1107d794c856e913b476fe01b88"
                    ),
                    "version": "0.1.3",
                    "yanked": False,
                },
                "dependencies": [],
                "name": "q-periapt-core",
                "sparse_index": {
                    "checksum": (
                        "f1b10cca5a308577fe4d2e1c7690b3c9be27e1107d794c856e913b476fe01b88"
                    ),
                    "version": "0.1.3",
                    "yanked": False,
                },
                "state": "published_verified",
                "verified_at": "2026-08-28T09:35:18Z",
                "version": "0.1.3",
            },
            {
                "crate_file": "q-periapt-kem-0.1.3.crate",
                "crate_sha256": (
                    "dc9b36c74c71d27614a600febb82363b103fbb692dd14af8eb9b36b8ecb4a901"
                ),
                "crate_size": 30747,
                "crates_io_api": {
                    "checksum": (
                        "dc9b36c74c71d27614a600febb82363b103fbb692dd14af8eb9b36b8ecb4a901"
                    ),
                    "version": "0.1.3",
                    "yanked": False,
                },
                "dependencies": [
                    "q-periapt-core",
                ],
                "name": "q-periapt-kem",
                "sparse_index": {
                    "checksum": (
                        "dc9b36c74c71d27614a600febb82363b103fbb692dd14af8eb9b36b8ecb4a901"
                    ),
                    "version": "0.1.3",
                    "yanked": False,
                },
                "state": "published_verified",
                "verified_at": "2026-08-28T09:35:22Z",
                "version": "0.1.3",
            },
            {
                "crate_file": "q-periapt-sig-0.1.3.crate",
                "crate_sha256": (
                    "7cfa7508761e3410128f8a04ac397d13a31b9650c83d8c786bb27f7be78d64ac"
                ),
                "crate_size": 27200,
                "crates_io_api": {
                    "checksum": (
                        "7cfa7508761e3410128f8a04ac397d13a31b9650c83d8c786bb27f7be78d64ac"
                    ),
                    "version": "0.1.3",
                    "yanked": False,
                },
                "dependencies": [
                    "q-periapt-core",
                ],
                "name": "q-periapt-sig",
                "sparse_index": {
                    "checksum": (
                        "7cfa7508761e3410128f8a04ac397d13a31b9650c83d8c786bb27f7be78d64ac"
                    ),
                    "version": "0.1.3",
                    "yanked": False,
                },
                "state": "published_verified",
                "verified_at": "2026-08-28T09:35:27Z",
                "version": "0.1.3",
            },
            {
                "crate_file": "q-periapt-backends-0.1.3.crate",
                "crate_sha256": (
                    "92fc27fb5d71f1e7084d42ab90f22e5b8d791177bfe807db67d28bd85e2db76b"
                ),
                "crate_size": 4_953_540,
                "crates_io_api": {
                    "checksum": (
                        "92fc27fb5d71f1e7084d42ab90f22e5b8d791177bfe807db67d28bd85e2db76b"
                    ),
                    "version": "0.1.3",
                    "yanked": False,
                },
                "dependencies": [
                    "q-periapt-core",
                    "q-periapt-sig",
                    "q-periapt-mlkem-native-sys",
                ],
                "name": "q-periapt-backends",
                "sparse_index": {
                    "checksum": (
                        "92fc27fb5d71f1e7084d42ab90f22e5b8d791177bfe807db67d28bd85e2db76b"
                    ),
                    "version": "0.1.3",
                    "yanked": False,
                },
                "state": "published_verified",
                "verified_at": "2026-08-28T09:35:31Z",
                "version": "0.1.3",
            },
            {
                "crate_file": "q-periapt-policy-0.1.3.crate",
                "crate_sha256": (
                    "e3f4d497e9455ae2e9c1171eb1c243beb42cd11f6a476a46bed323ec2b5a62da"
                ),
                "crate_size": 39253,
                "crates_io_api": {
                    "checksum": (
                        "e3f4d497e9455ae2e9c1171eb1c243beb42cd11f6a476a46bed323ec2b5a62da"
                    ),
                    "version": "0.1.3",
                    "yanked": False,
                },
                "dependencies": [
                    "q-periapt-core",
                    "q-periapt-sig",
                ],
                "name": "q-periapt-policy",
                "sparse_index": {
                    "checksum": (
                        "e3f4d497e9455ae2e9c1171eb1c243beb42cd11f6a476a46bed323ec2b5a62da"
                    ),
                    "version": "0.1.3",
                    "yanked": False,
                },
                "state": "published_verified",
                "verified_at": "2026-08-28T09:35:36Z",
                "version": "0.1.3",
            },
            {
                "crate_file": "q-periapt-ffi-0.1.3.crate",
                "crate_sha256": (
                    "801c25abc5cdfbff5cf19ba0262fc4940e116c54636c70cdbda83ddcfeb1de7f"
                ),
                "crate_size": 51309,
                "crates_io_api": {
                    "checksum": (
                        "801c25abc5cdfbff5cf19ba0262fc4940e116c54636c70cdbda83ddcfeb1de7f"
                    ),
                    "version": "0.1.3",
                    "yanked": False,
                },
                "dependencies": [
                    "q-periapt-core",
                    "q-periapt-kem",
                    "q-periapt-backends",
                    "q-periapt-policy",
                ],
                "name": "q-periapt-ffi",
                "sparse_index": {
                    "checksum": (
                        "801c25abc5cdfbff5cf19ba0262fc4940e116c54636c70cdbda83ddcfeb1de7f"
                    ),
                    "version": "0.1.3",
                    "yanked": False,
                },
                "state": "published_verified",
                "verified_at": "2026-08-28T09:35:40Z",
                "version": "0.1.3",
            },
            {
                "crate_file": "q-periapt-wasm-0.1.3.crate",
                "crate_sha256": (
                    "249f9ca36ff4511fa21c1467dc8f363f5d2f26a387ae753b49865beb12106633"
                ),
                "crate_size": 16695,
                "crates_io_api": {
                    "checksum": (
                        "249f9ca36ff4511fa21c1467dc8f363f5d2f26a387ae753b49865beb12106633"
                    ),
                    "version": "0.1.3",
                    "yanked": False,
                },
                "dependencies": [
                    "q-periapt-core",
                    "q-periapt-kem",
                    "q-periapt-backends",
                    "q-periapt-policy",
                ],
                "name": "q-periapt-wasm",
                "sparse_index": {
                    "checksum": (
                        "249f9ca36ff4511fa21c1467dc8f363f5d2f26a387ae753b49865beb12106633"
                    ),
                    "version": "0.1.3",
                    "yanked": False,
                },
                "state": "published_verified",
                "verified_at": "2026-08-28T09:35:45Z",
                "version": "0.1.3",
            },
            {
                "crate_file": "q-periapt-rustls-0.1.3.crate",
                "crate_sha256": (
                    "c93dc51c0f096dd117ccf17dac1c273c7566fd319a43f13183d14bd6b0d61fa4"
                ),
                "crate_size": 42289,
                "crates_io_api": {
                    "checksum": (
                        "c93dc51c0f096dd117ccf17dac1c273c7566fd319a43f13183d14bd6b0d61fa4"
                    ),
                    "version": "0.1.3",
                    "yanked": False,
                },
                "dependencies": [
                    "q-periapt-core",
                    "q-periapt-kem",
                    "q-periapt-backends",
                    "q-periapt-policy",
                ],
                "name": "q-periapt-rustls",
                "sparse_index": {
                    "checksum": (
                        "c93dc51c0f096dd117ccf17dac1c273c7566fd319a43f13183d14bd6b0d61fa4"
                    ),
                    "version": "0.1.3",
                    "yanked": False,
                },
                "state": "published_verified",
                "verified_at": "2026-08-28T09:35:50Z",
                "version": "0.1.3",
            },
            {
                "crate_file": "q-periapt-cli-0.1.3.crate",
                "crate_sha256": (
                    "86ff2ed77153de071d4758f4e3f6cb0b9117ee5cf68849ac823eabf850108aff"
                ),
                "crate_size": 11216,
                "crates_io_api": {
                    "checksum": (
                        "86ff2ed77153de071d4758f4e3f6cb0b9117ee5cf68849ac823eabf850108aff"
                    ),
                    "version": "0.1.3",
                    "yanked": False,
                },
                "dependencies": [],
                "name": "q-periapt-cli",
                "sparse_index": {
                    "checksum": (
                        "86ff2ed77153de071d4758f4e3f6cb0b9117ee5cf68849ac823eabf850108aff"
                    ),
                    "version": "0.1.3",
                    "yanked": False,
                },
                "state": "published_verified",
                "verified_at": "2026-08-28T09:35:54Z",
                "version": "0.1.3",
            },
        ],
        "identity": {
            "abi_version": 2,
            "product_version": "0.1.3",
            "publication_key": "crates_io_v0_1_3",
            "registry": "https://crates.io",
        },
        "kind": "qperiapt.abi2_crates_io_publication_receipt",
        "observation": {
            "observed_at": "2026-08-28T09:35:54Z",
            "package_contract": {
                "completed_at": "2026-08-25T09:59:54Z",
                "handoff_sha256": (
                    "71dda0bde0ff954b68e80411806f7b0d9749bd746191c49785390277cad20397"
                ),
                "source_commit": "e9ae27fcc8b66c37a700cfa0e1efbc4219eb5688",
                "transcript_sha256": (
                    "efea80bd1681be7a1571090fe192937d146c01dae282881b8b4339459d9060cb"
                ),
            },
            "source": {
                "canonical_source_tree_sha256": (
                    "2a2f0961c9a6fd3e5f410d78f760365593876b5036ddcaf491e917a6bb47e8db"
                ),
                "source_parent_commit": "e9ae27fcc8b66c37a700cfa0e1efbc4219eb5688",
                "tag_commit": "69e64078ea464109d7e846619e2ce493aa26934f",
                "tag_tree": "4c05594b8f8d305c8a22dc8a25b87685856854c5",
            },
        },
        "schema_version": 1,
        "status": "published_verified",
    }


def validate_crates_io_publication_receipt(receipt_value: object) -> None:
    """Validate one schema-1 crates.io receipt without filesystem or network I/O."""

    if _json_deep_equal(receipt_value, frozen_crates_io_v0_1_3_receipt()):
        # The 0.1.3 line published: deep equality with the frozen verified
        # receipt is the entire frozen-history contract, and that receipt
        # passed the full structural validation below when it was
        # committed.
        return
    # The structural machinery below stays the active path for receipts
    # that are not the frozen publication until the 0.1.4 opening renames
    # this module's active family to crates_io_v0_1_4; the frozen branch
    # above then becomes the frozen key's only accepting path.
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
validate_v0_1_3_publication_receipt = validate_crates_io_publication_receipt
