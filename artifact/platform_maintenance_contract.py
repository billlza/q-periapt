#!/usr/bin/env python3
"""Independent 0.1.5 platform revision anchored to the frozen original cohort."""

from __future__ import annotations

import copy
import hashlib
from typing import Never

from evidence_io import EvidenceIOError, parse_strict_json_bytes
from platform_distribution_contract import PlatformReleaseProfile
import platform_stable_publication_contract as platform_contract


PROFILE = PlatformReleaseProfile.MAINTENANCE_R2
PUBLICATION_KEY = PROFILE.publication_key
SCHEMA_VERSION = 1
KIND = "qperiapt.platform_maintenance_receipt"
BASE_COHORT_COMMIT = "cc21bc1cadac5148aadfd98f1c6b0e4acbbb0c06"
BASE_RESULTS_SHA256 = "90f5faed852311a59f388eaf79072c4887aa9cb3e68a78ac4a2e0ea0acf6844f"
BASE_SOURCE_COMMIT = "2b9c485f6c72f99b4cb8942269063692f3f2498e"
BASE_TAG_COMMIT = "fabe003ddc3507b88af7a67a7138344e4b9634fd"
BASE_TAG_TREE = "6038c28acd4600d5ad6671b99ef486f857a30acd"
BASE_APPLE_RELEASE_ID = 383170350
BASE_PLATFORM_RELEASE_ID = 383171691
BASE_AAR_SHA256 = "07502d813f1a02d43aa8f41fd4c6ecb95e7ae7c673139f04fdd3bae98360c225"
BASE_APPLE_TAG_OBJECT = "47162c5cc4d5d64d2c6d1c6f178db0a176e419bf"
BASE_PLATFORM_TAG_OBJECT = "3d926adcfc77a979ba5f54d37d8b3bbf23f7d19e"
# Exact observed r1 assets. Q independently pins the corresponding four digests.
BASE_APPLE_ASSETS = (
    (
        "APPLE_DISTRIBUTION.json",
        3388,
        "40507cc4267e2a556007524e02b3b33d2f91fcf070b6f503e5c3a92cebd5e1fe",
    ),
    (
        "CQPeriapt.xcframework.zip",
        29927579,
        "362233caa8f5e08230c370f75c09f6c0add9f0563e3eb9b0d9c51b525982bc70",
    ),
    (
        "MANIFEST.json",
        5913,
        "7c6fcc566c4043a5dc7516d6387d77986eee60ba7e81f6c53541521ac8fac4ad",
    ),
    (
        "SHA256SUMS",
        262,
        "861dada90cf480bb9a1d1bf56d7fd09df470e1ef7e555a5cc65d06713aa18816",
    ),
)


class PlatformMaintenanceContractError(ValueError):
    """A maintenance receipt changes history or lacks its own release evidence."""


def _fail(message: str) -> Never:
    raise PlatformMaintenanceContractError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        _fail(f"{label} must be a JSON object with string keys")
    return value


def base_anchor() -> dict[str, object]:
    """The immutable predecessor is data, never a selectable replacement source."""

    return {
        "cohort_commit": BASE_COHORT_COMMIT,
        "cohort_tag": "v0.1.5-verified-cohort",
        "results_sha256": BASE_RESULTS_SHA256,
        "apple_release_id": BASE_APPLE_RELEASE_ID,
        "platform_release_id": BASE_PLATFORM_RELEASE_ID,
        "platform_publication_key": "platform_v0_1_5",
        "platform_release_tag": "abi2-platforms-v0.1.5",
    }


def validate_base_cohort_bytes(raw: bytes) -> dict[str, object]:
    """Detect accidental selection or alteration of the exact installed Q bytes."""

    _require(
        type(raw) is bytes and len(raw) <= 16 * 1024 * 1024,
        "maintenance base results must be bounded bytes",
    )
    _require(
        hashlib.sha256(raw).hexdigest() == BASE_RESULTS_SHA256,
        "maintenance base cohort bytes differ from frozen Q",
    )
    try:
        parsed = parse_strict_json_bytes(raw, label="maintenance base cohort")
    except EvidenceIOError as exc:
        raise PlatformMaintenanceContractError(str(exc)) from exc
    # The exact Q digest pins all three complete receipts, including their old
    # verifier identities. Do not translate, normalize or re-finalize that image.
    return _object(parsed, "maintenance base results")


def publication(receipt_value: object) -> dict[str, object]:
    """Return one validated r2 publication while preserving its independent anchor."""

    receipt = _object(receipt_value, "platform maintenance receipt")
    _require(
        set(receipt)
        == {"schema_version", "kind", "base_cohort", "publication", "status"}
        and type(receipt["schema_version"]) is int
        and receipt["schema_version"] == SCHEMA_VERSION
        and receipt["kind"] == KIND,
        "platform maintenance receipt discriminant or fields differ",
    )
    _require(receipt["base_cohort"] == base_anchor(), "maintenance base anchor differs")
    result = _object(receipt["publication"], "maintenance publication")
    try:
        platform_contract.validate_platform_publication_receipt(result, profile=PROFILE)
    except platform_contract.PlatformV015PublicationContractError as exc:
        raise PlatformMaintenanceContractError(str(exc)) from exc
    _require(
        receipt["status"] == result["status"], "maintenance publication status differs"
    )
    observation = _object(result["observation"], "maintenance observation")
    source = _object(observation["source"], "maintenance source")
    _require(
        source["source_parent_commit"] != BASE_SOURCE_COMMIT
        and source["tag_commit"] != BASE_TAG_COMMIT,
        "maintenance publication must identify its new source and tag",
    )
    candidate = _object(observation["release_candidate"], "maintenance candidate")
    assets = candidate["assets"]
    assert isinstance(assets, list)  # The exact seven-asset contract validated this.
    aar = next(
        asset for asset in assets if asset["name"] == platform_contract.ANDROID_AAR
    )
    _require(
        aar["sha256"] != BASE_AAR_SHA256,
        "maintenance AAR still names the defective r1 bytes",
    )
    if result["status"] == platform_contract.PLATFORM_V0_1_5_STATUS_VERIFIED:
        _require(
            observation["release_id"]
            not in {BASE_APPLE_RELEASE_ID, BASE_PLATFORM_RELEASE_ID},
            "maintenance publication reused an original release identity",
        )
    return result


def wrap_publication(value: dict[str, object]) -> dict[str, object]:
    """Create only a validated revision wrapper; no observed fact is synthesized."""

    receipt = {
        "schema_version": SCHEMA_VERSION,
        "kind": KIND,
        "base_cohort": base_anchor(),
        "publication": copy.deepcopy(value),
        "status": value.get("status"),
    }
    publication(receipt)
    return receipt


def validate_transition(previous: object | None, current: object | None) -> None:
    """Require absent -> pending -> verified and immutable idempotence afterwards."""

    if current is None:
        _require(previous is None, "maintenance publication cannot be removed")
        return
    current_publication = publication(current)
    pending = platform_contract.PLATFORM_V0_1_5_STATUS_PENDING
    if previous is None:
        _require(
            current_publication["status"] == pending, "maintenance must begin pending"
        )
        return
    previous_publication = publication(previous)
    if previous == current:
        return
    _require(
        previous_publication["status"] == pending
        and current_publication["status"]
        == platform_contract.PLATFORM_V0_1_5_STATUS_VERIFIED,
        "maintenance receipt may only advance pending to verified",
    )
    previous_observation = _object(
        previous_publication["observation"], "previous observation"
    )
    current_observation = _object(
        current_publication["observation"], "current observation"
    )
    for field in (
        "source",
        "candidate_attestation",
        "release_candidate",
        "assembly_receipt_sha256",
    ):
        _require(
            previous_observation[field] == current_observation[field],
            f"maintenance promotion changed recorded {field}",
        )
