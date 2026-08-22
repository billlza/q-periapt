#!/usr/bin/env python3
"""Composite stable publication cohort and active-selector contract."""

from __future__ import annotations

import copy
import dataclasses
import re
from typing import Never

import apple_publication_contract as apple_contract
import crates_io_publication_contract as crates_contract
import platform_publication_contract as platform_contract
import platform_stable_publication_contract as stable_platform_contract


RELEASE_PUBLICATION_KEYS = frozenset(
    platform_contract.PLATFORM_PUBLICATION_KEYS
    | apple_contract.APPLE_PUBLICATION_KEYS
    | {crates_contract.CRATES_IO_PUBLICATION_KEY}
)

PUBLICATION_STATE_SOURCE = "source_results_installed"
PUBLICATION_STATE_PENDING = "stable_cohort_pending"
PUBLICATION_STATE_VERIFIED = "stable_cohort_verified"

NEUTRAL_SWIFT_BOUNDARY = (
    "Versioned Apple distribution selector. It names exactly one verified "
    "publication receipt and repeats that receipt's distribution projection. "
    "A pending receipt is never active. This selector is not independent "
    "source, device, notarization, App Store, or hostile-host evidence."
)
NEUTRAL_SWIFT_COMMAND = (
    "Use artifact/release_receipt_finalizer.py and the stable publication "
    "runbook in ARTIFACT.md; never edit this selector by hand."
)
NEUTRAL_SWIFT_LOCAL_STATUS = "selected_verified_publication_receipt"
NEUTRAL_SWIFT_SOURCE_STATUS = "active_verified_publication"
NEUTRAL_SWIFT_MODE = (
    "versioned Developer ID-signed SwiftPM binaryTarget distribution selector"
)

_LEGACY_SWIFT_KEYS = frozenset(
    {
        "boundary",
        "command",
        "current_local_status",
        "current_source_status",
        "dirty_diagnostic_command",
        "distribution",
        "historical_releases",
        "mode",
        "targets",
    }
)
_ACTIVE_SWIFT_KEYS = _LEGACY_SWIFT_KEYS | frozenset(
    {"active_publication_key"}
)
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_SAFE_SELECTOR_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,127}$")
_STABLE_PHYSICAL_STATUS = "current_clean_tree_physical_pass"
_STABLE_PERFORMANCE_STATUS = "current_controlled_pass"
_STABLE_ANDROID_AAR_STATUS = "current_clean_tree_package_pass"
_STABLE_PHYSICAL_ABI = "arm64-v8a"
_STABLE_ANDROID_AAR_MANIFEST_SCHEMA = 4
_STABLE_ANDROID_DEVICE_PROOF_SCHEMA = 6
_STABLE_PERFORMANCE_PROOF_SCHEMA = 8
_STABLE_ANDROID_AAR_PATH = (
    "target/qperiapt-android-aar/q-periapt-android-0.1.2/"
    "q-periapt-android-0.1.2.aar"
)
_STABLE_ANDROID_AAR_MANIFEST_PATH = (
    "target/qperiapt-android-aar/q-periapt-android-0.1.2/MANIFEST.json"
)
_STABLE_ANDROID_AAR_TARGETS = (
    "arm64-v8a",
    "x86_64",
    "armeabi-v7a",
    "x86",
)
_STABLE_ANDROID_TESTS = (
    "runtimeMetadataMatches",
    "signedPolicyDecisionIsExactAndFailClosed",
    "osRandomPolicyRoundtripAndWipes",
)


class ReleasePublicationContractError(ValueError):
    """A composite publication receipt, cohort, or selector is invalid."""


@dataclasses.dataclass(frozen=True, slots=True)
class StableSourceIdentity:
    source_parent_commit: str
    tag_commit: str
    tag_tree: str
    canonical_source_tree_sha256: str


def _fail(message: str) -> Never:
    raise ReleasePublicationContractError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(
        not isinstance(key, str) for key in value
    ):
        _fail(f"{label} must be a JSON object with string keys")
    return value


def _json_equal(left: object, right: object) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _json_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _json_equal(left_item, right_item)
            for left_item, right_item in zip(left, right, strict=True)
        )
    return left == right


def _publication_entries(manifest: dict[str, object]) -> dict[str, object]:
    publications = manifest.get("release_publications")
    if publications is None:
        return {}
    return _object(publications, "release_publications")


def _filtered_manifest(
    publications: dict[str, object], keys: frozenset[str]
) -> dict[str, object]:
    return {
        "release_publications": {
            key: publications[key] for key in keys if key in publications
        }
    }


def _validate_leaf_dispatch(manifest: dict[str, object]) -> dict[str, object]:
    if not isinstance(manifest, dict):
        _fail("results manifest must be a JSON object")
    publications = _publication_entries(manifest)
    unknown = sorted(set(publications) - RELEASE_PUBLICATION_KEYS)
    if unknown:
        _fail(f"release_publications has unknown entries: {unknown!r}")
    try:
        platform_contract.validate_release_publications(
            _filtered_manifest(
                publications, platform_contract.PLATFORM_PUBLICATION_KEYS
            )
        )
    except platform_contract.PlatformPublicationContractError as exc:
        raise ReleasePublicationContractError(str(exc)) from exc
    try:
        apple_contract.validate_apple_publications(
            _filtered_manifest(
                publications, apple_contract.APPLE_PUBLICATION_KEYS
            )
        )
    except apple_contract.ApplePublicationContractError as exc:
        raise ReleasePublicationContractError(str(exc)) from exc
    if crates_contract.CRATES_IO_PUBLICATION_KEY in publications:
        try:
            crates_contract.validate_crates_io_publication_receipt(
                publications[crates_contract.CRATES_IO_PUBLICATION_KEY]
            )
        except crates_contract.CratesIoPublicationContractError as exc:
            raise ReleasePublicationContractError(str(exc)) from exc
    return publications


def _swift_section(manifest: dict[str, object]) -> dict[str, object] | None:
    value = manifest.get("swift_xcframework")
    if value is None:
        return None
    return _object(value, "swift_xcframework")


def _is_legacy_alpha2_selector(
    manifest: dict[str, object], publications: dict[str, object]
) -> bool:
    swift = _swift_section(manifest)
    return (
        swift is not None
        and frozenset(swift) == _LEGACY_SWIFT_KEYS
        and apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY in publications
        and apple_contract.APPLE_V0_1_2_PUBLICATION_KEY not in publications
        and apple_contract.publication_values_equal(
            swift.get("distribution"),
            apple_contract.frozen_alpha2_r1_distribution(),
        )
    )


def neutral_swift_selector(
    manifest: dict[str, object],
) -> dict[str, object]:
    """Return the one-time neutral selector migration for the frozen baseline."""

    publications = _validate_leaf_dispatch(manifest)
    _require(
        _is_legacy_alpha2_selector(manifest, publications),
        "neutral selector migration requires the exact legacy alpha.2 selector",
    )
    migrated = copy.deepcopy(_swift_section(manifest))
    assert migrated is not None
    migrated.update(
        {
            "active_publication_key": (
                apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY
            ),
            "boundary": NEUTRAL_SWIFT_BOUNDARY,
            "command": NEUTRAL_SWIFT_COMMAND,
            "current_local_status": NEUTRAL_SWIFT_LOCAL_STATUS,
            "current_source_status": NEUTRAL_SWIFT_SOURCE_STATUS,
            "mode": NEUTRAL_SWIFT_MODE,
        }
    )
    return migrated


def _validate_active_selector(
    manifest: dict[str, object], publications: dict[str, object]
) -> None:
    swift = _swift_section(manifest)
    apple_keys = set(publications) & set(apple_contract.APPLE_PUBLICATION_KEYS)
    if swift is None and not apple_keys:
        return
    _require(swift is not None, "Apple publication receipt requires a selector")
    if _is_legacy_alpha2_selector(manifest, publications):
        return
    _require(
        frozenset(swift) == _ACTIVE_SWIFT_KEYS,
        "active Apple selector fields differ",
    )
    for field, expected in (
        ("boundary", NEUTRAL_SWIFT_BOUNDARY),
        ("command", NEUTRAL_SWIFT_COMMAND),
        ("current_local_status", NEUTRAL_SWIFT_LOCAL_STATUS),
        ("current_source_status", NEUTRAL_SWIFT_SOURCE_STATUS),
        ("mode", NEUTRAL_SWIFT_MODE),
    ):
        _require(swift[field] == expected, f"active Apple selector {field} differs")
    active_key = swift["active_publication_key"]
    _require(
        isinstance(active_key, str)
        and active_key in apple_contract.APPLE_PUBLICATION_KEYS
        and active_key in publications,
        "active Apple publication key does not name a recorded receipt",
    )
    receipt = _object(
        publications[active_key], f"active Apple publication {active_key}"
    )
    _require(
        receipt.get("status") == apple_contract.APPLE_STATUS_VERIFIED,
        "active Apple publication must be verified",
    )
    _require(
        apple_contract.publication_values_equal(
            swift["distribution"], receipt.get("distribution")
        ),
        "active Apple distribution differs from its versioned receipt",
    )


def _stable_cohort_state(publications: dict[str, object]) -> str:
    apple = publications.get(apple_contract.APPLE_V0_1_2_PUBLICATION_KEY)
    platform = publications.get(
        stable_platform_contract.PLATFORM_V0_1_2_PUBLICATION_KEY
    )
    crates = publications.get(crates_contract.CRATES_IO_PUBLICATION_KEY)
    if apple is None and platform is None and crates is None:
        return PUBLICATION_STATE_SOURCE
    if apple is not None and platform is not None and crates is None:
        apple_receipt = _object(apple, "Apple stable publication receipt")
        platform_receipt = _object(platform, "platform stable publication receipt")
        if (
            apple_receipt.get("status") == apple_contract.APPLE_STATUS_PENDING
            and platform_receipt.get("status")
            == stable_platform_contract.PLATFORM_V0_1_2_STATUS_PENDING
        ):
            return PUBLICATION_STATE_PENDING
    if apple is not None and platform is not None and crates is not None:
        apple_receipt = _object(apple, "Apple stable publication receipt")
        platform_receipt = _object(platform, "platform stable publication receipt")
        crates_receipt = _object(crates, "crates.io stable publication receipt")
        if (
            apple_receipt.get("status") == apple_contract.APPLE_STATUS_VERIFIED
            and platform_receipt.get("status")
            == stable_platform_contract.PLATFORM_V0_1_2_STATUS_VERIFIED
            and crates_receipt.get("status")
            == crates_contract.PUBLICATION_STATUS_PUBLISHED_VERIFIED
        ):
            return PUBLICATION_STATE_VERIFIED
    _fail("stable publication leaves do not form one coordinated cohort state")


def _source_object(
    receipt: object, *, domain: str
) -> dict[str, object]:
    value = _object(receipt, f"{domain} stable publication receipt")
    if domain == "Apple":
        return _object(value.get("source"), "Apple stable source identity")
    observation = _object(value.get("observation"), f"{domain} observation")
    return _object(observation.get("source"), f"{domain} stable source identity")


def _source_identity(value: dict[str, object], label: str) -> StableSourceIdentity:
    source_parent_commit = value.get("source_parent_commit")
    tag_commit = value.get("tag_commit")
    tag_tree = value.get("tag_tree")
    canonical_source_tree_sha256 = value.get(
        "canonical_source_tree_sha256"
    )
    _require(
        isinstance(source_parent_commit, str)
        and _COMMIT_RE.fullmatch(source_parent_commit) is not None
        and isinstance(tag_commit, str)
        and _COMMIT_RE.fullmatch(tag_commit) is not None
        and isinstance(tag_tree, str)
        and _COMMIT_RE.fullmatch(tag_tree) is not None
        and isinstance(canonical_source_tree_sha256, str)
        and _SHA256_RE.fullmatch(canonical_source_tree_sha256) is not None,
        f"{label} source identity is malformed",
    )
    assert isinstance(source_parent_commit, str)
    assert isinstance(tag_commit, str)
    assert isinstance(tag_tree, str)
    assert isinstance(canonical_source_tree_sha256, str)
    return StableSourceIdentity(
        source_parent_commit=source_parent_commit,
        tag_commit=tag_commit,
        tag_tree=tag_tree,
        canonical_source_tree_sha256=canonical_source_tree_sha256,
    )


def _validate_source_crosslinks(
    manifest: dict[str, object],
    publications: dict[str, object],
    state: str,
) -> StableSourceIdentity | None:
    if state == PUBLICATION_STATE_SOURCE:
        return None
    domain_sources = [
        _source_identity(
            _source_object(
                publications[apple_contract.APPLE_V0_1_2_PUBLICATION_KEY],
                domain="Apple",
            ),
            "Apple stable",
        ),
        _source_identity(
            _source_object(
                publications[
                    stable_platform_contract.PLATFORM_V0_1_2_PUBLICATION_KEY
                ],
                domain="platform",
            ),
            "platform stable",
        ),
    ]
    if state == PUBLICATION_STATE_VERIFIED:
        domain_sources.append(
            _source_identity(
                _source_object(
                    publications[crates_contract.CRATES_IO_PUBLICATION_KEY],
                    domain="crates.io",
                ),
                "crates.io stable",
            )
        )
    expected = domain_sources[0]
    _require(
        all(source == expected for source in domain_sources[1:]),
        "stable publication domains bind different source identities",
    )
    provenance = _object(manifest.get("provenance"), "results provenance")
    _require(
        provenance.get("snapshot_commit") == expected.source_parent_commit,
        "stable publication source parent differs from results provenance",
    )
    _require(
        manifest.get("proof_source_tree_sha256")
        == expected.canonical_source_tree_sha256,
        "stable publication source digest differs from the manifest root",
    )
    _require(
        expected.tag_commit != expected.source_parent_commit,
        "stable publication tag commit is not a results-only successor",
    )
    return expected


def _validate_registry_package_contract_crosslink(
    manifest: dict[str, object], publications: dict[str, object]
) -> None:
    """Bind the irreversible registry receipt to the selected Rust evidence."""

    registry = _object(
        publications[crates_contract.CRATES_IO_PUBLICATION_KEY],
        "crates.io stable publication receipt",
    )
    observation = _object(registry.get("observation"), "crates.io observation")
    package_contract = _object(
        observation.get("package_contract"),
        "crates.io package contract",
    )
    selected = _object(manifest.get("rust_publish"), "selected Rust package contract")
    _require(
        selected.get("current_source_status")
        == "current_clean_tree_rust_package_contract_pass"
        and selected.get("status") == "pass"
        and selected.get("upload_attempted") is False,
        "stable registry publication requires selected current no-upload Rust evidence",
    )
    for field in ("completed_at", "source_commit", "transcript_sha256"):
        _require(
            package_contract.get(field) == selected.get(field),
            f"crates.io package contract {field} differs from selected Rust evidence",
        )
    _require(
        package_contract.get("handoff_sha256")
        == selected.get("handoff_manifest_sha256"),
        "crates.io package contract handoff_sha256 differs from selected Rust evidence",
    )


def validate_stable_source_currentness(manifest: dict[str, object]) -> None:
    """Require the two fresh source gates added for the stable successor.

    Detailed proof schemas remain owned by ``proof_manifest`` and by the raw
    evidence verifiers.  This dependency-free aggregate check exists so every
    publication state machine can reject a hand-authored stale results value
    without introducing an import cycle.
    """

    if not isinstance(manifest, dict):
        _fail("results manifest must be a JSON object")
    provenance = _object(manifest.get("provenance"), "results provenance")
    source_commit = provenance.get("snapshot_commit")
    source_digest = manifest.get("proof_source_tree_sha256")
    _require(
        isinstance(source_commit, str)
        and _COMMIT_RE.fullmatch(source_commit) is not None,
        "stable source currentness requires a canonical source commit",
    )
    _require(
        isinstance(source_digest, str)
        and _SHA256_RE.fullmatch(source_digest) is not None,
        "stable source currentness requires a canonical source digest",
    )

    physical = _object(
        manifest.get("android_physical_runtime"),
        "stable physical Android runtime",
    )
    android_aar = _object(
        manifest.get("android_aar"),
        "stable Android AAR",
    )
    _require(
        android_aar.get("current_source_status") == _STABLE_ANDROID_AAR_STATUS
        and android_aar.get("status") == "pass"
        and android_aar.get("source_commit") == source_commit
        and android_aar.get("proof_source_tree_sha256") == source_digest
        and android_aar.get("source_tree_dirty") is False
        and android_aar.get("manifest_schema")
        == _STABLE_ANDROID_AAR_MANIFEST_SCHEMA
        and android_aar.get("aar_path") == _STABLE_ANDROID_AAR_PATH
        and android_aar.get("manifest_path")
        == _STABLE_ANDROID_AAR_MANIFEST_PATH
        and isinstance(android_aar.get("aar_sha256"), str)
        and _SHA256_RE.fullmatch(android_aar["aar_sha256"]) is not None
        and isinstance(android_aar.get("manifest_sha256"), str)
        and _SHA256_RE.fullmatch(android_aar["manifest_sha256"]) is not None
        and _present_bounded_text(android_aar.get("manifest_generated_at"))
        and android_aar.get("targets") == list(_STABLE_ANDROID_AAR_TARGETS),
        "stable publication requires a current clean Android AAR",
    )
    _require(
        physical.get("current_source_status") == _STABLE_PHYSICAL_STATUS
        and physical.get("status") == "pass"
        and physical.get("source_commit") == source_commit
        and physical.get("proof_source_tree_sha256") == source_digest
        and physical.get("source_tree_dirty") is False,
        "stable publication requires current clean physical Android evidence",
    )
    _require(
        physical.get("device_kind") == "physical"
        and physical.get("device_abi") == _STABLE_PHYSICAL_ABI
        and physical.get("proof_schema")
        == _STABLE_ANDROID_DEVICE_PROOF_SCHEMA
        and physical.get("release_candidate_mode") is True
        and physical.get("covered_tests") == list(_STABLE_ANDROID_TESTS),
        "stable physical Android evidence must be arm64-v8a release mode",
    )
    physical_run_id = physical.get("run_id")
    _require(
        isinstance(physical_run_id, str)
        and _RUN_ID_RE.fullmatch(physical_run_id) is not None
        and physical.get("proof_path")
        == (
            "target/qperiapt-android-device-smoke-runs/"
            f"{physical_run_id}/proof/qperiapt-android-device-proof.json"
        )
        and isinstance(physical.get("proof_sha256"), str)
        and _SHA256_RE.fullmatch(physical["proof_sha256"]) is not None
        and _present_bounded_text(physical.get("proof_generated_at")),
        "stable physical Android proof identity is malformed",
    )
    aar_targets = android_aar.get("targets")
    _require(
        isinstance(aar_targets, list)
        and all(isinstance(target, str) for target in aar_targets)
        and physical.get("device_abi") in aar_targets,
        "stable physical Android evidence is not covered by the selected AAR",
    )

    performance = _object(
        manifest.get("performance"),
        "stable performance evidence",
    )
    performance_path = performance.get("proof_path")
    _require(
        performance.get("current_source_status") == _STABLE_PERFORMANCE_STATUS
        and performance.get("status") == "pass"
        and performance.get("proof_schema")
        == _STABLE_PERFORMANCE_PROOF_SCHEMA
        and performance.get("source_commit") == source_commit
        and performance.get("source_tree_dirty") is False
        and performance.get("proof_source_tree_sha256") == source_digest
        and isinstance(performance_path, str)
        and performance_path.startswith("target/performance/")
        and _SAFE_SELECTOR_RE.fullmatch(
            performance_path.removeprefix("target/performance/")
        )
        is not None
        and isinstance(performance.get("proof_sha256"), str)
        and _SHA256_RE.fullmatch(performance["proof_sha256"]) is not None
        and _present_bounded_text(performance.get("proof_generated_at")),
        "stable publication requires current controlled performance evidence",
    )


def _present_bounded_text(value: object) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= 128
        and "\x00" not in value
    )


def validate_release_publications(manifest: dict[str, object]) -> None:
    """Validate leaves, coordinated state, source root, and active selector."""

    publications = _validate_leaf_dispatch(manifest)
    state = _stable_cohort_state(publications)
    _validate_source_crosslinks(manifest, publications, state)
    if state != PUBLICATION_STATE_SOURCE:
        validate_stable_source_currentness(manifest)
    if state == PUBLICATION_STATE_VERIFIED:
        _validate_registry_package_contract_crosslink(manifest, publications)
    _validate_active_selector(manifest, publications)
    swift = _swift_section(manifest)
    if swift is None:
        return
    active_key = swift.get("active_publication_key")
    expected_active = (
        apple_contract.APPLE_V0_1_2_PUBLICATION_KEY
        if state == PUBLICATION_STATE_VERIFIED
        else apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY
    )
    if active_key is not None:
        _require(
            active_key == expected_active,
            "active Apple selector differs from the coordinated cohort state",
        )


def stable_source_identity(
    manifest: dict[str, object],
) -> StableSourceIdentity | None:
    """Return the validated stable source identity, if a cohort is recorded."""

    publications = _validate_leaf_dispatch(manifest)
    state = _stable_cohort_state(publications)
    return _validate_source_crosslinks(manifest, publications, state)


def publication_state(manifest: dict[str, object]) -> str:
    """Return the validated coordinated stable publication state."""

    validate_release_publications(manifest)
    return _stable_cohort_state(_publication_entries(manifest))


def _require_historical_unchanged(
    previous: dict[str, object], current: dict[str, object]
) -> None:
    for key in (
        apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY,
        platform_contract.PLATFORM_R2_PUBLICATION_KEY,
    ):
        if key not in previous:
            _require(
                key not in current,
                f"historical publication {key!r} cannot be introduced",
            )
        else:
            _require(
                key in current and _json_equal(previous[key], current[key]),
                f"historical publication {key!r} changed or was removed",
            )


def _validate_selector_transition(
    previous_manifest: dict[str, object],
    current_manifest: dict[str, object],
    *,
    previous_state: str,
    current_state: str,
) -> None:
    previous = _swift_section(previous_manifest)
    current = _swift_section(current_manifest)
    _require(previous is not None and current is not None, "Apple selector is missing")
    if _is_legacy_alpha2_selector(
        previous_manifest, _publication_entries(previous_manifest)
    ):
        _require(
            current_state == PUBLICATION_STATE_SOURCE
            and _json_equal(current, neutral_swift_selector(previous_manifest)),
            "legacy Apple selector may only undergo the one-time neutral migration",
        )
        return
    if previous_state == current_state:
        _require(
            _json_equal(previous, current),
            "Apple selector changed without a cohort state transition",
        )
        return
    if current_state != PUBLICATION_STATE_VERIFIED:
        _require(
            _json_equal(previous, current),
            "Apple selector changed before the stable cohort was verified",
        )
        return
    _require(
        previous_state == PUBLICATION_STATE_PENDING,
        "stable Apple selector can only activate from the pending cohort",
    )
    for key in _ACTIVE_SWIFT_KEYS - {
        "active_publication_key",
        "distribution",
    }:
        _require(
            _json_equal(previous[key], current[key]),
            f"stable selector activation changed forbidden field {key!r}",
        )


def validate_release_publication_transition(
    previous: dict[str, object], current: dict[str, object]
) -> None:
    """Validate the exact source -> pending -> verified cohort transition."""

    validate_release_publications(previous)
    validate_release_publications(current)
    previous_publications = _publication_entries(previous)
    current_publications = _publication_entries(current)
    _require_historical_unchanged(previous_publications, current_publications)

    try:
        platform_contract.validate_release_publication_transition(
            _filtered_manifest(
                previous_publications,
                platform_contract.PLATFORM_PUBLICATION_KEYS,
            ),
            _filtered_manifest(
                current_publications,
                platform_contract.PLATFORM_PUBLICATION_KEYS,
            ),
        )
    except platform_contract.PlatformPublicationContractError as exc:
        raise ReleasePublicationContractError(str(exc)) from exc
    try:
        apple_contract.validate_apple_publication_transition(
            _filtered_manifest(
                previous_publications, apple_contract.APPLE_PUBLICATION_KEYS
            ),
            _filtered_manifest(
                current_publications, apple_contract.APPLE_PUBLICATION_KEYS
            ),
        )
    except apple_contract.ApplePublicationContractError as exc:
        raise ReleasePublicationContractError(str(exc)) from exc

    previous_state = _stable_cohort_state(previous_publications)
    current_state = _stable_cohort_state(current_publications)
    allowed = {
        (PUBLICATION_STATE_SOURCE, PUBLICATION_STATE_SOURCE),
        (PUBLICATION_STATE_SOURCE, PUBLICATION_STATE_PENDING),
        (PUBLICATION_STATE_PENDING, PUBLICATION_STATE_PENDING),
        (PUBLICATION_STATE_PENDING, PUBLICATION_STATE_VERIFIED),
        (PUBLICATION_STATE_VERIFIED, PUBLICATION_STATE_VERIFIED),
    }
    _require(
        (previous_state, current_state) in allowed,
        "stable publication cohort transition is not monotonic",
    )
    if crates_contract.CRATES_IO_PUBLICATION_KEY in previous_publications:
        _require(
            crates_contract.CRATES_IO_PUBLICATION_KEY in current_publications
            and _json_equal(
                previous_publications[crates_contract.CRATES_IO_PUBLICATION_KEY],
                current_publications[crates_contract.CRATES_IO_PUBLICATION_KEY],
            ),
            "verified crates.io publication receipt cannot change or be removed",
        )
    _validate_selector_transition(
        previous,
        current,
        previous_state=previous_state,
        current_state=current_state,
    )
