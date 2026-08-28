#!/usr/bin/env python3
"""Composite stable publication cohort and active-selector contract."""

from __future__ import annotations

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
    | {
        crates_contract.CRATES_IO_PUBLICATION_KEY,
        crates_contract.CRATES_IO_V0_1_3_PUBLICATION_KEY,
    }
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

_ACTIVE_SWIFT_KEYS = frozenset(
    {
        "active_publication_key",
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
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_STABLE_ANDROID_AAR_STATUS = "current_clean_tree_package_pass"
_STABLE_RUST_STATUS = "current_clean_tree_rust_package_contract_pass"
_STABLE_ANDROID_RUNTIME_STATUS = "current_clean_tree_emulator_pass"
_STABLE_LOCAL_INDEX_STATUS = "current_clean_tree_local_index_consumer_pass"
_STABLE_ANDROID_AAR_MANIFEST_SCHEMA = 4
_STABLE_ANDROID_DEVICE_PROOF_SCHEMA = 6
_STABLE_LOCAL_INDEX_SCHEMA = 5
_STABLE_LOCAL_CONSUMER_SCHEMA = 1
_STABLE_ANDROID_ABI = "arm64-v8a"
_STABLE_ANDROID_SDK = 35
_STABLE_ANDROID_PAGE_SIZE = 16_384
_STABLE_ANDROID_BUILD_TOOLS = "36.0.0"
# These currentness path literals (and the local_release_index path
# below) name the active 0.1.4 line: currentness only ever runs against
# the v0.1.4 cohort, never against frozen history.  proof_manifest's
# producer path constants carry these same 0.1.4 values.
_STABLE_ANDROID_AAR_PATH = (
    "target/qperiapt-android-aar/q-periapt-android-0.1.4/"
    "q-periapt-android-0.1.4.aar"
)
_STABLE_ANDROID_AAR_MANIFEST_PATH = (
    "target/qperiapt-android-aar/q-periapt-android-0.1.4/MANIFEST.json"
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
_RUST_HANDOFF_RE = re.compile(
    r"^target/qperiapt-rust-package-handoffs/"
    r"transaction\.[1-9][0-9]*-[0-9a-f]{32}/rust-package-handoff\.json$"
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
    if crates_contract.CRATES_IO_V0_1_3_PUBLICATION_KEY in publications:
        # The 0.1.3 line published: deep equality with the frozen verified
        # receipt is the frozen crates.io key's only accepting path.
        _require(
            _json_equal(
                publications[
                    crates_contract.CRATES_IO_V0_1_3_PUBLICATION_KEY
                ],
                crates_contract.frozen_crates_io_v0_1_3_receipt(),
            ),
            "frozen crates.io 0.1.3 publication receipt differs from the "
            "published history",
        )
    return publications


def _swift_section(manifest: dict[str, object]) -> dict[str, object] | None:
    value = manifest.get("swift_xcframework")
    if value is None:
        return None
    return _object(value, "swift_xcframework")


def _validate_active_selector(
    manifest: dict[str, object], publications: dict[str, object]
) -> None:
    # The one-time legacy alpha.2 selector migration completed on the
    # published 0.1.3 line, so its machinery is retired: every recorded
    # selector must be the migrated active form. The NEUTRAL_SWIFT_*
    # constants above stay authoritative because the active selector
    # carries them verbatim.
    swift = _swift_section(manifest)
    apple_keys = set(publications) & set(apple_contract.APPLE_PUBLICATION_KEYS)
    if swift is None and not apple_keys:
        return
    _require(swift is not None, "Apple publication receipt requires a selector")
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
    # The coordinated state machine tracks only the ACTIVE v0_1_4 cohort;
    # the frozen historical leaves are excluded from the state function.
    # Their five-leaf floor is enforced by _require_historical_unchanged
    # on every transition and follows by induction from the assembler's
    # initial-baseline validator, which requires exactly those leaves.
    apple = publications.get(apple_contract.APPLE_V0_1_4_PUBLICATION_KEY)
    platform = publications.get(
        stable_platform_contract.PLATFORM_V0_1_4_PUBLICATION_KEY
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
            == stable_platform_contract.PLATFORM_V0_1_4_STATUS_PENDING
        ):
            return PUBLICATION_STATE_PENDING
    if apple is not None and platform is not None and crates is not None:
        apple_receipt = _object(apple, "Apple stable publication receipt")
        platform_receipt = _object(platform, "platform stable publication receipt")
        crates_receipt = _object(crates, "crates.io stable publication receipt")
        if (
            apple_receipt.get("status") == apple_contract.APPLE_STATUS_VERIFIED
            and platform_receipt.get("status")
            == stable_platform_contract.PLATFORM_V0_1_4_STATUS_VERIFIED
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
                publications[apple_contract.APPLE_V0_1_4_PUBLICATION_KEY],
                domain="Apple",
            ),
            "Apple stable",
        ),
        _source_identity(
            _source_object(
                publications[
                    stable_platform_contract.PLATFORM_V0_1_4_PUBLICATION_KEY
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
    """Require the source-bound package closure used by stable publication.

    Detailed proof schemas remain owned by ``proof_manifest`` and by the raw
    evidence verifiers. This dependency-free aggregate rejects forged stale
    results without turning product-readiness device or performance evidence
    into a package-publication prerequisite.
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

    rust = _object(manifest.get("rust_publish"), "stable Rust package handoff")
    android_aar = _object(manifest.get("android_aar"), "stable Android AAR")
    android_runtime = _object(
        manifest.get("android_device_runtime"),
        "stable canonical Android runtime",
    )
    local_index = _object(
        manifest.get("local_release_index"),
        "stable local release index",
    )

    handoff_path = rust.get("handoff_manifest_path")
    _require(
        rust.get("current_source_status") == _STABLE_RUST_STATUS
        and rust.get("status") == "pass"
        and rust.get("source_commit") == source_commit
        and rust.get("proof_source_tree_sha256") == source_digest
        and rust.get("source_tree_dirty") is False
        and rust.get("upload_attempted") is False
        and rust.get("evidence_schema") == 2
        and rust.get("publishable_crates")
        == list(crates_contract.PUBLISHABLE_CRATES)
        and rust.get("package_list_pass_crates")
        == list(crates_contract.PUBLISHABLE_CRATES)
        and rust.get("package_verification_pass_crates")
        == list(crates_contract.PUBLISHABLE_CRATES)
        and isinstance(handoff_path, str)
        and _RUST_HANDOFF_RE.fullmatch(handoff_path) is not None
        and isinstance(rust.get("handoff_manifest_sha256"), str)
        and _SHA256_RE.fullmatch(rust["handoff_manifest_sha256"]) is not None
        and isinstance(rust.get("transcript_sha256"), str)
        and _SHA256_RE.fullmatch(rust["transcript_sha256"]) is not None
        and _present_bounded_text(rust.get("completed_at")),
        "stable publication requires a current clean Rust package handoff",
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

    android_run_id = android_runtime.get("run_id")
    _require(
        android_runtime.get("current_source_status")
        == _STABLE_ANDROID_RUNTIME_STATUS
        and android_runtime.get("status") == "pass"
        and android_runtime.get("source_commit") == source_commit
        and android_runtime.get("proof_source_tree_sha256") == source_digest
        and android_runtime.get("source_tree_dirty") is False
        and android_runtime.get("device_kind") == "emulator"
        and android_runtime.get("device_abi") == _STABLE_ANDROID_ABI
        and android_runtime.get("android_sdk") == _STABLE_ANDROID_SDK
        and android_runtime.get("page_size") == _STABLE_ANDROID_PAGE_SIZE
        and android_runtime.get("build_tools") == _STABLE_ANDROID_BUILD_TOOLS
        and android_runtime.get("proof_schema")
        == _STABLE_ANDROID_DEVICE_PROOF_SCHEMA
        and android_runtime.get("release_candidate_mode") is True
        and android_runtime.get("covered_tests") == list(_STABLE_ANDROID_TESTS)
        and isinstance(android_run_id, str)
        and _RUN_ID_RE.fullmatch(android_run_id) is not None
        and android_runtime.get("proof_path")
        == (
            "target/qperiapt-android-device-smoke-runs/"
            f"{android_run_id}/proof/qperiapt-android-device-proof.json"
        )
        and isinstance(android_runtime.get("proof_sha256"), str)
        and _SHA256_RE.fullmatch(android_runtime["proof_sha256"]) is not None
        and _present_bounded_text(android_runtime.get("proof_generated_at")),
        "stable publication requires current canonical Android runtime evidence",
    )

    consumer_run_id = local_index.get("consumer_receipt_run_id")
    _require(
        local_index.get("current_source_status") == _STABLE_LOCAL_INDEX_STATUS
        and local_index.get("status") == "pass"
        and local_index.get("consumer_status") == "pass"
        and local_index.get("source_commit") == source_commit
        and local_index.get("proof_source_tree_sha256") == source_digest
        and local_index.get("source_tree_dirty") is False
        and local_index.get("channel") == "release"
        and local_index.get("index_schema") == _STABLE_LOCAL_INDEX_SCHEMA
        and local_index.get("consumer_receipt_schema")
        == _STABLE_LOCAL_CONSUMER_SCHEMA
        and local_index.get("android_runtime_run_id") == android_run_id
        and local_index.get("android_runtime_proof_sha256")
        == android_runtime.get("proof_sha256")
        and local_index.get("index_path")
        == (
            "target/qperiapt-local-release/release/0.1.4/"
            f"{source_commit}/index.json"
        )
        and isinstance(local_index.get("index_sha256"), str)
        and _SHA256_RE.fullmatch(local_index["index_sha256"]) is not None
        and isinstance(consumer_run_id, str)
        and _RUN_ID_RE.fullmatch(consumer_run_id) is not None
        and local_index.get("consumer_receipt_path")
        == (
            "target/qperiapt-release-consumer-smoke/receipts/"
            f"{consumer_run_id}/qperiapt-release-consumer-receipt.json"
        )
        and isinstance(local_index.get("consumer_receipt_sha256"), str)
        and _SHA256_RE.fullmatch(local_index["consumer_receipt_sha256"])
        is not None
        and _present_bounded_text(local_index.get("generated_at"))
        and _present_bounded_text(local_index.get("consumer_receipt_generated_at")),
        "stable publication requires a current local release consumer receipt",
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
    # The selector must name the most recent verified publication: the
    # active apple_v0_1_4 receipt once its cohort verifies, otherwise the
    # frozen published apple_v0_1_3 receipt (the live selection since the
    # 0.1.3 line published). The alpha.2 prerelease can never be selected
    # again: the frozen five-leaf floor guarantees apple_v0_1_3 is
    # recorded in every manifest on the 0.1.4 line.
    expected_active = (
        apple_contract.APPLE_V0_1_4_PUBLICATION_KEY
        if state == PUBLICATION_STATE_VERIFIED
        else apple_contract.APPLE_V0_1_3_PUBLICATION_KEY
    )
    _require(
        swift.get("active_publication_key") == expected_active,
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
    # The complete five-leaf frozen floor: the Apple and platform frozen
    # families additionally enforce introduce/remove/change rules in
    # their own domain transition validators, and the frozen crates.io
    # leaf is pinned only here. Presence of all five leaves in every
    # manifest follows by induction from the assembler's initial-baseline
    # validator plus this no-removal rule.
    for key in (
        apple_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY,
        platform_contract.PLATFORM_R2_PUBLICATION_KEY,
        apple_contract.APPLE_V0_1_3_PUBLICATION_KEY,
        platform_contract.PLATFORM_V0_1_3_PUBLICATION_KEY,
        crates_contract.CRATES_IO_V0_1_3_PUBLICATION_KEY,
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
